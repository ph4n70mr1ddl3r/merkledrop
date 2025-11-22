use clap::Parser;
use rusqlite::{params, Connection};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tiny_keccak::{Hasher, Keccak};

#[derive(Parser, Debug)]
#[command(about = "Build address_index (address -> leaf_idx, leaf_hash) in merkle.db")]
struct Args {
    /// SQLite database containing the Merkle tree
    #[arg(long, default_value = "merkle.db")]
    database: PathBuf,

    /// Directory containing shard files
    #[arg(long, default_value = "shards")]
    shard_dir: PathBuf,

    /// Manifest file listing shard filenames in order
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Rows per batch commit
    #[arg(long, default_value_t = 200_000)]
    batch_size: usize,

    /// Seconds between progress logs
    #[arg(long, default_value_t = 10.0)]
    report_every: f64,
}

fn normalize_addr(addr: &str) -> String {
    let mut a = addr.trim();
    if let Some(stripped) = a.strip_prefix("0x").or_else(|| a.strip_prefix("0X")) {
        a = stripped;
    }
    a.to_ascii_lowercase()
}

fn addr_bytes(addr: &str) -> Result<[u8; 20], String> {
    let norm = normalize_addr(addr);
    let bytes = hex::decode(&norm).map_err(|e| format!("decode {addr}: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!("address must be 20 bytes: {addr}"));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn hash_leaf(addr: &str) -> Result<[u8; 32], String> {
    Ok(keccak256(&addr_bytes(addr)?))
}

fn load_manifest(manifest: &Path) -> Result<Vec<PathBuf>, String> {
    let file = File::open(manifest)
        .map_err(|e| format!("manifest {manifest:?} cannot be opened: {e}"))?;
    let mut shards = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| format!("read manifest line: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        shards.push(
            manifest
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(trimmed),
        );
    }
    if shards.is_empty() {
        return Err(format!("manifest {manifest:?} has no entries"));
    }
    Ok(shards)
}

fn apply_speed_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;
        PRAGMA locking_mode = EXCLUSIVE;
        PRAGMA temp_store = MEMORY;
        PRAGMA mmap_size = 1073741824;
        PRAGMA cache_size = -524288;
        PRAGMA foreign_keys = OFF;
    "#,
    )
}

fn ensure_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS address_index (
            address   TEXT PRIMARY KEY,
            leaf_idx  INTEGER NOT NULL,
            leaf_hash BLOB NOT NULL
        );
        DROP INDEX IF EXISTS idx_address_index_leaf;
    "#,
    )
}

fn create_index(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_address_index_leaf ON address_index(leaf_idx);",
        [],
    )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let manifest_path = args
        .manifest
        .clone()
        .unwrap_or_else(|| args.shard_dir.join("manifest.txt"));

    let shard_files = load_manifest(&manifest_path)?;
    println!(
        "Manifest: {:?} | shards: {} | db: {:?}",
        manifest_path,
        shard_files.len(),
        args.database
    );

    let mut conn = Connection::open(&args.database)?;
    apply_speed_pragmas(&conn)?;
    ensure_table(&conn)?;

    let batch_size = args.batch_size.max(1);
    let report_every = Duration::from_secs_f64(args.report_every.max(0.1));
    let mut last_report = Instant::now();
    let start = Instant::now();

    let mut inserted: usize = 0;
    let mut buffer: Vec<(String, i64, [u8; 32])> = Vec::with_capacity(batch_size);

    for shard in shard_files {
        let file = File::open(&shard)
            .map_err(|e| format!("open shard {shard:?} failed: {e}"))?;
        for line in BufReader::new(file).lines() {
            let addr = line?;
            if addr.trim().is_empty() {
                continue;
            }
            let norm = normalize_addr(&addr);
            let h = hash_leaf(&addr)?;
            buffer.push((norm, inserted as i64, h));
            inserted += 1;

            if buffer.len() >= batch_size {
                flush_batch(&mut conn, &mut buffer)?;
            }

            if last_report.elapsed() >= report_every {
                let rate = inserted as f64 / start.elapsed().as_secs_f64().max(0.001);
                eprintln!(
                    "{} rows | {:.0} rows/s | elapsed {:.1}s",
                    inserted,
                    rate,
                    start.elapsed().as_secs_f64()
                );
                last_report = Instant::now();
            }
        }
    }

    if !buffer.is_empty() {
        flush_batch(&mut conn, &mut buffer)?;
    }

    eprintln!("Creating index ...");
    create_index(&conn)?;

    let elapsed = start.elapsed().as_secs_f64();
    let rate = inserted as f64 / elapsed.max(0.001);
    eprintln!(
        "Completed: {} rows in {:.1}s ({:.0} rows/s)",
        inserted, elapsed, rate
    );
    Ok(())
}

fn flush_batch(
    conn: &mut Connection,
    buffer: &mut Vec<(String, i64, [u8; 32])>,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR IGNORE INTO address_index(address, leaf_idx, leaf_hash) VALUES (?1, ?2, ?3)",
        )?;
        for (addr, idx, hash) in buffer.iter() {
            stmt.execute(params![addr, idx, &hash[..]])?;
        }
    }
    tx.commit()?;
    buffer.clear();
    Ok(())
}
