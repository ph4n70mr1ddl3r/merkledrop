use clap::Parser;
use rusqlite::{params, Connection};
use chrono::Utc;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tiny_keccak::{Hasher, Keccak};

#[derive(Parser, Debug)]
#[command(about = "Build a Merkle tree from shards into merkle.db (nodes + meta).")]
struct Args {
    /// SQLite database to create/overwrite
    #[arg(long, default_value = "merkle.db")]
    database: PathBuf,

    /// Directory containing shard files
    #[arg(long, default_value = "shards")]
    shard_dir: PathBuf,

    /// Manifest file listing shard filenames in order
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Nodes per batch insert/commit
    #[arg(long, default_value_t = 50_000)]
    batch_size: usize,

    /// Seconds between progress logs
    #[arg(long, default_value_t = 5.0)]
    report_every: f64,
}

fn normalize_addr(addr: &str) -> &str {
    let mut a = addr.trim();
    if let Some(stripped) = a.strip_prefix("0x").or_else(|| a.strip_prefix("0X")) {
        a = stripped;
    }
    a
}

fn hash_leaf(addr: &str) -> Result<[u8; 32], String> {
    let norm = normalize_addr(addr);
    let raw = hex::decode(norm).map_err(|e| format!("decode {addr}: {e}"))?;
    if raw.len() != 20 {
        return Err(format!("address must be 20 bytes: {addr}"));
    }
    Ok(keccak256(&raw))
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn hash_pair(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(left.len() + right.len());
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    keccak256(&buf)
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
        PRAGMA temp_store = MEMORY;
        PRAGMA locking_mode = EXCLUSIVE;
        PRAGMA mmap_size = 1073741824;
        PRAGMA cache_size = -524288;
        PRAGMA foreign_keys = OFF;
    "#,
    )
}

fn ensure_tables(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS nodes (
            level INTEGER NOT NULL,
            idx   INTEGER NOT NULL,
            hash  BLOB NOT NULL,
            PRIMARY KEY (level, idx)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        ) WITHOUT ROWID;
    "#,
    )
}

fn store_meta(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

fn build_leaves(
    conn: &mut Connection,
    shards: &[PathBuf],
    batch_size: usize,
    report_every: Duration,
) -> Result<usize, Box<dyn std::error::Error>> {
    conn.execute("DELETE FROM nodes", [])?;
    let mut inserted: usize = 0;
    let mut batch = Vec::with_capacity(batch_size);
    let start = Instant::now();
    let mut last = start;

    eprintln!(
        "Reading shards ({} files) and hashing leaves...",
        shards.len()
    );
    for shard in shards {
        let file = File::open(shard)?;
        for line in BufReader::new(file).lines() {
            let addr = line?;
            if addr.trim().is_empty() {
                continue;
            }
            let h = hash_leaf(&addr)?;
            batch.push((0_i64, inserted as i64, h));
            inserted += 1;

            if batch.len() >= batch_size {
                flush_batch(conn, &batch)?;
                batch.clear();
            }

            if last.elapsed() >= report_every {
                eprintln!(
                    "Leaves processed: {} | {:.0} rows/s",
                    inserted,
                    inserted as f64 / start.elapsed().as_secs_f64().max(0.001)
                );
                last = Instant::now();
            }
        }
    }

    if !batch.is_empty() {
        flush_batch(conn, &batch)?;
    }

    eprintln!("Finished leaves: {} accounts", inserted);
    Ok(inserted)
}

fn flush_batch(
    conn: &mut Connection,
    batch: &[(i64, i64, [u8; 32])],
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO nodes (level, idx, hash) VALUES (?1, ?2, ?3)",
        )?;
        for (level, idx, hash) in batch {
            stmt.execute(params![level, idx, &hash[..]])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn build_level(
    conn: &mut Connection,
    level: i64,
    count: usize,
    batch_size: usize,
    report_every: Duration,
) -> Result<usize, Box<dyn std::error::Error>> {
    let parent_level = level + 1;
    let mut batch = Vec::with_capacity(batch_size);
    let mut parent_idx: usize = 0;
    let mut processed: usize = 0;
    let start = Instant::now();
    let mut last = start;

    eprintln!(
        "Building level {} from {} node(s)...",
        parent_level, count
    );

    let mut pending: Option<[u8; 32]> = None;
    let chunk_size = batch_size.saturating_mul(4).max(10_000);
    let mut offset: usize = 0;
    while offset < count {
        let upper = usize::min(offset + chunk_size, count);
        let mut stmt = conn.prepare(
            "SELECT hash FROM nodes WHERE level = ? AND idx >= ? AND idx < ? ORDER BY idx ASC",
        )?;
        let mut rows = stmt.query(params![level, offset as i64, upper as i64])?;
        while let Some(row) = rows.next()? {
            let hash: Vec<u8> = row.get(0)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);

            if let Some(left) = pending.take() {
                let parent_hash = hash_pair(&left, &arr);
                batch.push((parent_level, parent_idx as i64, parent_hash));
                parent_idx += 1;
                processed += 2;
            } else {
                pending = Some(arr);
            }
        }
        drop(rows);
        drop(stmt);

        if batch.len() >= batch_size {
            flush_batch(conn, &batch)?;
            batch.clear();
        }

        if last.elapsed() >= report_every {
            let pct = processed as f64 / count as f64 * 100.0;
            eprintln!(
                "Level {}: {:5.1}% ({}/{})",
                parent_level, pct, processed, count
            );
            last = Instant::now();
        }

        offset = upper;
    }

    if let Some(last_hash) = pending {
        let dup = hash_pair(&last_hash, &last_hash);
        batch.push((parent_level, parent_idx as i64, dup));
        parent_idx += 1;
    }

    if !batch.is_empty() {
        flush_batch(conn, &batch)?;
    }

    eprintln!("Level {} complete: {} node(s)", parent_level, parent_idx);
    Ok(parent_idx)
}

fn build_tree(
    conn: &mut Connection,
    leaf_count: usize,
    batch_size: usize,
    report_every: Duration,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut level: i64 = 0;
    let mut count = leaf_count;
    while count > 1 {
        count = build_level(conn, level, count, batch_size, report_every)?;
        level += 1;
    }

    let root: Vec<u8> = conn.query_row(
        "SELECT hash FROM nodes WHERE level = ? AND idx = 0",
        params![level],
        |row| row.get(0),
    )?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&root);
    Ok(out)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let manifest_path = args
        .manifest
        .clone()
        .unwrap_or_else(|| args.shard_dir.join("manifest.txt"));
    let shards = load_manifest(&manifest_path)?;

    let report_every = Duration::from_secs_f64(args.report_every.max(0.1));
    let batch_size = args.batch_size.max(1);

    let mut conn = Connection::open(&args.database)?;
    apply_speed_pragmas(&conn)?;
    ensure_tables(&conn)?;
    store_meta(&conn, "hash_function", "keccak256-tiny-keccak")?;
    store_meta(&conn, "shard_dir", &args.shard_dir.to_string_lossy())?;
    store_meta(&conn, "manifest", &manifest_path.to_string_lossy())?;

    eprintln!("Hash function: keccak256-tiny-keccak");
    let start = Instant::now();
    let leaf_count = build_leaves(&mut conn, &shards, batch_size, report_every)?;
    let root = build_tree(&mut conn, leaf_count, batch_size, report_every)?;
    let elapsed = start.elapsed().as_secs_f64();

    store_meta(&conn, "leaf_count", &leaf_count.to_string())?;
    store_meta(&conn, "root_hex", &hex::encode(root))?;
    store_meta(
        &conn,
        "built_at",
        &Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )?;
    conn.close().ok();

    println!("Merkle root: {}", hex::encode(root));
    println!("Accounts included: {}", leaf_count);
    println!("Elapsed: {:.1}s", elapsed);
    Ok(())
}
