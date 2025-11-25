use clap::Parser;
use serde::Serialize;
use sha3::{Digest, Keccak256};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "rust-merkle",
    about = "Build a Merkle tree over binary files or address shards"
)]
struct Args {
    /// Manifest file with newline-separated paths (processed in order).
    #[arg(long, default_value = "shards/manifest.txt")]
    manifest: Option<PathBuf>,

    /// Base directory to resolve manifest entries (ignored for absolute paths).
    #[arg(long, default_value = "shards")]
    base: PathBuf,

    /// Treat inputs as newline-delimited Ethereum addresses and hash (index,address).
    #[arg(long, default_value_t = true)]
    address_lines: bool,

    /// When --address-lines is set, write a 20-byte-per-leaf mapping file in leaf order.
    #[arg(long, default_value = "addresses.bin")]
    address_map: String,

    /// Output directory for layer files and metadata.
    #[arg(long, default_value = "out-rs")]
    out: PathBuf,

    /// Prefix for layer file names (layer0.bin, layer1.bin, ...).
    #[arg(long, default_value = "layer")]
    layer_prefix: String,

    /// Log progress every N leaves (0 disables).
    #[arg(long, default_value_t = 1_000_000)]
    log_interval: usize,

    /// Additional files to include as leaves (after manifest, if provided).
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    root: String,
    leaf_count: usize,
    hash_fn: String,
    leaf_encoding: String,
    pair_ordering: String,
    layer_files: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_map: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out)?;

    let layer0_name = format!("{}{:02}.bin", args.layer_prefix, 0);
    let layer0_path = args.out.join(&layer0_name);

    let mut leaf_count = 0usize;
    let started_at = std::time::Instant::now();

    if args.address_lines {
        let address_map_path = args.out.join(&args.address_map);
        let addrs_written = write_addresses(&args, &address_map_path)?;
        if addrs_written == 0 {
            return Err("No addresses written; provide files or a manifest".into());
        }
        leaf_count = addrs_written;
        println!(
            "Wrote {} addresses to {} in {:.2}s",
            leaf_count,
            address_map_path.display(),
            started_at.elapsed().as_secs_f64()
        );
        build_layer0_from_addresses(&address_map_path, &layer0_path, leaf_count, &args)?;
    } else {
        leaf_count = build_layer0_from_files(&args, &layer0_path)?;
    }

    println!(
        "Finished layer0: {} leaves in {:.2}s",
        leaf_count,
        started_at.elapsed().as_secs_f64()
    );

    let mut layer_files = vec![layer0_name];
    let mut current_path = layer0_path;
    let mut width = leaf_count;
    let mut layer = 0usize;

    while width > 1 {
        let next_layer = layer + 1;
        let next_name = format!("{}{:02}.bin", args.layer_prefix, next_layer);
        let next_path = args.out.join(&next_name);
        let parents = build_parent_layer(&current_path, width, &next_path)?;
        println!(
            "Built layer{} ({} nodes) from layer{} ({} leaves)",
            next_layer, parents, layer, width
        );
        layer_files.push(next_name);
        current_path = next_path;
        width = parents;
        layer = next_layer;
    }

    let root = read_first_hash(&current_path)?;
    let root_hex = to_hex(&root);
    println!("Merkle root: {}", root_hex);

    let meta = Meta {
        root: root_hex,
        leaf_count,
        hash_fn: "keccak256".to_string(),
        leaf_encoding: if args.address_lines {
            "abi.encodePacked(index,address)".to_string()
        } else {
            "keccak256(file_bytes)".to_string()
        },
        pair_ordering: "sorted".to_string(),
        layer_files,
        address_map: if args.address_lines {
            Some(args.address_map.clone())
        } else {
            None
        },
    };

    let meta_path = args.out.join("merkle-meta.json");
    let meta_json = serde_json::to_vec_pretty(&meta)?;
    fs::write(&meta_path, meta_json)?;
    println!("Wrote {}", meta_path.display());

    Ok(())
}

fn write_addresses(args: &Args, map_path: &Path) -> Result<usize> {
    let mut writer = BufWriter::new(File::create(map_path)?);
    let mut count = 0usize;

    if let Some(manifest) = &args.manifest {
        let file = File::open(manifest)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let path = resolve_path(trimmed, &args.base);
            count = write_addresses_from_file(&path, &mut writer, args.log_interval, count)?;
        }
    }

    for file in &args.files {
        count = write_addresses_from_file(file, &mut writer, args.log_interval, count)?;
    }

    writer.flush()?;
    Ok(count)
}

fn write_addresses_from_file(
    path: &Path,
    writer: &mut BufWriter<File>,
    log_interval: usize,
    mut count: usize,
) -> Result<usize> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let addr_str = line.trim();
        if addr_str.is_empty() {
            continue;
        }
        let addr = parse_address(addr_str)?;
        writer.write_all(&addr)?;
        count += 1;
        if log_interval > 0 && count % log_interval == 0 {
            println!("Addresses written: {}", count);
        }
    }
    Ok(count)
}

fn build_layer0_from_addresses(
    address_map: &Path,
    layer0_path: &Path,
    leaf_count: usize,
    args: &Args,
) -> Result<()> {
    let mut reader = BufReader::new(File::open(address_map)?);
    let mut writer = BufWriter::new(File::create(layer0_path)?);
    let mut buf = vec![0u8; 20 * 4096];
    let mut index = 0usize;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if n % 20 != 0 {
            return Err("address map read not aligned to 20 bytes".into());
        }
        let addrs = n / 20;
        for i in 0..addrs {
            let start = i * 20;
            let end = start + 20;
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&buf[start..end]);
            let leaf = hash_index_address(index, &addr);
            writer.write_all(&leaf)?;
            index += 1;
            if args.log_interval > 0 && index % args.log_interval == 0 {
                println!("Hashed {} leaves into layer0", index);
            }
        }
    }

    writer.flush()?;
    if index != leaf_count {
        return Err(format!(
            "leaf count mismatch: expected {}, wrote {}",
            leaf_count, index
        )
        .into());
    }
    Ok(())
}

fn build_layer0_from_files(args: &Args, layer0_path: &Path) -> Result<usize> {
    let mut writer = BufWriter::new(File::create(layer0_path)?);
    let mut count = 0usize;

    if let Some(manifest) = &args.manifest {
        let file = File::open(manifest)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let path = resolve_path(trimmed, &args.base);
            count = hash_file_into(&path, &mut writer, args.log_interval, count)?;
        }
    }

    for file in &args.files {
        count = hash_file_into(file, &mut writer, args.log_interval, count)?;
    }

    writer.flush()?;
    Ok(count)
}

fn hash_file_into(
    path: &Path,
    writer: &mut BufWriter<File>,
    log_interval: usize,
    mut count: usize,
) -> Result<usize> {
    let leaf = hash_file(path)?;
    writer.write_all(&leaf)?;
    count += 1;
    if log_interval > 0 && count % log_interval == 0 {
        println!("Processed {} leaves", count);
    }
    Ok(count)
}

fn resolve_path(entry: &str, base: &Path) -> PathBuf {
    let p = PathBuf::from(entry);
    if p.is_absolute() {
        p
    } else {
        base.join(p)
    }
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Keccak256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn parse_address(s: &str) -> Result<[u8; 20]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s).to_lowercase();
    if trimmed.len() != 40 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Invalid address: {}", s).into());
    }
    let bytes = hex::decode(trimmed)?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hash_index_address(index: usize, address: &[u8; 20]) -> [u8; 32] {
    let mut idx_bytes = [0u8; 32];
    idx_bytes[24..32].copy_from_slice(&(index as u64).to_be_bytes());
    let mut hasher = Keccak256::new();
    hasher.update(&idx_bytes);
    hasher.update(address);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn build_parent_layer(prev: &Path, width: usize, out: &Path) -> Result<usize> {
    let mut reader = BufReader::new(File::open(prev)?);
    let mut writer = BufWriter::new(File::create(out)?);

    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    let mut parents = 0usize;
    let mut i = 0usize;

    while i < width {
        reader.read_exact(&mut left)?;
        if i + 1 < width {
            reader.read_exact(&mut right)?;
        } else {
            right.copy_from_slice(&left); // duplicate last
        }
        let parent = hash_pair(&left, &right);
        writer.write_all(&parent)?;
        parents += 1;
        i += 2;
    }

    writer.flush()?;
    Ok(parents)
}

fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = Keccak256::new();
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn read_first_hash(path: &Path) -> Result<[u8; 32]> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut buf = [0u8; 32];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
