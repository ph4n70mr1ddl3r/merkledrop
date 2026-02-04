use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use rust_merkle::{parse_address, ADDRESS_SIZE, HASH_SIZE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "merkle-proof",
    about = "Generate a Merkle proof for an address"
)]
struct Args {
    /// Path to merkle-meta.json
    #[arg(long, default_value = "out-rs/merkle-meta.json")]
    meta: PathBuf,

    /// Directory containing layer files; defaults to meta's parent.
    #[arg(long)]
    layers_dir: Option<PathBuf>,

    /// Address map (20 bytes per address in leaf order). Defaults to meta.addressMap if present.
    #[arg(long)]
    address_map: Option<PathBuf>,

    /// Address to generate a proof for.
    #[arg(long)]
    address: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    root: String,
    leaf_count: usize,
    layer_files: Vec<String>,
    #[serde(rename = "addressMap")]
    address_map: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let meta: Meta = read_meta(&args.meta)?;
    let layers_dir = args.layers_dir.clone().unwrap_or_else(|| {
        args.meta
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });

    let address = args.address.to_lowercase();
    let addr_bytes = parse_address(&address)?;

    let map_path = resolve_address_map(&args, &meta, &layers_dir)?;
    let index = find_index_from_map(&addr_bytes, &map_path)?;
    let proof = build_proof(index, &meta, &layers_dir)?;

    println!("address: {address}");
    println!("index: {}", index);
    println!("root: {}", meta.root);
    println!("proof:");
    for p in proof {
        println!("  {p}");
    }
    Ok(())
}

fn read_meta(path: &Path) -> Result<Meta> {
    if !path.exists() {
        return Err(format!("meta file does not exist: {}", path.display()).into());
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let meta: Meta = serde_json::from_reader(reader)?;
    Ok(meta)
}

/// Builds a Merkle proof for the given leaf index by traversing the tree layers.
fn build_proof(index: usize, meta: &Meta, layers_dir: &Path) -> Result<Vec<String>> {
    let mut idx = index;
    let mut width = meta.leaf_count;
    let mut proof = Vec::with_capacity(meta.layer_files.len().saturating_sub(1));

    for (i, layer_file) in meta.layer_files.iter().enumerate() {
        if i == meta.layer_files.len() - 1 {
            break;
        }
        let sibling = sibling_index(idx, width);
        let sibling_hash = read_hash(&layers_dir.join(layer_file), sibling, width)?;
        proof.push(format!("0x{}", hex::encode(sibling_hash)));
        idx /= 2;
        width = width.div_ceil(2);
    }
    Ok(proof)
}

fn resolve_address_map(args: &Args, meta: &Meta, layers_dir: &Path) -> Result<PathBuf> {
    if let Some(name) = &meta.address_map {
        Ok(layers_dir.join(name))
    } else if let Some(ref path) = args.address_map {
        Ok(path.clone())
    } else {
        Err("no address map provided and none found in metadata".into())
    }
}

/// Binary searches the address map to find the index of a target address.
fn find_index_from_map(target: &[u8; ADDRESS_SIZE], path: &Path) -> Result<usize> {
    ensure_file_exists(path, "address map")?;

    let mut file = File::open(path)
        .map_err(|e| format!("failed to open address map {}: {}", path.display(), e))?;
    let len = file.metadata()?.len();
    if len % ADDRESS_SIZE as u64 != 0 {
        return Err(format!(
            "address map length {} is not a multiple of {} bytes",
            len, ADDRESS_SIZE
        )
        .into());
    }

    let count = (len / ADDRESS_SIZE as u64) as usize;
    if count == 0 {
        return Err(format!("address map {} is empty", path.display()).into());
    }

    let mut lo: i64 = 0;
    let mut hi: i64 = count as i64 - 1;
    let mut buf = [0u8; ADDRESS_SIZE];

    while lo <= hi {
        let mid = lo + ((hi - lo) / 2);
        let offset = mid as u64 * ADDRESS_SIZE as u64;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;
        match buf.cmp(target) {
            std::cmp::Ordering::Equal => return Ok(mid as usize),
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid - 1,
        }
    }

    Err(format!(
        "address 0x{} not found in address map {} (checked {} addresses, file size {} bytes)",
        hex::encode(target),
        path.display(),
        count,
        len
    )
    .into())
}

/// Reads a single hash from a layer file at the specified index.
/// Ensures the index is within the layer's width before seeking.
fn read_hash(path: &Path, index: usize, width: usize) -> Result<[u8; HASH_SIZE]> {
    ensure_file_exists(path, "layer file")?;

    if index >= width {
        return Err(format!(
            "index {} out of bounds for layer {} (width {})",
            index,
            path.display(),
            width
        )
        .into());
    }

    let mut file =
        File::open(path).map_err(|e| format!("failed to open layer {}: {}", path.display(), e))?;
    let offset = index * HASH_SIZE;
    file.seek(SeekFrom::Start(offset as u64)).map_err(|e| {
        format!(
            "failed to seek to offset {} (index {}) in {}: {}",
            offset,
            index,
            path.display(),
            e
        )
    })?;
    let mut buf = [0u8; HASH_SIZE];
    file.read_exact(&mut buf).map_err(|e| {
        format!(
            "failed to read hash at index {} from {}: {}",
            index,
            path.display(),
            e
        )
    })?;
    Ok(buf)
}

fn sibling_index(idx: usize, width: usize) -> usize {
    let sib = idx ^ 1;
    if sib < width {
        sib
    } else {
        idx
    }
}

/// Ensures a file exists, returning an error if it doesn't.
fn ensure_file_exists(path: &Path, description: &str) -> Result<()> {
    if !path.exists() {
        return Err(format!("{} does not exist: {}", description, path.display()).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sibling_index_even() {
        assert_eq!(sibling_index(0, 4), 1);
        assert_eq!(sibling_index(2, 4), 3);
        assert_eq!(sibling_index(10, 20), 11);
    }

    #[test]
    fn test_sibling_index_odd() {
        assert_eq!(sibling_index(1, 4), 0);
        assert_eq!(sibling_index(3, 4), 2);
        assert_eq!(sibling_index(11, 20), 10);
    }

    #[test]
    fn test_sibling_index_odd_width() {
        assert_eq!(sibling_index(2, 3), 2);
        assert_eq!(sibling_index(4, 5), 4);
    }
}
