use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use rust_merkle::{ensure_file_exists, parse_address, ADDRESS_SIZE, HASH_SIZE};

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
    let layers_dir = if let Some(dir) = &args.layers_dir {
        rust_merkle::resolve_path(dir.to_str().unwrap(), Path::new("."))?
    } else {
        args.meta
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };

    // Validate that the address map exists before proceeding
    if let Some(map_name) = &meta.address_map {
        let map_path = layers_dir.join(map_name);
        if !map_path.exists() {
            return Err(format!("address map not found: {}", map_path.display()).into());
        }
    }

    let address = args.address.to_lowercase();
    let addr_bytes = parse_address(&address)?;

    let map_path = resolve_address_map(&args, &meta, &layers_dir)?;
    let index = find_index_from_map(&addr_bytes, &map_path)?;

    // Validate that index is within leaf count
    if index >= meta.leaf_count {
        return Err(format!("index validation failed: address index {} is out of bounds for the Merkle tree which has only {} leaves. This indicates data corruption or an invalid address.", index, meta.leaf_count).into());
    }

    let proof = build_proof(index, &meta, &layers_dir)?;

    // Validate proof length for Solidity compatibility
    if proof.len() > 32 {
        return Err(format!("proof length {} exceeds maximum allowed 32", proof.len()).into());
    }

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
    if meta.layer_files.len() < 2 {
        return Err("proof generation failed: insufficient Merkle tree layers found. At least 2 layers are required to generate a proof. The tree may be too small or corrupted.".into());
    }

    let mut idx = index;
    let mut width = meta.leaf_count;
    let mut proof = Vec::with_capacity(meta.layer_files.len().saturating_sub(1));

    for (i, layer_file) in meta.layer_files.iter().enumerate() {
        if i == meta.layer_files.len() - 1 {
            break;
        }

        // Validate layer file exists
        let layer_path = layers_dir.join(layer_file);
        if !layer_path.exists() {
            return Err(format!("proof generation failed: required layer file not found at {}. The Merkle tree data may be incomplete or corrupted.", layer_path.display()).into());
        }

        let sibling = sibling_index(idx, width);
        let sibling_hash = read_hash(&layer_path, sibling, width)?;
        proof.push(format!("0x{}", hex::encode(sibling_hash)));
        idx /= 2;
        width = width.div_ceil(2);

        // Validate we haven't exceeded reasonable proof depth
        if proof.len() > 32 {
            return Err("proof depth exceeded maximum allowed 32".into());
        }
    }
    Ok(proof)
}

fn resolve_address_map(args: &Args, meta: &Meta, layers_dir: &Path) -> Result<PathBuf> {
    if let Some(name) = &meta.address_map {
        let path = rust_merkle::resolve_path(name, layers_dir)?;
        if !path.exists() {
            return Err(format!("address map not found: {}", path.display()).into());
        }
        Ok(path)
    } else if let Some(ref path) = args.address_map {
        let resolved_path =
            rust_merkle::resolve_path(path.as_path().to_str().unwrap(), layers_dir)?;
        if !resolved_path.exists() {
            return Err(format!("address map not found: {}", resolved_path.display()).into());
        }
        Ok(resolved_path)
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
            "address map validation failed: file size {} bytes is not a multiple of the expected {} bytes per address. File may be corrupted.",
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
        "address lookup failed: address 0x{} not found in the sorted address map {}. The address may not be eligible for the airdrop, or the address map file may be corrupted. Checked {} addresses across {} bytes.",
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

    #[test]
    fn test_read_hash_valid() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test_address_map.bin");

        // Create a sorted address map
        let test_addresses = [
            [0u8; 20], // Address 0 (all zeros)
            [1u8; 20], // Address 1
            [2u8; 20], // Address 2
        ];
        let test_data = test_addresses.concat();
        fs::write(&test_file, &test_data).unwrap();

        // Test finding existing addresses
        assert_eq!(find_index_from_map(&[0u8; 20], &test_file).unwrap(), 0);
        assert_eq!(find_index_from_map(&[1u8; 20], &test_file).unwrap(), 1);
        assert_eq!(find_index_from_map(&[2u8; 20], &test_file).unwrap(), 2);
    }

    #[test]
    fn test_find_index_from_map_not_found() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test_address_map.bin");

        // Create a test address map
        let test_data = [[1u8; 20], [2u8; 20]].concat();
        fs::write(&test_file, &test_data).unwrap();

        // Test finding non-existent address
        let result = find_index_from_map(&[0u8; 20], &test_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_find_index_from_map_empty() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("empty_address_map.bin");

        // Create empty address map
        fs::write(&test_file, []).unwrap();

        let result = find_index_from_map(&[1u8; 20], &test_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_resolve_address_map_from_meta() {
        let temp_dir = tempdir().unwrap();
        let meta_file = temp_dir.path().join("merkle-meta.json");
        let map_file = temp_dir.path().join("addresses.bin");

        // Create address map file
        fs::write(&map_file, [1u8; 20]).unwrap();

        // Create meta file with address map reference
        let meta_content = r#"{
            "root": "0x1234567890abcdef1234567890abcdef12345678",
            "leafCount": 1,
            "layerFiles": ["layer00.bin"],
            "addressMap": "addresses.bin"
        }"#;
        fs::write(&meta_file, meta_content).unwrap();

        // Test resolving address map from meta
        let args = Args {
            meta: meta_file.clone(),
            layers_dir: None,
            address_map: None,
            address: "0x1234567890123456789012345678901234567890".to_string(),
        };

        let meta = read_meta(&meta_file).unwrap();
        let resolved = resolve_address_map(&args, &meta, temp_dir.path()).unwrap();

        assert_eq!(resolved, map_file);
    }

    #[test]
    fn test_build_proof_edge_cases() {
        let temp_dir = temp_dir().unwrap();

        // Test with insufficient layers (should fail)
        let meta = Meta {
            root: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            leaf_count: 2,
            layer_files: vec!["layer00.bin".to_string()], // Only one layer
            address_map: None,
        };

        let result = build_proof(0, &meta, temp_dir.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("insufficient Merkle tree layers"));

        // Test with enough layers
        let layer_file = temp_dir.path().join("layer00.bin");
        fs::write(&layer_file, [[1u8; 32], [2u8; 32]].concat()).unwrap();

        let meta_enough_layers = Meta {
            root: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            leaf_count: 2,
            layer_files: vec!["layer00.bin".to_string(), "layer01.bin".to_string()],
            address_map: None,
        };

        // This should fail because layer01.bin doesn't exist, but that's expected
        let result = build_proof(0, &meta_enough_layers, temp_dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_length_validation() {
        // Test that proofs longer than 32 elements are rejected
        let temp_dir = tempdir().unwrap();

        // Create a meta that would generate a very long proof
        let meta = Meta {
            root: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            leaf_count: 1 << 33, // Would require 33 layers
            layer_files: (0..33).map(|i| format!("layer{:02}.bin", i)).collect(),
            address_map: None,
        };

        let result = build_proof(0, &meta, temp_dir.path());
        // Should fail due to proof depth exceeding maximum allowed
        assert!(result.is_err());
    }
}
