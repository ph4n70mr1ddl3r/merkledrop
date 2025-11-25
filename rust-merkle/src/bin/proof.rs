use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

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

    /// Directory containing lookup shards (prefix-based JSON).
    #[arg(long, default_value = "out/lookup")]
    lookup_dir: PathBuf,

    /// Optional address map (20 bytes per address in leaf order). Defaults to meta.addressMap if present.
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

#[derive(Deserialize)]
struct LookupEntry {
    address: String,
    index: usize,
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

    // Prefer address map if provided or present in meta; otherwise use lookup shards.
    let index = if let Some(map_path) = resolve_address_map(&args, &meta, &layers_dir) {
        find_index_from_map(&addr_bytes, &map_path, meta.leaf_count)?
    } else {
        find_index_lookup(&address, &args.lookup_dir)?
    };
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
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let meta: Meta = serde_json::from_reader(reader)?;
    Ok(meta)
}

fn find_index_lookup(address: &str, lookup_dir: &Path) -> Result<usize> {
    if !address.starts_with("0x") || address.len() != 42 {
        return Err("address must be 0x-prefixed and 40 hex chars".into());
    }
    let shard = &address[2..6];
    let path = lookup_dir.join(format!("{shard}.json"));
    let file = File::open(&path)
        .map_err(|e| format!("failed to open lookup shard {}: {}", path.display(), e))?;
    let entries: Vec<LookupEntry> = serde_json::from_reader(BufReader::new(file))?;
    for entry in entries {
        if entry.address.to_lowercase() == address {
            return Ok(entry.index);
        }
    }
    Err(format!("address not found in shard {}", shard).into())
}

fn build_proof(index: usize, meta: &Meta, layers_dir: &Path) -> Result<Vec<String>> {
    let mut idx = index;
    let mut width = meta.leaf_count;
    let mut proof = Vec::with_capacity(meta.layer_files.len());

    for layer_file in &meta.layer_files {
        let sibling = sibling_index(idx, width);
        let sibling_hash = read_hash(layers_dir.join(layer_file), sibling)?;
        proof.push(format!("0x{}", hex::encode(sibling_hash)));
        idx /= 2;
        width = (width + 1) / 2;
    }
    Ok(proof)
}

fn parse_address(addr: &str) -> Result<[u8; 20]> {
    if !addr.starts_with("0x") || addr.len() != 42 {
        return Err("address must be 0x-prefixed and 40 hex chars".into());
    }
    let bytes = hex::decode(&addr[2..])?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_address_map(args: &Args, meta: &Meta, layers_dir: &Path) -> Option<PathBuf> {
    if let Some(path) = &args.address_map {
        return Some(path.clone());
    }
    if let Some(name) = &meta.address_map {
        return Some(layers_dir.join(name));
    }
    None
}

fn find_index_from_map(target: &[u8; 20], path: &Path, _leaf_count: usize) -> Result<usize> {
    let mut file = File::open(path)
        .map_err(|e| format!("failed to open address map {}: {}", path.display(), e))?;
    let mut buf = vec![0u8; 20 * 4096];
    let mut index = 0usize;
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let chunks = read / 20;
        for i in 0..chunks {
            let start = i * 20;
            let end = start + 20;
            if &buf[start..end] == target {
                return Ok(index + i);
            }
        }
        index += chunks;
    }
    Err(format!("address not found in address map {}", path.display()).into())
}

fn read_hash(path: PathBuf, index: usize) -> Result<[u8; 32]> {
    let mut file =
        File::open(&path).map_err(|e| format!("failed to open layer {}: {}", path.display(), e))?;
    let offset = index * 32;
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut buf = [0u8; 32];
    file.read_exact(&mut buf)?;
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
