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

    /// Address map (20 bytes per address in leaf order). Defaults to meta.addressMap if present.
    #[arg(long, default_value = "out-rs/addresses.bin")]
    address_map: PathBuf,

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
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let meta: Meta = serde_json::from_reader(reader)?;
    Ok(meta)
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

fn resolve_address_map(args: &Args, meta: &Meta, layers_dir: &Path) -> Result<PathBuf> {
    if let Some(name) = &meta.address_map {
        Ok(layers_dir.join(name))
    } else {
        Ok(args.address_map.clone())
    }
}

fn find_index_from_map(target: &[u8; 20], path: &Path) -> Result<usize> {
    let mut file = File::open(path)
        .map_err(|e| format!("failed to open address map {}: {}", path.display(), e))?;
    let len = file.metadata()?.len();
    if len % 20 != 0 {
        return Err(format!("address map length {} is not a multiple of 20 bytes", len).into());
    }
    let mut lo: i64 = 0;
    let mut hi: i64 = (len / 20) as i64 - 1;
    let mut buf = [0u8; 20];

    while lo <= hi {
        let mid = lo + ((hi - lo) / 2);
        let offset = mid as u64 * 20;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;
        match buf.cmp(target) {
            std::cmp::Ordering::Equal => return Ok(mid as usize),
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid - 1,
        }
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
