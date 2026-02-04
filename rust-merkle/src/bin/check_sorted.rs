use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use rust_merkle::ADDRESS_SIZE;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "check-sorted",
    about = "Full-scan verify addresses.bin is globally sorted"
)]
struct Args {
    /// Path to addresses.bin (20 bytes per address, leaf order).
    #[arg(long, default_value = "out-rs/addresses.bin")]
    addresses: PathBuf,

    /// Chunk size in number of addresses to read per iteration.
    #[arg(long, default_value_t = 10_000)]
    chunk: usize,
}

/// Verifies that an addresses.bin file is globally sorted in ascending order.
fn main() -> Result<()> {
    let args = Args::parse();

    if !args.addresses.exists() {
        return Err(format!(
            "addresses file does not exist: {}",
            args.addresses.display()
        )
        .into());
    }

    let meta = std::fs::metadata(&args.addresses)?;
    let len = meta.len();
    if len % ADDRESS_SIZE as u64 != 0 {
        return Err(format!(
            "addresses.bin length {} is not a multiple of {} bytes",
            len, ADDRESS_SIZE
        )
        .into());
    }
    let total_addrs = (len / ADDRESS_SIZE as u64) as usize;
    println!(
        "Checking {} addresses in {} ({} bytes)…",
        total_addrs,
        args.addresses.display(),
        len
    );

    if total_addrs == 0 {
        println!("OK: file is empty");
        return Ok(());
    }

    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template("{bar:40.cyan/blue} {bytes}/{total_bytes} [{eta}]")?
            .progress_chars("##-"),
    );

    let mut reader = BufReader::new(File::open(&args.addresses)?);
    let buf_size = args
        .chunk
        .checked_mul(ADDRESS_SIZE)
        .ok_or("chunk size overflow")?;
    let mut buf = vec![0u8; buf_size];
    let mut prev: Option<[u8; ADDRESS_SIZE]> = None;
    let mut index: usize = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if n % ADDRESS_SIZE != 0 {
            return Err(format!(
                "read {} bytes which is not a multiple of {} (corrupt file?)",
                n, ADDRESS_SIZE
            )
            .into());
        }
        let count = n / ADDRESS_SIZE;
        for i in 0..count {
            let start = i * ADDRESS_SIZE;
            let end = start + ADDRESS_SIZE;
            let mut current = [0u8; ADDRESS_SIZE];
            current.copy_from_slice(&buf[start..end]);
            if let Some(p) = prev {
                if p.cmp(&current) == Ordering::Greater {
                    pb.finish_and_clear();
                    return Err(format!(
                        "not sorted at index {} -> {} (0x{} > 0x{})",
                        index - 1,
                        index,
                        hex::encode(p),
                        hex::encode(current)
                    )
                    .into());
                }
            }
            prev = Some(current);
            index += 1;
        }
        pb.inc(n as u64);
    }

    pb.finish_and_clear();
    println!("OK: {} addresses sorted ascending", total_addrs);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_size() {
        assert_eq!(ADDRESS_SIZE, 20);
    }
}
