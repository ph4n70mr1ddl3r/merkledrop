use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

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

fn main() -> Result<()> {
    let args = Args::parse();
    let meta = std::fs::metadata(&args.addresses)?;
    let len = meta.len();
    if len % 20 != 0 {
        return Err(format!("addresses.bin length {} is not a multiple of 20 bytes", len).into());
    }
    let total_addrs = (len / 20) as usize;
    println!(
        "Checking {} addresses in {} ({} bytes)…",
        total_addrs,
        args.addresses.display(),
        len
    );

    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template("{bar:40.cyan/blue} {bytes}/{total_bytes} [{eta}]")?
            .progress_chars("##-"),
    );

    let mut reader = BufReader::new(File::open(&args.addresses)?);
    let mut buf = vec![0u8; args.chunk * 20];
    let mut prev: Option<[u8; 20]> = None;
    let mut index: usize = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if n % 20 != 0 {
            return Err(format!(
                "read {} bytes which is not a multiple of 20 (corrupt file?)",
                n
            )
            .into());
        }
        let count = n / 20;
        for i in 0..count {
            let start = i * 20;
            let end = start + 20;
            let mut current = [0u8; 20];
            current.copy_from_slice(&buf[start..end]);
            if let Some(p) = prev {
                match p.cmp(&current) {
                    Ordering::Greater => {
                        pb.finish_and_clear();
                        return Err(
                            format!("not sorted at index {} -> {}", index - 1, index).into()
                        );
                    }
                    _ => {}
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
