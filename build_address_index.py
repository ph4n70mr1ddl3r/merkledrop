#!/usr/bin/env python3
"""
Populate address_index in merkle.db so proofs no longer need shard scans.

Reads shard files in manifest order, records address -> (leaf_idx, leaf_hash).
Safe to re-run; uses INSERT OR REPLACE. Progress is logged to stderr.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from pathlib import Path
from typing import List

from merkle_proof import hash_leaf, load_manifest, normalize_addr, read_addresses


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build address_index table mapping address -> leaf_idx/leaf_hash."
    )
    parser.add_argument(
        "--database",
        default="merkle.db",
        help="SQLite database containing the Merkle tree (default: merkle.db)",
    )
    parser.add_argument(
        "--shard-dir",
        default="shards",
        help="Directory containing shard files and manifest.txt (default: shards)",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Manifest file listing shard filenames in order (default: <shard-dir>/manifest.txt)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100_000,
        help="Number of rows per insert batch (default: 100,000)",
    )
    parser.add_argument(
        "--report-every",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Seconds between progress updates (default: 10.0)",
    )
    return parser.parse_args()


def ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS address_index (
            address   TEXT PRIMARY KEY,   -- lowercase hex, no 0x
            leaf_idx  INTEGER NOT NULL,
            leaf_hash BLOB NOT NULL
        )
        """
    )
    # Drop index before bulk insert for faster writes; recreate afterward.
    conn.execute("DROP INDEX IF EXISTS idx_address_index_leaf")


def build_index(
    conn: sqlite3.Connection,
    shard_files: List[Path],
    batch_size: int,
    report_every: float,
) -> None:
    ensure_table(conn)
    # Aggressive speed-oriented pragmas (safe for one-shot rebuilds).
    conn.execute("PRAGMA journal_mode = OFF")
    conn.execute("PRAGMA synchronous = OFF")
    conn.execute("PRAGMA locking_mode = EXCLUSIVE")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA mmap_size = 1073741824")  # 1 GiB mmap hint
    conn.execute("PRAGMA cache_size = -524288")  # ~512 MiB cache
    conn.execute("PRAGMA foreign_keys = OFF")

    cursor = conn.cursor()

    batch = []
    inserted = 0
    start = time.time()
    last_report = start

    for idx, addr in enumerate(read_addresses(shard_files)):
        batch.append((normalize_addr(addr), idx, hash_leaf(addr)))
        if len(batch) >= batch_size:
            cursor.executemany(
                "INSERT OR IGNORE INTO address_index(address, leaf_idx, leaf_hash) VALUES (?, ?, ?)",
                batch,
            )
            conn.commit()
            inserted += len(batch)
            batch.clear()
            now = time.time()
            if now - last_report >= max(0.5, report_every):
                rate = inserted / (now - start)
                print(
                    f"{inserted:,} rows inserted | {rate:,.0f} rows/s | elapsed {now - start:,.1f}s",
                    file=sys.stderr,
                )
                last_report = now

    if batch:
        cursor.executemany(
            "INSERT OR IGNORE INTO address_index(address, leaf_idx, leaf_hash) VALUES (?, ?, ?)",
            batch,
        )
        conn.commit()
        inserted += len(batch)

    # Build index after bulk load.
    print("Creating index idx_address_index_leaf ...", file=sys.stderr)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_address_index_leaf ON address_index(leaf_idx)"
    )
    conn.commit()

    duration = time.time() - start
    rate = inserted / duration if duration else 0
    print(
        f"Completed: {inserted:,} rows in {duration:,.1f}s ({rate:,.0f} rows/s)",
        file=sys.stderr,
    )


def main() -> None:
    args = parse_args()
    manifest_path = (
        Path(args.manifest) if args.manifest else Path(args.shard_dir) / "manifest.txt"
    )
    shard_files = load_manifest(manifest_path)
    conn = sqlite3.connect(args.database)
    try:
        build_index(conn, shard_files, args.batch_size, args.report_every)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
