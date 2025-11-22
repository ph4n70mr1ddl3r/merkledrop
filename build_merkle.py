#!/usr/bin/env python3
"""
Build a deterministic keccak256 Merkle tree from account shards and persist it to SQLite.

The tree is built in the exact order defined by shards/manifest.txt, emitting
progress updates as leaves and levels are processed. At completion, the script
prints the Merkle root and the number of accounts included.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from pathlib import Path
from typing import Callable, Iterable, Iterator, List, Optional, Tuple


# --- Minimal pure-Python keccak256 (Ethereum-compatible) --------------------

# Rotation offsets for keccak-f[1600]
_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_RC = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

_MASK_64 = (1 << 64) - 1


def _rotl64(x: int, n: int) -> int:
    return ((x << n) & _MASK_64) | (x >> (64 - n))


def _keccak_f(state: List[int]) -> None:
    for rc in _RC:
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]

        # Rho and Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y], _RHO[x][y])

        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])

        # Iota
        state[0] ^= rc


def keccak256_digest(data: bytes) -> bytes:
    """Keccak-256 with pad10*1 (Ethereum style)."""
    rate = 136  # bytes
    state = [0] * 25  # 5x5 lanes of 64 bits
    offset = 0
    # Absorb full blocks
    while offset + rate <= len(data):
        block = data[offset : offset + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[8 * i : 8 * (i + 1)], "little")
            state[i] ^= lane
        _keccak_f(state)
        offset += rate

    # Pad remaining bytes with 0x01 ... 0x80
    remaining = data[offset:]
    padded = bytearray(rate)
    padded[: len(remaining)] = remaining
    padded[len(remaining)] = 0x01
    padded[-1] |= 0x80
    for i in range(rate // 8):
        lane = int.from_bytes(padded[8 * i : 8 * (i + 1)], "little")
        state[i] ^= lane
    _keccak_f(state)

    # Squeeze digest
    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out.extend(state[i].to_bytes(8, "little"))
            if len(out) >= 32:
                break
        if len(out) >= 32:
            break
        _keccak_f(state)
    return bytes(out[:32])


def _resolve_keccak256() -> Tuple[str, Callable[[bytes], bytes]]:
    """
    Prefer fast keccak256 implementations if available, else fall back to the
    built-in pure Python version.
    """
    try:
        from sha3 import keccak_256  # type: ignore

        def digest(data: bytes) -> bytes:
            h = keccak_256()
            h.update(data)
            return h.digest()

        return "keccak256-pysha3", digest
    except Exception:
        pass

    try:
        # pycryptodomex (Cryptodome namespace)
        from Cryptodome.Hash import keccak  # type: ignore

        def digest(data: bytes) -> bytes:
            k = keccak.new(digest_bits=256)
            k.update(data)
            return k.digest()

        return "keccak256-pycryptodomex", digest
    except Exception:
        pass

    try:
        # pycryptodome (Crypto namespace) — less likely here but try.
        from Crypto.Hash import keccak  # type: ignore

        def digest(data: bytes) -> bytes:
            k = keccak.new(digest_bits=256)
            k.update(data)
            return k.digest()

        return "keccak256-pycryptodomex", digest
    except Exception:
        pass

    return "keccak256-purepython", keccak256_digest


# Deterministic hash function used for leaves and nodes (keccak256).
HASH_NAME, HASH_FUNC = _resolve_keccak256()


# --- Merkle construction ----------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a deterministic Merkle tree from shard files and store it in SQLite."
        )
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
        "--database",
        default="merkle.db",
        help="SQLite database file to store the tree (default: merkle.db)",
    )
    parser.add_argument(
        "--report-every",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Seconds between progress updates (default: 5.0)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50_000,
        help="Number of nodes to insert per transaction (default: 50,000)",
    )
    return parser.parse_args()


def load_manifest(manifest_path: Path) -> List[Path]:
    if not manifest_path.exists():
        sys.exit(f"Manifest not found: {manifest_path}")
    shard_files: List[Path] = []
    with open(manifest_path, "r", encoding="utf-8") as mf:
        for line in mf:
            name = line.strip()
            if not name:
                continue
            shard_files.append(manifest_path.parent / name)
    if not shard_files:
        sys.exit(f"No shard entries found in manifest: {manifest_path}")
    return shard_files


def hash_leaf(address: str) -> bytes:
    addr = address.strip()
    if addr.startswith("0x") or addr.startswith("0X"):
        addr = addr[2:]
    try:
        raw = bytes.fromhex(addr)
    except ValueError as exc:
        raise ValueError(f"Invalid hex address: {address!r}") from exc
    if len(raw) != 20:
        raise ValueError(f"Address must be 20 bytes: {address!r}")
    return HASH_FUNC(raw)


def hash_pair(left: bytes, right: bytes) -> bytes:
    return HASH_FUNC(left + right)


def init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    # Speed-oriented pragmas: disable journaling for this one-shot build, in-memory temp.
    conn.execute("PRAGMA journal_mode=OFF;")
    conn.execute("PRAGMA synchronous=OFF;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS nodes (
            level INTEGER NOT NULL,
            idx   INTEGER NOT NULL,
            hash  BLOB NOT NULL,
            PRIMARY KEY (level, idx)
        ) WITHOUT ROWID;
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        ) WITHOUT ROWID;
        """
    )
    return conn


def store_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
        (key, value),
    )


def read_addresses(shard_files: Iterable[Path]) -> Iterator[str]:
    for shard in shard_files:
        if not shard.exists():
            raise FileNotFoundError(f"Shard file missing: {shard}")
        with open(shard, "r", encoding="utf-8") as fh:
            for line in fh:
                addr = line.strip()
                if not addr:
                    continue
                yield addr


def insert_batch(
    conn: sqlite3.Connection, batch: List[Tuple[int, int, bytes]]
) -> None:
    conn.executemany(
        "INSERT OR REPLACE INTO nodes (level, idx, hash) VALUES (?, ?, ?)", batch
    )


def build_leaves(
    conn: sqlite3.Connection,
    shard_files: List[Path],
    batch_size: int,
    report_every: float,
) -> int:
    conn.execute("DELETE FROM nodes")
    leaf_idx = 0
    batch: List[Tuple[int, int, bytes]] = []
    last_report = time.time()

    print(
        f"Reading shards ({len(shard_files)} files) and hashing leaves...",
        file=sys.stderr,
    )

    for addr in read_addresses(shard_files):
        h = hash_leaf(addr)
        batch.append((0, leaf_idx, h))
        leaf_idx += 1

        if len(batch) >= batch_size:
            insert_batch(conn, batch)
            conn.commit()
            batch.clear()

        now = time.time()
        if now - last_report >= max(0.5, report_every):
            print(f"Leaves processed: {leaf_idx:,}", file=sys.stderr)
            last_report = now

    if batch:
        insert_batch(conn, batch)
        conn.commit()

    print(f"Finished leaves: {leaf_idx:,} accounts", file=sys.stderr)
    return leaf_idx


def iterate_level_hashes(
    conn: sqlite3.Connection, level: int
) -> Iterator[Tuple[int, bytes]]:
    cursor = conn.execute(
        "SELECT idx, hash FROM nodes WHERE level = ? ORDER BY idx ASC", (level,)
    )
    for idx, h in cursor:
        yield int(idx), h


def build_level(
    conn: sqlite3.Connection,
    level: int,
    count: int,
    batch_size: int,
    report_every: float,
) -> int:
    parent_level = level + 1
    batch: List[Tuple[int, int, bytes]] = []
    parent_idx = 0
    last_report = time.time()
    processed = 0

    print(
        f"Building level {parent_level} from {count:,} node(s)...",
        file=sys.stderr,
    )

    pending: Optional[Tuple[int, bytes]] = None
    for idx, h in iterate_level_hashes(conn, level):
        if pending is None:
            pending = (idx, h)
            continue

        left = pending[1]
        right = h
        parent_hash = hash_pair(left, right)
        batch.append((parent_level, parent_idx, parent_hash))
        parent_idx += 1
        processed += 2
        pending = None

        if len(batch) >= batch_size:
            insert_batch(conn, batch)
            conn.commit()
            batch.clear()

        now = time.time()
        if now - last_report >= max(0.5, report_every):
            pct = processed / count * 100 if count else 100.0
            print(
                f"Level {parent_level}: {pct:5.1f}% ({processed:,}/{count:,})",
                file=sys.stderr,
            )
            last_report = now

    if pending is not None:
        # Odd count: duplicate the last hash to keep tree deterministic.
        parent_hash = hash_pair(pending[1], pending[1])
        batch.append((parent_level, parent_idx, parent_hash))
        parent_idx += 1

    if batch:
        insert_batch(conn, batch)
        conn.commit()

    print(
        f"Level {parent_level} complete: {parent_idx:,} node(s)",
        file=sys.stderr,
    )
    return parent_idx


def build_tree(
    conn: sqlite3.Connection,
    leaf_count: int,
    batch_size: int,
    report_every: float,
) -> bytes:
    level = 0
    count = leaf_count
    while count > 1:
        count = build_level(conn, level, count, batch_size, report_every)
        level += 1

    cursor = conn.execute(
        "SELECT hash FROM nodes WHERE level = ? AND idx = 0", (level,)
    )
    row = cursor.fetchone()
    if row is None:
        raise RuntimeError("Failed to compute Merkle root.")
    return row[0]


def main() -> None:
    args = parse_args()
    shard_dir = Path(args.shard_dir)
    manifest_path = Path(args.manifest) if args.manifest else shard_dir / "manifest.txt"
    shard_files = load_manifest(manifest_path)

    conn = init_db(Path(args.database))
    store_meta(conn, "hash_function", HASH_NAME)
    store_meta(conn, "shard_dir", str(shard_dir))
    store_meta(conn, "manifest", str(manifest_path))
    conn.commit()

    print(f"Hash function: {HASH_NAME}", file=sys.stderr)
    start = time.time()
    leaf_count = build_leaves(conn, shard_files, args.batch_size, args.report_every)
    root = build_tree(conn, leaf_count, args.batch_size, args.report_every)
    duration = time.time() - start

    store_meta(conn, "leaf_count", str(leaf_count))
    store_meta(conn, "root_hex", root.hex())
    store_meta(conn, "built_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    conn.commit()
    conn.close()

    print(f"Merkle root: {root.hex()}")
    print(f"Accounts included: {leaf_count:,}")
    print(f"Elapsed: {duration:,.1f}s")


if __name__ == "__main__":
    main()
