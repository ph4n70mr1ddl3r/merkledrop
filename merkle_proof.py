#!/usr/bin/env python3
"""
Generate a Merkle proof for an address using an existing Merkle SQLite database.

The script:
1) Streams shard files in manifest order to locate the target address and its leaf index.
2) Walks the stored nodes in the SQLite DB to collect the sibling path.
3) Verifies the computed root matches the DB/meta root.

Outputs the proof as text (default) or JSON.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple


# --- Keccak utilities (with fast backends preferred) -----------------------


def _resolve_keccak256() -> Tuple[str, Callable[[bytes], bytes]]:
    """
    Prefer fast keccak256 implementations if available, else fall back to a
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
        from Cryptodome.Hash import keccak  # type: ignore

        def digest(data: bytes) -> bytes:
            k = keccak.new(digest_bits=256)
            k.update(data)
            return k.digest()

        return "keccak256-pycryptodomex", digest
    except Exception:
        pass

    try:
        from Crypto.Hash import keccak  # type: ignore

        def digest(data: bytes) -> bytes:
            k = keccak.new(digest_bits=256)
            k.update(data)
            return k.digest()

        return "keccak256-pycryptodome", digest
    except Exception:
        pass

    # Fallback: pure Python keccak256 (pad10*1), identical to build_merkle.
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
            c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] ^= d[x]
            b = [0] * 25
            for x in range(5):
                for y in range(5):
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y], _RHO[x][y])
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
            state[0] ^= rc

    def keccak256_digest(data: bytes) -> bytes:
        rate = 136
        state = [0] * 25
        offset = 0
        while offset + rate <= len(data):
            block = data[offset : offset + rate]
            for i in range(rate // 8):
                lane = int.from_bytes(block[8 * i : 8 * (i + 1)], "little")
                state[i] ^= lane
            _keccak_f(state)
            offset += rate
        remaining = data[offset:]
        padded = bytearray(rate)
        padded[: len(remaining)] = remaining
        padded[len(remaining)] = 0x01
        padded[-1] |= 0x80
        for i in range(rate // 8):
            lane = int.from_bytes(padded[8 * i : 8 * (i + 1)], "little")
            state[i] ^= lane
        _keccak_f(state)
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

    return "keccak256-purepython", keccak256_digest


HASH_NAME, HASH_FUNC = _resolve_keccak256()


# --- Helpers ----------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a Merkle proof for an address using merkle.db."
    )
    parser.add_argument("address", help="Ethereum address to prove (0x...)")
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
        help="SQLite database file containing the Merkle tree (default: merkle.db)",
    )
    parser.add_argument(
        "--report-every",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Seconds between progress updates while scanning shards (default: 5.0)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
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


def normalize_addr(addr: str) -> str:
    addr = addr.strip()
    if addr.startswith("0x") or addr.startswith("0X"):
        addr = addr[2:]
    return addr.lower()


def hash_leaf(address: str) -> bytes:
    addr = normalize_addr(address)
    try:
        raw = bytes.fromhex(addr)
    except ValueError as exc:
        raise ValueError(f"Invalid hex address: {address!r}") from exc
    if len(raw) != 20:
        raise ValueError(f"Address must be 20 bytes: {address!r}")
    return HASH_FUNC(raw)


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


def find_leaf_index(
    target_addr: str, shard_files: List[Path], report_every: float
) -> Tuple[int, bytes]:
    needle = normalize_addr(target_addr)
    last_report = time.time()
    for idx, addr in enumerate(read_addresses(shard_files)):
        if normalize_addr(addr) == needle:
            leaf_hash = hash_leaf(addr)
            return idx, leaf_hash
        now = time.time()
        if now - last_report >= max(0.5, report_every):
            print(f"Scanned {idx + 1:,} addresses...", file=sys.stderr)
            last_report = now
    raise SystemExit(f"Address not found in shards: {target_addr}")


def load_meta(conn: sqlite3.Connection) -> Dict[str, str]:
    rows = conn.execute("SELECT key, value FROM meta").fetchall()
    return {k: v for k, v in rows}


def fetch_hash(conn: sqlite3.Connection, level: int, idx: int) -> Optional[bytes]:
    row = conn.execute(
        "SELECT hash FROM nodes WHERE level = ? AND idx = ?", (level, idx)
    ).fetchone()
    return row[0] if row else None


def lookup_leaf(
    conn: sqlite3.Connection, address: str
) -> Optional[Tuple[int, bytes]]:
    try:
        row = conn.execute(
            "SELECT leaf_idx, leaf_hash FROM address_index WHERE address = ?",
            (normalize_addr(address),),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if not row:
        return None
    return int(row[0]), row[1]


def build_proof(
    conn: sqlite3.Connection,
    leaf_idx: int,
    leaf_hash: bytes,
    leaf_count: int,
) -> Tuple[List[Dict[str, str]], bytes]:
    proof: List[Dict[str, str]] = []
    current = leaf_hash
    idx = leaf_idx
    count = leaf_count
    level = 0

    while count > 1:
        sibling_idx = idx - 1 if idx % 2 else idx + 1
        sibling = fetch_hash(conn, level, sibling_idx)
        if sibling is None:
            # Missing sibling means last odd node; duplicate current.
            sibling = current
        side = "left" if idx % 2 else "right"  # sibling side relative to current
        proof.append({"side": side, "hash": "0x" + sibling.hex()})

        if idx % 2:
            current = HASH_FUNC(sibling + current)
        else:
            current = HASH_FUNC(current + sibling)

        idx //= 2
        count = (count + 1) // 2
        level += 1

    return proof, current


def main() -> None:
    args = parse_args()

    conn = sqlite3.connect(args.database)
    meta = load_meta(conn)
    meta_root = meta.get("root_hex")
    meta_leafs = meta.get("leaf_count")
    meta_hash = meta.get("hash_function")

    if not meta_root or not meta_leafs:
        sys.exit("Meta table missing root_hex or leaf_count.")
    leaf_count = int(meta_leafs)

    if not meta_hash or not meta_hash.startswith("keccak256"):
        sys.exit(f"Unsupported hash function in meta: {meta_hash}")

    print(f"Hash function (db): {meta_hash}", file=sys.stderr)
    print(f"Hash function (tool): {HASH_NAME}", file=sys.stderr)

    leaf_idx_hash = lookup_leaf(conn, args.address)
    if leaf_idx_hash is None:
        # Fall back to shard scan for backward compatibility if index is absent.
        shard_dir = Path(args.shard_dir)
        manifest_path = (
            Path(args.manifest) if args.manifest else shard_dir / "manifest.txt"
        )
        shard_files = load_manifest(manifest_path)
        print("Scanning shards to locate address...", file=sys.stderr)
        leaf_idx, leaf_hash = find_leaf_index(
            args.address, shard_files, args.report_every
        )
    else:
        leaf_idx, leaf_hash = leaf_idx_hash
        print("Found via address_index.", file=sys.stderr)

    print(f"Found at leaf index: {leaf_idx}", file=sys.stderr)

    proof, computed_root = build_proof(conn, leaf_idx, leaf_hash, leaf_count)
    conn.close()

    if computed_root.hex() != meta_root:
        sys.exit(
            f"Computed root {computed_root.hex()} does not match DB root {meta_root}"
        )

    if args.format == "json":
        print(
            json.dumps(
                {
                    "address": args.address,
                    "leaf_index": leaf_idx,
                    "leaf_hash": "0x" + leaf_hash.hex(),
                    "root": "0x" + computed_root.hex(),
                    "proof": proof,
                },
                indent=2,
            )
        )
    else:
        print(f"Address: {args.address}")
        print(f"Leaf index: {leaf_idx}")
        print(f"Leaf hash: 0x{leaf_hash.hex()}")
        print(f"Merkle root: 0x{computed_root.hex()}")
        print("Proof (leaf to root):")
        for i, item in enumerate(proof):
            print(f"  {i}: sibling-{item['side']}: {item['hash']}")


if __name__ == "__main__":
    main()
