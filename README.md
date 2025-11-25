# Fair Distribution Whitelist

This repository ships a 64,846,015-address Ethereum whitelist (addresses that paid ≥ 0.004 ETH in gas from genesis to block 23,000,000). It includes Rust tools to build Merkle layers and generate proofs for an airdrop contract that mints a fixed 100 MAT per claim.

## Contents
- `shards/`: 256 shard files listed in `shards/manifest.txt`, sorted by prefix.
- `rust-merkle/`: Rust CLI tools to build the Merkle tree and generate proofs.
- `proof-worker/`: Cloudflare Worker skeleton that serves proofs from precomputed layers (no JS build pipeline required).
- `MerkleAirdropToken.sol`: ERC20 that mints on claim using a Merkle root; owner can end the airdrop anytime.

## Build the Merkle tree (Rust)
Defaults are set for the provided shards. From repo root:
```bash
cargo run --release --manifest-path rust-merkle/Cargo.toml --
```
Outputs to `out-rs/`:
- `layer00.bin`, `layer01.bin`, … (sorted-pair Keccak tree; duplicates last on odd layers)
- `addresses.bin` (20-byte addresses in leaf order; index i → bytes [i*20, i*20+20))
- `merkle-meta.json` (root, leafCount, layer files, addressMap)

If you need to override paths:
```bash
cargo run --release --manifest-path rust-merkle/Cargo.toml -- \
  --manifest shards/manifest.txt \
  --base shards \
  --address-lines \
  --address-map addresses.bin \
  --out out-rs \
  --log-interval 1000000
```

## Get a proof for an address (Rust)
After building the tree:
```bash
cargo run --release --manifest-path rust-merkle/Cargo.toml --bin proof -- \
  --address 0xYourAddressHere \
  --address-map out-rs/addresses.bin \
  --meta out-rs/merkle-meta.json \
  --layers-dir out-rs
```
If `addressMap` is present in `merkle-meta.json` and layers live next to it, you can omit `--address-map`/`--layers-dir`.

## Airdrop contract
- Fixed claim: 100 MAT (18 decimals), minted on successful proof.
- Leaf encoding: `keccak256(abi.encodePacked(index, account))`.
- Owner can end the airdrop at any time; bitmap prevents double claims.
- File: `MerkleAirdropToken.sol`.

## Proof API option
`proof-worker/` contains a Cloudflare Worker skeleton that reads `layer*.bin` and `merkle-meta.json` from R2 and serves proofs at `/proof?address=…`. It also supports `addresses.bin` for index lookup. Adapt `wrangler.toml` with your bucket bindings before deploy.
