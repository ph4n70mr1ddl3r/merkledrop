# Fair Distribution Whitelist

This repository ships a 64,846,015-address Ethereum whitelist (addresses that paid ≥ 0.004 ETH in gas from genesis to block 23,000,000). It includes Rust tools to build Merkle layers and generate proofs for an airdrop contract that mints a fixed 100 MAT per claim.

## Security Features

- **Input Validation**: Comprehensive validation for all inputs including address checksums, proof lengths, and array bounds
- **Gas Optimization**: Efficient bitmap implementation and proof validation with length limits
- **Reentrancy Protection**: Built-in reentrancy guard for secure claiming
- **Batch Operations**: Support for batch claiming to reduce transaction costs
- **Owner Controls**: Secure ownership with transfer functionality and recovery mechanisms

## Contents
- `shards/`: 256 shard files listed in `shards/manifest.txt`, sorted by prefix.
- `rust-merkle/`: Rust CLI tools to build the Merkle tree and generate proofs.
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
If `addressMap` is present in `merkle-meta.json` and layers live next to it, you can omit `--address-map`/`--layers-dir`. The proof helper binary-searches the globally sorted `addresses.bin` to resolve the leaf index. Note: leaves now use `keccak256(abi.encode(index, address))`; regenerate layers/meta and update the contract root if you previously used `abi.encodePacked`.

## Verify sorting (optional)
To fully scan and confirm `addresses.bin` is globally sorted:
```bash
cargo run --release --manifest-path rust-merkle/Cargo.toml --bin check-sorted --
```

## Airdrop contract
- Fixed claim: 100 MAT (18 decimals), minted on successful proof.
- Leaf encoding: `keccak256(abi.encode(index, address))`.
- Owner can end the airdrop at any time; bitmap prevents double claims.
- Supports both individual and batch claiming
- File: `MerkleAirdropToken.sol`.

### Contract Features

**Individual Claiming:**
```solidity
function claim(uint256 index, address account, bytes32[] calldata merkleProof) external nonReentrant
```

**Batch Claiming:**
```solidity
function batchClaim(
    uint256[] calldata indexes,
    address[] calldata accounts,
    bytes32[][] calldata proofs
) external nonReentrant
```

**Security Features:**
- Proof length validation (max 32 proofs)
- Input validation for all parameters
- Reentrancy protection
- Comprehensive error handling

### Usage Example

1. **Generate proof for an address:**
```bash
cargo run --release --manifest-path rust-merkle/Cargo.toml --bin proof -- \
  --address 0xYourAddressHere \
  --address-map out-rs/addresses.bin \
  --meta out-rs/merkle-meta.json \
  --layers-dir out-rs
```

2. **Claim tokens in Solidity:**
```solidity
// Individual claim
airdropContract.claim(index, msg.sender, proof);

// Batch claim (up to 50 addresses at once)
uint256[] memory indexes = new uint256[](2);
address[] memory accounts = new address[](2);
bytes32[][] memory proofs = new bytes32[][](2);

// ... populate arrays ...

airdropContract.batchClaim(indexes, accounts, proofs);
```
