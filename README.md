# Fair Distribution Whitelist

This repository ships a 64,846,015-address Ethereum whitelist (addresses that paid ≥ 0.004 ETH in gas from genesis to block 23,000,000). It includes Rust tools to build Merkle layers and generate proofs for an airdrop contract that mints a fixed 100 MAT per claim.

## Quick Start

### Prerequisites
- **Rust**: Version 1.70 or later
- **Solidity**: Compatible with 0.8.23+
- **OpenZeppelin Contracts**: For IERC20 interface

### Setup
```bash
# Clone the repository
git clone https://github.com/your-repo/merkledrop.git
cd merkledrop

# Install Rust dependencies
cargo install --path rust-merkle

# Build the Merkle tree
cargo run --release --manifest-path rust-merkle/Cargo.toml --
```

## Security Features

- **Input Validation**: Comprehensive validation for all inputs including address checksums, proof lengths, and array bounds
- **Gas Optimization**: Efficient bitmap implementation and proof validation with length limits
- **Reentrancy Protection**: Built-in reentrancy guard for secure claiming
- **Batch Operations**: Support for batch claiming to reduce transaction costs (up to 50 addresses)
- **Emergency Pause**: Owner can pause/unpause the contract for emergency situations
- **Custom Error Types**: Detailed error messages for better debugging and gas efficiency
- **Owner Controls**: Secure ownership with transfer functionality and recovery mechanisms

## Contract Features

- **Fixed Claim Amount**: 100 MAT (18 decimals) per successful claim
- **Individual & Batch Claiming**: Support for single claims and batch operations
- **Emergency Controls**: Owner can pause, unpause, and end the airdrop
- **Recovery Functions**: Owner can recover ERC20 tokens and ETH sent to the contract
- **Reentrancy Protection**: Built-in security against reentrancy attacks
- **Memory Efficiency**: Bitmap tracking for claimed addresses

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

### Contract Functions

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

**Owner Functions:**
```solidity
function endAirdrop() external onlyOwner        // Stop all claiming
function pause() external onlyOwner            // Emergency pause
function unpause() external onlyOwner          // Resume after pause
function transferOwnership(...) external onlyOwner  // Transfer ownership
function recoverTokens(...) external onlyOwner      // Recover ERC20 tokens
function recoverETH(...) external onlyOwner         // Recover ETH
```

### Security Features
- Proof length validation (max 32 proofs)
- Input validation for all parameters
- Reentrancy protection
- Comprehensive error handling with custom error types
- Emergency pause functionality for critical situations
- Protection against double claiming via bitmap tracking

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
