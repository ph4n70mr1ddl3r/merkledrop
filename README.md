# Fair Distribution Whitelist

This repository ships a 64,846,015-address Ethereum whitelist (addresses that paid ≥ 0.004 ETH in gas from genesis to block 23,000,000). It includes Rust tools to build Merkle layers and generate proofs for an airdrop contract that mints a fixed 100 MAT per claim.

## Quick Start

### Security First Checklist

Before deployment, ensure you complete this security checklist:

1. **Path Validation**: Verify that all file operations use the secure path validation functions
2. **Input Testing**: Test with edge cases including maximum proof lengths, boundary addresses
3. **Reentrancy Testing**: Verify reentrancy protection works with external contract calls
4. **Gas Testing**: Benchmark gas costs for batch operations and maximum limits
5. **Access Control**: Implement multi-sig wallet for owner functions if possible

### Prerequisites

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

## Gas Estimates & Deployment Guidance

### Gas Cost Estimates

| Operation | Gas Cost (Estimate) | Notes |
|-----------|-------------------|--------|
| Single Claim | 85,000 - 120,000 | Varies with proof length |
| Batch Claim (10 addresses) | 180,000 - 250,000 | ~20% savings per additional address |
| Batch Claim (50 addresses) | 450,000 - 600,000 | Maximum batch size |
| Merkle Proof Validation | 2,000 - 5,000 per proof | Depends on proof depth |
| Bitmap Operations | 1,500 - 2,500 | Per claim operation |
| Ownership Transfer | 45,000 - 55,000 | Includes validation |
| ETH Recovery | 35,000 - 45,000 | Safe transfer pattern |

### Deployment Recommendations

#### 1. Contract Deployment
```solidity
// Recommended deployment parameters
uint256 public immutable claimAmount = 100 * 10**18;    // 100 tokens
uint256 public immutable maxSupply = 1000000 * 10**18;   // 1M tokens maximum
uint256 public constant MAX_PROOF_LENGTH = 32;          // Maximum proof depth
uint256 public constant MAX_BATCH_SIZE = 50;           // Maximum batch size
```

#### 2. Security Deployment Checklist
- [ ] Deploy to testnet first and audit all interactions
- [ ] Set up monitoring for contract activities
- [ ] Implement time-lock for critical operations
- [ ] Deploy with multi-sig ownership if possible
- [ ] Set up emergency stop procedures
- [ ] Verify cross-language compatibility with test script

#### 3. Gas Optimization Tips
- **Batch Operations**: Use batch claiming for multiple addresses to save ~20% gas per additional address
- **Proof Length**: Keep proofs as short as possible (optimal: 8-16 hashes)
- **Bitmap Efficiency**: The current bitmap implementation is already optimized for gas
- **Storage Layout**: Contract uses optimized storage patterns

#### 4. Monitoring Guidelines
```bash
# Run regular security checks
./cross_language_test.sh

# Monitor contract activity
forge test --gas-report

# Check for potential issues
cargo test --release -- --exact
```

#### 5. Troubleshooting Common Issues

**Claim Failures**:
- Verify Merkle root matches between Rust and Solidity
- Check that proofs are generated correctly using Rust tools
- Ensure addresses are properly formatted with EIP-55 checksum

**Gas Issues**:
- Monitor gas usage patterns in production
- Consider reducing batch size if gas limits are hit
- Use gas profiling for optimization

**Integration Problems**:
- Run cross-language tests to ensure compatibility
- Verify hash function consistency between implementations
- Check file path handling in Rust tools

### Security Verification

After setup, run security tests:
```bash
# Run Rust security tests
cargo test --release

# Verify file path validation
cargo run --release --manifest-path rust-merkle/Cargo.toml --bin proof -- \
  --address 0x0000000000000000000000000000000000000001 \
  --meta out-rs/merkle-meta.json
```

## Security Features

### Critical Security Protections
- **Reentrancy Protection**: Comprehensive reentrancy guards on all external state-changing functions
- **Front-running Prevention**: Combined validation and processing in batch claims to prevent front-running attacks
- **Input Validation**: Comprehensive validation for all inputs including address checksums, proof lengths, and array bounds
- **Path Validation**: Secure file operations with directory traversal protection in Rust tools
- **Gas Optimization**: Efficient bitmap implementation with inline assembly for critical operations

### Access Controls
- **Emergency Pause**: Owner can pause/unpause the contract for emergency situations
- **Multi-sig Ready**: Ownership transfer system supports multi-sig implementations
- **Recovery Functions**: Owner can recover ERC20 tokens and ETH sent to the contract
- **Secure Ownership**: Time-delay ownership transfer capabilities

### Vulnerability Mitigations
- **Double Spending Protection**: Bitmap tracking prevents double claiming
- **Proof Length Limits**: Maximum 32 proof elements to prevent gas limit issues
- **Memory Safety**: Rust implementation includes comprehensive bounds checking
- **Error Handling**: Custom error types for better debugging and gas efficiency

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

## Security Guidelines

### Critical Security Considerations

#### 1. Contract Deployment Security
- **Audit Requirements**: This contract should be professionally audited before mainnet deployment
- **Access Control**: Consider implementing a multi-sig wallet for owner functions
- **Time-locks**: Implement time-delay mechanisms for critical owner operations
- **Testing**: Comprehensive testing including integration tests between Rust and Solidity components

#### 2. Operational Security
- **Backup Strategy**: Maintain secure backups of Merkle tree data and metadata
- **Monitoring**: Implement monitoring for contract activity and potential attacks
- **Emergency Procedures**: Document clear emergency response procedures for security incidents
- **Access Management**: Strict access controls for development and deployment environments

#### 3. User Protection
- **Clear Documentation**: Provide clear instructions for users to verify their eligibility
- **Proof Generation**: Ensure users understand how to generate and verify proofs
- **Gas Warning**: Alert users about gas costs for batch operations
- **Scam Prevention**: Warn users about potential phishing attacks targeting private keys

### Known Limitations
- **Maximum Batch Size**: Limited to 50 addresses per batch claim for gas efficiency
- **Proof Length**: Maximum 32 proof elements for compatibility and gas limits
- **Storage Costs**: Bitmap tracking may incur significant storage costs for very large airdrops
- **External Dependencies**: Relies on OpenZeppelin IERC20 interface; ensure compatibility

### Security Best Practices
1. **Always verify proofs** before claiming tokens
2. **Test in staging environment** before mainnet deployment
3. **Monitor contract activity** for suspicious behavior
4. **Keep software updated** with latest security patches
5. **Follow access controls** strictly for owner functions
6. **Document all changes** and maintain change logs

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
- **Proof Validation**: Maximum 32 proof elements with comprehensive Merkle tree verification
- **Input Validation**: All parameters validated with explicit bounds checking
- **Reentrancy Protection**: Complete reentrancy guards on all external functions
- **Error Handling**: Comprehensive custom error types for security and debugging
- **Emergency Controls**: Pause functionality with proper access controls
- **Double Claim Prevention**: Efficient bitmap tracking using bit manipulation
- **Gas Optimization**: Inline assembly for critical bitmap operations

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
