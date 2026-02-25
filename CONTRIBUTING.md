# Contributing to Merkle Airdrop

Thank you for your interest in contributing to the Merkle Airdrop project! This guide will help you get started with development and contribution.

## Development Setup

### Prerequisites

- **Rust**: Version 1.70 or later (install via [rustup](https://rustup.rs/))
- **Solidity**: Compatible with 0.8.23+ (tested with Foundry)
- **Cargo**: Rust's package manager
- **Git**: For version control

### Initial Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/merkledrop.git
   cd merkledrop
   ```

2. **Install Rust dependencies:**
   ```bash
   cargo install --path rust-merkle
   ```

3. **Verify installation:**
   ```bash
   cargo run --release --manifest-path rust-merkle/Cargo.toml -- --help
   ```

## Project Structure

```
merkledrop/
├── MerkleAirdropToken.sol     # Main Solidity contract
├── rust-merkle/               # Rust CLI tools
│   ├── src/
│   │   ├── main.rs            # Main build tool
│   │   ├── lib.rs             # Library utilities
│   │   └── bin/               # Binary tools
│   │       ├── proof.rs       # Proof generator
│   │       └── check_sorted.rs # Sorting validator
│   ├── Cargo.toml            # Rust configuration
│   ├── rustfmt.toml          # Code formatting
│   └── clippy.toml           # Linting rules
├── shards/                   # Address data shards
├── out-rs/                   # Build outputs
└── README.md                 # Documentation
```

## Development Workflow

### 1. Building and Testing

#### Build Merkle Tree
```bash
# Build Merkle tree from shards
cargo run --release --manifest-path rust-merkle/Cargo.toml --

# Build with custom paths
cargo run --release --manifest-path rust-merkle/Cargo.toml -- \
  --manifest shards/manifest.txt \
  --base shards \
  --address-lines \
  --address-map addresses.bin \
  --out out-rs \
  --log-interval 1000000
```

#### Generate Proofs
```bash
# Generate proof for an address
cargo run --release --manifest-path rust-merkle/Cargo.toml --bin proof -- \
  --address 0xYourAddressHere \
  --address-map out-rs/addresses.bin \
  --meta out-rs/merkle-meta.json \
  --layers-dir out-rs
```

#### Verify Sorting
```bash
# Check if addresses are properly sorted
cargo run --release --manifest-path rust-merkle/Cargo.toml --bin check-sorted --
```

### 2. Code Quality

#### Rust Code Quality
```bash
# Format Rust code
cargo fmt --manifest-path rust-merkle/Cargo.toml

# Run linter
cargo clippy --manifest-path rust-merkle/Cargo.toml

# Run tests
cargo test --manifest-path rust-merkle/Cargo.toml
```

#### Solidity Code Quality
```bash
# Using Foundry for testing (if available)
forge test

# Using Hardhat (if available)
npx hardhat test

# Using Solc for compilation
solc --version
solc MerkleAirdropToken.sol
```

### 3. Testing Guidelines

#### Unit Tests
- Test individual functions in isolation
- Test edge cases and error conditions
- Test reentrancy scenarios for the Solidity contract
- Test Merkle proof generation and verification

#### Integration Tests
- Test the complete workflow from address generation to claiming
- Test batch claiming functionality
- Test emergency pause and unpause scenarios
- Test ownership transfer mechanisms

#### Security Tests
- Test reentrancy attacks
- Test input validation failures
- Test overflow/underflow scenarios
- Test access controls and ownership

## Contribution Guidelines

### Code Style

#### Rust
- Follow Rust formatting standards (`cargo fmt`)
- Use `clippy` with the project's configuration
- Write clear, concise comments for complex algorithms
- Use idiomatic Rust patterns

#### Solidity
- Follow OpenZeppelin style guidelines
- Use custom error types for better debugging
- Include comprehensive NatSpec documentation
- Use meaningful variable and function names
- Implement proper access controls

### Commit Message Guidelines

Use conventional commits format:

```
feat: add new functionality
fix: resolve a bug
docs: update documentation
style: format code
refactor: improve code structure
test: add tests
chore: maintenance tasks
```

Examples:
```
feat: add batch claiming functionality
fix: resolve reentrancy vulnerability in claim function
docs: update README with usage examples
refactor: improve Merkle tree building algorithm
test: add comprehensive unit tests for Solidity contract
```

### Pull Request Process

1. **Fork the repository** and create a feature branch
2. **Make your changes** following the guidelines above
3. **Run all tests** to ensure nothing is broken
4. **Update documentation** if needed
5. **Commit your changes** with clear, descriptive messages
6. **Submit a pull request** with:
   - Clear title describing the changes
   - Detailed description of the changes
   - Relevant issue references
   - Test results if applicable

### Security Considerations

- **Never commit sensitive information** (private keys, API keys, etc.)
- **Test thoroughly** before submitting security-related changes
- **Consider getting a security audit** for major changes
- **Follow smart security best practices** for the Solidity contract

### Issue Reporting

When reporting bugs or requesting features:

1. **Search existing issues** to avoid duplicates
2. **Provide detailed information**:
   - Expected vs. actual behavior
   - Steps to reproduce
   - Environment information (OS, tool versions)
   - Relevant code snippets
3. **Include examples** when possible
4. **Be clear and descriptive** in your issue description

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

## Support

For questions and support:
- Check the [README](README.md) for usage information
- Search existing [issues](https://github.com/your-repo/merkledrop/issues)
- Create a new issue if needed

Happy coding! 🚀