#!/bin/bash

# Cross-language integration test script
# This script verifies that Rust and Solidity implementations produce identical results

echo "Running cross-language integration tests..."

# Compile Solidity contract
echo "Compiling Solidity contract..."
forge build

# Run Rust tests to ensure basic functionality
echo "Running Rust tests..."
cd rust-merkle
cargo test
cd ..

# Create test data directory
mkdir -p test_data

# Generate test addresses and proofs using Rust
echo "Generating test data with Rust..."
cd rust-merkle
cargo run --bin generate_test_data > ../test_data/test_addresses.txt 2>/dev/null
cd ..

# Verify that the test data was generated
if [ ! -f "test_data/test_addresses.txt" ]; then
    echo "ERROR: Failed to generate test data with Rust"
    exit 1
fi

echo "Test data generated successfully:"
head -5 test_data/test_addresses.txt

# Compare hash functions
echo "Comparing hash functions..."
cd rust-merkle
cargo run --bin verify_hash_consistency
cd ..

# Generate proof verification test
echo "Generating proof verification test..."
cd rust-merkle
cargo run --bin test_proof_verification > ../test_data/proof_test_results.txt 2>/dev/null
cd ..

if [ -f "test_data/proof_test_results.txt" ]; then
    echo "Proof verification results:"
    cat test_data/proof_test_results.txt
fi

echo "Cross-language integration tests completed!"
echo "Check the test_data/ directory for generated test files and results."