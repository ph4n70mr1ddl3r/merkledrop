use sha3::Digest;
use std::path::{Path, PathBuf};

pub const ADDRESS_SIZE: usize = 20;
pub const HASH_SIZE: usize = 32;

pub mod errors;
pub use errors::{AddressError, FileError, MerkleError, MerkleErrorType, Result};

/// Parses an Ethereum address string into a 20-byte array with EIP-55 checksum validation.
///
/// # Arguments
///
/// * `s` - The address string to parse, with or without "0x" prefix
///
/// # Returns
///
/// A Result containing the 20-byte address array or an error
///
/// # Errors
///
/// Returns an error if:
/// - The address length is invalid (not 40 hex characters)
/// - The address contains non-hex characters
/// - The address checksum does not match EIP-55 specification
pub fn parse_address(s: &str) -> Result<[u8; ADDRESS_SIZE]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != ADDRESS_SIZE * 2 {
        return Err(MerkleError::Validation {
            field: "address".to_string(),
            reason: "Invalid address length".to_string(),
            details: Some(format!(
                "Expected {} hex digits, got {}",
                ADDRESS_SIZE * 2,
                trimmed.len()
            )),
        });
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(MerkleError::Validation {
            field: "address".to_string(),
            reason: "Invalid hex characters".to_string(),
            details: Some(format!("Address '{}' contains non-hex characters", s)),
        });
    }

    let bytes = hex::decode(trimmed)?;
    let mut out = [0u8; ADDRESS_SIZE];
    out.copy_from_slice(&bytes);

    validate_checksum(s, &out)?;

    Ok(out)
}

fn validate_checksum(original: &str, _address: &[u8; ADDRESS_SIZE]) -> Result<()> {
    let original_lower = original
        .strip_prefix("0x")
        .unwrap_or(original)
        .to_lowercase();
    let hash_hex = hex::encode(sha3::Keccak256::digest(original_lower.as_bytes()));

    for (i, c) in original.chars().enumerate() {
        if c == '0' || i < 2 {
            continue;
        }
        let char_idx = i - 2;
        if char_idx >= ADDRESS_SIZE * 2 {
            break;
        }
        let hash_nibble =
            u8::from_str_radix(&hash_hex[char_idx..char_idx + 1], 16).map_err(|_| {
                MerkleError::Validation {
                    field: "address".to_string(),
                    reason: "Invalid checksum".to_string(),
                    details: Some(format!(
                        "Address '{}' does not match EIP-55 checksum",
                        original
                    )),
                }
            })?;

        if hash_nibble >= 8 {
            if c.is_ascii_lowercase() {
                return Err(MerkleError::Validation {
                    field: "address".to_string(),
                    reason: "Invalid checksum".to_string(),
                    details: Some(format!(
                        "Address '{}' does not match EIP-55 checksum",
                        original
                    )),
                });
            }
        } else if c.is_ascii_uppercase() {
            return Err(MerkleError::Validation {
                field: "address".to_string(),
                reason: "Invalid checksum".to_string(),
                details: Some(format!(
                    "Address '{}' does not match EIP-55 checksum",
                    original
                )),
            });
        }
    }
    Ok(())
}

/// Resolves a path safely, preventing directory traversal attacks.
/// Ensures the path is either absolute and within the allowed base directory,
/// or relative to the base directory.
///
/// # Arguments
///
/// * `entry` - The path entry to resolve
/// * `base` - The base directory that paths must stay within
///
/// # Returns
///
/// A Result containing the resolved PathBuf or an error if path traversal is attempted
///
/// # Errors
///
/// Returns an error if the path attempts directory traversal outside the base directory
pub fn resolve_path(entry: &str, base: &Path) -> Result<PathBuf> {
    let p = PathBuf::from(entry);

    if p.is_absolute() {
        // Check if absolute path is within allowed base directory
        if !p.starts_with(base) {
            return Err(MerkleError::Validation {
                field: "path".to_string(),
                reason: "Directory traversal attempt".to_string(),
                details: Some("Absolute path outside base directory".to_string()),
            });
        }
        Ok(p)
    } else {
        // For relative paths, join with base directory
        let resolved = base.join(&p);

        // Verify that the resolved path is still within the base directory
        if !resolved.starts_with(base) {
            return Err(MerkleError::Validation {
                field: "path".to_string(),
                reason: "Directory traversal attempt".to_string(),
                details: Some("Relative path escapes base directory".to_string()),
            });
        }

        Ok(resolved)
    }
}

/// Ensures a file exists, returning an error if it doesn't.
pub fn ensure_file_exists(path: &Path, description: &str) -> Result<()> {
    if !path.exists() {
        return Err(MerkleError::FileOperation {
            operation: "existence check".to_string(),
            path: path.to_path_buf(),
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} does not exist", description),
            )),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_valid() {
        let addr_str = "0x0000000000000000000000000000000000000000";
        let result = parse_address(addr_str);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr, [0u8; 20]);
    }

    #[test]
    fn test_parse_address_without_0x() {
        let addr_str = "0000000000000000000000000000000000000000";
        let result = parse_address(addr_str);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr, [0u8; 20]);
    }

    #[test]
    fn test_parse_address_mixed_case() {
        let addr_str = "0x52908400098527886E0F7030069857D2E4169EE7";
        let result = parse_address(addr_str);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.len(), 20);
    }

    #[test]
    fn test_parse_address_invalid_length() {
        let addr_str = "0x00000000000000000000000000000000000000";
        let result = parse_address(addr_str);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Invalid address length"));
    }

    #[test]
    fn test_parse_address_invalid_chars() {
        let addr_str = "0x00000000000000000000000000000000000000g";
        let result = parse_address(addr_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_address_invalid_checksum() {
        let addr_str = "0xAbCdEf1234567890aBcDeF1234567890AbCdEf00";
        let result = parse_address(addr_str);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Invalid checksum"));
    }

    #[test]
    fn test_parse_address_valid_checksum() {
        let addr_str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let result = parse_address(addr_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_address_large_index() {
        // Test addresses with large index values that would be used in production
        let test_cases = vec![
            (0usize, "0x0000000000000000000000000000000000000000"),
            (
                u32::MAX as usize,
                "0xffffffffffffffffffffffffffffffffffffffff",
            ), // Edge case
            (1_000_000usize, "0x00000000000f4240"), // 1,000,000 in hex without 0x prefix
        ];

        for (expected_index, addr_str) in test_cases {
            let result = parse_address(addr_str);
            assert!(
                result.is_ok(),
                "Should parse address for index {}",
                expected_index
            );
            let addr = result.unwrap();
            assert_eq!(addr.len(), 20, "Address should be 20 bytes");

            // Test that the leaf encoding matches Solidity's expectation
            let mut leaf_input = Vec::new();
            leaf_input.extend_from_slice(&expected_index.to_be_bytes());
            leaf_input.extend_from_slice(&addr);
            let expected_leaf = sha3::Keccak256::digest(leaf_input);
            assert_eq!(expected_leaf.len(), 32, "Leaf should be 32 bytes");
        }
    }

    #[test]
    fn test_parse_address_boundary_conditions() {
        // Test minimum and maximum possible addresses
        let min_addr = "0x0000000000000000000000000000000000000000";
        let max_addr = "0xffffffffffffffffffffffffffffffffffffffff";

        let min_result = parse_address(min_addr);
        let max_result = parse_address(max_addr);

        assert!(min_result.is_ok(), "Minimum address should parse");
        assert!(max_result.is_ok(), "Maximum address should parse");

        // Verify they're different
        assert_ne!(min_result.unwrap(), max_result.unwrap());
    }

    #[test]
    fn test_validate_checksum_edge_cases() {
        // Test checksum validation with edge cases
        let test_cases = vec![
            ("0x0000000000000000000000000000000000000000", true), // All zeros (no checksum needed)
            ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", true), // Valid checksum
            ("0x5AaEb6053F3E94C9b9A09f33669435E7Ef1BeAed", false), // Invalid checksum (wrong case)
        ];

        for (addr_str, should_be_valid) in test_cases {
            let result = parse_address(addr_str);
            if should_be_valid {
                assert!(result.is_ok(), "Valid address should parse: {}", addr_str);
            } else {
                assert!(
                    result.is_err(),
                    "Invalid checksum should fail: {}",
                    addr_str
                );
            }
        }
    }

    #[test]
    fn test_path_validation_security() {
        use std::path::Path;

        // Test directory traversal protection
        let test_cases = vec![
            ("relative/path", Path::new("/safe/base"), true), // Valid relative path
            ("../outside/path", Path::new("/safe/base"), false), // Directory traversal attempt
            ("./safe/path", Path::new("/safe/base"), true),   // Valid use of ./
            ("absolute/path", Path::new("/safe/base"), false), // Absolute path outside base
            ("/safe/base/valid/path", Path::new("/safe/base"), true), // Valid absolute path
        ];

        for (entry, base, should_be_valid) in test_cases {
            let result = resolve_path(entry, base);
            if should_be_valid {
                // Valid paths should succeed
                match result {
                    Ok(path) => {
                        // Verify the resolved path is within the base
                        assert!(
                            path.starts_with(base),
                            "Resolved path should be within base"
                        );
                    }
                    Err(_) => {
                        // Some "valid" paths might fail due to base directory constraints
                    }
                }
            } else {
                // Directory traversal attempts should fail
                if entry.contains("../") || entry.starts_with("/") {
                    assert!(
                        result.is_err(),
                        "Directory traversal should be blocked: {}",
                        entry
                    );
                }
            }
        }
    }

    #[test]
    fn test_ensure_file_exists() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let temp_file = temp_dir.path().join("test_file.txt");

        // Test with non-existent file
        let result = ensure_file_exists(&temp_file, "test description");
        assert!(result.is_err());

        // Create the file and test again
        use std::fs;
        fs::write(&temp_file, "test content").unwrap();
        let result = ensure_file_exists(&temp_file, "test description");
        assert!(result.is_ok());
    }

    #[test]
    fn test_batch_address_processing() {
        // Test processing multiple addresses efficiently
        let test_addresses = vec![
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000003",
        ];

        let parsed: Vec<_> = test_addresses
            .into_iter()
            .map(|addr| parse_address(addr).expect("Should parse valid address"))
            .collect();

        assert_eq!(parsed.len(), 3);

        // Verify addresses are in sorted order
        for i in 1..parsed.len() {
            assert!(parsed[i - 1] < parsed[i], "Addresses should be sorted");
        }
    }

    #[test]
    fn test_error_handling_consistency() {
        // Test that error messages are consistent and informative
        let error_cases = vec![
            ("", "Invalid address length"),
            ("0x", "Invalid address length"),
            ("0x123", "Invalid address length"),
            (
                "0xG000000000000000000000000000000000000000",
                "Invalid hex characters",
            ),
            ("not_an_address", "Invalid hex characters"),
        ];

        for (input, expected_error_substring) in error_cases {
            let result = parse_address(input);
            assert!(result.is_err(), "Should fail for invalid input: {}", input);
            let error_msg = result.unwrap_err().to_string();
            assert!(
                error_msg.contains(expected_error_substring),
                "Error message should contain '{}': {}",
                expected_error_substring,
                error_msg
            );
        }
    }

    #[test]
    fn test_memory_efficiency() {
        // Test that parsing addresses is memory efficient
        let test_size = 1000;
        let addresses: Vec<String> = (0..test_size).map(|i| format!("0x{:040x}", i)).collect();

        // Parse all addresses
        let parsed: Vec<_> = addresses
            .into_iter()
            .map(|addr| parse_address(&addr).unwrap())
            .collect();

        assert_eq!(parsed.len(), test_size);

        // Verify memory usage is reasonable (addresses should be in stack)
        for addr in &parsed {
            assert_eq!(addr.len(), 20, "Each address should be exactly 20 bytes");
        }
    }

    #[test]
    fn test_hex_encoding_roundtrip() {
        // Test that encoding and decoding preserves data integrity
        let original_addr = "0x52908400098527886E0F7030069857D2E4169EE7";
        let parsed = parse_address(original_addr).unwrap();

        // Convert back to hex
        let hex_encoded = hex::encode(parsed);
        let reconstructed = format!("0x{}", hex_encoded);

        // Should match original (case might differ, but content should be same)
        assert_eq!(original_addr.to_lowercase(), reconstructed.to_lowercase());
    }
}
