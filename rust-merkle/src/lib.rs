use sha3::Digest;
use std::error::Error;
use std::fmt;

pub const ADDRESS_SIZE: usize = 20;
pub const HASH_SIZE: usize = 32;

#[derive(Debug)]
pub enum AddressError {
    InvalidLength {
        address: String,
        actual: usize,
        expected: usize,
    },
    InvalidHex {
        address: String,
    },
    InvalidChecksum {
        address: String,
    },
    DecodeError {
        source: hex::FromHexError,
    },
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::InvalidLength { address, actual, expected } => write!(
                f,
                "Invalid address length: '{}' has {} chars, expected {} hex digits (42 chars total with 0x)",
                address, actual, expected
            ),
            AddressError::InvalidHex { address } => write!(
                f,
                "Invalid address: '{}' contains non-hex characters",
                address
            ),
            AddressError::InvalidChecksum { address } => write!(
                f,
                "Invalid checksum: '{}' does not match EIP-55 checksum",
                address
            ),
            AddressError::DecodeError { source } => write!(f, "Failed to decode address hex: {}", source),
        }
    }
}

impl Error for AddressError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AddressError::DecodeError { source } => Some(source),
            _ => None,
        }
    }
}

impl From<hex::FromHexError> for AddressError {
    fn from(err: hex::FromHexError) -> Self {
        AddressError::DecodeError { source: err }
    }
}

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
pub fn parse_address(s: &str) -> Result<[u8; ADDRESS_SIZE], AddressError> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != ADDRESS_SIZE * 2 {
        return Err(AddressError::InvalidLength {
            address: s.to_string(),
            actual: trimmed.len(),
            expected: ADDRESS_SIZE * 2,
        });
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AddressError::InvalidHex {
            address: s.to_string(),
        });
    }

    let bytes = hex::decode(trimmed)?;
    let mut out = [0u8; ADDRESS_SIZE];
    out.copy_from_slice(&bytes);

    validate_checksum(s, &out)?;

    Ok(out)
}

fn validate_checksum(original: &str, _address: &[u8; ADDRESS_SIZE]) -> Result<(), AddressError> {
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
        let hash_nibble = u8::from_str_radix(&hash_hex[char_idx..char_idx + 1], 16).unwrap_or(0);

        if hash_nibble >= 8 {
            if c.is_ascii_lowercase() {
                return Err(AddressError::InvalidChecksum {
                    address: original.to_string(),
                });
            }
        } else if c.is_ascii_uppercase() {
            return Err(AddressError::InvalidChecksum {
                address: original.to_string(),
            });
        }
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid address length"));
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
        assert!(result.unwrap_err().to_string().contains("Invalid checksum"));
    }

    #[test]
    fn test_parse_address_valid_checksum() {
        let addr_str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let result = parse_address(addr_str);
        assert!(result.is_ok());
    }
}
