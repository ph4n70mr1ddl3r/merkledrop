use std::error::Error;
use std::fmt;

const ADDRESS_SIZE: usize = 20;

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

/// Parses an Ethereum address string into a 20-byte array.
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
    Ok(out)
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
}
