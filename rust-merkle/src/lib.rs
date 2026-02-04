use std::error::Error;

const ADDRESS_SIZE: usize = 20;

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
pub fn parse_address(s: &str) -> Result<[u8; ADDRESS_SIZE], Box<dyn Error + Send + Sync>> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != ADDRESS_SIZE * 2 {
        return Err(format!(
            "Invalid address length: '{}' has {} chars, expected {} hex digits (42 chars total with 0x)",
            s,
            trimmed.len(),
            ADDRESS_SIZE * 2
        )
        .into());
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Invalid address: '{}' contains non-hex characters", s).into());
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
