use std::error::Error;

const ADDRESS_SIZE: usize = 20;

pub fn parse_address(s: &str) -> Result<[u8; ADDRESS_SIZE], Box<dyn Error + Send + Sync>> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != ADDRESS_SIZE * 2 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "Invalid address: {} (must be {} hex chars)",
            s,
            ADDRESS_SIZE * 2
        )
        .into());
    }
    let bytes = hex::decode(trimmed)?;
    let mut out = [0u8; ADDRESS_SIZE];
    out.copy_from_slice(&bytes);
    Ok(out)
}
