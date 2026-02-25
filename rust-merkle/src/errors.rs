use std::fmt;
use std::path::PathBuf;

/// General application errors
#[derive(Debug)]
pub enum MerkleError {
    FileOperation {
        operation: String,
        path: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    Validation {
        field: String,
        reason: String,
        details: Option<String>,
    },
    Processing {
        operation: String,
        details: String,
    },
    Io {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleError::FileOperation {
                operation,
                path,
                source,
            } => {
                write!(
                    f,
                    "File operation failed: {} on {}: {}",
                    operation,
                    path.display(),
                    source
                )
            }
            MerkleError::Validation {
                field,
                reason,
                details,
            } => {
                if let Some(details) = details {
                    write!(
                        f,
                        "Validation failed for field '{}': {} (details: {})",
                        field, reason, details
                    )
                } else {
                    write!(f, "Validation failed for field '{}': {}", field, reason)
                }
            }
            MerkleError::Processing { operation, details } => {
                write!(f, "Processing failed during {}: {}", operation, details)
            }
            MerkleError::Io { source } => {
                write!(f, "I/O error: {}", source)
            }
        }
    }
}

impl std::error::Error for MerkleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MerkleError::FileOperation { source, .. } => Some(source.as_ref()),
            MerkleError::Io { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// Error type for address-related operations
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
            AddressError::InvalidLength {
                address,
                actual,
                expected,
            } => {
                write!(
                    f,
                    "Invalid address length: '{}' has {} chars, expected {} hex digits (42 chars total with 0x)",
                    address, actual, expected
                )
            }
            AddressError::InvalidHex { address } => {
                write!(
                    f,
                    "Invalid address: '{}' contains non-hex characters",
                    address
                )
            }
            AddressError::InvalidChecksum { address } => {
                write!(
                    f,
                    "Invalid checksum: '{}' does not match EIP-55 checksum",
                    address
                )
            }
            AddressError::DecodeError { source } => {
                write!(f, "Failed to decode address hex: {}", source)
            }
        }
    }
}

impl std::error::Error for AddressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
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

/// Error type for file operation errors
#[derive(Debug)]
pub enum FileError {
    NotFound(PathBuf),
    PermissionDenied(PathBuf),
    InvalidFormat(PathBuf),
    CorruptedData(PathBuf),
    Io {
        path: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileError::NotFound(path) => {
                write!(f, "File not found: {}", path.display())
            }
            FileError::PermissionDenied(path) => {
                write!(f, "Permission denied for file: {}", path.display())
            }
            FileError::InvalidFormat(path) => {
                write!(f, "Invalid file format: {}", path.display())
            }
            FileError::CorruptedData(path) => {
                write!(f, "Corrupted data in file: {}", path.display())
            }
            FileError::Io { path, source } => {
                write!(f, "I/O error for file {}: {}", path.display(), source)
            }
        }
    }
}

impl std::error::Error for FileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FileError::Io { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// Error type for Merkle tree operations
#[derive(Debug)]
pub enum MerkleErrorType {
    InvalidProof {
        leaf_index: Option<usize>,
        reason: String,
    },
    TreeConstruction {
        layer: usize,
        reason: String,
    },
    DataValidation {
        field: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for MerkleErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleErrorType::InvalidProof { leaf_index, reason } => {
                if let Some(index) = leaf_index {
                    write!(f, "Invalid Merkle proof for leaf {}: {}", index, reason)
                } else {
                    write!(f, "Invalid Merkle proof: {}", reason)
                }
            }
            MerkleErrorType::TreeConstruction { layer, reason } => {
                write!(
                    f,
                    "Failed to construct Merkle tree layer {}: {}",
                    layer, reason
                )
            }
            MerkleErrorType::DataValidation {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Data validation failed for field '{}': expected '{}', got '{}'",
                    field, expected, actual
                )
            }
        }
    }
}

/// Result type alias for the application
pub type Result<T> = std::result::Result<T, MerkleError>;

/// Convert address errors to merkle errors
impl From<AddressError> for MerkleError {
    fn from(err: AddressError) -> Self {
        MerkleError::Validation {
            field: "address".to_string(),
            reason: err.to_string(),
            details: None,
        }
    }
}

/// Convert file errors to merkle errors
impl From<FileError> for MerkleError {
    fn from(err: FileError) -> Self {
        MerkleError::FileOperation {
            operation: "unknown".to_string(),
            path: match &err {
                FileError::NotFound(path) => path.clone(),
                FileError::PermissionDenied(path) => path.clone(),
                FileError::InvalidFormat(path) => path.clone(),
                FileError::CorruptedData(path) => path.clone(),
                FileError::Io { path, .. } => path.clone(),
            },
            source: Box::new(err),
        }
    }
}

/// Convert hex decode errors to merkle errors
impl From<hex::FromHexError> for MerkleError {
    fn from(err: hex::FromHexError) -> Self {
        MerkleError::Validation {
            field: "hex".to_string(),
            reason: "Hex decoding failed".to_string(),
            details: Some(err.to_string()),
        }
    }
}
