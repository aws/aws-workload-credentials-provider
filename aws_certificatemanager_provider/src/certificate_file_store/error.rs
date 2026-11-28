use std::io;
use thiserror::Error;

/// Custom error type for certificate file store operations.
#[derive(Error, Debug)]
pub enum StoreError {
    /// An I/O error occurred during file operations.
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("CertificateStore update failed: {0}")]
    UpdateFailed(String),
    /// A rename failed after earlier files were already replaced.
    #[error("{0} (some certificate files were already replaced)")]
    PartialUpdate(Box<StoreError>),
}
