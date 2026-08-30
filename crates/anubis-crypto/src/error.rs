//! Error type for the ANUBIS crypto core.

use thiserror::Error;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("malformed header: {0}")]
    Header(String),

    #[error("invalid key: {0}")]
    Key(String),

    #[error("no matching identity for any recipient stanza")]
    NoMatch,

    #[error("integrity failure: {0}")]
    Integrity(String),

    #[error("signature verification failed")]
    BadSignature,

    #[error("unsupported: {0}")]
    Unsupported(String),
}
