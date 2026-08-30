//! ANUBIS v2 - hybrid post-quantum file encryption.
//!
//! Composes audited primitives; it does not implement any of them:
//!
//! | Role       | Primitive              | Standard      |
//! |------------|------------------------|---------------|
//! | KEM        | X25519 + ML-KEM-1024   | FIPS 203      |
//! | Signatures | ML-DSA-87              | FIPS 204      |
//! | AEAD       | ChaCha20-Poly1305      | RFC 8439      |
//! | KDF        | HKDF-SHA512            | RFC 5869      |
//! | Header MAC | HMAC-SHA512            | FIPS 198-1    |
//!
//! Every dependency is pure Rust: no liboqs, no OpenSSL, no C toolchain.

#![forbid(unsafe_code)]

pub mod armor;
pub mod b32;
pub mod error;
pub mod format;
pub mod hybrid;
pub mod keys;
pub mod stream;

pub use error::{Error, Result};
pub use format::{
    Decrypted, EncryptOptions, Header, Inspection, Verification, decrypt, encrypt, inspect, verify,
    verify_unsized, verify_with_progress,
};
pub use keys::{Identity, Recipient, fingerprint};

/// Crate version, surfaced by the CLI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
