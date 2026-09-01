//! Inert foundation for the future ANUBIS/v4 approved-algorithm candidate.
//!
//! This crate intentionally contains no production suite, parser, writer,
//! cryptographic provider, v3 key type, filesystem access, or validation
//! claim. The normative v4 protocol must be frozen before any of those can be
//! enabled.

#![forbid(unsafe_code)]

pub mod provider;
pub mod suite;
pub mod wire;
