//! Inert foundation for the future ANUBIS/v4 restricted cryptographic profile.
//!
//! This crate intentionally contains no production suite, parser, writer,
//! cryptographic provider, v3 key type, filesystem access, or validation
//! claim. Its lifecycle and output gates implement selected software-module
//! controls, but they are local engineering scaffolding rather than evidence
//! of FIPS 140-3 compliance, CAVP validation, or CMVP validation. The normative
//! v4 protocol must be frozen before production cryptography can be enabled.

#![forbid(unsafe_code)]

pub mod provider;
pub mod service;
pub mod suite;
pub mod wire;
