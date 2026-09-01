//! Wire identifiers that are already reserved by the v3 specification.

/// Reserved version token for the additive v4 candidate.
pub const VERSION: &str = "anubis-encryption.org/v4";
/// Reserved canonical first line, including its LF terminator.
pub const VERSION_LINE: &[u8] = b"anubis-encryption.org/v4\n";
