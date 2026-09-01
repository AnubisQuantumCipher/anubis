//! Bounded, exact container-version dispatch.
//!
//! The dispatcher reads one bounded canonical version line, then replays every
//! consumed byte to exactly one version-specific reader. It never tries one
//! parser and falls back to another.

use std::fmt;
use std::io::{self, BufRead, BufReader, Cursor, Read};

/// Current released v3 token.
pub const V3_MAGIC: &str = "anubis-encryption.org/v3";
/// Reserved additive v4 candidate token.
pub const V4_MAGIC: &str = anubis_v4_core::wire::VERSION;
/// anubis-rage 1.x token.
pub const LEGACY_V1_MAGIC: &str = "anubis-encryption.org/v1";
/// anubis-rage 1.4.0 token.
pub const LEGACY_V2_MAGIC: &str = "anubis-encryption.org/v2";

const VERSION_PREFIX: &[u8] = b"anubis-encryption.org/v";
const VERSION_TOKEN_LEN: usize = VERSION_PREFIX.len() + 1;
/// Maximum bytes consumed while looking for the first LF.
pub const MAX_VERSION_LINE: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VersionLinePolicy {
    LegacyV1,
    LegacyV2,
    CurrentV3,
    CandidateV4,
    Unknown,
}

/// Classify an already-canonical first line from its exact observations.
///
/// This is allocation-free and has no fallback state. The caller derives the
/// observations from input bytes; the finite policy is separately amenable to
/// exhaustive model checking.
pub(crate) fn version_line_policy(
    token_len: usize,
    prefix_matches: bool,
    version_byte: u8,
) -> VersionLinePolicy {
    if token_len != VERSION_TOKEN_LEN || !prefix_matches {
        return VersionLinePolicy::Unknown;
    }

    match version_byte {
        b'1' => VersionLinePolicy::LegacyV1,
        b'2' => VersionLinePolicy::LegacyV2,
        b'3' => VersionLinePolicy::CurrentV3,
        b'4' => VersionLinePolicy::CandidateV4,
        _ => VersionLinePolicy::Unknown,
    }
}

pub(crate) fn classify_version_line(line: &[u8]) -> VersionLinePolicy {
    let prefix_matches = line.get(..VERSION_PREFIX.len()) == Some(VERSION_PREFIX);
    let version_byte = line.get(VERSION_PREFIX.len()).copied().unwrap_or_default();
    version_line_policy(line.len(), prefix_matches, version_byte)
}

/// A supported wire-version identity. This enum is non-exhaustive so adding a
/// future reader does not turn downstream matches into silent policy choices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContainerVersion {
    V3,
    V4,
}

/// A bounded dispatch failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum DispatchError {
    Io(io::Error),
    UnexpectedEof,
    MissingNewline,
    TooLong,
    TrailingWhitespace,
    LegacyV1,
    LegacyV2,
    Unknown,
    V4ReadDisabled,
    V4WriteDisabled,
}

impl fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("I/O error while reading the ANUBIS version line"),
            Self::UnexpectedEof => formatter
                .write_str("malformed container version line: unexpected end of input"),
            Self::MissingNewline => formatter
                .write_str("malformed container version line: not LF-terminated"),
            Self::TooLong => write!(
                formatter,
                "malformed container version line: exceeds {MAX_VERSION_LINE} bytes"
            ),
            Self::TrailingWhitespace => formatter.write_str(
                "malformed container version line: trailing whitespace is not canonical",
            ),
            Self::LegacyV1 => formatter.write_str(
                "unsupported: ANUBIS/v1 file (anubis-rage 1.x, pure ML-KEM). Not supported; see MIGRATION.md",
            ),
            Self::LegacyV2 => formatter.write_str(
                "unsupported: ANUBIS/v2 file (anubis-rage 1.4.0, hybrid). Not supported; see MIGRATION.md",
            ),
            Self::Unknown => formatter.write_str("not an ANUBIS container"),
            Self::V4ReadDisabled => formatter.write_str(
                "unsupported: ANUBIS/v4 candidate file. This build has no enabled v4 reader; refusing to reinterpret it as ANUBIS/v3",
            ),
            Self::V4WriteDisabled => formatter.write_str(
                "unsupported: ANUBIS/v4 writing is disabled until the normative v4 suite and wire format are frozen",
            ),
        }
    }
}

impl std::error::Error for DispatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

struct ReplayReader<R: Read> {
    prefix: Cursor<Vec<u8>>,
    remainder: BufReader<R>,
}

impl<R: Read> Read for ReplayReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let from_prefix = self.prefix.read(output)?;
        if from_prefix != 0 || output.is_empty() {
            Ok(from_prefix)
        } else {
            self.remainder.read(output)
        }
    }
}

/// Reader proven by dispatch to begin with the exact v3 token.
pub struct V3Container<R: Read> {
    reader: ReplayReader<R>,
}

impl<R: Read> V3Container<R> {
    /// Recover a reader that replays every original byte, including the token.
    #[must_use]
    pub fn into_reader(self) -> impl Read {
        self.reader
    }
}

/// Reader proven by dispatch to begin with the reserved exact v4 token.
pub struct V4Container<R: Read> {
    reader: ReplayReader<R>,
}

impl<R: Read> V4Container<R> {
    /// Return the recognized version without exposing a parser fallback.
    #[must_use]
    pub const fn version(&self) -> ContainerVersion {
        ContainerVersion::V4
    }

    /// Recover the recognized v4 bytes for a future isolated v4 reader.
    /// This does not parse them and does not permit v3 fallback.
    #[must_use]
    pub fn into_reader(self) -> impl Read {
        self.reader
    }
}

/// Result of the one exact dispatch decision.
#[non_exhaustive]
pub enum ReadDispatch<R: Read> {
    V3(V3Container<R>),
    V4(V4Container<R>),
}

impl<R: Read> ReadDispatch<R> {
    /// Accept only v3. A recognized v4 token is an explicit downgrade refusal.
    pub fn require_v3(self) -> Result<V3Container<R>, DispatchError> {
        match self {
            Self::V3(reader) => Ok(reader),
            Self::V4(_) => Err(DispatchError::V4ReadDisabled),
        }
    }
}

/// Read and classify exactly one bounded canonical version line.
pub fn dispatch<R: Read>(reader: R) -> Result<ReadDispatch<R>, DispatchError> {
    let mut reader = BufReader::new(reader);
    let mut prefix = Vec::with_capacity(V3_MAGIC.len() + 1);
    let bytes_read = reader
        .by_ref()
        .take(MAX_VERSION_LINE as u64)
        .read_until(b'\n', &mut prefix)
        .map_err(DispatchError::Io)?;

    if bytes_read == 0 {
        return Err(DispatchError::UnexpectedEof);
    }
    if !prefix.ends_with(b"\n") {
        return Err(if bytes_read >= MAX_VERSION_LINE {
            DispatchError::TooLong
        } else {
            DispatchError::MissingNewline
        });
    }

    let token = &prefix[..prefix.len() - 1];
    if token.last().is_some_and(u8::is_ascii_whitespace) {
        return Err(DispatchError::TrailingWhitespace);
    }
    let policy = classify_version_line(token);

    let replay = ReplayReader {
        prefix: Cursor::new(prefix),
        remainder: reader,
    };
    match policy {
        VersionLinePolicy::CurrentV3 => Ok(ReadDispatch::V3(V3Container { reader: replay })),
        VersionLinePolicy::CandidateV4 => Ok(ReadDispatch::V4(V4Container { reader: replay })),
        VersionLinePolicy::LegacyV1 => Err(DispatchError::LegacyV1),
        VersionLinePolicy::LegacyV2 => Err(DispatchError::LegacyV2),
        VersionLinePolicy::Unknown => Err(DispatchError::Unknown),
    }
}

/// Explicit writer request. No caller can receive a v3 permit from a v4
/// request, and v4 has no permit type until its normative format is frozen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestedWriteFormat {
    V3,
    V4,
}

pub struct V3WritePermit(());

pub fn request_write(requested: RequestedWriteFormat) -> Result<V3WritePermit, DispatchError> {
    match requested {
        RequestedWriteFormat::V3 => Ok(V3WritePermit(())),
        RequestedWriteFormat::V4 => Err(DispatchError::V4WriteDisabled),
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Exact legacy/current/candidate recognition is disjoint and every other
    /// observation refuses. This proves only the finite production policy;
    /// ordinary tests cover how reader bytes become these observations.
    #[kani::proof]
    fn version_line_policy_matches_the_exact_decision_matrix() {
        let token_len: usize = kani::any();
        let prefix_matches: bool = kani::any();
        let version_byte: u8 = kani::any();

        let expected = if token_len != VERSION_TOKEN_LEN || !prefix_matches {
            VersionLinePolicy::Unknown
        } else {
            match version_byte {
                b'1' => VersionLinePolicy::LegacyV1,
                b'2' => VersionLinePolicy::LegacyV2,
                b'3' => VersionLinePolicy::CurrentV3,
                b'4' => VersionLinePolicy::CandidateV4,
                _ => VersionLinePolicy::Unknown,
            }
        };
        let actual = version_line_policy(token_len, prefix_matches, version_byte);

        assert_eq!(actual, expected);
        kani::cover!(matches!(actual, VersionLinePolicy::LegacyV1));
        kani::cover!(matches!(actual, VersionLinePolicy::LegacyV2));
        kani::cover!(matches!(actual, VersionLinePolicy::CurrentV3));
        kani::cover!(matches!(actual, VersionLinePolicy::CandidateV4));
        kani::cover!(matches!(actual, VersionLinePolicy::Unknown));
    }
}
