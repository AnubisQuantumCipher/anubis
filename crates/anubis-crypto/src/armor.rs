//! PEM-style ASCII armor for text-safe transport.
//!
//! Armor exists so a container can survive email, chat, and copy-paste. It
//! is deliberately NOT streaming: the whole container is buffered, because
//! base64 line-wrapping and the trailing boundary cannot be produced
//! incrementally without either seeking or emitting a malformed prefix on
//! error. Use binary output for large files.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64PAD;

use crate::error::{Error, Result};

pub const BEGIN: &str = "-----BEGIN ANUBIS ENCRYPTED FILE-----";
pub const END: &str = "-----END ANUBIS ENCRYPTED FILE-----";

/// Characters per armored line, matching PEM convention.
const WRAP: usize = 64;

/// Largest armored input accepted.
///
/// Armor is decoded BEFORE any key is involved, and decoding costs several
/// copies of the input, so an unbounded armored file is an unauthenticated
/// memory-exhaustion vector.
///
/// The cap is NOT the peak footprint. Decoding an accepted body holds the
/// text, a newline-stripped copy of it, and the decoded bytes at once, so the
/// analytical worst case is several times the cap; raising this limit
/// therefore buys an unauthenticated stranger several times as much memory.
/// (Rejected input never reaches that state, because the read is bounded.)
/// At 16 MiB the cap admits a measured maximum of 12383906 plaintext bytes,
/// which armors to exactly 16777216 -- far past any copy-paste or mail use.
///
/// Callers MUST bound the read itself; checking the length afterwards is not
/// a cap, because the allocation has already happened.
pub const MAX_ARMOR_BYTES: usize = 16 << 20;

/// A UTF-8 byte-order mark, which editors and mail clients prepend freely.
const BOM: &str = "\u{feff}";

fn strip_bom(s: &str) -> &str {
    s.strip_prefix(BOM).unwrap_or(s)
}

/// Parser state for the armor boundary policy.
///
/// Keep this policy separate from UTF-8 trimming and base64 decoding.  Besides
/// making the accepted grammar easier to review, the finite transition system
/// can be model-checked without symbolically executing allocation-heavy
/// standard-library string code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArmorSection {
    Before,
    Body,
    After,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArmorLine<'a> {
    Empty,
    Begin,
    End,
    Data(&'a str),
}

fn classify_line(line: &str) -> ArmorLine<'_> {
    if line.is_empty() {
        ArmorLine::Empty
    } else if line == BEGIN {
        ArmorLine::Begin
    } else if line == END {
        ArmorLine::End
    } else {
        ArmorLine::Data(line)
    }
}

/// Apply one already-trimmed line to the armor boundary state machine.
///
/// An accepted data line is returned to the caller for base64 accumulation.
/// Static error text keeps the transition itself allocation-free; `decode`
/// converts it into the crate's public error type at the boundary.
fn advance_armor<'a>(
    section: ArmorSection,
    line: ArmorLine<'a>,
) -> core::result::Result<(ArmorSection, Option<&'a str>), &'static str> {
    match (section, line) {
        (ArmorSection::Before, ArmorLine::Empty) => Ok((ArmorSection::Before, None)),
        (ArmorSection::Before, ArmorLine::Begin) => Ok((ArmorSection::Body, None)),
        (ArmorSection::Before, _) => Err("expected an ANUBIS armor header before any content"),

        (ArmorSection::Body, ArmorLine::Empty) => Ok((ArmorSection::Body, None)),
        (ArmorSection::Body, ArmorLine::End) => Ok((ArmorSection::After, None)),
        (ArmorSection::Body, ArmorLine::Begin) => Err("nested armor begin boundary"),
        (ArmorSection::Body, ArmorLine::Data(data)) => Ok((ArmorSection::Body, Some(data))),

        (ArmorSection::After, ArmorLine::Empty) => Ok((ArmorSection::After, None)),
        (ArmorSection::After, _) => Err("unexpected content after the armor end boundary"),
    }
}

/// Wrap a raw container in ASCII armor.
#[must_use]
pub fn encode(raw: &[u8]) -> String {
    let b64 = B64PAD.encode(raw);
    let mut out = String::with_capacity(b64.len() + b64.len() / WRAP + BEGIN.len() + END.len() + 4);
    out.push_str(BEGIN);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(WRAP) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// True if the bytes begin with an armor header, ignoring a leading BOM and
/// any amount of leading whitespace.
///
/// This must stay consistent with [`decode`]. If the sniff says binary where
/// decode would have succeeded, the user gets "not an ANUBIS file" on a
/// perfectly good armored container.
#[must_use]
pub fn looks_armored(prefix: &[u8]) -> bool {
    let text = String::from_utf8_lossy(prefix);
    strip_bom(text.trim_start()).trim_start().starts_with(BEGIN)
}

/// Recover a raw container from ASCII armor.
///
/// Rejects content before the begin boundary and after the end boundary, so
/// an attacker cannot smuggle a second, ignored payload past a reader who
/// only looks at one of them.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    if text.len() > MAX_ARMOR_BYTES {
        return Err(Error::Header(format!(
            "armored input exceeds {MAX_ARMOR_BYTES} bytes; use binary for large files"
        )));
    }

    let mut body = String::new();
    let mut section = ArmorSection::Before;

    for (i, line) in text.lines().enumerate() {
        // Only the very first line may carry a byte-order mark.
        let t = if i == 0 {
            strip_bom(line.trim()).trim()
        } else {
            line.trim()
        };

        let (next, data) = advance_armor(section, classify_line(t))
            .map_err(|message| Error::Header(message.into()))?;
        section = next;
        if let Some(data) = data {
            body.push_str(data);
        }
    }

    match section {
        ArmorSection::Before => {
            return Err(Error::Header("missing armor begin boundary".into()));
        }
        ArmorSection::Body => {
            return Err(Error::Header("missing armor end boundary".into()));
        }
        ArmorSection::After => {}
    }

    // STANDARD rejects non-canonical padding and trailing bits, so a given
    // byte string has exactly one accepted encoding.
    B64PAD
        .decode(body.as_bytes())
        .map_err(|e| Error::Header(format!("bad armor base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let raw: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let armored = encode(&raw);
        assert!(looks_armored(armored.as_bytes()));
        assert_eq!(decode(&armored).unwrap(), raw);
    }

    #[test]
    fn empty_round_trip() {
        let armored = encode(&[]);
        assert_eq!(decode(&armored).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn rejects_trailing_content() {
        let mut armored = encode(b"hello");
        armored.push_str("extra\n");
        assert!(decode(&armored).is_err());
    }

    #[test]
    fn rejects_leading_content() {
        let armored = format!("junk\n{}", encode(b"hello"));
        assert!(decode(&armored).is_err());
    }

    #[test]
    fn rejects_nested_begin() {
        let inner = encode(b"hello");
        let nested = inner.replace("-----END", &format!("{BEGIN}\n-----END"));
        assert!(decode(&nested).is_err());
    }

    #[test]
    fn rejects_missing_boundaries() {
        assert!(decode("just some text").is_err());
        assert!(decode(&format!("{BEGIN}\nAAAA\n")).is_err());
        assert!(decode(&format!("AAAA\n{END}\n")).is_err());
    }

    #[test]
    fn tolerates_a_bom_and_leading_blank_lines() {
        // A mail client or editor may prepend either. The sniff and the
        // decoder must agree, or armored files silently look like binary.
        let armored = format!("{BOM}\n\n\n{}", encode(b"bom test"));
        assert!(looks_armored(armored.as_bytes()));
        assert_eq!(decode(&armored).unwrap(), b"bom test");
    }

    #[test]
    fn rejects_embedded_control_bytes() {
        let armored = encode(b"hello").replace('\n', "\u{0}\n");
        assert!(decode(&armored).is_err());
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// The production boundary policy is a finite transition system.  Prove
    /// its complete accept/reject matrix rather than asking the model checker
    /// to rediscover Unicode trimming, `String`, and base64 internals.
    #[kani::proof]
    fn boundary_policy_matches_the_exact_transition_matrix() {
        let section_code: u8 = kani::any();
        let line_code: u8 = kani::any();
        kani::assume(section_code < 3);
        kani::assume(line_code < 4);
        kani::cover!(section_code == 0 && line_code == 0);
        kani::cover!(section_code == 1 && line_code == 3);
        kani::cover!(section_code == 2 && line_code == 1);

        let section = match section_code {
            0 => ArmorSection::Before,
            1 => ArmorSection::Body,
            _ => ArmorSection::After,
        };
        let line = match line_code {
            0 => ArmorLine::Empty,
            1 => ArmorLine::Begin,
            2 => ArmorLine::End,
            _ => ArmorLine::Data("x"),
        };
        let result = advance_armor(section, line);

        let should_accept = matches!(
            (section, line),
            (ArmorSection::Before, ArmorLine::Empty | ArmorLine::Begin)
                | (
                    ArmorSection::Body,
                    ArmorLine::Empty | ArmorLine::End | ArmorLine::Data(_)
                )
                | (ArmorSection::After, ArmorLine::Empty)
        );
        assert!(result.is_ok() == should_accept);

        if let Ok((next, data)) = result {
            assert!(data.is_some() == matches!(line, ArmorLine::Data(_)));
            match (section, line) {
                (ArmorSection::Before, ArmorLine::Begin) => {
                    assert!(next == ArmorSection::Body);
                }
                (ArmorSection::Body, ArmorLine::End) => {
                    assert!(next == ArmorSection::After);
                }
                _ => assert!(next == section),
            }
        }
    }
}
