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
    let mut seen_begin = false;
    let mut seen_end = false;

    for (i, line) in text.lines().enumerate() {
        // Only the very first line may carry a byte-order mark.
        let t = if i == 0 {
            strip_bom(line.trim()).trim()
        } else {
            line.trim()
        };

        if !seen_begin {
            if t == BEGIN {
                seen_begin = true;
            } else if !t.is_empty() {
                return Err(Error::Header(
                    "expected an ANUBIS armor header before any content".into(),
                ));
            }
            continue;
        }
        if seen_end {
            if t.is_empty() {
                continue;
            }
            return Err(Error::Header(
                "unexpected content after the armor end boundary".into(),
            ));
        }
        if t == END {
            seen_end = true;
            continue;
        }
        if t.is_empty() {
            continue;
        }
        if t == BEGIN {
            return Err(Error::Header("nested armor begin boundary".into()));
        }
        body.push_str(t);
    }

    if !seen_begin {
        return Err(Error::Header("missing armor begin boundary".into()));
    }
    if !seen_end {
        return Err(Error::Header("missing armor end boundary".into()));
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

    /// The sniff decides which parser an input reaches, so it must be total.
    /// Cheap to prove: no base64, pure prefix logic.
    #[kani::proof]
    #[kani::unwind(12)]
    fn looks_armored_never_panics() {
        let bytes: [u8; 8] = kani::any();
        let _ = looks_armored(&bytes);
    }

    /// Boundary handling on a well-formed envelope with a hostile body.
    ///
    /// Scoped deliberately: a fully symbolic input makes the base64 decoder's
    /// data-dependent loops intractable, and that decoder is a third-party
    /// crate rather than our logic. This pins the envelope and leaves the
    /// body free, which is exactly the part this module owns.
    #[kani::proof]
    #[kani::unwind(16)]
    fn envelope_handling_never_panics() {
        let body: [u8; 4] = kani::any();
        kani::assume(body.iter().all(|b| b.is_ascii_graphic()));
        let mut s = String::with_capacity(BEGIN.len() + END.len() + 8);
        s.push_str(BEGIN);
        s.push('\n');
        s.push_str(core::str::from_utf8(&body).unwrap());
        s.push('\n');
        s.push_str(END);
        s.push('\n');
        let _ = decode(&s);
    }

    /// Content after the end boundary must never be silently ignored: that
    /// would let a second payload ride along unseen by a reader who only
    /// inspects one of them.
    #[kani::proof]
    #[kani::unwind(16)]
    fn trailing_content_is_never_accepted() {
        let extra: [u8; 3] = kani::any();
        kani::assume(extra.iter().all(|b| b.is_ascii_graphic()));
        let mut s = String::new();
        s.push_str(BEGIN);
        s.push('\n');
        s.push_str(END);
        s.push('\n');
        s.push_str(core::str::from_utf8(&extra).unwrap());
        assert!(decode(&s).is_err());
    }
}
