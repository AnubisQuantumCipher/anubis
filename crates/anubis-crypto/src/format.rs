//! The ANUBIS/v2 container: header, key wrapping, and top-level operations.
//!
//! Layout:
//!
//! ```text
//! anubis-encryption.org/v2
//! -> hybrid-x25519-mlkem1024 <b64 epk(32)> <b64 mlkem_ct(1568)>
//! <b64 wrapped_file_key(48)>
//! -> mldsa87 <b64 verifying_key(2592)>        (optional)
//! --- <b64 hmac_sha512(64)>
//! <STREAM payload>
//! <raw ML-DSA-87 signature>                   (present iff mldsa87 stanza)
//! ```
//!
//! The signature covers `SHA-512(header_bytes || payload_ciphertext)`. It
//! deliberately does NOT cover only the header: the file key is known to
//! every recipient, so a header-only signature would let one recipient
//! re-author the payload and keep the signature valid.

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hybrid_array::Array;
use ml_dsa::{MlDsa87, Signature, VerifyingKey};
use sha2::{Digest, Sha512};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::io::{Seek, SeekFrom};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::hybrid;
use crate::keys::{Identity, MLDSA_VK_LEN, MLKEM_CT_LEN, Recipient, X25519_PUB_LEN};
use crate::stream;

/// First line of every ANUBIS/v3 file.
///
/// The number is 3, not 2, because anubis-rage 1.4.0 already shipped
/// "anubis-encryption.org/v2" for its own, incompatible hybrid format.
/// Two unparseable-by-each-other formats must not share a version string.
pub const MAGIC: &str = "anubis-encryption.org/v3";
/// anubis-rage 1.x, pure ML-KEM. Recognised only to refuse clearly.
pub const LEGACY_V1: &str = "anubis-encryption.org/v1";
/// anubis-rage 1.4.0 hybrid. Recognised only to refuse clearly.
pub const LEGACY_V2: &str = "anubis-encryption.org/v2";
/// Legacy hybrid stanza tag from anubis-rage 1.4.0.
pub const LEGACY_STANZA_HYBRID: &str = "hybrid";
/// Recipient stanza tag.
pub const STANZA_HYBRID: &str = "hybrid-x25519-mlkem1024";
/// Signature stanza tag.
pub const STANZA_SIG: &str = "mldsa87";
/// File key length.
pub const FILE_KEY_LEN: usize = 32;
/// Wrapped file key length (32 + Poly1305 tag).
pub const WRAPPED_LEN: usize = FILE_KEY_LEN + 16;
/// ML-DSA-87 signature length (FIPS 204).
pub const SIG_LEN: usize = 4627;
/// Signing domain separator, passed as the ML-DSA context string.
pub const SIG_CONTEXT: &[u8] = b"anubis-v2-file";

/// SHA-512 digest of the complete decoded binary container.
///
/// This covers the exact header, STREAM payload ciphertext, and signature
/// trailer when present. Transport armor is deliberately outside the digest.
pub type ContentId = [u8; 64];

fn finish_content_id(hasher: Sha512) -> ContentId {
    hasher.finalize().into()
}

type HmacSha512 = Hmac<Sha512>;

fn derive(file_key: &[u8; FILE_KEY_LEN], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha512>::new(None, file_key);
    hk.expand(info, out)
        .expect("output length is far below the HKDF-SHA512 limit");
}

fn payload_key(file_key: &[u8; FILE_KEY_LEN]) -> [u8; 32] {
    let mut k = [0u8; 32];
    derive(file_key, b"payload", &mut k);
    k
}

fn header_mac_key(file_key: &[u8; FILE_KEY_LEN]) -> [u8; 64] {
    let mut k = [0u8; 64];
    derive(file_key, b"header", &mut k);
    k
}

/// Wrap the file key under a per-recipient wrap key.
///
/// An all-zero nonce is safe here: the wrap key is derived from a fresh
/// ephemeral transcript for every recipient of every message, so no
/// (key, nonce) pair ever repeats.
fn wrap_file_key(wrap_key: &[u8; 32], file_key: &[u8; FILE_KEY_LEN]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(wrap_key.into());
    let mut buf = file_key.to_vec();
    cipher
        .encrypt_in_place(&Nonce::from([0u8; 12]), b"", &mut buf)
        .map_err(|_| Error::Integrity("file key wrapping failed".into()))?;
    Ok(buf)
}

fn unwrap_file_key(wrap_key: &[u8; 32], wrapped: &[u8]) -> Option<[u8; FILE_KEY_LEN]> {
    let cipher = ChaCha20Poly1305::new(wrap_key.into());
    let mut buf = wrapped.to_vec();
    cipher
        .decrypt_in_place(&Nonce::from([0u8; 12]), b"", &mut buf)
        .ok()?;
    let mut key = [0u8; FILE_KEY_LEN];
    if buf.len() != FILE_KEY_LEN {
        return None;
    }
    key.copy_from_slice(&buf);
    buf.zeroize();
    Some(key)
}

/// One recipient stanza.
#[derive(Clone)]
pub struct Stanza {
    pub epk: [u8; X25519_PUB_LEN],
    pub mlkem_ct: Vec<u8>,
    pub wrapped: Vec<u8>,
}

/// Longest permitted header line. Bounds memory against a crafted file
/// with no newlines, which `read_line` would otherwise slurp entirely.
pub const MAX_HEADER_LINE: usize = 8192;
/// Most recipient stanzas accepted. Also bounds decapsulation work, which
/// is the expensive half of parsing a hostile header.
pub const MAX_STANZAS: usize = 1024;

/// A parsed header.
pub struct Header {
    pub stanzas: Vec<Stanza>,
    pub verifying_key: Option<Vec<u8>>,
    pub mac: Vec<u8>,
    /// Exact header bytes, including the trailing MAC line.
    pub raw: Vec<u8>,
    /// Length of the authenticated prefix: everything before the MAC line.
    body_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderLinePolicy {
    Accept,
    UnexpectedEof,
    TooLong,
    MissingNewline,
    TrailingWhitespace,
}

/// Decide whether one decoded header line is canonical from the observations
/// made by `BufRead::read_line`.
///
/// Keeping the policy allocation-free and separate from I/O gives the parser
/// one production decision boundary that can be exhaustively model-checked.
/// UTF-8 decoding and the derivation of these observations remain the
/// responsibility of `read_line` and ordinary parser tests.
fn header_line_policy(
    bytes_read: usize,
    ends_with_lf: bool,
    has_trailing_whitespace: bool,
) -> HeaderLinePolicy {
    if bytes_read == 0 {
        HeaderLinePolicy::UnexpectedEof
    } else if bytes_read >= MAX_HEADER_LINE && !ends_with_lf {
        HeaderLinePolicy::TooLong
    } else if !ends_with_lf {
        HeaderLinePolicy::MissingNewline
    } else if has_trailing_whitespace {
        HeaderLinePolicy::TrailingWhitespace
    } else {
        HeaderLinePolicy::Accept
    }
}

fn header_body(stanzas: &[Stanza], vk: Option<&[u8]>) -> String {
    let mut s = String::new();
    s.push_str(MAGIC);
    s.push('\n');
    for st in stanzas {
        s.push_str("-> ");
        s.push_str(STANZA_HYBRID);
        s.push(' ');
        s.push_str(&B64.encode(st.epk));
        s.push(' ');
        s.push_str(&B64.encode(&st.mlkem_ct));
        s.push('\n');
        s.push_str(&B64.encode(&st.wrapped));
        s.push('\n');
    }
    if let Some(vk) = vk {
        s.push_str("-> ");
        s.push_str(STANZA_SIG);
        s.push(' ');
        s.push_str(&B64.encode(vk));
        s.push('\n');
    }
    s
}

impl Header {
    /// Parse a header from a buffered reader, leaving the reader positioned
    /// at the first payload byte.
    pub fn parse<R: BufRead>(reader: &mut R) -> Result<Self> {
        let mut raw = Vec::new();
        let mut line = String::new();

        let read_line = |reader: &mut R, line: &mut String, raw: &mut Vec<u8>| -> Result<()> {
            line.clear();
            // Bound the read so a file without newlines cannot exhaust memory.
            let mut limited = reader.take(MAX_HEADER_LINE as u64);
            let n = limited.read_line(line)?;
            let ends_with_lf = line.ends_with('\n');
            let has_trailing_whitespace = if ends_with_lf {
                let content = &line[..line.len() - 1];
                content.len() != content.trim_end().len()
            } else {
                false
            };

            match header_line_policy(n, ends_with_lf, has_trailing_whitespace) {
                HeaderLinePolicy::UnexpectedEof => {
                    return Err(Error::Header("unexpected end of file".into()));
                }
                HeaderLinePolicy::TooLong => {
                    return Err(Error::Header(format!(
                        "header line exceeds {MAX_HEADER_LINE} bytes"
                    )));
                }
                HeaderLinePolicy::MissingNewline => {
                    return Err(Error::Header(
                        "header line is not newline-terminated".into(),
                    ));
                }
                // Reject anything but a bare LF terminator. Without this,
                // trailing spaces or a CR would survive into the file while
                // parsing to the same values, making the header malleable.
                HeaderLinePolicy::TrailingWhitespace => {
                    return Err(Error::Header(
                        "header line has trailing whitespace; headers are canonical".into(),
                    ));
                }
                HeaderLinePolicy::Accept => {}
            }
            raw.extend_from_slice(line.as_bytes());
            Ok(())
        };

        read_line(reader, &mut line, &mut raw)?;
        let first = line.trim_end();
        if first != MAGIC {
            return Err(match first {
                LEGACY_V1 => Error::Unsupported(
                    "ANUBIS/v1 file (anubis-rage 1.x, pure ML-KEM). \
                     Not supported; see MIGRATION.md"
                        .into(),
                ),
                LEGACY_V2 => Error::Unsupported(
                    "ANUBIS/v2 file (anubis-rage 1.4.0, hybrid). \
                     Not supported; see MIGRATION.md"
                        .into(),
                ),
                other => Error::Header(format!(
                    "not an ANUBIS file: expected '{MAGIC}', found '{other}'"
                )),
            });
        }

        let mut stanzas = Vec::new();
        let mut verifying_key = None;
        let mac;
        let body_len;

        loop {
            // Everything before this line is the authenticated prefix.
            let line_start = raw.len();
            read_line(reader, &mut line, &mut raw)?;
            let trimmed = line.trim_end().to_string();

            if let Some(rest) = trimmed.strip_prefix("--- ") {
                body_len = line_start;
                mac = B64
                    .decode(rest)
                    .map_err(|e| Error::Header(format!("bad MAC encoding: {e}")))?;
                if mac.len() != 64 {
                    return Err(Error::Header(format!(
                        "MAC must be 64 bytes, got {}",
                        mac.len()
                    )));
                }
                break;
            }

            let Some(rest) = trimmed.strip_prefix("-> ") else {
                return Err(Error::Header(format!("unexpected line: '{trimmed}'")));
            };
            let parts: Vec<&str> = rest.split(' ').collect();

            match parts.first().copied() {
                Some(STANZA_HYBRID) => {
                    if verifying_key.is_some() {
                        return Err(Error::Header(
                            "recipient stanza follows mldsa87 stanza".into(),
                        ));
                    }
                    if parts.len() != 3 {
                        return Err(Error::Header(
                            "hybrid stanza needs exactly two arguments".into(),
                        ));
                    }
                    let epk_v = B64
                        .decode(parts[1])
                        .map_err(|e| Error::Header(format!("bad ephemeral key: {e}")))?;
                    let ct = B64
                        .decode(parts[2])
                        .map_err(|e| Error::Header(format!("bad ML-KEM ciphertext: {e}")))?;
                    if epk_v.len() != X25519_PUB_LEN {
                        return Err(Error::Header("ephemeral key must be 32 bytes".into()));
                    }
                    if ct.len() != MLKEM_CT_LEN {
                        return Err(Error::Header(format!(
                            "ML-KEM ciphertext must be {MLKEM_CT_LEN} bytes"
                        )));
                    }
                    read_line(reader, &mut line, &mut raw)?;
                    let wrapped = B64
                        .decode(line.trim_end())
                        .map_err(|e| Error::Header(format!("bad wrapped key: {e}")))?;
                    if wrapped.len() != WRAPPED_LEN {
                        return Err(Error::Header(format!(
                            "wrapped file key must be {WRAPPED_LEN} bytes, got {}",
                            wrapped.len()
                        )));
                    }
                    let mut epk = [0u8; X25519_PUB_LEN];
                    epk.copy_from_slice(&epk_v);
                    if stanzas.len() >= MAX_STANZAS {
                        return Err(Error::Header(format!(
                            "more than {MAX_STANZAS} recipient stanzas"
                        )));
                    }
                    stanzas.push(Stanza {
                        epk,
                        mlkem_ct: ct,
                        wrapped,
                    });
                }
                Some(STANZA_SIG) => {
                    if parts.len() != 2 {
                        return Err(Error::Header(
                            "signature stanza needs exactly one argument".into(),
                        ));
                    }
                    // Section 4.3: at most one signature block, and only after
                    // the recipient blocks. Accepting a second one silently
                    // last-wins, which lets a header advertise two signers
                    // while a verifier reports whichever the parser happened to
                    // keep -- two readers disagreeing about who signed a file
                    // is exactly the mistaken-identity outcome this format
                    // spends a fingerprint namespace to prevent.
                    if verifying_key.is_some() {
                        return Err(Error::Header("more than one mldsa87 stanza".into()));
                    }
                    if stanzas.is_empty() {
                        return Err(Error::Header(
                            "mldsa87 stanza before any recipient block".into(),
                        ));
                    }
                    let vk = B64
                        .decode(parts[1])
                        .map_err(|e| Error::Header(format!("bad verifying key: {e}")))?;
                    if vk.len() != MLDSA_VK_LEN {
                        return Err(Error::Header(format!(
                            "verifying key must be {MLDSA_VK_LEN} bytes, got {}",
                            vk.len()
                        )));
                    }
                    verifying_key = Some(vk);
                }
                Some(LEGACY_STANZA_HYBRID) => {
                    return Err(Error::Unsupported(
                        "ANUBIS/v2 file (anubis-rage 1.4.0, hybrid). \
                         Not supported; see MIGRATION.md"
                            .into(),
                    ));
                }
                other => {
                    return Err(Error::Unsupported(format!(
                        "unknown stanza type '{}'",
                        other.unwrap_or("")
                    )));
                }
            }
        }

        if stanzas.is_empty() {
            return Err(Error::Header("no recipient stanzas".into()));
        }

        Ok(Self {
            stanzas,
            verifying_key,
            mac,
            raw,
            body_len,
        })
    }

    /// The authenticated prefix: exact on-disk bytes before the MAC line.
    ///
    /// This deliberately returns the RAW bytes rather than re-serialising the
    /// parsed fields. Re-serialising would authenticate only the semantic
    /// content, leaving the encoding malleable: trailing whitespace could be
    /// altered without detection even though the header MAC is supposed to
    /// make any header modification detectable.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.raw[..self.body_len]
    }
}

/// Options for [`encrypt`].
pub struct EncryptOptions<'a> {
    pub recipients: &'a [Recipient],
    /// When set, the file is signed with this identity's ML-DSA-87 key.
    pub signer: Option<&'a Identity>,
}

/// Encrypt `reader` into `writer`. Returns plaintext bytes processed.
pub fn encrypt<R, W, F>(
    opts: &EncryptOptions<'_>,
    reader: &mut R,
    writer: &mut W,
    progress: F,
) -> Result<u64>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    if opts.recipients.is_empty() {
        return Err(Error::Key("at least one recipient is required".into()));
    }
    if opts.recipients.len() > MAX_STANZAS {
        return Err(Error::Key(format!(
            "more than {MAX_STANZAS} recipients requested"
        )));
    }

    let mut file_key = [0u8; FILE_KEY_LEN];
    getrandom::fill(&mut file_key)
        .map_err(|e| Error::Key(format!("system entropy unavailable: {e}")))?;

    let mut stanzas = Vec::with_capacity(opts.recipients.len());
    for r in opts.recipients {
        let enc = hybrid::encapsulate(r)?;
        stanzas.push(Stanza {
            epk: enc.x25519_epk,
            mlkem_ct: enc.mlkem_ct,
            wrapped: wrap_file_key(&enc.wrap_key, &file_key)?,
        });
    }

    let vk_bytes = opts
        .signer
        .map(|id| id.verifying_key().encode().as_slice().to_vec());

    let body = header_body(&stanzas, vk_bytes.as_deref());
    let mut mac_key = header_mac_key(&file_key);
    let mut mac = <HmacSha512 as hmac::digest::KeyInit>::new_from_slice(&mac_key)
        .map_err(|_| Error::Integrity("MAC key rejected".into()))?;
    mac.update(body.as_bytes());
    let tag = mac.finalize().into_bytes();
    mac_key.zeroize();

    let mut header = body.into_bytes();
    header.extend_from_slice(b"--- ");
    header.extend_from_slice(B64.encode(tag).as_bytes());
    header.push(b'\n');

    writer.write_all(&header)?;

    // Hash header and ciphertext together for the signature.
    let mut hasher = Sha512::new();
    hasher.update(&header);

    let mut pk = payload_key(&file_key);
    let total = {
        let mut tee = HashingWriter {
            inner: &mut *writer,
            hasher: &mut hasher,
        };
        stream::encrypt(&pk, reader, &mut tee, progress)?
    };
    pk.zeroize();
    file_key.zeroize();

    if let Some(signer) = opts.signer {
        let digest = hasher.finalize();
        let sk = signer.signing_key();
        let sig = sk
            .expanded_key()
            .sign_deterministic(&digest, SIG_CONTEXT)
            .map_err(|_| Error::Integrity("signing failed".into()))?;
        writer.write_all(sig.encode().as_slice())?;
    }

    writer.flush()?;
    Ok(total)
}

struct HashingWriter<'a, W: Write> {
    inner: &'a mut W,
    hasher: &'a mut Sha512,
}

impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.inner.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Outcome of a successful decryption.
pub struct Decrypted {
    pub bytes: u64,
    /// Present when the file carried a signature that verified.
    pub verified_key: Option<Vec<u8>>,
}

/// Content-bound outcome of a successful decryption.
///
/// This is returned by the explicitly named report and provisional APIs. The
/// released [`Decrypted`] shape remains unchanged for source compatibility.
pub struct DecryptionReport {
    pub bytes: u64,
    /// Present when the file carried a signature that verified.
    pub verified_key: Option<Vec<u8>>,
    /// SHA-512 over the complete decoded binary container.
    pub content_id: ContentId,
}

impl From<DecryptionReport> for Decrypted {
    fn from(report: DecryptionReport) -> Self {
        Self {
            bytes: report.bytes,
            verified_key: report.verified_key,
        }
    }
}

/// Size of the payload region, given the whole container and its overhead.
///
/// Split out so it can be proved rather than transcribed: `header_len` is
/// derived from parsed input, and plain `header_len + sig_len` wraps in
/// release, which would let the truncation guard pass and then underflow the
/// subtraction. Kani verifies this is total for all three inputs.
fn payload_span(total: u64, header_len: u64, sig_len: u64) -> Result<u64> {
    let overhead = header_len
        .checked_add(sig_len)
        .ok_or_else(|| Error::Integrity("header length overflow".into()))?;
    total
        .checked_sub(overhead)
        .ok_or_else(|| Error::Integrity("file is truncated".into()))
}

/// Require the sized API's declared container boundary to be the real EOF.
///
/// `BufReader` may already have read beyond the declared payload into its
/// internal buffer, so this must inspect the buffered view rather than the
/// underlying reader directly.
fn require_eof<R: BufRead>(reader: &mut R) -> Result<()> {
    if reader.fill_buf()?.is_empty() {
        Ok(())
    } else {
        Err(Error::Integrity(
            "trailing bytes after the declared container length".into(),
        ))
    }
}

/// How much input is available behind the reader.
enum Bound {
    /// Exact byte length of the whole container.
    Known(u64),
    /// Length unknown, e.g. a pipe. Signed containers must then be buffered
    /// so the fixed-size trailer can be split from the payload.
    Unknown,
}

/// Decrypt `reader` (whose total length is `total_len`) into `writer`,
/// withholding plaintext until the complete container has authenticated.
///
/// Plaintext is staged in a private, disk-backed temporary and copied to
/// `writer` only after payload authentication, signature verification, and
/// all container checks succeed. An integrity or signature failure therefore
/// writes zero bytes to the caller's writer while memory usage stays bounded.
///
/// A failure from the caller's `writer` while publishing already-verified
/// plaintext can still leave a partial write at that external sink. Callers
/// that need atomic destination-file publication must still provide their own
/// atomic file sink.
pub fn decrypt<R, W, F>(
    identities: &[Identity],
    reader: R,
    total_len: u64,
    writer: &mut W,
    progress: F,
) -> Result<Decrypted>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    decrypt_report(identities, reader, total_len, writer, progress).map(Into::into)
}

/// Content-bound counterpart to [`decrypt`].
///
/// Plaintext has the same fail-closed publication contract as [`decrypt`],
/// and the report additionally binds the result to the complete container.
pub fn decrypt_report<R, W, F>(
    identities: &[Identity],
    reader: R,
    total_len: u64,
    writer: &mut W,
    progress: F,
) -> Result<DecryptionReport>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let mut stage = PlaintextStage::create()?;
    let verdict = decrypt_provisional(identities, reader, total_len, &mut stage, progress);
    let (mut stage, decrypted) = stage.authenticate(verdict)?;
    stage.copy_to(writer)?;
    Ok(decrypted)
}

/// Decrypt into caller-owned private staging.
///
/// This is the constant-memory primitive used by callers which already own a
/// secure publication boundary. On `Err`, `writer` MAY contain a verified
/// plaintext prefix or the complete plaintext; a signed container's
/// file-wide signature is checked only after the payload. The caller MUST
/// discard the staging sink unless this returns `Ok(DecryptionReport)` and
/// MUST NOT pass a destination path, standard output, pipe, or
/// application-visible buffer directly.
pub fn decrypt_provisional<R, W, F>(
    identities: &[Identity],
    reader: R,
    total_len: u64,
    writer: &mut W,
    progress: F,
) -> Result<DecryptionReport>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    decrypt_impl(
        identities,
        reader,
        Bound::Known(total_len),
        writer,
        progress,
    )
}

/// Decrypt from a stream of unknown length, withholding plaintext until the
/// complete container has authenticated.
///
/// Carries the same zero-caller-output-on-integrity-error contract as
/// [`decrypt`]. Both the input processing and disk-backed plaintext staging
/// use bounded memory.
pub fn decrypt_unsized<R, W, F>(
    identities: &[Identity],
    reader: R,
    writer: &mut W,
    progress: F,
) -> Result<Decrypted>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    decrypt_unsized_report(identities, reader, writer, progress).map(Into::into)
}

/// Content-bound counterpart to [`decrypt_unsized`].
pub fn decrypt_unsized_report<R, W, F>(
    identities: &[Identity],
    reader: R,
    writer: &mut W,
    progress: F,
) -> Result<DecryptionReport>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let mut stage = PlaintextStage::create()?;
    let verdict = decrypt_unsized_provisional(identities, reader, &mut stage, progress);
    let (mut stage, decrypted) = stage.authenticate(verdict)?;
    stage.copy_to(writer)?;
    Ok(decrypted)
}

/// Provisional-output counterpart to [`decrypt_unsized`].
///
/// Unsigned containers stream straight through. Signed containers use a
/// fixed-size delay window to separate the signature trailer from the
/// payload without buffering the container. As with [`decrypt_provisional`],
/// the caller MUST keep `writer` private and discard it on `Err`.
pub fn decrypt_unsized_provisional<R, W, F>(
    identities: &[Identity],
    reader: R,
    writer: &mut W,
    progress: F,
) -> Result<DecryptionReport>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    decrypt_impl(identities, reader, Bound::Unknown, writer, progress)
}

/// Private disk-backed plaintext staging for the safe decrypt APIs.
///
/// The platform temp primitive is anonymous/unlinked (Unix) or opened with
/// delete-on-close and no sharing (Windows). It remains handle-only for its
/// lifetime instead of exposing a reusable plaintext path.
mod plaintext_stage {
    use super::*;

    /// A value whose authorization verdict succeeded.
    ///
    /// Its field is private so the only constructor is [`promote`].  Security
    /// sensitive capabilities are implemented on this type, never on the
    /// untrusted staging type.
    pub(super) struct Authenticated<S>(S);

    /// Convert a private stage into an authenticated stage if and only if the
    /// caller's verdict succeeded.  This small production primitive is the
    /// formal-verification boundary; filesystem and cryptographic behavior are
    /// covered by integration tests rather than modeled here.
    fn promote<S, T, E>(
        stage: S,
        verdict: core::result::Result<T, E>,
    ) -> core::result::Result<(Authenticated<S>, T), E> {
        verdict.map(|value| (Authenticated(stage), value))
    }

    pub(super) struct PlaintextStage {
        file: File,
    }

    impl PlaintextStage {
        pub(super) fn create() -> Result<Self> {
            Ok(Self {
                file: tempfile::tempfile()?,
            })
        }

        pub(super) fn authenticate<T>(
            self,
            verdict: Result<T>,
        ) -> Result<(Authenticated<Self>, T)> {
            promote(self, verdict)
        }
    }

    impl Authenticated<PlaintextStage> {
        pub(super) fn copy_to<W: Write>(&mut self, writer: &mut W) -> Result<()> {
            self.0.file.flush()?;
            self.0.file.seek(SeekFrom::Start(0))?;
            std::io::copy(&mut self.0.file, writer)?;
            Ok(())
        }
    }

    impl Write for PlaintextStage {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.file.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.file.flush()
        }
    }

    #[cfg(kani)]
    mod proofs {
        use super::*;

        #[derive(Default)]
        struct Probe {
            published: bool,
        }

        impl Authenticated<Probe> {
            fn publish(mut self) -> Probe {
                self.0.published = true;
                self.0
            }
        }

        /// A failed verdict cannot yield the authenticated type that owns the
        /// publication capability; a successful verdict can.  This proves the
        /// control-flow/type gate, not the correctness of the verdict itself.
        #[kani::proof]
        fn only_a_successful_verdict_yields_publication_capability() {
            let failed = promote(Probe::default(), Err::<(), u8>(1));
            assert!(failed.is_err());

            let succeeded = promote(Probe::default(), Ok::<(), u8>(()));
            assert!(succeeded.is_ok());
            let (authorized, ()) = succeeded.unwrap();
            let probe = authorized.publish();
            assert!(probe.published);
        }
    }
}

use plaintext_stage::PlaintextStage;

fn decrypt_impl<R, W, F>(
    identities: &[Identity],
    reader: R,
    bound: Bound,
    writer: &mut W,
    progress: F,
) -> Result<DecryptionReport>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let mut buf = BufReader::new(reader);
    let header = Header::parse(&mut buf)?;
    let header_len = header.raw.len() as u64;
    let signed = header.verifying_key.is_some();
    let sig_len = if signed { SIG_LEN as u64 } else { 0 };

    let payload_len = match bound {
        Bound::Known(total) => Some(payload_span(total, header_len, sig_len)?),
        Bound::Unknown => None,
    };
    if let Some(payload_len) = payload_len {
        stream::payload_geometry(payload_len)?;
    }

    // Recover the file key. A stanza that fails to decapsulate is skipped,
    // never fatal: one malformed stanza must not deny access to a file the
    // caller can legitimately open through another stanza.
    let mut file_key = None;
    'outer: for id in identities {
        for st in &header.stanzas {
            let Ok(wrap) = hybrid::decapsulate(id, &st.epk, &st.mlkem_ct) else {
                continue;
            };
            if let Some(fk) = unwrap_file_key(&wrap, &st.wrapped) {
                file_key = Some(fk);
                break 'outer;
            }
        }
    }
    let Some(mut file_key) = file_key else {
        return Err(Error::NoMatch);
    };

    // Authenticate the header before trusting anything in it.
    let mut mac_key = header_mac_key(&file_key);
    let mut mac = <HmacSha512 as hmac::digest::KeyInit>::new_from_slice(&mac_key)
        .map_err(|_| Error::Integrity("MAC key rejected".into()))?;
    mac.update(header.body());
    let expected = mac.finalize().into_bytes();
    mac_key.zeroize();
    if expected.as_slice().ct_eq(&header.mac).unwrap_u8() != 1 {
        file_key.zeroize();
        return Err(Error::Integrity(
            "header authentication failed: the header was modified".into(),
        ));
    }

    let mut signature_hasher = Sha512::new();
    signature_hasher.update(&header.raw);
    let mut content_hasher = Sha512::new();
    content_hasher.update(&header.raw);

    let pk = Zeroizing::new(payload_key(&file_key));
    file_key.zeroize();

    // Split payload from trailer.
    let (total, sig_bytes) = match (payload_len, signed) {
        (Some(len), _) => {
            let mut hr = DualHashingReader {
                inner: buf.by_ref().take(len),
                first: &mut signature_hasher,
                second: &mut content_hasher,
            };
            let total = stream::decrypt(&pk, &mut hr, writer, progress)?;
            // The digest must cover the whole payload REGION, not merely the
            // bytes the chunk loop happened to consume. Equal today, but an
            // unchecked invariant is exactly how a signature-scope bug ships.
            if hr.inner.limit() != 0 {
                return Err(Error::Integrity(
                    "payload region was not fully consumed".into(),
                ));
            }
            let mut sig = vec![0u8; sig_len as usize];
            if signed {
                buf.read_exact(&mut sig)
                    .map_err(|_| Error::Integrity("signature trailer is missing".into()))?;
            }
            require_eof(&mut buf)?;
            (total, sig)
        }
        (None, false) => {
            // Unsigned and unbounded: stream to end of input.
            let mut hr = DualHashingReader {
                inner: buf.by_ref(),
                first: &mut signature_hasher,
                second: &mut content_hasher,
            };
            let total = stream::decrypt(&pk, &mut hr, writer, progress)?;
            (total, Vec::new())
        }
        (None, true) => {
            // Signed and unbounded. Buffering the remainder would let anyone
            // holding the (published) recipient key drive us out of memory,
            // and would make a pipe behave worse than a file. A delay reader
            // withholds the last SIG_LEN bytes instead: whatever remains in
            // its window at EOF is exactly the trailer. Constant memory.
            let mut delay = DelayReader::new(buf.by_ref(), SIG_LEN);
            let total = {
                let mut hr = DualHashingReader {
                    inner: &mut delay,
                    first: &mut signature_hasher,
                    second: &mut content_hasher,
                };
                stream::decrypt(&pk, &mut hr, writer, progress)?
            };
            let sig = delay.into_tail()?;
            (total, sig)
        }
    };

    let mut verified_key = None;
    if let Some(vk_bytes) = &header.verifying_key {
        check_signature(vk_bytes, &sig_bytes, signature_hasher)?;
        verified_key = Some(vk_bytes.clone());
    }
    content_hasher.update(&sig_bytes);

    Ok(DecryptionReport {
        bytes: total,
        verified_key,
        content_id: finish_content_id(content_hasher),
    })
}

struct HashingReader<'a, R: Read> {
    inner: R,
    hasher: &'a mut Sha512,
}

struct DualHashingReader<'a, R: Read> {
    inner: R,
    first: &'a mut Sha512,
    second: &'a mut Sha512,
}

impl<R: Read> Read for DualHashingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.first.update(&buf[..n]);
        self.second.update(&buf[..n]);
        Ok(n)
    }
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Header-level facts about a file, obtainable without any key.
#[derive(Debug)]
pub struct Inspection {
    pub format: String,
    pub recipients: usize,
    pub signed: bool,
    pub verifying_key: Option<Vec<u8>>,
    pub header_bytes: u64,
    pub payload_bytes: u64,
    pub chunks: u64,
}

/// Full-container inspection bound to the exact decoded bytes.
///
/// The released header-only [`Inspection`] shape remains unchanged. APIs that
/// consume the complete input return this report with a mandatory content ID.
#[derive(Debug)]
pub struct InspectionReport {
    pub format: String,
    pub recipients: usize,
    pub signed: bool,
    pub verifying_key: Option<Vec<u8>>,
    pub header_bytes: u64,
    pub payload_bytes: u64,
    pub chunks: u64,
    /// SHA-512 over the complete decoded binary container.
    pub content_id: ContentId,
}

impl From<InspectionReport> for Inspection {
    fn from(report: InspectionReport) -> Self {
        Self {
            format: report.format,
            recipients: report.recipients,
            signed: report.signed,
            verifying_key: report.verifying_key,
            header_bytes: report.header_bytes,
            payload_bytes: report.payload_bytes,
            chunks: report.chunks,
        }
    }
}

/// A reader that withholds the final `tail` bytes of a stream.
///
/// Used to peel a fixed-size trailer off a stream whose length is unknown
/// without buffering the whole stream. Bytes are released only once `tail`
/// further bytes have been observed, so whatever remains in the window at
/// end of input is exactly the trailer.
struct DelayReader<R: Read> {
    inner: R,
    /// Backing buffer; live bytes are `window[head..]`.
    window: Vec<u8>,
    head: usize,
    tail: usize,
    eof: bool,
}

/// Bytes pulled from the inner reader per refill.
const REFILL: usize = 64 << 10;
/// Compact the buffer once this many consumed bytes accumulate at the front.
const COMPACT_AT: usize = 64 << 10;

impl<R: Read> DelayReader<R> {
    fn new(inner: R, tail: usize) -> Self {
        Self {
            inner,
            window: Vec::with_capacity(tail + REFILL),
            head: 0,
            tail,
            eof: false,
        }
    }

    fn live(&self) -> usize {
        self.window.len() - self.head
    }

    /// The withheld bytes. Errors if the stream was shorter than the trailer.
    fn into_tail(mut self) -> Result<Vec<u8>> {
        // Drain anything the consumer left unread.
        let mut sink = [0u8; 8192];
        while self.read(&mut sink)? > 0 {}
        if self.live() != self.tail {
            return Err(Error::Integrity("signature trailer is missing".into()));
        }
        self.window.drain(..self.head);
        Ok(self.window)
    }
}

impl<R: Read> DelayReader<R> {
    /// The withheld trailer, once the stream has been read to its end.
    ///
    /// `None` when fewer than `tail` bytes were ever withheld, which means the
    /// stream ended before it could carry a trailer at all.
    fn take_tail(&mut self) -> Option<Vec<u8>> {
        let live = self.window.len() - self.head;
        if !self.eof || live < self.tail {
            return None;
        }
        Some(self.window[self.window.len() - self.tail..].to_vec())
    }
}

impl<R: Read> Read for DelayReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let want = self.tail + out.len();
        // Refill in fixed blocks rather than sizing each read to the request.
        // Sizing to the request made a reader that returns few bytes per call
        // pay a full window resize and compaction per call, which is
        // quadratic; a throttled pipe crawled.
        while !self.eof && self.live() < want {
            let before = self.window.len();
            self.window.resize(before + REFILL, 0);
            let n = self.inner.read(&mut self.window[before..])?;
            self.window.truncate(before + n);
            if n == 0 {
                self.eof = true;
            }
        }
        let releasable = self.live().saturating_sub(self.tail);
        let n = releasable.min(out.len());
        out[..n].copy_from_slice(&self.window[self.head..self.head + n]);
        self.head += n;
        // Compact only once the dead prefix is worth moving, so the memmove
        // cost is amortised across many reads instead of paid on every one.
        if self.head >= COMPACT_AT {
            self.window.drain(..self.head);
            self.head = 0;
        }
        Ok(n)
    }
}

/// Inspect a file's header without decrypting it.
pub fn inspect<R: Read>(reader: R, total_len: u64) -> Result<Inspection> {
    let mut buf = BufReader::new(reader);
    let header = Header::parse(&mut buf)?;
    let header_len = header.raw.len() as u64;
    let signed = header.verifying_key.is_some();
    let sig_len = if signed { SIG_LEN as u64 } else { 0 };

    let payload = payload_span(total_len, header_len, sig_len)?;
    let geometry = stream::payload_geometry(payload)?;

    Ok(Inspection {
        format: MAGIC.to_string(),
        recipients: header.stanzas.len(),
        signed,
        verifying_key: header.verifying_key,
        header_bytes: header_len,
        payload_bytes: payload,
        chunks: geometry.chunks,
    })
}

/// Inspect a stream of unknown length in constant memory.
///
/// Unlike header-only [`inspect`], this consumes the complete decoded binary
/// container so it can report exact payload geometry and a [`ContentId`].
pub fn inspect_unsized<R: Read>(reader: R) -> Result<InspectionReport> {
    inspect_full(reader, None)
}

/// Inspect and hash a complete decoded binary container whose length is known.
///
/// The whole reader is consumed and its observed length must equal
/// `total_len`. Use header-only [`inspect`] when a content identifier is not
/// needed and avoiding a full read matters.
pub fn inspect_with_content_id<R: Read>(reader: R, total_len: u64) -> Result<InspectionReport> {
    inspect_full(reader, Some(total_len))
}

fn inspect_full<R: Read>(reader: R, expected_total: Option<u64>) -> Result<InspectionReport> {
    let mut buf = BufReader::new(reader);
    let header = Header::parse(&mut buf)?;
    let header_len = header.raw.len() as u64;
    let signed = header.verifying_key.is_some();
    let sig_len = if signed { SIG_LEN as u64 } else { 0 };

    let mut hasher = Sha512::new();
    hasher.update(&header.raw);
    let remainder = {
        let mut hashing = HashingReader {
            inner: buf,
            hasher: &mut hasher,
        };
        std::io::copy(&mut hashing, &mut std::io::sink())?
    };
    let observed_total = header_len
        .checked_add(remainder)
        .ok_or_else(|| Error::Integrity("container length overflow".into()))?;
    if let Some(expected) = expected_total {
        if observed_total != expected {
            return Err(Error::Integrity(format!(
                "container length mismatch: expected {expected} bytes, read {observed_total}"
            )));
        }
    }

    let payload = payload_span(observed_total, header_len, sig_len)?;
    let geometry = stream::payload_geometry(payload)?;
    Ok(InspectionReport {
        format: MAGIC.to_string(),
        recipients: header.stanzas.len(),
        signed,
        verifying_key: header.verifying_key,
        header_bytes: header_len,
        payload_bytes: geometry.bytes,
        chunks: geometry.chunks,
        content_id: finish_content_id(hasher),
    })
}

/// The outcome of a keyless signature check.
///
/// Every field here is derivable from the container and the public key it
/// carries. Nothing in this struct required a private key to produce.
#[derive(Debug)]
pub struct Verification {
    pub format: String,
    pub recipients: usize,
    pub signed: bool,
    /// The embedded ML-DSA-87 verifying key, when the container carries one.
    pub verifying_key: Option<Vec<u8>>,
    /// `Some(true)` when the signature verified. `None` means the container is
    /// unsigned, which is a distinct state and never a pass. A signature
    /// mismatch is returned as [`Error::BadSignature`].
    pub signature_ok: Option<bool>,
    pub header_bytes: u64,
    pub payload_bytes: u64,
    pub chunks: u64,
}

/// Content-bound outcome of a keyless signature check.
///
/// Reporting APIs preserve a structurally valid negative cryptographic
/// verdict as `Some(false)` and bind it to the complete container bytes. The
/// released [`Verification`] shape and strict error behavior remain intact.
#[derive(Debug)]
pub struct VerificationReport {
    pub format: String,
    pub recipients: usize,
    pub signed: bool,
    pub verifying_key: Option<Vec<u8>>,
    pub signature_ok: Option<bool>,
    pub header_bytes: u64,
    pub payload_bytes: u64,
    pub chunks: u64,
    /// SHA-512 over the complete decoded binary container.
    pub content_id: ContentId,
}

impl From<VerificationReport> for Verification {
    fn from(report: VerificationReport) -> Self {
        Self {
            format: report.format,
            recipients: report.recipients,
            signed: report.signed,
            verifying_key: report.verifying_key,
            signature_ok: report.signature_ok,
            header_bytes: report.header_bytes,
            payload_bytes: report.payload_bytes,
            chunks: report.chunks,
        }
    }
}

/// Verify a container's signature **without any private key**.
///
/// The signature is over `SHA-512(header_bytes || payload_ciphertext)`, and
/// the verifying key travels in the header, so checking it requires no
/// recipient identity, no file key, and no decryption. Anyone holding the
/// bytes can establish that the holder of a particular ML-DSA-87 key produced
/// this exact file.
///
/// This is deliberately reachable on its own rather than only as a step
/// inside [`decrypt`]. A third party auditing a container -- someone who
/// cannot and should not be able to read it -- must still be able to check
/// its provenance with the reference implementation instead of reconstructing
/// the signing transcript by guesswork.
///
/// What it does **not** establish is who that key belongs to. Compare the
/// fingerprint against a value confirmed out of band; an unpinned valid
/// signature identifies no one.
///
/// The payload is hashed, never decrypted, so nothing secret enters memory
/// and no plaintext is produced.
pub fn verify<R: Read>(reader: R, total_len: u64) -> Result<Verification> {
    verify_with_progress(reader, total_len, |_| {})
}

/// Verify while retaining a content-bound negative signature verdict.
///
/// A structurally complete signed container whose ML-DSA signature does not
/// verify returns `Ok(VerificationReport { signature_ok: Some(false), .. })`, along
/// with its signer key, payload geometry, and [`ContentId`]. Malformed,
/// truncated, or otherwise structurally unverifiable input still returns an
/// error and is never converted into a false verdict. Use [`verify`] when a
/// mismatch itself must remain [`Error::BadSignature`].
pub fn verify_report<R: Read>(reader: R, total_len: u64) -> Result<VerificationReport> {
    verify_report_with_progress(reader, total_len, |_| {})
}

/// [`verify`] for a stream of unknown length, such as a pipe.
///
/// Uses the same delay buffer as [`decrypt_unsized`]: the trailing `SIG_LEN`
/// bytes are withheld while everything ahead of them is hashed, so whatever
/// remains at end of input is exactly the signature. Memory stays bounded by
/// the trailer regardless of file size.
///
/// This matters more here than anywhere else in the crate. `verify` is the one
/// entry point meant to be aimed at a container from a stranger, so it must
/// not require holding that container in memory to form an opinion about it.
pub fn verify_unsized<R: Read>(reader: R) -> Result<Verification> {
    strict_verification(verify_unsized_report(reader)?)
}

/// Unknown-length counterpart to [`verify_report`].
///
/// Input remains constant-memory: the fixed signature trailer is withheld in
/// a delay window while the payload is hashed. Structural failures remain
/// errors; only an actual ML-DSA mismatch becomes `signature_ok: Some(false)`.
pub fn verify_unsized_report<R: Read>(reader: R) -> Result<VerificationReport> {
    let mut buf = BufReader::new(reader);
    let header = Header::parse(&mut buf)?;
    let header_len = header.raw.len() as u64;
    let signed = header.verifying_key.is_some();

    let mut hasher = Sha512::new();
    hasher.update(&header.raw);

    let Some(vk_bytes) = header.verifying_key.as_ref() else {
        let payload = {
            let mut hashing = HashingReader {
                inner: buf,
                hasher: &mut hasher,
            };
            std::io::copy(&mut hashing, &mut std::io::sink())?
        };
        let geometry = stream::payload_geometry(payload)?;
        return Ok(VerificationReport {
            format: MAGIC.to_string(),
            recipients: header.stanzas.len(),
            signed,
            verifying_key: None,
            signature_ok: None,
            header_bytes: header_len,
            payload_bytes: geometry.bytes,
            chunks: geometry.chunks,
            content_id: finish_content_id(hasher),
        });
    };

    let mut delay = DelayReader::new(buf.by_ref(), SIG_LEN);
    let mut window = vec![0u8; 64 << 10];
    let mut payload: u64 = 0;
    loop {
        let n = delay.read(&mut window)?;
        if n == 0 {
            break;
        }
        hasher.update(&window[..n]);
        payload += n as u64;
    }
    let sig_bytes = delay
        .take_tail()
        .ok_or_else(|| Error::Integrity("signature trailer is truncated".into()))?;

    let geometry = stream::payload_geometry(payload)?;

    let mut content_hasher = hasher.clone();
    content_hasher.update(&sig_bytes);
    let signature_ok = signature_verdict(vk_bytes, &sig_bytes, hasher)?;
    Ok(VerificationReport {
        format: MAGIC.to_string(),
        recipients: header.stanzas.len(),
        signed,
        verifying_key: header.verifying_key,
        signature_ok: Some(signature_ok),
        header_bytes: header_len,
        payload_bytes: geometry.bytes,
        chunks: geometry.chunks,
        content_id: finish_content_id(content_hasher),
    })
}

/// Decode the key and trailer and check the digest under them.
///
/// Shared by the sized and unsized paths so there is exactly one place where a
/// signature is judged, and no way for the two to drift apart.
fn check_signature(vk_bytes: &[u8], sig_bytes: &[u8], hasher: Sha512) -> Result<()> {
    if signature_verdict(vk_bytes, sig_bytes, hasher)? {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

/// Return a cryptographic verdict after all structural checks have completed.
///
/// An exact-length signature which fails decoding is an invalid signature,
/// not a malformed container: its bytes, signer, and content identity are all
/// still well-defined and may be reported as a bound negative verdict.
fn signature_verdict(vk_bytes: &[u8], sig_bytes: &[u8], hasher: Sha512) -> Result<bool> {
    let vk_arr =
        Array::try_from(vk_bytes).map_err(|_| Error::Header("bad verifying key length".into()))?;
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);
    let sig_arr =
        Array::try_from(sig_bytes).map_err(|_| Error::Integrity("bad signature length".into()))?;
    let Some(sig) = Signature::<MlDsa87>::decode(&sig_arr) else {
        return Ok(false);
    };

    let digest = hasher.finalize();
    Ok(vk.verify_with_context(&digest, SIG_CONTEXT, &sig))
}

/// [`verify`], reporting bytes hashed so far.
///
/// The callback receives a running count of payload bytes consumed, so a
/// caller can show progress while checking a container too large to sit in
/// memory.
pub fn verify_with_progress<R, F>(reader: R, total_len: u64, progress: F) -> Result<Verification>
where
    R: Read,
    F: FnMut(u64),
{
    strict_verification(verify_report_with_progress(reader, total_len, progress)?)
}

/// Reporting counterpart to [`verify_with_progress`].
///
/// Preserves a content-bound `Some(false)` only for a cryptographic signature
/// mismatch; all structural failures remain errors.
pub fn verify_report_with_progress<R, F>(
    reader: R,
    total_len: u64,
    mut progress: F,
) -> Result<VerificationReport>
where
    R: Read,
    F: FnMut(u64),
{
    let mut buf = BufReader::new(reader);
    let header = Header::parse(&mut buf)?;
    let header_len = header.raw.len() as u64;
    let signed = header.verifying_key.is_some();
    let sig_len = if signed { SIG_LEN as u64 } else { 0 };

    let payload = payload_span(total_len, header_len, sig_len)?;

    let geometry = stream::payload_geometry(payload)?;

    // Hash the header and the payload ciphertext exactly as the signer did.
    // The ciphertext is hashed as it lies on disk; it is never decrypted, so
    // this path handles a container addressed to someone else without ever
    // being able to read it.
    let mut hasher = Sha512::new();
    hasher.update(&header.raw);

    let mut window = vec![0u8; 64 << 10];
    let mut remaining = payload;
    let mut hashed: u64 = 0;
    while remaining > 0 {
        let want = remaining.min(window.len() as u64) as usize;
        buf.read_exact(&mut window[..want]).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Integrity("file is truncated".into())
            } else {
                Error::Io(e)
            }
        })?;
        hasher.update(&window[..want]);
        remaining -= want as u64;
        hashed += want as u64;
        progress(hashed);
    }

    let mut signature_ok = None;
    let mut sig_bytes = Vec::new();
    if header.verifying_key.is_some() {
        sig_bytes.resize(SIG_LEN, 0);
        buf.read_exact(&mut sig_bytes).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Integrity("signature trailer is truncated".into())
            } else {
                Error::Io(e)
            }
        })?;
    }

    require_eof(&mut buf)?;
    if let Some(vk_bytes) = header.verifying_key.as_ref() {
        signature_ok = Some(signature_verdict(vk_bytes, &sig_bytes, hasher.clone())?);
    }

    hasher.update(&sig_bytes);
    Ok(VerificationReport {
        format: MAGIC.to_string(),
        recipients: header.stanzas.len(),
        signed,
        verifying_key: header.verifying_key,
        signature_ok,
        header_bytes: header_len,
        payload_bytes: geometry.bytes,
        chunks: geometry.chunks,
        content_id: finish_content_id(hasher),
    })
}

fn strict_verification(verification: VerificationReport) -> Result<Verification> {
    if verification.signature_ok == Some(false) {
        Err(Error::BadSignature)
    } else {
        Ok(verification.into())
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// The payload region is computed by subtracting two attacker-influenced
    /// quantities from a third. In release builds Rust wraps on overflow, so
    /// an underflow here would produce an enormous `payload_len` and mis-slice
    /// the stream. This proves the guard makes that unreachable for every
    /// combination of the three values, not merely the ones a test picked.
    #[kani::proof]
    fn payload_length_arithmetic_cannot_underflow() {
        let total: u64 = kani::any();
        let header_len: u64 = kani::any();
        let signed: bool = kani::any();
        let sig_len: u64 = if signed { SIG_LEN as u64 } else { 0 };

        // Proves the REAL function, not a transcription of it.
        match payload_span(total, header_len, sig_len) {
            Ok(payload) => {
                // Accepting implies the decomposition is exact and total.
                assert!(payload <= total);
                assert!(header_len + sig_len + payload == total);
            }
            Err(_) => {}
        }
    }

    /// The production payload-geometry validator agrees with its exact
    /// encoding rule for every possible byte length.  This calls the real
    /// function rather than repeating a nearby chunk-count calculation.
    #[kani::proof]
    #[kani::solver(kissat)]
    fn production_payload_geometry_matches_its_spec_for_every_length() {
        let payload: u64 = kani::any();
        let chunk_ct = stream::CHUNK_CT as u64;
        let final_len = payload % chunk_ct;
        let should_accept =
            payload >= stream::TAG as u64 && (final_len == 0 || final_len >= stream::TAG as u64);

        match stream::payload_geometry(payload) {
            Ok(geometry) => {
                assert!(should_accept);
                assert!(geometry.bytes == payload);
                assert!(geometry.chunks == payload.div_ceil(chunk_ct));
                assert!(geometry.chunks >= 1);
            }
            Err(_) => assert!(!should_accept),
        }
    }
}

#[cfg(kani)]
mod parser_proofs {
    use super::*;

    /// The allocation-free production policy implements the complete decision
    /// matrix for every byte count and both boolean observations.  This does
    /// not model `String`, UTF-8 decoding, trimming, or later stanza parsing.
    #[kani::proof]
    fn header_line_policy_matches_the_exact_decision_matrix() {
        let bytes_read: usize = kani::any();
        let ends_with_lf: bool = kani::any();
        let has_trailing_whitespace: bool = kani::any();

        let expected = if bytes_read == 0 {
            HeaderLinePolicy::UnexpectedEof
        } else if bytes_read >= MAX_HEADER_LINE && !ends_with_lf {
            HeaderLinePolicy::TooLong
        } else if !ends_with_lf {
            HeaderLinePolicy::MissingNewline
        } else if has_trailing_whitespace {
            HeaderLinePolicy::TrailingWhitespace
        } else {
            HeaderLinePolicy::Accept
        };
        let actual = header_line_policy(bytes_read, ends_with_lf, has_trailing_whitespace);

        assert_eq!(actual, expected);
        kani::cover!(matches!(actual, HeaderLinePolicy::UnexpectedEof));
        kani::cover!(matches!(actual, HeaderLinePolicy::TooLong));
        kani::cover!(matches!(actual, HeaderLinePolicy::MissingNewline));
        kani::cover!(matches!(actual, HeaderLinePolicy::TrailingWhitespace));
        kani::cover!(matches!(actual, HeaderLinePolicy::Accept));
    }
}
