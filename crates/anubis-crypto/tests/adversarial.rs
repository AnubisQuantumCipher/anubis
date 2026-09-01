//! Adversarial and property tests for the ANUBIS/v3 container.
//!
//! `vectors.rs` proves the happy paths and one representative of each
//! failure class. This file is the hostile counterpart: it enumerates
//! corruption instead of sampling it, and every test here is written so that
//! a plausible implementation bug flips it red.
//!
//! Two behaviours documented here belong specifically to the explicitly
//! provisional decryption APIs. Both are side effects rather than bypasses --
//! provisional decryption still returns `Err` when it must:
//!
//! 1. Plaintext reaches the writer BEFORE the ML-DSA-87 trailer is checked
//!    (`signature_failure_still_streams_plaintext_to_the_provisional_writer`).
//!    Inherent to streaming; the caller must not publish output on `Err`.
//! 2. A multi-chunk file extended with junk emits a decrypted PREFIX before
//!    erroring (`extending_a_multichunk_file_never_yields_whole_plaintext`).
//!    Same rule for the caller.
//!
//! Header canonicality is load-bearing and gets dedicated coverage: the MAC
//! authenticates the RAW on-disk prefix, and the parser refuses any line
//! that is not exactly LF-terminated with no trailing whitespace. Between
//! them there is no parse-equivalent re-encoding of a header, which
//! `reordering_the_signature_stanza_breaks_the_header_mac` pins directly --
//! that case parses to identical fields and is caught only by a MAC over the
//! bytes as written.

use std::io::Read;

use anubis_crypto::Error;
use anubis_crypto::armor;
use anubis_crypto::format::{
    self, Decrypted, DecryptionReport, EncryptOptions, Header, MAX_HEADER_LINE, MAX_STANZAS,
    SIG_LEN, WRAPPED_LEN,
};
use anubis_crypto::keys::{
    IDENTITY_LEN, Identity, MLDSA_VK_LEN, MLKEM_CT_LEN, RECIPIENT_LEN, Recipient, X25519_PUB_LEN,
};
use anubis_crypto::stream::{CHUNK, TAG};
use sha2::{Digest, Sha512};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn seal(data: &[u8], recipients: &[Recipient], signer: Option<&Identity>) -> Vec<u8> {
    let mut out = Vec::new();
    let opts = EncryptOptions { recipients, signer };
    format::encrypt(&opts, &mut &data[..], &mut out, |_| {}).expect("encrypt");
    out
}

/// Decrypt, returning both the outcome and whatever reached the writer.
///
/// The writer contents matter: "returned Err" and "emitted no plaintext"
/// are two different contracts and this suite checks both.
fn open_raw(sealed: &[u8], ids: &[Identity]) -> (anubis_crypto::Result<Decrypted>, Vec<u8>) {
    let mut out = Vec::new();
    let len = sealed.len() as u64;
    let res = format::decrypt(ids, &mut &sealed[..], len, &mut out, |_| {});
    (res, out)
}

/// Decrypt through the explicitly provisional sized API.
fn open_provisional_raw(
    sealed: &[u8],
    ids: &[Identity],
) -> (anubis_crypto::Result<DecryptionReport>, Vec<u8>) {
    let mut out = Vec::new();
    let len = sealed.len() as u64;
    let res = format::decrypt_provisional(ids, &mut &sealed[..], len, &mut out, |_| {});
    (res, out)
}

/// Decrypt with a caller-supplied `total_len` that need not match the slice.
fn open_with_len(
    sealed: &[u8],
    ids: &[Identity],
    total_len: u64,
) -> (anubis_crypto::Result<Decrypted>, Vec<u8>) {
    let mut out = Vec::new();
    let res = format::decrypt(ids, &mut &sealed[..], total_len, &mut out, |_| {});
    (res, out)
}

/// Provisional sized decrypt with a caller-supplied length.
fn open_provisional_with_len(
    sealed: &[u8],
    ids: &[Identity],
    total_len: u64,
) -> (anubis_crypto::Result<DecryptionReport>, Vec<u8>) {
    let mut out = Vec::new();
    let res = format::decrypt_provisional(ids, &mut &sealed[..], total_len, &mut out, |_| {});
    (res, out)
}

/// Decrypt through the unknown-length (pipe) path.
fn open_unsized<R: Read>(
    reader: R,
    ids: &[Identity],
) -> (anubis_crypto::Result<Decrypted>, Vec<u8>) {
    let mut out = Vec::new();
    let res = format::decrypt_unsized(ids, reader, &mut out, |_| {});
    (res, out)
}

/// Decrypt through the explicitly provisional unknown-length API.
fn open_unsized_provisional<R: Read>(
    reader: R,
    ids: &[Identity],
) -> (anubis_crypto::Result<DecryptionReport>, Vec<u8>) {
    let mut out = Vec::new();
    let res = format::decrypt_unsized_provisional(ids, reader, &mut out, |_| {});
    (res, out)
}

fn open(sealed: &[u8], ids: &[Identity]) -> anubis_crypto::Result<Vec<u8>> {
    let (res, out) = open_raw(sealed, ids);
    res.map(|_| out)
}

fn header_len_of(sealed: &[u8]) -> usize {
    format::inspect(&mut &sealed[..], sealed.len() as u64)
        .expect("inspect")
        .header_bytes as usize
}

/// Deterministic filler. A constant byte would hide chunk-ordering bugs,
/// so use a cheap xorshift instead.
fn pseudo(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 33) as u8
        })
        .collect()
}

/// A reader that never returns more than `max` bytes per call, modelling a
/// pipe under back-pressure. The unknown-length decrypt path must cope.
struct Choked<'a> {
    data: &'a [u8],
    max: usize,
}

impl Read for Choked<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.data.len().min(out.len()).min(self.max);
        out[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

fn choked(data: &[u8], max: usize) -> Choked<'_> {
    Choked { data, max }
}

/// Base64 (standard, no padding) of `n` zero bytes: every 6-bit group is
/// zero, so the encoding is `ceil(n * 8 / 6)` copies of 'A'. The trailing
/// bits are zero, i.e. canonical, so `STANDARD_NO_PAD` accepts it.
fn b64_zeros(n: usize) -> String {
    "A".repeat((n * 8).div_ceil(6))
}

/// A structurally valid but cryptographically meaningless header.
fn synthetic_header(stanzas: usize, signed: bool) -> Vec<u8> {
    let mut s = String::new();
    s.push_str(format::MAGIC);
    s.push('\n');
    let epk = b64_zeros(X25519_PUB_LEN);
    let ct = b64_zeros(MLKEM_CT_LEN);
    let wrapped = b64_zeros(WRAPPED_LEN);
    for _ in 0..stanzas {
        s.push_str("-> ");
        s.push_str(format::STANZA_HYBRID);
        s.push(' ');
        s.push_str(&epk);
        s.push(' ');
        s.push_str(&ct);
        s.push('\n');
        s.push_str(&wrapped);
        s.push('\n');
    }
    if signed {
        s.push_str("-> ");
        s.push_str(format::STANZA_SIG);
        s.push(' ');
        s.push_str(&b64_zeros(MLDSA_VK_LEN));
        s.push('\n');
    }
    s.push_str("--- ");
    s.push_str(&b64_zeros(64));
    s.push('\n');
    s.into_bytes()
}

/// Assert that decryption refuses `bytes` without panicking and without
/// releasing a single plaintext byte. Returns the error for classification.
fn must_refuse(bytes: &[u8], id: &Identity, label: &str) -> Error {
    let (res, out) = open_raw(bytes, std::slice::from_ref(id));
    let err = match res {
        Ok(_) => panic!("{label}: decrypt accepted a malformed file"),
        Err(e) => e,
    };
    assert!(
        out.is_empty(),
        "{label}: malformed file produced {} bytes of output",
        out.len()
    );
    err
}

/// Split a header into lines, apply `f`, and reassemble with the payload and
/// any trailer intact.
fn rewrite_header_lines<F: FnOnce(&mut Vec<String>)>(sealed: &[u8], f: F) -> Vec<u8> {
    let hlen = header_len_of(sealed);
    let text = String::from_utf8(sealed[..hlen].to_vec()).expect("header is utf-8");
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    f(&mut lines);
    let mut out = Vec::with_capacity(sealed.len());
    for line in &lines {
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(&sealed[hlen..]);
    out
}

// ---------------------------------------------------------------------------
// 1. exhaustive single-bit corruption
// ---------------------------------------------------------------------------

/// Every bit position at the dense offsets, plus one rotating bit position
/// on a stride sweep across the whole file. `boundaries` are region joins,
/// which get the dense treatment along with both of their neighbours.
fn bit_probes(len: usize, boundaries: &[usize]) -> Vec<(usize, u8)> {
    let mut dense: Vec<usize> = Vec::new();
    dense.extend(0..len.min(32));
    dense.extend(len.saturating_sub(32)..len);
    for &b in boundaries {
        for d in [b.saturating_sub(1), b, b + 1] {
            if d < len {
                dense.push(d);
            }
        }
    }
    dense.sort_unstable();
    dense.dedup();

    let mut probes = Vec::with_capacity(dense.len() * 8 + len / 17 + 1);
    for &o in &dense {
        for bit in 0..8u32 {
            probes.push((o, 1u8 << bit));
        }
    }
    // Stride sweep: 17 is coprime with every field width in the header, so
    // the sweep does not settle into one column of the base64 grid.
    for o in (0..len).step_by(17) {
        if dense.binary_search(&o).is_err() {
            probes.push((o, 1u8 << (o % 8)));
        }
    }
    probes
}

#[test]
fn every_single_bit_flip_in_an_unsigned_file_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = pseudo(200, 0xA1);
    let sealed = seal(&msg, &[r], None);
    let hlen = header_len_of(&sealed);
    assert_eq!(sealed.len(), hlen + msg.len() + TAG);

    let probes = bit_probes(sealed.len(), &[hlen]);
    assert!(probes.len() > 400, "probe set too thin: {}", probes.len());

    for (off, mask) in probes {
        let mut bad = sealed.clone();
        bad[off] ^= mask;
        let (res, out) = open_raw(&bad, std::slice::from_ref(&id));
        assert!(
            res.is_err(),
            "bit {mask:#04x} at offset {off} (header_len {hlen}) decrypted successfully"
        );
        // Single chunk, no signature: nothing may reach the writer at all.
        assert!(
            out.is_empty(),
            "bit {mask:#04x} at offset {off} emitted {} bytes",
            out.len()
        );
    }
}

#[test]
fn every_single_bit_flip_in_a_signed_file_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = pseudo(200, 0xB2);
    let sealed = seal(&msg, &[r], Some(&id));
    let hlen = header_len_of(&sealed);
    let trailer = sealed.len() - SIG_LEN;
    assert_eq!(trailer, hlen + msg.len() + TAG);

    let probes = bit_probes(sealed.len(), &[hlen, trailer]);
    assert!(probes.len() > 800, "probe set too thin: {}", probes.len());

    for (off, mask) in probes {
        let mut bad = sealed.clone();
        bad[off] ^= mask;
        let (res, out) = open_provisional_raw(&bad, std::slice::from_ref(&id));
        let err = match res {
            Ok(_) => panic!("bit {mask:#04x} at offset {off} decrypted successfully"),
            Err(e) => e,
        };
        if off < trailer {
            assert!(
                out.is_empty(),
                "bit {mask:#04x} at offset {off} (pre-trailer) emitted {} bytes",
                out.len()
            );
        } else {
            // PROVISIONAL-API BEHAVIOUR: a corrupt trailer is only detected
            // after the payload has been decrypted into caller-owned private
            // staging. The error is always BadSignature, and the caller is
            // responsible for discarding that staging output.
            assert!(
                matches!(err, Error::BadSignature),
                "trailer corruption at {off} gave {err} instead of a signature failure"
            );
            assert_eq!(
                out, msg,
                "trailer corruption at {off} should have streamed the payload first"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 2. truncation at every boundary
// ---------------------------------------------------------------------------

#[test]
fn truncation_at_every_boundary_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = pseudo(300, 0xC3);

    for signed in [false, true] {
        let signer = if signed { Some(&id) } else { None };
        let sealed = seal(&msg, std::slice::from_ref(&r), signer);
        let hlen = header_len_of(&sealed);
        let total = sealed.len();

        let mut cuts = vec![0, 1, hlen - 1, hlen, hlen + 1, hlen + 16, total - 1];
        cuts.sort_unstable();
        cuts.dedup();
        assert_eq!(cuts.len(), 7, "expected 7 distinct cut points");

        for cut in cuts {
            let (res, out) = open_raw(&sealed[..cut], std::slice::from_ref(&id));
            assert!(
                res.is_err(),
                "signed={signed}: truncation to {cut} bytes (header_len {hlen}) decrypted"
            );
            assert!(
                out.is_empty(),
                "signed={signed}: truncation to {cut} emitted {} bytes",
                out.len()
            );

            // The unknown-length path must reach the same verdict; it has no
            // length field to lean on at all.
            let (res, out) = open_unsized(&sealed[..cut], std::slice::from_ref(&id));
            assert!(
                res.is_err(),
                "signed={signed}: unsized truncation to {cut} decrypted"
            );
            assert!(
                out.is_empty(),
                "signed={signed}: unsized cut {cut} emitted output"
            );
        }
    }
}

#[test]
fn truncating_a_multichunk_payload_yields_only_a_prefix() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = pseudo(2 * CHUNK + 77, 0xD4);
    let sealed = seal(&msg, &[r], None);

    // Drop the whole final chunk. The STREAM final-flag rule must catch it.
    let cut = sealed.len() - (77 + TAG);
    let (res, out) = open_provisional_raw(&sealed[..cut], std::slice::from_ref(&id));
    assert!(res.is_err(), "dropping the final chunk was not detected");
    assert!(
        out.len() < msg.len(),
        "truncation returned the full plaintext"
    );
    assert_eq!(out.as_slice(), &msg[..out.len()], "output is not a prefix");
}

#[test]
fn a_lying_total_length_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = b"length is an input, not a fact";
    let sealed = seal(msg, &[r], None);
    let hlen = header_len_of(&sealed) as u64;

    // Overstated: the payload region is not fully consumed. Without that
    // explicit check this would decrypt happily, because the chunk loop
    // simply stops at EOF and never notices the unread remainder.
    //
    // DOCUMENTED BEHAVIOUR: the region check runs AFTER the chunk loop, so
    // by the time it fires the writer has already received the plaintext.
    // Nothing unauthenticated escapes -- every chunk that was written
    // verified its own tag with the correct final flag, so those bytes are
    // exactly the sender's plaintext -- but the caller must still discard
    // its output on Err, the same rule as a signature failure. Note also
    // that only the CALLER can lie this way: a real file's size matches its
    // bytes, and an attacker who appends to the file instead is caught by
    // the chunk tag with no output at all (see the extension tests).
    for extra in [1u64, 16, 4096] {
        let (res, out) = open_provisional_with_len(
            &sealed,
            std::slice::from_ref(&id),
            sealed.len() as u64 + extra,
        );
        assert!(
            matches!(res, Err(Error::Integrity(_))),
            "total_len overstated by {extra} was accepted"
        );
        assert_eq!(
            out, msg,
            "overstated by {extra}: the payload is authentic and already \
             written; if this ever changes, revisit the caller contract"
        );
    }

    // Understated below the header: caught by the truncation guard, before
    // any payload byte is read.
    let (res, out) = open_with_len(&sealed, std::slice::from_ref(&id), hlen - 1);
    assert!(
        matches!(res, Err(Error::Integrity(_))),
        "an understated total_len passed the truncation guard"
    );
    assert!(out.is_empty(), "understated total_len emitted output");

    // Understated inside the payload: the tag no longer covers the bytes.
    let (res, out) = open_with_len(&sealed, std::slice::from_ref(&id), sealed.len() as u64 - 1);
    assert!(res.is_err(), "an understated total_len decrypted");
    assert!(out.is_empty(), "understated total_len emitted output");
}

// ---------------------------------------------------------------------------
// 3. extension
// ---------------------------------------------------------------------------

#[test]
fn appending_junk_to_an_unsigned_file_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = pseudo(1000, 0xE5);
    let sealed = seal(&msg, &[r], None);

    for extra in [1usize, 16, 65536] {
        let mut bad = sealed.clone();
        bad.extend(std::iter::repeat_n(0x5A, extra));

        let (res, out) = open_raw(&bad, std::slice::from_ref(&id));
        assert!(
            res.is_err(),
            "unsigned file extended by {extra} bytes decrypted a prefix silently"
        );
        // One-chunk file: the appended bytes land inside the only chunk, so
        // the tag fails before anything is written.
        assert!(
            out.is_empty(),
            "unsigned + {extra} junk bytes emitted {} bytes",
            out.len()
        );

        // The unsized path is the interesting one: it reads to EOF rather
        // than to a known length, so it has no length field to notice the
        // extension with. The STREAM final-chunk flag must carry it alone.
        let (res, out) = open_unsized(&bad[..], std::slice::from_ref(&id));
        assert!(
            res.is_err(),
            "unsized unsigned file extended by {extra} bytes was accepted"
        );
        assert!(out.is_empty(), "unsized + {extra} junk emitted output");
    }
}

#[test]
fn appending_junk_to_a_signed_file_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = pseudo(1000, 0xF6);
    let sealed = seal(&msg, &[r], Some(&id));

    for extra in [1usize, 16, 65536] {
        let mut bad = sealed.clone();
        bad.extend(std::iter::repeat_n(0x5A, extra));

        // Extension shifts the signature window, so the bytes handed to the
        // stream now include real signature bytes: the payload tag fails and
        // nothing is written.
        let (res, out) = open_raw(&bad, std::slice::from_ref(&id));
        assert!(
            res.is_err(),
            "signed file extended by {extra} bytes was accepted"
        );
        assert!(
            out.is_empty(),
            "signed + {extra} junk bytes emitted {} bytes",
            out.len()
        );

        let (res, out) = open_unsized(&bad[..], std::slice::from_ref(&id));
        assert!(
            res.is_err(),
            "unsized signed file extended by {extra} bytes was accepted"
        );
        assert!(
            out.is_empty(),
            "unsized signed + {extra} junk emitted output"
        );
    }
}

#[test]
fn extending_a_multichunk_file_never_yields_whole_plaintext() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = pseudo(2 * CHUNK + 50, 0x17);
    let sealed = seal(&msg, &[r], None);

    for extra in [1usize, 16, 65536] {
        let mut bad = sealed.clone();
        bad.extend(std::iter::repeat_n(0xC3, extra));
        for (label, (res, out)) in [
            (
                "sized",
                open_provisional_raw(&bad, std::slice::from_ref(&id)),
            ),
            (
                "unsized",
                open_unsized_provisional(&bad[..], std::slice::from_ref(&id)),
            ),
        ] {
            assert!(
                res.is_err(),
                "{label}: multi-chunk file extended by {extra} decrypted"
            );
            // DOCUMENTED BEHAVIOUR: chunks 0..n-1 are genuine and
            // authenticate normally, so their plaintext is streamed before
            // the tampered final chunk is rejected. A prefix escapes; the
            // whole plaintext never does, and the call still fails.
            assert!(
                out.len() < msg.len(),
                "{label}: extension by {extra} released {} of {} plaintext bytes",
                out.len(),
                msg.len()
            );
            assert_eq!(
                out.as_slice(),
                &msg[..out.len()],
                "{label}: released bytes are not a genuine prefix"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. malformed headers: error, never panic
// ---------------------------------------------------------------------------

#[test]
fn empty_and_stub_inputs_are_refused() {
    let id = Identity::generate().unwrap();

    // Empty input.
    let err = must_refuse(b"", &id, "empty");
    assert!(matches!(err, Error::Header(_)), "empty input: {err}");

    // Magic line only.
    let only_magic = format!("{}\n", format::MAGIC).into_bytes();
    let err = must_refuse(&only_magic, &id, "magic only");
    assert!(matches!(err, Error::Header(_)), "magic only: {err}");

    // Magic with no newline at all: a header line must be LF-terminated.
    let err = must_refuse(format::MAGIC.as_bytes(), &id, "magic, unterminated");
    assert!(matches!(err, Error::Header(_)), "unterminated magic: {err}");

    // A complete stanza but no MAC line: EOF mid-header.
    let mut no_mac = synthetic_header(1, false);
    let mac_at = no_mac.len() - (b"--- ".len() + b64_zeros(64).len() + 1);
    no_mac.truncate(mac_at);
    let err = must_refuse(&no_mac, &id, "no MAC line");
    assert!(matches!(err, Error::Header(_)), "missing MAC line: {err}");

    // MAC line present, but no recipient stanza precedes it.
    let no_stanzas = format!("{}\n--- {}\n", format::MAGIC, b64_zeros(64)).into_bytes();
    let err = must_refuse(&no_stanzas, &id, "no stanzas");
    assert!(matches!(err, Error::Header(_)), "no stanzas: {err}");
}

#[test]
fn stanzas_with_the_wrong_argument_count_are_refused() {
    let id = Identity::generate().unwrap();
    let tail = format!("{}\n--- {}\n", b64_zeros(WRAPPED_LEN), b64_zeros(64));

    let cases: Vec<(&str, String)> = vec![
        (
            "hybrid, no arguments",
            format!("-> {}\n", format::STANZA_HYBRID),
        ),
        (
            "hybrid, one argument",
            format!(
                "-> {} {}\n",
                format::STANZA_HYBRID,
                b64_zeros(X25519_PUB_LEN)
            ),
        ),
        (
            "hybrid, three arguments",
            format!(
                "-> {} {} {} {}\n",
                format::STANZA_HYBRID,
                b64_zeros(X25519_PUB_LEN),
                b64_zeros(MLKEM_CT_LEN),
                b64_zeros(8)
            ),
        ),
        (
            "signature, no arguments",
            format!("-> {}\n", format::STANZA_SIG),
        ),
        (
            "signature, two arguments",
            format!(
                "-> {} {} {}\n",
                format::STANZA_SIG,
                b64_zeros(MLDSA_VK_LEN),
                b64_zeros(4)
            ),
        ),
    ];

    for (label, stanza) in cases {
        let file = format!("{}\n{}{}", format::MAGIC, stanza, tail).into_bytes();
        let err = must_refuse(&file, &id, label);
        assert!(
            matches!(err, Error::Header(_)),
            "{label}: expected a header error, got {err}"
        );
    }
}

#[test]
fn base64_fields_of_the_wrong_length_are_refused() {
    let id = Identity::generate().unwrap();
    let ok_epk = b64_zeros(X25519_PUB_LEN);
    let ok_ct = b64_zeros(MLKEM_CT_LEN);
    let ok_wrapped = b64_zeros(WRAPPED_LEN);
    let ok_mac = b64_zeros(64);

    // Each case is a header in which exactly one field decodes to the wrong
    // number of bytes. The length checks, not the MAC, must catch these:
    // the MAC cannot even be computed without a file key.
    let cases: Vec<(&str, String)> = vec![
        (
            "epk 31 bytes",
            format!(
                "{}\n-> {} {} {}\n{}\n--- {}\n",
                format::MAGIC,
                format::STANZA_HYBRID,
                b64_zeros(X25519_PUB_LEN - 1),
                ok_ct,
                ok_wrapped,
                ok_mac
            ),
        ),
        (
            "epk 33 bytes",
            format!(
                "{}\n-> {} {} {}\n{}\n--- {}\n",
                format::MAGIC,
                format::STANZA_HYBRID,
                b64_zeros(X25519_PUB_LEN + 1),
                ok_ct,
                ok_wrapped,
                ok_mac
            ),
        ),
        (
            "ml-kem ciphertext one byte short",
            format!(
                "{}\n-> {} {} {}\n{}\n--- {}\n",
                format::MAGIC,
                format::STANZA_HYBRID,
                ok_epk,
                b64_zeros(MLKEM_CT_LEN - 1),
                ok_wrapped,
                ok_mac
            ),
        ),
        (
            "wrapped key 47 bytes",
            format!(
                "{}\n-> {} {} {}\n{}\n--- {}\n",
                format::MAGIC,
                format::STANZA_HYBRID,
                ok_epk,
                ok_ct,
                b64_zeros(WRAPPED_LEN - 1),
                ok_mac
            ),
        ),
        (
            "MAC 63 bytes",
            format!(
                "{}\n-> {} {} {}\n{}\n--- {}\n",
                format::MAGIC,
                format::STANZA_HYBRID,
                ok_epk,
                ok_ct,
                ok_wrapped,
                b64_zeros(63)
            ),
        ),
        (
            "verifying key one byte short",
            format!(
                "{}\n-> {} {} {}\n{}\n-> {} {}\n--- {}\n",
                format::MAGIC,
                format::STANZA_HYBRID,
                ok_epk,
                ok_ct,
                ok_wrapped,
                format::STANZA_SIG,
                b64_zeros(MLDSA_VK_LEN - 1),
                ok_mac
            ),
        ),
        (
            "epk is not base64 at all",
            format!(
                "{}\n-> {} !!!!! {}\n{}\n--- {}\n",
                format::MAGIC,
                format::STANZA_HYBRID,
                ok_ct,
                ok_wrapped,
                ok_mac
            ),
        ),
        (
            // Length 1 mod 4 is not a valid unpadded base64 length.
            "epk base64 length 1 mod 4",
            format!(
                "{}\n-> {} {} {}\n{}\n--- {}\n",
                format::MAGIC,
                format::STANZA_HYBRID,
                "A".repeat(45),
                ok_ct,
                ok_wrapped,
                ok_mac
            ),
        ),
        (
            // 'B' in the final position sets bits a 32-byte value cannot
            // use. STANDARD_NO_PAD rejects non-canonical trailing bits; if
            // it did not, one logical header would have several accepted
            // byte encodings, which is the malleability the raw-bytes header
            // MAC exists to prevent.
            "epk with non-canonical trailing bits",
            format!(
                "{}\n-> {} {}B {}\n{}\n--- {}\n",
                format::MAGIC,
                format::STANZA_HYBRID,
                "A".repeat(X25519_PUB_LEN * 8 / 6),
                ok_ct,
                ok_wrapped,
                ok_mac
            ),
        ),
    ];

    for (label, text) in cases {
        let err = must_refuse(text.as_bytes(), &id, label);
        assert!(
            matches!(err, Error::Header(_)),
            "{label}: expected a header error, got {err}"
        );
    }
}

#[test]
fn header_lines_are_strictly_canonical() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let sealed = seal(b"canonical headers only", &[r], None);
    assert!(open(&sealed, std::slice::from_ref(&id)).is_ok());

    // Trailing whitespace on any header line must be refused. Before this
    // rule existed, a keyless attacker could add trailing spaces anywhere in
    // an unsigned header and the file still decrypted, because the MAC was
    // computed over a re-serialised canonical form rather than the bytes.
    for (label, suffix) in [
        ("space", " "),
        ("tab", "\t"),
        ("two spaces", "  "),
        ("carriage return", "\r"),
    ] {
        for line_idx in 0..4usize {
            let bad = rewrite_header_lines(&sealed, |lines| {
                if line_idx < lines.len() {
                    lines[line_idx].push_str(suffix);
                }
            });
            let err = must_refuse(&bad, &id, &format!("{label} on line {line_idx}"));
            assert!(
                matches!(err, Error::Header(_)),
                "{label} on line {line_idx}: expected a header error, got {err}"
            );
        }
    }

    // A blank line anywhere inside the header is not a stanza.
    let bad = rewrite_header_lines(&sealed, |lines| lines.insert(1, String::new()));
    let err = must_refuse(&bad, &id, "blank line");
    assert!(matches!(err, Error::Header(_)), "blank line: {err}");
}

#[test]
fn crlf_line_endings_are_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();

    for signed in [false, true] {
        let signer = if signed { Some(&id) } else { None };
        let sealed = seal(
            b"CRLF is not a canonical ANUBIS header",
            std::slice::from_ref(&r),
            signer,
        );
        let hlen = header_len_of(&sealed);

        let mut crlf = Vec::with_capacity(sealed.len() + 64);
        for &b in &sealed[..hlen] {
            if b == b'\n' {
                crlf.push(b'\r');
            }
            crlf.push(b);
        }
        crlf.extend_from_slice(&sealed[hlen..]);
        assert!(crlf.len() > sealed.len());

        // A CR is trailing whitespace, so parsing refuses it outright rather
        // than accepting two byte encodings of one logical header.
        let err = must_refuse(&crlf, &id, &format!("CRLF, signed={signed}"));
        assert!(
            matches!(err, Error::Header(_)),
            "CRLF signed={signed}: expected a header error, got {err}"
        );
    }
}

#[test]
fn reordering_recipient_stanzas_breaks_the_header_mac() {
    // The sharpest test of "the MAC covers the raw bytes". Recipient order is
    // the writer's order and carries no meaning to the parser: swapping two
    // recipient stanzas yields the same set of stanzas, so a MAC over a
    // canonical re-serialisation of the parsed fields would still verify.
    // Only a MAC over the on-disk prefix notices. The swap is
    // length-preserving, so nothing else about the file changes.
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let rs = [a.to_recipient().unwrap(), b.to_recipient().unwrap()];
    let sealed = seal(b"who signed this, and where does it say so", &rs, Some(&a));

    // A recipient stanza is TWO lines: the tagged line and its continuation
    // body. Both must move together, or the swap detaches a wrapped key from
    // its stanza and the result fails to decapsulate for an uninteresting
    // reason instead of failing the MAC for the interesting one.
    let rec_prefix = format!("-> {} ", format::STANZA_HYBRID);
    let moved = rewrite_header_lines(&sealed, |lines| {
        let heads: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.starts_with(&rec_prefix))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(heads.len(), 2, "expected two recipient stanzas");
        let (a0, b0) = (heads[0], heads[1]);
        assert_eq!(b0, a0 + 2, "each stanza should be two lines");
        lines.swap(a0, b0);
        lines.swap(a0 + 1, b0 + 1);
    });
    assert_eq!(moved.len(), sealed.len(), "the swap must preserve length");
    assert_ne!(moved, sealed);

    // It still parses, and to the same set of fields.
    let parsed = Header::parse(&mut &moved[..]).expect("reordered header parses");
    assert_eq!(parsed.stanzas.len(), 2);
    assert!(parsed.verifying_key.is_some());

    let err = must_refuse(&moved, &a, "reordered recipient stanzas");
    assert!(
        matches!(err, Error::Integrity(_)),
        "reordering must fail header authentication, got {err}"
    );
}

#[test]
fn signature_stanza_before_any_recipient_is_rejected() {
    // Section 4.3 requires this structurally, and structural rejection is
    // strictly stronger than catching it with the header MAC: the MAC needs
    // the file key, so only a recipient could ever notice. A parse-time
    // refusal is visible to anyone, including `verify`, which holds no key.
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let rs = [a.to_recipient().unwrap(), b.to_recipient().unwrap()];
    let sealed = seal(b"ordering is normative", &rs, Some(&a));

    let sig_prefix = format!("-> {} ", format::STANZA_SIG);
    let moved = rewrite_header_lines(&sealed, |lines| {
        let at = lines
            .iter()
            .position(|l| l.starts_with(&sig_prefix))
            .expect("signature stanza");
        let line = lines.remove(at);
        lines.insert(1, line);
    });

    let err = match Header::parse(&mut &moved[..]) {
        Err(e) => e,
        Ok(_) => panic!("a signature stanza before the recipients must be rejected"),
    };
    assert!(
        matches!(&err, Error::Header(m) if m.contains("before any recipient")),
        "expected an ordering refusal, got {err}"
    );
    // And the keyless verifier refuses it too, without any identity.
    assert!(format::verify(&moved[..], moved.len() as u64).is_err());
}

#[test]
fn a_second_signature_stanza_is_rejected() {
    // Last-wins on a duplicate would let one header advertise two signers
    // while each reader reports whichever its parser happened to keep. Two
    // readers disagreeing about who signed a file is the mistaken-identity
    // outcome the fingerprint namespaces exist to prevent.
    let a = Identity::generate().unwrap();
    let to = Identity::generate().unwrap();
    let sealed = seal(b"one signer only", &[to.to_recipient().unwrap()], Some(&a));

    let sig_prefix = format!("-> {} ", format::STANZA_SIG);
    let doubled = rewrite_header_lines(&sealed, |lines| {
        let at = lines
            .iter()
            .position(|l| l.starts_with(&sig_prefix))
            .expect("signature stanza");
        let line = lines[at].clone();
        lines.insert(at, line);
    });

    let err = match Header::parse(&mut &doubled[..]) {
        Err(e) => e,
        Ok(_) => panic!("a second signature stanza must be rejected"),
    };
    assert!(
        matches!(&err, Error::Header(m) if m.contains("more than one mldsa87")),
        "expected a cardinality refusal, got {err}"
    );
    assert!(format::verify(&doubled[..], doubled.len() as u64).is_err());
}

#[test]
fn header_lines_longer_than_the_cap_are_rejected() {
    let id = Identity::generate().unwrap();

    // Exactly at the cap with no terminator: refused by the cap, cheaply.
    let at_cap = vec![b'A'; MAX_HEADER_LINE];
    let err = must_refuse(&at_cap, &id, "line exactly at the cap");
    assert!(
        err.to_string().contains("exceeds"),
        "expected the line-length cap to fire, got: {err}"
    );

    // Over the cap, as a stanza line rather than the magic line.
    let mut over = format!("{}\n-> ", format::MAGIC).into_bytes();
    over.extend(std::iter::repeat_n(b'A', MAX_HEADER_LINE + 1));
    over.push(b'\n');
    let err = must_refuse(&over, &id, "stanza line over the cap");
    assert!(
        err.to_string().contains("exceeds"),
        "expected the line-length cap to fire, got: {err}"
    );

    // One byte under the cap, terminated: the cap must not fire, so the
    // failure comes from the content instead. This pins the boundary.
    let mut under = vec![b'A'; MAX_HEADER_LINE - 1];
    under.push(b'\n');
    let err = must_refuse(&under, &id, "line one byte under the cap");
    assert!(
        !err.to_string().contains("exceeds"),
        "the cap fired one byte early: {err}"
    );
    assert!(matches!(err, Error::Header(_)), "under the cap: {err}");
}

#[test]
fn an_endless_header_line_is_bounded() {
    let id = Identity::generate().unwrap();

    // 200 MiB with no newline, and then an INFINITE stream. Neither is
    // allocated by this test: the reader is generated. Both must fail
    // immediately, which is only possible because the parser bounds each
    // line read. Without the cap, `read_line` would slurp the whole stream
    // and the infinite case would never return.
    const HUGE: u64 = 200 * 1024 * 1024;
    let mut out = Vec::new();
    let res = format::decrypt(
        std::slice::from_ref(&id),
        std::io::repeat(b'A').take(HUGE),
        HUGE,
        &mut out,
        |_| {},
    );
    assert!(
        matches!(res, Err(Error::Header(_))),
        "a 200 MiB header line should be refused by the cap"
    );
    assert!(out.is_empty());

    let res = format::inspect(std::io::repeat(b'A').take(HUGE), HUGE);
    assert!(
        matches!(res, Err(Error::Header(_))),
        "inspect must be bounded too"
    );

    // Unbounded input on the pipe path. If the cap ever regresses, this test
    // hangs instead of failing, which is itself a loud signal.
    let mut out = Vec::new();
    let res = format::decrypt_unsized(
        std::slice::from_ref(&id),
        std::io::repeat(b'A'),
        &mut out,
        |_| {},
    );
    assert!(
        matches!(res, Err(Error::Header(_))),
        "an infinite header line must be refused"
    );
    assert!(out.is_empty());
}

#[test]
fn more_stanzas_than_the_cap_are_rejected() {
    let id = Identity::generate().unwrap();

    // Exactly at the cap: structurally acceptable, so the refusal has to
    // come from cryptography rather than from the cap.
    let mut at_cap = synthetic_header(MAX_STANZAS, false);
    let hlen = at_cap.len();
    at_cap.extend_from_slice(&[0u8; 64]);
    let info = format::inspect(&mut &at_cap[..], at_cap.len() as u64).expect("cap-sized header");
    assert_eq!(info.recipients, MAX_STANZAS);
    assert_eq!(info.header_bytes as usize, hlen);
    let err = must_refuse(&at_cap, &id, "1024 stanzas");
    assert!(matches!(err, Error::NoMatch), "1024 stanzas: {err}");

    // One over the cap, and the 10000 the brief asked for. Both must be
    // refused by the parser, before any decapsulation happens: the cap is
    // what bounds unauthenticated work, since every stanza costs an ML-KEM
    // key expansion plus a decapsulation.
    for n in [MAX_STANZAS + 1, 10_000] {
        let mut file = synthetic_header(n, false);
        file.extend_from_slice(&[0u8; 64]);
        let res = format::inspect(&mut &file[..], file.len() as u64);
        let err = match res {
            Ok(i) => panic!("{n} stanzas inspected fine, reporting {}", i.recipients),
            Err(e) => e,
        };
        assert!(
            err.to_string()
                .contains(&format!("more than {MAX_STANZAS}")),
            "{n} stanzas: expected the stanza cap to fire, got {err}"
        );
        let err = must_refuse(&file, &id, &format!("{n} stanzas"));
        assert!(matches!(err, Error::Header(_)), "{n} stanzas: {err}");
    }
}

#[test]
fn unknown_stanza_types_are_refused() {
    let id = Identity::generate().unwrap();
    let tail = format!("{}\n--- {}\n", b64_zeros(WRAPPED_LEN), b64_zeros(64));

    for stanza in [
        "-> quantum-magic AAAA\n",
        "-> HYBRID-X25519-MLKEM1024 AAAA AAAA\n", // case matters
        "-> mldsa65 AAAA\n",
        "-> hybrid-x25519-mlkem1024x AAAA AAAA\n",
    ] {
        let file = format!("{}\n{}{}", format::MAGIC, stanza, tail).into_bytes();
        let err = must_refuse(file.as_slice(), &id, stanza.trim_end());
        assert!(
            matches!(err, Error::Unsupported(_)),
            "{stanza:?}: expected 'unsupported', got {err}"
        );
    }

    // Lines that are neither a stanza nor a MAC line. Note that "-> " and
    // "--- " are trailing-whitespace violations, caught before dispatch.
    for line in [
        "\n",
        "hello\n",
        " -> hybrid-x25519-mlkem1024 A A\n",
        "---\n",
        "--- \n",
        "-> \n",
        "->\n",
    ] {
        let file = format!("{}\n{}{}", format::MAGIC, line, tail).into_bytes();
        let err = must_refuse(file.as_slice(), &id, line.trim_end());
        assert!(
            matches!(err, Error::Header(_)),
            "{line:?}: expected a header error, got {err}"
        );
    }
}

#[test]
fn a_duplicated_mac_line_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let sealed = seal(b"one MAC line, exactly", &[r], None);
    let hlen = header_len_of(&sealed);

    // The MAC line is the last line of the header.
    let mac_start = sealed[..hlen - 1]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|p| p + 1)
        .expect("header has more than one line");
    let mac_bytes = sealed[mac_start..hlen].to_vec();
    assert!(mac_bytes.starts_with(b"--- "));

    // Duplicate after the real MAC line: the parser stops at the first one,
    // so the copy becomes payload and the payload tag must fail. The header
    // itself still authenticates, which is correct -- it was not modified.
    let mut dup_after = sealed[..hlen].to_vec();
    dup_after.extend_from_slice(&mac_bytes);
    dup_after.extend_from_slice(&sealed[hlen..]);
    let err = must_refuse(&dup_after, &id, "duplicate MAC after");
    assert!(
        matches!(err, Error::Integrity(_)),
        "duplicate MAC after: {err}"
    );

    // Duplicate before the stanzas: the header ends before any stanza is
    // seen, which must be refused rather than treated as zero recipients.
    let mut dup_before = format!("{}\n", format::MAGIC).into_bytes();
    dup_before.extend_from_slice(&mac_bytes);
    dup_before.extend_from_slice(&sealed[format::MAGIC.len() + 1..]);
    let err = must_refuse(&dup_before, &id, "duplicate MAC before");
    assert!(
        matches!(err, Error::Header(_)),
        "duplicate MAC before: {err}"
    );
}

#[test]
fn legacy_stanza_and_version_lines_are_refused_specifically() {
    let id = Identity::generate().unwrap();
    let tail = format!("{}\n--- {}\n", b64_zeros(WRAPPED_LEN), b64_zeros(64));

    // v3 magic with the anubis-rage 1.4.0 stanza tag.
    let file = format!(
        "{}\n-> {} AAAA\n{}",
        format::MAGIC,
        format::LEGACY_STANZA_HYBRID,
        tail
    )
    .into_bytes();
    let err = must_refuse(&file, &id, "legacy hybrid stanza");
    assert!(matches!(err, Error::Unsupported(_)), "legacy stanza: {err}");

    for magic in [format::LEGACY_V1, format::LEGACY_V2] {
        let file = format!("{magic}\n-> whatever\n").into_bytes();
        let err = must_refuse(&file, &id, magic);
        assert!(
            matches!(err, Error::Unsupported(_)),
            "{magic}: expected 'unsupported', got {err}"
        );
        assert!(
            err.to_string().contains("MIGRATION.md"),
            "{magic}: the refusal should point somewhere useful: {err}"
        );
    }
}

#[test]
fn invalid_utf8_in_the_header_errors_without_panicking() {
    let id = Identity::generate().unwrap();
    // A lone 0x80 continuation byte cannot appear in valid UTF-8, and the
    // header is read line-wise into a String.
    let mut file = format!("{}\n-> ", format::MAGIC).into_bytes();
    file.extend_from_slice(&[0x80, 0xFF, 0xFE, b'\n']);
    file.extend_from_slice(format!("--- {}\n", b64_zeros(64)).as_bytes());
    let err = must_refuse(&file, &id, "invalid utf-8");
    assert!(matches!(err, Error::Io(_)), "invalid utf-8: {err}");

    // Invalid UTF-8 in the magic line itself.
    let mut file = vec![0xC3, 0x28, b'\n'];
    file.extend_from_slice(format!("--- {}\n", b64_zeros(64)).as_bytes());
    let err = must_refuse(&file, &id, "invalid utf-8 magic");
    assert!(matches!(err, Error::Io(_)), "invalid utf-8 magic: {err}");
}

// ---------------------------------------------------------------------------
// 5. chunk-boundary matrix
// ---------------------------------------------------------------------------

#[test]
fn chunk_boundary_matrix_round_trips_exactly() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();

    let lengths = [
        0,
        1,
        15,
        16,
        17,
        CHUNK - 1,
        CHUNK,
        CHUNK + 1,
        2 * CHUNK - 1,
        2 * CHUNK,
        2 * CHUNK + 1,
        3 * CHUNK + 123,
    ];

    for len in lengths {
        let data = pseudo(len, 0x9000 + len as u64);
        let sealed = seal(&data, std::slice::from_ref(&r), None);

        // Chunk count derived from the spec, not from the implementation:
        // 64 KiB chunks, and an empty payload still gets one final chunk.
        let expect_chunks = if len == 0 { 1 } else { len.div_ceil(CHUNK) };
        let info = format::inspect(&mut &sealed[..], sealed.len() as u64).unwrap();
        assert_eq!(info.chunks as usize, expect_chunks, "chunk count at {len}");
        assert_eq!(
            info.payload_bytes as usize,
            len + expect_chunks * TAG,
            "payload size at {len}"
        );
        assert_eq!(
            sealed.len(),
            info.header_bytes as usize + len + expect_chunks * TAG,
            "total size at {len}"
        );

        let (res, out) = open_raw(&sealed, std::slice::from_ref(&id));
        let d = res.unwrap_or_else(|e| panic!("decrypt failed at {len}: {e}"));
        assert_eq!(d.bytes as usize, len, "reported byte count at {len}");
        assert!(d.verified_key.is_none(), "unsigned file reported a signer");
        assert_eq!(out.len(), len, "output length at {len}");
        assert_eq!(out, data, "output content at {len}");
    }
}

#[test]
fn a_signed_file_at_a_chunk_boundary_still_verifies() {
    // The signature hashes header || ciphertext, which is where an off-by-one
    // in the chunk lookahead would show up as a verification failure.
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    for len in [CHUNK - 1, CHUNK, CHUNK + 1] {
        let data = pseudo(len, 0x77 + len as u64);
        let sealed = seal(&data, std::slice::from_ref(&r), Some(&id));
        let (res, out) = open_raw(&sealed, std::slice::from_ref(&id));
        let d = res.unwrap_or_else(|e| panic!("signed decrypt failed at {len}: {e}"));
        assert_eq!(out, data, "signed round trip at {len}");
        assert_eq!(
            d.verified_key.as_deref(),
            Some(id.verifying_key().encode().as_slice()),
            "signer at {len}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5b. the unknown-length (pipe) path
// ---------------------------------------------------------------------------

#[test]
fn decrypt_unsized_agrees_with_decrypt() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();

    for signed in [false, true] {
        let signer = if signed { Some(&id) } else { None };
        for len in [
            0,
            1,
            TAG,
            CHUNK - 1,
            CHUNK,
            CHUNK + 1,
            2 * CHUNK,
            2 * CHUNK + 9,
        ] {
            let data = pseudo(len, 0x5150 + len as u64);
            let sealed = seal(&data, std::slice::from_ref(&r), signer);

            let (sized, sized_out) = open_raw(&sealed, std::slice::from_ref(&id));
            let sized = sized.unwrap_or_else(|e| panic!("sized failed at {len}: {e}"));
            let (un, un_out) = open_unsized(&sealed[..], std::slice::from_ref(&id));
            let un = un.unwrap_or_else(|e| panic!("unsized failed at signed={signed} {len}: {e}"));

            assert_eq!(sized_out, data, "sized output at {len}");
            assert_eq!(un_out, data, "unsized output at signed={signed} {len}");
            assert_eq!(sized.bytes, un.bytes, "byte counts disagree at {len}");
            assert_eq!(
                sized.verified_key, un.verified_key,
                "signer disagrees at signed={signed} {len}"
            );
            assert_eq!(un.verified_key.is_some(), signed);
        }
    }
}

#[test]
fn decrypt_unsized_survives_a_choked_reader() {
    // A pipe may return a handful of bytes per read. The signed path peels
    // the 4627-byte trailer off with a delay window, which is exactly the
    // logic that small reads stress.
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();

    let small = pseudo(300, 0x2A);
    let sealed = seal(&small, std::slice::from_ref(&r), Some(&id));
    for max in [1usize, 3, 17, 4096] {
        let (res, out) = open_unsized(choked(&sealed, max), std::slice::from_ref(&id));
        let d = res.unwrap_or_else(|e| panic!("choked({max}) failed: {e}"));
        assert_eq!(out, small, "choked({max}) output");
        assert!(d.verified_key.is_some(), "choked({max}) lost the signer");
    }

    // Multi-chunk, so the trailer split happens after several chunks. Larger
    // reads only here: the delay window is topped up per outer read, so very
    // small reads over a large stream cost quadratic memmove.
    let big = pseudo(2 * CHUNK + 5, 0x2B);
    let sealed = seal(&big, std::slice::from_ref(&r), Some(&id));
    for max in [4096usize, 65536] {
        let (res, out) = open_unsized(choked(&sealed, max), std::slice::from_ref(&id));
        let d = res.unwrap_or_else(|e| panic!("choked({max}) multi-chunk failed: {e}"));
        assert_eq!(out, big, "choked({max}) multi-chunk output");
        assert!(d.verified_key.is_some());
    }

    // Unsigned, choked, and extended: the unsized unsigned path reads to
    // EOF, so only the final-chunk flag stands between it and silently
    // accepting a longer stream.
    let sealed = seal(&small, std::slice::from_ref(&r), None);
    let mut extended = sealed.clone();
    extended.push(0x00);
    let (res, out) = open_unsized(choked(&extended, 5), std::slice::from_ref(&id));
    assert!(res.is_err(), "choked unsigned extension was accepted");
    assert!(out.is_empty());
}

#[test]
fn decrypt_unsized_rejects_a_missing_trailer() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let sealed = seal(&pseudo(4000, 0x3C), std::slice::from_ref(&r), Some(&id));

    for gone in [1usize, 16, SIG_LEN - 1, SIG_LEN] {
        let (res, out) = open_unsized(&sealed[..sealed.len() - gone], std::slice::from_ref(&id));
        assert!(
            res.is_err(),
            "unsized: removing {gone} trailer bytes was accepted"
        );
        assert!(out.is_empty(), "unsized: removing {gone} emitted output");
    }

    // A signed container whose payload plus trailer is shorter than the
    // trailer itself: the delay window can never fill.
    let tiny = seal(b"", std::slice::from_ref(&r), Some(&id));
    let hlen = header_len_of(&tiny);
    let (res, _) = open_unsized(&tiny[..hlen + 8], std::slice::from_ref(&id));
    assert!(res.is_err(), "unsized: a stub trailer was accepted");
}

// ---------------------------------------------------------------------------
// 6. key separation properties
// ---------------------------------------------------------------------------

#[test]
fn independently_generated_identities_never_collide() {
    const N: usize = 12;
    let ids: Vec<Identity> = (0..N).map(|_| Identity::generate().unwrap()).collect();
    let recipients: Vec<Recipient> = ids.iter().map(|i| i.to_recipient().unwrap()).collect();

    let mut payloads: Vec<Vec<u8>> = recipients.iter().map(Recipient::to_payload).collect();
    let mut prints: Vec<String> = recipients.iter().map(Recipient::fingerprint).collect();
    let mut secrets: Vec<Vec<u8>> = ids.iter().map(Identity::to_payload).collect();

    for p in &payloads {
        assert_eq!(p.len(), RECIPIENT_LEN);
    }
    for s in &secrets {
        assert_eq!(s.len(), IDENTITY_LEN);
    }
    for f in &prints {
        assert_eq!(f.len(), 24, "fingerprint shape: {f}");
        assert_eq!(f.matches('-').count(), 4, "fingerprint groups: {f}");
        assert!(
            f.chars().all(|c| c == '-' || c.is_ascii_hexdigit()),
            "fingerprint alphabet: {f}"
        );
    }

    payloads.sort_unstable();
    payloads.dedup();
    prints.sort_unstable();
    prints.dedup();
    secrets.sort_unstable();
    secrets.dedup();
    assert_eq!(
        payloads.len(),
        N,
        "two identities produced the same recipient"
    );
    assert_eq!(
        prints.len(),
        N,
        "two identities produced the same fingerprint"
    );
    assert_eq!(secrets.len(), N, "two identities produced the same secret");
}

#[test]
fn an_identity_cannot_open_another_identitys_file() {
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let sealed = seal(b"for alice only", &[alice.to_recipient().unwrap()], None);

    let (res, out) = open_raw(&sealed, std::slice::from_ref(&bob));
    assert!(
        matches!(res, Err(Error::NoMatch)),
        "a non-recipient must get NoMatch, got {:?}",
        res.err().map(|e| e.to_string())
    );
    assert!(
        out.is_empty(),
        "a non-recipient received {} bytes",
        out.len()
    );
    assert_eq!(
        open(&sealed, std::slice::from_ref(&alice)).unwrap(),
        b"for alice only"
    );

    // An empty identity list is the degenerate case of the same rule.
    let (res, _) = open_raw(&sealed, &[]);
    assert!(matches!(res, Err(Error::NoMatch)), "no identities at all");

    // A trailing identity in the list still works: the search covers all
    // identities, not just the first.
    let ids = [bob, Identity::generate().unwrap(), alice];
    assert_eq!(open(&sealed, &ids).unwrap(), b"for alice only");
}

#[test]
fn encrypting_the_same_plaintext_twice_produces_different_ciphertext() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = b"deterministic input, randomised output";

    let a = seal(msg, std::slice::from_ref(&r), None);
    let b = seal(msg, std::slice::from_ref(&r), None);
    assert_eq!(a.len(), b.len(), "same input should give the same length");
    assert_ne!(a, b, "two encryptions produced identical bytes");

    // Differ from the very first stanza onwards: fresh ephemeral X25519 key,
    // fresh ML-KEM ciphertext, fresh file key.
    let ha = Header::parse(&mut &a[..]).unwrap();
    let hb = Header::parse(&mut &b[..]).unwrap();
    assert_ne!(ha.stanzas[0].epk, hb.stanzas[0].epk, "ephemeral key reused");
    assert_ne!(
        ha.stanzas[0].mlkem_ct, hb.stanzas[0].mlkem_ct,
        "ML-KEM ciphertext reused"
    );
    assert_ne!(
        ha.stanzas[0].wrapped, hb.stanzas[0].wrapped,
        "wrapped key reused"
    );
    assert_ne!(ha.mac, hb.mac, "header MAC reused");
    let hlen = header_len_of(&a);
    assert_ne!(a[hlen..], b[hlen..], "payload ciphertext reused");

    assert_eq!(open(&a, std::slice::from_ref(&id)).unwrap(), msg);
    assert_eq!(open(&b, std::slice::from_ref(&id)).unwrap(), msg);
}

#[test]
fn the_same_recipient_listed_twice_uses_independent_wrap_keys() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = b"listed twice, wrapped twice";
    let sealed = seal(msg, &[r.clone(), r], None);

    let header = Header::parse(&mut &sealed[..]).unwrap();
    assert_eq!(header.stanzas.len(), 2);
    let (a, b) = (&header.stanzas[0], &header.stanzas[1]);

    assert_ne!(
        a.epk, b.epk,
        "the two stanzas share an ephemeral X25519 key"
    );
    assert_ne!(
        a.mlkem_ct, b.mlkem_ct,
        "the two stanzas share an ML-KEM ciphertext"
    );
    // The decisive assertion: the file key is wrapped under an all-zero
    // nonce, so equal wrapped bytes for equal plaintext would prove the wrap
    // key was reused -- a nonce reuse that leaks the Poly1305 key.
    assert_ne!(
        a.wrapped, b.wrapped,
        "identical wrapped keys prove wrap-key reuse under a zero nonce"
    );
    assert_eq!(a.wrapped.len(), WRAPPED_LEN);
    assert_eq!(b.wrapped.len(), WRAPPED_LEN);

    // And it still opens.
    assert_eq!(open(&sealed, std::slice::from_ref(&id)).unwrap(), msg);
    let info = format::inspect(&mut &sealed[..], sealed.len() as u64).unwrap();
    assert_eq!(info.recipients, 2);
}

#[test]
fn every_recipient_of_a_multi_recipient_file_gets_a_distinct_stanza() {
    let ids: Vec<Identity> = (0..4).map(|_| Identity::generate().unwrap()).collect();
    let rs: Vec<Recipient> = ids.iter().map(|i| i.to_recipient().unwrap()).collect();
    let msg = pseudo(4096, 0x44);
    let sealed = seal(&msg, &rs, None);

    let header = Header::parse(&mut &sealed[..]).unwrap();
    assert_eq!(header.stanzas.len(), 4);
    let mut epks: Vec<[u8; X25519_PUB_LEN]> = header.stanzas.iter().map(|s| s.epk).collect();
    let mut wrapped: Vec<Vec<u8>> = header.stanzas.iter().map(|s| s.wrapped.clone()).collect();
    epks.sort_unstable();
    epks.dedup();
    wrapped.sort_unstable();
    wrapped.dedup();
    assert_eq!(epks.len(), 4, "ephemeral keys are not per-recipient");
    assert_eq!(wrapped.len(), 4, "wrapped file keys are not per-recipient");

    for id in &ids {
        assert_eq!(open(&sealed, std::slice::from_ref(id)).unwrap(), msg);
    }

    // Swapping two stanzas' wrapped keys must break for EVERY recipient,
    // including the two whose stanzas were untouched: the header MAC covers
    // the whole prefix, not just the stanza a given reader used.
    let swapped = rewrite_header_lines(&sealed, |lines| {
        assert!(!lines[2].starts_with("-> ") && !lines[4].starts_with("-> "));
        lines.swap(2, 4);
    });
    assert_eq!(swapped.len(), sealed.len());
    for (n, id) in ids.iter().enumerate() {
        let (res, out) = open_raw(&swapped, std::slice::from_ref(id));
        assert!(
            res.is_err(),
            "swapped wrapped keys decrypted for identity {n}"
        );
        assert!(out.is_empty(), "identity {n} received output");
    }
}

// ---------------------------------------------------------------------------
// 7. signature downgrade
// ---------------------------------------------------------------------------

#[test]
fn stripping_the_signature_stanza_and_trailer_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = b"authenticated authorship";
    let sealed = seal(msg, &[r], Some(&id));

    // Forge the unsigned form of the same file: drop the "-> mldsa87 ..."
    // line from the header and drop the 4627-byte trailer.
    let sig_prefix = format!("-> {} ", format::STANZA_SIG);
    let mut removed = 0usize;
    let mut downgraded = rewrite_header_lines(&sealed, |lines| {
        let before = lines.len();
        lines.retain(|l| !l.starts_with(&sig_prefix));
        removed = before - lines.len();
    });
    assert_eq!(removed, 1, "expected exactly one signature stanza");
    downgraded.truncate(downgraded.len() - SIG_LEN);

    // The downgraded file parses cleanly and the file key still unwraps --
    // the stanza that carries it was untouched. What stops the attack is the
    // header MAC over the raw authenticated prefix: deleting the mldsa87
    // line changes those bytes. OBSERVED: Error::Integrity ("header
    // authentication failed"), reached before a payload byte is written.
    let parsed = Header::parse(&mut &downgraded[..]).expect("downgraded header still parses");
    assert!(parsed.verifying_key.is_none(), "signature stanza survived");
    assert_eq!(parsed.stanzas.len(), 1);

    let err = must_refuse(&downgraded, &id, "signature downgrade");
    assert!(
        matches!(err, Error::Integrity(_)),
        "signature downgrade: expected an integrity failure, got {err}"
    );
}

#[test]
fn stripping_only_the_signature_trailer_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let sealed = seal(&pseudo(9000, 0x88), &[r], Some(&id));

    // Whole trailer gone: the header still advertises a signature, so the
    // length accounting reassigns payload bytes to the trailer and the
    // payload tag fails.
    let err = must_refuse(&sealed[..sealed.len() - SIG_LEN], &id, "trailer removed");
    assert!(matches!(err, Error::Integrity(_)), "trailer removed: {err}");

    // Trailer one byte short.
    let (res, _) = open_raw(&sealed[..sealed.len() - 1], std::slice::from_ref(&id));
    assert!(res.is_err(), "a trailer one byte short was accepted");

    // Trailer replaced with zeros of the right length.
    let mut zeroed = sealed.clone();
    let n = zeroed.len();
    zeroed[n - SIG_LEN..].fill(0);
    let (res, _) = open_raw(&zeroed, std::slice::from_ref(&id));
    assert!(
        matches!(res, Err(Error::BadSignature)),
        "an all-zero signature was not rejected as a bad signature"
    );
}

#[test]
fn a_signature_from_the_wrong_key_is_rejected() {
    let signer = Identity::generate().unwrap();
    let impostor = Identity::generate().unwrap();
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();

    let real = seal(b"same payload", std::slice::from_ref(&r), Some(&signer));
    let other = seal(b"same payload", std::slice::from_ref(&r), Some(&impostor));
    assert_eq!(real.len(), other.len());

    // Transplant the impostor's trailer onto the genuine file. The verifying
    // key in the header is still the signer's, so verification must fail.
    let mut swapped = real.clone();
    let n = swapped.len();
    swapped[n - SIG_LEN..].copy_from_slice(&other[other.len() - SIG_LEN..]);
    let (res, _) = open_raw(&swapped, std::slice::from_ref(&id));
    assert!(
        matches!(res, Err(Error::BadSignature)),
        "a foreign signature was accepted"
    );

    // Substituting the verifying key instead breaks the header MAC. Reuse
    // the impostor's own base64 rather than re-implementing an encoder.
    let sig_prefix = format!("-> {} ", format::STANZA_SIG);
    let vk_b64_len = (MLDSA_VK_LEN * 8).div_ceil(6);
    let other_vk = {
        let hlen = header_len_of(&other);
        let text = String::from_utf8(other[..hlen].to_vec()).unwrap();
        text.lines()
            .find(|l| l.starts_with(&sig_prefix))
            .expect("signature stanza")
            .to_string()
    };
    assert_eq!(other_vk.len(), sig_prefix.len() + vk_b64_len);
    let forged = rewrite_header_lines(&real, |lines| {
        let at = lines
            .iter()
            .position(|l| l.starts_with(&sig_prefix))
            .expect("signature stanza");
        assert_ne!(lines[at], other_vk, "the two verifying keys are identical");
        lines[at] = other_vk.clone();
    });
    assert_eq!(forged.len(), real.len());
    let err = must_refuse(&forged, &id, "substituted verifying key");
    assert!(
        matches!(err, Error::Integrity(_)),
        "substituting the verifying key: {err}"
    );
}

#[test]
fn signature_failure_still_streams_plaintext_to_the_provisional_writer() {
    // DOCUMENTED BEHAVIOUR. ANUBIS streams: the payload is decrypted and
    // written chunk by chunk, and the ML-DSA-87 trailer can only be checked
    // once the whole payload has been read. So on a signature failure the
    // provisional caller has ALREADY received the plaintext, even though
    // decrypt_provisional() returns Err. Every caller of that primitive MUST
    // discard its private staging output on Err rather than publishing it.
    let signer = Identity::generate().unwrap();
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = pseudo(500, 0x99);
    let mut sealed = seal(&msg, &[r], Some(&signer));
    let n = sealed.len();
    sealed[n - 1] ^= 0x80;

    let (res, out) = open_provisional_raw(&sealed, std::slice::from_ref(&id));
    assert!(
        matches!(res, Err(Error::BadSignature)),
        "corrupt signature must fail"
    );
    assert_eq!(
        out, msg,
        "this test exists to pin the streaming side effect; if the \
         implementation starts buffering, update the CLI contract too"
    );
}

#[test]
fn safe_decrypt_apis_publish_nothing_on_bad_signature_or_truncation() {
    let signer = Identity::generate().unwrap();
    let id = Identity::generate().unwrap();
    let recipient = id.to_recipient().unwrap();
    let plaintext = pseudo(CHUNK + 73, 0x5A5E);

    let mut bad_signature = seal(&plaintext, std::slice::from_ref(&recipient), Some(&signer));
    let last = bad_signature.len() - 1;
    bad_signature[last] ^= 0x40;
    for (label, (result, output)) in [
        (
            "sized bad signature",
            open_raw(&bad_signature, std::slice::from_ref(&id)),
        ),
        (
            "unsized bad signature",
            open_unsized(&bad_signature[..], std::slice::from_ref(&id)),
        ),
    ] {
        assert!(
            matches!(result, Err(Error::BadSignature)),
            "{label}: expected BadSignature"
        );
        assert!(output.is_empty(), "{label}: published plaintext");
    }

    let unsigned = seal(&plaintext, &[recipient], None);
    let truncated = &unsigned[..unsigned.len() - 1];
    for (label, (result, output)) in [
        (
            "sized truncation",
            open_raw(truncated, std::slice::from_ref(&id)),
        ),
        (
            "unsized truncation",
            open_unsized(truncated, std::slice::from_ref(&id)),
        ),
    ] {
        assert!(result.is_err(), "{label}: truncated container decrypted");
        assert!(output.is_empty(), "{label}: published plaintext");
    }
}

// ---------------------------------------------------------------------------
// 8. key encoding robustness
// ---------------------------------------------------------------------------

#[test]
fn recipient_decode_rejects_malformed_strings() {
    let id = Identity::generate().unwrap();
    let good = id.to_recipient().unwrap().encode().unwrap();
    assert!(Recipient::decode(&good).is_ok());

    let mut cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("whitespace only", "   \n\t ".into()),
        ("hrp only", "anubis".into()),
        ("separator only", "1".into()),
        ("empty data part", "anubis1".into()),
        ("checksum only", "anubis1qqqqqq".into()),
        ("wrong hrp", format!("age1{}", &good[7..])),
        (
            "bitcoin-shaped",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
        ),
        ("identity hrp", format!("ANUBIS-SECRET-KEY-1{}", &good[7..])),
        ("truncated to half", good[..good.len() / 2].to_string()),
        ("truncated by one", good[..good.len() - 1].to_string()),
        ("one char appended", format!("{good}q")),
        (
            "invalid bech32 char 'b'",
            format!("{}b", &good[..good.len() - 1]),
        ),
        (
            "invalid bech32 char 'i'",
            format!("{}i", &good[..good.len() - 1]),
        ),
        ("mixed case", good.to_uppercase() + "q"),
        ("nul byte", format!("{good}\0")),
        ("long garbage", "anubis1".to_string() + &"q".repeat(50_000)),
    ];
    // Single-character mutations spread across the data part.
    for k in 1..8 {
        let pos = 7 + (good.len() - 8) * k / 8;
        let mut s = good.clone();
        let ch = if s.as_bytes()[pos] == b'q' { 'p' } else { 'q' };
        s.replace_range(pos..pos + 1, &ch.to_string());
        cases.push(("mutated character", s));
    }

    for (label, s) in cases {
        assert!(
            Recipient::decode(&s).is_err(),
            "Recipient::decode accepted {label}"
        );
    }
}

#[test]
fn identity_decode_rejects_malformed_strings() {
    let id = Identity::generate().unwrap();
    let good = id.encode().unwrap();
    assert!(Identity::decode(&good).is_ok());
    // Bech32 is case-insensitive as a whole and the identity HRP is compared
    // case-insensitively, so the all-lowercase form must also decode.
    let lowercase = good.to_lowercase();
    let compatible = Identity::decode(&lowercase).expect("lowercase identity must decode");
    assert_eq!(
        compatible.encode().unwrap(),
        good,
        "lowercase identity must re-encode canonically"
    );

    let hrp_len = "ANUBIS-SECRET-KEY-1".len();
    let mut cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("hrp only", "ANUBIS-SECRET-KEY-".into()),
        ("empty data part", "ANUBIS-SECRET-KEY-1".into()),
        (
            "wrong hrp",
            format!("ANUBIS-PUBLIC-KEY-1{}", &good[hrp_len..]),
        ),
        ("recipient hrp", format!("anubis1{}", &good[hrp_len..])),
        ("truncated by one", good[..good.len() - 1].to_string()),
        ("truncated to half", good[..good.len() / 2].to_string()),
        ("one char appended", format!("{good}Q")),
        ("mixed case", format!("{}q", &good[..good.len() - 1])),
        (
            "long garbage",
            "ANUBIS-SECRET-KEY-1".to_string() + &"Q".repeat(50_000),
        ),
    ];
    for k in 1..8 {
        let pos = hrp_len + (good.len() - hrp_len - 1) * k / 8;
        let mut s = good.clone();
        let ch = if s.as_bytes()[pos] == b'Q' { 'P' } else { 'Q' };
        s.replace_range(pos..pos + 1, &ch.to_string());
        cases.push(("mutated character", s));
    }

    for (label, s) in cases {
        assert!(
            Identity::decode(&s).is_err(),
            "Identity::decode accepted {label}"
        );
    }
}

#[test]
fn recipient_and_identity_encodings_are_not_interchangeable() {
    let id = Identity::generate().unwrap();
    let secret = id.encode().unwrap();
    let public = id.to_recipient().unwrap().encode().unwrap();

    // A valid recipient must not decode as an identity, and vice versa.
    // Getting this wrong is how a secret key ends up in a public field.
    assert!(
        matches!(Identity::decode(&public), Err(Error::Key(_))),
        "a recipient string must not decode as an identity"
    );
    assert!(
        matches!(Recipient::decode(&secret), Err(Error::Key(_))),
        "an identity string must not decode as a recipient"
    );

    // Keys arrive surrounded by whitespace in the wild (copy and paste).
    let wrapped_recipient = format!("  {public}\n");
    assert_eq!(
        Recipient::decode(&wrapped_recipient)
            .expect("surrounding whitespace must be accepted")
            .encode()
            .unwrap(),
        public,
        "trimmed recipient must re-encode without whitespace"
    );
    let wrapped_identity = format!("\t{secret}  \n");
    assert_eq!(
        Identity::decode(&wrapped_identity)
            .expect("surrounding whitespace must be accepted")
            .encode()
            .unwrap(),
        secret,
        "trimmed identity must re-encode without whitespace"
    );
}

#[test]
fn from_payload_rejects_every_wrong_length() {
    for n in [
        0usize,
        1,
        RECIPIENT_LEN - 1,
        RECIPIENT_LEN + 1,
        IDENTITY_LEN,
        4096,
    ] {
        assert!(
            Recipient::from_payload(&vec![0u8; n]).is_err(),
            "Recipient::from_payload accepted {n} bytes"
        );
    }
    assert!(Recipient::from_payload(&vec![0u8; RECIPIENT_LEN]).is_ok());

    for n in [0usize, 1, IDENTITY_LEN - 1, IDENTITY_LEN + 1, RECIPIENT_LEN] {
        assert!(
            Identity::from_payload(&vec![0u8; n]).is_err(),
            "Identity::from_payload accepted {n} bytes"
        );
    }
    assert!(Identity::from_payload(&[0u8; IDENTITY_LEN]).is_ok());
}

#[test]
fn encrypting_to_no_recipients_is_refused() {
    let err = format::encrypt(
        &EncryptOptions {
            recipients: &[],
            signer: None,
        },
        &mut &b"nobody can read this"[..],
        &mut Vec::new(),
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(err, Error::Key(_)), "no recipients: {err}");
}

// ---------------------------------------------------------------------------
// 8b. ASCII armor
// ---------------------------------------------------------------------------

#[test]
fn armor_round_trips_and_is_recognised() {
    for len in [0usize, 1, 47, 48, 64, 65, 4096] {
        let raw = pseudo(len, 0x5000 + len as u64);
        let text = armor::encode(&raw);
        assert!(text.starts_with(armor::BEGIN), "missing begin boundary");
        assert!(text.ends_with('\n'), "armor must end with a newline");
        assert!(
            text.lines().any(|l| l == armor::END),
            "missing end boundary"
        );
        assert!(
            armor::looks_armored(text.as_bytes()),
            "not recognised at {len}"
        );
        assert_eq!(armor::decode(&text).unwrap(), raw, "round trip at {len}");

        // Every body line stays inside the PEM wrap width.
        for line in text
            .lines()
            .filter(|l| *l != armor::BEGIN && *l != armor::END)
        {
            assert!(line.len() <= 64, "body line too long: {}", line.len());
        }
    }
}

#[test]
fn armor_rejects_content_around_the_boundaries() {
    let raw = pseudo(200, 0x51);
    let good = armor::encode(&raw);

    // Content BEFORE the begin boundary.
    for prefix in ["hello\n", "-----BEGIN PGP MESSAGE-----\n", "AAAA\n", "\0\n"] {
        assert!(
            armor::decode(&format!("{prefix}{good}")).is_err(),
            "accepted content before the boundary: {prefix:?}"
        );
    }

    // Blank lines, indentation and a byte-order mark before the boundary are
    // benign: editors and mail clients add them. The sniff must agree with
    // the decoder, or a good file is reported as binary.
    for prefix in ["\n\n   \n", "\u{feff}", "\u{feff}\n\n", "   "] {
        let text = format!("{prefix}{good}");
        assert_eq!(
            armor::decode(&text).unwrap(),
            raw,
            "rejected benign prefix {prefix:?}"
        );
        assert!(
            armor::looks_armored(text.as_bytes()),
            "sniff disagrees with decode on prefix {prefix:?}"
        );
    }

    // Content AFTER the end boundary, including a whole second block: an
    // attacker must not be able to append an ignored payload.
    for suffix in ["extra\n", "AAAA\n", "-----END ANUBIS ENCRYPTED FILE-----\n"] {
        assert!(
            armor::decode(&format!("{good}{suffix}")).is_err(),
            "accepted content after the boundary: {suffix:?}"
        );
    }
    assert!(
        armor::decode(&format!("{good}{good}")).is_err(),
        "accepted two concatenated armor blocks"
    );

    // Lone and misordered boundaries.
    assert!(armor::decode(armor::BEGIN).is_err(), "begin alone");
    assert!(armor::decode(armor::END).is_err(), "end alone");
    assert!(armor::decode("").is_err(), "empty armor");
    assert!(armor::decode("\n\n\n").is_err(), "blank armor");
    assert!(
        armor::decode(&format!("{}\nAAAA\n", armor::BEGIN)).is_err(),
        "missing end boundary"
    );
    assert!(
        armor::decode(&format!("{}\nAAAA\n{}\n", armor::END, armor::BEGIN)).is_err(),
        "boundaries in the wrong order"
    );

    // A nested begin boundary inside the body.
    let nested = good.replace(armor::END, &format!("{}\n{}", armor::BEGIN, armor::END));
    assert!(
        armor::decode(&nested).is_err(),
        "accepted a nested begin boundary"
    );
}

#[test]
fn armor_rejects_corrupt_base64() {
    // 301 is not a multiple of three, so the encoding definitely ends in
    // padding, which the padding cases below depend on.
    let raw = pseudo(301, 0x52);
    let good = armor::encode(&raw);
    assert!(good.contains('='), "the fixture must contain padding");

    let body_line = |f: &dyn Fn(&str) -> String| -> String {
        let mut lines: Vec<String> = good.lines().map(str::to_string).collect();
        lines[2] = f(&lines[2]);
        lines.join("\n") + "\n"
    };

    // Padding is canonical: neither stripping nor adding it is accepted.
    assert!(
        armor::decode(&good.replace('=', "")).is_err(),
        "accepted armor with the padding stripped"
    );
    assert!(
        armor::decode(&good.replace("=\n", "==\n")).is_err(),
        "accepted armor with extra padding"
    );

    // An embedded NUL is not whitespace, so it must reach the decoder and be
    // refused rather than silently trimmed away.
    assert!(
        armor::decode(&body_line(&|l| format!("{l}\0"))).is_err(),
        "accepted a trailing NUL in a body line"
    );
    assert!(
        armor::decode(&body_line(&|l| format!("\0{}", &l[1..]))).is_err(),
        "accepted a NUL inside a body line"
    );

    // Non-base64 characters, a length that cannot be base64, and interior
    // whitespace, which trimming each line must not silently absorb.
    assert!(armor::decode(&body_line(&|l| format!("{l}!"))).is_err());
    assert!(armor::decode(&body_line(&|l| l[..l.len() - 1].to_string())).is_err());
    assert!(
        armor::decode(&body_line(&|l| format!("{} {}", &l[..8], &l[8..]))).is_err(),
        "accepted a space inside a body line"
    );
}

#[test]
fn armor_enforces_its_size_cap() {
    // Just under the cap round trips; just over is refused before the
    // decoder allocates anything further. `armored_len` models the encoding
    // rule exactly -- 4 base64 characters per 3 bytes, one newline per 64
    // characters, two boundary lines -- so the fixtures sit on either side
    // of the cap by construction rather than by guesswork.
    fn armored_len(raw: usize) -> usize {
        let b64 = 4 * raw.div_ceil(3);
        armor::BEGIN.len() + 1 + b64 + b64.div_ceil(64) + armor::END.len() + 1
    }

    let overhead = armor::BEGIN.len() + armor::END.len() + 2;
    // 65 characters of output (64 base64 plus a newline) per 48 input bytes.
    let mut under_raw = (armor::MAX_ARMOR_BYTES - overhead) * 48 / 65;
    while armored_len(under_raw) > armor::MAX_ARMOR_BYTES {
        under_raw -= 48;
    }
    // The model must match the real encoder, or the fixtures prove nothing.
    for probe in [0usize, 1, 2, 3, 47, 48, 49, 192, 4096] {
        assert_eq!(
            armored_len(probe),
            armor::encode(&vec![0x5A; probe]).len(),
            "length model disagrees with the encoder at {probe}"
        );
    }
    let under = armor::encode(&vec![0x5A; under_raw]);
    assert!(
        under.len() <= armor::MAX_ARMOR_BYTES,
        "fixture is not under the cap: {} > {}",
        under.len(),
        armor::MAX_ARMOR_BYTES
    );
    assert_eq!(
        armor::decode(&under).unwrap().len(),
        under_raw,
        "an armored file just under the cap must decode"
    );

    let over = armor::encode(&vec![0x5A; under_raw + 65536]);
    assert!(
        over.len() > armor::MAX_ARMOR_BYTES,
        "fixture is not over the cap"
    );
    let err = armor::decode(&over).expect_err("armor over the cap must be refused");
    assert!(
        err.to_string().contains("exceeds"),
        "expected the armor cap to fire, got: {err}"
    );
}

#[test]
fn armor_does_not_mask_an_integrity_failure() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = pseudo(2000, 0x53);
    let sealed = seal(&msg, &[r], Some(&id));

    // Armor is transport, not authentication: it must round trip the exact
    // container bytes and change no verdict.
    let text = armor::encode(&sealed);
    let back = armor::decode(&text).unwrap();
    assert_eq!(back, sealed, "armor is not byte-transparent");
    assert_eq!(open(&back, std::slice::from_ref(&id)).unwrap(), msg);

    // CRLF mangling by a mail transport is survivable for armor, which trims
    // each line -- unlike the container header, where a CR is fatal.
    let crlf = text.replace('\n', "\r\n");
    assert_eq!(
        armor::decode(&crlf).unwrap(),
        sealed,
        "armor should survive CRLF"
    );

    // A corrupted container inside valid armor must still be caught by the
    // container itself, in the header, the payload and the trailer alike.
    let hlen = header_len_of(&sealed);
    for at in [
        10usize,
        hlen - 2,
        hlen + 5,
        sealed.len() - SIG_LEN + 3,
        sealed.len() - 1,
    ] {
        let mut bad = sealed.clone();
        bad[at] ^= 0x01;
        let text = armor::encode(&bad);
        let back = armor::decode(&text).expect("armor of a corrupt container still decodes");
        assert_eq!(back, bad, "armor altered the bytes at {at}");
        let (res, _) = open_raw(&back, std::slice::from_ref(&id));
        assert!(res.is_err(), "armor masked a corrupt container at {at}");
    }
}

#[test]
fn looks_armored_is_not_fooled() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let sealed = seal(b"binary, not armored", &[r], None);

    assert!(
        !armor::looks_armored(&sealed),
        "a binary container is not armored"
    );
    assert!(!armor::looks_armored(b""), "empty input is not armored");
    assert!(
        !armor::looks_armored(b"-----BEGIN ANUBIS"),
        "a truncated boundary"
    );
    assert!(
        !armor::looks_armored(b"-----BEGIN PGP MESSAGE-----\n"),
        "another armor format"
    );
    assert!(
        !armor::looks_armored(&[0xFF, 0xFE, 0x00, 0x01]),
        "invalid utf-8 must not be reported as armor"
    );
    assert!(
        armor::looks_armored(format!("\n\n  {}\n", armor::BEGIN).as_bytes()),
        "leading blank space is tolerated"
    );
    // Only a prefix is needed, which is how a CLI sniffs a file cheaply.
    let armored = armor::encode(&sealed);
    assert!(armor::looks_armored(&armored.as_bytes()[..40]));
}

// ---------------------------------------------------------------------------
// 9. large file
// ---------------------------------------------------------------------------

#[test]
fn eight_mebibyte_round_trip_is_byte_identical() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    // Deliberately not a chunk multiple: 128 full chunks plus a short one.
    const LEN: usize = 8 * 1024 * 1024 + 4321;
    let data = pseudo(LEN, 0xDEAD_BEEF);
    let sealed = seal(&data, &[r], Some(&id));

    let expect_chunks = LEN.div_ceil(CHUNK);
    assert_eq!(expect_chunks, 129);
    let info = format::inspect(&mut &sealed[..], sealed.len() as u64).unwrap();
    assert_eq!(info.chunks as usize, expect_chunks);
    assert_eq!(info.payload_bytes as usize, LEN + expect_chunks * TAG);
    assert!(info.signed);

    let (res, out) = open_raw(&sealed, std::slice::from_ref(&id));
    let d = res.expect("8 MiB decrypt");
    assert_eq!(d.bytes as usize, LEN);
    assert_eq!(out.len(), LEN);
    assert_eq!(out, data, "8 MiB round trip was not byte-identical");
    assert_eq!(
        d.verified_key.as_deref(),
        Some(id.verifying_key().encode().as_slice())
    );

    // The pipe path must reach the same answer on the same bytes, and does
    // so with a constant-size delay window rather than by buffering.
    let (res, out) = open_unsized(&sealed[..], std::slice::from_ref(&id));
    let d = res.expect("8 MiB unsized decrypt");
    assert_eq!(d.bytes as usize, LEN);
    assert_eq!(out, data, "8 MiB unsized round trip was not byte-identical");

    // One bit anywhere in the middle of a large payload is still caught.
    let mut bad = sealed;
    let off = header_len_of(&bad) + 3 * CHUNK + 7;
    bad[off] ^= 0x04;
    let (res, out) = open_raw(&bad, std::slice::from_ref(&id));
    assert!(res.is_err(), "a flipped bit in chunk 3 was not detected");
    assert!(out.len() < LEN, "the whole plaintext escaped");
}

// ---------------------------------------------------------------------------
// keyless verification
//
// The signature is over SHA-512(header || payload ciphertext) and the
// verifying key travels in the header, so checking it needs no identity at
// all. These tests hold that property: `verify` must reach the same verdict
// as `decrypt` while holding no key, and must refuse everything `decrypt`
// refuses. A verifier that is more permissive than the decryptor would be
// worse than none, because it is the tool a third party trusts when they
// cannot open the file themselves.
// ---------------------------------------------------------------------------

fn verify_bytes(sealed: &[u8]) -> anubis_crypto::Result<format::Verification> {
    let len = sealed.len() as u64;
    format::verify(sealed, len)
}

#[test]
fn verify_accepts_a_signed_container_without_any_identity() {
    let signer = Identity::generate().unwrap();
    let to = Identity::generate().unwrap();
    let sealed = seal(
        b"sealed to somebody else",
        &[to.to_recipient().unwrap()],
        Some(&signer),
    );

    // No identity is passed in, and the one that could decrypt is not the one
    // that signed. This is the third-party auditor's position exactly.
    let v = verify_bytes(&sealed).expect("verify");
    assert!(v.signed);
    assert_eq!(v.signature_ok, Some(true));
    assert_eq!(
        v.verifying_key.as_deref(),
        Some(signer.verifying_key().encode().as_slice())
    );

    // And the decryptor agrees, from the other side of the key boundary.
    let opened = open(&sealed, &[to]).expect("decrypt");
    assert_eq!(opened, b"sealed to somebody else");
}

#[test]
fn verify_reports_unsigned_as_absent_never_as_a_pass() {
    let to = Identity::generate().unwrap();
    let sealed = seal(b"no signature here", &[to.to_recipient().unwrap()], None);

    let v = verify_bytes(&sealed).expect("verify");
    assert!(!v.signed);
    // None, not Some(false): nothing was checked, and nothing failed.
    assert_eq!(v.signature_ok, None);
    assert!(v.verifying_key.is_none());
}

#[test]
fn verify_refuses_a_tampered_payload() {
    let signer = Identity::generate().unwrap();
    let to = Identity::generate().unwrap();
    let plain = pseudo(200_000, 0x5157);
    let sealed = seal(&plain, &[to.to_recipient().unwrap()], Some(&signer));

    // Flip one bit in the payload region, well clear of header and trailer.
    let mut bad = sealed.clone();
    let at = header_len_of(&sealed) + 64;
    bad[at] ^= 0x01;

    assert!(matches!(verify_bytes(&bad), Err(Error::BadSignature)));
}

#[test]
fn verify_refuses_a_tampered_header() {
    let signer = Identity::generate().unwrap();
    let to = Identity::generate().unwrap();
    let sealed = seal(
        b"header integrity",
        &[to.to_recipient().unwrap()],
        Some(&signer),
    );

    // The signature covers the header including its MAC line, so a header
    // edit breaks it even though the verifier cannot check the MAC itself.
    let mut bad = sealed.clone();
    bad[10] ^= 0x01;
    assert!(verify_bytes(&bad).is_err());
}

#[test]
fn verify_refuses_a_swapped_signature() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let to = Identity::generate().unwrap();
    let rec = to.to_recipient().unwrap();

    let one = seal(b"message one", std::slice::from_ref(&rec), Some(&a));
    let two = seal(b"message two", &[rec], Some(&b));

    // Graft b's trailer onto a's container: a valid signature, wrong bytes.
    let mut forged = one[..one.len() - SIG_LEN].to_vec();
    forged.extend_from_slice(&two[two.len() - SIG_LEN..]);

    assert!(matches!(verify_bytes(&forged), Err(Error::BadSignature)));
}

#[test]
fn reporting_verify_binds_a_false_verdict_to_content_and_signer() {
    let signer = Identity::generate().unwrap();
    let recipient = Identity::generate().unwrap();
    let mut sealed = seal(
        &pseudo(CHUNK + 31, 0x00BA_D51A),
        &[recipient.to_recipient().unwrap()],
        Some(&signer),
    );
    let last = sealed.len() - 1;
    sealed[last] ^= 0x20;
    let expected_content_id: [u8; 64] = Sha512::digest(&sealed).into();
    let expected_key = signer.verifying_key().encode().as_slice().to_vec();

    let sized = format::verify_report(&sealed[..], sealed.len() as u64).unwrap();
    let streamed = format::verify_unsized_report(choked(&sealed, 17)).unwrap();
    for report in [&sized, &streamed] {
        assert!(report.signed);
        assert_eq!(report.signature_ok, Some(false));
        assert_eq!(report.verifying_key.as_ref(), Some(&expected_key));
        assert_eq!(report.content_id, expected_content_id);
        assert!(report.payload_bytes >= TAG as u64);
        assert!(report.chunks > 0);
    }

    assert!(matches!(
        format::verify(&sealed[..], sealed.len() as u64),
        Err(Error::BadSignature)
    ));
    assert!(matches!(
        format::verify_unsized(&sealed[..]),
        Err(Error::BadSignature)
    ));
}

#[test]
fn reporting_verify_never_turns_structural_failure_into_false() {
    let signer = Identity::generate().unwrap();
    let recipient = Identity::generate().unwrap();
    let sealed = seal(
        b"structural failures have no verdict",
        &[recipient.to_recipient().unwrap()],
        Some(&signer),
    );
    let header_len = header_len_of(&sealed);
    let grossly_truncated = &sealed[..header_len + SIG_LEN - 1];

    assert!(matches!(
        format::verify_report(grossly_truncated, grossly_truncated.len() as u64),
        Err(Error::Integrity(_))
    ));
    assert!(matches!(
        format::verify_unsized_report(grossly_truncated),
        Err(Error::Integrity(_))
    ));
    let malformed = b"not a container";
    assert!(matches!(
        format::verify_report(malformed.as_slice(), malformed.len() as u64),
        Err(Error::Header(_))
    ));
    assert!(matches!(
        format::verify_unsized_report(malformed.as_slice()),
        Err(Error::Header(_))
    ));
}

#[test]
fn sized_full_container_apis_reject_bytes_beyond_the_declared_length() {
    let signer = Identity::generate().unwrap();
    let recipient = Identity::generate().unwrap();
    let plaintext = pseudo(CHUNK + 19, 0xE0F0_0001);
    let sealed = seal(
        &plaintext,
        &[recipient.to_recipient().unwrap()],
        Some(&signer),
    );
    let declared_len = sealed.len() as u64;
    let mut extended = sealed;
    extended.extend_from_slice(b"suffix outside the declared container");

    let mut safe_output = Vec::new();
    let safe = format::decrypt(
        std::slice::from_ref(&recipient),
        &extended[..],
        declared_len,
        &mut safe_output,
        |_| {},
    );
    assert!(matches!(safe, Err(Error::Integrity(_))));
    assert!(safe_output.is_empty(), "safe decrypt published plaintext");

    let mut provisional_output = Vec::new();
    let provisional = format::decrypt_provisional(
        std::slice::from_ref(&recipient),
        &extended[..],
        declared_len,
        &mut provisional_output,
        |_| {},
    );
    assert!(matches!(provisional, Err(Error::Integrity(_))));
    assert_eq!(
        provisional_output, plaintext,
        "provisional API contract changed"
    );

    assert!(matches!(
        format::verify(&extended[..], declared_len),
        Err(Error::Integrity(_))
    ));
    assert!(matches!(
        format::verify_report(&extended[..], declared_len),
        Err(Error::Integrity(_))
    ));
}

#[test]
fn verify_refuses_a_truncated_container() {
    let signer = Identity::generate().unwrap();
    let to = Identity::generate().unwrap();
    let sealed = seal(
        &pseudo(100_000, 9),
        &[to.to_recipient().unwrap()],
        Some(&signer),
    );
    let header = header_len_of(&sealed);

    // Truncation splits into two regimes and the boundary is worth pinning,
    // because the two produce different reports to a user.
    //
    // Gross truncation -- no room left for a payload and a trailer -- is
    // structurally detectable and is reported as an integrity failure, so a
    // damaged file is not presented as a forged one.
    // Two structurally detectable bands: no room for the trailer at all, and
    // room for the trailer but not for even one AEAD tag of payload.
    let cuts = [
        header,
        header + 1,
        header + SIG_LEN - 1,
        header + SIG_LEN,           // trailer fits, payload is empty
        header + SIG_LEN + TAG - 1, // payload smaller than one tag
    ];
    for cut in cuts {
        let err = verify_bytes(&sealed[..cut]).unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "truncation to {cut} must report integrity, got {err:?}"
        );
    }

    // Losing a byte off the end of a long file is NOT structurally
    // detectable: what remains is a well-formed container whose digest no
    // longer matches. Cryptography cannot tell that from an edit, and the
    // verifier must not pretend otherwise -- it reports a signature that did
    // not verify, which is exactly what it observed.
    assert!(matches!(
        verify_bytes(&sealed[..sealed.len() - 1]),
        Err(Error::BadSignature)
    ));
}

#[test]
fn verify_agrees_with_inspect_on_header_facts() {
    let signer = Identity::generate().unwrap();
    let to = Identity::generate().unwrap();
    let sealed = seal(
        &pseudo(300_000, 77),
        &[to.to_recipient().unwrap()],
        Some(&signer),
    );
    let len = sealed.len() as u64;

    let i = format::inspect(&sealed[..], len).expect("inspect");
    let v = verify_bytes(&sealed).expect("verify");

    // Two independent paths over the same bytes must not disagree about what
    // the container is; a divergence here is a parser bug in one of them.
    assert_eq!(i.header_bytes, v.header_bytes);
    assert_eq!(i.payload_bytes, v.payload_bytes);
    assert_eq!(i.chunks, v.chunks);
    assert_eq!(i.recipients, v.recipients);
    assert_eq!(i.signed, v.signed);
    assert_eq!(i.verifying_key, v.verifying_key);
}

#[test]
fn verify_never_emits_plaintext_and_handles_an_empty_payload() {
    let signer = Identity::generate().unwrap();
    let to = Identity::generate().unwrap();
    let sealed = seal(b"", &[to.to_recipient().unwrap()], Some(&signer));

    let v = verify_bytes(&sealed).expect("verify");
    assert_eq!(v.signature_ok, Some(true));

    // An empty plaintext is still one chunk of ciphertext, and the verifier
    // must account for it rather than reading the trailer as payload.
    assert!(v.payload_bytes >= TAG as u64);
    assert_eq!(v.chunks, 1);
}

// ---------------------------------------------------------------------------
// Remediation regressions
// ---------------------------------------------------------------------------

#[test]
fn non_contributory_x25519_inputs_are_rejected_on_both_sides() {
    let id = Identity::generate().unwrap();
    let mut payload = id.to_recipient().unwrap().to_payload();
    payload[..X25519_PUB_LEN].fill(0);
    let degenerate = Recipient::from_payload(&payload).unwrap();

    let enc_err = match anubis_crypto::hybrid::encapsulate(&degenerate) {
        Ok(_) => panic!("non-contributory recipient was accepted"),
        Err(err) => err,
    };
    assert!(
        matches!(enc_err, Error::Key(_)),
        "unexpected encapsulation error: {enc_err}"
    );

    let epk = [0u8; X25519_PUB_LEN];
    let ct = vec![0u8; MLKEM_CT_LEN];
    let dec_err = anubis_crypto::hybrid::decapsulate(&id, &epk, &ct).unwrap_err();
    assert!(
        matches!(dec_err, Error::Header(_)),
        "unexpected decapsulation error: {dec_err}"
    );
}

#[test]
fn parser_rejects_a_recipient_stanza_after_the_signature_stanza() {
    let id = Identity::generate().unwrap();
    let sealed = seal(b"ordering", &[id.to_recipient().unwrap()], Some(&id));
    let header_len = header_len_of(&sealed);
    let header = std::str::from_utf8(&sealed[..header_len]).unwrap();
    let mut lines: Vec<&str> = header.lines().collect();
    let mac = lines.pop().unwrap();
    let recipient_line = lines[1];
    let wrapped_line = lines[2];
    lines.push(recipient_line);
    lines.push(wrapped_line);
    lines.push(mac);

    let mut reordered = lines.join("\n").into_bytes();
    reordered.push(b'\n');
    reordered.extend_from_slice(&sealed[header_len..]);
    let err = format::inspect(&reordered[..], reordered.len() as u64).unwrap_err();
    assert!(
        matches!(err, Error::Header(_)),
        "recipient after signature was not a header error: {err}"
    );
}

#[test]
fn writer_refuses_too_many_recipients_before_writing() {
    let id = Identity::generate().unwrap();
    let recipient = id.to_recipient().unwrap();
    let recipients = vec![recipient; MAX_STANZAS + 1];
    let mut out = Vec::new();
    let err = format::encrypt(
        &EncryptOptions {
            recipients: &recipients,
            signer: None,
        },
        &mut &b"never written"[..],
        &mut out,
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(err, Error::Key(_)), "unexpected error: {err}");
    assert!(
        out.is_empty(),
        "recipient-cap failure wrote container bytes"
    );
}

#[test]
fn all_container_paths_reject_impossible_stream_geometry() {
    let id = Identity::generate().unwrap();
    let sealed = seal(b"geometry", &[id.to_recipient().unwrap()], None);
    let header_len = header_len_of(&sealed);
    let mut malformed = sealed[..header_len].to_vec();
    malformed.resize(header_len + anubis_crypto::stream::CHUNK_CT + 1, 0);

    assert!(format::inspect(&malformed[..], malformed.len() as u64).is_err());
    assert!(format::inspect_unsized(&malformed[..]).is_err());
    assert!(format::verify(&malformed[..], malformed.len() as u64).is_err());
    assert!(format::verify_unsized(&malformed[..]).is_err());
    let (sized, sized_out) = open_raw(&malformed, std::slice::from_ref(&id));
    assert!(sized.is_err());
    assert!(sized_out.is_empty());
    let (streamed, unsized_out) = open_unsized(&malformed[..], std::slice::from_ref(&id));
    assert!(streamed.is_err());
    assert!(unsized_out.is_empty());
}

#[test]
fn content_id_covers_the_complete_decoded_container() {
    let signer = Identity::generate().unwrap();
    let recipient = Identity::generate().unwrap();
    let sealed = seal(
        b"content identity",
        &[recipient.to_recipient().unwrap()],
        Some(&signer),
    );
    let expected: [u8; 64] = Sha512::digest(&sealed).into();

    let header_only = format::inspect(&sealed[..], sealed.len() as u64).unwrap();
    assert!(header_only.signed);

    let sized = format::inspect_with_content_id(&sealed[..], sealed.len() as u64).unwrap();
    let streamed = format::inspect_unsized(choked(&sealed, 17)).unwrap();
    let verified = format::verify_report(&sealed[..], sealed.len() as u64).unwrap();
    let verified_unsized = format::verify_unsized_report(choked(&sealed, 17)).unwrap();
    let mut plaintext = Vec::new();
    let decrypted = format::decrypt_report(
        &[recipient],
        &sealed[..],
        sealed.len() as u64,
        &mut plaintext,
        |_| {},
    )
    .unwrap();

    assert_eq!(sized.content_id, expected);
    assert_eq!(streamed.content_id, expected);
    assert_eq!(verified.content_id, expected);
    assert_eq!(verified_unsized.content_id, expected);
    assert_eq!(decrypted.content_id, expected);
    assert_eq!(plaintext, b"content identity");
}

#[test]
fn full_inspection_rejects_a_false_length_claim() {
    let id = Identity::generate().unwrap();
    let sealed = seal(b"length", &[id.to_recipient().unwrap()], None);
    assert!(format::inspect_with_content_id(&sealed[..], 0).is_err());
}

#[test]
fn rustcrypto_expanded_secret_types_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<ml_kem::DecapsulationKey1024>();
    assert_zeroize_on_drop::<ml_dsa::SigningKey<ml_dsa::MlDsa87>>();
    assert_zeroize_on_drop::<ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa87>>();
}
