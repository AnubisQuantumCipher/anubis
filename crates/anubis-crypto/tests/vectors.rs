//! Behavioural tests for the ANUBIS/v3 container.
//!
//! These defend observable contracts: round-trip fidelity, chunk-boundary
//! handling, and that every class of corruption is actually rejected.

use anubis_crypto::format::{self, EncryptOptions};
use anubis_crypto::keys::{Identity, Recipient, fingerprint};
use anubis_crypto::stream::CHUNK;
use bech32::Fe32IterExt;

fn seal(data: &[u8], recipients: &[Recipient], signer: Option<&Identity>) -> Vec<u8> {
    let mut out = Vec::new();
    let opts = EncryptOptions { recipients, signer };
    format::encrypt(&opts, &mut &data[..], &mut out, |_| {}).expect("encrypt");
    out
}

fn open(sealed: &[u8], ids: &[Identity]) -> anubis_crypto::Result<Vec<u8>> {
    let mut out = Vec::new();
    let len = sealed.len() as u64;
    format::decrypt(ids, &mut &sealed[..], len, &mut out, |_| {})?;
    Ok(out)
}

#[test]
fn round_trip_preserves_plaintext() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let msg = b"attack at dawn";
    let sealed = seal(msg, &[r], None);
    assert_eq!(open(&sealed, std::slice::from_ref(&id)).unwrap(), msg);
}

#[test]
fn empty_input_is_still_authenticated() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let sealed = seal(b"", &[r], None);
    // One empty final chunk: a bare 16-byte tag.
    assert_eq!(open(&sealed, std::slice::from_ref(&id)).unwrap(), b"");
}

#[test]
fn exact_chunk_multiples_round_trip() {
    // The lookahead logic is easiest to get wrong exactly on a boundary.
    for len in [CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK] {
        let id = Identity::generate().unwrap();
        let r = id.to_recipient().unwrap();
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let sealed = seal(&data, &[r], None);
        let got = open(&sealed, std::slice::from_ref(&id)).unwrap();
        assert_eq!(got.len(), len, "length mismatch at {len}");
        assert_eq!(got, data, "content mismatch at {len}");
    }
}

#[test]
fn any_recipient_can_open_a_multi_recipient_file() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let c = Identity::generate().unwrap();
    let rs = [a.to_recipient().unwrap(), b.to_recipient().unwrap()];
    let sealed = seal(b"team secret", &rs, None);

    assert_eq!(
        open(&sealed, std::slice::from_ref(&a)).unwrap(),
        b"team secret"
    );
    assert_eq!(
        open(&sealed, std::slice::from_ref(&b)).unwrap(),
        b"team secret"
    );
    // A non-recipient must not.
    assert!(open(&sealed, std::slice::from_ref(&c)).is_err());
}

#[test]
fn signed_files_verify_and_report_the_signer() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let sealed = seal(b"signed payload", &[r], Some(&id));

    let mut out = Vec::new();
    let len = sealed.len() as u64;
    let res = format::decrypt(
        std::slice::from_ref(&id),
        &mut &sealed[..],
        len,
        &mut out,
        |_| {},
    )
    .expect("verified decrypt");

    assert_eq!(out, b"signed payload");
    let vk = res.verified_key.expect("signature should be reported");
    assert_eq!(vk, id.verifying_key().encode().as_slice().to_vec());
}

#[test]
fn payload_tampering_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let mut sealed = seal(b"the quick brown fox", &[r], None);
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01;
    assert!(open(&sealed, std::slice::from_ref(&id)).is_err());
}

#[test]
fn header_tampering_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let sealed = seal(b"payload", &[r], None);

    // Corrupt one base64 character inside the wrapped-key line.
    let text = String::from_utf8_lossy(&sealed).to_string();
    let idx = text.find("--- ").expect("mac line");
    let mut bytes = sealed.clone();
    bytes[idx - 5] ^= 0x01;
    assert!(open(&bytes, std::slice::from_ref(&id)).is_err());
}

#[test]
fn truncation_is_rejected() {
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let data: Vec<u8> = (0..3 * CHUNK).map(|i| (i % 251) as u8).collect();
    let sealed = seal(&data, &[r], None);

    // Drop the final chunk. The final-flag rule must catch this.
    let cut = sealed.len() - (CHUNK + 16);
    assert!(open(&sealed[..cut], std::slice::from_ref(&id)).is_err());
}

#[test]
fn signature_forgery_is_rejected() {
    let signer = Identity::generate().unwrap();
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let mut sealed = seal(b"authentic", &[r], Some(&signer));

    // Flip a bit inside the trailing signature.
    let n = sealed.len();
    sealed[n - 10] ^= 0x01;
    assert!(open(&sealed, std::slice::from_ref(&id)).is_err());
}

#[test]
fn inspect_reports_header_facts_without_keys() {
    let id = Identity::generate().unwrap();
    let other = Identity::generate().unwrap();
    let rs = [id.to_recipient().unwrap(), other.to_recipient().unwrap()];
    let sealed = seal(b"x", &rs, Some(&id));

    let info = format::inspect(&mut &sealed[..], sealed.len() as u64).unwrap();
    assert_eq!(info.format, "anubis-encryption.org/v3");
    assert_eq!(info.recipients, 2);
    assert!(info.signed);
    assert_eq!(info.chunks, 1);
}

#[test]
fn legacy_anubis_rage_files_get_a_migration_error() {
    // anubis-rage 1.4.0 hybrid header.
    let legacy = b"anubis-encryption.org/v2\n-> hybrid\nAAAA\n";
    let err = format::inspect(&mut &legacy[..], legacy.len() as u64).unwrap_err();
    assert!(
        err.to_string().contains("MIGRATION.md"),
        "expected a migration hint, got: {err}"
    );

    let v1 = b"anubis-encryption.org/v1\n-> mlkem\n";
    let err = format::inspect(&mut &v1[..], v1.len() as u64).unwrap_err();
    assert!(err.to_string().contains("MIGRATION.md"), "got: {err}");
}

#[test]
fn keys_round_trip_through_bech32() {
    let id = Identity::generate().unwrap();
    let encoded = id.encode().unwrap();
    assert!(encoded.starts_with("ANUBIS-SECRET-KEY-1"));
    let back = Identity::decode(&encoded).unwrap();
    assert_eq!(back.to_payload(), id.to_payload());

    let r = id.to_recipient().unwrap();
    let renc = r.encode().unwrap();
    assert!(renc.starts_with("anubis1"));
    let rback = Recipient::decode(&renc).unwrap();
    assert_eq!(rback.to_payload(), r.to_payload());
    assert_eq!(rback.fingerprint(), r.fingerprint());
}

#[test]
fn legacy_bech32_keys_decode_but_reencode_canonically_as_bech32m() {
    let id = Identity::generate().unwrap();

    let identity_hrp = bech32::Hrp::parse("ANUBIS-SECRET-KEY-").unwrap();
    let legacy_identity =
        bech32::encode_upper::<anubis_crypto::b32::Bech32Unlimited>(identity_hrp, &id.to_payload())
            .unwrap();
    let canonical_identity = id.encode().unwrap();
    assert_ne!(legacy_identity, canonical_identity);
    assert_eq!(
        Identity::decode(&legacy_identity)
            .unwrap()
            .encode()
            .unwrap(),
        canonical_identity
    );

    let recipient = id.to_recipient().unwrap();
    let recipient_hrp = bech32::Hrp::parse("anubis").unwrap();
    let legacy_recipient = bech32::encode_lower::<anubis_crypto::b32::Bech32Unlimited>(
        recipient_hrp,
        &recipient.to_payload(),
    )
    .unwrap();
    let canonical_recipient = recipient.encode().unwrap();
    assert_ne!(legacy_recipient, canonical_recipient);
    assert_eq!(
        Recipient::decode(&legacy_recipient)
            .unwrap()
            .encode()
            .unwrap(),
        canonical_recipient
    );
}

#[test]
fn identity_rejects_a_checksumming_alias_with_nonzero_padding() {
    let id = Identity::generate().unwrap();
    let canonical = id.encode().unwrap();
    let parsed = bech32::primitives::decode::CheckedHrpstring::new::<
        anubis_crypto::b32::Bech32mUnlimited,
    >(&canonical)
    .unwrap();
    let hrp = parsed.hrp();
    let mut symbols: Vec<bech32::Fe32> = parsed.fe32_iter().collect();
    let final_symbol = symbols.last_mut().expect("identity data symbol");
    assert_eq!(final_symbol.to_u8() & 1, 0, "canonical padding bit");
    *final_symbol = bech32::Fe32::try_from(final_symbol.to_u8() | 1).unwrap();

    // Recompute a fully valid Bech32m checksum over the non-canonical symbol
    // stream. A decoder which only verifies the checksum and then drops the
    // leftover bit sees the same identity payload and incorrectly accepts an
    // alternate string for the same secret.
    let alias: String = symbols
        .into_iter()
        .with_checksum::<anubis_crypto::b32::Bech32mUnlimited>(&hrp)
        .chars()
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    let alias_parsed = bech32::primitives::decode::CheckedHrpstring::new::<
        anubis_crypto::b32::Bech32mUnlimited,
    >(&alias)
    .expect("alias checksum must be valid");
    assert_eq!(
        alias_parsed.byte_iter().collect::<Vec<_>>(),
        id.to_payload(),
        "the alias must decode to the same bytes before padding validation"
    );
    assert!(
        anubis_crypto::b32::decode(&alias).is_err(),
        "the public low-level decoder must also reject the alias"
    );
    let error = Identity::decode(&alias).unwrap_err();
    assert!(
        error.to_string().contains("padding"),
        "nonzero padding produced the wrong error: {error}"
    );
}

#[test]
fn key_encodings_have_the_specified_lengths() {
    let id = Identity::generate().unwrap();
    assert_eq!(id.to_payload().len(), 128);
    assert_eq!(id.to_recipient().unwrap().to_payload().len(), 1600);
    // Identity stays inside the range where the bech32 guarantee holds.
    assert!(id.encode().unwrap().len() < 1023);
}

#[test]
fn fingerprint_matches_independently_derived_vectors() {
    // Vectors computed from the specification by a separate party.
    assert_eq!(fingerprint(&[0u8; 1600]), "E61F-41D5-7DB2-08C5-F92A");
    assert_eq!(fingerprint(&[0u8; 128]), "3872-3A2E-5E8A-17AA-7950");
}

#[test]
fn a_corrupted_recipient_string_is_refused() {
    let id = Identity::generate().unwrap();
    let mut s = id.to_recipient().unwrap().encode().unwrap();
    // Flip a character in the data part.
    let pos = s.len() / 2;
    let ch = if s.as_bytes()[pos] == b'q' { 'p' } else { 'q' };
    s.replace_range(pos..pos + 1, &ch.to_string());
    assert!(Recipient::decode(&s).is_err());
}

#[test]
fn header_whitespace_malleability_is_rejected() {
    // Regression: the header MAC once covered a canonical re-serialisation
    // rather than the on-disk bytes, so an attacker with no keys could add
    // trailing whitespace anywhere in an unsigned header and it still
    // decrypted. That falsified the "header was modified" guarantee.
    let id = Identity::generate().unwrap();
    let r = id.to_recipient().unwrap();
    let sealed = seal(b"malleable?", &[r], None);

    // Append a space to the end of the magic line.
    let nl = sealed.iter().position(|&b| b == b'\n').unwrap();
    let mut tampered = Vec::new();
    tampered.extend_from_slice(&sealed[..nl]);
    tampered.push(b' ');
    tampered.extend_from_slice(&sealed[nl..]);

    assert!(
        open(&tampered, std::slice::from_ref(&id)).is_err(),
        "trailing whitespace in the header must be rejected"
    );

    // A carriage return must be rejected too, not silently normalised.
    let mut crlf = Vec::new();
    crlf.extend_from_slice(&sealed[..nl]);
    crlf.push(b'\r');
    crlf.extend_from_slice(&sealed[nl..]);
    assert!(
        open(&crlf, std::slice::from_ref(&id)).is_err(),
        "CR must be rejected"
    );
}

#[test]
fn oversized_header_lines_are_refused() {
    // A file with no newline must not be slurped into memory.
    let mut hostile = Vec::from(&b"anubis-encryption.org/v3\n"[..]);
    hostile.extend(std::iter::repeat_n(b'A', 64 * 1024));
    let err = format::inspect(&mut &hostile[..], hostile.len() as u64).unwrap_err();
    assert!(err.to_string().contains("exceeds"), "got: {err}");
}
