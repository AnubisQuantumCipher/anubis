//! Compile-time guards for the released v2.1 public data shapes.

use anubis_crypto::format::{Decrypted, Inspection, Verification};

#[test]
fn released_result_structs_keep_their_exhaustive_shapes() {
    let Decrypted {
        bytes,
        verified_key,
    } = Decrypted {
        bytes: 0,
        verified_key: None,
    };
    assert_eq!(bytes, 0);
    assert!(verified_key.is_none());

    let inspection = Inspection {
        format: String::new(),
        recipients: 0,
        signed: false,
        verifying_key: None,
        header_bytes: 0,
        payload_bytes: 0,
        chunks: 0,
    };
    let Inspection {
        format: _,
        recipients: _,
        signed: _,
        verifying_key: _,
        header_bytes: _,
        payload_bytes: _,
        chunks: _,
    } = inspection;

    let verification = Verification {
        format: String::new(),
        recipients: 0,
        signed: false,
        verifying_key: None,
        signature_ok: None,
        header_bytes: 0,
        payload_bytes: 0,
        chunks: 0,
    };
    let Verification {
        format: _,
        recipients: _,
        signed: _,
        verifying_key: _,
        signature_ok: _,
        header_bytes: _,
        payload_bytes: _,
        chunks: _,
    } = verification;
}

#[test]
fn released_bech32_error_type_keeps_its_traits_and_signature() {
    fn assert_traits<T: Clone + PartialEq + Eq>() {}
    assert_traits::<anubis_crypto::b32::DecodeError>();

    type DecodeResult = Result<(bech32::Hrp, Vec<u8>), anubis_crypto::b32::DecodeError>;
    let decoder: fn(&str) -> DecodeResult = anubis_crypto::b32::decode;
    let _ = decoder;
}
