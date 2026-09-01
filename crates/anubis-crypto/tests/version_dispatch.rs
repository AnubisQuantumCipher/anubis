//! Exact outer-version dispatch tests.

use std::io::{Cursor, Read};

use anubis_crypto::container::{
    self, DispatchError, ReadDispatch, RequestedWriteFormat, V3_MAGIC, V4_MAGIC,
};

struct OneByteReader<R>(R);

impl<R: Read> Read for OneByteReader<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        self.0.read(&mut output[..1])
    }
}

fn read_all(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).expect("read replay");
    bytes
}

#[test]
fn dispatch_replays_every_v3_byte_exactly() {
    let input = format!("{V3_MAGIC}\nsecond line\npayload").into_bytes();
    let dispatched = container::dispatch(Cursor::new(input.clone())).expect("dispatch");
    let v3 = dispatched.require_v3().expect("require v3");
    assert_eq!(read_all(v3.into_reader()), input);
}

#[test]
fn dispatch_preserves_bytes_buffered_after_version_line() {
    let mut input = format!("{V3_MAGIC}\n").into_bytes();
    input.extend((0..16384).map(|index| (index % 251) as u8));

    let dispatched = container::dispatch(Cursor::new(input.clone())).expect("dispatch");
    let v3 = dispatched.require_v3().expect("require v3");
    assert_eq!(read_all(v3.into_reader()), input);
}

#[test]
fn dispatch_handles_one_byte_reads() {
    let input = format!("{V3_MAGIC}\nbody").into_bytes();
    let dispatched =
        container::dispatch(OneByteReader(Cursor::new(input.clone()))).expect("one-byte dispatch");
    let v3 = dispatched.require_v3().expect("require v3");
    assert_eq!(read_all(v3.into_reader()), input);
}

#[test]
fn dispatch_recognizes_v4_without_invoking_v3() {
    let input = format!("{V4_MAGIC}\nfuture bytes").into_bytes();
    let dispatched = container::dispatch(Cursor::new(input.clone())).expect("dispatch");
    match dispatched {
        ReadDispatch::V4(v4) => assert_eq!(read_all(v4.into_reader()), input),
        ReadDispatch::V3(_) => panic!("reserved v4 token routed to v3"),
        _ => panic!("unexpected future dispatch variant"),
    }
}

#[test]
fn require_v3_refuses_recognized_v4() {
    let input = format!("{V4_MAGIC}\nfuture bytes");
    let error = match container::dispatch(input.as_bytes()).expect("recognize v4") {
        ReadDispatch::V4(v4) => ReadDispatch::V4(v4).require_v3().err().expect("refuse v4"),
        ReadDispatch::V3(_) => panic!("reserved v4 token routed to v3"),
        _ => panic!("unexpected future dispatch variant"),
    };
    assert!(matches!(error, DispatchError::V4ReadDisabled));
    assert!(error.to_string().contains("refusing to reinterpret"));
}

#[test]
fn requesting_v4_write_never_returns_a_v3_permit() {
    assert!(container::request_write(RequestedWriteFormat::V3).is_ok());
    assert!(matches!(
        container::request_write(RequestedWriteFormat::V4),
        Err(DispatchError::V4WriteDisabled)
    ));
}

#[test]
fn dispatch_bounds_and_canonicalizes_the_version_line() {
    let too_long = vec![b'A'; container::MAX_VERSION_LINE];
    assert!(matches!(
        container::dispatch(Cursor::new(too_long)),
        Err(DispatchError::TooLong)
    ));
    assert!(matches!(
        container::dispatch(Cursor::new(V3_MAGIC.as_bytes())),
        Err(DispatchError::MissingNewline)
    ));
    assert!(matches!(
        container::dispatch(Cursor::new(format!("{V3_MAGIC}\r\n"))),
        Err(DispatchError::TrailingWhitespace)
    ));
    assert!(matches!(
        container::dispatch(Cursor::new(format!("{V3_MAGIC} \n"))),
        Err(DispatchError::TrailingWhitespace)
    ));
}

#[test]
fn legacy_and_unknown_tokens_never_route_to_a_current_parser() {
    for (token, expected) in [
        (container::LEGACY_V1_MAGIC, DispatchError::LegacyV1),
        (container::LEGACY_V2_MAGIC, DispatchError::LegacyV2),
    ] {
        let error = match container::dispatch(Cursor::new(format!("{token}\n"))) {
            Ok(_) => panic!("legacy token was dispatched"),
            Err(error) => error,
        };
        assert_eq!(
            core::mem::discriminant(&error),
            core::mem::discriminant(&expected)
        );
        assert!(error.to_string().contains("MIGRATION.md"));
    }

    for input in [
        b"not an ANUBIS file\n".as_slice(),
        b"anubis-encryption.org/v5\n".as_slice(),
        b"anubis-encryption.org/v30\n".as_slice(),
    ] {
        assert!(matches!(
            container::dispatch(Cursor::new(input)),
            Err(DispatchError::Unknown)
        ));
    }
}
