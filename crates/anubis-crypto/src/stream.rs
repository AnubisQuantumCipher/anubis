//! STREAM payload encryption.
//!
//! Chunked ChaCha20-Poly1305 in the STREAM construction of Hoang,
//! Reyhanitabar, Rogaway and Vizar. Plaintext is split into 64 KiB chunks;
//! each chunk is sealed under a 12-byte nonce formed as an 11-byte
//! big-endian counter followed by a single byte that is 0x01 for the final
//! chunk and 0x00 otherwise.
//!
//! The final-chunk flag is what makes truncation detectable: an attacker who
//! drops trailing chunks produces a stream whose last chunk was sealed with
//! the flag clear, and decryption rejects it.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use std::io::{Read, Write};

use crate::error::{Error, Result};

/// Plaintext chunk size.
pub const CHUNK: usize = 65536;
/// Poly1305 tag length.
pub const TAG: usize = 16;
/// Ciphertext chunk size.
pub const CHUNK_CT: usize = CHUNK + TAG;

/// Validated geometry of an encoded STREAM payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadGeometry {
    /// Ciphertext bytes, including one Poly1305 tag per chunk.
    pub bytes: u64,
    /// Number of encoded chunks.
    pub chunks: u64,
}

/// Validate the byte geometry of an encoded STREAM payload.
///
/// Every non-final chunk occupies exactly [`CHUNK_CT`] bytes. The final
/// chunk contains up to [`CHUNK`] plaintext bytes and exactly one [`TAG`],
/// so a short final fragment can never be shorter than a tag. Empty
/// plaintext is represented by one tag-only final chunk.
pub fn payload_geometry(bytes: u64) -> Result<PayloadGeometry> {
    if bytes < TAG as u64 {
        return Err(Error::Integrity(
            "truncated payload: first chunk is shorter than an authentication tag".into(),
        ));
    }

    let chunk_ct = CHUNK_CT as u64;
    let final_len = bytes % chunk_ct;
    if final_len != 0 && final_len < TAG as u64 {
        return Err(Error::Integrity(
            "truncated payload: trailing bytes are shorter than an authentication tag".into(),
        ));
    }

    Ok(PayloadGeometry {
        bytes,
        chunks: bytes.div_ceil(chunk_ct),
    })
}

fn nonce_for(counter: u64, last: bool) -> Result<Nonce> {
    // 11-byte counter space; refuse rather than wrap.
    if counter >= 1u64 << 56 {
        return Err(Error::Integrity("chunk counter exhausted".into()));
    }
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(last);
    Ok(Nonce::from(n))
}

/// Read exactly `want` bytes unless EOF arrives first.
fn read_upto<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Encrypt `reader` into `writer` under `key`, reporting bytes consumed.
///
/// `progress` is called with the running plaintext byte count after each
/// chunk. Empty input produces exactly one empty final chunk (a bare tag),
/// so an empty file is still authenticated.
pub fn encrypt<R, W, F>(
    key: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
    mut progress: F,
) -> Result<u64>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut cur = vec![0u8; CHUNK];
    let mut next = vec![0u8; CHUNK];
    let mut buf = Vec::with_capacity(CHUNK_CT);

    let mut cur_len = read_upto(reader, &mut cur)?;
    let mut counter: u64 = 0;
    let mut total: u64 = 0;

    loop {
        // A short read means EOF; otherwise look ahead to decide finality.
        let next_len = if cur_len == CHUNK {
            read_upto(reader, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;

        buf.clear();
        buf.extend_from_slice(&cur[..cur_len]);
        let nonce = nonce_for(counter, last)?;
        cipher
            .encrypt_in_place(&nonce, b"", &mut buf)
            .map_err(|_| Error::Integrity("chunk encryption failed".into()))?;
        writer.write_all(&buf)?;

        total += cur_len as u64;
        progress(total);

        if last {
            break;
        }
        core::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        counter += 1;
    }

    Ok(total)
}

/// Decrypt `reader` into `writer` under `key`, reporting plaintext bytes.
pub fn decrypt<R, W, F>(
    key: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
    mut progress: F,
) -> Result<u64>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut cur = vec![0u8; CHUNK_CT];
    let mut next = vec![0u8; CHUNK_CT];
    let mut buf = Vec::with_capacity(CHUNK_CT);

    let mut cur_len = read_upto(reader, &mut cur)?;
    let mut counter: u64 = 0;
    let mut total: u64 = 0;
    let mut ciphertext_total: u64 = 0;

    // A payload always has at least one chunk, even when empty.
    if cur_len < TAG {
        return Err(Error::Integrity(
            "truncated payload: first chunk is shorter than an authentication tag".into(),
        ));
    }

    loop {
        let next_len = if cur_len == CHUNK_CT {
            read_upto(reader, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;

        if next_len > 0 && next_len < TAG {
            return Err(Error::Integrity(
                "truncated payload: trailing bytes are shorter than a tag".into(),
            ));
        }

        buf.clear();
        buf.extend_from_slice(&cur[..cur_len]);
        let nonce = nonce_for(counter, last)?;
        cipher
            .decrypt_in_place(&nonce, b"", &mut buf)
            .map_err(|_| {
                Error::Integrity(format!(
                    "chunk {counter} failed authentication: the file was modified, \
                 truncated, or is not addressed to this identity"
                ))
            })?;
        writer.write_all(&buf)?;

        total += buf.len() as u64;
        ciphertext_total = ciphertext_total
            .checked_add(cur_len as u64)
            .ok_or_else(|| Error::Integrity("payload length overflow".into()))?;
        progress(total);

        if last {
            break;
        }
        core::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        counter += 1;
    }

    payload_geometry(ciphertext_total)?;
    Ok(total)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// A repeated (key, nonce) pair destroys ChaCha20-Poly1305. The payload
    /// key is fixed for a file, so safety rests entirely on the nonce being
    /// distinct for every chunk. This proves the construction is injective:
    /// distinct (counter, last) pairs cannot collide, over ALL counters, not
    /// a sampled subset.
    #[kani::proof]
    fn nonce_construction_is_injective() {
        let c1: u64 = kani::any();
        let c2: u64 = kani::any();
        let l1: bool = kani::any();
        let l2: bool = kani::any();

        // Only reachable counters matter; the guard rejects the rest.
        kani::assume(c1 < 1u64 << 56);
        kani::assume(c2 < 1u64 << 56);

        let n1 = nonce_for(c1, l1).unwrap();
        let n2 = nonce_for(c2, l2).unwrap();

        if c1 != c2 || l1 != l2 {
            assert!(n1 != n2, "distinct chunks produced the same nonce");
        } else {
            assert!(n1 == n2, "nonce construction is not deterministic");
        }
    }

    /// The final-chunk flag is what makes truncation detectable, so a
    /// final-chunk nonce must never equal a non-final nonce at any counter.
    #[kani::proof]
    fn final_flag_always_changes_the_nonce() {
        let c: u64 = kani::any();
        kani::assume(c < 1u64 << 56);
        assert!(nonce_for(c, true).unwrap() != nonce_for(c, false).unwrap());
    }

    /// The counter guard must actually stop before the 11-byte field wraps.
    #[kani::proof]
    fn counter_guard_rejects_out_of_range() {
        let c: u64 = kani::any();
        let last: bool = kani::any();
        let r = nonce_for(c, last);
        assert!(r.is_ok() == (c < 1u64 << 56));
    }
}
