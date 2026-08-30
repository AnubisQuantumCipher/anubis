//! Hybrid X25519 + ML-KEM-1024 key encapsulation.
//!
//! An attacker must break BOTH primitives to recover the wrap key. The
//! combiner binds the full transcript (ephemeral X25519 public key and
//! ML-KEM ciphertext) into the HKDF salt, so a wrap key is bound to the
//! exact ciphertexts that produced it. Without that binding an attacker who
//! could substitute one component's ciphertext might steer the derived key.

use hkdf::Hkdf;
use ml_kem::Decapsulate;
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::{Identity, Recipient, MLKEM_CT_LEN, X25519_PUB_LEN};

/// Length of the derived key-wrapping key.
pub const WRAP_KEY_LEN: usize = 32;

/// Domain separation string for the hybrid combiner.
pub const COMBINER_INFO: &[u8] = b"anubis-hybrid-v2/X25519+MLKEM-1024";

/// The hybrid KEM combiner.
///
/// `HKDF-SHA512(salt = x25519_epk || mlkem_ct, ikm = x25519_ss || mlkem_ss,
/// info = COMBINER_INFO)` truncated to 32 bytes.
#[must_use]
pub fn combine(
    x25519_ss: &[u8],
    mlkem_ss: &[u8],
    x25519_epk: &[u8],
    mlkem_ct: &[u8],
) -> [u8; WRAP_KEY_LEN] {
    let mut salt = Vec::with_capacity(x25519_epk.len() + mlkem_ct.len());
    salt.extend_from_slice(x25519_epk);
    salt.extend_from_slice(mlkem_ct);

    let mut ikm = Vec::with_capacity(x25519_ss.len() + mlkem_ss.len());
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(mlkem_ss);

    let hk = Hkdf::<Sha512>::new(Some(&salt), &ikm);
    let mut okm = [0u8; WRAP_KEY_LEN];
    hk.expand(COMBINER_INFO, &mut okm)
        .expect("32 bytes is far below the HKDF-SHA512 output limit");

    ikm.zeroize();
    okm
}

/// The public half of one encapsulation.
///
/// `wrap_key` is secret and is wiped when dropped.
pub struct Encapsulation {
    /// Ephemeral X25519 public key.
    pub x25519_epk: [u8; X25519_PUB_LEN],
    /// ML-KEM-1024 ciphertext.
    pub mlkem_ct: Vec<u8>,
    /// Derived 32-byte key-wrapping key.
    pub wrap_key: Zeroizing<[u8; WRAP_KEY_LEN]>,
}


/// Encapsulate to a recipient, producing a fresh wrap key.
pub fn encapsulate(recipient: &Recipient) -> Result<Encapsulation> {
    // Classical half: ephemeral X25519.
    let mut eph_bytes = [0u8; 32];
    getrandom::fill(&mut eph_bytes)
        .map_err(|e| Error::Key(format!("system entropy unavailable: {e}")))?;
    let eph = StaticSecret::from(eph_bytes);
    eph_bytes.zeroize();

    let x25519_epk = *PublicKey::from(&eph).as_bytes();
    let peer = PublicKey::from(*recipient.x25519_bytes());
    let mut x25519_ss = eph.diffie_hellman(&peer).to_bytes();

    // Post-quantum half: ML-KEM-1024.
    let ek = recipient.mlkem_key()?;
    let mut m = [0u8; 32];
    getrandom::fill(&mut m)
        .map_err(|e| Error::Key(format!("system entropy unavailable: {e}")))?;
    let (ct, mlkem_ss) = ek.encapsulate_deterministic(&ml_kem::array::Array(m));
    m.zeroize();

    let mlkem_ct = ct.as_slice().to_vec();
    let wrap_key = combine(&x25519_ss, mlkem_ss.as_slice(), &x25519_epk, &mlkem_ct);
    x25519_ss.zeroize();

    Ok(Encapsulation {
        x25519_epk,
        mlkem_ct,
        wrap_key: Zeroizing::new(wrap_key),
    })
}

/// Recover the wrap key for a stanza using an identity.
pub fn decapsulate(
    identity: &Identity,
    x25519_epk: &[u8],
    mlkem_ct: &[u8],
) -> Result<[u8; WRAP_KEY_LEN]> {
    if x25519_epk.len() != X25519_PUB_LEN {
        return Err(Error::Header(format!(
            "ephemeral X25519 key must be {X25519_PUB_LEN} bytes, got {}",
            x25519_epk.len()
        )));
    }
    if mlkem_ct.len() != MLKEM_CT_LEN {
        return Err(Error::Header(format!(
            "ML-KEM ciphertext must be {MLKEM_CT_LEN} bytes, got {}",
            mlkem_ct.len()
        )));
    }

    let mut epk = [0u8; X25519_PUB_LEN];
    epk.copy_from_slice(x25519_epk);
    let mut x25519_ss = identity
        .x25519_secret()
        .diffie_hellman(&PublicKey::from(epk))
        .to_bytes();

    let ct = ml_kem::array::Array::try_from(mlkem_ct)
        .map_err(|_| Error::Header("bad ML-KEM ciphertext length".into()))?;
    let mlkem_ss = identity.mlkem_key().decapsulate(&ct);

    let wrap_key = combine(&x25519_ss, mlkem_ss.as_slice(), x25519_epk, mlkem_ct);
    x25519_ss.zeroize();
    Ok(wrap_key)
}
