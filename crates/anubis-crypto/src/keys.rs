//! ANUBIS key material: identities (secret) and recipients (public).
//!
//! Identities store *seeds*, not expanded keys. FIPS 203 permits
//! deterministic key generation from a 64-byte (d || z) seed, and ml-kem's
//! own documentation notes the expanded 3168-byte form "is deprecated in
//! practice; use `from_seed`". Seeds keep an identity at 128 bytes, which
//! encodes to roughly 210 bech32 characters -- comfortably inside the 1023
//! range where the bech32m checksum guarantee holds.
//!
//! Recipients cannot be shrunk the same way: encapsulating genuinely
//! requires the full 1568-byte ML-KEM encapsulation key. They therefore
//! exceed the guaranteed range, which is why `fingerprint` exists.

use bech32::Hrp;
use hybrid_array::Array;
use ml_dsa::{MlDsa87, SigningKey, VerifyingKey};
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, KeyExport};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::b32::Bech32mUnlimited;
use crate::error::{Error, Result};

/// X25519 public key length.
pub const X25519_PUB_LEN: usize = 32;
/// X25519 secret scalar length.
pub const X25519_SEC_LEN: usize = 32;
/// ML-KEM-1024 encapsulation key length (FIPS 203).
pub const MLKEM_EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext length (FIPS 203).
pub const MLKEM_CT_LEN: usize = 1568;
/// ML-KEM (d || z) seed length.
pub const MLKEM_SEED_LEN: usize = 64;
/// ML-DSA-87 seed length (FIPS 204 xi).
pub const MLDSA_SEED_LEN: usize = 32;
/// ML-DSA-87 verifying key length.
pub const MLDSA_VK_LEN: usize = 2592;

/// Public recipient payload: x25519_pub || mlkem_ek.
pub const RECIPIENT_LEN: usize = X25519_PUB_LEN + MLKEM_EK_LEN;
/// Secret identity payload: x25519_sec || mlkem_seed || mldsa_seed.
pub const IDENTITY_LEN: usize = X25519_SEC_LEN + MLKEM_SEED_LEN + MLDSA_SEED_LEN;

const HRP_RECIPIENT: &str = "anubis";
const HRP_IDENTITY: &str = "ANUBIS-SECRET-KEY-";

/// 80-bit human-verifiable handle for a recipient payload.
///
/// Rendered as five groups of four uppercase hex digits, e.g.
/// `3F2A-91C7-04BE-D5A8-6612`. This is the identifier humans should compare
/// out of band; the full bech32 string is a machine artifact.
#[must_use]
pub fn fingerprint(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    let mut out = String::with_capacity(24);
    for (i, byte) in digest.iter().take(10).enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push('-');
        }
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)
        .map_err(|e| Error::Key(format!("system entropy unavailable: {e}")))?;
    Ok(buf)
}

/// A public ANUBIS recipient: X25519 public key plus ML-KEM-1024
/// encapsulation key.
#[derive(Clone)]
pub struct Recipient {
    x25519: [u8; X25519_PUB_LEN],
    mlkem_ek: Vec<u8>,
}

impl Recipient {
    /// Raw 1600-byte payload: x25519_pub || mlkem_ek.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECIPIENT_LEN);
        out.extend_from_slice(&self.x25519);
        out.extend_from_slice(&self.mlkem_ek);
        out
    }

    /// Parse from a raw payload.
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        if payload.len() != RECIPIENT_LEN {
            return Err(Error::Key(format!(
                "recipient must be {RECIPIENT_LEN} bytes, got {}",
                payload.len()
            )));
        }
        let mut x25519 = [0u8; X25519_PUB_LEN];
        x25519.copy_from_slice(&payload[..X25519_PUB_LEN]);
        Ok(Self {
            x25519,
            mlkem_ek: payload[X25519_PUB_LEN..].to_vec(),
        })
    }

    /// Encode as `anubis1...`.
    pub fn encode(&self) -> Result<String> {
        let hrp = Hrp::parse(HRP_RECIPIENT)
            .map_err(|e| Error::Key(format!("bad hrp: {e}")))?;
        bech32::encode_lower::<Bech32mUnlimited>(hrp, &self.to_payload())
            .map_err(|e| Error::Key(format!("bech32 encode failed: {e}")))
    }

    /// Decode from `anubis1...`.
    pub fn decode(s: &str) -> Result<Self> {
        let (hrp, data) = crate::b32::decode(s.trim())
            .map_err(|e| Error::Key(format!("bech32 decode failed: {e}")))?;
        if hrp.as_str() != HRP_RECIPIENT {
            return Err(Error::Key(format!(
                "expected an '{HRP_RECIPIENT}1...' recipient, got '{}'",
                hrp.as_str()
            )));
        }
        Self::from_payload(&data)
    }

    /// 80-bit fingerprint of this recipient.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.to_payload())
    }

    #[must_use]
    pub fn x25519_bytes(&self) -> &[u8; X25519_PUB_LEN] {
        &self.x25519
    }

    /// Reconstruct the ML-KEM encapsulation key.
    pub fn mlkem_key(&self) -> Result<EncapsulationKey1024> {
        let arr = ml_kem::array::Array::try_from(self.mlkem_ek.as_slice())
            .map_err(|_| Error::Key("bad ML-KEM encapsulation key length".into()))?;
        EncapsulationKey1024::new(&arr)
            .map_err(|_| Error::Key("ML-KEM encapsulation key failed validation".into()))
    }
}

/// A secret ANUBIS identity. Capability-complete: it can decrypt and sign.
///
/// `Debug` is implemented by hand and deliberately redacts the key material.
/// A derived `Debug` would print 128 bytes of secret into any log line that
/// happened to format an identity.
pub struct Identity {
    x25519: [u8; X25519_SEC_LEN],
    mlkem_seed: [u8; MLKEM_SEED_LEN],
    mldsa_seed: [u8; MLDSA_SEED_LEN],
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl core::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Recipient")
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.x25519.zeroize();
        self.mlkem_seed.zeroize();
        self.mldsa_seed.zeroize();
    }
}

impl Identity {
    /// Generate a fresh identity from system entropy.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            x25519: random_bytes::<X25519_SEC_LEN>()?,
            mlkem_seed: random_bytes::<MLKEM_SEED_LEN>()?,
            mldsa_seed: random_bytes::<MLDSA_SEED_LEN>()?,
        })
    }

    /// Parse from a raw 128-byte payload.
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        if payload.len() != IDENTITY_LEN {
            return Err(Error::Key(format!(
                "identity must be {IDENTITY_LEN} bytes, got {}",
                payload.len()
            )));
        }
        let mut x25519 = [0u8; X25519_SEC_LEN];
        let mut mlkem_seed = [0u8; MLKEM_SEED_LEN];
        let mut mldsa_seed = [0u8; MLDSA_SEED_LEN];
        let (a, rest) = payload.split_at(X25519_SEC_LEN);
        let (b, c) = rest.split_at(MLKEM_SEED_LEN);
        x25519.copy_from_slice(a);
        mlkem_seed.copy_from_slice(b);
        mldsa_seed.copy_from_slice(c);
        Ok(Self {
            x25519,
            mlkem_seed,
            mldsa_seed,
        })
    }

    /// Raw 128-byte payload. Secret: handle accordingly.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IDENTITY_LEN);
        out.extend_from_slice(&self.x25519);
        out.extend_from_slice(&self.mlkem_seed);
        out.extend_from_slice(&self.mldsa_seed);
        out
    }

    /// Encode as `ANUBIS-SECRET-KEY-1...`.
    ///
    /// The intermediate payload is wiped: an identity is 128 bytes of pure
    /// secret and every keygen and key load would otherwise leave a copy in
    /// freed heap.
    pub fn encode(&self) -> Result<String> {
        let hrp = Hrp::parse(HRP_IDENTITY)
            .map_err(|e| Error::Key(format!("bad hrp: {e}")))?;
        let payload = Zeroizing::new(self.to_payload());
        bech32::encode_upper::<Bech32mUnlimited>(hrp, &payload)
            .map_err(|e| Error::Key(format!("bech32 encode failed: {e}")))
    }

    /// Decode from `ANUBIS-SECRET-KEY-1...`.
    pub fn decode(s: &str) -> Result<Self> {
        let (hrp, data) = crate::b32::decode(s.trim())
            .map_err(|e| Error::Key(format!("bech32 decode failed: {e}")))?;
        let data = Zeroizing::new(data);
        if !hrp.as_str().eq_ignore_ascii_case(HRP_IDENTITY) {
            return Err(Error::Key(format!(
                "expected an '{HRP_IDENTITY}1...' identity, got '{}'",
                hrp.as_str()
            )));
        }
        Self::from_payload(&data)
    }

    pub(crate) fn x25519_secret(&self) -> StaticSecret {
        StaticSecret::from(self.x25519)
    }

    pub(crate) fn mlkem_key(&self) -> DecapsulationKey1024 {
        DecapsulationKey1024::from_seed(Array(self.mlkem_seed))
    }

    /// ML-DSA-87 signing key derived from the identity seed.
    pub fn signing_key(&self) -> SigningKey<MlDsa87> {
        SigningKey::<MlDsa87>::from_seed(&Array(self.mldsa_seed))
    }

    /// ML-DSA-87 verifying key derived from the identity seed.
    pub fn verifying_key(&self) -> VerifyingKey<MlDsa87> {
        let sk = self.signing_key();
        sk.expanded_key().verifying_key()
    }

    /// The public recipient corresponding to this identity.
    pub fn to_recipient(&self) -> Result<Recipient> {
        let x_pub = PublicKey::from(&self.x25519_secret());
        let dk = self.mlkem_key();
        let ek_bytes = dk.encapsulation_key().to_bytes();
        Ok(Recipient {
            x25519: *x_pub.as_bytes(),
            mlkem_ek: ek_bytes.as_slice().to_vec(),
        })
    }
}
