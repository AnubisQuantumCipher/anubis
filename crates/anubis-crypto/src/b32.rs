//! Bech32m and legacy Bech32 with the code-length cap lifted.
//!
//! `bech32::Bech32m` hardcodes `CODE_LENGTH = 1023`. An ANUBIS recipient
//! carries a 1568-byte ML-KEM-1024 encapsulation key, which encodes to
//! roughly 2573 characters and is therefore rejected by the stock
//! implementation.
//!
//! This type reuses the exact BIP-350 bech32m generator polynomial and
//! target residue and lifts only the length cap. The checksum arithmetic is
//! unchanged; what changes is the guarantee. Bech32m's error-detection
//! properties are proven only within the code length, so beyond 1023
//! characters the checksum still detects most corruption but carries no
//! formal guarantee. That is precisely why every recipient also carries an
//! 80-bit fingerprint (see `keys::fingerprint`) for human verification.

use bech32::Fe32;
use bech32::primitives::checksum::Checksum;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::primitives::gf32_ext::Fe1024;

/// Bech32m checksum with no code-length limit.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Bech32mUnlimited;

impl Checksum for Bech32mUnlimited {
    type MidstateRepr = u32;
    type CorrectionField = Fe1024;

    const ROOT_GENERATOR: Self::CorrectionField = Fe1024::new([Fe32::P, Fe32::X]);
    const ROOT_EXPONENTS: core::ops::RangeInclusive<usize> = 24..=26;

    // The only deviation from `bech32::Bech32m`.
    const CODE_LENGTH: usize = usize::MAX;

    const CHECKSUM_LENGTH: usize = 6;
    // BIP-350 bech32 generator, shifted forms.
    const GENERATOR_SH: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    // BIP-350 bech32m target residue.
    const TARGET_RESIDUE: u32 = 0x2bc8_30a3;
}

/// Legacy BIP-173 Bech32 checksum with no code-length limit.
///
/// ANUBIS writers use [`Bech32mUnlimited`]. This type exists only so readers
/// can recover keys produced from an earlier revision of the format document
/// which named Bech32 even though deployed ANUBIS releases emitted Bech32m.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Bech32Unlimited;

impl Checksum for Bech32Unlimited {
    type MidstateRepr = u32;
    type CorrectionField = Fe1024;

    const ROOT_GENERATOR: Self::CorrectionField = Fe1024::new([Fe32::P, Fe32::X]);
    const ROOT_EXPONENTS: core::ops::RangeInclusive<usize> = 24..=26;
    const CODE_LENGTH: usize = usize::MAX;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    const TARGET_RESIDUE: u32 = 1;
}

/// Decode a canonical [`Bech32mUnlimited`] string or a legacy
/// [`Bech32Unlimited`] string.
///
/// `bech32::decode` only tries the stock `Bech32`/`Bech32m` checksums, both
/// of which cap the code length at 1023 and therefore reject ANUBIS
/// recipients outright.
pub fn decode(s: &str) -> Result<(bech32::Hrp, Vec<u8>), DecodeError> {
    decode_canonical(s).map_err(|error| match error {
        CanonicalDecodeError::Bech32(error) => error,
        CanonicalDecodeError::NonCanonicalPadding => {
            bech32::primitives::decode::ChecksumError::InvalidLength.into()
        }
    })
}

/// Key-layer decoder which retains the precise canonical-padding diagnostic.
pub(crate) fn decode_key(s: &str) -> Result<(bech32::Hrp, Vec<u8>), CanonicalDecodeError> {
    decode_canonical(s)
}

fn decode_canonical(s: &str) -> Result<(bech32::Hrp, Vec<u8>), CanonicalDecodeError> {
    match decode_checked::<Bech32mUnlimited>(s) {
        Ok(decoded) => Ok(decoded),
        Err(CanonicalDecodeError::Bech32(bech32m_error)) => {
            match decode_checked::<Bech32Unlimited>(s) {
                Ok(decoded) => Ok(decoded),
                Err(CanonicalDecodeError::NonCanonicalPadding) => {
                    Err(CanonicalDecodeError::NonCanonicalPadding)
                }
                Err(_) => Err(CanonicalDecodeError::Bech32(bech32m_error)),
            }
        }
        Err(error) => Err(error),
    }
}

fn decode_checked<Ck: Checksum>(s: &str) -> Result<(bech32::Hrp, Vec<u8>), CanonicalDecodeError> {
    let parsed = CheckedHrpstring::new::<Ck>(s).map_err(CanonicalDecodeError::Bech32)?;
    let hrp = parsed.hrp();
    let data: Vec<u8> = parsed.byte_iter().collect();

    // `byte_iter` necessarily discards the leftover bits that do not fill a
    // complete byte. Re-encoding the decoded bytes under the same checksum
    // profile proves those bits were the unique canonical zero padding and
    // that no redundant field element was accepted. Case is deliberately
    // ignored here because whole-token lower/uppercase compatibility is
    // handled by the key layer.
    let canonical = bech32::encode_lower::<Ck>(hrp, &data)
        .map_err(|_| CanonicalDecodeError::NonCanonicalPadding)?;
    if !canonical.eq_ignore_ascii_case(s) {
        return Err(CanonicalDecodeError::NonCanonicalPadding);
    }
    Ok((hrp, data))
}

/// Internal key-string decoding failure with a precise padding diagnostic.
#[derive(Debug)]
pub(crate) enum CanonicalDecodeError {
    /// The Bech32 syntax or checksum was invalid.
    Bech32(bech32::primitives::decode::CheckedHrpstringError),
    /// The final five-bit group did not carry canonical zero padding.
    NonCanonicalPadding,
}

impl core::fmt::Display for CanonicalDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bech32(error) => write!(f, "{error}"),
            Self::NonCanonicalPadding => f.write_str("non-canonical trailing bit padding"),
        }
    }
}

impl std::error::Error for CanonicalDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bech32(error) => Some(error),
            Self::NonCanonicalPadding => None,
        }
    }
}

// Preserve the released public error type, including Clone/PartialEq/Eq and
// downstream pattern matching. Canonical-padding failures use the closest
// existing checksum classification at this low-level compatibility boundary;
// the key API above retains the more specific diagnostic.
pub use bech32::primitives::decode::CheckedHrpstringError as DecodeError;
