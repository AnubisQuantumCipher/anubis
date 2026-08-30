//! Bech32m with the code-length cap lifted.
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

use bech32::primitives::checksum::Checksum;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::primitives::gf32_ext::Fe1024;
use bech32::Fe32;

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

/// Decode a string encoded with [`Bech32mUnlimited`].
///
/// `bech32::decode` only tries the stock `Bech32`/`Bech32m` checksums, both
/// of which cap the code length at 1023 and therefore reject ANUBIS
/// recipients outright.
pub fn decode(s: &str) -> core::result::Result<(bech32::Hrp, Vec<u8>), DecodeError> {
    let parsed = CheckedHrpstring::new::<Bech32mUnlimited>(s)?;
    Ok((parsed.hrp(), parsed.byte_iter().collect()))
}

pub use bech32::primitives::decode::CheckedHrpstringError as DecodeError;
