//! Exact suite identity without an enabled production suite.

use core::fmt;

/// An exact, non-negotiable v4 suite identity.
///
/// ```compile_fail
/// use anubis_v4_core::suite::SuiteId;
/// let _ = SuiteId::new("placeholder");
/// ```
///
/// No public constructor or production constant exists yet. That is
/// deliberate: unresolved protocol decisions must not escape as a de facto
/// suite identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SuiteId {
    canonical: &'static str,
    _private: (),
}

impl SuiteId {
    /// Return the complete canonical suite identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.canonical
    }
}

impl fmt::Display for SuiteId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.canonical)
    }
}

#[cfg(test)]
pub(crate) const fn test_suite(canonical: &'static str) -> SuiteId {
    SuiteId {
        canonical,
        _private: (),
    }
}
