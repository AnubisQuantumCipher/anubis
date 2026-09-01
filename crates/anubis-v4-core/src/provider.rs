//! Provider activation boundary for a future normative suite.
//!
//! Provider-reported identity is inventory, not CAVP or CMVP evidence. This
//! module exposes no cryptographic operation and no validation-status field.

use crate::suite::SuiteId;
use core::fmt;

/// Inventory identity reported by a provider adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderIdentity {
    pub implementation: String,
    pub implementation_version: String,
    pub module_version: Option<String>,
}

/// Provider activation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderError {
    Unavailable,
    UnsupportedSuite { requested: SuiteId },
    SelfTestFailed,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("v4 provider is unavailable"),
            Self::UnsupportedSuite { requested } => write!(
                formatter,
                "v4 provider does not support requested suite '{requested}'"
            ),
            Self::SelfTestFailed => formatter.write_str("v4 provider self-test failed"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// Minimal bootstrap behavior required before a provider becomes operational.
pub trait ProviderBootstrap {
    fn identity(&self) -> ProviderIdentity;

    fn self_test(&mut self, requested: SuiteId) -> Result<(), ProviderError>;
}

/// Opaque proof that one exact provider/suite pair passed its startup test.
///
/// ```compile_fail
/// use anubis_v4_core::provider::Operational;
/// let _ = Operational { provider: (), suite: todo!() };
/// ```
pub struct Operational<'provider, P: ProviderBootstrap + ?Sized> {
    provider: &'provider mut P,
    suite: SuiteId,
}

impl<P: ProviderBootstrap + ?Sized> Operational<'_, P> {
    /// Inventory identity of the activated provider.
    #[must_use]
    pub fn identity(&self) -> ProviderIdentity {
        self.provider.identity()
    }

    /// Exact suite for which the startup test succeeded.
    #[must_use]
    pub const fn suite(&self) -> SuiteId {
        self.suite
    }
}

/// Activate exactly the requested suite or return an error.
///
/// There is no fallback provider or suite selection. External callers cannot
/// invoke this yet because the crate intentionally exports no `SuiteId` value.
pub fn activate<P: ProviderBootstrap + ?Sized>(
    provider: &mut P,
    exact_suite: SuiteId,
) -> Result<Operational<'_, P>, ProviderError> {
    provider.self_test(exact_suite)?;
    Ok(Operational {
        provider,
        suite: exact_suite,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::test_suite;

    struct FakeProvider {
        accept: bool,
        observed: Option<SuiteId>,
    }

    impl ProviderBootstrap for FakeProvider {
        fn identity(&self) -> ProviderIdentity {
            ProviderIdentity {
                implementation: "fake".into(),
                implementation_version: "test-only".into(),
                module_version: None,
            }
        }

        fn self_test(&mut self, requested: SuiteId) -> Result<(), ProviderError> {
            self.observed = Some(requested);
            if self.accept {
                Ok(())
            } else {
                Err(ProviderError::SelfTestFailed)
            }
        }
    }

    #[test]
    fn failed_self_test_cannot_produce_operational_capability() {
        let requested = test_suite("test-suite");
        let mut provider = FakeProvider {
            accept: false,
            observed: None,
        };

        assert!(matches!(
            activate(&mut provider, requested),
            Err(ProviderError::SelfTestFailed)
        ));
        assert_eq!(provider.observed, Some(requested));
    }

    #[test]
    fn exact_requested_suite_reaches_provider_without_fallback() {
        let requested = test_suite("test-suite");
        let mut provider = FakeProvider {
            accept: true,
            observed: None,
        };

        let operational = activate(&mut provider, requested).expect("activation");
        assert_eq!(operational.suite(), requested);
        assert_eq!(operational.identity().implementation, "fake");
    }
}
