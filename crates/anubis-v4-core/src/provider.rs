//! Fail-closed provider lifecycle for the future normative suite.
//!
//! Provider-reported identity is inventory, not CAVP or CMVP evidence. This
//! module exposes no cryptographic operation and no validation-status field.
//! It does model the lifecycle boundary that every future operation must pass:
//! pre-operational self-tests, a latched error state, an operational
//! capability, and an explicit zeroization result.

use crate::suite::SuiteId;
use core::fmt;

mod sealed {
    pub trait Sealed {}
}

/// Inventory identity reported by a provider adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderIdentity {
    pub implementation: String,
    pub implementation_version: String,
    pub module_version: String,
}

/// Observable state of the isolated candidate module boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleState {
    PreOperational,
    SelfTesting,
    Operational,
    Error,
}

/// Result of the most recent explicit zeroization request.
///
/// This is an interface result, not evidence that a compiler, operating
/// system, allocator, storage device, or physical memory erased every copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZeroizationStatus {
    NotPerformed,
    Succeeded,
    Failed,
}

/// Provider or lifecycle failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderError {
    Unavailable,
    UnsupportedSuite { requested: SuiteId },
    SelfTestFailed,
    ZeroizationFailed,
    NotOperational { state: ModuleState },
    InvalidTransition { state: ModuleState },
    ErrorStateLatched,
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
            Self::ZeroizationFailed => formatter.write_str("v4 provider zeroization failed"),
            Self::NotOperational { state } => {
                write!(formatter, "v4 module is not operational (state: {state:?})")
            }
            Self::InvalidTransition { state } => {
                write!(formatter, "invalid v4 module transition from {state:?}")
            }
            Self::ErrorStateLatched => formatter.write_str("v4 module error state is latched"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// Bootstrap behavior required before a provider becomes operational.
///
/// The eventual provider must perform every pre-operational test required by
/// the frozen suite and module integrity design. A successful return is only a
/// local lifecycle event; it is not CAVP or CMVP evidence.
pub trait ProviderBootstrap: sealed::Sealed {
    fn identity(&self) -> ProviderIdentity;

    fn pre_operational_self_tests(&mut self, requested: SuiteId) -> Result<(), ProviderError>;

    fn zeroize(&mut self) -> Result<(), ProviderError>;
}

/// Module owner that keeps lifecycle state and the provider in one boundary.
///
/// External callers cannot instantiate a production module yet because the
/// crate intentionally exports no constructible production SuiteId.
pub struct Module<P: ProviderBootstrap> {
    provider: P,
    suite: SuiteId,
    state: ModuleState,
    zeroization_status: ZeroizationStatus,
}

impl<P: ProviderBootstrap> Module<P> {
    /// Create a pre-operational boundary for exactly one provider and suite.
    ///
    /// ```compile_fail
    /// use anubis_v4_core::{provider::Module, suite::SuiteId};
    /// # struct Provider;
    /// # impl anubis_v4_core::provider::ProviderBootstrap for Provider {
    /// #     fn identity(&self) -> anubis_v4_core::provider::ProviderIdentity { todo!() }
    /// #     fn pre_operational_self_tests(&mut self, _: SuiteId) -> Result<(), anubis_v4_core::provider::ProviderError> { todo!() }
    /// #     fn zeroize(&mut self) -> Result<(), anubis_v4_core::provider::ProviderError> { todo!() }
    /// # }
    /// let suite = SuiteId::new("unreviewed-suite");
    /// let _ = Module::new(Provider, suite);
    /// ```
    #[must_use]
    pub const fn new(provider: P, exact_suite: SuiteId) -> Self {
        Self {
            provider,
            suite: exact_suite,
            state: ModuleState::PreOperational,
            zeroization_status: ZeroizationStatus::NotPerformed,
        }
    }

    /// Inventory identity of the provider inside this boundary.
    #[must_use]
    pub fn identity(&self) -> ProviderIdentity {
        self.provider.identity()
    }

    /// Exact suite assigned to this boundary.
    #[must_use]
    pub const fn suite(&self) -> SuiteId {
        self.suite
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ModuleState {
        self.state
    }

    /// Result of the most recent explicit zeroization request.
    #[must_use]
    pub const fn zeroization_status(&self) -> ZeroizationStatus {
        self.zeroization_status
    }

    /// Run the pre-operational test sequence exactly once.
    ///
    /// Any failure latches the module in ModuleState::Error. A successful
    /// result is required before an Operational capability can exist.
    pub fn initialize(&mut self) -> Result<(), ProviderError> {
        match self.state {
            ModuleState::PreOperational => self.run_self_tests(),
            ModuleState::Error => Err(ProviderError::ErrorStateLatched),
            state => Err(ProviderError::InvalidTransition { state }),
        }
    }

    /// Re-run the complete self-test sequence on demand.
    ///
    /// A failed on-demand test latches the same error state as a startup test.
    pub fn run_on_demand_self_tests(&mut self) -> Result<(), ProviderError> {
        match self.state {
            ModuleState::Operational => self.run_self_tests(),
            ModuleState::Error => Err(ProviderError::ErrorStateLatched),
            state => Err(ProviderError::InvalidTransition { state }),
        }
    }

    /// Borrow the provider through an opaque operational capability.
    ///
    /// The capability exposes no cryptographic operation yet. Future services
    /// must be methods on this capability so pre-operational and error states
    /// cannot reach the provider's service surface.
    pub fn operational(&mut self) -> Result<Operational<'_, P>, ProviderError> {
        if self.state != ModuleState::Operational {
            return Err(ProviderError::NotOperational { state: self.state });
        }

        Ok(Operational { module: self })
    }

    /// Request provider zeroization and expose its explicit result.
    ///
    /// Zeroization does not recover a latched error state. A zeroization
    /// failure itself latches the module in the error state.
    pub fn zeroize(&mut self) -> Result<ZeroizationStatus, ProviderError> {
        match self.provider.zeroize() {
            Ok(()) => {
                self.zeroization_status = ZeroizationStatus::Succeeded;
                Ok(ZeroizationStatus::Succeeded)
            }
            Err(_) => {
                self.zeroization_status = ZeroizationStatus::Failed;
                self.state = ModuleState::Error;
                Err(ProviderError::ZeroizationFailed)
            }
        }
    }

    fn run_self_tests(&mut self) -> Result<(), ProviderError> {
        self.state = ModuleState::SelfTesting;
        match self.provider.pre_operational_self_tests(self.suite) {
            Ok(()) => {
                self.state = ModuleState::Operational;
                Ok(())
            }
            Err(error) => {
                self.state = ModuleState::Error;
                Err(error)
            }
        }
    }
}

/// Opaque proof that one exact provider/suite pair passed its self-tests.
///
/// ```compile_fail
/// use anubis_v4_core::provider::Operational;
/// let _ = Operational { module: todo!() };
/// ```
pub struct Operational<'provider, P: ProviderBootstrap> {
    module: &'provider mut Module<P>,
}

impl<P: ProviderBootstrap> Operational<'_, P> {
    /// Inventory identity of the activated provider.
    #[must_use]
    pub fn identity(&self) -> ProviderIdentity {
        self.module.provider.identity()
    }

    /// Exact suite for which the self-test sequence succeeded.
    #[must_use]
    pub const fn suite(&self) -> SuiteId {
        self.module.suite
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::test_suite;

    struct FakeProvider {
        self_test_result: Result<(), ProviderError>,
        zeroize_result: Result<(), ProviderError>,
        observed_suites: Vec<SuiteId>,
        zeroize_called: bool,
    }

    impl FakeProvider {
        fn accepting() -> Self {
            Self {
                self_test_result: Ok(()),
                zeroize_result: Ok(()),
                observed_suites: Vec::new(),
                zeroize_called: false,
            }
        }
    }

    impl sealed::Sealed for FakeProvider {}

    impl ProviderBootstrap for FakeProvider {
        fn identity(&self) -> ProviderIdentity {
            ProviderIdentity {
                implementation: "fake".into(),
                implementation_version: "test-only".into(),
                module_version: "test-module".into(),
            }
        }

        fn pre_operational_self_tests(&mut self, requested: SuiteId) -> Result<(), ProviderError> {
            self.observed_suites.push(requested);
            self.self_test_result.clone()
        }

        fn zeroize(&mut self) -> Result<(), ProviderError> {
            self.zeroize_called = true;
            self.zeroize_result.clone()
        }
    }

    #[test]
    fn operational_capability_requires_successful_initialization() {
        let requested = test_suite("test-suite");
        let mut module = Module::new(FakeProvider::accepting(), requested);

        assert_eq!(module.state(), ModuleState::PreOperational);
        assert!(matches!(
            module.operational(),
            Err(ProviderError::NotOperational {
                state: ModuleState::PreOperational
            })
        ));

        module.initialize().expect("initialization");
        assert_eq!(module.state(), ModuleState::Operational);
        let operational = module.operational().expect("operational capability");
        assert_eq!(operational.suite(), requested);
        assert_eq!(operational.identity().implementation, "fake");
    }

    #[test]
    fn failed_self_test_latches_error_and_cannot_be_retried() {
        let requested = test_suite("test-suite");
        let mut provider = FakeProvider::accepting();
        provider.self_test_result = Err(ProviderError::SelfTestFailed);
        let mut module = Module::new(provider, requested);

        assert_eq!(module.initialize(), Err(ProviderError::SelfTestFailed));
        assert_eq!(module.state(), ModuleState::Error);
        assert_eq!(module.initialize(), Err(ProviderError::ErrorStateLatched));
        assert_eq!(
            module.run_on_demand_self_tests(),
            Err(ProviderError::ErrorStateLatched)
        );
        assert!(matches!(
            module.operational(),
            Err(ProviderError::NotOperational {
                state: ModuleState::Error
            })
        ));
    }

    #[test]
    fn exact_requested_suite_reaches_every_self_test_without_fallback() {
        let requested = test_suite("test-suite");
        let mut module = Module::new(FakeProvider::accepting(), requested);

        module.initialize().expect("initialization");
        module
            .run_on_demand_self_tests()
            .expect("on-demand self-test");

        assert_eq!(module.provider.observed_suites, vec![requested, requested]);
    }

    #[test]
    fn failed_on_demand_self_test_latches_error() {
        let requested = test_suite("test-suite");
        let mut module = Module::new(FakeProvider::accepting(), requested);
        module.initialize().expect("initialization");
        module.provider.self_test_result = Err(ProviderError::SelfTestFailed);

        assert_eq!(
            module.run_on_demand_self_tests(),
            Err(ProviderError::SelfTestFailed)
        );
        assert_eq!(module.state(), ModuleState::Error);
    }

    #[test]
    fn zeroization_reports_success_without_recovering_error_state() {
        let requested = test_suite("test-suite");
        let mut provider = FakeProvider::accepting();
        provider.self_test_result = Err(ProviderError::SelfTestFailed);
        let mut module = Module::new(provider, requested);
        let _ = module.initialize();

        assert_eq!(module.zeroization_status(), ZeroizationStatus::NotPerformed);
        assert_eq!(module.zeroize(), Ok(ZeroizationStatus::Succeeded));
        assert_eq!(module.zeroization_status(), ZeroizationStatus::Succeeded);
        assert!(module.provider.zeroize_called);
        assert_eq!(module.state(), ModuleState::Error);
    }

    #[test]
    fn zeroization_failure_latches_error_and_reports_failure() {
        let requested = test_suite("test-suite");
        let mut provider = FakeProvider::accepting();
        provider.zeroize_result = Err(ProviderError::ZeroizationFailed);
        let mut module = Module::new(provider, requested);
        module.initialize().expect("initialization");

        assert_eq!(module.zeroize(), Err(ProviderError::ZeroizationFailed));
        assert_eq!(module.zeroization_status(), ZeroizationStatus::Failed);
        assert_eq!(module.state(), ModuleState::Error);
    }
}
