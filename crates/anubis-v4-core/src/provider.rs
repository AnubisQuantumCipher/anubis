//! Fail-closed provider lifecycle for the future normative suite.
//!
//! Provider-reported identity is inventory, not CAVP or CMVP evidence. Provider
//! identity cannot supply validation metadata; the module-owned completed-
//! service indicator can report only `NotValidated`. This module exposes no
//! cryptographic operation. It models the boundary every future operation must pass:
//! ordered pre-operational self-tests, a latched error state, an operational
//! capability, terminal zeroization, and a result-bound output gate.

use crate::service::{
    CompletedService, ServiceCompletion, ServiceId, ServiceIndicator, ServiceProfileStatus,
};
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
    Zeroized,
}

/// Reason the complete module-owned self-test sequence is running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelfTestKind {
    PreOperational,
    OnDemand,
}

/// Mandatory order of the future module's self-test groups.
///
/// The hooks are scaffolding only. The crate does not yet contain the
/// integrity mechanism, known answers, or cryptographic implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelfTestPhase {
    IntegrityPrimitiveCast,
    ModuleIntegrity,
    RemainingAlgorithmCasts,
}

const SELF_TEST_PHASES: [SelfTestPhase; 3] = [
    SelfTestPhase::IntegrityPrimitiveCast,
    SelfTestPhase::ModuleIntegrity,
    SelfTestPhase::RemainingAlgorithmCasts,
];

/// Observable summary of the most recent self-test sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelfTestStatus {
    NotRun,
    Running {
        kind: SelfTestKind,
        phase: SelfTestPhase,
    },
    Passed {
        kind: SelfTestKind,
    },
    Failed {
        kind: SelfTestKind,
        phase: SelfTestPhase,
    },
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
    ServiceFailed,
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
            Self::ServiceFailed => formatter.write_str("v4 service failed"),
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

    fn run_self_test_phase(
        &mut self,
        requested: SuiteId,
        kind: SelfTestKind,
        phase: SelfTestPhase,
    ) -> Result<(), ProviderError>;

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
    self_test_status: SelfTestStatus,
    zeroization_status: ZeroizationStatus,
}

/// Read-only status produced by the lifecycle owner, not by the provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleStatus {
    identity: ProviderIdentity,
    suite: SuiteId,
    state: ModuleState,
    self_test_status: SelfTestStatus,
    zeroization_status: ZeroizationStatus,
}

impl ModuleStatus {
    #[must_use]
    pub const fn identity(&self) -> &ProviderIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn suite(&self) -> SuiteId {
        self.suite
    }

    #[must_use]
    pub const fn state(&self) -> ModuleState {
        self.state
    }

    #[must_use]
    pub const fn self_test_status(&self) -> SelfTestStatus {
        self.self_test_status
    }

    #[must_use]
    pub const fn zeroization_status(&self) -> ZeroizationStatus {
        self.zeroization_status
    }
}

impl<P: ProviderBootstrap> Module<P> {
    /// Create a pre-operational boundary for exactly one provider and suite.
    ///
    /// ```compile_fail
    /// use anubis_v4_core::{provider::Module, suite::SuiteId};
    /// # struct Provider;
    /// # impl anubis_v4_core::provider::ProviderBootstrap for Provider {
    /// #     fn identity(&self) -> anubis_v4_core::provider::ProviderIdentity { todo!() }
    /// #     fn run_self_test_phase(&mut self, _: SuiteId, _: anubis_v4_core::provider::SelfTestKind, _: anubis_v4_core::provider::SelfTestPhase) -> Result<(), anubis_v4_core::provider::ProviderError> { todo!() }
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
            self_test_status: SelfTestStatus::NotRun,
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

    /// Summary of the most recent module-owned self-test sequence.
    #[must_use]
    pub const fn self_test_status(&self) -> SelfTestStatus {
        self.self_test_status
    }

    /// Read-only status snapshot. Provider identity is inventory only.
    #[must_use]
    pub fn status(&self) -> ModuleStatus {
        ModuleStatus {
            identity: self.provider.identity(),
            suite: self.suite,
            state: self.state,
            self_test_status: self.self_test_status,
            zeroization_status: self.zeroization_status,
        }
    }

    /// Run the pre-operational test sequence exactly once.
    ///
    /// Any failure latches the module in ModuleState::Error. A successful
    /// result is required before an Operational capability can exist.
    pub fn initialize(&mut self) -> Result<(), ProviderError> {
        match self.state {
            ModuleState::PreOperational => self.run_self_tests(SelfTestKind::PreOperational),
            ModuleState::Error => Err(ProviderError::ErrorStateLatched),
            state => Err(ProviderError::InvalidTransition { state }),
        }
    }

    /// Re-run the complete self-test sequence on demand.
    ///
    /// A failed on-demand test latches the same error state as a startup test.
    pub fn run_on_demand_self_tests(&mut self) -> Result<(), ProviderError> {
        match self.state {
            ModuleState::Operational => self.run_self_tests(SelfTestKind::OnDemand),
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
    /// Successful zeroization permanently revokes operation. Zeroization does
    /// not recover a latched error state, and failure latches the error state.
    pub fn zeroize(&mut self) -> Result<ZeroizationStatus, ProviderError> {
        let error_was_latched = self.state == ModuleState::Error;
        match self.attempt_zeroization() {
            ZeroizationStatus::Succeeded => {
                if !error_was_latched {
                    self.state = ModuleState::Zeroized;
                }
                Ok(ZeroizationStatus::Succeeded)
            }
            ZeroizationStatus::Failed => {
                self.state = ModuleState::Error;
                Err(ProviderError::ZeroizationFailed)
            }
            ZeroizationStatus::NotPerformed => unreachable!("zeroization attempt has a result"),
        }
    }

    fn run_self_tests(&mut self, kind: SelfTestKind) -> Result<(), ProviderError> {
        self.state = ModuleState::SelfTesting;
        for phase in SELF_TEST_PHASES {
            self.self_test_status = SelfTestStatus::Running { kind, phase };
            if let Err(error) = self.provider.run_self_test_phase(self.suite, kind, phase) {
                self.self_test_status = SelfTestStatus::Failed { kind, phase };
                self.latch_error_and_cleanup();
                return Err(error);
            }
        }

        self.self_test_status = SelfTestStatus::Passed { kind };
        self.state = ModuleState::Operational;
        Ok(())
    }

    fn attempt_zeroization(&mut self) -> ZeroizationStatus {
        if self.zeroization_status == ZeroizationStatus::Succeeded {
            return ZeroizationStatus::Succeeded;
        }

        self.zeroization_status = match self.provider.zeroize() {
            Ok(()) => ZeroizationStatus::Succeeded,
            Err(_) => ZeroizationStatus::Failed,
        };
        self.zeroization_status
    }

    fn latch_error_and_cleanup(&mut self) {
        self.state = ModuleState::Error;
        let _ = self.attempt_zeroization();
    }
}

impl<P: ProviderBootstrap> Drop for Module<P> {
    fn drop(&mut self) {
        let _ = self.attempt_zeroization();
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

    /// Return module status through the same result-bound gate future services
    /// must use.
    pub fn status(&mut self) -> Result<CompletedService<ModuleStatus>, ProviderError> {
        let status = self.module.status();
        self.complete_service(
            ServiceId::MODULE_STATUS,
            ServiceProfileStatus::AdministrativeCompleted,
            ServiceCompletion::Completed(status),
        )
    }

    fn complete_service<T>(
        &mut self,
        service: ServiceId,
        profile_status: ServiceProfileStatus,
        completion: ServiceCompletion<T>,
    ) -> Result<CompletedService<T>, ProviderError> {
        if self.module.state != ModuleState::Operational {
            return Err(ProviderError::NotOperational {
                state: self.module.state,
            });
        }

        match completion {
            ServiceCompletion::Completed(output) => {
                let indicator = ServiceIndicator::local(service, self.module.suite, profile_status);
                Ok(CompletedService::local(output, indicator))
            }
            ServiceCompletion::Rejected => Err(ProviderError::ServiceFailed),
            ServiceCompletion::Fatal => {
                self.module.latch_error_and_cleanup();
                Err(ProviderError::ServiceFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{CmvpValidationStatus, ServiceProfileStatus, test_service};
    use crate::suite::test_suite;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ZeroizeObservation {
        Never,
        Once,
        Repeated,
    }

    struct FakeProvider {
        self_test_failure: Option<(SelfTestPhase, ProviderError)>,
        zeroize_result: Result<(), ProviderError>,
        observed_phases: Vec<(SuiteId, SelfTestKind, SelfTestPhase)>,
        zeroize_observation: Rc<Cell<ZeroizeObservation>>,
    }

    impl FakeProvider {
        fn accepting() -> Self {
            Self {
                self_test_failure: None,
                zeroize_result: Ok(()),
                observed_phases: Vec::new(),
                zeroize_observation: Rc::new(Cell::new(ZeroizeObservation::Never)),
            }
        }

        fn zeroize_observation(&self) -> Rc<Cell<ZeroizeObservation>> {
            Rc::clone(&self.zeroize_observation)
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

        fn run_self_test_phase(
            &mut self,
            requested: SuiteId,
            kind: SelfTestKind,
            phase: SelfTestPhase,
        ) -> Result<(), ProviderError> {
            self.observed_phases.push((requested, kind, phase));
            match &self.self_test_failure {
                Some((failed_phase, error)) if *failed_phase == phase => Err(error.clone()),
                _ => Ok(()),
            }
        }

        fn zeroize(&mut self) -> Result<(), ProviderError> {
            let observed = match self.zeroize_observation.get() {
                ZeroizeObservation::Never => ZeroizeObservation::Once,
                ZeroizeObservation::Once | ZeroizeObservation::Repeated => {
                    ZeroizeObservation::Repeated
                }
            };
            self.zeroize_observation.set(observed);
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
        assert_eq!(
            module.self_test_status(),
            SelfTestStatus::Passed {
                kind: SelfTestKind::PreOperational
            }
        );
        let operational = module.operational().expect("operational capability");
        assert_eq!(operational.suite(), requested);
        assert_eq!(operational.identity().implementation, "fake");
    }

    #[test]
    fn self_test_phases_are_module_owned_and_ordered() {
        let requested = test_suite("test-suite");
        let mut module = Module::new(FakeProvider::accepting(), requested);

        module.initialize().expect("initialization");

        assert_eq!(
            module.provider.observed_phases,
            vec![
                (
                    requested,
                    SelfTestKind::PreOperational,
                    SelfTestPhase::IntegrityPrimitiveCast
                ),
                (
                    requested,
                    SelfTestKind::PreOperational,
                    SelfTestPhase::ModuleIntegrity
                ),
                (
                    requested,
                    SelfTestKind::PreOperational,
                    SelfTestPhase::RemainingAlgorithmCasts
                ),
            ]
        );
    }

    #[test]
    fn failed_self_test_short_circuits_latches_and_cleans_up() {
        let requested = test_suite("test-suite");
        let mut provider = FakeProvider::accepting();
        provider.self_test_failure = Some((
            SelfTestPhase::ModuleIntegrity,
            ProviderError::SelfTestFailed,
        ));
        let zeroize_observation = provider.zeroize_observation();
        let mut module = Module::new(provider, requested);

        assert_eq!(module.initialize(), Err(ProviderError::SelfTestFailed));
        assert_eq!(module.state(), ModuleState::Error);
        assert_eq!(
            module.self_test_status(),
            SelfTestStatus::Failed {
                kind: SelfTestKind::PreOperational,
                phase: SelfTestPhase::ModuleIntegrity
            }
        );
        assert_eq!(module.zeroization_status(), ZeroizationStatus::Succeeded);
        assert_eq!(zeroize_observation.get(), ZeroizeObservation::Once);
        assert_eq!(
            module.provider.observed_phases,
            vec![
                (
                    requested,
                    SelfTestKind::PreOperational,
                    SelfTestPhase::IntegrityPrimitiveCast
                ),
                (
                    requested,
                    SelfTestKind::PreOperational,
                    SelfTestPhase::ModuleIntegrity
                ),
            ]
        );
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
    fn on_demand_sequence_uses_the_exact_suite_without_fallback() {
        let requested = test_suite("test-suite");
        let mut module = Module::new(FakeProvider::accepting(), requested);

        module.initialize().expect("initialization");
        module.provider.observed_phases.clear();
        module
            .run_on_demand_self_tests()
            .expect("on-demand self-test");

        assert_eq!(
            module.provider.observed_phases,
            vec![
                (
                    requested,
                    SelfTestKind::OnDemand,
                    SelfTestPhase::IntegrityPrimitiveCast
                ),
                (
                    requested,
                    SelfTestKind::OnDemand,
                    SelfTestPhase::ModuleIntegrity
                ),
                (
                    requested,
                    SelfTestKind::OnDemand,
                    SelfTestPhase::RemainingAlgorithmCasts
                ),
            ]
        );
        assert_eq!(
            module.self_test_status(),
            SelfTestStatus::Passed {
                kind: SelfTestKind::OnDemand
            }
        );
    }

    #[test]
    fn failed_on_demand_self_test_latches_error() {
        let requested = test_suite("test-suite");
        let mut module = Module::new(FakeProvider::accepting(), requested);
        module.initialize().expect("initialization");
        module.provider.self_test_failure = Some((
            SelfTestPhase::RemainingAlgorithmCasts,
            ProviderError::SelfTestFailed,
        ));

        assert_eq!(
            module.run_on_demand_self_tests(),
            Err(ProviderError::SelfTestFailed)
        );
        assert_eq!(module.state(), ModuleState::Error);
    }

    #[test]
    fn successful_zeroization_is_terminal_and_idempotent() {
        let requested = test_suite("test-suite");
        let provider = FakeProvider::accepting();
        let zeroize_observation = provider.zeroize_observation();
        let mut module = Module::new(provider, requested);
        module.initialize().expect("initialization");

        assert_eq!(module.zeroization_status(), ZeroizationStatus::NotPerformed);
        assert_eq!(module.zeroize(), Ok(ZeroizationStatus::Succeeded));
        assert_eq!(module.zeroization_status(), ZeroizationStatus::Succeeded);
        assert_eq!(module.state(), ModuleState::Zeroized);
        assert!(matches!(
            module.operational(),
            Err(ProviderError::NotOperational {
                state: ModuleState::Zeroized
            })
        ));
        assert_eq!(
            module.initialize(),
            Err(ProviderError::InvalidTransition {
                state: ModuleState::Zeroized
            })
        );
        assert_eq!(module.zeroize(), Ok(ZeroizationStatus::Succeeded));
        assert_eq!(zeroize_observation.get(), ZeroizeObservation::Once);
    }

    #[test]
    fn successful_cleanup_never_recovers_a_latched_error() {
        let requested = test_suite("test-suite");
        let mut provider = FakeProvider::accepting();
        provider.self_test_failure = Some((
            SelfTestPhase::IntegrityPrimitiveCast,
            ProviderError::SelfTestFailed,
        ));
        let mut module = Module::new(provider, requested);
        let _ = module.initialize();

        assert_eq!(module.zeroization_status(), ZeroizationStatus::Succeeded);
        assert_eq!(module.zeroize(), Ok(ZeroizationStatus::Succeeded));
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

    #[test]
    fn drop_attempts_cleanup_when_explicit_zeroization_did_not_run() {
        let provider = FakeProvider::accepting();
        let zeroize_observation = provider.zeroize_observation();
        {
            let _module = Module::new(provider, test_suite("test-suite"));
        }
        assert_eq!(zeroize_observation.get(), ZeroizeObservation::Once);
    }

    #[test]
    fn completed_status_is_bound_to_truthful_local_metadata() {
        let requested = test_suite("test-suite");
        let mut module = Module::new(FakeProvider::accepting(), requested);
        module.initialize().expect("initialization");
        let mut operational = module.operational().expect("operational capability");

        let completed = operational.status().expect("status service");
        let (status, indicator) = completed.into_parts();

        assert_eq!(status.state(), ModuleState::Operational);
        assert_eq!(indicator.service(), ServiceId::MODULE_STATUS);
        assert_eq!(indicator.suite(), requested);
        assert_eq!(
            indicator.profile_status(),
            ServiceProfileStatus::AdministrativeCompleted
        );
        assert_eq!(
            indicator.cmvp_validation(),
            CmvpValidationStatus::NotValidated
        );
        assert_eq!(indicator.cmvp_certificate(), None);
    }

    #[test]
    fn rejected_service_releases_no_result_and_keeps_module_operational() {
        let mut module = Module::new(FakeProvider::accepting(), test_suite("test-suite"));
        module.initialize().expect("initialization");
        let mut operational = module.operational().expect("operational capability");

        let result = operational.complete_service::<String>(
            test_service("test-service"),
            ServiceProfileStatus::RestrictedProfileCompleted,
            ServiceCompletion::Rejected,
        );

        assert!(matches!(result, Err(ProviderError::ServiceFailed)));
        assert_eq!(operational.module.state(), ModuleState::Operational);
    }

    #[test]
    fn fatal_service_latches_cleans_and_stale_capability_refuses_output() {
        let provider = FakeProvider::accepting();
        let zeroize_observation = provider.zeroize_observation();
        let mut module = Module::new(provider, test_suite("test-suite"));
        module.initialize().expect("initialization");
        let mut operational = module.operational().expect("operational capability");
        let service = test_service("test-service");

        let failed = operational.complete_service::<String>(
            service,
            ServiceProfileStatus::RestrictedProfileCompleted,
            ServiceCompletion::Fatal,
        );
        assert!(matches!(failed, Err(ProviderError::ServiceFailed)));
        assert_eq!(operational.module.state(), ModuleState::Error);
        assert_eq!(zeroize_observation.get(), ZeroizeObservation::Once);

        let refused = operational.complete_service(
            service,
            ServiceProfileStatus::RestrictedProfileCompleted,
            ServiceCompletion::Completed(String::from("must-not-release")),
        );
        assert!(matches!(
            refused,
            Err(ProviderError::NotOperational {
                state: ModuleState::Error
            })
        ));
    }

    #[test]
    fn successful_restricted_service_is_result_bound_and_not_validated() {
        let requested = test_suite("test-suite");
        let mut module = Module::new(FakeProvider::accepting(), requested);
        module.initialize().expect("initialization");
        let mut operational = module.operational().expect("operational capability");

        let completed = operational
            .complete_service(
                test_service("test-service"),
                ServiceProfileStatus::RestrictedProfileCompleted,
                ServiceCompletion::Completed(String::from("staged-output")),
            )
            .expect("completed service");
        let (output, indicator) = completed.into_parts();

        assert_eq!(output, "staged-output");
        assert_eq!(
            indicator.profile_status(),
            ServiceProfileStatus::RestrictedProfileCompleted
        );
        assert_eq!(
            indicator.cmvp_validation(),
            CmvpValidationStatus::NotValidated
        );
        assert_eq!(indicator.cmvp_certificate(), None);
    }
}
