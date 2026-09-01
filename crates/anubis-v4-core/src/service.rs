//! Result-bound classification for future v4 services.
//!
//! This module does not expose a production cryptographic service. It defines
//! the output boundary that future services must use: only the module-owned
//! lifecycle gate can construct a completed result or its classification.

use crate::suite::SuiteId;
use core::fmt;

/// CMVP status attached to every locally completed service.
///
/// This crate has no certificate-aware variant. Adding one requires a reviewed
/// API and claim-gate change backed by an official certificate for the exact
/// module version and operational environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CmvpValidationStatus {
    NotValidated,
}

/// Local classification of a completed service.
///
/// `RestrictedProfileCompleted` is project-maintained implementation metadata.
/// It does not mean that the service or module is approved, CAVP validated,
/// FIPS 140-3 compliant, or CMVP validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ServiceProfileStatus {
    AdministrativeCompleted,
    RestrictedProfileCompleted,
}

/// Opaque identity for one exact service.
///
/// No public constructor exists, so callers and providers cannot invent a
/// service identity or use one to manufacture assurance metadata.
///
/// ```compile_fail
/// use anubis_v4_core::service::ServiceId;
/// let _ = ServiceId::new("unreviewed-service");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ServiceId {
    canonical: &'static str,
    _private: (),
}

impl ServiceId {
    pub(crate) const MODULE_STATUS: Self = Self::internal("module-status");

    const fn internal(canonical: &'static str) -> Self {
        Self {
            canonical,
            _private: (),
        }
    }

    /// Return the complete canonical service identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.canonical
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.canonical)
    }
}

/// Module-owned classification bound to one successful service result.
///
/// The private fields deliberately prevent providers and callers from
/// constructing or altering this value.
///
/// ```compile_fail
/// use anubis_v4_core::service::ServiceIndicator;
/// let _ = ServiceIndicator {
///     service: todo!(),
///     suite: todo!(),
///     profile_status: todo!(),
///     cmvp_validation: todo!(),
/// };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceIndicator {
    service: ServiceId,
    suite: SuiteId,
    profile_status: ServiceProfileStatus,
    cmvp_validation: CmvpValidationStatus,
}

impl ServiceIndicator {
    pub(crate) const fn local(
        service: ServiceId,
        suite: SuiteId,
        profile_status: ServiceProfileStatus,
    ) -> Self {
        Self {
            service,
            suite,
            profile_status,
            cmvp_validation: CmvpValidationStatus::NotValidated,
        }
    }

    #[must_use]
    pub const fn service(&self) -> ServiceId {
        self.service
    }

    #[must_use]
    pub const fn suite(&self) -> SuiteId {
        self.suite
    }

    #[must_use]
    pub const fn profile_status(&self) -> ServiceProfileStatus {
        self.profile_status
    }

    #[must_use]
    pub const fn cmvp_validation(&self) -> CmvpValidationStatus {
        self.cmvp_validation
    }

    /// No completed service in this crate can carry a CMVP certificate.
    #[must_use]
    pub const fn cmvp_certificate(&self) -> Option<&'static str> {
        None
    }
}

/// Owned output released together with its unforgeable local classification.
///
/// This wrapper has no public constructor. Errors never receive one.
///
/// ```compile_fail
/// use anubis_v4_core::service::CompletedService;
/// let _ = CompletedService {
///     output: vec!["unreviewed"],
///     indicator: todo!(),
/// };
/// ```
#[must_use = "completed service output and its classification must be handled"]
pub struct CompletedService<T> {
    output: T,
    indicator: ServiceIndicator,
}

impl<T> CompletedService<T> {
    pub(crate) const fn local(output: T, indicator: ServiceIndicator) -> Self {
        Self { output, indicator }
    }

    /// Consume the result and return its output and inseparable classification.
    pub fn into_parts(self) -> (T, ServiceIndicator) {
        (self.output, self.indicator)
    }
}

/// Private handoff from an in-boundary implementation to the output gate.
///
/// The currently inert crate exercises all branches with test services. Future
/// concrete services must stage owned output before selecting `Completed`.
#[allow(dead_code)]
pub(crate) enum ServiceCompletion<T> {
    Completed(T),
    Rejected,
    Fatal,
}

#[cfg(test)]
pub(crate) const fn test_service(canonical: &'static str) -> ServiceId {
    ServiceId::internal(canonical)
}
