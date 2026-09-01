# ANUBIS v4 non-certified engineering profile

This directory is the controlled self-assessment for ANUBIS/v4. The owner has
chosen to continue engineering without purchasing CST-laboratory or CMVP
validation. The machine-readable truth is
[program-status.json](program-status.json): certification is sponsor-deferred
and unstarted, no sponsor or laboratory commitment is recorded, the restricted
profile is not available, and no FIPS 140-3 compliance, approved-mode, CAVP,
CMVP, certificate, or independent-audit claim is made.

The supportable description is narrow:

> ANUBIS/v4 is a non-validated restricted cryptographic profile using
> NIST-standardized algorithms. It implements selected software-module
> controls drawn from FIPS 140-3 and public CMVP guidance. Repository tests and
> proofs are project-maintained engineering evidence, not external validation.

## Engineering target

The candidate boundary is the future versioned software core built from
`anubis-v4-core`. The CLI, ANUBIS Vault desktop process, Omarchy plugin, v3
compatibility implementation, key-store integration, and filesystem
publication logic remain outside that boundary.

No production v4 suite identifier, parser, writer, provider, or cryptographic
service is enabled. The next gate is a recorded project architecture decision
that freezes the restricted suite and service contract before release-format
compatibility commitments. That decision must resolve the fixed hybrid versus
ML-KEM-only profile, entropy and DRBG design, operational environment, wire
protocol, SSP lifecycle, and local vector interface.

## Controls already implemented

The inert v4 core now owns:

- exact v3/v4 dispatch with no fallback and no v4 writer permit;
- module-owned ordered self-test phases and an observable test summary;
- pre-operational, self-testing, operational, latched-error, and terminally
  zeroized states;
- best-effort provider cleanup after self-test or fatal service failure and on
  module drop;
- an opaque operational capability that rechecks state before output;
- a result-bound, non-forgeable service classification that always reports
  `NotValidated` and no CMVP certificate.

These are lifecycle and output-control scaffolding. The self-test hooks use a
fake provider, zeroization status is not physical-memory proof, and there is no
production cryptography.

## Active project-owned gates

- freeze the normative restricted suite, service API, and byte-exact v4 format;
- implement one sealed production provider with no negotiation or fallback;
- implement integrity verification, cryptographic self-tests, on-demand tests,
  failure injection, output inhibition, and the terminal error path;
- implement non-cloneable SSP owners, full cleanup paths, a private entropy
  boundary, and a serialized DRBG/nonce lifecycle;
- create deterministic local vector interfaces and independent interoperability
  tests over the exact compiled implementation;
- preserve full-file authenticated plaintext staging outside the core;
- freeze one reproducible initial build and supported operational environment;
- run adversarial tests and storage-bounded proof lanes before opt-in release;
- retain compact revision-bound results while deleting disposable compiler,
  solver, and vector-session trees.

Passing those gates will strengthen local evidence. It will not produce an
algorithm certificate or a validated cryptographic module.

## Claim gates

- v3 remains available and explicitly non-validated.
- v4 remains unavailable until its production implementation and release gates
  pass; scaffolding alone cannot enable it.
- neither v3 nor v4 exposes an approved mode.
- local or ACVP-compatible vectors must never be called CAVP validation.
- FIPS 140-3 compliance and validation remain false.
- `scripts/check-cmvp-status.py` validates the exact non-certified status schema,
  keeps runtime v3 claims false, rejects unsupported positive prose, and runs in
  the protected fixed-name **CMVP certificate claim gate** CI job.

The lexical checks are defense in depth against accidental drift, not a defense
against a malicious repository administrator. Protected-branch review and CI
also cannot create external validation.

## Sponsor-deferred optional validation

External people or organizations may fund the official validation or independent
audit workstream under [SPONSORSHIP.md](SPONSORSHIP.md). Current engineering
does not wait on that path. A sponsorship commitment alone does not authorize a
claim, select a laboratory, approve spend, or prove an algorithm or module. If
the external workstream is activated, refresh every incorporated requirement
and program document, retain controlled copies where licensing requires them,
contract an accredited CST laboratory under explicit authority, and use
Production ACVTS and CMVP submission processes for the exact module and
operational environment. The dormant [laboratory RFQ](LAB-RFQ.md) is retained
only as a resumption reference; it is not approved for distribution or spend.

## Package map

| File | Purpose |
| --- | --- |
| [program-status.json](program-status.json) | Machine-readable non-certified state and claim-gate input |
| [SOURCES.md](SOURCES.md) | Official-source snapshot and bounded refresh policy |
| [READINESS.md](READINESS.md) | Active engineering register and deferred external gaps |
| [MODULE-BOUNDARY.md](MODULE-BOUNDARY.md) | Candidate software boundary, ports, services, and OEs |
| [ALGORITHM-PROFILE.md](ALGORITHM-PROFILE.md) | Restricted-profile design baseline and local vector scope |
| [SPONSORSHIP.md](SPONSORSHIP.md) | Funding boundary and activation rules for optional validation or audit |
| [LAB-RFQ.md](LAB-RFQ.md) | Dormant certification-resumption reference; no authority to spend |
