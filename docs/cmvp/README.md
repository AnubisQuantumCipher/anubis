# ANUBIS FIPS 140-3 validation program

This directory is the working handoff package for a real FIPS 140-3 validation,
not a marketing roadmap. The current machine-readable truth is
[program-status.json](program-status.json): it records no ANUBIS-linked CAVP
certificate, no CMVP certificate, no approved mode, and no validation claim.

## Selected target

The initial target is a new Security Level 1 software cryptographic module for
ANUBIS/v4. The target boundary is the versioned binary built from
anubis-v4-core. The CLI, ANUBIS Vault desktop process, Omarchy plugin, v3
compatibility implementation, key-store integration, and filesystem
publication logic remain outside that boundary.

The proposed first-certification profile uses ML-KEM-1024 without X25519,
subject to the CST-laboratory architecture checkpoint. This is the
lowest-complexity path under the current ML-KEM guidance. Existing ANUBIS/v3
hybrid encryption remains readable and unchanged outside the approved module.
A future fixed X25519 plus ML-KEM hybrid may be considered only after written
CST-laboratory agreement on the current IG D.S constraints and its additional
test scope.

No production v4 suite identifier, parser, writer, or cryptographic service is
enabled yet. That is a deliberate architecture gate: the selected laboratory
must review the boundary, algorithm profile, entropy strategy, operational
environment, and wire protocol before those decisions become release
compatibility commitments.

## Work that can be completed in the repository

- isolate and version the software-module boundary;
- implement fail-closed pre-operational testing, operational and error states,
  data-output inhibition, on-demand testing, zeroization reporting, and
  per-service approved-status indicators;
- implement the lab-agreed approved algorithms and a deterministic ACVP adapter
  over the exact compiled implementation;
- freeze one narrow initial operational environment and reproducible build;
- write the roles, services, interfaces, SSP, self-test, lifecycle, finite-state
  model, and operator-guidance material;
- generate the current MIS and Security Policy package with the lab;
- retain bounded, revision-bound evidence while deleting disposable build,
  solver, and ACVTS working trees.

## Work that only external authorities can complete

The vendor must execute a commercial statement of work with an
NVLAP-accredited Cryptographic and Security Testing laboratory. The laboratory
must independently test the exact module, use Production ACVTS for algorithm
validation, assign the test identifier, prepare and submit the package, and
resolve CMVP coordination. NIST and CCCS issue and post the certificate after
their review and fee requirements are satisfied.

Formal proofs, local vectors, Demo ACVTS sessions, dependency certificates, and
provider self-reports cannot replace those actions.

## Release and claim gates

- v3 stays available and explicitly non-approved.
- v4 cryptographic code stays disabled until the laboratory architecture
  checkpoint is closed.
- an approved-only runtime mode stays unavailable until every callable
  cryptographic service is classified and its indicator is implemented.
- FIPS 140-3 validation stays false until the exact module version and tested
  operational environment appear on an official CMVP certificate.
- scripts/check-cmvp-status.py rejects any attempt to flip the current
  pre-certificate status into a validation claim, pins the current engine
  claim fields, scans common positive prose, and validates the built CLI's
  actual status JSON in CI.

The lexical source/prose checks are defense in depth against accidental drift,
not protection from a malicious repository administrator. The GitHub branch
rules should require the fixed-name “CMVP certificate claim gate” check,
runtime engine checks, and independent review for claim-surface changes. Even
those controls cannot create a validation; the official CMVP certificate
remains the authority.

## Package map

| File | Purpose |
| --- | --- |
| [program-status.json](program-status.json) | Machine-readable pre-certificate state and claim gate input |
| [SOURCES.md](SOURCES.md) | Current official-source snapshot and digests |
| [READINESS.md](READINESS.md) | Requirement-to-evidence gap register |
| [MODULE-BOUNDARY.md](MODULE-BOUNDARY.md) | Candidate software boundary, ports, services, and OEs |
| [ALGORITHM-PROFILE.md](ALGORITHM-PROFILE.md) | Proposed first-certification algorithm and ACVP scope |
| [LAB-RFQ.md](LAB-RFQ.md) | Procurement-ready CST-laboratory request and intake checklist |
