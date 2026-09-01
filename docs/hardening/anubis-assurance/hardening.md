# Security Hardening Review: ANUBIS Assurance Boundary

## Evidence Basis

This portfolio is derived from the completed ANUBIS security scan at revision
`8e26122fec7a94afca425abffa2d2c146ce241de`, its post-scan remediation record,
and source inspection at starting revision
`f7f37f17cf4be68c49431df91f8d6c7a24d8a993`. The analysis is bound to scan
manifest SHA-256
`708fd251769ef4ac5ca86edd81b061092c0376c841aa0b0821bed282983639f1`.
Source drift is `present` because assurance work is already in progress beyond
that starting revision.

The scan's findings are useful here because they repeatedly show security
claims crossing ownership boundaries: parser rules diverged, publication
safety depended on API convention, attestations were bound to mutable paths,
secret erasure depended on dependency features, and reader/writer limits
drifted. The remediation report says those defects were fixed and tested; this
proposal does not reopen or claim to close them. It asks how we can make future
claims harder to overstate and future drift easier to detect.

The NIST boundary is equally important. FIPS 203 identifies ML-KEM-1024 as
security category 5, and FIPS 204 identifies ML-DSA-87 as category 5. That is a
post-quantum algorithm-strength category. FIPS 140-3 instead defines four
qualitative cryptographic-module security levels. CMVP validation requires an
accredited laboratory submission and validation-authority review; source code,
tests, and formal proofs do not create that certificate.

## Constraints

- Preserve the ability to decrypt and verify existing ANUBIS/v3 containers.
- Make future encryption changes additive and explicitly versioned; do not
  silently reinterpret the v3 version line.
- Keep the existing remediations active throughout migration.
- Describe ML-KEM-1024 and ML-DSA-87 as NIST security category 5 parameters,
  never as “FIPS level 5.”
- Do not use “FIPS validated,” “CMVP validated,” or equivalent language unless
  a certificate covers the exact module, version, operational environment, and
  approved mode being described.
- No independent-audit or external-validation sponsor is currently committed.
  External sponsorship is welcome under `docs/cmvp/SPONSORSHIP.md`; until scoped
  evidence exists, formal work must remain explicit about non-claims and cannot
  replace CMVP's independent laboratory process.
- Proof generation must be storage-bounded. Solver scratch, generated vectors,
  build trees, and expanded traces are disposable; retained evidence is compact,
  quota-enforced, and revision-bound.
- No measured latency, throughput, memory, migration-volume, or proof-storage
  budget was supplied. Tradeoffs below are source-derived or hypothetical and
  include measurement plans.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| Make cryptographic and formal-assurance claims versioned, machine-checkable, and non-overstated | Safe publication, content-bound attestations, hybrid contribution, zeroization, strict parser, and reader/writer invariant findings; FIPS 203, FIPS 204, FIPS 140-3, CAVP, and CMVP | **Option 1:** v3 evidence-only; **Option 2:** additive isolated v4 restricted-profile candidate; **Option 3:** in-place replacement | Select Option 2 while retaining Option 1's claim-ledger discipline for v3 | [Truthful machine-verifiable assurance](proposals/truthful-machine-verifiable-assurance.md) |

## Recommendation Summary

I recommend the additive v4 candidate boundary under the current constraints.
It gives us a clean place to use a fixed suite selected from current NIST
approved functions, define one typed parser and publication state machine, and
attach formal evidence to an immutable wire version. Existing v3 files remain
readable through an isolated compatibility reader, so stronger forward design
does not require destructive migration or a misleading reinterpretation of v3.

Option 1 is still valuable and should be implemented as part of every path: a
claim ledger, bounded Kani runs, differential vectors, and revision-bound
evidence improve honesty and regression detection now. It does not, by itself,
turn the current ChaCha20-Poly1305 v3 suite into an approved-mode candidate or
make the product CMVP validated. Option 3 has a real maintenance advantage—one
engine and no long-lived compatibility branch—but its wire ambiguity, forced
migration, and rollback risk are disproportionate for encrypted user data.

The selected design is deliberately called a **restricted-profile candidate**,
not an approved or validated module. Even a complete formal proof portfolio
cannot issue CAVP or CMVP certificates. The owner will not purchase the external
validation process, while outside sponsors may fund it separately. The current
claim ceiling is that the exact version uses specified NIST algorithms and has
machine-checked stated properties—not that it is FIPS 140-3 validated. Funding
alone does not raise that ceiling.

## Next Decisions

- Freeze the v4 threat model, algorithm suite, hybrid-combiner rules, and wire
  grammar before production implementation.
- Decide whether the candidate retains X25519 as an explicitly non-NIST
  auxiliary contribution or selects an ML-KEM-only profile; freeze one choice
  and never describe either as an approved mode.
- Define the exact proof obligations and assumptions for parser totality,
  nonce uniqueness, transcript binding, fail-closed publication, downgrade
  resistance, and secret lifetime.
- Set operator-controlled proof artifact and free-space quotas in CI and local
  tooling. Retain compact evidence, not solver workspaces.
- Decide whether v4 encryption is initially opt-in or becomes the default only
  after interoperability, migration, and rollback gates pass.
- If formal CMVP validation ever becomes a requirement, engage an accredited
  CST laboratory; do not change claim language in anticipation of a future
  certificate.
