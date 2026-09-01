# Non-certified v4 engineering self-assessment

Status at 2026-09-01: implementation in progress; the restricted v4 profile is
not available. External certification is sponsor-deferred and unstarted. This
register separates project-owned engineering gates from work that would exist
only if an external sponsor funded and the owner authorized CST-laboratory and
CMVP validation.

FIPS 140-3 incorporates requirements from ISO/IEC 19790 and ISO/IEC 24759. The
repository does not contain a complete controlled requirement set or assertion
trace. Consequently this is a design-control self-assessment, not a claim of
meeting, conforming to, or complying with FIPS 140-3.

## Active engineering register

| Area | State | Current evidence | Next project-owned closure |
| --- | --- | --- | --- |
| Governance and profile freeze | Blocked | Scope and non-claims are recorded; the exact v4 suite and service contract are not frozen. | Record an architecture decision covering hybrid selection, algorithms, entropy, wire rules, services, error policy, and release criteria. |
| Candidate boundary | Partial | `anubis-v4-core` is isolated; v3, CLI, Vault, plugin, key store, filesystem, and plaintext publication stay outside. | Freeze dependency closure, build form, API/FFI boundary, concurrency owner, and supported operational environment. |
| Lifecycle and state model | Partial | Module-owned ordered self-test phases, operational capability, latched error, terminal zeroization, cleanup attempts, and read-only status exist. | Replace fake hooks with integrity and algorithm tests; define panic/abort and shared-library concurrency behavior. |
| Service and output gate | Partial | Only the module can construct completed-service metadata; every completed result says `NotValidated` and has no CMVP certificate. Rejected and fatal fake services return no result; fatal failure latches and cleans. | Route each reviewed concrete service through the gate; prove no alternate output path and preserve whole-file plaintext staging outside the core. |
| Cryptographic algorithms | Blocked | No production v4 provider or constructible suite exists. | Implement the frozen NIST-standard profile through one sealed provider, with no negotiation or fallback. |
| Integrity and self-tests | Blocked | The control-flow order and failure paths are tested with a fake provider. | Implement module integrity, known-answer/conditional tests, on-demand initiation, fault injection, and data-output inhibition. |
| SSP ownership and cleanup | Blocked | Provider cleanup is attempted after fatal transitions and on drop; status explicitly disclaims all-copy erasure. | Inventory every SSP, use non-cloneable/non-debug zeroizing owners, cover temporaries and early returns, and verify explicit and drop cleanup. |
| Entropy, DRBG, and nonces | Blocked | v4 exposes no random service. | Implement a private sealed entropy interface and serialized DRBG with reseed, fork/snapshot, counter reservation, and fail-before-output rules. |
| Wire format and publication | Partial | Exact version dispatch refuses unknown input and v4 writes cannot fall back to v3. Existing v3 decryption stages authenticated plaintext before publication. | Freeze byte-exact v4 grammar/transcript/records and retain the outer all-record, terminal, and signature-policy publication gate. |
| Local vector interface | Blocked | Existing v3 interoperability does not exercise v4. | Build a deterministic test-only adapter over the exact compiled provider; run authoritative vectors and an independent implementation. Label all results local, not CAVP. |
| Adversarial and formal evidence | Partial | v3 has adversarial suites and storage-guarded Kani lanes. v4 lifecycle transitions have exhaustive unit tests. | Add malformed-input, failure-injection, SSP, nonce, state, parser, and publication obligations as concrete v4 services land. |
| Reproducible build and lifecycle | Partial | Cargo.lock, locked builds, pinned actions, and bounded cleanup controls exist. | Freeze a supported build image/toolchain/linker/flags, unique core version, SBOM/provenance, installation controls, and change policy. |
| Independent review | Optional / sponsor-deferred | No third-party cryptographic audit has occurred. | Welcome independent or sponsor-funded design, source, and vector review; this does not block the engineering release, and the public audit claim stays false until a scoped report exists. |

## Current release blockers

- no normative production suite, provider, parser, writer, or v4 key type;
- no real integrity test or algorithm self-test expected answers;
- no AES-GCM, key wrap, DRBG, ML-KEM, or ML-DSA service in the v4 boundary;
- no SSP inventory or concrete zeroizing owners;
- no private entropy source, reseed policy, fork defense, or authoritative nonce
  counter;
- no frozen v4 transcript, AAD, record geometry, terminal rule, or signature
  policy;
- no deterministic local adapter or independent v4 vector implementation;
- no shared-library concurrency design or reproducible supported build/OE.

The existing v3 ChaCha20-Poly1305 format, direct `getrandom` use, and hybrid
construction are not silently relabeled as the restricted v4 profile.

## Evidence already retained

- exact no-fallback v3/v4 dispatch and permanent v3 compatibility;
- safe v3 plaintext publication boundaries;
- v4 lifecycle, terminal-zeroization, cleanup, stale-capability, and
  result-bound non-validation tests;
- adversarial, interoperability, desktop, plugin, and installation tests;
- committed dependency lock and pinned CI inputs;
- storage-guarded bounded Kani proofs with explicit non-claims;
- machine-readable and prose claim gates that keep certification and audit
  assertions false.

These reduce engineering risk. They are local implementation evidence, not a
CAVP certificate, CST-laboratory report, CMVP certificate, complete compliance
assessment, physical-memory zeroization proof, or third-party audit.

## Active critical path

- freeze the restricted v4 profile and service/API decision without changing
  v3;
- implement concrete SSP owners, entropy/DRBG, integrity, self-tests, and the
  fixed production provider behind the existing lifecycle and output gates;
- freeze the v4 byte format and independent model before enabling production
  parsing or writing;
- run authoritative local vectors, independent interoperability, failure
  injection, adversarial tests, and bounded formal lanes;
- freeze the supported build and operational environment, then retain compact
  revision/binary-bound evidence;
- ship v4 only as an explicit opt-in after every applicable release blocker is
  closed; preserve v3 reading and the v4 rollback path.

## Sponsor-deferred external validation gaps

The following are deliberately inactive because no sponsor commitment or owner
authorization is recorded:

| External item | Current truth | Required only if certification resumes |
| --- | --- | --- |
| Controlled complete requirements | No complete licensed ISO assertion trace is held in the repository. | Obtain authorized requirements access and build a complete applicability/assertion trace with the selected CST laboratory. |
| Algorithm validation | No ANUBIS-linked CAVP certificates are claimed. | Run Production ACVTS through an accredited laboratory for the exact implementation and OE. |
| Module testing and submission | No CSTL, TID, MIS, CMVP Security Policy, or independent module report exists. | Contract a laboratory, complete module testing and documents, and submit through the official process. |
| Certificate | No ANUBIS CMVP certificate is claimed. | Change to a reviewed certificate-aware schema only after the official listing names the exact module version and OE. |

The [sponsorship policy](SPONSORSHIP.md) defines the activation boundary. The
dormant [LAB-RFQ.md](LAB-RFQ.md) is a historical resumption aid, not an active
purchase request.

Official exact-name searches recorded for the current negative result:
[CMVP Active](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&Vendor=Anubis%20Quantum%20Cipher&CertificateStatus=Active&submit=Search),
[Historical](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&Vendor=Anubis%20Quantum%20Cipher&CertificateStatus=Historical&submit=Search),
[Revoked](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&Vendor=Anubis%20Quantum%20Cipher&CertificateStatus=Revoked&submit=Search), and
[CAVP implementation search](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-search?searchMode=implementation&vendor=Anubis%20Quantum%20Cipher&productType=-1&ipp=100&submit-btn=Search).
