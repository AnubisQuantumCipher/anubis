# Full-submission readiness register

Status at 2026-09-01: not ready for a FIPS 140-3 Full Submission. “Blocked”
below means required work is absent or not frozen; it does not mean the
validation program should stop.

FIPS 140-3 incorporates ISO/IEC 19790 and ISO/IEC 24759. Their applicable
requirements and test assertions must be obtained and traced in the controlled
lab project. NIST's public SP 800-140 supplements and Implementation Guidance
modify that baseline but do not replace the complete ISO requirements.

| Area | State | Repository evidence and gap | Closure |
| --- | --- | --- | --- |
| Governance and licensed requirements | Blocked | No selected CSTL, compliance owner, controlled ISO copies, or assertion trace exists. | Vendor procures authorized access, names an owner, and lab confirms applicability. |
| Module boundary and identity | Partial | anubis-v4-core is isolated and inert; MODULE-BOUNDARY.md proposes a shared-library boundary. Exact module version, binary, dependencies, compiler, flags, and digest are unfrozen. | Close at the lab architecture checkpoint and freeze one reproducible IUT. |
| Approved algorithms | Blocked | v3 requires ChaCha20-Poly1305 and has no approved mode. v4 implements no cryptography. | Preserve v3 outside; implement only the lab-approved v4 profile and obtain Production ACVP evidence. |
| Interfaces and data flow | Draft | Candidate data, control, status, and power interfaces are listed but no production API or SSP-crossing diagram exists. | Freeze every API, port classification, SSP crossing, and output-inhibition rule. |
| Roles, services, authentication | Blocked | CLI commands are not a FIPS roles/services matrix. | Assign every approved, non-approved, administrative, status, test, and zeroization service to User/Crypto Officer roles and specify access rights. |
| Approved-service indicator | Blocked | Current false validation metadata is truthful but is not a per-service indicator. | Return an externally accessible, unambiguous result for each completed service under IG 2.4.C. |
| Finite-state model and errors | Partial | v4 now has pre-operational, self-testing, operational, and latched error states plus an opaque operational capability. There is no crypto/output gate or concurrency model. | Bind every service/output path to the operational capability; complete transition table, recovery rules, and failure injection. |
| Software integrity/loading | Blocked | No approved runtime integrity check covers the candidate binary. | Lab-select integrity mechanism and authenticated extent; order its CAST before integrity verification; classify replacement/loading. |
| Self-tests | Blocked | Unit, adversarial, interoperability, and Kani tests are developer evidence. The provider hook has no real expected answers. | Implement all applicable CASTs, PCTs, integrity, implicit-rejection, on-demand, and failure paths in the module. |
| SSP inventory and zeroization | Blocked | v3 partially zeroizes fixed secret types but also carries identity text in ordinary Strings. No v4 SSP table or real zeroization exists. | Inventory every seed/key/secret/DRBG state and its lifecycle; eliminate ordinary secret carriers in-boundary; test explicit zeroization. |
| Entropy and RBG | Blocked | v3 calls getrandom directly. There is no approved DRBG, SP 800-90B/90C design, entropy estimate, or ESV evidence. | Select IG 9.3.A architecture with the lab; implement approved DRBG and direct entropy interface; obtain required ESV/RBG evidence. |
| Operational environment | Blocked | CI uses moving Ubuntu and Arch images; Omarchy/Arch is rolling. | Freeze one initial OS/kernel/processor/loader/runtime/toolchain path that the lab can reproduce. |
| Physical/non-invasive areas | Unresolved | No TOEPP physical mapping; no non-invasive or other-attack mitigation claim. | Lab determines applicability and section levels; document the production-grade platform without inventing mitigations. |
| Lifecycle/build controls | Partial | Cargo.lock, locked builds, checksummed CI inputs, and pinned actions are positive. Package version reuse, differing Rust metadata/CI versions, floating stable packaging, and moving images remain. | Assign unique module version; freeze build image/compiler/linker/flags/SBOM/provenance/install/CVE/change controls. |
| Security Policy and MIS | Blocked | Product SECURITY.md is a threat model, not the CMVP non-proprietary policy. No MIS exists. | Complete the current MIS schema and Security Policy template with the CSTL after architecture freeze. |
| Algorithm validation | External | Official exact-vendor/name searches returned no ANUBIS CAVP validation as of the status date. | Build Demo adapter locally; CSTL runs Production ACVTS and obtains certificates for the exact IUT/OE. |
| Independent module testing | External | No TID, CSTL report, or independent source review exists. | Contract an accredited CSTL; deliver source, module, OE, documentation, and fault-injection build under its test plan. |
| Submission and certificate | External | Official exact-vendor searches returned no active, historical, or revoked ANUBIS certificate. No displayed MIP/IUT entry was found; those lists can omit confidential activity. | CSTL submits through Web Cryptik; vendor funds applicable fees; CMVP alone issues/posts the certificate. |

## Current code blockers

- v3 ChaCha20-Poly1305 cannot become the approved encryption service merely by
  changing a status flag.
- direct getrandom output is not an approved DRBG service.
- the v3 RFC 5869 hybrid profile is not a frozen SP 800-56C hybrid service.
- the exact Rust algorithm implementations and operational environment have no
  ANUBIS-linked CAVP certificates.
- v4 has no AES-GCM, AES-KW, DRBG, integrity, cryptographic self-test, service
  indicator, SSP owner, parser, writer, or ACVP adapter.
- distinct SHAKE wrappers and CPU-feature-dependent code paths must be
  consolidated or independently enumerated/tested.
- generic Omarchy/Arch is not a frozen operational environment.
- release identity is ambiguous while post-release source still reports the
  released package version and packaging follows a floating stable toolchain.

## Evidence ANUBIS already has

- explicit no-fallback v3/v4 version dispatch and v3 compatibility;
- safe plaintext publication boundaries;
- adversarial, interoperability, desktop, plugin, and installation tests;
- committed dependency lock and pinned CI inputs;
- storage-guarded bounded Kani proofs with explicit non-claims;
- truthful runtime/documentation status that does not confuse Category 5
  parameter sets with FIPS 140-3 Security Levels.

These reduce engineering risk. Their consequence ceiling remains local
implementation evidence; none is a CSTL report, CAVP certificate, or CMVP
certificate.

## Critical path

1. Obtain controlled access to the incorporated ISO requirements and execute a
   CSTL NDA/SOW for a pre-assessment plus full validation.
2. Close the boundary, Level 1 target, Scenario 1 profile, entropy route,
   signature scope, integrity mechanism, operational environment, and ACVP
   adapter strategy in writing.
3. Implement the frozen module and ACVP adapter without changing v3.
4. Run local Demo ACVTS, self-test fault injection, security tests, and bounded
   formal lanes; retain compact revision/binary-bound evidence.
5. Freeze the candidate binary/build/OE and complete the current MIS and
   Security Policy.
6. CSTL runs Production ACVTS/entropy/module testing, assigns the TID, and
   submits the Full Submission.
7. Resolve CMVP comments and fees through the CSTL.
8. Enable a certificate-aware status schema only after the official
   certificate names the exact module version and operational environment.

Official exact-name searches used for the current negative result:
[CMVP Active](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&Vendor=Anubis%20Quantum%20Cipher&CertificateStatus=Active&submit=Search),
[Historical](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&Vendor=Anubis%20Quantum%20Cipher&CertificateStatus=Historical&submit=Search),
[Revoked](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&Vendor=Anubis%20Quantum%20Cipher&CertificateStatus=Revoked&submit=Search), and
[CAVP implementation search](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-search?searchMode=implementation&vendor=Anubis%20Quantum%20Cipher&productType=-1&ipp=100&submit-btn=Search).
