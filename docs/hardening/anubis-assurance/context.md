# ANUBIS Assurance Hardening Context

This file records local working context for the derived hardening analysis. It
is not a certification record, a proof result, or part of the sealed source
scan.

## Source Identity

| Field | Value |
| --- | --- |
| Repository | `AnubisQuantumCipher/anubis` |
| Source scan artifact | Local sealed artifact; intentionally not committed |
| Source scan ID | `fed81f96-bb3e-403e-9fce-b95ca5687c5f` |
| Source scan revision | `8e26122fec7a94afca425abffa2d2c146ce241de` |
| Source scan manifest SHA-256 | `708fd251769ef4ac5ca86edd81b061092c0376c841aa0b0821bed282983639f1` |
| Implementation starting revision | `f7f37f17cf4be68c49431df91f8d6c7a24d8a993` |
| Source drift | `present` |

The manifest digest was re-read from the local artifact and matched the value
above. The working tree already contains uncommitted assurance work beyond the
implementation starting revision. This portfolio therefore uses the sealed
scan as historical evidence, the starting revision as the post-remediation
source baseline, and does not silently describe current uncommitted files as
part of either immutable snapshot.

## Evidence Inventory

| Evidence | Reader-facing title | Kind | Integrity or location | Relevance |
| --- | --- | --- | --- | --- |
| `SCAN-MANIFEST` | Completed ANUBIS security scan manifest | scan manifest | SHA-256 `708fd251769ef4ac5ca86edd81b061092c0376c841aa0b0821bed282983639f1` | Binds the threat model, scope, limitations, and source revision. |
| `SCAN-FINDINGS` | Validated ANUBIS findings registry | scan findings | SHA-256 `7d1ee38f92fda1fb8726b9a170b6ff81ee5a2fa2aae19e88dc8e3ac3004b5543` | Records the repeated parser, state, publication, secret-lifetime, and compatibility failures that motivate a stronger assurance boundary. |
| `SCAN-COVERAGE` | ANUBIS scan coverage record | scan coverage | SHA-256 `e904802cc5af7f8e72891f53f8c4ddac35dab622051c2f0b22592d298fe4eee4` | Limits the source-backed conclusions to the reviewed surfaces. |
| `SCAN-REPORT` | Human-readable ANUBIS security review | scan report | SHA-256 `b8d4805168463fd546a5d6b418c5fe6ad84b154754e7172a17a0e3ca03c2f730` | Summarizes the sealed baseline; it is not modified by this analysis. |
| `FIX-REPORT` | Post-scan remediation report | remediation evidence | SHA-256 `dc9b5fab7e5ff8aac897b36e979026ff73b0ff89b2e9bdc4b9eb48f3d406d51d` | Reports that the baseline findings were fixed and tested before the starting revision; it explicitly remains a non-audit result. |
| `SRC-FORMAT-V3` | ANUBIS/v3 fixed cryptographic suite | source document | `docs/FORMAT.md` at `f7f37f17cf4be68c49431df91f8d6c7a24d8a993` | Specifies X25519 plus ML-KEM-1024, ML-DSA-87, ChaCha20-Poly1305, HKDF-SHA-512, and HMAC-SHA-512. |
| `SRC-SECURITY` | ANUBIS security policy and non-claims | source document | `docs/SECURITY.md` at `f7f37f17cf4be68c49431df91f8d6c7a24d8a993` | States that ANUBIS is unaudited and that composition code remains the project-owned risk surface. |
| `SRC-PROOFS` | Existing bounded model-checking harnesses | source | `crates/anubis-crypto/src/{armor,format,stream}.rs` at `f7f37f17cf4be68c49431df91f8d6c7a24d8a993` | Shows useful Kani harnesses for parser panic freedom, length arithmetic, payload geometry, and nonce construction; the starting revision's CI does not execute them. |
| `NIST-FIPS-203` | FIPS 203 ML-KEM standard | authoritative document | [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | Identifies ML-KEM-1024 as security category 5. |
| `NIST-FIPS-204` | FIPS 204 ML-DSA standard | authoritative document | [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | Identifies ML-DSA-87 as security category 5. |
| `NIST-FIPS-140-3` | FIPS 140-3 cryptographic-module requirements | authoritative document | [NIST FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) | Defines four qualitative module security levels and broader module requirements; it does not define a fifth module level. |
| `NIST-CMVP` | Cryptographic Module Validation Program | authoritative program page | [NIST CMVP](https://csrc.nist.gov/Projects/cryptographic-module-validation-program) | Establishes that an accredited CST laboratory tests a module and CMVP reviews and validates the submission. |
| `NIST-CAVP` | Cryptographic Algorithm Validation Program | authoritative program page | [NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program) | Establishes that algorithm validation is a prerequisite, but not a substitute, for module validation. |
| `NIST-APPROVED-FUNCTIONS` | SP 800-140C approved security functions | authoritative program page | [NIST SP 800-140C supplemental information](https://csrc.nist.gov/projects/cryptographic-module-validation-program/sp-800-140-series-supplemental-information/sp800-140c) | Supplies the current approved-function boundary that a candidate suite must track. |

## Canonical Finding Registry

These titles make every canonical identifier used in the proposal locally
understandable. The sealed `findings.json` remains authoritative for the full
writeups.

| Finding ID | Title | Architectural signal |
| --- | --- | --- |
| `csf_61ce296e94ea8662ff9ffb8b` | The public decrypt API writes plaintext before sender-signature verification | Publication safety was a caller convention rather than an owned state transition. |
| `csf_eae655e2268c2ff7817b9e6e` | Desktop subprocess collectors reuse stale security verdicts | Security state could outlive the operation that established it. |
| `csf_76db625f533baa8783a78614` | Vault authentication attestations are bound only to filenames | Trust evidence was bound to a mutable path rather than immutable content and policy. |
| `csf_588ce26089cdbc4ef10bd7d0` | Global JSON mode corrupts payloads written to stdout | Payload and control protocols shared one channel without a typed boundary. |
| `csf_56b1cb1233c54e1d461d5460` | Cancelling an inspection can bind the old result to the new path | Operation generation and target identity were mutable global state. |
| `csf_0d5b21a23ecc3a280a0b5da0` | Key strings use Bech32m while the format requires Bech32 | Implementation and normative format evolved without an explicit migration boundary. |
| `csf_ccbaf15b9000aaed3501ad63` | Degenerate X25519 keys silently remove the classical hybrid contribution | A claimed hybrid invariant lacked enforcement at both contribution boundaries. |
| `csf_0f08d88ff87f4bec498a3cba` | Unforced output can overwrite a file created after the no-clobber check | Publication policy and the final filesystem operation were separated. |
| `csf_58df7fb1d2a76abf92e202fc` | Selected I/O failures leave named plaintext or key temporaries | Sensitive temporary lifetime depended on scattered cleanup calls. |
| `csf_5cc259216333671f3a069613` | Expanded post-quantum secret keys are not zeroized on drop | Secret-destruction claims depended on dependency feature configuration. |
| `csf_9d9df46d6643ed55c167c261` | Rust accepts signed structures rejected by the normative verifier | Structural validation was duplicated across readers and drifted. |
| `csf_e1639c7a9aa4324d05ea5051` | Encryption can create containers its own reader refuses | Reader and writer constraints did not share a single invariant owner. |
| `csf_92c997b27c890dde4bd90842` | Binary inspect buffers an unknown-length stream without a bound | A streaming claim did not hold on an unbounded input path. |

## Evidence Boundary

- **Observed:** the v3 specification fixes its suite to ChaCha20-Poly1305,
  hybrid X25519 plus ML-KEM-1024, and optional ML-DSA-87; the scan found
  cross-boundary defects; the remediation report says those defects were fixed
  at the implementation starting revision; Kani harnesses exist in source.
- **Inferred:** without one versioned algorithm boundary and a machine-readable
  claim-to-evidence ledger, future changes can allow documentation, runtime
  behavior, formal harnesses, and operator-facing attestations to drift again.
- **Proposed:** preserve v3 decryption, introduce an isolated additive v4
  approved-algorithm-candidate core, and make every assurance claim conditional
  on revision-bound evidence.

Formal verification can establish only the modeled properties, assumptions,
bounds, and toolchain recorded in an evidence bundle. It cannot issue a CAVP
algorithm certificate, a CMVP module certificate, or replace the independent
laboratory and validation-authority steps required by those programs.

## Storage Constraint

The operator explicitly requires proof work not to exhaust local storage. The
selected design therefore treats solver scratch, Cargo targets, generated
vectors, and expanded traces as disposable workspace. Only a bounded,
content-addressed evidence bundle is retained: manifests, tool versions,
summaries, compact counterexamples, and compressed logs. A configurable byte
quota and free-space preflight must fail closed before a proof run, and cleanup
must run on success, failure, and cooperative cancellation.
