# ANUBIS assurance boundary

This document is the claim ledger for ANUBIS. It separates algorithm facts,
implementation evidence, design goals, and certifications so that one cannot be
silently promoted into another.

## Current claim, in one paragraph

ANUBIS/v3 uses the ML-KEM-1024 parameter set from
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and the ML-DSA-87
parameter set from [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). Both
are NIST post-quantum security Category 5 parameter sets. ANUBIS/v3 is **not a
FIPS 140-3 validated cryptographic module**, does **not** have a CMVP
certificate, and does **not** provide an approved-only mode. Its current wire
format also requires ChaCha20-Poly1305, which is not in the CMVP approved
security-function list. Formal methods and automated tests strengthen evidence
for specifically stated implementation properties; they cannot create a CMVP
validation or establish every property of the system.

## Category 5 is not “FIPS level 5”

These two classifications answer different questions:

| Term | Meaning | ANUBIS/v3 status |
| --- | --- | --- |
| NIST PQ security Category 5 | A strength category for post-quantum parameter sets. ML-KEM-1024 and ML-DSA-87 are Category 5. | Uses Category 5 parameter sets. |
| FIPS 140-3 Security Level | A cryptographic-module validation level covering module boundaries, roles, services, self-tests, key management, physical security, lifecycle assurance, and more. FIPS 140-3 defines Levels 1 through 4. | Not validated at any level. There is no Level 5. |
| CAVP algorithm validation | Testing an implementation of an approved algorithm through the Cryptographic Algorithm Validation Program. | No ANUBIS CAVP certificate is claimed. |
| CMVP module validation | Validation of a defined cryptographic module through the Cryptographic Module Validation Program and an accredited laboratory. | No ANUBIS CMVP certificate is claimed. |

Primary sources: [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final),
[CMVP](https://csrc.nist.gov/Projects/cryptographic-module-validation-program),
[CMVP standards and process](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/fips-140-3-standards),
and [CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program).

Implementing a standardized algorithm is not the same as using a validated
module. Passing local vectors is not CAVP validation. Formal verification is
not a substitute for the external process that the CMVP definition requires.
The project is now pursuing that external path through the controlled
[CMVP readiness package](cmvp/README.md). Until an accredited laboratory tests
the exact module and CMVP issues a certificate, the strongest honest claim is
an **approved-algorithm candidate with machine-checked stated properties**, not
“FIPS validated.”

## v3 algorithm profile

| Function | v3 construction | Classification relevant to this ledger |
| --- | --- | --- |
| Post-quantum KEM | ML-KEM-1024 | FIPS 203, Category 5 parameter set |
| Classical hybrid component | X25519 | RFC 7748; not an independently approved v3 service |
| Hybrid combiner | HKDF-SHA-512 | RFC 5869 construction used by the v3 format |
| File-key wrapping | ChaCha20-Poly1305 | RFC 8439; not an approved-only CMVP profile |
| Payload encryption | Chunked ChaCha20-Poly1305 STREAM | RFC 8439 primitive; not an approved-only CMVP profile |
| Header authentication | HMAC-SHA-512 | FIPS-standardized primitive used in an unvalidated composition |
| Optional signature | ML-DSA-87 | FIPS 204, Category 5 parameter set |

The precise, interoperable v3 construction remains in [FORMAT.md](FORMAT.md).
That document specifies behavior; it is not a certificate.

## Machine-checkable evidence in this repository

The storage-guarded Kani lane model-checks production Rust functions against explicit
harness assertions. `scripts/kani-bounded.sh` pins Kani, runs one solver job at
a time, gives every harness a timeout, confines conventional temporary files to
the disposable tree, supervises the version probe and proof in separate
validated sessions, monitors scratch growth, free space, and aggregate process
RSS, requires every inventoried `cover!` obligation to be reachable, and
deletes intermediate models on every handled exit. A successful proof whose
cleanup fails is a failed gate. CI installs the version-locked Kani proxy and
verifies the SHA-256 digest of the explicit runtime release bundle before setup;
it keeps only the concise log. This avoids treating large, version-specific
CBMC build products as durable evidence.

| Property | Production boundary exercised | What success establishes | What it does not establish |
| --- | --- | --- | --- |
| Armor boundary transition matrix | `armor::advance_armor` | Every state/line-class pair follows the asserted finite accept/reject matrix; cover checks make representative security branches reachable. | UTF-8 trimming, base64 correctness, arbitrary-length allocation behavior, or the whole decoder. |
| Exact outer-version policy | `container::version_line_policy` | Every modeled token-length/prefix/version-byte observation maps to one disjoint legacy, v3, v4-candidate, or unknown state; every state is reachable and there is no fallback state. | Correct derivation of those observations, whole-reader behavior, or correctness of a future v4 parser. |
| Safe plaintext promotion | `format::plaintext_stage::promote` | A failed verdict cannot produce the authenticated type that owns `copy_to`; success can. | That the cryptographic verdict is correct, filesystem atomicity, or OS behavior. |
| CLI output authorization | `anubis-cli::authorize_stage` | A failed caller-policy verdict cannot produce the policy-authorized type that owns file/stdout publication; success can. | That the policy verdict is correct, pathname safety, filesystem atomicity, or OS behavior. |
| Payload span arithmetic | `format::payload_span` | Every accepted decomposition avoids underflow and reconstructs the original total. | Parser correctness or authenticity of the lengths. |
| Payload geometry | `stream::payload_geometry` | For the modeled input domain, acceptance, byte count, and chunk count match the asserted encoding rule. | AEAD security or that a payload with valid geometry authenticates. |
| Payload nonce construction | `stream::nonce_for` | In-range counter/final-flag inputs satisfy the asserted injectivity, separation, and counter-guard properties. | Random-key quality, AEAD security, or platform execution. |
| Header-line acceptance policy | `format::header_line_policy` | Every byte-count/newline/trailing-whitespace observation maps to the asserted finite canonicality decision, with every outcome reachable. | UTF-8 decoding, correct derivation of the observations, stanza/base64 parsing, or whole-parser panic freedom. |

Kani verifies Rust after translation to its CBMC model. These harnesses do not
prove the cryptographic assumptions behind ML-KEM, ML-DSA, X25519, HKDF, HMAC,
or ChaCha20-Poly1305. They do not prove the Rust compiler, LLVM, CPU, kernel,
random-number generator, dependency supply chain, side-channel behavior, fault
resistance, or desktop presentation correct. Ordinary unit, adversarial,
interoperability, CTest, and UI protocol tests remain required because they
exercise boundaries the model does not contain.

The full `String`/base64 header parser is intentionally not represented as an
exhaustive Kani claim: symbolic library internals do not fit this bounded lane.
The production parser's allocation-free decision boundary is model-checked,
while complete parser behavior remains an adversarial and interoperability test
responsibility. A resource-limit failure is never reported as proof success.

Run the complete guarded lane with:

```bash
./scripts/kani-bounded.sh
```

For a single development harness, use the runner's only accepted selector:

```bash
./scripts/kani-bounded.sh --harness armor::proofs::boundary_policy_matches_the_exact_transition_matrix
```

Arbitrary Kani arguments are deliberately rejected so callers cannot override
the serialized job count, disposable target, timeout, output policy, or other
resource guards.

A timeout, storage-threshold, free-space, or RSS refusal, unreachable required
cover property, counterexample, unsupported reachable construct, or nonzero
verifier exit is a failed gate. It is never converted into a skip or a weaker
success claim.

## Storage and evidence retention policy

Formal intermediates are intentionally reproducible and disposable:

- proof source, harness source, tool version, commit identity, and concise
  result logs are durable;
- CI pins the Rust release, Kani installer version, Kani runtime bundle URL,
  and runtime bundle digest; the hosted runner image and its preinstalled
  system packages remain outside that content pin;
- Kani target trees, GOTO binaries, SAT/SMT scratch, incremental objects, and
  ordinary Cargo proof build products are not uploaded or committed;
- local runs hold an atomic exclusive lock directory, preflight free space
  on the disposable, `KANI_HOME`, and `RUSTUP_HOME` filesystems before the
  setup-capable version probe; the probe has bounded combined output, CPU,
  wall time, aggregate RSS, disposable-tree growth, aggregate filesystem
  growth, and a runtime free-space floor;
- the proof points `TMPDIR` and Cargo's target into the disposable tree,
  rejects a symlinked proof-target parent, monitors that tree's filesystem plus
  scratch and aggregate proof-process RSS thresholds, terminates the complete
  solver process group on a breach, and cleans the exact validated work
  directory on every handled exit;
- both Cargo phases enter distinct PID=PGID=SID sessions and cross a validation
  barrier before work begins. A pre-opened FIFO watchdog is armed first; if the
  outer monitor disappears, including through `SIGKILL`, EOF terminates and
  then force-kills the otherwise orphaned phase process group;
- fake-verifier lifecycle tests exercise exact version-before-proof ordering,
  version mismatch and multiline rejection, probe timeout, probe/proof
  measurement failures, non-isolated-session refusal, normal completion,
  child failure, outer-supervisor `SIGKILL`, stale-lock refusal, no-orphan
  behavior, cleanup, and low-space refusal without generating solver
  intermediates;
- CI runners are ephemeral and do not cache the formal target directory;
- a release may retain a compact machine-readable proof manifest, but never an
  unbounded solver tree.

This controls accumulation. The polling guards are defense in depth, not a
kernel-enforced filesystem quota: one write can overshoot between polls, a tool
can ignore `TMPDIR`, and unrelated processes can consume the same filesystem.
Killing the outer supervisor can leave the disposable directory and its stale
lock, but the active phase watchdog stops the live writer and the next run
refuses the lock instead of creating another tree. Killing the watchdog and its
phase group itself with an uncatchable signal, a kernel failure, or power loss
remains outside a shell runner's guarantee. The operator must inspect stale
state before cleaning the exact validated work directory.
The startup reserve and runtime free-space floor make ordinary exhaustion less
likely, but they cannot prove the host will never fill. A deployment needing a
hard aggregate limit must run the same disposable tree on an operator-created
quota-controlled filesystem. An oversized proof must fail and be redesigned or
run only after a deliberately reviewed resource-policy change.

`cargo kani setup` is an explicit toolchain installation outside this runner;
its persistent runtime is not proof scratch and is not deleted after a proof.
Operators must provision and inspect that one-time installation separately.
The guarded runner neither invokes that setup command nor accumulates another
solver tree when a stale lock exists.

## Additive v4 target

The v3 format is frozen for compatibility. Replacing algorithms in place would
make old ciphertext ambiguous and would not create a coherent validation
boundary. The implemented foundation now provides an exact, bounded one-time
version dispatcher and an isolated `anubis-v4-core` crate. The CLI recognizes
the reserved `anubis-encryption.org/v4` token and refuses it before loading v3
identities or creating plaintext staging. A v4 write request cannot yield a v3
permit. The isolated crate exports no production suite value, parser, writer,
cryptographic operation, backend dependency, or provider-supplied validation
status. Its fake-provider tests now exercise pre-operational, self-testing,
operational, latched error, on-demand test, and explicit zeroization-result
transitions. No cryptographic service is exposed.

The proposed lowest-risk first-certification target is ML-KEM-1024 Scenario 1,
ML-DSA-87, AES-256-GCM payload protection, AES-256-KW file-key wrapping,
HMAC_DRBG/SHA2-512, and the applicable SHA2/SHA3/SHAKE/HMAC prerequisites.
Direct KEM-key use, key wrap, provider-owned IV generation, entropy/ESV route,
encoded AAD/transcript, signature interface, final-record rules, integrity
mechanism, and exact ACVP registrations remain CST-laboratory architecture
gates. No provider or production suite has been frozen.

The current [FIPS 140-3 Implementation Guidance](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf)
permits a predefined ML-KEM hybrid to include a non-approved but allowed
classical component only under specific module-owned constraints. ML-KEM-only
is a deliberate first-certificate scope reduction, not a FIPS requirement to
remove X25519. If a later v4 design selects the classical hedge, the candidate
core must own the complete fixed hybrid service; an application that
independently calls unrelated X25519, ML-KEM, and HKDF services is not the same
boundary. The decision and test inventory are in
[cmvp/ALGORITHM-PROFILE.md](cmvp/ALGORITHM-PROFILE.md). Relevant sources include
[SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final),
[SP 800-56C Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final),
[SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), and
[SP 800-38F](https://csrc.nist.gov/pubs/sp/800/38/f/final).

The future v4 label will remain `approved-algorithm-candidate` unless and until
an actual certificate says otherwise. A container cannot assert that it was
created by a validated implementation; runtime status must report the active
provider, approved-only state, validation boolean, and certificate identifier.
Today there is no v4 runtime mode to report.

## Required v4 proof and test gates

Before v4 can become the default writer, it must have:

- frozen byte-exact v3 decrypt vectors and permanent v3 read compatibility;
- deterministic test-provider v4 wire vectors and an independent verifier;
- approved-algorithm known-answer and ACVP-compatible vector interfaces;
- cross-provider differential encryption, decryption, and signature checks;
- adversarial downgrade, suite-confusion, reorder, duplicate, truncation,
  substitution, key-wrap corruption, signature corruption, counter exhaustion,
  provider-failure, and trailing-byte cases;
- a machine-checked publication state model in which `Published` is reachable
  only after header authentication, complete payload authentication, signature
  disposition, and caller policy acceptance;
- bounded parser/arithmetic/nonce proofs with explicit reachability checks;
- reproducible dependency, action, toolchain, and release provenance.

These gates can make the implementation substantially more reviewable and can
falsify many defect classes. They still do not turn ANUBIS into a CMVP-validated
module without the process NIST defines.

## Evidence history

The sealed baseline security review identified concrete implementation defects;
the remediation report records their fixes and limitations. The architectural
follow-up is indexed under
[`docs/hardening/anubis-assurance/`](hardening/anubis-assurance/). Those design
documents are derived analysis, not additional scan findings and not proof that
future v4 work is implemented.
