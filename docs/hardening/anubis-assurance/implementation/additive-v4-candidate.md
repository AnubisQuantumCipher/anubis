# Implementation Plan: Additive Isolated v4 Approved-Algorithm Candidate

## Selected Design And Constraints

The selected design preserves ANUBIS/v3 compatibility and adds a distinct v4
core behind explicit version dispatch. It incorporates the v3 evidence-only
controls—claim ledger, bounded proofs, differential vectors, and truthful
non-claims—rather than treating them as a competing track.

The implementation must preserve these constraints:

- Existing valid v3 ciphertext remains decryptable and verifiable.
- No v4 algorithm or structure is emitted under the v3 version line.
- A request for v4 never silently falls back to v3.
- All remediations present at the implementation starting revision remain in
  force until the corresponding path is revalidated.
- “Category 5” refers only to the NIST strength categories assigned to
  ML-KEM-1024 and ML-DSA-87. It never means a FIPS 140-3 module level.
- “Approved-algorithm candidate” means the design targets functions and profiles
  on the current NIST approved boundary. It does not mean CAVP-validated,
  CMVP-validated, or approved mode.
- Formal evidence states its model, assumptions, bounds, source revision, tool
  versions, status, and non-claims. It cannot substitute for CMVP's accredited
  laboratory and validation-authority process.
- Proof and vector work is storage-bounded. Heavy build, solver, and generated
  artifacts are disposable. A configured free-space floor, scratch quota, and
  retained-evidence quota are mandatory gates, not advisory warnings.

The initial v4 design target is ML-KEM-1024, ML-DSA-87, AES-256-GCM payload
protection, an approved AES key-wrap construction, and applicable approved
SHA-2/HMAC/KDF functions. This is not yet a normative suite. The classical
hybrid contribution and exact KDF/key-wrap profiles are open design gates that
must be resolved against current NIST and CMVP guidance before production bytes
are emitted.

## Source Revision And Drift Check

This plan is bound to source scan manifest SHA-256
`708fd251769ef4ac5ca86edd81b061092c0376c841aa0b0821bed282983639f1`
and scan revision `8e26122fec7a94afca425abffa2d2c146ce241de`.
Implementation begins from
`f7f37f17cf4be68c49431df91f8d6c7a24d8a993`.

Recorded `sourceDrift` is `present`: the working tree contains assurance work
beyond the starting revision. Before each work package changes production code,
capture the current commit and dirty-path inventory, compare relevant parser,
crypto, CLI, Vault, plugin, documentation, and CI boundaries with this plan,
and record the result in the implementation review. If drift changes the version
dispatcher, publication gate, cryptographic suite, secret owner, or evidence
schema, return to design review instead of adapting silently.

## Implemented Foundation Checkpoint

The repository now contains a deliberately non-operational foundation ahead of
`WP-V4-SPEC`:

- `anubis-crypto::container` makes one bounded exact v1/v2/v3/v4/unknown
  decision, replays all consumed v3 bytes, and exposes no fallback state;
- the CLI requires the v3 dispatch capability before loading identities or
  creating plaintext staging, for binary and armored input;
- recognized v4 input is refused explicitly, and an explicit v4 write request
  cannot yield a v3 permit;
- `anubis-v4-core` is a separate non-publishable crate with no production suite
  value, parser, writer, crypto operation, v3 key dependency, backend, or
  provider-supplied validation claim;
- provider activation is tested only with a fake exact-suite/self-test boundary;
- the version policy is Kani-covered, while reader replay, CLI ordering, and
  binary/armored refusal remain ordinary tests with their stated limitations.

This checkpoint does not complete `WP-V4-SPEC` or `WP-V4-CORE`. It emits no v4
bytes and deliberately leaves the classical contribution, combiner, key wrap,
KDF, IV/nonce ownership, transcript, chunk, and provider decisions unresolved.
It also leaves full-length, domain-separated recipient and signer identifiers
as a specification gate: v3's transcribable 80-bit fingerprints remain useful
display handles but are not a Category-5 authorization identity.

## Affected Components

| Component | Expected role |
| --- | --- |
| `crates/anubis-crypto/src/format.rs` | Preserve v3 behavior, expose explicit format dispatch, and remove any implicit suite inference from outer callers. |
| `crates/anubis-crypto/src/stream.rs` | Retain v3 STREAM behavior; do not generalize it into ambiguous cross-version code. |
| `crates/anubis-crypto/src/hybrid.rs` | Preserve v3 combiner; introduce no v4 behavior until the v4 hybrid specification is frozen. |
| `crates/anubis-crypto/src/armor.rs` | Dispatch decoded bytes by canonical version without accepting cross-version ambiguity. |
| `crates/anubis-crypto/src/v4/` or a dedicated workspace crate | Own v4 checked types, parser, writer, suite, state machine, and provider boundary. Final placement is a review gate. |
| `crates/anubis-cli/src/main.rs` | Add explicit format selection, truthful JSON/human status, downgrade refusal, and compatibility behavior. |
| `crates/anubis-cli/src/io.rs` | Preserve atomic no-clobber and staging semantics for both version readers. |
| `desktop/qml/` and `desktop/src/` | Display actual format/evidence state and keep operation/content bindings current. |
| `plugin/khephri.anubis/` | Consume versioned status without inventing a validation claim. |
| `docs/FORMAT.md` and a new normative v4 specification | Keep v3 frozen; define v4 independently with exact vectors and failure rules. |
| `docs/SECURITY.md`, `docs/ASSURANCE.md`, and README surfaces | Publish the claim ledger in reader-facing language and preserve non-claims. |
| `.github/workflows/` | Run pinned formal, differential, compatibility, desktop, and evidence-schema gates. |
| `scripts/` | Host the storage-bounded proof runner, evidence bundler, cleanup validation, and claim checker. |

## Ordered Work Packages

### `WP-CLAIMS` — Establish the claim and evidence contract

Define a versioned machine-readable claim schema before adding a v4 primitive.
Each record carries the format version, source revision, suite identifier,
statement, evidence references, proof status, assumptions, consequence ceiling,
and non-claims. Add a vocabulary guard that rejects “FIPS level 5,” rejects
unqualified “FIPS validated,” and requires certificate identity before any
validated-module statement can be enabled.

Acceptance for this package requires schema validation, stale-revision
rejection, non-claim preservation, and reader-facing rendering that identifies
v3 as non-CMVP-validated while accurately naming its category-5 PQ parameters.

### `WP-STORAGE` — Build the proof-resource safety boundary

Create one runner used locally and in CI. It must:

- resolve a dedicated scratch directory and reject broad or ambiguous cleanup
  targets;
- preflight filesystem free space against an operator-configured floor;
- enforce per-run scratch and retained-bundle byte ceilings;
- place Cargo targets, solver caches, generated vectors, and expanded traces in
  the disposable scratch tree;
- publish evidence through a temporary bundle followed by an atomic rename only
  after all requested checks and schema validation succeed;
- retain manifests, source/tool digests, obligation status, compact
  counterexamples, and compressed logs while excluding build trees and solver
  caches;
- deduplicate retained objects by content digest and prune only inside the
  dedicated evidence cache under the configured global ceiling;
- clean scratch on success, refusal, test failure, solver failure, and
  cooperative cancellation;
- leave the previously current evidence pointer unchanged on every failed or
  incomplete run.

Exercise the runner with injected low-space, over-quota, cancellation, stale
lock, cleanup-failure, corrupt-bundle, and concurrent-run conditions. A resource
refusal is a first-class result and cannot be retried through a weaker proof
lane under the same claim.

### `WP-V3-EVIDENCE` — Make the compatibility baseline reproducible

Pin the Kani toolchain and execute every existing harness. Add focused models
for content-bound attestations, operation generations, terminal plaintext
publication, checked format geometry, and claim freshness where the production
logic can be represented as pure state transitions. Record explicit unwind and
input bounds.

Retain independent v3 vectors and parsers that do not call the production parser.
Require agreement on valid canonical inputs and rejection classes. Keep the
full workspace, desktop, plugin, installation, tamper, no-clobber, cleanup, and
bounded-memory tests as separate evidence; do not relabel them as formal proof.

This package establishes the “never regress” floor. No v4 patch may merge if it
changes v3 fixtures, safe-publication behavior, content/signer pinning, strict
geometry, no-clobber publication, or secret-lifetime expectations without an
explicit compatibility and security review.

### `WP-V4-SPEC` — Freeze the v4 protocol before production implementation

Write a normative v4 specification with a unique version line, fixed suite,
canonical encoding, exact domain separation, transcript, key schedule, nonce
construction, associated data, chunk geometry, recipient limits, signature
coverage, and terminal failure behavior. Maintain a decision record for the
classical hybrid contribution and cite the current NIST/CMVP guidance used.

The specification must explain which functions are intended as approved
security functions, which component—if any—is auxiliary and non-approved, and
which security strength may be claimed. It must state that formal results and
local vectors do not create CAVP or CMVP certificates.

Before code emits v4 bytes, obtain review agreement between the normative spec,
pure state model, independent vector generator, and production API contract.
Any unresolved nonce, transcript, downgrade, or hybrid-combiner question blocks
production enablement.

### `WP-V4-CORE` — Implement a small isolated candidate core

Implement v4 behind a crate or module boundary that has no access to CLI paths,
QML state, ambient filesystem destinations, or untyped JSON. Use checked
representations for canonical header, validated geometry, suite identifier,
content identity, signer policy, and publication state. Make invalid state
transitions unrepresentable where Rust's type system permits.

The cryptographic provider interface must bind exact algorithm/profile
identifiers and expose known-answer/self-test hooks. It must never select a
different algorithm because one provider is unavailable. Secret-owning types
zeroize on drop where the underlying platform and dependency support it, and
the claim ledger records the limits of memory-erasure evidence.

The outer version dispatcher reads only enough bounded input to identify the
canonical version, then transfers ownership to exactly one reader. Unknown,
ambiguous, malformed, or unsupported versions fail closed. The v4 reader and
writer share checked geometry and transcript construction; separate independent
test implementations remain outside production.

### `WP-REFINEMENT` — Connect formal models to production code

Keep pure models small and executable. Use Kani for bounded Rust invariants and
panic freedom, property-based/differential testing for model-to-code agreement,
and a symbolic protocol model for secrecy/authentication statements under named
primitive assumptions. Add traceability from every claim to the production
function, model obligation, test/vector, and source revision that support it.

Do not assert whole-program equivalence unless an appropriate tool actually
proves it. Where I/O adapters, crypto dependency internals, compiler behavior,
or platform calls remain outside the formal model, keep those non-claims in the
generated evidence and cover them with proportionate tests and independent
vectors.

### `WP-SURFACES` — Integrate without inflating assurance language

Add explicit `v3`/`v4` selection and reporting to CLI structured output, Vault,
and plugin state. Each security verdict binds operation generation, canonical
content identity, format version, suite, signer policy, exit state, and evidence
revision where displayed. A missing or stale field prevents promotion.

User-visible labels distinguish “v4 candidate,” “category-5 PQ parameters,”
“machine-checked properties,” and “CMVP validated.” The last label remains
unavailable unless certificate metadata is configured and matches the exact
module/version/environment. No UI or plugin infers validation from an algorithm
name.

### `WP-ROLLOUT` — Introduce v4 reversibly

Ship read-only fixtures and internal dispatch first. Enable v4 writes only
through an explicit opt-in after cross-implementation vectors, proof gates,
resource tests, and recovery exercises pass. Collect format-version telemetry
only if it is privacy-preserving and documented; do not inspect user plaintext
or identity material for migration inventory.

Change the default writer only through a separate release decision backed by
measured performance/resource results and demonstrated rollback. Preserve the
v3 reader and an explicitly versioned v4 reader. A future v3 writer retirement
or reader retirement is out of scope and requires its own data-inventory and
recovery proposal.

## Compatibility And Migration

Version dispatch is additive. Existing v3 APIs retain their released behavior
or gain additive report types; exhaustive public enums and error shapes require
source-compatibility review. The CLI default remains unchanged while v4 is
internal or opt-in. Vault and plugin must tolerate an unknown future format by
showing an unsupported state, never by treating it as v3.

No automatic data rewrite occurs. Users may explicitly decrypt and re-encrypt
after v4 is enabled, but the source container is preserved until the destination
is independently parsed, authenticated, and—where policy requires—signature
verified. Migration tooling must not claim that re-encryption preserves the
original sender signature, timestamp, or provenance; new ciphertext is a new
artifact.

Compatibility fixtures include all released v3 vectors, malformed rejection
cases, signed and unsigned containers, armored and binary forms, seekable and
non-seekable inputs, file and stdout destinations, and CLI/Vault/plugin
structured-output contracts. v4 fixtures are added without modifying expected
v3 bytes.

## Tactical Protections During Migration

The post-scan remediations remain mandatory:

- safe decrypt APIs stage plaintext until complete policy success;
- provisional streaming APIs remain explicitly named and require discard on
  error;
- desktop/plugin collectors reset per operation and bind results to current
  generations, content IDs, targets, and signer policy;
- JSON control records never share stdout with arbitrary payload bytes;
- no-clobber publication is one atomic filesystem operation;
- named sensitive temporaries use owned RAII cleanup and never scrub bytes
  already published through a link;
- expanded PQ secrets and intermediate material retain zeroization features and
  owners;
- parser ordering, exact EOF, signature geometry, and reader/writer ceilings
  remain shared and strict;
- unknown-length inspection remains bounded;
- non-contributory classical inputs remain rejected in every v3 path.

The new version dispatcher is not permission to bypass these controls. Where
v4 shares an outer adapter, both versions must satisfy the adapter's stronger
publication, path, cleanup, and operation-lifetime contracts.

## Tests And Security Validation

| Gate | Required evidence | Non-claim |
| --- | --- | --- |
| Claim schema | Valid/invalid fixtures, stale-source rejection, forbidden-vocabulary tests | Does not establish underlying crypto correctness |
| Storage safety | Low-space, quota, cancellation, crash, cleanup, concurrency, and atomic-publication tests | Does not prove disk erasure or survive uncatchable termination |
| v3 compatibility | Byte fixtures, independent verifier agreement, adversarial rejection, full workspace/desktop/plugin suite | Does not prove absence of every v3 defect |
| v4 parser/model | Bounded panic-freedom, canonicality, geometry, state-transition, and differential tests | Bounded model is not an unbounded protocol proof |
| Nonce/transcript | Injectivity and domain-separation obligations plus generated boundary cases | Does not prove primitive security or entropy quality |
| Hybrid protocol | Symbolic claims under explicit primitive, corruption, and trust assumptions | Does not prove implementation constant time or side-channel resistance |
| Primitive conformance | Official/example vectors and independent provider/vector adapter agreement | Local vector success is not a CAVP certificate |
| Publication | Bad tag, bad signature, wrong signer, wrong content, truncation, extension, cancellation, and I/O failure emit no destination/plaintext | Platform behavior remains limited to tested operating environments |
| Downgrade | Requested v4 cannot emit v3; v3 cannot parse v4; unknown suite/version refuses | Does not prevent a user from explicitly choosing legacy v3 |
| UI/plugin | Current generation/content/version/suite/evidence required for promotion | Same-user process compromise remains outside the sandbox claim |

All security test data uses disposable identities and generated plaintext.
Live password-manager material and real user ciphertext are not needed for
these gates.

## Performance And Resource Benchmarks

Use the same host, toolchain, build profile, input corpus, and destination type
for baseline and candidate. Record rather than infer:

- encryption/decryption throughput and latency for file and pipe paths;
- signed and unsigned operation cost;
- recipient-count scaling for encapsulation, parse, and header size;
- peak resident memory and private temporary disk use;
- binary and installed footprint by component;
- startup and Vault interaction latency;
- Kani and symbolic-run wall time, CPU, peak scratch bytes, retained bundle
  bytes, cache effectiveness, and cleanup remainder;
- CI artifact upload/download size and retention behavior.

Decision thresholds are configuration owned by the operator and release policy.
The benchmark runner reads them from versioned configuration and refuses to
declare a gate passed when a threshold is absent. Proof-storage thresholds are
hard ceilings: a run that would exceed them returns a resource refusal, keeps
the prior evidence current, and cleans its scratch.

## Rollout And Rollback

Rollout states are explicit and monotonically evidenced: internal parser,
read-only fixtures, opt-in writer, candidate default, and—only under a separate
future decision—legacy-writer retirement. Promotion between states requires the
claim schema, compatibility suite, formal obligations, resource gates,
independent vectors, and recovery exercise to name the same revision.

Rollback stops new v4 writes through configuration or release reversion while
retaining a pinned reader for already-created v4 data. It never relabels v4 as
v3 and never silently migrates ciphertext. Evidence bundles for a withdrawn
revision are marked revoked or superseded without deleting the historical
manifest needed to understand the decision.

For proof-storage incidents, rollback disables the failing proof schedule,
cleans only the validated dedicated scratch/cache roots, restores the prior
current-evidence pointer, and reruns after quota or tool configuration is
reviewed. It does not delete repository data, user vault data, identities, or
the last valid compact bundle.

## Acceptance Criteria

- The source drift check is recorded and no relevant drift remains unexplained.
- The claim ledger rejects category/module-level conflation and unqualified
  validation language.
- Every current assurance statement resolves to evidence for the same source
  revision and preserves assumptions and non-claims.
- The proof runner refuses insufficient space or quota, cleans disposable
  intermediates on every tested terminal path, and cannot replace valid evidence
  with a partial run.
- The retained proof cache remains at or below the configured global byte
  ceiling under repeated successful and failing runs.
- All v3 compatibility, security, desktop, plugin, installation, and independent
  verification gates remain green on the refreshed revision.
- The normative v4 specification, pure model, independent vectors, and
  production implementation agree on canonical valid and invalid cases.
- Version dispatch is exact: v3 and v4 are disjoint, unknown versions refuse,
  and a requested v4 write never falls back.
- Bad authentication, bad signature policy, truncation, extension, malformed
  geometry, cancellation, and I/O failure publish no plaintext or destination.
- Secret-owner and dependency-feature checks remain enforced for both version
  paths.
- Benchmarks meet operator-configured runtime, memory, temporary-disk, and proof
  resource thresholds before any default change.
- CLI, Vault, plugin, README, format, security, and assurance documents use the
  same versioned vocabulary and do not claim CAVP or CMVP validation.
- The v4 rollback exercise stops writes while preserving read access to v4
  fixtures and all supported v3 containers.

## Open Decisions

- CST-laboratory confirmation of the proposed versioned shared-library boundary.
- CST-laboratory confirmation of the first-certificate ML-KEM-only Scenario 1
  profile; a fixed X25519 hybrid remains a deliberate higher-scope alternative.
- Exact provider, direct KEM-key use, AES-KW profile, and ACVP adapter strategy.
- Normative AES-GCM nonce, chunking, AAD, transcript, and final-record rules.
- Exact DRBG/entropy/ESV, module-integrity, signature, and tested-OE profiles.
- Operator values for free-space, scratch, retained-evidence, benchmark, and CI
  retention thresholds.
- Formal toolchain beyond Kani for protocol-level and refinement obligations.
- Evidence cache location, content-addressed index format, and safe pruning
  ownership.
- Opt-in release and default-change criteria.
- Long-term v3 writer support policy.

External CAVP/CMVP validation is now the selected outcome. The controlled
readiness register, proposed boundary/profile, and CST-laboratory RFQ are in
[`docs/cmvp/`](../../../cmvp/README.md). Validation language remains false
until CMVP issues the exact certificate.
