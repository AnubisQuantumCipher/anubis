# Restricted v4 algorithm-profile decision record

Status: design baseline awaiting project architecture decision and independent
review. No production v4 suite is frozen or enabled. The listed standards and
local vector plans are not CAVP validation, approved operation, FIPS 140-3
compliance, or CMVP validation.

## Decision principles

- preserve v3 read compatibility and never reinterpret v3 bytes;
- select one exact v4 suite with no negotiation or provider fallback;
- keep all key establishment, combination, wrapping, payload protection,
  signing, DRBG state, and SSP lifecycle inside the candidate core;
- use NIST-standardized post-quantum and symmetric algorithms where the v4
  security design permits;
- preserve the classical-plus-post-quantum hedge unless a recorded threat and
  interoperability review justifies an ML-KEM-only suite;
- release no cryptographic output before startup tests and no decrypt output
  before complete authentication;
- describe every result as local restricted-profile metadata, never approval or
  validation.

## Open suite decision

The architecture review must choose exactly one of these before a production
`SuiteId` or wire byte exists:

| Candidate | Construction | Tradeoff |
| --- | --- | --- |
| Fixed hybrid | X25519 plus ML-KEM-1024 combined by a fixed, domain-separated KDF | Preserves the v3 defense-in-depth rationale but adds a non-NIST primitive and more combination/testing surface. |
| ML-KEM only | ML-KEM-1024 key establishment | Narrower implementation and vector surface, but removes the classical hedge that v3 deliberately provides. |

This choice is a product security decision, not a certification shortcut. It
must be documented against store-now-decrypt-later goals, implementation
diversity, cryptanalytic failure modes, recipient-key migration, and v3/v4
interoperability. Silent runtime choice between the candidates is forbidden.

## Components common to the baseline

| Purpose | Candidate construction | Required boundary rule |
| --- | --- | --- |
| Post-quantum key establishment | ML-KEM-1024, FIPS 203 and SP 800-227 | KeyGen, Encaps, Decaps, key checks, and implicit rejection stay inside |
| Hybrid combination if selected | Fixed X25519 plus ML-KEM-1024 input to a domain-separated NIST KDF profile | Both contributions and ordering are mandatory; neither is a separately selectable service |
| File-key wrapping | AES-256-KW, SP 800-38F | The exact KEK derivation is frozen with the suite; raw shared secrets and KEKs never leave |
| Payload protection | AES-256-GCM, SP 800-38D | Core-generated unique IV per record and full authentication tag |
| Random-bit generation | HMAC_DRBG with SHA2-512 | OS randomness supplies complete instantiate/reseed requests only, never caller-visible raw output |
| Signature | ML-DSA-87, FIPS 204 | Hedged signing unless a recorded side-channel and fault analysis supports the standardized deterministic variant |
| Prerequisites | SHA2-512, HMAC-SHA2-512, SHA3-256, SHA3-512, SHAKE128, SHAKE256 | Every distinct compiled implementation path is inventoried and tested |
| Core integrity candidate | HMAC-SHA2-512 | Authenticated extent, key placement, loader order, and build integration must be frozen before release |

The exact KDF profile, direct-versus-derived KEK decision, GCM IV construction,
DRBG instantiate/reseed policy, signature interface, and integrity packaging
remain unresolved. No implementation may choose defaults implicitly.

## Payload and transcript rules to freeze

For each file, the core owns one non-cloneable content-encryption key. For each
recipient, key establishment and any hybrid combination produce
recipient-specific keying material used only through the frozen wrap profile;
all shared secrets and KEKs are cleaned on success and every error path.

Each payload record receives a core-owned IV reserved atomically before output.
Associated data must bind the immutable canonical header, record index, and
terminal marker. An empty file must still have an authenticated terminal
record. The core outputs no record plaintext until its tag succeeds. The outer
safe API stages authenticated records and publishes nothing until all records,
the terminal condition, required signature disposition, and caller policy
succeed.

The signature transcript must be byte-exact, domain separated, and cover the
canonical container from its version token through the final encrypted record,
excluding only the signature trailer defined by the frozen grammar. Pure versus
standardized pre-hash ML-DSA is an explicit suite decision, never a silent
substitution.

## Production API restrictions

- no caller-supplied IV, entropy, seed, or DRBG state;
- no raw ML-KEM or hybrid shared-secret output;
- no generic AES, hash, HMAC, SHAKE, KDF, or DRBG API;
- no expanded private-key import path merely because local vectors need a test
  hook;
- one externally indistinguishable decryption failure for key establishment,
  unwrap, tag, terminal, and required-signature rejection;
- result-bound restricted-profile classification returned only with a completed
  owned output;
- no data output before successful integrity and algorithm tests, during
  on-demand tests, or after error/zeroization.

## Local vector and ACVP-compatible adapter scope

The deterministic test adapter must call the exact compiled in-boundary
implementation and expose only frozen capabilities needed for authoritative
vectors:

- AES forward/inverse prerequisites, AES-GCM, and AES-KW;
- SHA2-512, HMAC-SHA2-512, and HMAC_DRBG;
- SHA3-256, SHA3-512, SHAKE128, and SHAKE256;
- ML-KEM-1024 KeyGen, encapsulation, decapsulation, key checks, valid paths, and
  implicit-rejection paths;
- ML-DSA-87 KeyGen, the selected SigGen variant, SigVer, and pairwise checks;
- X25519 and the exact combiner only if the fixed hybrid is selected.

The adapter is test-only, must not add a production primitive API, and must be
checked for equivalence with the release provider. Passing public vectors or an
ACVP-compatible local session remains developer evidence and must never be
reported as CAVP validation.

Distinct SHAKE wrappers, CPU feature paths, portable versus accelerated code,
and platform-specific provider branches are separate implementations until
evidence demonstrates otherwise. Consolidate them or inventory and test each
supported path.

## Required core self-tests

The project-owned inventory must cover:

- prerequisite test ordering and software integrity verification;
- known-answer tests for every enabled symmetric, hash, HMAC, SHAKE, KDF, and
  DRBG operation;
- ML-KEM encapsulation, decapsulation, implicit rejection, KeyGen, and checks;
- ML-DSA generation, signing, verification, sampling/rejection, and pairwise
  consistency paths;
- X25519 and hybrid-combiner paths if the fixed hybrid is selected;
- on-demand initiation, failure injection, output inhibition, latched error,
  terminal zeroization, and cleanup outcomes.

Unit tests, bounded proofs, and local vectors do not replace core-executed
self-tests.

## Architecture decision gate

Before a production `SuiteId` exists, record independent review of:

- fixed hybrid versus ML-KEM only and the exact combiner/KDF;
- KEK derivation, AES-KW profile, and SSP lifetimes;
- GCM IV construction, per-key invocation accounting, AAD, header
  canonicalization, record geometry, and terminal rule;
- HMAC_DRBG instantiate/reseed policy, entropy request, personalization,
  strength target, fork/snapshot handling, and fail-before-output behavior;
- pure versus standardized pre-hash ML-DSA and signature requirement policy;
- integrity algorithm, key placement, authenticated extent, package layout,
  loader behavior, and supported operational environment;
- test-adapter equivalence to the production core;
- FFI concurrency, one authoritative lifecycle/DRBG owner, and rollback.

Primary sources: [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final),
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final),
[SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final),
[SP 800-56C Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final),
[SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final),
[SP 800-38F](https://csrc.nist.gov/pubs/sp/800/38/f/final), and
[CAVP prerequisites](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/prerequisites).
