# First-certification algorithm profile

Status: proposed baseline for a CST-laboratory architecture checkpoint. No
production v4 suite is frozen or enabled by this document.

## Decision

The lowest-risk initial certificate target is IG D.S Scenario 1 with
ML-KEM-1024 only. ANUBIS/v3 retains its fixed X25519 plus ML-KEM construction
outside the candidate FIPS boundary. This is a deliberate scope reduction, not
a claim that CMVP forbids hybrid KEMs.

The current IG also permits a fixed Scenario 2 hybrid. If v4 must preserve a
classical-plus-post-quantum hedge, the project may select that profile before
the wire format freezes. It would require module-enforced predefined
components and ordering, an approved combiner, additional testing, and X25519
classified as non-approved but allowed with no security claimed. X25519 could
not be exposed as an independent approved service. Written Security Policy
instructions alone would not enforce those restrictions.

## Proposed fixed v4 suite

| Purpose | Proposed construction | Boundary rule |
| --- | --- | --- |
| Recipient key establishment | ML-KEM-1024, FIPS 203 and SP 800-227 | KeyGen, Encaps, Decaps, both key checks, and implicit rejection stay inside |
| File-key wrapping | AES-256-KW, SP 800-38F | The ML-KEM 256-bit shared-secret key is the KEK; no baseline KDF |
| Payload protection | AES-256-GCM, SP 800-38D | Module-internal 96-bit random IV per record and a full 128-bit tag |
| Random-bit generation | HMAC_DRBG with SHA2-512 | Linux getrandom supplies instantiate/reseed entropy only, never service output |
| Signature | Pure ML-DSA-87; hedged by default | Deterministic only after the documented assessment and CSTL acceptance |
| PQ prerequisites | SHA3-256, SHA3-512, SHAKE128, SHAKE256 | Every distinct implementation path is tested |
| Module integrity candidate | HMAC-SHA2-512 | Exact authenticated extent/key placement remain a lab packaging decision |

FIPS 204 defaults to hedged signing. The deterministic variant remains
conditional on a documented side-channel and fault-attack assessment and CSTL
acceptance; otherwise the profile must use hedged ML-DSA with module-generated
randomness.

For each file, the module generates one fresh AES-256 content-encryption key.
For each recipient, ML-KEM Encaps returns a ciphertext and shared-secret key;
the module uses that recipient-specific key directly as the AES-256-KW
key-encryption key to wrap the file key, then zeroizes the KEM secret. SP
800-227 defines an established shared-secret key as usable directly as a
symmetric key or keying material. The CST laboratory must approve this exact
use and MIS categorization before freeze.

Each payload record receives a fresh module-DRBG-generated IV. Associated data
binds the immutable canonical header, record index, and final-record marker.
An empty file still has a terminal authenticated record. The module outputs no
record plaintext until that record's GCM tag succeeds. The outer ANUBIS safe
API must stage those authenticated records and publish nothing until every
record, the terminal condition, and the caller's signature policy succeed. The
design must enforce SP 800-38D's RBG-based construction limit across all
instances using a given key, fail or rekey before the bound, and satisfy current
IG C.H. ACVP does not establish IV uniqueness.

The signature context is proposed as ASCII anubis-v4-file. ML-DSA signs the
canonical byte transcript incrementally from the v4 version through the final
GCM record, excluding the signature trailer. If the implementation cannot
provide a lab-acceptable streaming pure interface, standardized HashML-DSA is
an explicit alternative suite decision, never a silent substitution.

## Production API restrictions

- one exact suite identifier and no negotiation or provider fallback;
- no caller-supplied GCM IV;
- no raw ML-KEM shared-secret output;
- no generic AES, hash, HMAC, SHAKE, or DRBG production API;
- no expanded private-key import path merely because ACVP needs a lab hook;
- generic decryption failure for decapsulation, key-check, unwrap, tag, final
  record, and required-signature failure;
- an unambiguous approved-service indicator returned with each completed
  service;
- no cryptographic data output before successful integrity and algorithm
  self-tests or after entry into the latched error state.

## Baseline ACVP scope

The adapter must call the exact compiled in-boundary implementation and
register only shipped capabilities:

- AES forward and inverse prerequisite implementation;
- AES-GCM encrypt/decrypt with the selected key, IV, and tag profile;
- AES-KW wrap/unwrap with the selected KEK and payload-key profile;
- SHA2-512 and HMAC-SHA2-512;
- HMAC_DRBG with SHA2-512;
- SHA3-256, SHA3-512, SHAKE128, and SHAKE256;
- ML-KEM-1024 KeyGen plus EncapDecap encapsulation, decapsulation, both key
  checks, valid paths, and implicit-rejection paths;
- ML-DSA-87 KeyGen, pure SigGen using the lab-approved hedged or deterministic
  variant, and SigVer with the external interface and seed key format.

The current ML-KEM and ML-DSA ACVP schemas are evolving work products. The
adapter must query the service and the laboratory must approve the exact
production registrations at test time rather than freezing today's draft
revision names into the protocol.

The local dependency graph currently reaches Keccak/SHAKE through distinct
wrapper paths for ML-KEM and ML-DSA. One algorithm certificate cannot be
assumed to cover both implementations. Before freeze, either consolidate on
one provider path or have the laboratory enumerate and test every distinct
implementation. CPU feature selection creates the same concern for portable
and accelerated paths; the first certificate should freeze one tested path or
explicitly cover each path.

## Required module self-tests

The lab-reviewed startup inventory must include:

- the software integrity verification and prerequisite CAST ordering;
- CASTs for AES, GCM, KW, SHA2-512, HMAC-SHA2-512, every SHA3/SHAKE
  implementation, and HMAC_DRBG operations;
- ML-KEM Encaps, Decaps, implicit-rejection, and KeyGen paths;
- ML-DSA SigGen, SigVer, and KeyGen paths, including applicable ML-DSA-87
  sampling/rejection paths;
- pairwise consistency tests for generated ML-KEM and ML-DSA key pairs;
- on-demand initiation, failure injection, data-output inhibition, latched
  error behavior, and explicit zeroization result.

Developer unit tests, Kani proofs, and ACVP vectors do not replace these
module-executed self-tests.

## Architecture-checkpoint decisions

The CST laboratory must close these before a production SuiteId exists:

- direct KEM-key-as-KEK use and AES-KW service categorization;
- GCM IV construction, invocation cap, AAD, header canonicalization, record
  geometry, and terminal rule;
- HMAC_DRBG instantiate/reseed policy, entropy request, nonce,
  personalization, claimed strength, and ESV route;
- pure streaming ML-DSA versus standardized HashML-DSA;
- whether signatures are mandatory, optional, or excluded from the first
  certificate;
- integrity algorithm, key placement, authenticated extent, package layout,
  loader behavior, and operational environment;
- ACVP test-interface equivalence to the production module.

Primary sources: [current FIPS 140-3 IG](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf),
[SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final),
[SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final),
[SP 800-38F](https://csrc.nist.gov/pubs/sp/800/38/f/final),
[CAVP prerequisites](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/prerequisites),
[ML-KEM ACVP](https://pages.nist.gov/ACVP/draft-celi-acvp-ml-kem.html), and
[ML-DSA ACVP](https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html).
