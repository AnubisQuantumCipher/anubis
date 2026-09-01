# Candidate v4 software boundary

Status: project-owned architecture candidate for a non-validated restricted
profile. This is not a CMVP Security Policy, compliance assertion, tested
module specification, or certificate boundary.

## Boundary decision

The intended core is one versioned Linux software component built from
`anubis-v4-core` and an explicitly inventoried in-boundary dependency closure.
A shared library remains a provisional packaging option, not a frozen promise.
Before production cryptography lands, a project architecture decision must
freeze the API/FFI form, executable code and static-data extent, integrity
mechanism, core version, compiler, flags, dependency closure, concurrency
owner, and supported operational environment.

The application is an untrusted caller of this boundary. No UI state, CLI
message, file extension, container header, dependency name, provider string, or
local test result can assert compliance, approval, CAVP validation, or CMVP
validation.

## Intended inside boundary

- one authoritative lifecycle and latched error state;
- software integrity verification and its pre-operational gate;
- complete algorithm self-tests, conditional tests, and on-demand initiation;
- a private DRBG and entropy-source interface;
- fixed-suite ML-KEM key generation, encapsulation, decapsulation, and checks;
- fixed-suite ML-DSA key generation, signing, verification, and pairwise checks;
- file content-encryption-key generation and recipient key establishment;
- the project-selected NIST-standard key derivation and wrapping construction;
- AES-GCM payload services and core-owned IV generation;
- exact transcript, associated-data, nonce, and record-state construction;
- SSP ownership, import/export controls, and zeroization;
- explicit role/service authorization if the frozen API requires roles;
- a result-bound restricted-profile classification for each completed service;
- core identity, version, state, self-test, error, and zeroization status.

## Outside boundary

- ANUBIS/v3 and every v3 primitive;
- the `anubis` CLI, ANUBIS Vault, and Omarchy plugin;
- pathname handling, filesystem reads/writes, plaintext staging, and atomic
  publication;
- ProtonPass and every external secret store;
- container browsing, address-book labels, audit presentation, and telemetry;
- the operating system, CPU, loader, storage device, and physical enclosure.

The application may pass plaintext, ciphertext, public keys, wrapped keys,
signatures, private-key seeds, and explicit policy through reviewed ports. It
must not receive raw KEM shared secrets, DRBG state, intermediate
key-encryption keys, or unwrapped file keys. Any future exception requires a
recorded threat analysis and a new service contract; documentation alone
cannot override the code boundary.

## Interface classes

| Logical interface | Candidate API material |
| --- | --- |
| Data input | plaintext, ciphertext, public keys, wrapped keys, signatures |
| Data output | owned ciphertext, fully authenticated plaintext records, public keys, wrapped keys, signatures, verification verdicts |
| Control input | exact service selection, fixed suite, role/policy, sizes, terminal-record flag |
| Status output | core state, operation result, restricted-profile classification, self-test result, zeroization result, exact identity |
| Execution input | process loading and execution supplied by the supported platform |

Data output must be inhibited during pre-operational testing and after a
latched error or terminal zeroization. A decryption service must stage its owned
output until authentication completes. The outer application must separately
preserve its stricter whole-file rule: publish nothing until all records, the
terminal condition, signature disposition, and caller policy pass.

## Services and restrictions

There is no production service or role model yet. The frozen design must define
administrative status, initialization, on-demand testing, and zeroization
separately from cryptographic services. It must not expose a generic algorithm
selector, suite negotiation, fallback provider, raw primitive API, caller
supplied GCM IV, raw DRBG output, or raw KEM shared-secret output.

The core, never a provider or caller, owns service classification. The current
type can report only `NotValidated` with no CMVP certificate. The term
`RestrictedProfileCompleted` records a successful local code path; it does not
mean approved operation or external validation.

## Operational environment

Generic Omarchy or rolling Arch Linux is not a reproducible supported
environment. Before v4 release, freeze one narrow build and runtime profile and
record:

- kernel and operating-system identity;
- CPU architecture and processor family;
- enabled processor algorithm features;
- dynamic loader and C runtime;
- Rust compiler, linker, build flags, and dependency lockfile;
- exact core artifact digest and integrity-test coverage;
- installation path, ownership, and permissions;
- dynamic versus static delivery and the concurrency/singleton model.

That record is reproducibility evidence only. It does not create certificate
coverage.

## Current code checkpoint

The isolated crate has no production suite value or cryptographic operation.
The lifecycle owner now models `PreOperational`, `SelfTesting`, `Operational`,
latched `Error`, and terminal `Zeroized` states. It drives an ordered integrity
primitive, module-integrity, and remaining-algorithm self-test sequence. Any
self-test or fatal-service failure latches the error state before best-effort
provider cleanup. Drop also attempts idempotent cleanup.

An opaque operational capability exists only after the exact suite's self-test
sequence succeeds, rechecks state before completing output, and remains unable
to release a result after a fatal transition. Completed output is inseparable
from module-owned service metadata hard-coded as not CMVP validated. Successful
explicit zeroization permanently revokes operation.

This remains scaffolding. Fake hooks are not real integrity or algorithm tests;
provider zeroization status is not proof that every compiler, allocator, OS,
storage, or physical-memory copy was erased; panic/abort behavior and
shared-library concurrency are not solved; and generic staged test output does
not prove future concrete output types contain no SSPs.
