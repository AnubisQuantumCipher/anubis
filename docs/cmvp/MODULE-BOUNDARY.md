# Candidate module boundary

Status: architecture candidate for CST-laboratory review. It is not a validated
module specification or Security Policy.

## Boundary decision

The initial validation target is one versioned Linux shared library, provisionally
named libanubis_fips.so, built from anubis-v4-core and its explicitly inventoried
in-boundary dependencies. Its executable code and static data form the logical
software boundary. The exact distributed binary, integrity mechanism, module
version, compiler, flags, dependency closure, and tested operational environment
must be frozen with the selected CST laboratory.

The application is an untrusted caller of this boundary. No UI state, CLI
message, file extension, container header, dependency name, or provider string
can assert that the module is validated.

## Inside the proposed boundary

- module lifecycle and latched error state;
- software integrity verification and its pre-operational gate;
- complete cryptographic algorithm self-tests and conditional tests;
- approved DRBG and entropy-source interface;
- ML-KEM key generation, encapsulation, decapsulation, and required key checks;
- ML-DSA key generation, signature generation, signature verification, and
  required pairwise checks;
- file content-encryption-key generation and recipient key establishment;
- approved key derivation and key wrapping selected with the laboratory;
- AES-256-GCM payload services and module-owned IV generation;
- exact transcript, associated-data, nonce, and chunk-state construction;
- SSP ownership, import/export controls, and zeroization;
- role/service authorization;
- approved-service status indication for every service invocation;
- module identity, version, state, self-test, error, and zeroization status.

## Outside the proposed boundary

- ANUBIS/v3 and every v3 primitive;
- X25519 for the initial certificate;
- the anubis CLI, ANUBIS Vault, and Omarchy plugin;
- pathname handling, filesystem reads/writes, plaintext staging, and atomic
  publication;
- ProtonPass and every external secret store;
- container browsing, address-book labels, audit presentation, and telemetry;
- the operating system, CPU, process loader, storage device, and physical
  enclosure remain outside the logical software boundary; the Security Policy
  nevertheless identifies the tested operational environment.

The application may pass plaintext, ciphertext, public keys, private-key seeds,
and policy parameters through documented ports. It must not receive raw KEM
shared secrets, DRBG internal state, intermediate key-encryption keys, or
unwrapped file keys unless a lab-reviewed service explicitly requires that
output.

## Interface classes

| Logical interface | Candidate API material |
| --- | --- |
| Data input | plaintext, ciphertext, public keys, wrapped keys, signatures |
| Data output | ciphertext, authenticated plaintext, public keys, wrapped keys, signatures, verification verdicts |
| Control input | exact service selection, fixed suite, role, sizes, final-record flag, external policy |
| Status output | module state, operation result, approved-service indicator, self-test result, zeroization result, exact module identity |
| Power input | process loading and execution supplied by the tested platform |

Data output must be inhibited during pre-operational testing and in the latched
error state. The outer application must separately preserve its existing rule
that unauthenticated plaintext is never published.

## Roles and services

The candidate uses a User role for approved cryptographic services and a Crypto
Officer role for installation, integrity/self-test invocation, status, and
zeroization operations. The exact role-selection and authentication treatment
is not frozen; the CST laboratory must reconcile it with the Security Level 1
requirements and the final API.

There will be no generic algorithm-selection API, no suite negotiation, no
fallback provider, no standalone raw primitive API, and no non-approved cipher
service inside the initial boundary.

## Operational environment

Omarchy is based on rolling Arch Linux, so a label such as “Omarchy” is not a
reproducible tested environment. The first certificate should name one narrow,
frozen Linux operational environment and hardware platform that the laboratory
can reproduce. Additional architectures and distributions are later
validation-maintenance decisions, not assumptions attached to the first
certificate.

Before freeze, record:

- kernel and operating-system identity;
- CPU architecture and processor family;
- presence or absence of processor algorithm acceleration;
- dynamic loader and C runtime;
- Rust compiler, linker, build flags, and dependency lockfile;
- exact module binary digest and integrity-test coverage;
- installation path, ownership, and permissions;
- whether the module is delivered dynamically or statically linked.

## Current code checkpoint

The isolated crate has no production suite value or cryptographic operation.
Its provider owner now models PreOperational, SelfTesting, Operational, and
latched Error states. An opaque operational capability exists only after the
exact suite's self-test hook succeeds; failed startup or on-demand tests block
that capability. Zeroization has an explicit success/failure result and cannot
recover a latched error state.

This is implementation scaffolding only. It does not yet provide the integrity
test, algorithm self-tests, data-output gate, service indicator, SSP
zeroization implementation, CAVP evidence, or CMVP evidence required by the
final module.
