# CST-laboratory RFQ and intake package

Status: ready for vendor identity, commercial approval, and identical
distribution to shortlisted laboratories. No lab has been contacted and no
money has been committed.

## Vendor inputs still required

Do not infer these from a GitHub account, local machine, or password manager:

- legal vendor/certificate name;
- legal address, website, and product URL;
- primary technical and billing contacts;
- authorized NDA/MSA/SOW/PO signer;
- billing entity and payment method;
- export-control and source-handling constraints;
- desired submission window and approved budget;
- whether the certificate must cover only Linux aarch64/Omarchy hardware or
  additional operational environments;
- whether v4 must retain a classical-plus-PQ hybrid or may use the proposed
  ML-KEM-only first profile.

## Current accredited shortlist

The official NVLAP directory was checked on 2026-09-01 under ITST:
Cryptographic and Security Testing for both ACVT and Cryptographic Modules -
Module Testing. Accreditation confirms scope, not current PQ staffing,
availability, price, or fitness.

| Laboratory | NVLAP code | Directory observation |
| --- | --- | --- |
| Acumen Security | 201029-0 | Commercial testing service; ACVT and all-level/all-type module scope; displayed CST expiry 2027-06-30 |
| Gossamer Security Solutions | 200997-0 | Commercial; both scopes; displayed CST expiry 2027-09-30 |
| Penumbra Security | 200983-0 | Commercial; both scopes; displayed CST expiry 2026-12-31 |
| Lightship Security | 600207-0 | Commercial; both scopes; displayed CST expiry 2026-12-31 |
| AEGISOLVE | 200802-0 | Commercial; both scopes; displayed CST expiry 2026-12-31 |

Re-query the [official NVLAP directory](https://www-s.nist.gov/niws/index.cfm?event=directory.search)
before sending and before signing. Require accreditation to remain active
through the expected Production ACVTS and submission dates.

## Identical RFQ text

Subject: RFQ — ANUBIS v4 Linux/Rust FIPS 140-3 Level 1 Full Submission

We are seeking an NVLAP-accredited CST laboratory for pre-assessment,
cryptographic algorithm validation, entropy/RBG strategy, module conformance
testing, and a FIPS 140-3 Full Submission for a new software cryptographic
module.

The proposed boundary is one versioned Linux shared library. The CLI, desktop
application, Omarchy plugin, filesystem handling, and legacy v3 implementation
are outside the boundary. The lowest-risk proposed suite uses ML-KEM-1024,
AES-256-KW, AES-256-GCM, HMAC_DRBG/SHA2-512, ML-DSA-87, and required
SHA2/SHA3/SHAKE/HMAC prerequisites. No production v4 wire format or
cryptographic provider has been frozen; we want a written architecture
checkpoint before implementation compatibility commitments.

Please quote and describe:

- a fixed-scope architecture/gap assessment before implementation freeze;
- current hands-on FIPS 203/204 ML-KEM/ML-DSA and Rust/Linux experience;
- Production ACVTS registrations, prerequisite algorithms, adapter/IUT
  equivalence approach, and responsibility split;
- entropy-source, SP 800-90B/90C, ESV, HMAC_DRBG, and Linux getrandom strategy;
- software integrity, self-test, service-indicator, SSP, zeroization, and
  operational-environment recommendations;
- remote versus on-site test-environment requirements;
- Full Submission testing/report/MIS/Security Policy/Web Cryptik deliverables;
- schedule, current capacity, dependencies, and accreditation validity through
  submission;
- fixed lab fees, contingent fees, included remediation rounds, retest/change
  orders, NIST CR pass-through, possible ECR allocation, and payment milestones;
- NDA, source-code handling, data residency, export, and deletion terms;
- CMVP coordination support and post-validation change/revalidation support;
- any technical choice in the attached profile that you would require us to
  change before suite freeze.

Please separate laboratory fees from NIST cost-recovery fees and identify every
assumption that can change price or schedule.

## Attachments for the first call

- this RFQ;
- [program status](program-status.json);
- [source snapshot](SOURCES.md);
- [readiness register](READINESS.md);
- [candidate boundary](MODULE-BOUNDARY.md);
- [algorithm profile](ALGORITHM-PROFILE.md);
- repository commit and clean/dirty status;
- current architecture, API, dependency, build, and threat-model documents.

Do not send private identities, ProtonPass exports, production ciphertext,
customer data, or unrelated machine state. Use disposable test fixtures and
the laboratory's approved secure source-transfer channel after an NDA.

## Commercial reality

NIST's current 2026 Full Submission Security Level 1 fee table lists a
$16,000 cost-recovery fee and a possible $3,000 extended-cost-recovery fee.
Laboratory fees are separate and are only known after quotes. NIST review does
not begin until its applicable payment is confirmed. This file does not
authorize a lab contract, purchase order, invoice, or payment.

Source: [NIST cost-recovery fees](https://csrc.nist.gov/projects/cryptographic-module-validation-program/nist-cost-recovery-fees)
and [CST laboratory fees](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/cst-lab-accreditation-and-fees).

## Award gate

Before award, compare proposals on written technical fit, accreditation
duration, PQC staffing, entropy plan, total fee structure, remediation terms,
schedule, source handling, and CMVP coordination ownership. Require the chosen
lab to return a signed architecture-decision record before v4 production bytes
or the module version are frozen.
