# Optional validation and audit sponsorship

Status: open to external sponsorship; no sponsor, funding commitment,
laboratory engagement, test identifier, CAVP certificate, audit report, or CMVP
certificate is currently recorded. ANUBIS engineering and release decisions do
not wait on this optional workstream.

People, companies, foundations, research groups, and other organizations may
offer to fund work that the project owner has chosen not to purchase directly.
Eligible scope can include:

- an independent cryptographic design, source, or interoperability review;
- an accredited CST-laboratory architecture assessment;
- Production ACVTS work for the exact implementation and operational environment;
- module testing, documentation, submission, and official CMVP coordination;
- licensing, controlled requirements access, reproducible build infrastructure,
  and bounded testing resources required by that external work.

## What sponsorship does not buy

Funding alone does not make ANUBIS compliant, approved, CAVP validated,
independently audited, or CMVP validated. It does not permit a positive badge,
certificate number, approved-mode indicator, endorsement, backdoor, weakened
algorithm, hidden change, release bypass, or private claim. Sponsors do not gain
authority to rewrite evidence, suppress findings, or override technical and
security review.

Every implementation or claim change remains subject to the repository's normal
review, tests, protected checks, public non-claims, and exact evidence boundary.
Official status can change only after the relevant authority publishes or the
independent reviewer delivers evidence for the exact version, boundary, and
operational environment being described.

## Activation gate

Before the dormant external workstream becomes active, record all of the
following without placing sensitive information in the public repository:

- a written funding commitment, authorized scope, budget owner, and conflict-of-interest terms;
- the project owner's explicit authorization for laboratory contact and spend;
- the exact review or validation target, deliverables, publication expectations,
  source-handling rules, and independence requirements;
- a fresh check of applicable NIST, CMVP, CAVP, NVLAP, and laboratory requirements;
- a reviewed transition of `program-status.json` that keeps every positive claim
  false until its own official evidence exists.

Use [GitHub issue 1](https://github.com/AnubisQuantumCipher/anubis/issues/1) for
public coordination. Do not post credentials, ProtonPass data, private keys,
production ciphertext, customer data, payment details, legal addresses, or
private contact information there. No payment account or fundraising provider
is implied by this policy.

The dormant [LAB-RFQ.md](LAB-RFQ.md) may be refreshed only after this activation
gate is satisfied. Until then, the exact status remains `sponsor-deferred`.
