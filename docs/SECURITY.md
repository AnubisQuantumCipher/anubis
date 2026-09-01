# Security Policy and Threat Model

ANUBIS 2.1.0

This document states what ANUBIS is intended to guarantee, what those
guarantees rest on, and what assurance the implementation actually carries. It
is written to be read before deciding to rely on this software, and it does not
overstate.

---

## 1. Assurance statement

Read this section first. It is the part most likely to matter to you.

**ANUBIS has not undergone a third-party cryptographic audit.** No independent
firm or individual has reviewed its design or its implementation under a formal
engagement. There is no audit report, because there has been no audit. If you
require audited software, ANUBIS does not currently meet that requirement, and
no amount of the rest of this document changes that.

**ANUBIS is not FIPS 140-3 validated.** ML-KEM-1024 and ML-DSA-87 are NIST
post-quantum Category 5 parameter sets, but an algorithm standard and a
validated cryptographic module are not the same claim. FIPS 140-3 defines
Security Levels 1 through 4; there is no Level 5. ANUBIS has no CMVP
certificate and v3 has no approved-only mode. The normative claim taxonomy,
formal harness inventory, non-claims, and additive v4 candidate architecture
are maintained in [ASSURANCE.md](ASSURANCE.md).

**ANUBIS composes audited and standardised primitives; it does not implement
them.** All cryptographic operations are delegated to established Rust
libraries. ANUBIS supplies the protocol around them: the KEM combiner, the
header format, the key encodings, the file handling. That is a meaningful
reduction in risk surface, and it is important to be precise about what it does
and does not buy:

- What it buys: the primitives themselves, the ChaCha20 permutation, the
  Poly1305 MAC, the X25519 scalar multiplication, the ML-KEM and ML-DSA
  lattice arithmetic, SHA-2, HMAC, HKDF, are not novel code written for this
  project. They come from the RustCrypto organisation and `dalek-cryptography`,
  are widely deployed, and several have had independent review.
- What it does not buy: composition bugs are the most common source of real
  cryptographic failures, and composition is exactly the part ANUBIS wrote.
  Nonce management, key separation, the order of MAC and signature
  computation, transcript binding, the final-chunk rule, parser strictness. A
  correct primitive used incorrectly is insecure. That code is unaudited.

**Where the risk actually concentrates.** Being specific is more useful than a
blanket disclaimer. The parts of ANUBIS most likely to contain a
security-relevant defect, in rough descending order:

1. **The header parser.** It processes attacker-controlled bytes before any
   authentication has succeeded. It is the only code that must be correct
   against wholly hostile input with no key material involved.
2. **Nonce discipline in wrapping.** The all-zero wrapping nonce
   (`FORMAT.md` section 6.2) is safe only because every recipient block gets a
   fresh ephemeral keypair. A refactor that cached or reused an ephemeral
   across recipients or messages would be catastrophic and would not fail any
   round-trip test.
3. **The final-chunk rule.** A reader that infers "final" from a short read
   rather than from lookahead accepts truncated files silently
   (`FORMAT.md` section 8.3). This is a well-known way to get STREAM wrong.
4. **Partial output on failure.** Payload chunks authenticate one at a time, so
   an online AEAD can in principle release plaintext before the whole file is
   authentic (`FORMAT.md` section 9). The reference implementation closes this
   for both destinations: a file destination is written as a temporary beside
   the destination and renamed only after the payload authenticates and the
   signature policy passes, and a stdout destination is streamed into an
   unlinked scratch file and copied out only after the same checks. A failed
   decryption emits nothing, to a path or to a pipe. The remaining exposure is
   that this is implementation behaviour rather than a format guarantee, so a
   consumer of any ANUBIS implementation must still check the exit status.
5. **Key handling at rest.** Identity file permissions, zeroization coverage,
   and the absence of any passphrase protection.
6. **Signature policy at the call site.** The format cannot make a signature
   unstrippable (section 2.4). Whether a downgraded container is caught depends
   entirely on the caller passing `--require-signature` or `--signer`, which is
   a decision outside the cryptography.

The format specification states each of these as a normative requirement so
that implementations and machine-checkable properties have an exact target.
It is not equivalent to an audit or certification. Bounded Kani harnesses cover
selected production arithmetic, nonce, armor-state, parser, and publication
gates; ordinary adversarial and interoperability tests cover other boundaries.
Neither evidence class proves the whole cryptosystem. [ASSURANCE.md](ASSURANCE.md)
records the precise scope instead of collapsing all of it into “formally
verified.”

**What an adversarial review has already changed.** The following were real
defects, found by adversarial review of this implementation and closed. They
are listed because "we fixed some things" is not useful to a reviewer and the
specifics are:

- **The header MAC now covers the raw on-disk header bytes**, exactly as read,
  rather than a canonical re-serialisation of the parsed fields. Under the old
  behaviour an attacker holding no keys at all could append trailing whitespace
  anywhere in an unsigned header and the file still decrypted, because the
  re-serialisation discarded the whitespace before the MAC saw it. That
  falsified the documented property that any header modification is detected.
  For a conforming file the MAC value is unchanged, so this is a tightening and
  not a wire-format break.
- **Header lines must be canonical.** A CR, or any trailing whitespace, on any
  header line is now rejected outright rather than trimmed. Malleable
  serialisation is what made the previous item exploitable, so both halves were
  fixed.
- **The parser is bounded.** `MAX_HEADER_LINE` is 8192 bytes and `MAX_STANZAS`
  is 1024. Without the first, a crafted file containing no newline caused an
  unbounded read; without the second, a header naming a million recipients
  forced a million decapsulations, which is the expensive half of parsing a
  hostile header. Both are refusals before any key is involved.
- **ASCII armor is capped** at 16777216 bytes of armored text, because armored
  input is buffered and base64-decoded whole before any key is involved
  (`FORMAT.md` section 9). Write and read measure the same quantity against the
  same limit, so armoring cannot produce a container that then fails to read:
  12383906 bytes of plaintext armors to exactly 16777216 bytes and round-trips,
  12383907 is refused before anything is written. A 256 MiB armored file
  presented to `decrypt` is refused having peaked between 14.3 and 19.5 MiB
  resident across six runs.
- **Secrets are created at mode 0600 with `create_new`**, rather than written
  and then `chmod`-ed. The old order left a private key world-readable under a
  typical `umask` for the duration of the write, and `create_new` additionally
  refuses to follow a pre-planted symlink at the destination. Decrypted
  plaintext now lands at 0600 as well, on the grounds that the output of a
  decryption tool is sensitive by default.
- **`--require-signature` and `--signer` were added**, because the format
  cannot prevent a recipient from stripping a signature and nothing existed to
  let a caller insist on one. See section 2.4.
- **Input geometry now comes from the same open file handle as the bytes.** A
  pathname replacement between `open` and `metadata` can no longer make the
  payload/trailer boundary describe a different file. Sized full-container
  operations also consume to EOF and reject a length mismatch.
- **Hostile header text is escaped in diagnostics.** Unknown version and stanza
  lines no longer carry raw terminal control bytes into human-mode errors.
- **Independent verification no longer needs a second unbounded binary-container copy.**
  The Python verifier reads a bounded header, streams binary hashing, and scans
  armored lines without allocating one object per attacker-supplied line. The
  shell verifier binds every read to one Linux file descriptor, rejects
  before/after metadata changes, streams its preimage, and creates fixed-name
  intermediates only in a fresh private directory. Sparse/short-line memory
  tests and a deterministic path-replacement regression enforce those
  boundaries without retaining a second container.
- **Config and state directory parents are private.** Direct CLI setup and the
  installer both enforce mode `0700` on the config, identity, and audit-state
  directories; secret files and the audit log remain mode `0600`.
- **Audit writes refuse pathname redirection.** On Unix the log is opened with
  no-follow semantics, must be a regular single-link file, and is tightened to
  mode `0600` through the open handle. A symlinked private state directory is
  refused, and audit refusal never changes the cryptographic operation result.
- **Secret-looking identity arguments are redacted at every diagnostic edge.**
  Recipient, signer, name, and parser mistakes cannot reflect an
  `ANUBIS-SECRET-KEY-1...` capability into terminal output, JSON errors, or new
  audit records. Public names and labels reject that marker anywhere rather
  than only at the first byte, and legacy capability-bearing filenames are
  ignored. Signer pins are validated and canonicalized before reuse.
- **Human-mode paths are terminal-safe.** Control-bearing pathnames remain
  unchanged for filesystem operations; structured output redacts any embedded
  secret-identity capability, and human result/error rendering escapes controls
  rather than executing them in a terminal. Parser errors suppress
  control-bearing command-line values entirely.
- **Unsized verification is linear under tiny reads.** The delayed-trailer
  reader reuses its refill allocation, so a one-byte producer no longer causes
  a large zero-filled extension on every read; the adversarial multi-chunk
  matrix includes that producer.
- **Desktop decrypts are content-bound.** The desktop requires a current full
  inspection and always passes its content ID back to decrypt. File replacement
  invalidates inspection and signature attestations; signer and signature
  policy are snapshotted across overwrite confirmation. Structured paths remain
  exact across QML and local IPC, while authorship wording requires a successful
  content-and-signer-bound verification.
- **Desktop local IPC uses a private runtime boundary.** Single-instance
  requests use a mode/owner-checked runtime directory, bounded JSON frames, a
  matching request acknowledgement, and a launch lock that serializes stale
  socket removal with listen. If that boundary is unavailable, forwarding is
  disabled rather than falling back to a public predictable socket.

**Status of the primitive crates.** Several of the pure-Rust post-quantum
implementations ANUBIS depends on carry pre-1.0 version numbers and their own
authors' cautions about maturity. The `ml-kem` and `ml-dsa` crates are recent
implementations of recently finalised standards. They are not as
battle-tested as X25519 or ChaCha20-Poly1305. This is a genuine and current
limitation, and it is one of the reasons the construction is hybrid rather than
post-quantum only: see section 4.

---

## 2. Security goals

Each goal is stated with the assumption it rests on. If the assumption fails,
the goal fails.

### 2.1 Confidentiality of the payload (IND-CCA2)

**Goal.** An adversary who does not hold any recipient identity learns nothing
about the plaintext beyond its approximate length, even when able to submit
chosen ciphertexts for decryption and observe whether they succeed.

**Rests on:**

- **Either** the Computational Diffie-Hellman / hashed-DH assumption in
  Curve25519, **or** the Module Learning With Errors (MLWE) assumption
  underlying ML-KEM-1024. Only one need hold; see section 4.
- The KEM combiner being a secure dual-KEM combiner. ANUBIS uses
  HKDF-SHA-512 over the concatenated shared secrets with the full recipient
  transcript as salt (`FORMAT.md` section 5.3). Transcript binding is what
  makes the combiner IND-CCA2 secure when either component is, and is what
  prevents ciphertext-substitution and re-encapsulation attacks against a
  naive shared-secret-only combiner.
- HKDF-SHA-512 behaving as a secure extract-then-expand KDF, and SHA-512 being
  collision and preimage resistant.
- ChaCha20-Poly1305 being a secure AEAD under RFC 8439, with no (key, nonce)
  pair ever repeating. Nonce uniqueness for the payload follows from the
  chunk counter; for the wrapping step it follows from wrap-key uniqueness,
  which follows from ephemeral freshness.
- The system CSPRNG producing unpredictable bytes. All ephemeral keys, file
  keys, and identity seeds come from the operating system's RNG. A
  compromised or predictable RNG defeats everything here.

**Explicitly not covered.** Length. See `FORMAT.md` section 14.2; plaintext
length is recoverable from file size.

### 2.2 Integrity and ordering of the payload

**Goal.** Any modification, truncation, extension, chunk reordering, chunk
duplication, or splicing of chunks between files is detected before the
affected plaintext is accepted.

**Rests on:** Poly1305 being a secure one-time MAC under a fresh key stream per
nonce; the STREAM construction's counter-in-nonce and final-flag encoding; and
the reader implementing the lookahead of `FORMAT.md` section 8.3.

**Caveat.** Detection is not prevention, and it is not repair. A file
destination never receives a partial plaintext, because decryption streams to a
temporary and renames only after the whole payload authenticates, and a stdout
destination streams into an unlinked scratch file and is copied out only after
the same checks pass, so no partial prefix escapes either. That is
implementation behaviour, not a format guarantee: check the exit status
regardless. See `FORMAT.md` section 9.

### 2.3 Integrity of the header, for recipients

**Goal.** A recipient detects any modification of the version line, any
recipient block, or the signature block, including removal of a recipient block
or removal of the entire signature block.

**Rests on:** HMAC-SHA-512 being a secure PRF/MAC; the MAC key being derived
from the file key by HKDF with a distinct `info` string; constant-time
comparison; and the MAC being computed over the **raw on-disk header bytes**
rather than over a re-serialisation of the parsed fields.

That last clause is load-bearing and was once wrong. When the MAC was computed
over a canonical re-serialisation, an attacker holding no keys could append
trailing whitespace anywhere in an unsigned header: the parser trimmed it, the
re-serialisation did not contain it, the MAC still matched, and the file
decrypted. The goal above was therefore false as written. Two changes make it
true: the MAC is taken over the bytes as read, and any header line carrying a
CR or trailing whitespace is rejected as non-canonical before the MAC is
consulted at all. The parser is also bounded, at `MAX_HEADER_LINE` = 8192 bytes
per line and `MAX_STANZAS` = 1024 stanzas, so a hostile header cannot exhaust
memory or force unbounded decapsulation work before authentication.

**Caveat, and it is a real one.** The header MAC key comes from the file key,
so **only a party who can decrypt can verify the header**. A non-recipient
cannot check header integrity at all. Furthermore, any recipient can forge a
header MAC, because every recipient learns the file key. The header MAC
authenticates the header to recipients as a group; it does not authenticate the
sender to anyone. Section 2.4 states what that costs.

### 2.4 Sender authentication (SUF-CMA), optional

**Goal.** When a signature is present, **anyone holding the bytes** can verify
that the holder of the corresponding ML-DSA-87 signing key produced **this
exact file**. Verification is keyless: the signature is over a digest of the
header and the payload ciphertext, and the verifying key travels in the
header, so a third party who cannot decrypt the container -- and should not be
able to -- can still establish its provenance (`anubis verify`, or
[VERIFYING.md](VERIFYING.md) for a stock-OpenSSL recipe). Concretely: the
signature is over `SHA-512(header || payload_ciphertext)`, so it commits the
signer to the recipient set, the header, and every byte of ciphertext. Strong
unforgeability: an adversary cannot produce any new valid (message, signature)
pair, including a second signature on an already-signed file.

**Rests on:** ML-DSA-87 being SUF-CMA secure under FIPS 204, which rests on
MLWE and Module-SIS; SHA-512 being collision resistant, since a collision on
`S` would transfer a signature to a different file; correct use of the pure
(non-prehashed) variant with the context string `"anubis-v2-file"`; and the
signing key remaining secret.

**What this buys, specifically.** Because the signature covers the ciphertext
and not merely the header, a *recipient* cannot re-author the payload under the
sender's signature. This matters because every recipient learns the file key
and can otherwise produce ciphertext at will. Had the signature covered only
the header, one recipient of a multi-recipient file could substitute arbitrary
content and other recipients would see it as validly signed by the sender.
Covering the ciphertext closes that, and it is the reason signing is the
stronger mode for multi-recipient files.

**Caveats:**

- **An unpinned valid signature says almost nothing.** It proves that *someone*
  holding *some* ML-DSA-87 key signed this file. It is not evidence of who,
  because ANUBIS has no PKI, no web of trust, no key transparency, and no
  revocation. Binding a verifying key to a person is entirely the operator's
  problem. `decrypt` reports the signer's fingerprint, in human output and as
  `signer_fingerprint` in `--json`, so that a caller can compare it against a
  fingerprint confirmed out of band; `--signer FINGERPRINT` makes the
  comparison a precondition rather than an afterthought. Until it is pinned to
  a key you have independently confirmed, treat "signature verified" as
  "well-formed", not as "authentic".
- **A recipient can strip the signature. This is not preventable in-format.**
  Every recipient learns the file key, and therefore holds the header MAC key.
  Any recipient can construct a container over the same content with the
  `mldsa87` stanza removed, a header MAC recomputed to match, and the 4627-byte
  trailer dropped, and pass it on as a perfectly valid unsigned container.
  Nothing in the format detects this, because there is nothing left to detect:
  the result is an ordinary unsigned file, indistinguishable from one that was
  never signed. Demonstrated end to end on this machine, without touching any
  internals -- a recipient decrypted a signed container and re-encrypted the
  identical plaintext without `--sign`; the downgraded container decrypted
  cleanly downstream, byte-identical content, `signed: false`.

  **The mitigation is entirely at the call site.** `--require-signature` exits 1
  on an unsigned container, and `--signer FINGERPRINT` exits 1 unless the
  signature is present, valid, and by that key; neither writes plaintext on
  failure. Both refused the downgraded container above. If the consumer of a
  file does not pass one of them, a signature is an advisory label that any
  recipient can peel off. Do not read the presence of signing support as
  meaning signatures cannot be removed.
- **No freshness or context.** A signature attests that the key produced these
  bytes. It carries no timestamp, no expiry, and no statement about intent or
  about when the file should be considered current. An old signed file replays
  perfectly. Read it as "this key produced these exact bytes", not as a dated,
  contextual assertion.
- **Verification needs the whole file.** The signature is a trailer covering
  the ciphertext, so it cannot be checked on a partial file, and a reader must
  not release plaintext before verifying. The reference implementation achieves
  this on non-seekable input without buffering the plaintext, by peeling the
  fixed-length trailer through a delay reader; see `FORMAT.md` sections 9 and
  10.5.
- **Signing removes deniability.** The guarantee is strong and publicly
  verifiable, which is the same thing as saying it is undeniable. See 2.5.

### 2.5 Non-goals

ANUBIS does not attempt, and MUST NOT be relied on for: metadata
confidentiality, length hiding, recipient-count hiding, forward secrecy against
identity compromise, post-compromise security or ratcheting, deniability,
replay or freshness protection, passphrase protection of identities at rest,
availability, resistance to an adversary with code execution or memory access on
the machine, or resistance to a compromised CSPRNG. `FORMAT.md` section 14.2
enumerates these with reasons.

Note that non-repudiation is **not** in this list. A signature does commit the
signer to the exact file, so it is closer to non-repudiation than a header-only
signature would be. It is still not a dated or contextual assertion, there is
no PKI binding the key to a person, and any recipient can strip it before
passing the file on (2.4), so do not treat it as a legal instrument. What a
signature can support is the narrow claim "the holder of this key produced
these exact bytes", asserted only about a file you received signed and pinned
with `--signer`.

---

## 3. Threat model

### 3.1 Adversaries in scope

| Adversary | Capability | Outcome |
|---|---|---|
| Passive network or storage observer | Reads ciphertext | Learns plaintext length, recipient count, whether signed, and the signer's verifying key. Learns nothing of payload content. |
| Active tamperer | Modifies ciphertext at rest or in flight | All modifications detected by a recipient, including trailing whitespace or a CR anywhere in the header, which is now rejected as non-canonical. No output is produced on failure, to a path or a pipe. May always deny access. |
| Chosen-ciphertext attacker | Submits crafted files, observes success or failure | No advantage, given IND-CCA2 of the combiner. Failure reporting is deliberately coarse: ML-KEM implicit rejection is never surfaced separately from unwrap failure. |
| Future quantum adversary with recorded ciphertext | Runs Shor and Grover against a stored file | Breaks X25519. Must still break ML-KEM-1024. See section 4. |
| Malicious sender | Sends a file to a recipient | Can send anything. A signature identifies which key sent it, if the key is recognised. |
| Malicious recipient (multi-recipient file) | Holds one valid identity | Learns the file key, hence the payload; can forge header MACs and author new files under the same file key. Cannot produce a validly *signed* file under someone else's key, since the signature covers the ciphertext. **Can** strip the signature and hand on a valid unsigned container; only `--require-signature` or `--signer` at the consumer catches that. Multi-recipient encryption is not compartmentalisation. |

### 3.2 Adversaries out of scope

Out of scope means ANUBIS offers no defence, not that the risk is unimportant.

- **Local code execution or memory access** on a machine while an identity is
  loaded. Zeroization reduces the window; it does not close it. Swap, core
  dumps, hibernation images, and debuggers can all capture key material.
- **Filesystem read access** to `~/.config/anubis/identities/`. Identity files
  are protected by mode `0600` in a `0700` directory and nothing else. There is
  no passphrase. An adversary who reads the file has full decrypt and sign
  capability, because identities are capability-complete. What *is* defended is
  the creation window: secrets are created with `create_new` at mode `0600` in
  a single step, rather than written and then `chmod`-ed, so the content is
  never briefly world-readable under a permissive `umask` and the write cannot
  be redirected through a symlink planted at the destination. Decrypted
  plaintext is created the same way. An identity's `Debug` formatting is
  redacted, so key material cannot reach a log line by accident.
- **Physical side channels**: timing, cache, power, electromagnetic. Constant
  time is required for MAC and fingerprint comparison and expected of the
  primitive crates, but ANUBIS makes no side-channel claim and has not been
  tested for one.
- **Supply chain**: a compromised dependency, a compromised toolchain, or a
  compromised build host. `Cargo.lock` pins versions; nothing here defends
  against a malicious upstream release.
- **A compromised CSPRNG.** Everything depends on it.
- **Coercion of a key holder.** No amount of cryptography addresses this, and
  the absence of deniability means the format offers no help.
- **Traffic analysis.** Who sent what to whom, when, and how large, is all
  visible to an observer of the transport, and partly visible in the file
  itself.

---

## 4. Why hybrid

### 4.1 The construction

Every ANUBIS file is encrypted under a key derived from **both** an X25519 key
agreement and an ML-KEM-1024 encapsulation. The two shared secrets are
combined with HKDF-SHA-512, and the wrapped file key is recoverable only from
the combined output.

The consequence is the point of the whole design: **an attacker must break both
X25519 and ML-KEM-1024.** Breaking either one alone yields nothing. The
combiner is secure as long as at least one component KEM is secure.

This is a deliberate hedge in two directions at once, and it is worth stating
both because they point opposite ways:

- **X25519 protects against ML-KEM being wrong.** ML-KEM-1024 standardises a
  lattice construction finalised in 2024. The MLWE assumption is far less
  studied than discrete log, and the pure-Rust implementations of it are new.
  Should a cryptanalytic advance or an implementation flaw weaken the
  post-quantum half, files remain protected by well-understood elliptic-curve
  cryptography.
- **ML-KEM protects against X25519 being broken by a quantum computer.** A
  sufficiently large quantum computer running Shor's algorithm would break
  X25519 outright. Should that happen, files remain protected by the lattice
  half.

Neither half is trusted alone. That is the entire argument for accepting the
size cost of a 2344-byte header.

### 4.2 What the quantum threat actually is

Being accurate here matters more than being alarming.

**No cryptographically relevant quantum computer is known to exist.** Publicly
known quantum hardware is many orders of magnitude short of what breaking
X25519 would require, in both qubit count and error rates. Nobody is decrypting
X25519 traffic with a quantum computer today, as far as is publicly known.
ANUBIS is not a response to a present break, and any tool marketed as such
would be misrepresenting the situation.

**The actual threat is store-now-decrypt-later.** An adversary can record
encrypted traffic or seize encrypted storage today, retain it, and decrypt it
years from now if a capable quantum computer is eventually built. That threat
is real *now*, because the recording happens now, and no later change of
software can protect data an adversary already holds. This is why post-quantum
encryption is worth adopting before quantum computers exist, and it is the only
threat model under which ANUBIS offers an advantage over well-implemented
classical encryption.

The practical question is therefore not "is X25519 broken" but "how long must
this data stay confidential, and could someone be keeping a copy". If the
answer is "a few days" or "nobody is recording it", classical encryption is
sufficient and simpler. If the answer is "decades" and the data is being
transmitted or stored somewhere an adversary could retain it, hybrid PQC is a
rational hedge. Choose accordingly rather than by default.

**Signatures are a different case, and a weaker argument.** Store-now-decrypt-
later does not apply to signatures: a signature verified today cannot be
retroactively forged by a future quantum computer, because forging it later
does not help an attacker who needed it accepted at the time. ML-DSA-87 is
included for long-lived authentication, where a signature must still be
unforgeable decades hence, and for suite consistency. The urgency argument for
post-quantum signatures is genuinely weaker than for encryption, and this
document does not pretend otherwise.

### 4.3 Comparison with other tools

Stated factually. **None of the tools below is broken, and this document does
not claim otherwise.** They make different, defensible choices.

| Tool | Key exchange / encryption | Post-quantum | System dependencies |
|---|---|---|---|
| `age` / `rage` | X25519 | No | None (`rage` is pure Rust) |
| GnuPG | RSA, or ECC including Curve25519 | No (classical algorithms) | libgcrypt and others |
| `anubis-rage` 1.4.0 | X25519 + Kyber via liboqs | Yes | liboqs (C) |
| ANUBIS 2.1.0 | X25519 + ML-KEM-1024, pure Rust | Yes | None |

Accurate characterisations, to avoid the usual unfair comparisons:

- **`age` and `rage` use X25519 and are not quantum-resistant.** They are also
  excellent, simple, widely reviewed tools whose format ANUBIS's header
  deliberately resembles. `rage` in particular is pure Rust with no system
  dependencies. If store-now-decrypt-later is not in your threat model, `age`
  is a very reasonable choice and is more mature than ANUBIS.
- **GnuPG uses RSA or elliptic-curve cryptography,** neither of which is
  quantum-resistant. GnuPG is vastly more featureful than ANUBIS, has decades
  of deployment and scrutiny, and solves key distribution and revocation
  problems that ANUBIS does not attempt at all. Its complexity is the cost of
  that scope.
- **What ANUBIS actually offers over these** is narrow and should be judged
  narrowly: hybrid post-quantum key encapsulation, in a small format, with no
  system dependencies. Its disadvantages are equally concrete: no audit, far
  less deployment, a larger header, no key management, no passphrase
  protection, and no ecosystem.

Being newer is not an advantage. Choose ANUBIS if hybrid PQC with zero system
dependencies is specifically what you need; choose a mature tool otherwise.

---

## 5. Cryptographic dependencies

Security rests on these implementations. Each is a pure-Rust crate; there is no
C code and no system cryptographic library in the dependency graph.

| Purpose | Crate | Standard |
|---|---|---|
| X25519 key agreement | `x25519-dalek` | RFC 7748 |
| ML-KEM-1024 | `ml-kem` | FIPS 203 |
| ML-DSA-87 | `ml-dsa` | FIPS 204 |
| ChaCha20-Poly1305 | `chacha20poly1305` | RFC 8439 |
| SHA-2, HMAC, HKDF | `sha2`, `hmac`, `hkdf` | FIPS 180-4, RFC 2104, RFC 5869 |
| Bech32m key encoding | `bech32` | BIP-350 |

ANUBIS writes Bech32m. Its readers retain one-way compatibility with legacy
BIP-173 Bech32 checksums and canonicalize accepted keys back to Bech32m.

A vulnerability in any of these is a vulnerability in ANUBIS. `Cargo.lock` is
committed so that builds are reproducible and so that a dependency advisory can
be mapped to an exact version.

---

## 6. Operational guidance

The format cannot enforce these. They are where practical security is usually
won or lost.

- **Back up identity files, and test the restore.** Losing an identity means
  permanently losing access to everything encrypted to it. There is no
  recovery, no escrow, and no key derivation from a passphrase. The
  230-character identity string is short enough to be written on paper
  deliberately.

  An identity is a single file, `~/.config/anubis/identities/<name>.key`. To
  back one up and prove the backup works:

  ```sh
  # 1. Copy the identity somewhere durable and offline.
  cp ~/.config/anubis/identities/default.key /mnt/backup/

  # 2. Record the two fingerprints separately from the key, so a restored
  #    file can be recognised as the right one.
  anubis status --json | jq -r '.identities[] | "\(.name) \(.fingerprint) \(.signing_fingerprint)"'

  # 3. TEST THE RESTORE, in a scratch HOME, before you need it.
  #    An untested backup is a belief, not a backup.
  export HOME=$(mktemp -d)
  mkdir -p "$HOME/.config/anubis/identities"
  cp /mnt/backup/default.key "$HOME/.config/anubis/identities/"
  chmod 700 "$HOME/.config/anubis" "$HOME/.config/anubis/identities"
  chmod 600 "$HOME/.config/anubis/identities/default.key"
  anubis status                      # fingerprints must match step 2
  anubis decrypt --identity default some-real-container.anubis -o /dev/null
  ```

  Restoring is exactly that copy plus those modes: mode `0600` in a `0700`
  directory. Nothing else is required, and nothing in the file depends on the
  machine that made it.

- **Keep a container you can re-open as a canary.** A backup that restores a
  file which no longer decrypts anything is not a backup. Step 3 above is the
  whole test, and it costs one command.
- **Verify recipients out of band by fingerprint.** Confirm the 80-bit
  `ANUBIS-FP` over a channel the adversary does not control. Accepting a
  recipient from an untrusted channel means encrypting to whoever supplied it.
  Do not skip this because the Bech32 string "looks right": a recipient's
  Bech32 checksum guarantee is degraded at 2573 characters
  (`FORMAT.md` section 11.1), which is exactly why the fingerprint exists.
- **Treat identity files as the crown jewels.** Mode `0600`, in a `0700`
  directory, on encrypted storage, never in a repository, never in a cloud
  sync folder, never pasted into a chat. One leaked identity is both decrypt
  and sign capability.
- **Check exit status, always.** No ANUBIS output, to a file or a pipe, should
  be treated as authentic without it. The reference implementation withholds
  output until everything verifies, so in practice a non-zero exit comes with
  nothing to discard, but that is a property of this implementation and not of
  the format: another conforming implementation may stream straight to the pipe.
  See `FORMAT.md` section 9.
- **Treat forced termination as an abnormal recovery case.** `SIGINT` and
  `SIGTERM` are handled cooperatively and remove an owned output sidecar when
  the engine reaches an I/O boundary. A silent pipe whose read is restarted by
  the operating system may need data or EOF before that boundary is reached.
  On an ordinary error, the sidecar name is removed while its protected handle
  is still open; on Windows that handle continues denying read/write sharing
  until removal has succeeded. If removal itself is refused, the implementation
  makes a best-effort truncation of unpublished staging data while the handle
  is still protected. A file already published through the atomic no-replace
  hard-link path is never truncated merely because sidecar cleanup failed.
  `SIGKILL`, a crash, or power loss cannot run cleanup and may leave a hidden,
  sidecar beside the intended destination. Unix creates it at mode `0600`;
  Windows denies read/write sharing while the staging handle is open, but a
  sidecar left after forced process death inherits the destination directory's
  ACL and must be treated as sensitive. It is never promoted to the
  destination name; remove it only after confirming no ANUBIS process still
  owns it.
- **Insist on the signature you are relying on.** `decrypt` verifies a
  signature that is present, but silently accepts a container that has none, and
  any recipient can strip one (2.4). If a workflow's security argument depends
  on a file having come from a particular sender, pass
  `--signer FINGERPRINT` with a fingerprint you confirmed out of band. Pass
  `--require-signature` when you need *some* signature but pin the key
  elsewhere. Reading `signed: true` after the fact is weaker: it tells you the
  file you happened to receive was signed, not that an unsigned substitute
  would have been rejected.
- **Do not compare a recipient fingerprint with a signer fingerprint.** They
  are separate namespaces over different keys. One identity has both and they
  differ. `status --json` reports them as `fingerprint` and
  `signing_fingerprint`; `--signer` takes the latter.
- **The short fingerprint is a human handle, not a Category-5 identifier.**
  `ANUBIS-FP` is deliberately an 80-bit, transcribable prefix. The v3
  `--signer` policy inherits that reduced binding strength even though the
  embedded ML-DSA key and signature are much stronger. Do not describe a
  fingerprint match itself as post-quantum Category 5. A future format/profile
  must add domain-separated full-length recipient and signer identifiers while
  retaining the short form only for display and error detection.
- **Rotate identities if retrospective compromise matters.** There is no
  forward secrecy against identity compromise. Rotating and re-encrypting
  archives bounds the damage of a future key theft.
- **Sign only when attribution is wanted.** A signature is a public, linkable
  statement that a particular key produced the file.
- **Do not encrypt many tiny files individually.** The fixed header dominates:
  a 1 KiB file becomes 3384 bytes. Encrypt an archive.
- **Do not armor bulk data.** Armor buffers and is capped at 16777216 bytes of
  armored text, roughly 11.8 MiB of plaintext. Binary output is
  constant-memory at any size. Armor is for pasting a short container into a
  message, not for transporting archives.
- **Keep dependencies current.** `cargo update` and `cargo audit`.

---

## 7. Reporting a vulnerability

Security reports are welcome and will be handled seriously.

**Do not open a public issue for a security vulnerability.** Public disclosure
before a fix exists puts users at risk.

**How to report.** Open a private security advisory through the repository's
GitHub Security tab, using "Report a vulnerability". This creates a private
channel between reporter and maintainer and is the preferred route.

**What to include.** The more of this you can provide, the faster a fix
happens:

- ANUBIS version (`anubis status`) and the affected component: format,
  implementation, CLI, or plugin.
- A description of the issue and the security property you believe it
  violates, referencing `FORMAT.md` where applicable.
- Reproduction steps, ideally a minimal test case. Where a test file is
  involved, include it, generated with throwaway keys only.
- Your assessment of impact and of any preconditions an attacker needs.
- Whether you intend to disclose publicly, and on what timeline.

**Never include real identity strings, real recipient keys, or real encrypted
data in a report.** Generate fresh throwaway keys to demonstrate an issue.

**What to expect.**

| Stage | Target |
|---|---|
| Acknowledgement of receipt | 72 hours |
| Initial assessment and severity | 7 days |
| Fix, or a plan with a date | 30 days for high severity |
| Coordinated public disclosure | By agreement, default 90 days |

This is a small project and these are targets, not contractual commitments. If
a report goes unacknowledged past 14 days, escalating by opening a public issue
that says only that an unacknowledged security report exists, with no technical
detail, is a reasonable step.

**In scope:** anything violating a stated goal in section 2; format ambiguities
allowing a conformant implementation to be insecure; parser flaws reachable
before authentication; nonce or key reuse; failures to detect tampering or
truncation; partial plaintext leakage beyond what section 9 documents;
incorrect file permissions or key material reaching logs, the audit stream, or
the terminal unexpectedly.

**Out of scope:** the absence of features documented as non-goals in section
2.5; vulnerabilities in dependencies, which should be reported upstream, though
telling us so we can bump the pin is appreciated; the "no audit" status itself;
the documented store-now-decrypt-later reasoning; theoretical attacks requiring
a quantum computer against the hybrid construction as a whole; anything
requiring local code execution or read access to identity files.

**Credit.** Reporters will be credited in the fix's release notes unless they
ask not to be. There is no bug bounty; this project has no funding for one, and
saying so plainly is better than implying otherwise.

---

## 8. Version support

Only the latest release receives security fixes. There are no long-term
support branches.

`anubis-rage` 1.x and 1.4.0, and both wire formats they wrote
(`anubis-encryption.org/v1` and `anubis-encryption.org/v2`), are **end of life**
and receive no security fixes. They could not be installed on Omarchy in the
first place, because liboqs is not available; see `MIGRATION.md`. Migrate.

The 2.x line writes `anubis-encryption.org/v3`. Note that the wire format is
v3 while the software is 2.x: the predecessor spent the v1 and v2 identifiers
on two incompatible formats. `FORMAT.md` section 15 documents this.

---

## 9. Summary

- No third-party audit. None. Weigh that.
- Not FIPS 140-3 validated; no CMVP certificate or approved-only v3 mode.
- Category 5 describes the ML-KEM-1024 and ML-DSA-87 parameter sets, not a
  nonexistent FIPS module level.
- Audited, standardised primitives; unaudited composition around them.
- Storage-guarded model checking covers stated implementation properties only;
  see `ASSURANCE.md` for each proof, reachability gate, and non-claims.
- Hybrid: an attacker must break both X25519 and ML-KEM-1024.
- No cryptographically relevant quantum computer is known to exist. The threat
  addressed is store-now-decrypt-later, not a present break.
- Other tools are not broken. They make different tradeoffs.
- Payload content is protected. Metadata, length, and recipient count are not.
- No forward secrecy against identity compromise, no deniability, no replay
  protection, no passphrase on identities. Signatures do commit the signer to
  the exact file, but carry no timestamp and no identity binding.
- **A signature is not unstrippable.** Any recipient can hand on a valid
  unsigned container carrying the same content, and the format cannot detect
  it. An unpinned valid signature proves only that someone holding some
  ML-DSA-87 key signed the file, not who. Use `--require-signature`, or
  `--signer` with a fingerprint confirmed out of band, or do not rely on
  signatures at all.
- An adversarial review closed real defects in the header MAC, header
  canonicalisation, parser bounds, armor bounds, and secret file creation.
  Section 1 lists each one and what it allowed.
- Report vulnerabilities privately via GitHub Security Advisories.
