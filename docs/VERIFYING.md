# Verifying an ANUBIS container without trusting ANUBIS

A signature is only as useful as an independent party's ability to check it.
This document is for that party: someone holding a `.anubis` container who
wants to know who produced it, and who has no reason to take the `anubis`
binary's word for anything.

Everything here is derivable from [`FORMAT.md`](FORMAT.md). Two worked,
tested implementations ship alongside it:

| | |
|---|---|
| [`verify/openssl-verify.sh`](verify/openssl-verify.sh) | POSIX shell + Linux `/proc` + stock OpenSSL ≥ 3.5. No ANUBIS code, no Rust, no Python. |
| [`verify/anubis-verify.py`](verify/anubis-verify.py) | Python 3 standard library, shelling out to `openssl` for the ML-DSA primitive. Written from the specification alone. |

Both refuse a tampered container and both agree with `anubis verify` on every
case in their test matrices.

Resource behavior is bounded deliberately. The Python verifier reads only the
maximum header prefix and streams a binary payload into SHA-512; armor remains
whole-buffered under the format's armor cap, but its lines are scanned without
materialising an attacker-sized list. The shell verifier opens the input once,
routes every utility through that Linux descriptor, rejects in-place metadata
changes, streams the signed preimage, and never retains a second
container-sized copy. Supplying its optional work-directory argument creates a
fresh private child beneath that directory, so fixed intermediate names cannot
follow pre-planted links.

The CI matrix also replaces the caller's input symlink in the middle of the
shell transcript check and requires the result to remain bound to the file
handle opened at startup. This is a regression test for consistency, not a
claim that mutable filesystems provide immutable snapshots.

---

## What can be checked without a key, and what cannot

| | Needs a key? | Why |
|---|---|---|
| ML-DSA-87 signature | **No** | Covers a digest of the header and the payload ciphertext; the verifying key travels in the header. |
| Signer fingerprint | **No** | SHA-256 over that same public key. |
| Header, payload, chunk accounting | **No** | Plain structure. |
| Header MAC (§7) | **Yes** | Keyed from the file key, which only a recipient can recover. |
| Plaintext | **Yes** | It is encrypted. |

So a third party can establish **who produced these exact bytes** and nothing
about their content. That is the whole of what a signature offers, and it is
worth being precise about the limits:

- A valid signature proves the holder of that ML-DSA-87 key produced this
  file. It does **not** say who that holder is. Compare the fingerprint
  against a value confirmed out of band, or you have authenticated nobody.
- **Absence of a signature carries no information.** Every recipient holds the
  file key and can therefore produce an unsigned container with the same
  plaintext and a recomputed header MAC. That result is indistinguishable from
  a file that was never signed. Require a signature up front (`--signer`);
  never infer anything from its absence.
- A signature carries no timestamp and no replay protection.

---

## The transcript, in full

This is the part a reimplementer needs and the part that is easy to guess
wrong. Two details defeat the obvious attempt:

**1. The message is a digest, not the file.** ML-DSA is used in its *pure*
(not pre-hashed) form, but the message handed to it is itself a 64-byte
SHA-512 digest:

```
S         = SHA-512( file[0 .. file_size - 4627) )       # 64 bytes
signature = file[file_size - 4627 .. file_size)          # 4627 bytes
```

`file[0 .. file_size-4627)` is exactly `header_bytes ‖ payload_ciphertext`,
because the header is a prefix of the file with no separator. Verifying over
any raw byte range of the file therefore fails by construction.

**2. There is a context string.** The 14 ASCII bytes `anubis-v2-file`
(`616e756269732d76322d66696c65`) are passed as the ML-DSA context to both sign
and verify. Omitting it fails. The `v2` is a fixed domain separator carried
over from the product name; it is **not** the wire-format version and is never
renamed.

There is no other preprocessing, no additional domain separation, and no
header-field subsetting.

---

## With stock OpenSSL

```sh
docs/verify/openssl-verify.sh container.anubis
ANUBIS_EXPECT_FP=A4DB-4D6C-B58D-2003-C7E6 docs/verify/openssl-verify.sh container.anubis
```

Exit `0` verified, `1` present-and-failed or pin mismatch, `2` unsigned or
malformed.

The three steps that are not obvious:

**Extract without a parser.** The MAC line is the first line matching
`^--- ` followed by 86 base64 characters; it is exactly 91 bytes including its
newline, so `header_len` is that offset plus 91. The verifying key is the 3456
base64 characters after the literal `-> mldsa87 `. Because 2592 is divisible
by 3, the unpadded base64 needs no `=` repair.

That deliberately small shell recipe is an independent signature-transcript
check, not a complete ANUBIS grammar validator. A valid signature over
non-canonical or otherwise malformed header bytes can still be cryptographically
valid. Use the independent Python parser or `anubis verify` when structural
validity is also required; neither can check the keyed header MAC without a
recipient identity.

**Wrap the key.** OpenSSL wants a DER `SubjectPublicKeyInfo`, with OID
`2.16.840.1.101.3.4.3.19` and the parameters field **absent** (not NULL). The
key length is fixed, so the whole SPKI is a constant 22-byte prefix followed by
the raw 2592 bytes:

```
30 82 0A 32 30 0B 06 09 60 86 48 01 65 03 04 03 13 03 82 0A 21 00
```

**Verify.** `-rawin` with **no** `-digest`; OpenSSL applies the FIPS 204
`M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M` encoding itself:

```sh
openssl pkeyutl -verify -pubin -inkey vk.der -keyform DER \
  -rawin -in S.bin -sigfile signature.raw \
  -pkeyopt context-string:anubis-v2-file
```

`-digest sha512` is not merely wrong; OpenSSL rejects it outright with
*"-digest (prehash) is not supported with ML-DSA-87"*, which is a useful
signpost that you are on the pre-hashed path by mistake.

---

## With the reference implementation

```sh
anubis verify container.anubis
anubis verify --signer A4DB-4D6C-B58D-2003-C7E6 container.anubis
anubis verify --json container.anubis
```

It needs no identity, decrypts nothing, and streams — a container larger than
memory, or arriving on a pipe, is fine. Exit `0` only when a signature is
present **and** valid **and**, if pinned, by that signer.

`--json` prints exactly one object:

```json
{"kind":"verify","ok":true,"signed":true,"signature_ok":true,
 "signer_fingerprint":"A4DB-4D6C-B58D-2003-C7E6","header_mac_ok":null, ...}
```

`signature_ok` is `true`, `false`, or `null`, and the three are distinct:
`null` means the check could not be made — an unsigned container, a truncated
file, a malformed header — and is never a pass or a failure. `header_mac_ok`
is always `null` here, because this command holds no key.

### Truncation, honestly

Truncation splits into two regimes and the tools report them differently:

- **Gross** — no room for a trailer, or a payload smaller than one AEAD tag —
  is structurally detectable and reported as an integrity failure, so a
  damaged file is not presented as a forged one.
- **Losing a few bytes off a long file** is *not* structurally detectable.
  What remains is a well-formed container whose digest no longer matches.
  Cryptography cannot distinguish that from an edit, and the verifier does not
  pretend to: it reports a signature that did not verify, which is exactly
  what it observed.

---

## In the desktop application

The container inspector reports a signature's **presence** and its
**validity** as separate states, because they are separate claims:

- `SIGNED — NOT VERIFIED HERE` — the header names a signer, and nothing has
  checked the signature. Drawn neutral. A **verify signature** button runs the
  check; it needs no key, so it is offered even for a container this vault
  cannot decrypt.
- `SIGNATURE VERIFIED — ML-DSA-87` — a verify ran over these exact bytes at a
  stated time and matched. Drawn in the accent colour, which on that surface
  means verified and nothing else.
- `SIGNATURE FAILED` — it ran and did not match. Drawn urgent.

The claim is always about a check that happened, never about the file's
general trustworthiness, and it is session state that is never persisted.
