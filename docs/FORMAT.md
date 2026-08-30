# ANUBIS/v3 File Format Specification

Wire format: `ANUBIS/v3`, version line `anubis-encryption.org/v3`
Reference implementation: ANUBIS 2.0.0
Status: stable
Encoding of this document: US-ASCII

**The format version and the software version are independent, and they do not
match.** The wire format is **v3**; the software that implements it is version
**2.0.0**. This is correct and deliberate: the predecessor tool,
`anubis-rage`, already shipped two incompatible formats numbered v1 and v2, so
the first format specified in this document has to be v3. Do not "correct"
either number to agree with the other. Section 15 documents the lineage.

This document specifies the `ANUBIS/v3` encrypted file format completely enough
to write an interoperable implementation without reference to the ANUBIS source
code. Every field length is stated in bytes. Where a length is a function of
another length, the function is given explicitly.

An implementation that produces byte-identical output for identical inputs and
identical randomness, and that accepts every file this specification declares
valid while rejecting every file it declares invalid, is conformant.

---

## 1. Conventions

**Byte order.** All integers on the wire are unsigned big-endian.

**`||`** denotes concatenation of octet strings.

**`b64(x)`** denotes standard Base64 (RFC 4648 section 4, alphabet
`A-Za-z0-9+/`) with **all `=` padding characters removed**. Decoders MUST
reject input containing `=`, containing characters outside the alphabet,
containing whitespace, or whose length is congruent to 1 modulo 4. Decoders
MUST reject non-canonical encodings, that is, encodings whose final Base64
character has non-zero unused low bits. `b64` of an `n`-byte string is exactly
`ceil(4 * n / 3)` characters.

**Header line terminator** is a single LINE FEED, `0x0A`. Carriage return
`0x0D` is not permitted anywhere in the header, and neither is any other
trailing whitespace: a header line MUST consist of its defined content followed
immediately by one `0x0A`. Header lines are therefore canonical, and a parser
MUST reject a line that carries trailing whitespace of any kind rather than
trimming it. Section 7.1 explains why this is normative and not cosmetic.

**Header line length** is bounded. A parser MUST reject any header line longer
than `MAX_HEADER_LINE` = 8192 bytes, which is comfortably above the longest
line this format defines (the 3468-byte `-> mldsa87` stanza). The bound exists
so that a crafted file containing no `0x0A` at all cannot force an unbounded
read before any key material is involved.

**HKDF** is HKDF (RFC 5869) instantiated with HMAC-SHA-512. Where a salt is
specified as *zero-length*, HKDF-Extract is called with a zero-length salt,
which RFC 5869 defines as equivalent to a salt of `HashLen` zero bytes, here 64
zero bytes. `HKDF(salt, ikm, info, L)` denotes `L` bytes of output key
material.

**AEAD** is ChaCha20-Poly1305 as specified in RFC 8439: 32-byte key, 12-byte
nonce, 16-byte authentication tag appended to the ciphertext. Every AEAD
invocation in this format uses **empty associated data**.

**Failure is fatal.** Any authentication failure, any length mismatch, any
parse error: the implementation MUST abort and MUST NOT emit any plaintext
produced before the failure was detected. See section 9.

---

## 2. Cryptographic parameters

> **One AEAD, and only one.** `ANUBIS/v3` encrypts payloads with
> ChaCha20-Poly1305 and nothing else. There is no AES in this format, no
> cipher negotiation, and no agility: the suite is fixed by the version line.
> Earlier, unrelated crates published under the names `anubis-rage` and
> `anubis-age` implement the superseded `v1`/`v2` formats and describe a
> different construction; documentation generated from those crates does not
> describe this format. Section 15 lists the identifiers already spent.

| Parameter | Value | Reference |
|---|---|---|
| Classical KEM | X25519 | RFC 7748 |
| Post-quantum KEM | ML-KEM-1024 | FIPS 203 |
| Signature | ML-DSA-87, pure, ctx `"anubis-v2-file"` | FIPS 204 |
| Signature digest | SHA-512 over header + payload ciphertext | FIPS 180-4 |
| AEAD | ChaCha20-Poly1305 | RFC 8439 |
| KDF | HKDF-SHA-512 | RFC 5869, FIPS 180-4 |
| Header MAC | HMAC-SHA-512 | RFC 2104 |
| Fingerprint hash | SHA-256, truncated to 10 bytes | FIPS 180-4 |

Fixed primitive sizes, in bytes:

| Quantity | Bytes |
|---|---|
| X25519 public key | 32 |
| X25519 secret key (scalar) | 32 |
| X25519 shared secret | 32 |
| ML-KEM-1024 encapsulation key (public) | 1568 |
| ML-KEM-1024 decapsulation key, expanded | 3168 |
| ML-KEM-1024 decapsulation seed `(d, z)` | 64 |
| ML-KEM-1024 ciphertext | 1568 |
| ML-KEM-1024 shared secret | 32 |
| ML-DSA-87 verifying key (public) | 2592 |
| ML-DSA-87 signing key, expanded | 4896 |
| ML-DSA-87 key seed | 32 |
| ML-DSA-87 signature | 4627 |
| File key | 32 |
| Wrap key | 32 |
| Wrapped file key | 48 |
| Payload key | 32 |
| Header MAC key | 64 |
| Poly1305 tag | 16 |
| Recipient fingerprint | 10 |
| Plaintext chunk | 65536 (final chunk: 1..65536) |

---

## 3. File layout

A file has two or three regions, in this order:

```
+--------------------------------------------------+
| header    (US-ASCII text, LF-terminated lines)   |
+--------------------------------------------------+
| payload   (binary, STREAM-encrypted chunks)      |
+--------------------------------------------------+
| signature (raw ML-DSA-87, exactly 4627 bytes)    |  <- only if signed
+--------------------------------------------------+  <- EOF
```

The payload begins at the byte immediately following the `0x0A` that terminates
the MAC line. There is no separator and no length prefix anywhere.

**The signature, when present, is a trailer of exactly 4627 bytes at the end of
the file.** It is raw binary, not Base64, and it is not part of the header.

Region boundaries are therefore computed as:

```
header_len    = offset of the first byte after the MAC line's LF
sig_len       = 4627 if the header contains a mldsa87 stanza, else 0
payload_len   = file_size - header_len - sig_len
payload_range = [header_len, file_size - sig_len)
sig_range     = [file_size - 4627, file_size)      when signed
```

A reader MUST determine `sig_len` from the presence of the `-> mldsa87` stanza
in the header, which it has already parsed, and MUST reject a signed file whose
size is less than `header_len + 16 + 4627`, since the payload cannot be shorter
than one empty chunk.

Note that `payload_len` is derived by subtraction, so a signed file's payload
region ends 4627 bytes before EOF, not at EOF. An implementation that streams
the payload MUST bound its read at `file_size - sig_len`; reading to EOF would
feed signature bytes into the AEAD and fail on the final chunk.

---

## 4. Header

### 4.1 Grammar

```abnf
; whole file
file         = header payload [ signature-trailer ]
signature-trailer = 4627OCTET     ; present iff header has signature-stanza

; header, US-ASCII text
header       = version-line 1*recipient-block [ signature-stanza ] mac-line

version-line = %s"anubis-encryption.org/v3" LF

recipient-block = stanza-line wrapped-line
stanza-line  = %s"-> hybrid-x25519-mlkem1024" SP b64-32 SP b64-1568 LF
wrapped-line = b64-48 LF

signature-stanza = %s"-> mldsa87" SP b64-2592 LF

mac-line     = %s"---" SP b64-64 LF

SP           = %x20
LF           = %x0A
```

`b64-N` is `b64` of exactly `N` bytes; a decoder MUST verify the decoded length.

The header carries the signer's **verifying key** only. The signature itself is
not in the header at all; it is the file's trailer (section 3, section 10).
The presence of `signature-stanza` is what tells a reader that a 4627-byte
trailer exists.

### 4.2 Annotated example

```
anubis-encryption.org/v3
-> hybrid-x25519-mlkem1024 <b64 of x25519_epk, 32 B -> 43 chars> <b64 of mlkem_ct, 1568 B -> 2091 chars>
<b64 of wrapped_file_key, 48 B -> 64 chars>
-> mldsa87 <b64 of verifying_key, 2592 B -> 3456 chars>
--- <b64 of header MAC, 64 B -> 86 chars>
```

Exact line lengths, including the terminating `0x0A`:

| Line | Bytes |
|---|---|
| `anubis-encryption.org/v3` | 25 |
| recipient stanza line | 2163 |
| wrapped file key line | 65 |
| `-> mldsa87` stanza line | 3468 |
| (no signature line: the signature is a 4627-byte trailer) | 0 |
| MAC line | 91 |

### 4.3 Ordering and cardinality

1. The version line MUST be first and MUST appear exactly once.
2. One or more recipient blocks follow. Their order is the writer's
   recipient order and is preserved verbatim on rewrite. A parser MUST reject a
   header carrying more than `MAX_STANZAS` = 1024 recipient blocks. That bound
   is normative rather than advisory because each block costs one hybrid
   decapsulation, which is the expensive half of parsing a header, and the work
   is spent before anything has been authenticated: a header naming a million
   recipients is a cheap request for an expensive computation. An
   implementation MAY impose a lower ceiling and MUST report exceeding it as a
   header error, not as "no matching identity".
3. At most one signature block follows the recipient blocks. Its presence is
   what makes a file signed; there is no separate flag.
4. The MAC line MUST be last and MUST appear exactly once.

A parser MUST reject: an unknown version line; a stanza tag other than
`hybrid-x25519-mlkem1024` or `mldsa87`; a `mldsa87` stanza appearing before any
recipient block; more than one `mldsa87` stanza; zero recipient blocks; any
line after the MAC line; a header not terminated by a MAC line.

The two `mldsa87` rules are structural on purpose, and rejecting them at parse
is strictly stronger than catching them with the header MAC: the MAC needs the
file key, so only a recipient could ever notice, whereas a parse-time refusal
is visible to anyone -- including a keyless verifier. Accepting a second
stanza with last-wins semantics would let one header advertise two signers
while each reader reports whichever its parser happened to keep, and two
readers disagreeing about who signed a file is exactly the mistaken-identity
outcome the fingerprint namespaces of section 11.4 exist to prevent.

Unknown stanza tags are **not** skipped. `ANUBIS/v3` has no extension
mechanism: forward compatibility is handled by bumping the version line.
Section 15 explains why that bump must never reuse a previously published
identifier, and lists the identifiers already spent.

### 4.4 Duplicate recipients

The same recipient MAY legitimately appear in two blocks, since each block
carries independent ephemeral material. Implementations MUST NOT deduplicate
blocks **on read**, and MUST NOT treat a duplicate as an error. A decrypting
implementation tries blocks in file order and uses the first that succeeds.

De-duplication **on write** is a separate question and is permitted. A writer
MAY collapse recipients that are byte-identical before encapsulating, and the
reference implementation does: naming one key twice through `-r`, or once
through `-r` and again through `-R`, produces a single stanza. This is a
writer-side convenience and changes nothing a reader must do. Note the
consequence for header size: the recipient count a reader observes is the
number of distinct recipients, not the number the caller named.

---

## 5. Key agreement

For each recipient, the writer performs one hybrid encapsulation. The two
component KEMs are run independently and their shared secrets are combined.

### 5.1 Encapsulation

Given a recipient's `x25519_pk` (32 bytes) and `mlkem_ek` (1568 bytes):

```
1. Generate a fresh X25519 keypair (x25519_esk, x25519_epk).
   x25519_esk MUST be 32 bytes from a cryptographically secure RNG.
2. x25519_ss = X25519(x25519_esk, x25519_pk)                        (32 bytes)
3. (mlkem_ct, mlkem_ss) = ML-KEM-1024.Encaps(mlkem_ek)      (1568, 32 bytes)
4. wrap_key = HKDF-SHA512(
       salt = x25519_epk || mlkem_ct,                            (1600 bytes)
       ikm  = x25519_ss  || mlkem_ss,                              (64 bytes)
       info = "anubis-hybrid-v2/X25519+MLKEM-1024",
       L    = 32)
```

The ephemeral X25519 keypair and the ML-KEM encapsulation MUST be fresh for
every recipient of every message. Reuse across recipients would make
`wrap_key` collide across blocks and, given the all-zero wrapping nonce of
section 6, would be catastrophic.

An implementation MUST reject an all-zero `x25519_ss`, which indicates a
low-order or otherwise degenerate recipient public key.

### 5.2 Decapsulation

Given an identity's `x25519_sk` and `mlkem_dk`, and a parsed recipient block:

```
1. x25519_ss = X25519(x25519_sk, x25519_epk)
2. mlkem_ss  = ML-KEM-1024.Decaps(mlkem_dk, mlkem_ct)
3. wrap_key  = HKDF-SHA512(salt = x25519_epk || mlkem_ct,
                           ikm  = x25519_ss  || mlkem_ss,
                           info = "anubis-hybrid-v2/X25519+MLKEM-1024",
                           L    = 32)
```

ML-KEM decapsulation is defined for all inputs: FIPS 203 specifies implicit
rejection, returning a pseudorandom shared secret derived from the
decapsulation key's rejection seed rather than signalling failure. A wrong key
or a corrupted ciphertext therefore does not fail here; it produces a wrong
`wrap_key` and the AEAD unwrap of section 6 fails instead. Implementations
MUST NOT attempt to detect decapsulation failure any earlier, and MUST NOT
report the two component KEMs' outcomes separately: the only observable
signal is the single unwrap result.

### 5.3 Why the transcript is bound into the salt

The salt is not a nonce and is not random padding. It is the complete
recipient-block transcript, `x25519_epk || mlkem_ct`, the exact 1600 bytes that
the reader will parse out of the header.

Combining two KEMs by hashing only their shared secrets is not sufficient.
Neither X25519 nor ML-KEM-1024 is a committing KEM: for both, an adversary can
in general find a *different* ciphertext that decapsulates, under the same
recipient key, to a shared secret the adversary can predict or relate to
another. If `wrap_key` depended only on `x25519_ss || mlkem_ss`, an active
adversary who observed a valid header could attempt to substitute one component
ciphertext, or re-encapsulate against the same recipient, and produce a second
header that a reader would resolve to the same `wrap_key` as the first. That
turns a passive record into an oracle and breaks the intended one-header,
one-key correspondence. The generic composition literature calls the fix
transcript binding or ciphertext binding; it is what makes the combiner
IND-CCA2 secure as long as *either* component is.

Binding the transcript makes `wrap_key` a function of the bytes on the wire.
Change any byte of `x25519_epk` or `mlkem_ct` and `wrap_key` changes
unpredictably, so the wrapped file key no longer unwraps. The recipient block
is thereby non-malleable as a unit, and `wrap_key` is unique per recipient per
message without a per-block nonce. That uniqueness is precisely the
precondition that licenses the all-zero wrapping nonce below.

The ordering `x25519 || mlkem` in both salt and IKM is normative. So is the
`info` string, byte-exactly, with no terminating NUL:

```
"anubis-hybrid-v2/X25519+MLKEM-1024"
```

which is 34 US-ASCII bytes:

```
61 6e 75 62 69 73 2d 68 79 62 72 69 64 2d 76 32 2f 58 32 35
35 31 39 2b 4d 4c 4b 45 4d 2d 31 30 32 34
```

**The `v2` inside this string is the cipher-suite version, not the wire-format
version, and it is deliberately not renamed.** The suite, X25519 with
ML-KEM-1024 combined by HKDF-SHA-512, is unchanged from the construction the
string was minted for; the wire format around it is what advanced to v3.
Renaming the `info` string would change every derived `wrap_key` and silently
break interoperability with every conformant implementation, for no
cryptographic benefit. It is a fixed, opaque domain-separation label. Treat
the 34 bytes above as the normative definition and do not attempt to keep it in
step with the version line.

---

## 6. File key and wrapping

### 6.1 File key

The **file key** is 32 bytes drawn from a cryptographically secure RNG. It is
generated once per file, independent of the recipient count, and it is what
every recipient block conveys. It never appears on the wire in the clear.

### 6.2 Wrapping

For each recipient block:

```
wrapped_file_key = ChaCha20Poly1305(
        key   = wrap_key,
        nonce = 00 00 00 00 00 00 00 00 00 00 00 00,   (12 zero bytes)
        aad   = "",                                     (empty)
        plaintext = file_key)                            (32 bytes)
                                                     -> 48 bytes
```

48 bytes: 32 bytes of ciphertext followed by the 16-byte Poly1305 tag.

**On the all-zero nonce.** ChaCha20-Poly1305 requires that a (key, nonce) pair
never repeat. Here the nonce is constant, so the requirement falls entirely on
key uniqueness, and section 5.3 supplies it: `wrap_key` is
`HKDF(x25519_epk || mlkem_ct, ...)`, and `x25519_epk` is a fresh ephemeral
public key for every block. Two blocks share a `wrap_key` only if they share an
ephemeral keypair, which a conformant writer never does. A fixed nonce is
therefore safe and is preferred to a random one, because it removes 12 bytes
per recipient from the header and removes the possibility of a writer emitting
a repeated random nonce under a repeated key.

Implementations MUST derive a fresh ephemeral keypair per block. An
implementation that caches or reuses ephemeral keys is non-conformant and
insecure.

### 6.3 Unwrapping

A reader attempts, for each recipient block in file order, the AEAD open with
the `wrap_key` derived in section 5.2 and the all-zero nonce. The first
success yields `file_key` and fixes which identity decrypted the file. If no
block succeeds under any available identity, the file is not addressed to the
holder and the implementation reports exactly that, without disclosing which
blocks were attempted.

### 6.4 Derived keys

Both derivations take the file key as IKM, a zero-length salt, and distinct
`info` strings. The `info` strings are exactly the 7 bytes `"payload"` and the
6 bytes `"header"`, with no terminating NUL and no version prefix.

```
payload_key    = HKDF-SHA512(salt = "", ikm = file_key, info = "payload", L = 32)
header_mac_key = HKDF-SHA512(salt = "", ikm = file_key, info = "header",  L = 64)
```

Domain separation by `info` is what allows one 32-byte secret to serve both
purposes. `payload_key` is a ChaCha20-Poly1305 key; `header_mac_key` is an
HMAC-SHA-512 key at the full 64-byte block-aligned length, so HMAC uses it
directly without pre-hashing.

---

## 7. Header MAC

### 7.1 Computation

Let `H` be the header bytes **up to but not including** the MAC line, that is,
everything from the first byte of the version line through the `0x0A` that
terminates the last line preceding the MAC line. `H` includes all line feeds.

```
header_mac = HMAC-SHA512(key = header_mac_key, message = H)      (64 bytes)
```

The MAC line is then `"--- " || b64(header_mac) || LF`.

The MAC covers the version line, every recipient block, and the signature block
if present. It does not cover itself, and it does not cover the payload; the
payload is protected by its own AEAD tags (section 8).

**`H` is the raw bytes as they appear on disk.** A verifier MUST compute the
MAC over the octets it actually read, retained verbatim, and MUST NOT
re-serialise the parsed stanzas and MAC that instead. The distinction has no
effect on a conforming file -- both procedures produce the same `H`, so this
rule is a tightening and not a wire-format change -- but it is the difference
between the section 7.2 guarantee holding and not holding.

This was a real defect, not a hypothetical one. An implementation that
re-serialised was malleable: an attacker holding no key material could append
trailing whitespace anywhere in an unsigned header, the parser would trim it,
the re-serialised `H` would not contain it, the MAC would still match, and the
modified file decrypted. The claim in 7.2 that any header edit is detected was
therefore false. Two rules together make it true: this one, and the section 1
requirement that a header line carrying a CR or trailing whitespace be rejected
outright rather than trimmed. An implementation that adopts only one of them is
still vulnerable, because canonical parsing without raw-byte MAC coverage still
leaves other trimmable ambiguities, and raw-byte coverage without canonical
parsing merely converts forgeries into confusing failures.

### 7.2 Verification

A reader recovers `file_key`, derives `header_mac_key`, recomputes
`header_mac` over `H`, and compares against the decoded MAC line in **constant
time**. A mismatch is a fatal error and MUST be reported as a header integrity
failure distinct from "no matching identity".

Verification MUST happen before any payload chunk is decrypted. This is what
makes recipient-block tampering, stanza reordering, recipient stripping, and
signature-block stripping detectable: any such edit changes `H`.

Note the direction of the dependency: the MAC key comes from the file key,
which comes from a successful unwrap. A reader who cannot decrypt cannot
verify the header, and this is by design. The header MAC is an integrity
guarantee for legitimate recipients, not a public one.

That has a consequence which section 14.2 states in full and which must not be
read past here: **every recipient holds `file_key`, therefore every recipient
holds `header_mac_key`, therefore every recipient can produce a header MAC over
any header it likes.** Detection of "signature-block stripping" above means
detection by a recipient of an edit made by a *non*-recipient. It is not, and
cannot be, detection of an edit made by someone who could decrypt the file.

---

## 8. Payload

### 8.1 STREAM

The payload is the plaintext encrypted under the STREAM construction of
Rogaway and Hoang, "Online Authenticated-Encryption and its Nonce-Reuse
Misuse-Resistance", instantiated with ChaCha20-Poly1305.

The plaintext is split into chunks of exactly **65536 bytes**, except the final
chunk, which is 1 to 65536 bytes inclusive. Each chunk is sealed
independently under `payload_key` with a nonce that encodes the chunk's index
and whether it is final. Ciphertext chunks are written back to back in order.

```
ciphertext_chunk[i] = ChaCha20Poly1305(
        key   = payload_key,
        nonce = nonce(i, final),
        aad   = "",
        plaintext = plaintext_chunk[i])
```

Each chunk expands by exactly 16 bytes. A full ciphertext chunk is therefore
65552 bytes.

### 8.2 Nonce

The 12-byte nonce is:

```
byte  0..10  chunk counter, 11-byte big-endian, starting at 0
byte     11  0x01 if this is the final chunk, 0x00 otherwise
```

Concretely, chunk 0 of a multi-chunk file uses:

```
00 00 00 00 00 00 00 00 00 00 00 00
```

chunk 1 uses:

```
00 00 00 00 00 00 00 00 00 00 01 00
```

and the final chunk, at index `n-1`, uses that index in bytes 0..10 followed by
`0x01`. For a single-chunk file the only nonce is:

```
00 00 00 00 00 00 00 00 00 00 00 01
```

The counter MUST NOT wrap. Its ceiling, `2^88 - 1`, bounds a file at
`2^88 * 65536` bytes, far beyond any reachable size; an implementation MUST
nonetheless treat counter overflow as a fatal error rather than wrapping.

Note that the wrapping nonce of section 6.2 is the all-zero nonce, which is
also chunk 0's non-final nonce. There is no collision risk: the keys are
different and unrelated, `wrap_key` versus `payload_key`.

### 8.3 The final-chunk rule

This rule is normative and is the single most common source of
incompatibility between STREAM implementations. State it exactly:

> **Exactly one chunk in every file carries the final flag `0x01`, and it is
> the last chunk. A chunk whose plaintext length is 0 is permitted if and only
> if the plaintext of the entire file is empty, in which case the file has
> exactly one chunk.**

Consequences:

- **Empty input.** One chunk, plaintext length 0, nonce
  `00 00 00 00 00 00 00 00 00 00 00 01`, ciphertext length 16, consisting
  solely of the Poly1305 tag over the empty message. The payload of an
  encrypted empty file is 16 bytes, never 0 bytes. A zero-length payload is
  invalid and MUST be rejected.
- **Length an exact multiple of 65536.** The last full chunk carries the
  final flag. No trailing empty chunk is written. A 65536-byte plaintext has
  exactly one chunk of 65536 bytes with the final nonce; a 131072-byte
  plaintext has two chunks, indices 0 and 1, with the final flag on index 1.
- **Length not a multiple of 65536.** The final chunk is the remainder,
  `len mod 65536` bytes, with the final flag.

The chunk count is `max(1, ceil(len / 65536))`.

A reader determines chunk boundaries from the remaining byte count, not from
any in-band length. Reading proceeds as follows:

1. Read up to 65552 bytes.
2. If fewer than 16 bytes were available, the payload is truncated: fatal error.
3. If exactly 65552 bytes were read **and** at least one further byte exists,
   this is a non-final chunk: open with flag `0x00`, emit, increment counter,
   repeat from step 1.
4. Otherwise this is the final chunk: open with flag `0x01`, emit, stop. Any
   remaining bytes at this point mean trailing garbage: fatal error.

Step 3's lookahead is what enforces the rule. A reader that guesses "final"
from a short read alone will accept a truncated file whose truncation lands on
a chunk boundary.

### 8.4 Truncation and reordering

The final flag is what makes truncation detectable. Cut a multi-chunk file at
a chunk boundary and the new last chunk still authenticates as a non-final
chunk, but step 3's lookahead finds no following byte, so the reader tries flag
`0x01`, the nonce differs from the one used to seal it, and the tag fails.
Chunk reordering, duplication, and splicing between files all fail for the same
reason: the counter is in the nonce.

The one thing the payload construction does not protect on its own is
association with a particular header, since `payload_key` is a deterministic
function of `file_key`. A payload cannot be moved to a header that conveys a
different file key.

---

## 9. Streaming, and what may be emitted before authentication

A conformant implementation decrypts chunk by chunk and MAY write each
plaintext chunk to its output as soon as that chunk's tag verifies. It
therefore may, on a truncated or tampered file, have already written every
chunk preceding the damage.

This is a real property of any online AEAD and MUST be surfaced, not hidden:

- When the output is a file, an implementation MUST NOT leave a partial
  plaintext at the destination path. Write to a temporary file in the
  destination directory and rename it into place only after the final chunk
  verifies, or remove the partial file on error.
- When the output is a pipe or standard output, a partial prefix may already
  have escaped. The implementation MUST exit non-zero and report the failure on
  standard error; a consumer of the pipe MUST check the exit status before
  treating the bytes as authentic.
- An implementation MUST NOT buffer the whole plaintext in memory in order to
  satisfy the file rule. Bounded memory is a design requirement for file
  destinations.

### 9.1 Streams in the reference implementation

Stream support is optional in this specification: an implementation MAY require
seekable files and refuse pipes, which sidesteps the second rule entirely.
**The reference implementation does support streams.** `encrypt`, `decrypt`,
and `inspect` accept `-` as the input argument, `encrypt` and `decrypt` accept
`-` as the output, and an input of `-` with no output specified defaults to
standard output. A pipeline such as

```
tar cf - dir | anubis encrypt -r KEY --sign -o - - > out.anubis
anubis decrypt -o - - < out.anubis | tar xf -
```

is supported and works on genuinely non-seekable descriptors in both
directions.

**Memory is bounded in all four combinations**, and does not grow with the
file. Measured on this machine with a 256 MiB plaintext, three runs of each
case, sampling `VmHWM` from `/proc`:

| Operation | Input | Output | Peak resident |
|---|---|---|---|
| `encrypt` | file | file | 3592 - 3668 kB |
| `encrypt` | file | stdout | 3640 - 3664 kB |
| `encrypt` | pipe | file | 3736 - 3740 kB |
| `encrypt` | pipe | stdout | 3712 - 3740 kB |
| `decrypt` | file | file | 3316 kB |
| `decrypt` | file | stdout | 3372 - 3380 kB |
| `decrypt` | pipe | file | 3668 - 3732 kB |
| `decrypt` | pipe | stdout | 3732 kB |

**Nothing is published before the whole container verifies, in any of them.**
The file destination writes to a temporary beside the destination and renames
after verification. The stdout destination cannot rename, and cannot recall
bytes once written, so it streams the plaintext into an *unlinked* scratch file
in the temporary directory -- created, then immediately removed, so the
descriptor stays valid while the file has no name, is invisible to other
processes, and does not survive a crash -- and copies it to standard output
only after the payload, the signature, and the reader's signature policy have
all been satisfied. Verified at 256 MiB by corrupting the final chunk and
decrypting to standard output: zero bytes emitted, exit status 1, for signed
and unsigned containers alike; and on a clean container the piped output is
byte-identical to the source.

This makes the second rule above stricter than it needs to be for this
implementation, but the rule stays as written, because it is the guarantee a
*conforming* implementation must provide and a consumer must assume. An
implementation that streams straight to the pipe is conforming; it simply
offers less.

The scratch-file approach trades memory for **temporary disk space equal to the
plaintext**. An implementation MUST degrade safely if that space is
unavailable: the reference implementation falls back to holding the plaintext in
memory, so the withholding guarantee is never weakened, only its space profile.
Verified by pointing `TMPDIR` at an unwritable directory: output byte-identical.

**Signed files.** The signature covers the payload ciphertext and sits at the
end of the file (section 10), so it cannot be verified until every ciphertext
byte has been read. A reader MUST complete signature verification before
releasing *any* plaintext to its caller. It MUST NOT release plaintext first
and check the signature afterwards, and MUST NOT silently treat the file as
unsigned.

That does not require buffering the plaintext and does not require a seekable
input. The trailer is a fixed 4627 bytes, so a reader consuming a non-seekable
stream can hold exactly that many bytes back in a delay buffer, hash and
decrypt everything ahead of it, and find the trailer waiting in the buffer at
end of input. The reference implementation does this, which is why the
`decrypt` rows above are flat across all four combinations. An implementation
that will not manage the delay buffer MAY read the ciphertext twice, hashing on
the first pass, or buffer the plaintext; one that can do none of these MUST
refuse and say so.

For signed files the partial-output hazard therefore does not arise in this
implementation at all: nothing reaches the destination, path or pipe, until the
whole file has been authenticated and the reader's signature policy has been
satisfied. Signing is the stronger mode, and it costs neither single-pass
streaming nor bounded memory.

### 9.2 ASCII armor is not a stream

An implementation MAY offer an ASCII-armored container: the binary container
base64-encoded, wrapped at 64 columns, between the boundary lines
`-----BEGIN ANUBIS ENCRYPTED FILE-----` and
`-----END ANUBIS ENCRYPTED FILE-----`, each terminated by `0x0A`. Armor is a
transport encoding of a whole container and is **not** part of the wire format
specified here; a reader detects it by the opening boundary line rather than by
a flag.

Armor cannot be streamed, because the boundary and the wrapping must be removed
and the base64 decoded before the version line is even visible, and all of that
happens before any key material is involved. An implementation offering armor
therefore MUST bound the armored text it will accept, and SHOULD apply the same
bound to what it will produce so that a file it writes is a file it can read.
The reference implementation uses `MAX_ARMOR_BYTES` = 16777216 bytes of armored
text in both directions: 12383906 bytes of plaintext armors to exactly
16777216 bytes and round-trips, and one byte more is refused before anything is
written. Armored input over the bound is refused having peaked between 14.3 and
19.5 MiB resident, against a 256 MiB armored file.

For a container of `C` bytes, let `B = 4 * ceil(C / 3)` be the unpadded base64
length. The armored file is then exactly

```
armored(C) = B + ceil(B / 64) + 74
```

bytes: the encoded text, one `0x0A` per wrapped line, and 74 bytes for the two
boundary lines with their terminators. The 2378-byte single-recipient unsigned
container of section 12 armors to 3296 bytes, and the 12389274-byte container
that a 12383906-byte plaintext produces armors to exactly 16777216. Both match
what the reference implementation writes.

---

## 10. Signatures

### 10.1 Purpose

The header MAC proves that whoever assembled the header knew the file key,
which every recipient does. It does not identify the sender. The optional
ML-DSA-87 signature does: it binds the whole file to a long-term verifying key
that the reader can recognise.

A signature is present if and only if the header contains a `-> mldsa87`
stanza. There is no separate flag.

### 10.2 The signed message

The signature is over a digest of the **entire file except the signature
itself**:

```
S = SHA-512( header_bytes || payload_ciphertext )              (64 bytes)
```

where

- `header_bytes` is the complete header **including the MAC line and its
  terminating `0x0A`**, that is, bytes `[0, header_len)`; and
- `payload_ciphertext` is the entire payload region, every ciphertext chunk
  with its tag, that is, bytes `[header_len, file_size - 4627)`.

Note the difference from the header MAC of section 7: the MAC is computed over
the header *excluding* its own MAC line, whereas `S` *includes* the MAC line.
They are different inputs and must not be conflated.

```
signature = ML-DSA-87.Sign(signing_key, S, ctx = "anubis-v2-file")
                                                              (4627 bytes)
```

ML-DSA is used in its pure (not pre-hashed) form per FIPS 204, with the
**context string** `"anubis-v2-file"`, which is exactly 14 US-ASCII bytes with
no terminating NUL:

```
61 6e 75 62 69 73 2d 76 32 2d 66 69 6c 65
```

Implementations MUST NOT use HashML-DSA, MUST NOT use an empty context string,
and MUST pass this context to both sign and verify. As with the KEM `info`
string of section 5.3, the `v2` here is a fixed domain separator carried over
from the product name; it is **not** the wire-format version and MUST NOT be
renamed to `v3`. Changing it would invalidate every existing signature.

### 10.3 Why the signature is a trailer

The signature covers the payload ciphertext, and the payload ciphertext is not
known until it has been streamed. Placing the signature in the header would
therefore require buffering the entire file, or two passes over the input, before
the first header byte could be written.

Putting it at the end makes signing **single-pass and streamable at any file
size**: the writer hashes header bytes and ciphertext chunks into a running
SHA-512 as it emits them, then signs the digest and appends 4627 bytes. Memory
is bounded by one chunk regardless of input size.

Storing it raw rather than Base64 saves 1544 bytes per signed file, the
expansion that encoding 4627 bytes into 6170 characters would cost, and keeps
the header pure US-ASCII by construction: all binary lives in the binary
regions.

### 10.4 Signing procedure

The order is normative:

```
1. assemble the version line and all recipient blocks
2. append "-> mldsa87 " b64(verifying_key) LF
3. compute header_mac over everything so far    (section 7.1)
4. append "--- " b64(header_mac) LF             -> header complete
5. h = SHA-512 context; absorb all header bytes from step 4
6. for each chunk: seal it, emit it, absorb the ciphertext chunk into h
7. S = h.finalize()
8. signature = Sign(signing_key, S, ctx = "anubis-v2-file")
9. append the 4627 raw signature bytes         -> EOF
```

The verifying key is written into the header *before* the header MAC is
computed, so the MAC covers the verifying key. A `-> mldsa87` stanza therefore
cannot be stripped, added, or swapped **by a party who cannot decrypt the
file** without failing MAC verification. It can be by a recipient, who holds
the file key and hence the header MAC key; see 10.6.

### 10.5 Verifying procedure

**The signature check itself requires no key.** `S` is a digest of the header
and the payload ciphertext, and the verifying key travels in the header, so
everything needed to check a signature is in the file. Nothing in this section
that touches a key is a precondition of the ML-DSA-87 verification; the key
steps belong to *decryption*, which has its own ordering requirement.

Checking a signature, and nothing else -- the position of a third party
auditing a container they cannot open:

```
1. parse the header; a mldsa87 stanza is present, so sig_len = 4627
2. reject if file_size < header_len + 4627 + 16
3. read the last 4627 bytes as the signature
4. h = SHA-512 over header_bytes || payload region [header_len, size-4627)
5. ML-DSA-87.Verify(verifying_key, h.finalize(), signature,
                    ctx = "anubis-v2-file")
```

That is the whole of it. No identity, no file key, no decryption, and no
plaintext. The reference implementation exposes it as `anubis verify`; see
[VERIFYING.md](VERIFYING.md) for a worked recipe using stock OpenSSL instead.

Decrypting a signed container additionally requires the file key, and there
the ordering IS normative:

```
1. parse the header                            (sig_len = 4627 if signed)
2. reject if file_size < header_len + 4627 + 16
3. recover the file key                        (section 6.3)
4. verify the header MAC over H                (section 7.2)
5. read the last 4627 bytes as the signature
6. h = SHA-512 over header_bytes || payload region [header_len, size-4627)
7. ML-DSA-87.Verify(verifying_key, h.finalize(), signature,
                    ctx = "anubis-v2-file")
8. only then decrypt and emit payload chunks
```

Step 4 precedes step 7, and both precede step 8. **A reader MUST NOT emit any
plaintext before signature verification has succeeded.**

This does **not** require seeking, buffering the plaintext, or a second pass
over the input. The trailer length is fixed at 4627 bytes, so a reader
consuming a non-seekable stream can hold the trailing 4627 bytes back in a
delay buffer while hashing and decrypting everything ahead of them, and find
the signature waiting in that buffer at end of input. What it does require is
that the plaintext produced during the pass not be released to the caller until
step 7 succeeds: write it to a temporary and rename after verification, as
section 9.1 describes. An implementation that will not implement the delay
buffer MAY read the ciphertext twice, hashing on the first pass, or buffer the
plaintext; one that can do none of these MUST refuse and say so rather than
silently treating the file as unsigned.

Verification succeeding proves that the holder of the signing key corresponding
to `verifying_key` produced this exact file. It does not establish that the key
belongs to any particular person. An implementation MUST report "signed by an
unknown key" distinctly from "signature valid, key known" and MUST NOT present
the former as authenticated.

### 10.6 What the signature covers

`S` covers the version line, every recipient block, the verifying key, the
header MAC, and every byte of payload ciphertext. Consequently a signature
binds:

- **the exact recipient set.** Adding or removing a recipient invalidates it.
- **the exact plaintext**, transitively: the ciphertext determines the
  plaintext given the file key.
- **the pairing of that payload with that header.** Payloads cannot be swapped
  between signed files.

**Covering the ciphertext, rather than only the header, is a deliberate and
necessary choice.** Every recipient learns the file key, so a recipient can
always produce a valid ciphertext of a plaintext of its choosing. Were the
signature over the header alone, a recipient could re-encrypt arbitrary content
under the original signed header and the signature would still verify, letting
one recipient forge messages that appear signed by the sender. Because `S`
includes the ciphertext, any such re-encryption changes `S` and the signature
fails. A signature is therefore meaningful evidence to a recipient about what
the sender actually sent.

The remaining limits are worth stating precisely, since the guarantee is strong
enough to be misread as stronger than it is:

- **A recipient can remove the signature entirely, and this is not detectable.**
  Every recipient holds the file key and therefore the header MAC key
  (section 7.2). A recipient can construct a container carrying the same
  plaintext with the `-> mldsa87` stanza absent, a header MAC recomputed to
  match, and no trailer, and that container is a perfectly ordinary unsigned
  ANUBIS file. There is nothing to detect, because the result is
  indistinguishable from a file that was never signed. No change to this format
  can prevent it: the capability follows from the recipient knowing the file
  key, which is the same thing as the recipient being able to decrypt.

  The consequence is that **absence of a signature carries no information about
  whether the sender signed.** A reader that cares MUST make a signature a
  precondition rather than checking after the fact. The reference
  implementation exposes this as `--require-signature`, which fails on an
  unsigned container, and `--signer FINGERPRINT`, which fails unless the
  signature is present, valid, and by that key; neither writes plaintext on
  failure. An implementation of this format SHOULD offer equivalents, and its
  documentation MUST NOT describe signatures as unstrippable.
- **An unpinned valid signature identifies no one.** It establishes that the
  holder of some ML-DSA-87 key produced these exact bytes. Which key, and
  whether that key belongs to anyone in particular, is outside this format. A
  reader SHOULD surface the signer's fingerprint (section 11.4 applied to the
  verifying key) so that a caller can compare it against a value confirmed out
  of band.
- A signature says the signing key produced this file. It says nothing about
  *when*, and nothing about whether the sender intended this particular
  recipient to receive it now. There is no timestamp and no replay protection
  (section 14.2).
- Verification requires the whole file. A signature cannot be checked on a
  partial download, and cannot be checked at all by a party who cannot read the
  payload region's length, which requires parsing the header.
- The signature is public and links every file signed by one key. It is not a
  private authentication mechanism (section 14.2).

---

## 11. Key encodings

There are exactly three key artifacts, and they are deliberately not
symmetric:

| Artifact | Encoding | Payload | Length | Bech32 checksum guarantee |
|---|---|---|---|---|
| Recipient | Bech32, HRP `anubis` | 1600 B | 2573 chars | **degraded** (see 11.1) |
| Identity | Bech32, HRP `ANUBIS-SECRET-KEY-` | 128 B | 230 chars | intact |
| Verifying key | none; embedded in file | 2592 B | n/a | n/a |

The ML-DSA-87 verifying key has **no standalone string encoding**. It is not
needed to encrypt to someone, so it is deliberately absent from the recipient
string; it travels inside signed files in the `-> mldsa87` stanza (section 4.1)
and nowhere else. Implementations MUST NOT add it to the recipient payload,
and MUST NOT define a fourth encoding for it.

### 11.1 Bech32 profile

Recipients and identities are Bech32 strings using the BIP-173 character set,
generator polynomial, and checksum constant. This is `bech32`, not the BIP-350
`bech32m` variant, and the constant is BIP-173's.

The BIP-173 90-character address limit is **not** applied; ANUBIS payloads are
far larger than any Bitcoin address. Implementations MUST use a
no-length-limit encoder and decoder. What *does* matter is the underlying
BCH code length limit of 1023 characters, and the two artifacts fall on
opposite sides of it:

- **Identity: codeword 211 characters (205 data + 6 checksum), inside 1023.**
  The Bech32 guarantee of detecting any up to 4 substitution errors holds in
  full. An identity is a hand-handleable token.
- **Recipient: codeword 2566 characters (2560 data + 6 checksum), far outside
  1023.** Beyond 1023, the guaranteed error-detection property **does not
  hold**. The checksum remains a sound probabilistic integrity check, with
  roughly a `2^-30` chance of accepting a random corruption, but a specific
  adversarial or systematic 4-character corruption is no longer provably
  caught. Treat a recipient's checksum as a typo screen, not as a guarantee,
  and never as an error-correcting code.

This asymmetry is the entire reason recipient fingerprints (section 11.4)
exist. A recipient is a machine and clipboard artifact; the fingerprint is the
human handle used to confirm it out of band.

Bech32 forbids mixed case. Recipients are lowercase throughout; identities are
uppercase throughout. A decoder MUST reject a mixed-case string; MUST reject a
recipient whose HRP is not exactly `anubis`; MUST reject an identity whose HRP
is not exactly `ANUBIS-SECRET-KEY-`; MUST reject any key string containing
whitespace, since each key is a single unwrapped token; and MUST reject a
string whose trailing bit padding is non-zero.

### 11.2 Recipient

```
HRP:     "anubis"                                    (lowercase)
Payload: x25519_public (32) || mlkem_encapsulation_key (1568)
Total:   1600 bytes
String:  "anubis1" + 2560 data characters + 6 checksum characters
Length:  2573 characters
```

1600 bytes is 12800 bits, an exact multiple of 5, so the data part carries no
padding bits. A decoder MUST reject a recipient whose decoded payload is not
exactly 1600 bytes.

### 11.3 Identity

```
HRP:     "ANUBIS-SECRET-KEY-"                        (uppercase)
Payload: x25519_secret_scalar (32)
      || mlkem_seed_d_z       (64)
      || mldsa87_seed         (32)
Total:   128 bytes
String:  "ANUBIS-SECRET-KEY-1" + 205 data characters + 6 checksum characters
Length:  230 characters
```

128 bytes is 1024 bits; 205 five-bit groups carry 1025 bits, so the data part
ends with exactly **1 zero padding bit**. A decoder MUST reject a non-zero
padding bit, and MUST reject an identity whose decoded payload is not exactly
128 bytes.

**Seeds, not expanded keys.** An identity stores three seeds and expands them
at load:

```
mlkem_dk  = ML-KEM-1024.KeyGen_internal(d, z)    from mlkem_seed_d_z  (64 B)
mlkem_ek  = the encapsulation key produced by the same KeyGen
(vk, sk)  = ML-DSA-87.KeyGen(mldsa87_seed)       from mldsa87_seed    (32 B)
x25519_pk = X25519_base(x25519_secret_scalar)
```

Both expansions are the deterministic key generation of their respective
standards: FIPS 203 derives the full 3168-byte decapsulation key from `(d, z)`,
and FIPS 204 derives the 4896-byte signing key and 2592-byte verifying key from
a 32-byte seed. Storing seeds is not a space optimisation with a security
cost; it is the form the standards intend. The `ml-kem` crate exposes
`DecapsulationKey::from_seed` and `to_seed` publicly and documents the expanded
3168-byte form as deprecated in practice in favour of the seed, and `ml-dsa`
takes a 32-byte `B32` seed for key generation. ANUBIS follows that guidance.

The consequence that matters most here is the length one: 128 bytes keeps the
identity codeword at 211 characters, comfortably inside the 1023-character
range where Bech32's error-detection guarantee is intact. The expanded
alternative, 32 + 3168 + 32 = 3232 bytes, would have produced a codeword of
over 5000 characters and put the *secret* key in the degraded regime alongside
the recipient. Seeds keep the artifact a human can transcribe correctly.

**Identities are capability-complete.** One identity decrypts and signs. There
is no separate signing key file, no non-signing identity form, and no way to
hold a decrypt-only identity. Whether a given file is signed is the writer's
per-invocation choice, not a property of the identity.

An identity determines its recipient entirely: expand as above and concatenate
`x25519_pk || mlkem_ek`. Implementations SHOULD verify on load that this
matches the recipient recorded alongside the identity, if one is recorded.

### 11.4 Recipient fingerprint

Because a recipient's Bech32 checksum guarantee is degraded (section 11.1), a
recipient additionally has an 80-bit fingerprint for out-of-band human
verification.

```
fp_bytes = SHA-256(recipient_payload)[0..10]                 (10 bytes)
```

`recipient_payload` is the 1600 raw payload bytes of section 11.2, **not** the
Bech32 string, so the fingerprint is independent of encoding. The rendering is
uppercase hexadecimal, 20 characters, in 5 groups of 4 separated by
HYPHEN-MINUS:

```
ANUBIS-FP: 3F2A-91C7-04BE-D5A8-6612
```

The group separators and the case are presentational; comparison MUST be
performed on `fp_bytes`, and an implementation SHOULD accept operator input
with separators and case in any form. Comparison of fingerprints MUST be
constant time.

80 bits is chosen for transcribability. It resists second-preimage search but
it is **not** collision resistant at a cryptographic level: a birthday attack
against a 10-byte digest costs about `2^40` work, which is achievable. So:

- A fingerprint confirms that a recipient you already have is the one your
  correspondent intended. That is a second-preimage question, and 80 bits is
  ample.
- A fingerprint is **not** an identifier to look a recipient up by, and not
  something to accept a new recipient on the strength of alone in a setting
  where an adversary chose both candidate keys. Verify the fingerprint of a
  recipient you received; do not treat a fingerprint as a substitute for the
  recipient itself.

Two worked vectors, computable by any implementation without reference to
ANUBIS. Digests are given in full so they can be checked exactly:

```
recipient_payload = 1600 bytes of 0x00
SHA-256           = e61f41d57db208c5f92a35c4ce7198570924a3fc87eeba83441fceee5d6a2865
first 10 bytes    = e61f41d57db208c5f92a
fingerprint       = E61F-41D5-7DB2-08C5-F92A

identity_payload  = 128 bytes of 0x00
SHA-256           = 38723a2e5e8a17aa7950dc008209944e898f69a7bd10a23c839d341e935fd5ca
first 10 bytes    = 38723a2e5e8a17aa7950
fingerprint       = 3872-3A2E-5E8A-17AA-7950
```

Reproduce either with:

```sh
head -c 1600 /dev/zero | sha256sum   # recipient vector
head -c 128  /dev/zero | sha256sum   # identity vector
```

Identities are fingerprinted by the same function over the 128-byte identity
payload when an implementation needs to name an identity without displaying it.
An identity fingerprint MUST NOT be presented as a recipient fingerprint; they
are different preimages and will not match.

### 11.5 Secret handling

Identity strings are secrets. Implementations MUST create identity files with
mode `0600` inside a directory created with mode `0700`, MUST NOT write them to
a terminal without an explicit request, MUST NOT include them in any log or
audit record, and SHOULD zeroize in-memory copies of secret scalars, seeds,
expanded secret keys, shared secrets, wrap keys, file keys, and payload keys
when dropped.

Note that the expanded ML-KEM and ML-DSA secret keys are reconstructed in
memory on every load. They are as sensitive as the seeds and MUST be zeroized
on drop as well.

---

## 12. Byte budget

All figures in this section were verified by exact rational arithmetic and
cross-checked against files produced by the reference implementation.

### 12.1 Header

| Component | Bytes |
|---|---|
| Version line | 25 |
| Recipient block (stanza 2163 + wrapped 65) | 2228 |
| `-> mldsa87` stanza line (verifying key only) | 3468 |
| MAC line | 91 |

Header size as a function of recipient count `r`:

```
header(r, unsigned) = 25 + 2228*r + 91          = 116  + 2228*r
header(r, signed)   = 25 + 2228*r + 3468 + 91   = 3584 + 2228*r
```

### 12.2 Signature trailer

```
trailer(unsigned) = 0
trailer(signed)   = 4627
```

A fixed cost, independent of recipient count and file size. Note it is raw,
not Base64: encoding it would have cost 6170 bytes, so the trailer form saves
1544 bytes per signed file.

Total fixed cost of signing is therefore `3468 + 4627 = 8095` bytes.

### 12.3 Per-file overhead

| Recipients | Header unsigned | Header signed | Signed, incl. trailer |
|---|---|---|---|
| 1 | 2344 | 5812 | 10439 |
| 2 | 4572 | 8040 | 12667 |
| 5 | 11256 | 14724 | 19351 |
| 10 | 22396 | 25864 | 30491 |

### 12.4 Payload

```
chunks(len)  = max(1, ceil(len / 65536))
payload(len) = len + 16 * chunks(len)
```

| Plaintext | Chunks | Payload | Tag overhead |
|---|---|---|---|
| 0 | 1 | 16 | 16 |
| 1 | 1 | 17 | 16 |
| 21 | 1 | 37 | 16 |
| 65536 | 1 | 65552 | 16 |
| 65537 | 2 | 65569 | 32 |
| 1 MiB (1048576) | 16 | 1048832 | 256 |
| 1 GiB (1073741824) | 16384 | 1074003968 | 262144 |

Tag overhead is 16 bytes per 65536, that is 1 part in 4096, about 0.0244 percent.

### 12.5 Total file size

```
size(len, r, signed) = header(r, signed) + payload(len) + trailer(signed)
```

One recipient, 1 MiB plaintext:

```
plaintext                        1048576
tag overhead (16 chunks x 16)        256

unsigned:  2344  + 1048832 +    0  = 1051176   overhead   2600  (0.2480%)
signed:    5812  + 1048832 + 4627  = 1059271   overhead  10695  (1.0200%)
```

The header dominates overhead for small files and is negligible for large ones.
A 1 KiB plaintext becomes 3384 bytes unsigned, more than three times the input,
because of the fixed 2344-byte header. ANUBIS is not a good format for
encrypting many tiny files individually; encrypt an archive.

### 12.6 Armored size

Armor (section 9.2) is applied to the finished container. For a container of
`C` bytes, with `B = 4 * ceil(C / 3)`:

```
armored(C) = B + ceil(B / 64) + 74
```

| Plaintext | Recipients | Signed | Container | Armored |
|---|---|---|---|---|
| 18 | 1 | no | 2378 | 3296 |
| 18 | 1 | yes | 10473 | 14257 |
| 12383906 | 1 | no | 12389274 | 16777216 |

The last row is the boundary of the reference implementation's 16777216-byte
armor bound: one more plaintext byte is refused before anything is written.
Armor therefore tops out near 11.81 MiB of plaintext, which is the whole point
of section 9.2 -- armor is for pasting a short container into a message.

### 12.7 Sizes at rest

| Item | Size |
|---|---|
| Recipient string | 2573 characters |
| Identity string | 230 characters |
| Fingerprint, rendered | 24 characters (20 hex + 4 hyphens) |

**Identity file layout.** The file is not bare key material. It carries a
comment preamble, then the identity string on its own line:

```
# ANUBIS identity: default
# created: 2026-08-29T21:02:48Z
# recipient: anubis1...
ANUBIS-SECRET-KEY-1...
```

A parser MUST skip blank lines and lines whose first character is `#`, and MUST
take the first remaining non-blank line as the identity string. The comments
are informational only: the `recipient` comment MUST NOT be trusted, since the
recipient is derivable from the identity, and an implementation SHOULD verify
the two agree and warn if they do not.

Because of the preamble, the file is larger than the 230-character key. With
the three comment lines shown above it is 2877 bytes, dominated by the 2573-
character recipient comment. That size is not normative; the number and content
of comment lines are an implementation choice.

---

## 13. Test vectors

An implementation claiming conformance SHOULD verify at least the following.
These are structural assertions, checkable without a reference
implementation, and they cover the cases where implementations diverge.

1. **Empty plaintext.** Encrypt 0 bytes to one recipient, unsigned. Total file
   is 2344 + 16 = 2360 bytes. The payload is 16 bytes. Decryption yields 0
   bytes.
2. **One byte.** Total file 2344 + 17 = 2361 bytes.
3. **Exact chunk boundary.** Encrypt 65536 bytes. Payload is 65552 bytes, one
   chunk, final nonce `00`x11 `01`. Assert that no second chunk is written.
4. **Chunk boundary plus one.** Encrypt 65537 bytes. Payload is 65569 bytes:
   chunk 0 of 65552 bytes with flag `0x00`, then chunk 1 of 17 bytes with
   flag `0x01`.
5. **Truncation at a boundary.** Take the 65537-byte file, drop the trailing
   17-byte chunk, and assert decryption fails. This is the case that catches a
   missing final-flag lookahead.
6. **Header tamper.** Flip one bit in the `mlkem_ct` field. Assert the failure
   is reported as a header integrity or unwrap failure, and that no plaintext
   is emitted.
7. **Signature stanza strip by a non-recipient.** Remove the `-> mldsa87` line
   from a signed file, leaving the MAC line untouched. Assert header MAC
   verification fails, rather than the file being accepted as unsigned.
   Separately, remove the line *and* the 4627-byte trailer: assert it still
   fails, since the MAC covered the verifying key. Note the limit of this test:
   it establishes only that a party who cannot decrypt cannot strip a
   signature. Vector 23 covers the party who can.
8. **Recipient strip.** From a two-recipient file, remove one recipient block.
   Assert header MAC verification fails for the remaining recipient.
9. **Payload tamper.** Flip one bit in the last chunk of a multi-chunk file.
   Assert failure after earlier chunks decrypted, and that no partial
   plaintext remains at the destination path.
10. **Non-canonical Base64.** Re-encode a 32-byte field so its final character
    has non-zero unused low bits. Assert the header is rejected.
11. **Padded Base64.** Append `=` to any field. Assert rejection.
12. **Identity round trip.** Generate an identity, derive its recipient,
    encrypt to that recipient, decrypt with the identity, assert the plaintext
    matches. Assert the identity string is exactly 230 characters and the
    recipient exactly 2573.
13. **Seed expansion determinism.** Load the same identity twice; assert the
    derived recipient, verifying key, and fingerprint are identical both times.
14. **Wrong identity.** Decrypt a file with an unrelated identity. Assert the
    failure is "no matching identity" and that ML-KEM implicit rejection did
    not surface as a distinct error.
15. **Identity padding bit.** Corrupt an identity's final data character so the
    trailing padding bit is 1. Assert the identity is rejected.
16. **Fingerprint vectors.** Assert the two vectors of section 11.4 reproduce
    exactly.
17. **Signed file geometry.** Encrypt 21 bytes to one recipient with a
    signature. Assert: total 10476 bytes; header 5812; payload region 37 bytes
    (21 + 16); trailer exactly 4627 bytes. Assert `header_len + payload_len +
    4627 == file_size`.
18. **Trailer placement.** On that same file, flip the last byte and assert the
    failure is reported as *signature verification* failing. Then flip the
    first byte after the header and assert the failure is reported as *chunk 0
    authentication* failing. An implementation that reports the same error for
    both, or reports a chunk failure for the first case, has the regions
    swapped or mis-bounded. This is the decisive test for trailer placement.
19. **Payload bound on signed files.** Assert the reader stops the payload at
    `file_size - 4627` and does not feed trailer bytes into the AEAD. A reader
    that reads to EOF fails the final chunk on every signed file, so a signed
    round trip succeeding is itself evidence of correct bounding.
20. **Recipient re-authoring is rejected.** As a legitimate recipient, recover
    the file key from a signed file, encrypt different plaintext under the same
    file key, and splice it in place of the original payload, keeping the header
    and the original trailer. Assert signature verification fails. This is the
    attack that a header-only signature would permit, and the reason `S` covers
    the ciphertext (section 10.6).
21. **Signature context string.** Verify with an empty context string instead of
    `"anubis-v2-file"` and assert verification fails, confirming the context is
    actually passed through.
22. **No plaintext before verification.** On a signed file with a corrupted
    trailer, assert that no output file is left behind. If the implementation
    supports a stdout destination, assert that nothing was written there
    either, or document that a prefix may escape (section 9).
23. **Signature strip by a recipient is undetectable.** As a legitimate
    recipient, produce a container carrying the same plaintext with no
    `-> mldsa87` stanza, a header MAC recomputed under the same file key, and no
    trailer. Assert that it decrypts cleanly and reports itself unsigned. This
    vector is expected to *succeed*: it is the format's stated limitation
    (section 10.6), and an implementation that claims to detect it is claiming
    something false. Then assert that a reader configured to require a
    signature refuses it, which is the only available mitigation.
24. **Non-canonical header lines.** Append one space to the version line of an
    otherwise valid unsigned file, and separately insert a CR before its
    terminating LF. Assert both are rejected as malformed headers, and that the
    rejection happens without reference to any key. An implementation that
    trims and accepts is malleable in exactly the way section 7.1 describes.
25. **Header bounds.** Present a file whose second line is 20000 bytes with no
    LF, and assert rejection on line length rather than an unbounded read.
    Present a header with 1100 recipient blocks and assert rejection on stanza
    count, before any decapsulation is attempted.
26. **Armor round trip and bound.** If the implementation offers armor
    (section 9.2): assert an armored file begins
    `-----BEGIN ANUBIS ENCRYPTED FILE-----`, ends
    `-----END ANUBIS ENCRYPTED FILE-----`, wraps at 64 columns, is detected on
    read without a flag, and round-trips. Assert the size formula of section
    12.6 on a known container. Assert that the write side and the read side
    enforce the same bound, so that no accepted input produces an unreadable
    output.

---

## 14. Security considerations

The format is designed to make specific guarantees. It is at least as
important to state what it does not do. Nothing in this section is a defect to
be fixed later; each item is an accepted consequence of the design.

### 14.1 What the format provides

- **Payload confidentiality** against an adversary who does not hold a
  recipient identity, under the assumption that breaking it requires breaking
  *both* X25519 and ML-KEM-1024 (see `SECURITY.md`).
- **Payload integrity and ordering.** Any modification, truncation,
  reordering, duplication, or cross-file splicing of ciphertext chunks is
  detected.
- **Header integrity, for recipients, against non-recipients.** Any
  modification of the version line, any recipient block, or the signature block
  by a party who cannot decrypt is detected by a recipient. The MAC is computed
  over the raw on-disk bytes and header lines are canonical, so trimmable
  whitespace is not a bypass (section 7.1). This is **not** integrity against
  another recipient: see 14.2.
- **Sender authentication and file commitment,** when a signature is present
  and the verifying key is recognised out of band. The signature covers the
  header and the whole payload ciphertext, so it commits the signer to the exact
  file. What it does not provide is any assurance that a signature was present
  in the first place: see 14.2.

### 14.2 What the format does not provide

**A signature can be removed by any recipient, undetectably.** Every recipient
holds the file key and therefore the header MAC key, so any recipient can emit
a container carrying the same plaintext with the `-> mldsa87` stanza absent, a
valid recomputed header MAC, and no trailer. The result is an ordinary unsigned
ANUBIS file and there is nothing in it to detect. No revision of this format
can prevent it without taking the file key away from recipients, which would
stop them decrypting. Consequences a reader must internalise:

- **Absence of a signature is not evidence that the sender did not sign.**
- **Presence of an unpinned valid signature identifies no one.** It establishes
  that the holder of some ML-DSA-87 key produced these exact bytes, nothing
  more.
- Therefore a reader relying on sender authentication MUST make it a
  precondition, refusing an unsigned container and refusing a signature by any
  key other than one confirmed out of band, rather than inspecting after
  decryption. Section 10.6 names the reference implementation's flags for this.

**Header integrity does not hold against another recipient.** The header MAC
key is derived from the file key, so it authenticates the header to the
recipient set collectively, not to any individual within it. A multi-recipient
file is not compartmentalisation.

**No metadata confidentiality beyond the payload.** The header is plaintext by
construction. Anyone can read it.

**The recipient count is visible.** It is exactly the number of recipient
blocks, trivially computable from the header as
`(header_size - 116) / 2228`, or `(header_size - 9755) / 2228` when signed.
There is no padding and no dummy-recipient mechanism. If the number of
parties addressed is itself sensitive, this format leaks it.

**Recipient identities are not visible, but linkability is limited.** A
recipient block does not name its recipient: it contains only ephemeral
material, so an observer cannot tell who a file is for, and cannot tell whether
two files share a recipient. Trial decryption by a party holding an identity is
the only way to learn that a block is addressed to it. This is a deliberate
strength; it is stated here so it is not confused with the count leak above.

**The plaintext length is inferable to within 65536 bytes,** and in fact much
more tightly: `len` is recoverable exactly as
`payload_size - 16 * ceil(payload_size / 65552)` for all but the empty case.
There is no length padding. File size, and therefore approximate content size,
is public.

**Whether the file is signed is visible,** as is the signer's verifying key, in
the clear, to anyone. A signature block is a public statement that a
particular long-term key produced this file, and it is directly linkable across
every file signed by that key. If the fact of sender identity is sensitive, do
not sign.

**No forward secrecy against identity compromise.** The X25519 ephemeral gives
forward secrecy against compromise of the *ephemeral* key only, which is
discarded immediately. It gives none against compromise of the recipient's
long-term identity. An adversary who records ciphertext today and obtains the
identity later decrypts everything recorded. The ephemeral is per-message, but
the identity is not ratcheted, not rotated by the format, and not bounded in
time. Any long-term-key encryption scheme has this property; ANUBIS does not
escape it. Rotate identities, and re-encrypt archives to new recipients, if
retrospective compromise matters.

Note that because identities are seed-form and capability-complete (section
11.3), one compromised 128-byte identity string yields both decryption and
signing capability. There is no partial compromise.

**No deniability.** A signature is a durable, publicly verifiable artifact tied
to a long-term key. Because `S` covers the payload ciphertext (section 10.6), a
signature is strong: it commits the signer to this exact file, and a recipient
cannot re-author the payload under it. That strength is precisely what removes
deniability. Anyone holding the file and the verifying key can demonstrate that
the signing key produced it.

In the unsigned case the header MAC gives no sender authentication at all,
because every recipient knows the file key and can forge it. So the two modes
are: attributable and non-deniable, or unattributable. There is no
designated-verifier mode, no deniable authentication, and no way to authenticate
to one recipient without also being demonstrable to third parties.

What a signature still does **not** establish, and must not be read as
establishing: *when* the file was produced, whether the sender intended a
particular recipient to hold it now, or that the sender endorsed the plaintext
for any purpose beyond sending it. There is no timestamp and no replay
protection. Treat a signature as "this key produced these exact bytes", not as
a dated, contextual statement of intent.

**No replay protection, no freshness, no ordering between files.** There is no
timestamp, no sequence number, no expiry, and no nonce that a reader could
check against previously seen files. An adversary can deliver an old, valid,
correctly signed file again, and a reader has no in-format way to notice.
Applications needing freshness must put it in the plaintext.

**No filename, permissions, timestamps, or other file metadata.** The format
encrypts a byte stream. Name, mode, ownership, and modification time are not
carried and not protected. Encrypting an archive is the way to preserve them.

**No compression, and none should be added at this layer.** Compressing before
encrypting makes plaintext length a function of plaintext content, which is a
side channel; the CRIME and BREACH results are the standard illustration. If
compression is applied, it is the application's choice and the application's
risk.

**No password-based mode.** There is no passphrase stanza and no KDF over
human input. Identity files are protected by filesystem permissions only, not
by a passphrase. An adversary who reads an identity file has the identity.

**Nothing is hidden from an adversary who holds an identity.** A single
recipient of a multi-recipient file learns the file key and can therefore
decrypt the payload and produce a header MAC indistinguishable from the
sender's. Multi-recipient encryption is not compartmentalisation.

A recipient can also author a *new* file under the same file key that other
recipients will decrypt successfully. What it cannot do is make that file
*signed*: the signature covers the payload ciphertext (section 10.6), so a
re-authored payload fails verification. Unsigned files therefore carry no
protection against a co-recipient impersonating the sender, and signed files do.
If you are encrypting to more than one party and it matters which of them wrote
what, sign.

**The recipient fingerprint is not collision resistant.** 80 bits;
see section 11.4 for exactly what it does and does not establish.

**Availability is not addressed.** An adversary who can modify a file can
always deny access to it. Integrity means damage is detected, not repaired.

**Side channels are out of scope for the format** and are an implementation
concern: constant-time comparison of MACs and fingerprints is mandated above,
and the underlying primitives are expected to be constant-time, but this
document makes no timing, cache, or power-analysis guarantee, and offers no
protection against an adversary with local access to a machine while an
identity is in memory.

---

## 15. Format lineage and version numbering

### 15.1 The three published formats

| Version line | Written by | Construction | Supported here |
|---|---|---|---|
| `anubis-encryption.org/v1` | `anubis-rage` 1.x | Pure ML-KEM-1024 | No |
| `anubis-encryption.org/v2` | `anubis-rage` 1.4.0 | Hybrid, stanza tag `hybrid` | No |
| `anubis-encryption.org/v3` | ANUBIS 2.0.0 | This specification | Yes |

**ANUBIS/v3**, specified by this document: hybrid X25519 + ML-KEM-1024,
ML-DSA-87 signatures, HKDF-SHA-512, transcript-bound KEM combiner, seed-form
capability-complete identities, recipient fingerprints, pure-Rust primitives.

The two `anubis-rage` formats are not interoperable with v3. They differ in the
KEM combiner, the key encodings, and the header grammar, and they required
liboqs. See `MIGRATION.md`.

### 15.2 Why this format is v3 while the software is 2.0.0

The obvious question, answered so that nobody renumbers either value.

`anubis-rage` published two mutually incompatible wire formats and numbered
them v1 and v2. Both identifiers are therefore permanently spent. This
specification describes a third incompatible format, so it takes the next free
identifier, v3.

The software implementing it is version 2.0.0, because it is the second major
release of the ANUBIS tool, following the 1.x `anubis-rage` line. The two
numbering sequences count different things and there is no reason for them to
agree:

- **Wire-format version** counts incompatible on-disk formats. It changes only
  when a file written by the new version cannot be read by the old one.
- **Software version** counts releases of the program.

A future ANUBIS 2.1 or 3.0 that does not change the on-disk format will still
write `anubis-encryption.org/v3`. That is the intended behaviour.

### 15.3 The averted collision, and the rule it establishes

An earlier draft of this specification used `anubis-encryption.org/v2` as its
version line, unaware that `anubis-rage` 1.4.0 had already used that exact
string for its own hybrid mode. Two mutually unparseable formats would have
shared a version identifier, leaving every file written in either format
permanently ambiguous to tooling that had only the version line to go on.

That was corrected before release by moving to v3. The rule it establishes is
normative for all future revisions:

> **A version identifier is spent once published. Any incompatible revision of
> this format MUST take an identifier that has never appeared in any released
> tool, and MUST NOT reuse v1, v2, or v3.** The next available identifier is
> `anubis-encryption.org/v4`.

The check before minting a new identifier is not "is it unused by us" but "is
it unused by anything that ever shipped".

### 15.4 Rejecting legacy files

Because the old formats exist in the wild and one of them was very nearly
confusable with this one, the error behaviour is normative. These are the
failures real users encounter, and a generic parse error wastes their time.

| Detected | Required behaviour |
|---|---|
| Version line `anubis-encryption.org/v1` | Reject at the version line. Error identifies the file as `ANUBIS/v1` from `anubis-rage` 1.x, pure ML-KEM, and points at `MIGRATION.md`. |
| Version line `anubis-encryption.org/v2` | Reject at the version line. Error identifies the file as `ANUBIS/v2` from `anubis-rage` 1.4.0, hybrid, and points at `MIGRATION.md`. |
| First stanza tag exactly `hybrid` | Reject with the same legacy error naming `anubis-rage` 1.4.0. MUST NOT surface as a generic unknown-stanza error. |
| Any other unrecognised version line or stanza tag | Reject as malformed. |

The `hybrid` stanza case is retained as a distinct check even though the v2
version line is now rejected earlier: it costs nothing and it catches a file
whose version line was edited by hand or by a well-meaning script.

Rejection is always fail-closed and always happens before any key material is
used. There is no partial compatibility, no fallback parsing, and no
auto-upgrade path.

### 15.5 Legacy recipients

The same collision affected keys, and here it is not fully averted, because a
human-readable part cannot be renumbered without changing every recipient
string. `anubis-rage` used the Bech32 human-readable part `anubis`, so its
recipients also begin `anubis1`, rendered in its documentation as
`anubis1hybrid1x25519...mlkem1024...`.

Old and new recipients are distinguishable only by decoded payload length.
This specification requires the decoded recipient payload to be **exactly 1600
bytes** (section 11.2). An old-style recipient does not satisfy it. That
length check is therefore load-bearing rather than a defensive nicety:

- An implementation MUST enforce the 1600-byte length on every recipient
  decode, before the payload is used.
- When the human-readable part is `anubis` but the decoded length differs, an
  implementation SHOULD report that the string looks like an `anubis-rage`
  1.4.0 recipient and point at `MIGRATION.md`, rather than reporting a bare
  length mismatch.

Identities do not collide: `anubis-rage` did not use the human-readable part
`ANUBIS-SECRET-KEY-`.
