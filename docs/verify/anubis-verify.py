#!/usr/bin/env python3
"""
anubis-verify.py -- an INDEPENDENT ANUBIS/v3 container parser and signature verifier.

Written from docs/FORMAT.md ALONE (no reference source was consulted).  Pure Python
3 standard library, except that the ML-DSA-87 primitive itself is delegated to the
`openssl` binary (>= 3.5), because Python has no ML-DSA.

What it does, per the spec:
  * parses the header grammar of section 4.1 strictly (canonical lines, section 1)
  * computes the region geometry of section 3
  * computes the chunk count of section 8.3 from the payload byte count alone
  * renders the signer fingerprint of section 11.4 applied to the verifying key
    (as section 10.6 directs)
  * computes S = SHA-512(header_bytes || payload_ciphertext)   (section 10.2)
  * verifies ML-DSA-87.Verify(vk, S, sig, ctx="anubis-v2-file"), pure, not
    HashML-DSA                                                  (section 10.2/10.5)

What it deliberately does NOT do: anything requiring the file key.  The header MAC
(section 7) is keyed by HKDF(file_key), so a keyless verifier cannot check it.  It
is reported as unverifiable, never as "ok".

Exit codes:
  0  signature present and VALID
  1  signature present and INVALID (FAIL)
  2  no signature present (ABSENT)
  3  malformed container / spec violation
  4  environment problem (openssl missing or unusable)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------- constants
# All of these are quoted from FORMAT.md; the section is given for each.

VERSION_LINE = b"anubis-encryption.org/v3"           # sec 4.1
LEGACY_VERSION_LINES = {                             # sec 15.4
    b"anubis-encryption.org/v1": "ANUBIS/v1 from anubis-rage 1.x (pure ML-KEM); see MIGRATION.md",
    b"anubis-encryption.org/v2": "ANUBIS/v2 from anubis-rage 1.4.0 (hybrid); see MIGRATION.md",
}
TAG_RECIPIENT = b"-> hybrid-x25519-mlkem1024"        # sec 4.1
TAG_SIGNATURE = b"-> mldsa87"                        # sec 4.1
TAG_MAC = b"---"                                     # sec 4.1

MAX_HEADER_LINE = 8192                               # sec 1
MAX_STANZAS = 1024                                   # sec 4.3
MAX_ARMOR_BYTES = 16777216                           # sec 9.2
# Exact largest v3 header from sec 4.2: version, every permitted recipient
# block, one optional signature stanza, and the final MAC line.
MAX_HEADER_BYTES = 25 + MAX_STANZAS * (2163 + 65) + 3468 + 91
HASH_BLOCK_BYTES = 1024 * 1024

LEN_X25519_EPK = 32                                  # sec 2
LEN_MLKEM_CT = 1568                                  # sec 2
LEN_WRAPPED_FILE_KEY = 48                            # sec 2
LEN_MLDSA_VK = 2592                                  # sec 2
LEN_MLDSA_SIG = 4627                                 # sec 2
LEN_HEADER_MAC = 64                                  # sec 2 (HMAC-SHA-512)
LEN_POLY1305_TAG = 16                                # sec 2
CHUNK_PLAINTEXT = 65536                              # sec 2 / 8.1
CHUNK_CIPHERTEXT = CHUNK_PLAINTEXT + LEN_POLY1305_TAG  # 65552, sec 8.1

SIG_CONTEXT = b"anubis-v2-file"                      # sec 10.2, 14 ASCII bytes
FP_BYTES = 10                                        # sec 11.4, SHA-256 truncated

ARMOR_BEGIN = b"-----BEGIN ANUBIS ENCRYPTED FILE-----"   # sec 9.2
ARMOR_END = b"-----END ANUBIS ENCRYPTED FILE-----"       # sec 9.2

B64_ALPHABET = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


class Malformed(Exception):
    """The container violates FORMAT.md.  Fail closed (sec 1, sec 9)."""


class VerifierUnavailable(Exception):
    """The ML-DSA-87 backend could not render a verdict.

    Kept strictly distinct from Malformed and from a FAIL verdict: an
    environment problem is not evidence about the file.
    """


def terminal_safe(text: str) -> str:
    """Render user-controlled text without emitting terminal controls."""
    rendered: list[str] = []
    for character in text:
        if character.isprintable() and character not in ("\u2028", "\u2029"):
            rendered.append(character)
        else:
            rendered.append(character.encode("unicode_escape").decode("ascii"))
    return "".join(rendered)


# ---------------------------------------------------------------- base64, sec 1
def b64_decode_exact(s: bytes, want_len: int, what: str) -> bytes:
    """Standard Base64, RFC 4648 sec 4, with ALL '=' padding removed (sec 1).

    Rejects: '=' anywhere, characters outside the alphabet, whitespace,
    len % 4 == 1, non-canonical encodings (final character with non-zero unused
    low bits), and a decoded length other than `want_len`.
    """
    if b"=" in s:
        raise Malformed(f"{what}: base64 carries '=' padding (sec 1 forbids it)")
    for ch in s:
        if ch not in B64_ALPHABET:
            raise Malformed(
                f"{what}: byte 0x{ch:02x} is outside the base64 alphabet (sec 1)"
            )
    n = len(s)
    if n % 4 == 1:
        raise Malformed(f"{what}: base64 length {n} is 1 mod 4 (sec 1)")
    # Canonicality: the trailing character must have its unused low bits clear.
    if n % 4 in (2, 3):
        tail = base64.b64decode(s + b"=" * (4 - n % 4), validate=True)
        if base64.b64encode(tail).rstrip(b"=") != s:
            raise Malformed(
                f"{what}: non-canonical base64, final character has non-zero "
                f"unused low bits (sec 1)"
            )
    try:
        raw = base64.b64decode(s + b"=" * (-n % 4), validate=True)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - screened
        raise Malformed(f"{what}: base64 decode failed: {exc}") from exc
    if len(raw) != want_len:
        raise Malformed(
            f"{what}: decoded length {len(raw)}, expected {want_len} (sec 4.1)"
        )
    # b64 of an n-byte string is exactly ceil(4n/3) characters (sec 1).
    expect_chars = -(-4 * want_len // 3)
    if n != expect_chars:
        raise Malformed(
            f"{what}: base64 is {n} characters, expected {expect_chars} (sec 1)"
        )
    return raw


# ---------------------------------------------------------------- fingerprint, sec 11.4
def fp_bytes(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()[:FP_BYTES]


def fp_render(fp: bytes) -> str:
    """Uppercase hex, 20 characters, 5 groups of 4 separated by HYPHEN-MINUS."""
    h = fp.hex().upper()
    return "-".join(h[i:i + 4] for i in range(0, 20, 4))


def fp_parse(text: str) -> bytes:
    """Accept operator input with separators and case in any form (sec 11.4)."""
    h = "".join(c for c in text if c not in "- \t:_").lower()
    if len(h) != 2 * FP_BYTES:
        raise Malformed(f"fingerprint {text!r} is not {2 * FP_BYTES} hex digits")
    try:
        return bytes.fromhex(h)
    except ValueError as exc:
        raise Malformed(f"fingerprint {text!r} is not hexadecimal") from exc


# ---------------------------------------------------------------- armor, sec 9.2
def dearmor_if_needed(data: bytes) -> tuple[bytes, bool]:
    """Armor is a transport encoding, detected by the opening boundary line."""
    if not data.startswith(ARMOR_BEGIN):
        return data, False
    if len(data) > MAX_ARMOR_BYTES:
        raise Malformed(
            f"armored input is {len(data)} bytes, over MAX_ARMOR_BYTES "
            f"{MAX_ARMOR_BYTES} (sec 9.2)"
        )
    # Do not use bytes.splitlines()/split here. An accepted-size input may
    # contain millions of tiny lines; materialising one Python object per line
    # turns the byte cap into an unauthenticated memory-amplification path.
    # Scan by offset and retain only the bounded body plus one line at a time.
    first_lf = data.find(b"\n")
    if first_lf < 0 or data[:first_lf] != ARMOR_BEGIN:
        raise Malformed("armor boundary lines are malformed (sec 9.2)")

    body = bytearray()
    previous_body_line: bytes | None = None
    position = first_lf + 1
    saw_end = False
    while position <= len(data):
        lf = data.find(b"\n", position)
        line_end = len(data) if lf < 0 else lf
        if line_end - position > 64:
            # The end boundary is shorter than the body-line cap, so no valid
            # line is lost by refusing before slicing an attacker-sized span.
            raise Malformed("armor body is not wrapped at 64 columns (sec 9.2)")
        if lf < 0:
            line = data[position:line_end]
            next_position = len(data) + 1
        else:
            line = data[position:line_end]
            next_position = lf + 1

        if line == ARMOR_END:
            # Match the former parser's exact trailer policy: the end boundary
            # may be the final bytes or carry one final LF, with nothing after.
            if lf >= 0 and next_position != len(data):
                raise Malformed("armor boundary lines are malformed (sec 9.2)")
            if previous_body_line is None:
                raise Malformed("armor body is missing (sec 9.2)")
            if not 1 <= len(previous_body_line) <= 64:
                raise Malformed("armor body is not wrapped at 64 columns (sec 9.2)")
            body.extend(previous_body_line)
            saw_end = True
            break

        if previous_body_line is not None:
            # "wrapped at 64 columns" means every non-final data line is
            # exactly 64 characters. Reject short-line floods immediately.
            if len(previous_body_line) != 64:
                raise Malformed("armor body is not wrapped at 64 columns (sec 9.2)")
            body.extend(previous_body_line)
        previous_body_line = line

        if lf < 0:
            break
        position = next_position

    if not saw_end:
        raise Malformed("armor boundary lines are malformed (sec 9.2)")
    try:
        decoded = base64.b64decode(body, validate=True)
        return decoded, True
    except (binascii.Error, ValueError) as exc:
        raise Malformed(f"armor base64 decode failed: {exc}") from exc


# ---------------------------------------------------------------- header, sec 4
class Line:
    __slots__ = ("content", "start", "end")

    def __init__(self, content: bytes, start: int, end: int) -> None:
        self.content = content   # without the terminating LF
        self.start = start       # offset of first byte of the line
        self.end = end           # offset just past the terminating LF


def read_line(data: bytes, pos: int) -> Line:
    """One canonical header line (sec 1).

    A header line MUST consist of its defined content followed immediately by
    one 0x0A.  CR is not permitted anywhere in the header, nor is any other
    trailing whitespace, and a parser MUST reject rather than trim.  Lines are
    bounded at MAX_HEADER_LINE so a file with no 0x0A cannot force an unbounded
    read before any key material is involved.
    """
    limit = min(len(data), pos + MAX_HEADER_LINE + 1)
    nl = data.find(b"\n", pos, limit)
    if nl < 0:
        if limit == len(data):
            raise Malformed(
                f"header ends without a line feed at offset {pos} "
                f"(header not terminated by a MAC line, sec 4.3)"
            )
        raise Malformed(
            f"header line at offset {pos} exceeds MAX_HEADER_LINE "
            f"{MAX_HEADER_LINE} bytes (sec 1)"
        )
    content = data[pos:nl]
    if b"\r" in content:
        raise Malformed(f"header line at offset {pos} contains CR 0x0D (sec 1)")
    for ch in content:
        if ch > 0x7F:
            raise Malformed(
                f"header line at offset {pos} contains non-ASCII byte "
                f"0x{ch:02x} (sec 1: the header is US-ASCII)"
            )
    if content and content[-1:] in (b" ", b"\t", b"\x0b", b"\x0c"):
        raise Malformed(
            f"header line at offset {pos} carries trailing whitespace; a parser "
            f"MUST reject rather than trim (sec 1, sec 7.1)"
        )
    return Line(content, pos, nl + 1)


class Header:
    def __init__(self) -> None:
        self.recipients: list[dict] = []
        self.verifying_key: bytes | None = None
        self.header_mac: bytes = b""
        self.header_len: int = 0
        self.mac_line_start: int = 0


def parse_header(data: bytes) -> Header:
    h = Header()
    pos = 0

    # 1. version line: MUST be first, exactly once (sec 4.3)
    ln = read_line(data, pos)
    if ln.content in LEGACY_VERSION_LINES:
        raise Malformed(
            f"legacy container: {LEGACY_VERSION_LINES[ln.content]} (sec 15.4)"
        )
    if ln.content != VERSION_LINE:
        raise Malformed(
            f"unknown version line {ln.content!r}; expected "
            f"{VERSION_LINE.decode()!r} (sec 4.1, sec 15.4)"
        )
    pos = ln.end

    seen_mac = False
    while not seen_mac:
        ln = read_line(data, pos)
        c = ln.content

        if c.startswith(TAG_MAC + b" ") or c == TAG_MAC:
            # 4. MAC line MUST be last and MUST appear exactly once (sec 4.3)
            if not c.startswith(TAG_MAC + b" "):
                raise Malformed("MAC line is missing its base64 field (sec 4.1)")
            h.header_mac = b64_decode_exact(
                c[len(TAG_MAC) + 1:], LEN_HEADER_MAC, "header MAC"
            )
            h.mac_line_start = ln.start
            h.header_len = ln.end
            seen_mac = True
            break

        if c.startswith(TAG_SIGNATURE + b" ") or c == TAG_SIGNATURE:
            # 3. at most one signature block, AFTER the recipient blocks (sec 4.3)
            if h.verifying_key is not None:
                raise Malformed("more than one mldsa87 stanza (sec 4.3)")
            if not h.recipients:
                raise Malformed(
                    "mldsa87 stanza appears before any recipient block (sec 4.3)"
                )
            if not c.startswith(TAG_SIGNATURE + b" "):
                raise Malformed("mldsa87 stanza is missing its base64 field")
            h.verifying_key = b64_decode_exact(
                c[len(TAG_SIGNATURE) + 1:], LEN_MLDSA_VK, "mldsa87 verifying key"
            )
            if len(ln.content) + 1 != 3468:
                raise Malformed(
                    f"mldsa87 stanza line is {len(ln.content) + 1} bytes, "
                    f"expected 3468 (sec 4.2)"
                )
            pos = ln.end
            continue

        if c.startswith(TAG_RECIPIENT + b" "):
            if h.verifying_key is not None:
                raise Malformed(
                    "recipient block follows the mldsa87 stanza; recipient blocks "
                    "come first (sec 4.3)"
                )
            if len(h.recipients) >= MAX_STANZAS:
                raise Malformed(
                    f"more than MAX_STANZAS {MAX_STANZAS} recipient blocks; this "
                    f"is a header error, not 'no matching identity' (sec 4.3)"
                )
            fields = c[len(TAG_RECIPIENT) + 1:].split(b" ")
            if len(fields) != 2:
                raise Malformed(
                    f"recipient stanza has {len(fields)} fields after the tag, "
                    f"expected 2 (sec 4.1)"
                )
            epk = b64_decode_exact(fields[0], LEN_X25519_EPK, "x25519_epk")
            ct = b64_decode_exact(fields[1], LEN_MLKEM_CT, "mlkem_ct")
            if len(ln.content) + 1 != 2163:
                raise Malformed(
                    f"recipient stanza line is {len(ln.content) + 1} bytes, "
                    f"expected 2163 (sec 4.2)"
                )
            # wrapped-line follows immediately (sec 4.1: recipient-block =
            # stanza-line wrapped-line)
            w = read_line(data, ln.end)
            wrapped = b64_decode_exact(
                w.content, LEN_WRAPPED_FILE_KEY, "wrapped file key"
            )
            if len(w.content) + 1 != 65:
                raise Malformed(
                    f"wrapped file key line is {len(w.content) + 1} bytes, "
                    f"expected 65 (sec 4.2)"
                )
            h.recipients.append(
                {"x25519_epk": epk, "mlkem_ct": ct, "wrapped_file_key": wrapped}
            )
            pos = w.end
            continue

        # Unknown stanza tags are NOT skipped; there is no extension
        # mechanism (sec 4.3).  The bare `hybrid` tag gets its own error
        # (sec 15.4), even though the v2 version line is rejected earlier.
        tag = c.split(b" ", 1)[0]
        if c.startswith(b"-> "):
            tag = c[3:].split(b" ", 1)[0]
            if tag == b"hybrid":
                raise Malformed(
                    "stanza tag 'hybrid': this is an anubis-rage 1.4.0 "
                    "(ANUBIS/v2) container; see MIGRATION.md (sec 15.4)"
                )
            raise Malformed(f"unknown stanza tag {tag!r} (sec 4.3)")
        raise Malformed(
            f"unrecognised header line at offset {ln.start}: {c[:48]!r} (sec 4.1)"
        )

    if not h.recipients:
        raise Malformed("zero recipient blocks (sec 4.3)")
    if len(h.header_mac) != LEN_HEADER_MAC:  # pragma: no cover
        raise Malformed("header MAC is not 64 bytes")
    if h.header_len != h.mac_line_start + 91:
        raise Malformed(
            f"MAC line is {h.header_len - h.mac_line_start} bytes, expected 91 "
            f"(sec 4.2)"
        )
    return h


# ---------------------------------------------------------------- geometry, sec 3 / 8.3
def chunk_count(payload_len: int) -> int:
    """Chunk boundaries come from the remaining byte count, not any in-band
    length (sec 8.3).  A full ciphertext chunk is 65552 bytes; the final chunk
    is 16..65552.  A zero-length payload is invalid and MUST be rejected."""
    if payload_len < LEN_POLY1305_TAG:
        raise Malformed(
            f"payload region is {payload_len} bytes; the payload of even an "
            f"empty file is 16 bytes and a zero-length payload is invalid "
            f"(sec 8.3)"
        )
    full, rem = divmod(payload_len, CHUNK_CIPHERTEXT)
    if rem == 0:
        return full
    if rem < LEN_POLY1305_TAG:
        raise Malformed(
            f"payload region's final chunk is {rem} bytes, shorter than the "
            f"16-byte tag: truncated payload (sec 8.3 step 2)"
        )
    return full + 1


def plaintext_len(payload_len: int, chunks: int) -> int:
    """`len` is recoverable exactly as payload_size - 16*chunks (sec 14.2)."""
    return payload_len - LEN_POLY1305_TAG * chunks


# ---------------------------------------------------------------- ML-DSA via openssl
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


# id-ml-dsa-87, 2.16.840.1.101.3.4.3.19 (FIPS 204 / RFC 9881 OID arc)
OID_ML_DSA_87 = bytes.fromhex("0609608648016503040313")


def spki_from_raw_vk(vk: bytes) -> bytes:
    """SubjectPublicKeyInfo wrapper so the openssl CLI can load the raw key.

    NOTE: this wrapper is NOT part of ANUBIS/v3.  FORMAT.md sec 11 is explicit
    that the verifying key has no standalone string encoding and travels raw in
    the `-> mldsa87` stanza.  The DER is purely a transport into openssl.
    """
    alg = b"\x30" + _der_len(len(OID_ML_DSA_87)) + OID_ML_DSA_87
    bits = b"\x00" + vk
    bitstring = b"\x03" + _der_len(len(bits)) + bits
    body = alg + bitstring
    return b"\x30" + _der_len(len(body)) + body


def openssl_mldsa87_verify(
    vk: bytes, message: bytes, signature: bytes, context: bytes, openssl: str = "openssl"
) -> tuple[bool, str]:
    """ML-DSA-87.Verify(vk, message, signature, ctx) -- PURE, not HashML-DSA.

    `-rawin` hands openssl the message unhashed, which is what pure ML-DSA
    wants: the 64-byte digest S is the message, not something to hash again.
    The context string is passed as an octet-string pkeyopt (sec 10.2 requires
    it be passed to verify, and forbids an empty context).
    """
    with tempfile.TemporaryDirectory() as td:
        pk = os.path.join(td, "vk.der")
        mf = os.path.join(td, "msg.bin")
        sf = os.path.join(td, "sig.bin")
        with open(pk, "wb") as f:
            f.write(spki_from_raw_vk(vk))
        with open(mf, "wb") as f:
            f.write(message)
        with open(sf, "wb") as f:
            f.write(signature)
        cmd = [
            openssl, "pkeyutl", "-verify",
            "-pubin", "-inkey", pk, "-keyform", "DER",
            "-rawin", "-in", mf, "-sigfile", sf,
        ]
        if context:
            cmd += ["-pkeyopt", "hexcontext-string:" + context.hex()]
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=120)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise VerifierUnavailable(f"cannot run openssl: {exc}") from exc
        out = (p.stdout + p.stderr).decode("utf-8", "replace").strip()
        if p.returncode == 0 and "Verified Successfully" in out:
            return True, out
        # Fail closed, but do not launder an environment problem into a
        # cryptographic verdict: only openssl's own "Signature Verification
        # Failure" counts as a real FAIL.  A key-loading or provider error is
        # an EnvironmentError, not evidence about the file.
        if "Signature Verification Failure" in out:
            return False, out
        raise VerifierUnavailable(
            f"openssl could not perform the ML-DSA-87 verification (rc="
            f"{p.returncode}): {out}"
        )


# ---------------------------------------------------------------- top level
def _read_exact_region(source, offset: int, length: int) -> bytes:
    source.seek(offset)
    data = source.read(length)
    if len(data) != length:
        raise Malformed("container changed or ended while it was being verified")
    return data


def _hash_prefix(read_region, end: int) -> bytes:
    digest = hashlib.sha512()
    offset = 0
    while offset < end:
        length = min(HASH_BLOCK_BYTES, end - offset)
        digest.update(read_region(offset, length))
        offset += length
    return digest.digest()


def _analyse_decoded(
    path: str,
    header_data: bytes,
    file_size: int,
    armored: bool,
    read_region,
    openssl: str,
    expect_signer: str | None,
) -> dict:
    h = parse_header(header_data)
    header_len = h.header_len
    signed = h.verifying_key is not None
    sig_len = LEN_MLDSA_SIG if signed else 0            # sec 3

    if signed and file_size < header_len + LEN_POLY1305_TAG + LEN_MLDSA_SIG:
        raise Malformed(
            f"signed file is {file_size} bytes, below header_len + 16 + 4627 = "
            f"{header_len + 16 + LEN_MLDSA_SIG} (sec 3)"
        )
    payload_len = file_size - header_len - sig_len
    if payload_len < 0:
        raise Malformed(
            f"file is {file_size} bytes, shorter than header {header_len} + "
            f"trailer {sig_len} (sec 3)"
        )
    chunks = chunk_count(payload_len)

    # Expected header size, sec 12.1 -- an independent cross-check of the parse.
    expect_header = 116 + 2228 * len(h.recipients) + (3468 if signed else 0)
    if expect_header != header_len:
        raise Malformed(
            f"header is {header_len} bytes; sec 12.1 formula for "
            f"{len(h.recipients)} recipient(s), signed={signed} gives "
            f"{expect_header}"
        )

    res = {
        "path": os.path.abspath(path),
        "format": VERSION_LINE.decode(),
        "armored": armored,
        "file_size": file_size,
        "recipients": len(h.recipients),
        "header_bytes": header_len,
        "payload_bytes": payload_len,
        "chunks": chunks,
        "plaintext_bytes": plaintext_len(payload_len, chunks),
        "signed": signed,
        "trailer_bytes": sig_len,
        # sec 7.2: the MAC key comes from the file key, so a keyless verifier
        # cannot check it.  Never report it as ok.
        "header_mac_ok": None,
        "header_mac_note": "requires the file key (sec 7.2); not checkable keylessly",
        "signer_fingerprint": None,
        "signature_ok": None,
        "result": None,
        "detail": None,
    }

    if not signed:
        res["result"] = "ABSENT"
        res["detail"] = (
            "no -> mldsa87 stanza, so no trailer. Absence of a signature carries "
            "no information about whether the sender signed (sec 10.6/14.2)."
        )
        return res

    vk = h.verifying_key
    fp = fp_bytes(vk)                                    # sec 11.4 via sec 10.6
    res["signer_fingerprint"] = fp_render(fp)
    res["signer_fingerprint_hex"] = fp.hex()

    signature = read_region(file_size - LEN_MLDSA_SIG, LEN_MLDSA_SIG)
    # S covers exactly the decoded bytes preceding the fixed signature trailer.
    # Read in bounded blocks so a valid binary container never needs a second
    # attacker-sized in-memory or on-disk copy.
    S = _hash_prefix(read_region, file_size - LEN_MLDSA_SIG)  # sec 10.2
    res["digest_S"] = S.hex()

    ok, detail = openssl_mldsa87_verify(vk, S, signature, SIG_CONTEXT, openssl)
    res["signature_ok"] = ok
    res["detail"] = detail

    if not ok:
        res["result"] = "FAIL"
        return res

    if expect_signer is not None:
        want = fp_parse(expect_signer)
        if not hmac.compare_digest(want, fp):            # sec 11.4: constant time
            res["result"] = "FAIL"
            res["detail"] = (
                f"signature is valid but by {fp_render(fp)}, not the pinned "
                f"{fp_render(want)}"
            )
            return res
        res["signer_pinned"] = True

    res["result"] = "VALID"
    return res


def analyse(path: str, openssl: str = "openssl", expect_signer: str | None = None) -> dict:
    with open(path, "rb") as source:
        before = os.fstat(source.fileno())
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )

        def ensure_source_unchanged(kind: str) -> None:
            after = os.fstat(source.fileno())
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if after_identity != before_identity:
                raise Malformed(f"{kind} container changed while it was being verified")

        prefix = source.read(len(ARMOR_BEGIN))
        source.seek(0)

        if prefix.startswith(ARMOR_BEGIN):
            if before.st_size > MAX_ARMOR_BYTES:
                raise Malformed(
                    f"armored input is {before.st_size} bytes, over MAX_ARMOR_BYTES "
                    f"{MAX_ARMOR_BYTES} (sec 9.2)"
                )
            raw = source.read(MAX_ARMOR_BYTES + 1)
            if len(raw) > MAX_ARMOR_BYTES:
                raise Malformed(
                    f"armored input exceeds MAX_ARMOR_BYTES {MAX_ARMOR_BYTES} (sec 9.2)"
                )
            data, armored = dearmor_if_needed(raw)
            del raw

            def read_region(offset: int, length: int) -> bytes:
                end = offset + length
                region = data[offset:end]
                if len(region) != length:
                    raise Malformed("decoded armor ended while it was being verified")
                return region

            result = _analyse_decoded(
                path,
                data[:MAX_HEADER_BYTES + 1],
                len(data),
                armored,
                read_region,
                openssl,
                expect_signer,
            )
            ensure_source_unchanged("armored")
            return result

        # Binary input remains on the same open handle. Only the maximally
        # sized header prefix is materialized; payload hashing is streaming.
        header_data = source.read(MAX_HEADER_BYTES + 1)

        def read_region(offset: int, length: int) -> bytes:
            return _read_exact_region(source, offset, length)

        result = _analyse_decoded(
            path,
            header_data,
            before.st_size,
            False,
            read_region,
            openssl,
            expect_signer,
        )
        ensure_source_unchanged("binary")
        return result


def render_text(r: dict, verbose: bool) -> str:
    L = []
    A = L.append
    A(f"file                {terminal_safe(r['path'])}")
    A(f"format              {r['format']}" + ("  (ASCII-armored)" if r["armored"] else ""))
    A(f"file size           {r['file_size']} bytes")
    A(f"recipients          {r['recipients']}")
    A(f"header_bytes        {r['header_bytes']}")
    A(f"payload_bytes       {r['payload_bytes']}")
    A(f"chunks              {r['chunks']}")
    A(f"plaintext_bytes     {r['plaintext_bytes']}  (inferred, sec 14.2)")
    A(f"signed              {'yes' if r['signed'] else 'no'}")
    A(f"trailer_bytes       {r['trailer_bytes']}")
    A("header_mac_ok       unverifiable without the file key (sec 7.2)")
    if r["signed"]:
        A(f"signer_fingerprint  {r['signer_fingerprint']}")
        if verbose:
            A(f"S (SHA-512)         {r['digest_S']}")
    A("")
    if r["result"] == "VALID":
        A(f"SIGNATURE: VALID -- ML-DSA-87, pure, ctx=\"anubis-v2-file\"")
        A(f"           signed by {r['signer_fingerprint']}")
        if r.get("signer_pinned"):
            A("           and that fingerprint matches the pinned value")
        else:
            A("           an unpinned valid signature identifies no one (sec 10.6);")
            A("           compare this fingerprint against a value confirmed out of band.")
    elif r["result"] == "FAIL":
        A("SIGNATURE: FAIL -- the signature does not verify over this file")
        detail = r["detail"].splitlines()[-1] if r["detail"] else ""
        A(f"           {terminal_safe(detail)}")
    elif r["result"] == "ABSENT":
        A("SIGNATURE: ABSENT -- this container carries no -> mldsa87 stanza")
        A("           Absence of a signature is NOT evidence the sender did not")
        A("           sign: any recipient can strip one undetectably (sec 14.2).")
    return "\n".join(L)


def selftest(openssl: str) -> int:
    """The checkable-without-a-reference-implementation vectors of sec 13."""
    fails = 0

    def check(name, got, want):
        nonlocal fails
        ok = got == want
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: got {got!r}")
        if not ok:
            print(f"         expected {want!r}")
            fails += 1

    print("sec 13 vector 16 -- fingerprint vectors (sec 11.4):")
    check("recipient, 1600 zero bytes", fp_render(fp_bytes(b"\x00" * 1600)),
          "E61F-41D5-7DB2-08C5-F92A")
    check("identity, 128 zero bytes", fp_render(fp_bytes(b"\x00" * 128)),
          "3872-3A2E-5E8A-17AA-7950")

    print("sec 12.4 -- chunk count formula:")
    for payload, want in [(16, 1), (17, 1), (37, 1), (65552, 1), (65569, 2),
                          (1048832, 16), (1074003968, 16384)]:
        check(f"payload {payload}", chunk_count(payload), want)

    print("sec 12.1 -- header size formula:")
    for r, signed, want in [(1, False, 2344), (1, True, 5812), (2, True, 8040),
                            (5, True, 14724), (10, True, 25864)]:
        check(f"r={r} signed={signed}", 116 + 2228 * r + (3468 if signed else 0), want)

    print("sec 1 -- base64 canonicality:")
    for bad, why in [(b"AAAB", "wrong length for 32 B"),
                     (b"AA==", "carries padding"),
                     (b"A", "1 mod 4")]:
        try:
            b64_decode_exact(bad, 32, "test")
            print(f"  [FAIL] {why}: accepted")
            fails += 1
        except Malformed:
            print(f"  [PASS] {why}: rejected")
    # non-canonical: 32 bytes is 43 chars; last char has 2 unused low bits
    good = base64.b64encode(b"\x00" * 32).rstrip(b"=")
    bad = good[:-1] + b"B"   # 'A'=0 -> 'B'=1, low bit set
    try:
        b64_decode_exact(bad, 32, "test")
        print("  [FAIL] non-canonical trailing bits: accepted")
        fails += 1
    except Malformed:
        print("  [PASS] non-canonical trailing bits: rejected")

    print("sec 9.2 -- canonical armor wrapping:")
    canonical_armor = ARMOR_BEGIN + b"\nQUJD\n" + ARMOR_END + b"\n"
    check("single final data line", dearmor_if_needed(canonical_armor), (b"ABC", True))
    short_nonfinal = ARMOR_BEGIN + b"\nA\nAAA\n" + ARMOR_END + b"\n"
    try:
        dearmor_if_needed(short_nonfinal)
        print("  [FAIL] short non-final data line: accepted")
        fails += 1
    except Malformed:
        print("  [PASS] short non-final data line: rejected")

    print("terminal diagnostics:")
    check("control rendering", terminal_safe("path\x1b[2J\nnext"),
          "path\\x1b[2J\\nnext")

    print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILURE(S)'}")
    return 0 if fails == 0 else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Independent ANUBIS/v3 parser and ML-DSA-87 signature verifier "
                    "(derived from docs/FORMAT.md alone).")
    ap.add_argument("file", nargs="?", help="container to verify")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--openssl", default="openssl", help="path to the openssl binary")
    ap.add_argument("--signer", metavar="FINGERPRINT",
                    help="require the signature be by this fingerprint (sec 10.6)")
    ap.add_argument("--require-signature", action="store_true",
                    help="fail on an unsigned container (sec 10.6/14.2)")
    ap.add_argument("--selftest", action="store_true",
                    help="run the sec 13 vectors that need no reference implementation")
    ap.add_argument("--context", default=None,
                    help="override the ML-DSA context string (for negative testing "
                         "of sec 13 vector 21); default is anubis-v2-file")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest(a.openssl)
    if not a.file:
        ap.error("a container path is required (or --selftest)")

    global SIG_CONTEXT
    if a.context is not None:
        SIG_CONTEXT = a.context.encode()

    try:
        r = analyse(a.file, a.openssl, a.signer)
    except Malformed as exc:
        if a.json:
            print(json.dumps({"result": "MALFORMED", "error": str(exc)}))
        else:
            print(f"MALFORMED: {terminal_safe(str(exc))}", file=sys.stderr)
        return 3
    except VerifierUnavailable as exc:
        print(f"ENVIRONMENT: {terminal_safe(str(exc))}", file=sys.stderr)
        return 4
    except MemoryError:
        print("ENVIRONMENT: verifier memory limit exhausted", file=sys.stderr)
        return 4
    except OSError as exc:
        print(
            f"ENVIRONMENT: cannot read {terminal_safe(a.file)}: "
            f"{terminal_safe(str(exc))}",
            file=sys.stderr,
        )
        return 4

    if a.json:
        print(json.dumps(r, sort_keys=True))
    else:
        print(render_text(r, a.verbose))

    if r["result"] == "VALID":
        return 0
    if r["result"] == "FAIL":
        return 1
    # ABSENT
    return 2 if not a.require_signature else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
