#!/bin/sh
# ----------------------------------------------------------------------------
# openssl-verify.sh -- independently verify the ML-DSA-87 signature of an
#                      ANUBIS/v3 container using ONLY stock OpenSSL >= 3.5,
#                      POSIX shell, and the Linux /proc descriptor view.  No
#                      ANUBIS code, no Rust, no Python.
#
# Usage:  ./openssl-verify.sh <container.anubis> [workdir]
#
#   workdir            optional parent; if given, a private unique child is
#                      kept beneath it and holds every
#                      intermediate byte string (vk.raw, vk.der, S.bin,
#                      signature.raw) for independent inspection. The signed
#                      preimage is streamed into SHA-512 and is never copied.
#   ANUBIS_EXPECT_FP   optional env var; pin the signer, e.g.
#                      ANUBIS_EXPECT_FP=A4DB-4D6C-B58D-2003-C7E6 ./openssl-verify.sh f
#                      Separators and case are ignored in the comparison.
#
# Exit:   0  signature present and VERIFIED (and, if pinned, by the pinned key)
#         1  signature present and FAILED to verify, or signer pin mismatched
#         2  container is unsigned, malformed, or a precondition failed
#
# Transcript implemented (ANUBIS/v3 FORMAT.md sections 3, 4.1, 10.2, 10.5):
#
#   header_len        = offset just past the LF that ends the "--- <mac>" line
#   sig_len           = 4627 iff the header carries a "-> mldsa87" stanza
#   payload_ct        = file[header_len .. file_size - sig_len)
#   S                 = SHA-512( file[0 .. file_size - sig_len) )      64 bytes
#                       ( == SHA-512( header_bytes || payload_ct ), because the
#                         header is a prefix of the file and there is no
#                         separator anywhere )
#   verifying_key     = base64-nopad payload of the "-> mldsa87" line   2592 B
#   signature         = last 4627 bytes of the file
#
#   VALID  <=>  ML-DSA-87.Verify(vk, S, signature, ctx = "anubis-v2-file")
#
#   ML-DSA is used PURE (FIPS 204 Algorithm 3, not HashML-DSA).  The message
#   handed to ML-DSA is the 64-byte digest S itself; OpenSSL must not hash it
#   again.  That is what "-rawin" with no "-digest" means for ML-DSA in
#   OpenSSL: the input bytes are the message M, and the provider applies the
#   FIPS 204 M' = 0x00 || len(ctx) || ctx || M encoding internally.
#
# NOT checked here (both need the file key, i.e. a recipient secret):
#   * the HMAC-SHA-512 header MAC of FORMAT.md section 7
#   * anything about the plaintext
# A valid signature proves the holder of the signing key produced these exact
# bytes.  It does not say who that holder is; compare SIGNER-FP out of band.
# ----------------------------------------------------------------------------

set -eu
umask 077

SIG_LEN=4627          # ML-DSA-87 signature, raw, file trailer   (FORMAT.md 2)
VK_LEN=2592           # ML-DSA-87 verifying key, raw             (FORMAT.md 2)
VK_B64_LEN=3456       # ceil(4*2592/3); 2592 % 3 == 0 so NO '=' padding needed
MAC_LINE_LEN=91       # "--- " + 86 b64 chars + LF               (FORMAT.md 4.2)
MLDSA_TAG_LEN=11      # length of the literal "-> mldsa87 "
CTX_HEX=616e756269732d76322d66696c65      # "anubis-v2-file", 14 ASCII bytes

# Largest header the format permits, so the text scan below is bounded and a
# multi-gigabyte container costs one bounded read, not a full pass:
#   25 (version) + 1024 * (2163 + 65) (MAX_STANZAS recipient blocks)
#      + 3468 (mldsa87 stanza) + 91 (MAC line)  =  2285056
MAX_HEADER=2285056

# DER SubjectPublicKeyInfo prefix for a raw 2592-byte ML-DSA-87 public key.
#   30 82 0A 32                 SEQUENCE, length 2610
#     30 0B                       SEQUENCE (AlgorithmIdentifier), length 11
#       06 09 60 86 48 01 65 03 04 03 13
#                                 OID 2.16.840.1.101.3.4.3.19  (id-ml-dsa-87)
#                                 -- parameters field ABSENT, per
#                                 -- draft-ietf-lamps-dilithium-certificates
#     03 82 0A 21 00              BIT STRING, length 2593, 0 unused bits
#     <2592 raw public key bytes>
SPKI_PREFIX_B64='MIIKMjALBglghkgBZQMEAxMDggohAA=='

die()  { printf '%s\n' "ERROR: $*" >&2; exit 2; }
say()  { printf '%s\n' "$*"; }

case "${1:-}" in
  -h|--help|'') sed -n '2,46p' "$0"; exit 2 ;;
esac
FILE=$1
if ! exec 3< "$FILE" 2>/dev/null; then
    die "cannot open input"
fi
# Every utility reopens this already-open descriptor, never the caller's path.
# A symlink replacement therefore cannot splice observations from two files.
SOURCE_FD="/proc/$$/fd/3"
[ -r "$SOURCE_FD" ] && [ -f "$SOURCE_FD" ] \
  || die "input must be a regular file and Linux /proc must expose its open descriptor"
START_META=$(stat -Lc '%s|%d|%i|%y|%z' "$SOURCE_FD") \
  || die "cannot identify the opened input handle"
SIZE=${START_META%%|*}
case "$SIZE" in
    ''|*[!0-9]*) die "opened input reported an invalid size" ;;
esac
check_source_unchanged() {
    CURRENT_META=$(stat -Lc '%s|%d|%i|%y|%z' "$SOURCE_FD") \
      || die "cannot re-identify the opened input handle"
    [ "$CURRENT_META" = "$START_META" ] \
      || die "container changed while it was being verified"
}

WANT=''
WANT_RENDERED=''
if [ -n "${ANUBIS_EXPECT_FP:-}" ]; then
    WANT=$(printf '%s' "$ANUBIS_EXPECT_FP" | tr -d -- '-: ' | tr 'a-f' 'A-F')
    case "$WANT" in
        *[!0-9A-F]*|'') die "ANUBIS_EXPECT_FP must be exactly 20 hexadecimal characters" ;;
    esac
    [ "${#WANT}" = 20 ] \
      || die "ANUBIS_EXPECT_FP must be exactly 20 hexadecimal characters"
    WANT_RENDERED=$(printf '%s' "$WANT" \
      | sed 's/\(....\)\(....\)\(....\)\(....\)\(....\)/\1-\2-\3-\4-\5/')
fi

if [ $# -ge 2 ]; then
    WORK_PARENT=$2
    mkdir -p "$WORK_PARENT" 2>/dev/null \
      || die "could not create the requested workdir parent"
    [ -d "$WORK_PARENT" ] && [ ! -L "$WORK_PARENT" ] \
      || die "workdir parent must be a real directory, not a symlink"
    WORK=$(mktemp -d "$WORK_PARENT/anubis-verify.XXXXXX" 2>/dev/null) \
      || die "could not create a private verifier workdir"
    CLEAN=0
    say "workdir       : retained in a private child of the requested parent"
else
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/anubis-verify.XXXXXX" 2>/dev/null) \
      || die "could not create a private verifier workdir"
    CLEAN=1
fi
HASH_PID=''
cleanup() {
    if [ -n "$HASH_PID" ] && kill -0 "$HASH_PID" 2>/dev/null; then
        kill -TERM "$HASH_PID" 2>/dev/null || true
        wait "$HASH_PID" 2>/dev/null || true
    fi
    if [ "$CLEAN" = 1 ]; then
        case "$WORK" in
            "${TMPDIR:-/tmp}"/anubis-verify.*)
                find "$WORK" -xdev -depth -delete 2>/dev/null \
                  || { printf '%s\n' "ERROR: verifier cleanup failed" >&2; return 1; }
                ;;
            *) printf '%s\n' "ERROR: refusing unsafe verifier cleanup path" >&2; return 1 ;;
        esac
    fi
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

say "container      : opened regular-file handle"
say "file_size      : $SIZE"

# --- 1. version line ---------------------------------------------------------
VER=$(head -c 25 "$SOURCE_FD")
[ "$VER" = 'anubis-encryption.org/v3' ] || die "not an ANUBIS/v3 container (bad version line)"
say "format         : anubis-encryption.org/v3"

# --- 2. locate the MAC line -> header_len ------------------------------------
# The MAC line is the LAST header line and is the FIRST line in the file that
# matches "--- " + exactly 86 base64 characters.  Its total length including
# the terminating LF is fixed at 91 bytes (FORMAT.md 4.2).
HEAD_SCAN="$WORK/head.scan"
head -c "$MAX_HEADER" "$SOURCE_FD" > "$HEAD_SCAN"
MAC_OFF=$(LC_ALL=C grep -a -b -o -m1 '^--- [A-Za-z0-9+/]\{86\}$' "$HEAD_SCAN" \
          | head -n1 | cut -d: -f1) || true
[ -n "${MAC_OFF:-}" ] || die "no MAC line found; header is malformed"
HEADER_LEN=$(( MAC_OFF + MAC_LINE_LEN ))
say "header_len     : $HEADER_LEN"

# --- 3. signed? locate the mldsa87 stanza ------------------------------------
VK_OFF=$(LC_ALL=C grep -a -b -o -m1 "^-> mldsa87 [A-Za-z0-9+/]\{$VK_B64_LEN\}\$" "$HEAD_SCAN" \
         | head -n1 | cut -d: -f1) || true
if [ -z "${VK_OFF:-}" ]; then
    say "signed         : no"
    say ""
    say "RESULT: UNSIGNED -- there is no '-> mldsa87' stanza, so there is no"
    say "        4627-byte trailer and nothing to verify.  Per FORMAT.md 10.6"
    say "        the ABSENCE of a signature carries no information: any"
    say "        recipient can strip one undetectably.  Treat this as"
    say "        'not signed', never as 'signature ok'."
    check_source_unchanged
    exit 2
fi
[ "$VK_OFF" -lt "$HEADER_LEN" ] || die "mldsa87 stanza found outside the header"
say "signed         : yes"

# --- 4. region arithmetic ----------------------------------------------------
PAYLOAD_END=$(( SIZE - SIG_LEN ))
PAYLOAD_LEN=$(( PAYLOAD_END - HEADER_LEN ))
MIN=$(( HEADER_LEN + 16 + SIG_LEN ))          # FORMAT.md 3 / 10.5 step 2
[ "$SIZE" -ge "$MIN" ] || die "signed file too short: $SIZE < $MIN"
say "payload_range  : [$HEADER_LEN, $PAYLOAD_END)  len=$PAYLOAD_LEN"
say "sig_range      : [$PAYLOAD_END, $SIZE)  len=$SIG_LEN"

# --- 5. carve out the three byte strings -------------------------------------
# 5a. verifying key: the 3456 base64 chars after "-> mldsa87 "
head -c $(( VK_OFF + MLDSA_TAG_LEN + VK_B64_LEN )) "$SOURCE_FD" \
  | tail -c "$VK_B64_LEN" > "$WORK/vk.b64"
# 2592 is divisible by 3, so the base64 is exactly 3456 chars with no '='
# padding and STANDARD_NO_PAD decodes with a plain base64 decoder.
openssl base64 -d -A -in "$WORK/vk.b64" -out "$WORK/signer.vk.raw"
GOT=$(wc -c < "$WORK/signer.vk.raw" | tr -d ' ')
[ "$GOT" = "$VK_LEN" ] || die "verifying key decoded to $GOT bytes, expected $VK_LEN"

# 5b. signature trailer: the last 4627 bytes
tail -c "$SIG_LEN" "$SOURCE_FD" > "$WORK/signature.raw"

# --- 6. S = SHA-512(header_bytes || payload_ciphertext) ----------------------
# Stream the attacker-sized preimage directly. Retaining another full copy in
# the work directory makes an independent check needlessly double its storage.
HASH_PIPE="$WORK/preimage.pipe"
mkfifo "$HASH_PIPE"
openssl dgst -sha512 -binary -out "$WORK/S.bin" < "$HASH_PIPE" &
HASH_PID=$!
if ! head -c "$PAYLOAD_END" "$SOURCE_FD" > "$HASH_PIPE"; then
    wait "$HASH_PID" 2>/dev/null || true
    HASH_PID=''
    die "could not stream the signed preimage"
fi
if ! wait "$HASH_PID"; then
    HASH_PID=''
    die "OpenSSL could not hash the signed preimage"
fi
HASH_PID=''
rm -f "$HASH_PIPE"
S_HEX=$(od -An -tx1 -v "$WORK/S.bin" | tr -d ' \n')
say "S (sha512)     : $S_HEX"

# --- 7. wrap the raw key as a DER SubjectPublicKeyInfo -----------------------
printf '%s' "$SPKI_PREFIX_B64" | openssl base64 -d -A > "$WORK/spki.prefix"
cat "$WORK/spki.prefix" "$WORK/signer.vk.raw" > "$WORK/signer.vk.der"
openssl pkey -pubin -inform DER -in "$WORK/signer.vk.der" -noout >/dev/null 2>&1 \
  || die "OpenSSL refused the DER SubjectPublicKeyInfo (need OpenSSL >= 3.5 with ML-DSA)"

FP=$(openssl dgst -sha256 -r "$WORK/signer.vk.raw" | cut -d' ' -f1 \
     | cut -c1-20 | tr 'a-f' 'A-F' \
     | sed 's/\(....\)\(....\)\(....\)\(....\)\(....\)/\1-\2-\3-\4-\5/')
say "signer_fp      : $FP"
say "ctx            : anubis-v2-file (hex $CTX_HEX)"
say ""

# --- 8. pure ML-DSA-87 verify, message = S, ctx = "anubis-v2-file" ----------
# -rawin           : the input file IS the message; do not pre-hash it.
# no -digest       : ML-DSA-87 is pure; OpenSSL rejects -digest for this alg.
# hexcontext-string: the 14-byte FIPS 204 context, passed as hex so no shell
#                    quoting or encoding can corrupt it.  The plain form
#                    "-pkeyopt context-string:anubis-v2-file" is equivalent.
set +e
OUT=$(openssl pkeyutl -verify \
        -pubin -inkey "$WORK/signer.vk.der" -keyform DER \
        -rawin \
        -in "$WORK/S.bin" \
        -sigfile "$WORK/signature.raw" \
        -pkeyopt "hexcontext-string:$CTX_HEX" 2>&1)
RC=$?
set -e
printf '%s\n' "$OUT"
check_source_unchanged

if [ "$RC" = 0 ]; then
    if [ -n "$WANT" ]; then
        GOTFP=$(printf '%s' "$FP" | tr -d '-')
        if [ "$WANT" != "$GOTFP" ]; then
            say ""
            say "RESULT: SIGNATURE VALID but SIGNER PIN MISMATCH"
            say "        expected $WANT_RENDERED, got $FP -- reject."
            exit 1
        fi
        say "signer pin     : MATCHED $WANT_RENDERED"
    fi
    say ""
    say "RESULT: SIGNATURE VALID"
    say "        The holder of the ML-DSA-87 signing key whose verifying key"
    say "        fingerprints as $FP produced these exact $SIZE bytes."
    say "        This does NOT establish who that holder is (FORMAT.md 10.6)."
    exit 0
else
    say ""
    say "RESULT: SIGNATURE INVALID -- reject this container."
    exit 1
fi
