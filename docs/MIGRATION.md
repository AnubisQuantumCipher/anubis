# Migrating from anubis-rage 1.4.0 to ANUBIS 2.0.0

This guide covers moving from `anubis-rage` 1.4.0, the `rage` fork whose crypto
lived in the `anubis-age` crate, to ANUBIS 2.0.0.

There is no in-place upgrade. Keys and files are both incompatible. What
follows is exact rather than reassuring: read section 3 before you delete
anything.

---

## 1. Why the rewrite happened

### 1.1 anubis-rage could not be installed on Omarchy

`anubis-rage` 1.4.0 obtained its post-quantum primitives from the `oqs` crate,
which is a set of Rust bindings to **liboqs**, the Open Quantum Safe project's C
library. The dependency chain, taken from the published `Cargo.lock`, is:

```
anubis-rage 1.4.0
  -> anubis-age 1.4.0
       -> oqs 0.11.0
            -> oqs-sys 0.11.0+liboqs-0.13.0
                 -> bindgen, cmake, pkg-config, libc
```

`oqs-sys` builds liboqs from source at crate build time. Its own dependencies
name the requirement precisely: `cmake` to drive the C build, `bindgen` to
generate FFI bindings, `pkg-config` to locate the result. The output is a
binary linked against a C library that must then be present at runtime.

liboqs is not in the Arch Linux official repositories, and it is not installed
on this machine. On this architecture it was not installable from the AUR
either. The practical result was that `cargo install anubis-rage` failed on
Omarchy, and the old README's advice for the resulting runtime failure was to
set `LD_LIBRARY_PATH` to `/usr/local/lib`, which is to say: build and install a
C library by hand into `/usr/local` first.

So the tool did not merely work poorly on Omarchy. It could not be installed at
all.

### 1.2 What v2 does instead

ANUBIS 2.0.0 uses pure-Rust implementations of the same standards:

| Purpose | anubis-rage 1.4.0 | ANUBIS 2.0.0 |
|---|---|---|
| ML-KEM-1024 | `oqs` -> liboqs (C) | `ml-kem` (pure Rust, FIPS 203) |
| ML-DSA-87 | `oqs` -> liboqs (C) | `ml-dsa` (pure Rust, FIPS 204) |
| X25519 | `curve25519-dalek` | `x25519-dalek` |
| AEAD | ChaCha20-Poly1305, AES-GCM-SIV | ChaCha20-Poly1305 |
| Build requires | C compiler, CMake, pkg-config | `cargo` only |
| Runtime requires | liboqs shared library | nothing |

`cargo install` works. There is no C code in the dependency graph, no liboqs,
no OpenSSL, and no CMake.

The cryptographic suite is not weaker for being pure Rust: ML-KEM-1024 and
ML-DSA-87 are the same FIPS 203 and FIPS 204 algorithms at the same parameter
sets. The protocol around them did change, deliberately; see `FORMAT.md`.

---

## 2. Before you start

**Check what you have.**

```sh
command -v anubis-rage anubis-rage-keygen anubis-rage-sign
anubis-rage --version
```

If none of those exist, you never had a working install, which on Omarchy is
the expected case. You have no v1 or v2 files and no old keys. Skip to
section 6, install ANUBIS, and generate a fresh identity.

**If you do have a working `anubis-rage`, keep it.** Do not uninstall it until
every file you care about has been re-encrypted and verified. It is the only
software that can read your old files.

**Find your old material.**

```sh
ls -la ~/.config/anubis-rage/ 2>/dev/null
ls -la ~/.anubis/ 2>/dev/null
find "$HOME" \( -name '*.age' -o -name '*.anubis' \) -type f 2>/dev/null | head -50
```

---

## 3. What is incompatible, precisely

### 3.1 Version numbering, so the rest of this document reads correctly

Three wire formats have been published under the ANUBIS name. Note that
`anubis-rage` shipped **two** of them:

| Version line | Written by | Construction | Readable by ANUBIS 2.0.0 |
|---|---|---|---|
| `anubis-encryption.org/v1` | `anubis-rage` 1.x | Pure ML-KEM-1024 | No |
| `anubis-encryption.org/v2` | `anubis-rage` 1.4.0 | Hybrid, stanza tag `hybrid` | No |
| `anubis-encryption.org/v3` | ANUBIS 2.0.0 | Hybrid, stanza tag `hybrid-x25519-mlkem1024` | Yes |

**The wire format is v3 while the software is 2.0.0.** That mismatch is
intentional. `anubis-rage` had already spent the identifiers v1 and v2 on two
incompatible formats, so the format specified by ANUBIS 2.0.0 has to be v3,
while the software is the second major release of the tool. Neither number is
wrong and neither should be "corrected" to match the other. `FORMAT.md`
section 15 records this.

If you are scripting against `--json`, the `format` field reads `ANUBIS/v3`.

### 3.2 Files

Old files are not readable by ANUBIS 2.0.0. Both old version lines are
rejected at the version line, each with an error that names the tool that wrote
it and points here.

An important detail if you are inspecting files by hand: **the old hybrid format
and an early unreleased draft of the new one both used the version line
`anubis-encryption.org/v2`.** That collision is why the released format is v3.
Nothing you have in hand is affected, since no draft-format files were ever
written by a released tool, but it explains why the version line jumps from v2
to v3 with no v2 of ours in between.

The old hybrid header looked like this:

```
anubis-encryption.org/v2
-> hybrid
<b64 x25519 ephemeral public key>
<b64 ML-KEM-1024 ciphertext>
<encrypted file key>
--- <SHA-512 HMAC>
```

The new one bumps the version line, names the suite in the stanza tag, and puts
both KEM fields on the stanza line:

```
anubis-encryption.org/v3
-> hybrid-x25519-mlkem1024 <b64 epk> <b64 ct>
<b64 wrapped file key>
-> mldsa87 <b64 verifying key>            [only when signed]
--- <b64 HMAC-SHA-512>
```

When a file is signed, the header carries only the verifying key; the 4627-byte
ML-DSA-87 signature itself is a raw trailer at the very end of the file, after
the payload. That is different from the old tool, which produced signatures in a
separate pass, and it is why there is no `anubis` equivalent of
`anubis-rage-sign sign` operating on an existing file.

Identify any file without decrypting it:

```sh
head -2 file.age
```

- First line ends `/v1`: old pure-PQC file. Needs section 4.
- First line ends `/v2`, second line `-> hybrid`: old hybrid file. Needs
  section 4.
- First line ends `/v3`: already a current file. Use `anubis inspect`.

### 3.3 Keys

Old keys are not usable by ANUBIS 2.0.0.

| | anubis-rage 1.4.0 | ANUBIS 2.0.0 |
|---|---|---|
| Recipient | `anubis1hybrid1x25519...mlkem1024...` | `anubis1...`, payload exactly 1600 bytes, 2573 characters |
| Identity | `anubis-rage-keygen` output file | `ANUBIS-SECRET-KEY-1...`, 230 characters |
| Signing key | Separate file from `anubis-rage-sign keygen` | Inside the identity; no separate file |

**Recipients collide, and this one could not be fixed by renumbering.** The old
tool also used the Bech32 human-readable part `anubis`, so old and new
recipients both begin `anubis1`. A human-readable part cannot be changed
without invalidating every recipient string ever issued, so instead ANUBIS
enforces a strict length: a current recipient decodes to exactly 1600 bytes,
and an old one does not. An old recipient is therefore rejected rather than
misread, and the error says it looks like an `anubis-rage` recipient.

Do not attempt to hand-convert one. An old recipient's key material is
differently structured, and it contains no ML-DSA verifying key at all.

**Identities cannot be converted.** A current identity is 32 bytes of X25519
secret scalar, a 64-byte ML-KEM seed, and a 32-byte ML-DSA seed, totalling 128
bytes. The old format stored expanded liboqs key material and kept signing keys
in a separate file. There is no mapping. Generate new keys.

### 3.4 Features that are gone

Check this table before migrating, because a workflow may depend on one of
these.

| anubis-rage 1.4.0 feature | Status in ANUBIS 2.0.0 |
|---|---|
| `-p` / `--passphrase` symmetric encryption | **Removed.** No passphrase mode at all. Identity files only. |
| `-a` / `--armor` PEM output | **Back.** `anubis encrypt -a/--armor` writes `-----BEGIN ANUBIS ENCRYPTED FILE-----` ... `-----END ANUBIS ENCRYPTED FILE-----`, base64 at 64 columns. Decrypt and inspect auto-detect it. Capped at 16777216 bytes of armored text. |
| `age` plugin support (`-j`) | **Removed.** |
| AES-GCM-SIV | **Removed.** ChaCha20-Poly1305 only. |
| `--max-work-factor` | Removed; it only ever applied to passphrase mode. |
| Separate `-sign` binary, detached signing pass | **Merged** into `anubis encrypt --sign`. |
| Multiple localisations | Removed; English only. |
| Recipients from a file (`-R`) | **Back.** `-R`/`--recipients-file`, one recipient per line, blank lines and `#` ignored, repeatable, combinable with `-r`. The `anubis recipient` address book also exists, and `-r` takes a label. |
| `--output`, repeated `-r` | Kept. |
| stdin/stdout piping | **Back.** `-` is stdin as the input and stdout as `--output`, on `encrypt`, `decrypt` and `inspect`. An input of `-` with no `--output` defaults to stdout. Constant memory at any size. |
| (new) | `anubis recipient list/add/remove`, `anubis status`, `anubis completions`, `--json` on every command, `decrypt --require-signature` and `--signer` |

If you rely on passphrase encryption, ANUBIS 2.0.0 does not replace
`anubis-rage` for that use, and `age` is the better tool for it. ASCII armor,
`-R` recipient files, and stdin/stdout piping were absent from early 2.0.0
builds and are present now; earlier revisions of this document said otherwise
and were wrong.

---

## 4. Re-encrypting your files

The only path is: decrypt with the old tool, encrypt with the new one. The
plaintext must exist, at least in a pipe, in between. No transcryption path
avoids this, because the file key derivation differs.

### 4.1 Install both, then generate a current identity

```sh
# The old tool must still be present and working.
anubis-rage --version

# The new tool.
cd anubis && ./install.sh   # from wherever you cloned the repository
anubis keygen --name default
anubis status
```

`anubis keygen` prints the new recipient and its fingerprint. Note both.

### 4.2 One file

`anubis encrypt` accepts `-` as its input, so the old `age`-style pipeline
works directly and the plaintext never touches a filesystem:

```sh
NEW_RECIPIENT="$(anubis status --json \
    | jq -r '.identities[] | select(.name=="default") | .recipient')"

anubis-rage -d -i ~/.config/anubis-rage/identity.txt secret.age \
    | anubis encrypt --recipient "$NEW_RECIPIENT" --sign - --output secret.anubis
```

If the old file was signed, add `-k "$OLD_VERIFY_KEY"` to the `anubis-rage`
invocation. If you do not want a new signature, drop `--sign`.

Earlier revisions of this document told you to stage the plaintext in a
`/dev/shm` scratch file with a cleanup `trap`, because `-` was not accepted.
That workaround is obsolete; delete it from any script you copied it into.

**One thing the pipeline does not give you for free.** A pipeline reports the
exit status of its *last* command, so a failure in `anubis-rage` would be
invisible and you would write a short output file that looks complete. In
`bash` or any shell with it, set `pipefail`:

```sh
set -euo pipefail
```

POSIX `sh` has no `pipefail`. If you must use `sh`, either check
`${PIPESTATUS[@]}` under `bash` instead, or stage the plaintext as the bulk
script in section 4.4 does -- staging remains the safer construction in a
portable script, not because piping is unsupported, but because separate
commands let `set -e` catch each failure individually.

### 4.3 Verify before deleting

Never delete an old file until you have decrypted its replacement and compared
the plaintext. Compare with `cmp`, do not eyeball.

```sh
anubis-rage -d -i ~/.config/anubis-rage/identity.txt secret.age > /tmp/old.out
anubis decrypt --identity default secret.anubis --output /tmp/new.out

if cmp -s /tmp/old.out /tmp/new.out; then
    echo "OK, plaintexts identical"
else
    echo "MISMATCH, keep the old file"
fi
rm -f /tmp/old.out /tmp/new.out
```

Put the scratch files on a `tmpfs` if the plaintext is sensitive, and remove
them either way. Or avoid them: both commands accept `-`, so
`anubis decrypt -o - secret.anubis | cmp - <(anubis-rage -d -i ... secret.age)`
compares without either plaintext reaching a filesystem, under `bash`.

### 4.4 Bulk migration

POSIX sh. Safe by construction: it never deletes an input, removes partial
output on any failure, and round-trips every result before calling it good.

```sh
#!/bin/sh
# migrate-anubis.sh -- re-encrypt every *.age file under a directory tree.
# Verifies each result by round trip. Never deletes an input.
set -eu

SRC_DIR="${1:?usage: migrate-anubis.sh DIRECTORY}"
OLD_IDENTITY="${OLD_IDENTITY:-$HOME/.config/anubis-rage/identity.txt}"
IDENTITY="${IDENTITY:-default}"

[ -d "$SRC_DIR" ]     || { echo "not a directory: $SRC_DIR" >&2; exit 1; }
[ -f "$OLD_IDENTITY" ] || { echo "no old identity at $OLD_IDENTITY" >&2; exit 1; }
command -v anubis-rage >/dev/null 2>&1 || { echo "anubis-rage not found" >&2; exit 1; }
command -v anubis      >/dev/null 2>&1 || { echo "anubis not found" >&2; exit 1; }
command -v jq          >/dev/null 2>&1 || { echo "jq not found" >&2; exit 1; }

RECIPIENT="$(anubis status --json \
    | jq -r --arg n "$IDENTITY" '.identities[] | select(.name==$n) | .recipient')"
[ -n "$RECIPIENT" ] || { echo "no identity named $IDENTITY" >&2; exit 1; }

SCRATCH="$(mktemp -d "${TMPDIR:-/dev/shm}/anubis-mig.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

# Collect the file list first, so the loop body runs in this shell and the
# counters survive it.
find "$SRC_DIR" -type f -name '*.age' > "$SCRATCH/list"

ok=0
fail=0
skip=0

while IFS= read -r old; do
    new="${old%.age}.anubis"

    if [ -e "$new" ]; then
        echo "SKIP   $old (target exists)"
        skip=$((skip + 1))
        continue
    fi

    # Stage the plaintext, so an old-tool failure is caught before any
    # output file exists.
    if ! anubis-rage -d -i "$OLD_IDENTITY" "$old" \
            > "$SCRATCH/plain" 2> "$SCRATCH/err"; then
        echo "FAIL   $old (old decrypt: $(tr '\n' ' ' < "$SCRATCH/err"))"
        fail=$((fail + 1))
        continue
    fi

    if ! anubis encrypt --recipient "$RECIPIENT" --sign \
            "$SCRATCH/plain" --output "$new" 2> "$SCRATCH/err"; then
        echo "FAIL   $old (new encrypt: $(tr '\n' ' ' < "$SCRATCH/err"))"
        rm -f "$new"
        fail=$((fail + 1))
        continue
    fi

    if ! anubis decrypt --identity "$IDENTITY" "$new" \
            --output "$SCRATCH/check" 2> "$SCRATCH/err"; then
        echo "FAIL   $old (new decrypt: $(tr '\n' ' ' < "$SCRATCH/err"))"
        rm -f "$new"
        fail=$((fail + 1))
        continue
    fi

    if cmp -s "$SCRATCH/plain" "$SCRATCH/check"; then
        echo "OK     $old -> $new"
        ok=$((ok + 1))
    else
        echo "FAIL   $old (round trip mismatch)"
        rm -f "$new"
        fail=$((fail + 1))
    fi
done < "$SCRATCH/list"

echo "done: $ok migrated, $fail failed, $skip skipped"
echo "No .age file was deleted. Remove them yourself once satisfied."
[ "$fail" -eq 0 ]
```

Run it:

```sh
chmod +x migrate-anubis.sh
./migrate-anubis.sh ~/Documents/encrypted
```

The deliberate choices, since they are the difference between this script and a
dangerous one:

- The file list is written to a scratch file and the loop reads from it via
  redirection, so the loop body runs in the current shell and the counters are
  still correct at the end. A `find | while read` pipeline would run the body
  in a subshell and silently discard them.
- The intermediate plaintext goes to a scratch directory rather than through a
  pipe, so a failure in the old tool is detected before any output file exists.
  Piping would work -- `anubis encrypt` accepts `-` -- but POSIX `sh` has no
  `pipefail`, so a pipeline here could not distinguish a truncated stream from a
  complete one. This is a portability constraint of the script, not a
  limitation of the tool.
- A partial output file is removed on every failure path.
- Every result is decrypted and compared before being reported `OK`.
- No input is ever deleted, and the script exits non-zero if anything failed.

### 4.5 After migration

Only once every file reports `OK` and you have spot-checked several plaintexts
by hand:

```sh
find ~/Documents/encrypted -name '*.age' -print    # review the list first
find ~/Documents/encrypted -name '*.age' -delete   # then, deliberately

cargo uninstall anubis-rage
```

**Keep a copy of your old identity file offline, indefinitely.** If an old file
surfaces later from a backup, that identity is the only way to read it, and
`anubis-rage` can be rebuilt from crates.io on a machine where liboqs is
available. Deleting the old identity makes old files permanently unreadable.

---

## 5. CLI mapping

`anubis-rage` followed `age`: flag-driven, three binaries. ANUBIS uses one
binary with subcommands.

### 5.1 Binaries

| anubis-rage 1.4.0 | ANUBIS 2.0.0 |
|---|---|
| `anubis-rage` | `anubis encrypt`, `anubis decrypt` |
| `anubis-rage-keygen` | `anubis keygen` |
| `anubis-rage-sign` | folded into `anubis encrypt --sign` and `anubis inspect` |
| (none) | `anubis status`, `anubis recipient` |

### 5.2 Encryption

| anubis-rage 1.4.0 | ANUBIS 2.0.0 |
|---|---|
| `-e`, `--encrypt` | `anubis encrypt` |
| `-r`, `--recipient KEY` | `-r`, `--recipient KEY_OR_LABEL` |
| `-R`, `--recipients-file FILE` | `-R`, `--recipients-file FILE`; also the `anubis recipient` address book, since `-r` takes a label |
| `-o`, `--output FILE` | `-o`, `--output FILE` |
| `-s`, `--signing-key FILE` | `--sign`, plus `--identity NAME` to choose which |
| (none) | `--force` to overwrite an existing output |
| `-a`, `--armor` | `-a`, `--armor`; auto-detected on read, capped at 16777216 bytes of armored text |
| `-p`, `--passphrase` | removed |
| `--max-work-factor WF` | removed |
| `-j PLUGIN` | removed |

There is no `-R` flag. Repeated recipients on a file are handled by the address
book instead, which is better than a flag because a label survives across
invocations:

```sh
anubis recipient add anubis1alice... --label alice
anubis recipient add anubis1bob...   --label bob
anubis recipient list

# -r accepts a label as readily as a full key.
anubis encrypt -r alice -r bob report.pdf -o report.pdf.anubis
```

```sh
# anubis-rage 1.4.0
anubis-rage -e -r anubis1hybrid1... -s signing.key -o out.age in.txt

# ANUBIS 2.0.0
anubis encrypt -r anubis1... --sign -o out.anubis in.txt
```

### 5.3 Decryption

| anubis-rage 1.4.0 | ANUBIS 2.0.0 |
|---|---|
| `-d`, `--decrypt` | `anubis decrypt` |
| `-i`, `--identity FILE` | `--identity NAME` (no short `-i`) |
| `-k`, `--verify-key KEY` | none needed; a present signature is verified automatically |
| `-o`, `--output FILE` | `-o`, `--output FILE` |
| (none) | `--force` to overwrite an existing output |

```sh
# anubis-rage 1.4.0
anubis-rage -d -i identity.txt -k anubis1sig... -o out.txt in.age

# ANUBIS 2.0.0
anubis decrypt --identity default -o out.txt in.anubis
```

Two changes to note. **There is no short `-i`;** write `--identity`. And it
takes an identity *name* from `~/.config/anubis/identities/`, not a path, so the
common case is `--identity default`, which is also the default value and can be
omitted entirely.

There is no verify flag because there is nothing to opt into: if the file
carries a signature, `decrypt` verifies it before writing any plaintext and
fails if it does not check out. Read the `signed` and `signer_fingerprint`
fields of `inspect --json` if you need to act on who signed a file, and use
`decrypt --require-signature` or `decrypt --signer FINGERPRINT` if you need to
*insist* on it -- a recipient can strip a signature, so checking after the fact
is weaker than making it a precondition. See `SECURITY.md` section 2.4.

### 5.4 Key generation

| anubis-rage 1.4.0 | ANUBIS 2.0.0 |
|---|---|
| `anubis-rage-keygen -o FILE` | `anubis keygen --name NAME` (`--force` to replace) |
| `anubis-rage-keygen -y` (derive public) | `anubis status` lists recipients and fingerprints |
| `anubis-rage-sign keygen -o FILE` | not needed; the signing key is in the identity |
| `anubis-rage-sign extract -i FILE` | `anubis status --json`, `.identities[].recipient` |

```sh
# anubis-rage 1.4.0: two keys, two files
anubis-rage-keygen -o identity.txt
anubis-rage-sign keygen -o signing.key
anubis-rage-sign extract -i signing.key

# ANUBIS 2.0.0: one identity does both
anubis keygen --name default
```

The consolidation is deliberate. A current identity is capability-complete: it
decrypts and signs. There is no separate signing key to manage, and no way to
hold a decrypt-only identity. The security consequence is stated in
`SECURITY.md`: one leaked identity is both capabilities, with no partial
compromise.

### 5.5 Signing and verification

`anubis-rage-sign` attached or stripped a signature as a separate pass over an
already-encrypted file. Now signing happens during encryption, in one pass.

| anubis-rage 1.4.0 | ANUBIS 2.0.0 |
|---|---|
| `anubis-rage-sign sign -k KEY -i IN -o OUT` | `anubis encrypt --sign` |
| `anubis-rage-sign verify -k KEY -i IN -o OUT` | automatic on `decrypt`; `anubis inspect` to check without decrypting |

Two substantive differences beyond the ergonomics:

- **The signature covers the whole file, not just the header.** It is over
  `SHA-512(header || payload_ciphertext)` and is stored as a 4627-byte raw
  trailer at the end of the file. So a signature commits the sender to the exact
  ciphertext, and a recipient cannot re-author the payload under it.
- **You cannot add or remove a signature after the fact.** There is no
  equivalent of `anubis-rage-sign sign` operating on an existing encrypted file,
  because the signature depends on the ciphertext and the header MAC covers the
  verifying key. To change whether a file is signed, re-encrypt it.

```sh
# anubis-rage 1.4.0: encrypt, then sign as a second pass
anubis-rage -e -r anubis1hybrid1... -o tmp.age in.txt
anubis-rage-sign sign -k signing.key -i tmp.age -o out.age

# ANUBIS 2.0.0: one pass
anubis encrypt -r anubis1... --sign -o out.anubis in.txt

# Inspect without decrypting
anubis inspect out.anubis
anubis inspect out.anubis --json | jq '{format, signed, signer_fingerprint, payload_bytes}'
```

There is no separate verify step to remember: `anubis decrypt` verifies the
signature when one is present, before writing any plaintext. Read the `signed`
and `signer_fingerprint` JSON fields if your workflow needs to act on who
signed a file, and pass `--signer FINGERPRINT` if the workflow depends on it.

### 5.6 Machine-readable output

New, with no old equivalent: every subcommand accepts `--json` and emits
single-line JSON objects on stdout. This is what the Omarchy plugin consumes.

```sh
anubis status --json | jq .
anubis inspect file.anubis --json | jq .
anubis encrypt -r "$R" big.iso -o big.iso.anubis --json \
  | jq -c 'select(.kind=="progress")'
```

If you had scripts scraping `anubis-rage` stderr, replace that with `--json`.

---

## 6. Fresh install, no old material

The expected case on Omarchy, where `anubis-rage` never installed.

```sh
git clone https://github.com/AnubisQuantumCipher/anubis
cd anubis
./install.sh
```

Then:

```sh
anubis keygen --name default
anubis status
```

`install.sh` puts the binary in `~/.local/bin`, creates
`~/.config/anubis/identities` at mode 700 and `~/.local/state/anubis`, and
registers the `khephri.anubis` bar widget in `~/.config/omarchy/shell.json`
after taking a timestamped backup. It is idempotent.

---

## 7. Troubleshooting

**`ANUBIS/v1 file (anubis-rage 1.x, pure ML-KEM). Not supported`**
A pure-PQC file from `anubis-rage` 1.x. See section 4.

**`ANUBIS/v2 file (anubis-rage 1.4.0, hybrid). Not supported`**
An old hybrid file. See section 4. Confirm with `head -2 file.age`; the second
line will be `-> hybrid`.

**`invalid recipient: expected 1600 bytes`**
An old-style `anubis1hybrid1...` recipient. Old recipients cannot be converted.
Ask the holder for a current recipient, or generate your own.

**`no matching identity`**
The file is not encrypted to any identity you hold. If you were migrating,
check that you passed the new recipient to `encrypt` and not the old one.

**`anubis-rage: command not found` during migration**
You need the old tool to read old files, and it needs liboqs. Build it on a
machine where liboqs is available, or install liboqs into `/usr/local` and set
`LD_LIBRARY_PATH=/usr/local/lib` as the old README described. If you cannot,
and the plaintext exists nowhere else, that data is unrecoverable. That failure
mode is precisely what the rewrite exists to prevent.

**Migrated file is larger than expected**
Expected. Signing costs a fixed 8095 bytes: a 3468-byte `-> mldsa87` header
stanza carrying the verifying key, plus a 4627-byte raw signature trailer at the
end of the file. A signed single-recipient header is 5812 bytes against 2344
unsigned. Drop `--sign` if you do not need sender authentication. See
`FORMAT.md` section 12.

**Why does `inspect` say `anubis-encryption.org/v3` when I installed 2.0.0?**
Correct and intentional. Wire format v3, software 2.0.0. See section 3.1.

**Round-trip mismatch during bulk migration**
The script keeps the old file and removes the partial new one, so nothing is
lost. Investigate that single file with section 4.3 before rerunning.

---

## 8. Summary

- `anubis-rage` 1.4.0 needed liboqs, a C library absent from the Arch repos and
  from this machine, so it could not be installed on Omarchy. ANUBIS 2.0.0 is
  pure Rust with zero system dependencies.
- `anubis-rage` published two wire formats, v1 and v2. ANUBIS 2.0.0 publishes
  v3. The software version 2.0.0 and the format version v3 differ on purpose.
- Files are not compatible. Decrypt with the old tool, re-encrypt with the new.
- Keys are not compatible and cannot be converted. Generate a new identity.
  Old recipients are caught by a strict 1600-byte length check.
- Three binaries became one with subcommands. Signing keys folded into the
  identity, which now decrypts and signs.
- Passphrase mode, `age` plugins, and AES-GCM-SIV are gone. ASCII armor, `-R`
  recipient files, and stdin/stdout piping are present; a `-` argument means
  stdin or stdout on `encrypt`, `decrypt` and `inspect`.
- Verify every re-encrypted file by round trip before deleting anything, and
  keep your old identity offline forever.
