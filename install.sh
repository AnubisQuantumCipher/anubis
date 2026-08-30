#!/bin/sh
# Build and install ANUBIS, then register its Omarchy bar widget.
#
#   * builds crates/anubis-cli with cargo (release)
#   * installs the `anubis` binary into ~/.local/bin
#   * creates ~/.config/anubis/identities (mode 700) and ~/.local/state/anubis
#   * adds { "id": "khephri.anubis" } to bar.layout.right in
#     ~/.config/omarchy/shell.json, after writing a timestamped backup
#
# Idempotent: re-running only fills in what is missing. Never overwrites an
# identity, never duplicates the widget entry, never edits shell.json without
# backing it up first.
#
# POSIX sh. Requires: cargo. Optional: jq (for the widget registration).

set -eu

WIDGET_ID="khephri.anubis"
BIN_NAME="anubis"

BIN_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/anubis"
IDENTITY_DIR="${CONFIG_DIR}/identities"
STATE_DIR="${HOME}/.local/state/anubis"
SHELL_JSON="${HOME}/.config/omarchy/shell.json"

SRC_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
CRATE_DIR="${SRC_DIR}/crates/anubis-cli"

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- preflight

step "Checking prerequisites"

command -v cargo >/dev/null 2>&1 \
    || die "cargo not found. Install Rust: https://rustup.rs"
say "cargo: $(cargo --version)"

[ -d "${CRATE_DIR}" ] \
    || die "${CRATE_DIR} not found. Run this script from the anubis checkout."

HAVE_JQ=0
if command -v jq >/dev/null 2>&1; then
    HAVE_JQ=1
    say "jq:    $(jq --version 2>&1 | head -n 1)"
else
    warn "jq not found; the bar widget will not be registered automatically."
fi

# ---------------------------------------------------------------- build

step "Building ${BIN_NAME} (release)"

# Build from the workspace root so the workspace Cargo.lock is honoured.
( cd "${SRC_DIR}" && cargo build --release --all-features -p anubis-cli ) \
    || die "cargo build failed"

BUILT="${SRC_DIR}/target/release/${BIN_NAME}"
[ -x "${BUILT}" ] || die "expected binary at ${BUILT}, not found after build"
say "built: ${BUILT}"

# ---------------------------------------------------------------- install

step "Installing binary"

mkdir -p "${BIN_DIR}"
# Copy to a temporary name then move into place, so a running `anubis` is not
# corrupted mid-write and the replacement is atomic.
TMP_BIN="${BIN_DIR}/.${BIN_NAME}.new.$$"
trap 'rm -f "${TMP_BIN}"' EXIT INT TERM
cp -f "${BUILT}" "${TMP_BIN}"
chmod 0755 "${TMP_BIN}"
mv -f "${TMP_BIN}" "${BIN_DIR}/${BIN_NAME}"
trap - EXIT INT TERM
say "installed: ${BIN_DIR}/${BIN_NAME}"

VERSION="$("${BIN_DIR}/${BIN_NAME}" --version 2>/dev/null || echo 'unknown')"
say "version:   ${VERSION}"

# ---------------------------------------------------------------- directories

step "Creating directories"

# Identity directory is 700 and the config directory holding it is 700 too:
# secret key material lives here and nothing else should be able to list it.
mkdir -p "${IDENTITY_DIR}"
chmod 0700 "${CONFIG_DIR}"
chmod 0700 "${IDENTITY_DIR}"
say "${CONFIG_DIR} (700)"
say "${IDENTITY_DIR} (700)"

mkdir -p "${STATE_DIR}"
chmod 0755 "${STATE_DIR}"
say "${STATE_DIR}"

# Tighten any pre-existing identity files that are more permissive than 600.
# Never touches contents, only the mode.
if [ -d "${IDENTITY_DIR}" ]; then
    find "${IDENTITY_DIR}" -maxdepth 1 -type f ! -perm 600 \
        -exec chmod 0600 {} + 2>/dev/null || true
fi

# ---------------------------------------------------------------- bar widget

step "Registering Omarchy bar widget (${WIDGET_ID})"

register_widget() {
    if [ "${HAVE_JQ}" -eq 0 ]; then
        warn "skipping: jq is required to edit shell.json safely"
        say  "  Add this to bar.layout.right in ${SHELL_JSON} by hand:"
        say  "      { \"id\": \"${WIDGET_ID}\" }"
        return 0
    fi

    if [ ! -f "${SHELL_JSON}" ]; then
        warn "skipping: ${SHELL_JSON} not found (Omarchy shell not installed?)"
        return 0
    fi

    # Refuse to touch a file that is not valid JSON.
    if ! jq -e . "${SHELL_JSON}" >/dev/null 2>&1; then
        warn "skipping: ${SHELL_JSON} is not valid JSON; not editing it"
        return 0
    fi

    # Already present? Then this is a no-op and no backup is written.
    if jq -e --arg id "${WIDGET_ID}" \
            'any((.bar.layout.right // [])[]?; .id == $id)' \
            "${SHELL_JSON}" >/dev/null 2>&1; then
        say "already registered; shell.json unchanged"
        return 0
    fi

    BACKUP="${SHELL_JSON}.bak.$(date +%Y%m%d-%H%M%S)"
    cp -p "${SHELL_JSON}" "${BACKUP}" \
        || die "could not write backup ${BACKUP}; refusing to edit shell.json"
    say "backup: ${BACKUP}"

    TMP_JSON="${SHELL_JSON}.new.$$"
    # Append the widget to bar.layout.right, creating the path if absent.
    # `//` guards a missing or null array; the `any` test makes the filter
    # itself idempotent even if this function is somehow re-entered.
    if jq --arg id "${WIDGET_ID}" '
            .bar.layout.right = (
                (.bar.layout.right // [])
                | if any(.[]?; .id == $id) then . else . + [{"id": $id}] end
            )
        ' "${SHELL_JSON}" > "${TMP_JSON}" 2>/dev/null \
        && [ -s "${TMP_JSON}" ] \
        && jq -e . "${TMP_JSON}" >/dev/null 2>&1
    then
        mv -f "${TMP_JSON}" "${SHELL_JSON}"
        say "added { \"id\": \"${WIDGET_ID}\" } to bar.layout.right"
    else
        rm -f "${TMP_JSON}"
        warn "jq edit failed; ${SHELL_JSON} left untouched (backup at ${BACKUP})"
        return 0
    fi

    # Verify the result really contains the entry exactly once.
    COUNT="$(jq --arg id "${WIDGET_ID}" \
        '[(.bar.layout.right // [])[]? | select(.id == $id)] | length' \
        "${SHELL_JSON}" 2>/dev/null || echo 0)"
    if [ "${COUNT}" != "1" ]; then
        warn "expected exactly 1 ${WIDGET_ID} entry, found ${COUNT}"
        warn "restore with: cp -p '${BACKUP}' '${SHELL_JSON}'"
    fi
}

register_widget

# Reload the shell so the widget appears, if the tooling is present.
if command -v omarchy-shell >/dev/null 2>&1; then
    omarchy-shell shell rescanPlugins >/dev/null 2>&1 || true
    say "requested plugin rescan"
fi

# ---------------------------------------------------------------- next steps

step "Next steps"

case ":${PATH}:" in
    *":${BIN_DIR}:"*) ;;
    *)
        say "1. Add ~/.local/bin to your PATH, it is not there now:"
        say "       export PATH=\"\$HOME/.local/bin:\$PATH\""
        say ""
        ;;
esac

cat <<EOF
Generate an identity (it both decrypts and signs):

    anubis keygen --name default

Then encrypt, decrypt, and inspect:

    anubis encrypt -r anubis1... --sign file -o file.anubis
    anubis decrypt --identity default file.anubis -o file
    anubis inspect file.anubis
    anubis status

Save a recipient under a label so you need not paste 2573-character keys:

    anubis recipient add anubis1... --label alice
    anubis encrypt -r alice file -o file.anubis

Or keep a list of recipients in a file, one per line, '#' for comments:

    anubis encrypt -R team.txt file -o file.anubis

'-' is stdin and stdout, so no scratch file is needed:

    tar cf - dir | anubis encrypt -r anubis1... --sign -o - - > dir.anubis
    anubis decrypt -o - - < dir.anubis | tar xf -

ASCII-armor for email or copy-paste. Decrypt detects it automatically:

    anubis encrypt -r anubis1... -a file        # writes file.anubis.txt

Armor buffers, and is capped at 16777216 bytes of armored text, roughly
11.8 MiB of plaintext. Use binary output for anything larger.

If you depend on a file having come from a particular sender, make it a
precondition rather than checking afterwards. A recipient can strip a
signature:

    anubis decrypt --require-signature file.anubis -o file
    anubis decrypt --signer AAAA-BBBB-CCCC-DDDD-EEEE file.anubis -o file

Shell completions are not installed by this script. Generate them:

    anubis completions bash > ~/.local/share/bash-completion/completions/anubis
    anubis completions zsh  > ~/.local/share/zsh/site-functions/_anubis
    anubis completions fish > ~/.config/fish/completions/anubis.fish

Before encrypting anything real, verify your correspondent's recipient
fingerprint (ANUBIS-FP) out of band. A recipient is 2573 characters and
cannot be checked by eye. Note that a recipient fingerprint and a signer
fingerprint are different values over different keys: 'anubis status --json'
reports them as .fingerprint and .signing_fingerprint. --signer takes the
latter.

Two things worth knowing:

  * ANUBIS has NOT had a third-party cryptographic audit. It composes
    audited primitives rather than implementing them. Read docs/SECURITY.md.

  * Back up your identity file. Losing it means permanently losing access
    to everything encrypted to it. There is no recovery and no escrow.

Docs: docs/FORMAT.md  docs/SECURITY.md  docs/MIGRATION.md
EOF

say ""
say "Done."
