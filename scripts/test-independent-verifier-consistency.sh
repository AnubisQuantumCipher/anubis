#!/usr/bin/env bash

set -euo pipefail

# The same file doubles as the test-only OpenSSL shim. The verifier has already
# opened its source before this first base64 decode. Replacing the caller's
# symlink here deterministically checks that later utilities still use that
# original handle rather than reopening the path.
if [[ "${ANUBIS_OPENSSL_SWAP_TEST:-0}" == "1" ]]; then
    if [[ "${1:-}" == "base64" && ! -e "${ANUBIS_SWAP_MARKER:?}" ]]; then
        next_link="${ANUBIS_SWAP_LINK:?}.next.$$"
        ln -s -- "${ANUBIS_SWAP_REPLACEMENT:?}" "$next_link"
        mv -Tf -- "$next_link" "$ANUBIS_SWAP_LINK"
        : >"$ANUBIS_SWAP_MARKER"
    fi
    exec "${ANUBIS_REAL_OPENSSL:?}" "$@"
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly repo_root
valid=${1:?usage: test-independent-verifier-consistency.sh VALID TAMPERED}
tampered=${2:?usage: test-independent-verifier-consistency.sh VALID TAMPERED}
[[ -f "$valid" && -f "$tampered" ]] || {
    echo "consistency fixtures must be regular files" >&2
    exit 2
}

valid=$(readlink -f -- "$valid")
tampered=$(readlink -f -- "$tampered")
[[ "$(stat -c %s -- "$valid")" == "$(stat -c %s -- "$tampered")" ]] || {
    echo "consistency fixtures must have the same size" >&2
    exit 2
}

fixture_root=$(mktemp -d /tmp/anubis-verifier-consistency.XXXXXX)
readonly fixture_root
cleanup() {
    local original_status=$?
    case "$fixture_root" in
        /tmp/anubis-verifier-consistency.*) ;;
        *) echo "refusing unsafe consistency-test cleanup path" >&2; return 1 ;;
    esac
    if [[ -d "$fixture_root" && ! -L "$fixture_root" ]]; then
        find "$fixture_root" -xdev -depth -delete
    fi
    return "$original_status"
}
trap cleanup EXIT

mkdir "$fixture_root/fakebin"
ln -s -- "$valid" "$fixture_root/container.anubis"
ln -s -- "$repo_root/scripts/test-independent-verifier-consistency.sh" \
    "$fixture_root/fakebin/openssl"
real_openssl=$(command -v openssl)
readonly real_openssl

env PATH="$fixture_root/fakebin:$PATH" \
    ANUBIS_OPENSSL_SWAP_TEST=1 \
    ANUBIS_REAL_OPENSSL="$real_openssl" \
    ANUBIS_SWAP_LINK="$fixture_root/container.anubis" \
    ANUBIS_SWAP_REPLACEMENT="$tampered" \
    ANUBIS_SWAP_MARKER="$fixture_root/swapped" \
    sh "$repo_root/docs/verify/openssl-verify.sh" \
    "$fixture_root/container.anubis" >/dev/null

[[ -f "$fixture_root/swapped" ]] || {
    echo "consistency test did not replace the caller's path" >&2
    exit 1
}
[[ "$(readlink -f -- "$fixture_root/container.anubis")" == "$tampered" ]] || {
    echo "consistency test replacement did not become visible" >&2
    exit 1
}

echo "Independent verifier single-handle consistency self-test: ok"
