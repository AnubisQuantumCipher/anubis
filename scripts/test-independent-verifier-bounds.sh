#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly repo_root
fixture_root=$(mktemp -d /tmp/anubis-verifier-bounds.XXXXXX)
readonly fixture_root

cleanup() {
    local original_status=$?
    case "$fixture_root" in
        /tmp/anubis-verifier-bounds.*) ;;
        *) echo "refusing unsafe verifier-test cleanup path: $fixture_root" >&2; return 1 ;;
    esac
    if [[ -d "$fixture_root" && ! -L "$fixture_root" ]]; then
        find "$fixture_root" -xdev -depth -delete
    fi
    return "$original_status"
}
trap cleanup EXIT

run_bounded_malformed_case() {
    local path=$1
    local observed_status

    set +e
    (
        ulimit -v 131072
        PYTHONDONTWRITEBYTECODE=1 python3 \
            "$repo_root/docs/verify/anubis-verify.py" "$path" >/dev/null 2>&1
    )
    observed_status=$?
    set -e
    if [[ "$observed_status" != 3 ]]; then
        echo "bounded verifier case returned $observed_status, expected malformed status 3" >&2
        return 1
    fi
}

# Sparse files exercise apparent attacker-controlled length without consuming
# corresponding storage. The binary verifier must read only its bounded header
# prefix instead of materializing the apparent payload.
binary="$fixture_root/hostile-binary.anubis"
printf '%s\n' 'anubis-encryption.org/v3' >"$binary"
truncate -s 1G "$binary"
run_bounded_malformed_case "$binary"

# Armor is intentionally materialized, so its size ceiling must be checked from
# the open handle before attempting a whole-file read.
armored="$fixture_root/hostile-armor.anubis"
printf '%s\n' '-----BEGIN ANUBIS ENCRYPTED FILE-----' >"$armored"
truncate -s 32M "$armored"
run_bounded_malformed_case "$armored"

# A byte cap is not sufficient if parsing first creates one Python object per
# attacker-supplied line. Keep this input under the armor cap but give it a
# flood of empty, non-canonical body lines; the verifier must reject during its
# streaming line scan without exhausting the same memory limit.
short_lines="$fixture_root/hostile-short-lines.anubis"
{
    printf '%s\n' '-----BEGIN ANUBIS ENCRYPTED FILE-----'
    head -c 15000000 /dev/zero | tr '\0' '\n'
    printf '%s\n' '-----END ANUBIS ENCRYPTED FILE-----'
} >"$short_lines"
short_lines_size=$(wc -c <"$short_lines")
if (( short_lines_size >= 16777216 )); then
    echo "short-line fixture unexpectedly exceeds the armor cap" >&2
    exit 1
fi
run_bounded_malformed_case "$short_lines"

echo "Independent verifier bounded-memory guard self-test: ok"
