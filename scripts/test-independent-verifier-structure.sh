#!/usr/bin/env bash

set -euo pipefail

# Regression test for the structural refusals FORMAT.md 4.3 requires of a
# keyless verifier. From one valid signed container it derives headers that
# are cryptographically well-formed but structurally forbidden -- a second
# mldsa87 stanza, a signature stanza before any recipient block, and no
# recipient block at all -- and requires both independent verifiers to refuse
# them with a visible diagnostic. It also checks that a missing input path is
# reported rather than swallowed, which is the failure a silenced stderr hides.

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly repo_root
valid=${1:?usage: test-independent-verifier-structure.sh VALID_SIGNED_CONTAINER}
[[ -f "$valid" ]] || {
    echo "structure fixture must be a regular file" >&2
    exit 2
}
valid=$(readlink -f -- "$valid")

shell_verifier="$repo_root/docs/verify/openssl-verify.sh"
python_verifier="$repo_root/docs/verify/anubis-verify.py"

fixture_root=$(mktemp -d /tmp/anubis-verifier-structure.XXXXXX)
readonly fixture_root
cleanup() {
    local original_status=$?
    case "$fixture_root" in
        /tmp/anubis-verifier-structure.*) ;;
        *) echo "refusing unsafe structure-test cleanup path" >&2; return 1 ;;
    esac
    if [[ -d "$fixture_root" && ! -L "$fixture_root" ]]; then
        find "$fixture_root" -xdev -depth -delete
    fi
    return "$original_status"
}
trap cleanup EXIT

# Split the header (text up to and including the 91-byte MAC line) from the
# binary remainder, using the same scan the shell verifier documents.
mac_offset=$(LC_ALL=C grep -a -b -o -m1 '^--- [A-Za-z0-9+/]\{86\}$' "$valid" \
             | head -n1 | cut -d: -f1)
[[ -n "$mac_offset" ]] || {
    echo "fixture has no MAC line" >&2
    exit 2
}
header_len=$((mac_offset + 91))
head -c "$header_len" -- "$valid" > "$fixture_root/header"
tail -c +$((header_len + 1)) -- "$valid" > "$fixture_root/rest"
grep -q '^-> mldsa87 ' "$fixture_root/header" || {
    echo "fixture must be a signed container" >&2
    exit 2
}

# Each derived header keeps every original line byte-for-byte, so the only
# difference from the valid container is stanza structure.
awk '{ print } /^-> mldsa87 /{ print }' "$fixture_root/header" \
    > "$fixture_root/dup.header"
signature_line=$(grep '^-> mldsa87 ' "$fixture_root/header")
awk -v sig="$signature_line" \
    '/^-> mldsa87 /{ next } /^-> hybrid-x25519-mlkem1024 / && !moved { print sig; moved = 1 } { print }' \
    "$fixture_root/header" > "$fixture_root/early.header"
awk 'BEGIN { skip = 0 } /^-> hybrid-x25519-mlkem1024 /{ skip = 2 } skip > 0 { skip--; next } { print }' \
    "$fixture_root/header" > "$fixture_root/norecip.header"

for name in dup early norecip; do
    cat "$fixture_root/$name.header" "$fixture_root/rest" > "$fixture_root/$name.anubis"
done

failures=0
expect() {
    local label=$1 want=$2 got=$3 stderr_file=$4
    if [[ "$got" != "$want" ]]; then
        echo "FAIL $label: exit $got, expected $want" >&2
        failures=$((failures + 1))
    elif [[ "$want" != 0 && ! -s "$stderr_file" ]]; then
        echo "FAIL $label: refused silently; a diagnostic is required" >&2
        failures=$((failures + 1))
    fi
}

run_shell() {
    local label=$1 file=$2 want=$3 rc
    set +e
    sh "$shell_verifier" "$file" > "$fixture_root/sh.out" 2> "$fixture_root/sh.err"
    rc=$?
    set -e
    expect "shell $label" "$want" "$rc" "$fixture_root/sh.err"
}

run_python() {
    local label=$1 file=$2 want=$3 rc
    set +e
    python3 -I "$python_verifier" "$file" > "$fixture_root/py.out" 2> "$fixture_root/py.err"
    rc=$?
    set -e
    expect "python $label" "$want" "$rc" "$fixture_root/py.err"
}

run_shell "valid control" "$valid" 0
run_python "valid control" "$valid" 0
run_shell "duplicate mldsa87 stanza" "$fixture_root/dup.anubis" 2
run_python "duplicate mldsa87 stanza" "$fixture_root/dup.anubis" 3
run_shell "mldsa87 stanza before recipients" "$fixture_root/early.anubis" 2
run_python "mldsa87 stanza before recipients" "$fixture_root/early.anubis" 3
run_shell "no recipient block" "$fixture_root/norecip.anubis" 2
run_python "no recipient block" "$fixture_root/norecip.anubis" 3
run_shell "missing input path" "$fixture_root/does-not-exist.anubis" 2
run_python "missing input path" "$fixture_root/does-not-exist.anubis" 4

if (( failures > 0 )); then
    echo "Independent verifier structural refusal self-test: $failures failure(s)" >&2
    exit 1
fi
echo "Independent verifier structural refusal self-test: ok"
