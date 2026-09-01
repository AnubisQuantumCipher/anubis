#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly repo_root
fixture_root=$(mktemp -d /tmp/anubis-kani-guards.XXXXXX)
readonly fixture_root

cleanup() {
    case "$fixture_root" in
        /tmp/anubis-kani-guards.*) ;;
        *) echo "refusing unsafe test cleanup path: $fixture_root" >&2; return 1 ;;
    esac
    if [[ -d "$fixture_root" && ! -L "$fixture_root" ]]; then
        find "$fixture_root" -xdev -depth -delete
    fi
}
trap cleanup EXIT

expect_status() {
    local expected=$1
    shift
    local observed
    set +e
    "$@" >/dev/null 2>&1
    observed=$?
    set -e
    if [[ "$observed" != "$expected" ]]; then
        echo "unexpected status $observed (wanted $expected): $*" >&2
        return 1
    fi
}

# A harness selector can never be reparsed as a Kani option.
expect_status 2 "$repo_root/scripts/kani-bounded.sh" --harness --version

# A symlinked target parent is rejected before traps are armed. In particular,
# stale work in the symlink destination must not be recursively deleted.
parent_case="$fixture_root/parent"
mkdir -p "$parent_case/scripts" "$parent_case/backing/kani-bounded-work"
cp "$repo_root/scripts/kani-bounded.sh" "$parent_case/scripts/kani-bounded.sh"
cp "$repo_root/scripts/kani-cover-gate.awk" "$parent_case/scripts/kani-cover-gate.awk"
cp "$repo_root/Cargo.lock" "$parent_case/Cargo.lock"
cp "$repo_root/Cargo.lock" "$parent_case/backing/kani-bounded-work/sentinel"
ln -s backing "$parent_case/target"
expect_status 2 "$parent_case/scripts/kani-bounded.sh"
test -f "$parent_case/backing/kani-bounded-work/sentinel"

# Lock acquisition uses mkdir, so a replaced lock path is neither followed nor
# opened/truncated. The external sentinel must survive the refusal.
lock_case="$fixture_root/lock"
mkdir -p "$lock_case/scripts" "$lock_case/target" "$lock_case/backing"
cp "$repo_root/scripts/kani-bounded.sh" "$lock_case/scripts/kani-bounded.sh"
cp "$repo_root/scripts/kani-cover-gate.awk" "$lock_case/scripts/kani-cover-gate.awk"
cp "$repo_root/Cargo.lock" "$lock_case/Cargo.lock"
cp "$repo_root/Cargo.lock" "$lock_case/backing/sentinel"
ln -s "$lock_case/backing" "$lock_case/target/.kani-bounded.lockdir"
expect_status 1 "$lock_case/scripts/kani-bounded.sh"
test -f "$lock_case/backing/sentinel"

echo "Kani runner path/selector guard self-test: ok"
