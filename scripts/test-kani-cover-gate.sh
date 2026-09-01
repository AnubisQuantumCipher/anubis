#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly gate="$repo_root/scripts/kani-cover-gate.awk"

printf ' ** 3 of 3 cover properties satisfied\n ** 5 of 5 cover properties satisfied\n' |
    awk -v expected=8 -f "$gate" >/dev/null

if printf ' ** 0 of 1 cover properties satisfied\n' |
    awk -v expected=1 -f "$gate" >/dev/null; then
    echo "cover gate accepted an unreachable obligation" >&2
    exit 1
fi

if printf 'VERIFICATION:- SUCCESSFUL\n' |
    awk -v expected=1 -f "$gate" >/dev/null; then
    echo "cover gate accepted a missing reachability summary" >&2
    exit 1
fi

if printf ' ** 3 of 3 cover properties satisfied\n' |
    awk -v expected=8 -f "$gate" >/dev/null; then
    echo "cover gate accepted an incomplete obligation inventory" >&2
    exit 1
fi

printf 'VERIFICATION:- SUCCESSFUL\n' |
    awk -v expected=0 -f "$gate" >/dev/null

echo "Kani cover-result gate self-test: ok"
