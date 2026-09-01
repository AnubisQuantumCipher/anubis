#!/usr/bin/env bash

set -euo pipefail

# Deliberately omit session creation. The runner must detect this before its
# validation barrier releases the fake Cargo process.
if [[ "${1:-}" == "--wait" ]]; then
    shift
fi
exec "$@"
