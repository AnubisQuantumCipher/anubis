#!/usr/bin/env bash

set -euo pipefail

fake_kani_phase() {
    local marker=${ANUBIS_FAKE_KANI_MARKER:-}
    local phase=preflight
    local record

    if [[ -n "$marker" && -f "$marker" ]]; then
        while IFS= read -r record; do
            if [[ "$record" =~ ^version\ [1-9][0-9]*$ ]]; then
                phase=version
            elif [[ "$record" =~ ^proof\ [1-9][0-9]*$ ]]; then
                phase=proof
            fi
        done <"$marker"
    fi
    printf '%s\n' "$phase"
}

case "${ANUBIS_FAKE_DU_MODE:-real}" in
    real)
        exec "${ANUBIS_REAL_DU:?missing real du path}" "$@"
        ;;
    failure)
        if [[ "$(fake_kani_phase)" == proof &&
            ( -z "${ANUBIS_FAKE_FAILURE_ARM:-}" ||
                -f "$ANUBIS_FAKE_FAILURE_ARM" ) ]]; then
            exit 1
        fi
        exec "${ANUBIS_REAL_DU:?missing real du path}" "$@"
        ;;
    probe-failure)
        if [[ "$(fake_kani_phase)" == version &&
            ( -z "${ANUBIS_FAKE_FAILURE_ARM:-}" ||
                -f "$ANUBIS_FAKE_FAILURE_ARM" ) ]]; then
            exit 1
        fi
        exec "${ANUBIS_REAL_DU:?missing real du path}" "$@"
        ;;
    *)
        printf '%s\n' "unknown fake du mode: ${ANUBIS_FAKE_DU_MODE:-}" >&2
        exit 64
        ;;
esac
