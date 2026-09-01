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

if [[ "${ANUBIS_FAKE_LOW_SPACE:-0}" == "1" ]]; then
    printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on'
    printf '%s\n' 'fake 2 1 1 50% /'
    exit 0
fi

case "${ANUBIS_FAKE_DF_MODE:-real}" in
    real)
        ;;
    runtime-failure)
        if [[ "$(fake_kani_phase)" == proof &&
            ( -z "${ANUBIS_FAKE_FAILURE_ARM:-}" ||
                -f "$ANUBIS_FAKE_FAILURE_ARM" ) ]]; then
            exit 1
        fi
        ;;
    probe-failure)
        if [[ "$(fake_kani_phase)" == version &&
            ( -z "${ANUBIS_FAKE_FAILURE_ARM:-}" ||
                -f "$ANUBIS_FAKE_FAILURE_ARM" ) ]]; then
            exit 1
        fi
        ;;
    *)
        printf '%s\n' "unknown fake df mode: ${ANUBIS_FAKE_DF_MODE:-}" >&2
        exit 64
        ;;
esac

exec "${ANUBIS_REAL_DF:?missing real df path}" "$@"
