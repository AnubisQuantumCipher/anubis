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

if [[ -n "${ANUBIS_FAKE_KANI_ISOLATION_SIGNAL:-}" &&
    "${1:-}" == "-o" && "${2:-}" == "pgid=" && "${3:-}" == "-p" ]]; then
    if identity=$("${ANUBIS_REAL_PS:?missing real ps path}" "$@"); then
        printf '%s\n' "$identity"
        : >"$ANUBIS_FAKE_KANI_ISOLATION_SIGNAL"
        exit 0
    fi
    exit 1
fi

if [[ "${1:-}" == "-eo" && "${2:-}" == "pgid=,rss=" ]]; then
    case "${ANUBIS_FAKE_PS_MODE:-real}" in
        rss-failure)
            if [[ "$(fake_kani_phase)" == proof &&
                ( -z "${ANUBIS_FAKE_FAILURE_ARM:-}" ||
                    -f "$ANUBIS_FAKE_FAILURE_ARM" ) ]]; then
                exit 1
            fi
            ;;
        probe-rss-failure)
            if [[ "$(fake_kani_phase)" == version &&
                ( -z "${ANUBIS_FAKE_FAILURE_ARM:-}" ||
                    -f "$ANUBIS_FAKE_FAILURE_ARM" ) ]]; then
                exit 1
            fi
            ;;
    esac
fi

case "${ANUBIS_FAKE_PS_MODE:-real}" in
    real | rss-failure | probe-rss-failure)
        exec "${ANUBIS_REAL_PS:?missing real ps path}" "$@"
        ;;
    *)
        printf '%s\n' "unknown fake ps mode: ${ANUBIS_FAKE_PS_MODE:-}" >&2
        exit 64
        ;;
esac
