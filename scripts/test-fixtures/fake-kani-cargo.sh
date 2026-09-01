#!/usr/bin/env bash

set -euo pipefail

marker=${ANUBIS_FAKE_KANI_MARKER:?missing fake Kani marker}
isolation_signal=${ANUBIS_FAKE_KANI_ISOLATION_SIGNAL:-}

if [[ "${1:-}" == "kani" && "${2:-}" == "--version" ]]; then
    if [[ -n "$isolation_signal" ]]; then
        rm -f -- "$isolation_signal"
    fi
    printf 'version %s\n' "$$" >>"$marker"
    case "${ANUBIS_FAKE_KANI_VERSION_MODE:-success}" in
        success)
            printf '%s\n' 'cargo-kani 0.67.0'
            exit 0
            ;;
        failure)
            exit 17
            ;;
        wrong)
            printf '%s\n' 'cargo-kani 0.66.0'
            exit 0
            ;;
        multiline)
            printf '%s\n' 'cargo-kani 0.67.0'
            printf '%s\n' 'unexpected extra version output' >&2
            exit 0
            ;;
        block)
            trap 'exit 143' TERM INT HUP
            while :; do
                sleep 1
            done
            ;;
        *)
            printf '%s\n' \
                "unknown fake Kani version mode: ${ANUBIS_FAKE_KANI_VERSION_MODE:-}" >&2
            exit 64
            ;;
    esac
fi

if [[ "${1:-}" != "kani" ]]; then
    printf '%s\n' "unexpected fake cargo invocation: $*" >&2
    exit 64
fi

printf 'proof %s\n' "$$" >>"$marker"
printf '%s\n' 'VERIFICATION:- SUCCESSFUL'

wait_for_isolation_observation() {
    [[ -n "$isolation_signal" ]] || return 0
    while [[ ! -f "$isolation_signal" ]]; do
        sleep 0.01
    done
}

case "${ANUBIS_FAKE_KANI_MODE:-success}" in
    success)
        wait_for_isolation_observation
        exit 0
        ;;
    failure)
        wait_for_isolation_observation
        exit 17
        ;;
    block)
        trap 'exit 143' TERM INT HUP
        while :; do
            sleep 1
        done
        ;;
    *)
        printf '%s\n' "unknown fake Kani mode: ${ANUBIS_FAKE_KANI_MODE:-}" >&2
        exit 64
        ;;
esac
