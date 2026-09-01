#!/usr/bin/env bash
# Run ANUBIS model checks without retaining solver/build intermediates.

set -euo pipefail
# Non-interactive job control must stay off so the background `setsid` process
# is not already a process-group leader and therefore never needs to fork.
set +m
umask 077

readonly REQUIRED_KANI_VERSION="0.67.0"
# Proof work has a 4 GiB monitored threshold, expressed in KiB. A run refuses
# to start unless twice that space is free, leaving the other half as a reserve.
readonly MAX_WORK_KIB="4194304"
readonly MIN_START_FREE_KIB="8388608"
readonly MIN_RUNTIME_FREE_KIB="4194304"
# Stop a pathological symbolic path even if its disk model remains small. RSS
# is summed across the verifier process group at every polling interval.
readonly MAX_PROOF_RSS_KIB="4194304"

kani_args=()
selected_harness=""
case "$#" in
    0) ;;
    2)
        if [[ "$1" != "--harness" || ! "$2" =~ ^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$ ]]; then
            echo "usage: $0 [--harness RUST_HARNESS_NAME]" >&2
            exit 2
        fi
        selected_harness=$2
        kani_args=(--harness "$selected_harness" --exact)
        ;;
    *)
        echo "usage: $0 [--harness RUST_HARNESS_NAME]" >&2
        exit 2
        ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly repo_root
readonly target_root="$repo_root/target"
readonly work_dir="$target_root/kani-bounded-work"
readonly lock_dir="$target_root/.kani-bounded.lockdir"

case "$work_dir" in
    "$repo_root"/target/kani-bounded-work) ;;
    *) echo "refusing unsafe Kani work path: $work_dir" >&2; exit 2 ;;
esac

proof_pid=""
launcher_pid=""
lock_owned=0

target_parent_valid() {
    if [[ ! -d "$target_root" || -L "$target_root" ]]; then
        return 1
    fi
    local resolved_target
    resolved_target=$(CDPATH= cd -- "$target_root" 2>/dev/null && pwd -P) || return 1
    [[ "$resolved_target" == "$target_root" ]]
}

proof_group_alive() {
    [[ -n "$proof_pid" ]] && kill -0 -- "-$proof_pid" 2>/dev/null
}

stop_proof_group() {
    local signalled=0
    if proof_group_alive; then
        kill -TERM -- "-$proof_pid" 2>/dev/null || true
        signalled=1
    elif [[ -n "$launcher_pid" ]] && kill -0 "$launcher_pid" 2>/dev/null; then
        # Covers the tiny interval before `setsid` creates the new group.
        kill -TERM "$launcher_pid" 2>/dev/null || true
        signalled=1
    fi
    if (( signalled != 0 )); then
        sleep 5
        if proof_group_alive; then
            kill -KILL -- "-$proof_pid" 2>/dev/null || true
        elif [[ -n "$launcher_pid" ]] && kill -0 "$launcher_pid" 2>/dev/null; then
            kill -KILL "$launcher_pid" 2>/dev/null || true
        fi
    fi
    return 0
}

clean_work_dir() {
    if ! target_parent_valid; then
        echo "refusing cleanup through an invalid proof target parent: $target_root" >&2
        return 1
    fi
    if [[ -L "$work_dir" ]]; then
        echo "refusing to clean symlinked Kani work path: $work_dir" >&2
        return 1
    fi
    if [[ -d "$work_dir" ]]; then
        find "$work_dir" -xdev -depth -delete
    fi
}

release_lock() {
    if (( lock_owned == 0 )); then
        return 0
    fi
    if ! target_parent_valid; then
        echo "refusing lock cleanup through an invalid proof target parent: $target_root" >&2
        return 1
    fi
    if [[ ! -d "$lock_dir" || -L "$lock_dir" ]]; then
        echo "refusing to remove replaced Kani lock directory: $lock_dir" >&2
        return 1
    fi
    if ! rmdir -- "$lock_dir"; then
        echo "refusing to remove non-empty Kani lock directory: $lock_dir" >&2
        return 1
    fi
    lock_owned=0
}

cleanup() {
    local original_status=$?
    local cleanup_failed=0
    trap - EXIT INT TERM HUP
    set +e
    stop_proof_group || cleanup_failed=1
    clean_work_dir || cleanup_failed=1
    release_lock || cleanup_failed=1
    if (( original_status == 0 && cleanup_failed != 0 )); then
        echo "Kani checks passed, but safe proof cleanup failed" >&2
        exit 1
    fi
    exit "$original_status"
}

cd "$repo_root"
test -f Cargo.lock
mkdir -p "$target_root"
if ! target_parent_valid; then
    echo "refusing invalid or symlinked proof target parent: $target_root" >&2
    exit 2
fi

# Atomic directory creation prevents concurrent runs without opening or
# truncating a path that an attacker could replace with a symlink. A stale
# directory causes a refusal and must be inspected rather than auto-deleted.
if ! mkdir -- "$lock_dir"; then
    echo "another Kani run or stale lock owns $lock_dir" >&2
    exit 1
fi
lock_owned=1
if ! target_parent_valid; then
    echo "proof target parent changed while acquiring the lock" >&2
    lock_owned=0
    exit 2
fi

# Cleanup is armed only after the target parent and no-follow lock have been
# validated. It revalidates them again before every deletion.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

clean_work_dir
mkdir -p "$work_dir/tmp"
readonly ready_fifo="$work_dir/session.ready"
readonly proof_log="$work_dir/kani.log"
mkfifo -- "$ready_fifo"

if ! command -v rg >/dev/null 2>&1; then
    echo "ripgrep is required to inventory Kani cover obligations" >&2
    exit 1
fi
if [[ -z "$selected_harness" ]]; then
    expected_cover_total=$(rg -o --glob '*.rs' 'kani::cover!' crates | wc -l)
    expected_cover_total=${expected_cover_total//[[:space:]]/}
else
    case "$selected_harness" in
        armor::proofs::boundary_policy_matches_the_exact_transition_matrix)
            expected_cover_total=3
            ;;
        format::parser_proofs::header_line_policy_matches_the_exact_decision_matrix)
            expected_cover_total=5
            ;;
        *)
            expected_cover_total=0
            ;;
    esac
fi
if [[ ! "$expected_cover_total" =~ ^[0-9]+$ ]]; then
    echo "could not inventory required Kani cover obligations" >&2
    exit 1
fi

kani_version=$(cargo kani --version)
if [[ "$kani_version" != "cargo-kani $REQUIRED_KANI_VERSION" ]]; then
    echo "expected cargo-kani $REQUIRED_KANI_VERSION, found: $kani_version" >&2
    exit 1
fi

available_kib=$(df -Pk "$work_dir" | awk 'NR == 2 { print $4 }')
if [[ ! "$available_kib" =~ ^[0-9]+$ ]]; then
    echo "could not determine available filesystem space" >&2
    exit 1
fi
if (( available_kib < MIN_START_FREE_KIB )); then
    echo "refusing Kani run: ${available_kib} KiB free; ${MIN_START_FREE_KIB} KiB required" >&2
    exit 1
fi

echo "Kani $REQUIRED_KANI_VERSION; disposable target: $work_dir"
echo "Storage threshold: ${MAX_WORK_KIB} KiB; starting free space: ${available_kib} KiB"
echo "Runtime free-space floor: ${MIN_RUNTIME_FREE_KIB} KiB"
echo "Proof-process RSS threshold: ${MAX_PROOF_RSS_KIB} KiB"

# `setsid --wait` becomes the proof session leader (job control is disabled)
# while the wrapper confirms that exact ID through a private FIFO. Monitoring
# begins only after that handshake, closing the startup race where the parent
# could probe the group before `setsid` had created it. The wrapper tees a terse,
# colorless log into the disposable tree so required cover reachability can be
# checked before success is returned.
exec 8<>"$ready_fifo"
setsid --wait bash -c '
    set -o pipefail
    proof_log=$1
    proof_tmp=$2
    proof_target=$3
    shift 3
    exec 8>&-
    printf "%s\n" "$$" >&3
    exec 3>&-
    env CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never NO_COLOR=1 \
        TMPDIR="$proof_tmp" cargo kani --workspace \
        -j 1 \
        --output-format terse \
        -Z unstable-options \
        --harness-timeout 15m \
        --target-dir "$proof_target" \
        "$@" 2>&1 | tee "$proof_log"
' anubis-kani "$proof_log" "$work_dir/tmp" "$work_dir" "${kani_args[@]}" \
    3>"$ready_fifo" &
launcher_pid=$!
proof_pid=$launcher_pid

candidate_pid=""
if ! IFS= read -r -t 10 candidate_pid <&8; then
    exec 8>&-
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "Kani session startup handshake failed" >&2
    exit 1
fi
exec 8>&-
if [[ ! "$candidate_pid" =~ ^[1-9][0-9]*$ ]]; then
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "Kani session reported an invalid process-group ID" >&2
    exit 1
fi
if [[ "$candidate_pid" != "$launcher_pid" ]]; then
    kill -TERM -- "-$candidate_pid" 2>/dev/null || true
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "Kani session startup changed process identity" >&2
    exit 1
fi
actual_pgid=$(ps -o pgid= -p "$candidate_pid" | awk '{$1=$1; print}')
if [[ "$actual_pgid" != "$candidate_pid" ]]; then
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "Kani session did not become its own process-group leader" >&2
    exit 1
fi

resource_limit_hit=0
while proof_group_alive; do
    if ! target_parent_valid; then
        echo "Kani proof target parent changed while the proof group was live" >&2
        resource_limit_hit=1
        stop_proof_group
        break
    fi

    used_kib=$(du -sk "$work_dir" | awk '{ print $1 }')
    if [[ "$used_kib" =~ ^[0-9]+$ ]] && (( used_kib > MAX_WORK_KIB )); then
        echo "Kani storage threshold exceeded: ${used_kib} KiB > ${MAX_WORK_KIB} KiB" >&2
        resource_limit_hit=1
        stop_proof_group
        break
    fi

    runtime_free_kib=$(df -Pk "$work_dir" | awk 'NR == 2 { print $4 }')
    if [[ "$runtime_free_kib" =~ ^[0-9]+$ ]] && (( runtime_free_kib < MIN_RUNTIME_FREE_KIB )); then
        echo "Kani runtime free-space floor breached: ${runtime_free_kib} KiB < ${MIN_RUNTIME_FREE_KIB} KiB" >&2
        resource_limit_hit=1
        stop_proof_group
        break
    fi

    if ! proof_rss_kib=$(ps -eo pgid=,rss= | awk -v wanted="$proof_pid" '
        $1 == wanted { total += $2; found = 1 }
        END { if (!found) exit 2; print total + 0 }
    '); then
        if proof_group_alive; then
            echo "Kani RSS measurement failed while the proof group was live" >&2
            resource_limit_hit=1
            stop_proof_group
        fi
        break
    fi
    if [[ "$proof_rss_kib" =~ ^[0-9]+$ ]] && (( proof_rss_kib > MAX_PROOF_RSS_KIB )); then
        echo "Kani RSS threshold exceeded: ${proof_rss_kib} KiB > ${MAX_PROOF_RSS_KIB} KiB" >&2
        resource_limit_hit=1
        stop_proof_group
        break
    fi
    sleep 2
done

set +e
wait "$launcher_pid"
proof_status=$?
set -e
proof_pid=""
launcher_pid=""

if (( resource_limit_hit != 0 )); then
    exit 1
fi
if (( proof_status != 0 )); then
    exit "$proof_status"
fi

if [[ ! -f "$proof_log" || -L "$proof_log" ]]; then
    echo "Kani completed without a safe result log" >&2
    exit 1
fi
cover_gate="$repo_root/scripts/kani-cover-gate.awk"
if [[ ! -f "$cover_gate" || -L "$cover_gate" ]]; then
    echo "missing or unsafe Kani cover gate: $cover_gate" >&2
    exit 1
fi
if ! cover_result=$(LC_ALL=C awk -v expected="$expected_cover_total" -f "$cover_gate" "$proof_log"); then
    echo "Kani cover gate failed: $cover_result" >&2
    exit 1
fi
echo "Kani cover gate: $cover_result"
exit 0
