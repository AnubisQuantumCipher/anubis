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
# The version proxy can perform a first-run install. Give that setup-capable
# probe the same wall budget as one proof harness and bound captured stdout.
readonly VERSION_PROBE_TIMEOUT_SECONDS="900"
readonly MAX_VERSION_OUTPUT_BYTES="65536"

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
proof_group_validated=0
lock_owned=0

process_identity() {
    local process_pid=$1
    ps -o pgid=,sid= -p "$process_pid" | awk '
        NF == 2 && $1 ~ /^[1-9][0-9]*$/ && $2 ~ /^[1-9][0-9]*$/ {
            print $1, $2
            found = 1
            exit
        }
        END { if (!found) exit 1 }
    '
}

readonly runner_parent_pid=$PPID
if ! runner_identity=$(process_identity "$$"); then
    echo "could not identify the Kani runner process" >&2
    exit 1
fi
read -r runner_pgid runner_sid <<<"$runner_identity"
readonly runner_pgid runner_sid
if ! runner_parent_identity=$(process_identity "$runner_parent_pid"); then
    echo "could not identify the process invoking the Kani runner" >&2
    exit 1
fi
read -r runner_parent_pgid runner_parent_sid <<<"$runner_parent_identity"
readonly runner_parent_pgid runner_parent_sid

target_parent_valid() {
    if [[ ! -d "$target_root" || -L "$target_root" ]]; then
        return 1
    fi
    local resolved_target
    resolved_target=$({ CDPATH= cd -- "$target_root" 2>/dev/null && pwd -P; } 9>&-) || return 1
    [[ "$resolved_target" == "$target_root" ]]
}

proof_group_alive() {
    (( proof_group_validated != 0 )) &&
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
        sleep 5 9>&-
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
readonly version_ready_fifo="$work_dir/version.ready"
readonly ready_fifo="$work_dir/session.ready"
readonly supervisor_fifo="$work_dir/supervisor.live"
readonly validation_fifo="$work_dir/session.validated"
readonly version_output="$work_dir/kani-version.txt"
readonly version_timeout_marker="$work_dir/version-timeout.hit"
readonly proof_log="$work_dir/kani.log"
mkfifo -- "$version_ready_fifo"
mkfifo -- "$ready_fifo"
mkfifo -- "$supervisor_fifo"
mkfifo -- "$validation_fifo"

cover_inventory="$work_dir/cover-inventory.txt"
set +e
if command -v rg >/dev/null 2>&1; then
    rg -o --glob '*.rs' 'kani::cover!' crates >"$cover_inventory"
    cover_search_status=$?
elif command -v grep >/dev/null 2>&1; then
    grep -Rho --include='*.rs' -- 'kani::cover!' crates >"$cover_inventory"
    cover_search_status=$?
else
    cover_search_status=127
fi
set -e
# Both search tools use status 1 for a valid empty result. Any other nonzero
# status means the inventory itself was not trustworthy, so fail closed.
if (( cover_search_status > 1 )); then
    echo "could not search source for Kani cover obligations" >&2
    exit 1
fi
if [[ -z "$selected_harness" ]]; then
    expected_cover_total=$(wc -l <"$cover_inventory")
    expected_cover_total=${expected_cover_total//[[:space:]]/}
else
    case "$selected_harness" in
        armor::proofs::boundary_policy_matches_the_exact_transition_matrix)
            expected_cover_total=3
            ;;
        format::parser_proofs::header_line_policy_matches_the_exact_decision_matrix)
            expected_cover_total=5
            ;;
        container::proofs::version_line_policy_matches_the_exact_decision_matrix)
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

filesystem_free_kib() {
    local path=${1:-$work_dir}
    local measured
    measured=$({ df -Pk "$path" | awk 'NR == 2 { print $4 }'; } 9>&-) || return 1
    [[ "$measured" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$measured"
}

# Kani accepts relative or even empty KANI_HOME values, while Rustup treats an
# empty RUSTUP_HOME as unset. Resolve only far enough to identify the existing
# filesystem that would receive a missing setup tree; never create or clean an
# external tool home here.
existing_storage_anchor() {
    local candidate=$1
    local parent
    if [[ -z "$candidate" ]]; then
        candidate=$repo_root
    elif [[ "$candidate" != /* ]]; then
        candidate="$repo_root/$candidate"
    fi
    while [[ ! -e "$candidate" ]]; do
        [[ "$candidate" != / ]] || return 1
        parent=${candidate%/*}
        [[ -n "$parent" ]] || parent=/
        [[ "$parent" != "$candidate" ]] || return 1
        candidate=$parent
    done
    printf '%s\n' "$candidate"
}

if [[ -v HOME ]]; then
    default_tool_home=$HOME
elif ! default_tool_home=$(CDPATH= cd -- ~ 2>/dev/null && pwd -P); then
    echo "could not determine the default Kani/Rustup storage home" >&2
    exit 1
fi
if [[ -v KANI_HOME ]]; then
    kani_storage_root=$KANI_HOME
elif [[ -n "$default_tool_home" ]]; then
    kani_storage_root="$default_tool_home/.kani"
else
    kani_storage_root=.kani
fi
if [[ -v RUSTUP_HOME && -n "$RUSTUP_HOME" ]]; then
    rustup_storage_root=$RUSTUP_HOME
elif [[ -n "$default_tool_home" ]]; then
    rustup_storage_root="$default_tool_home/.rustup"
else
    rustup_storage_root=.rustup
fi

probe_storage_anchors=()
probe_start_free_kib=()
for storage_root in "$work_dir" "$kani_storage_root" "$rustup_storage_root"; do
    if ! storage_anchor=$(existing_storage_anchor "$storage_root"); then
        echo "could not resolve a Kani version-probe storage filesystem" >&2
        exit 1
    fi
    if ! storage_free_kib=$(filesystem_free_kib "$storage_anchor"); then
        echo "could not measure a Kani version-probe storage filesystem" >&2
        exit 1
    fi
    if (( storage_free_kib < MIN_START_FREE_KIB )); then
        echo "refusing Kani version probe: a setup filesystem has ${storage_free_kib} KiB free; ${MIN_START_FREE_KIB} KiB required" >&2
        exit 1
    fi
    probe_storage_anchors+=("$storage_anchor")
    probe_start_free_kib+=("$storage_free_kib")
done

probe_storage_within_limits() {
    local used_kib
    local current_free_kib
    local starting_free_kib
    local index

    if ! used_kib=$({ du -sk "$work_dir" | awk '{ print $1 }'; } 9>&-) ||
        [[ ! "$used_kib" =~ ^[0-9]+$ ]]; then
        echo "Kani version-probe storage measurement failed" >&2
        return 1
    fi
    if (( used_kib > MAX_WORK_KIB )); then
        echo "Kani version-probe storage threshold exceeded" >&2
        return 1
    fi

    for index in "${!probe_storage_anchors[@]}"; do
        if ! current_free_kib=$(filesystem_free_kib "${probe_storage_anchors[index]}"); then
            echo "Kani version-probe free-space measurement failed" >&2
            return 1
        fi
        if (( current_free_kib < MIN_RUNTIME_FREE_KIB )); then
            echo "Kani version-probe runtime free-space floor breached" >&2
            return 1
        fi
        starting_free_kib=${probe_start_free_kib[index]}
        if (( current_free_kib < starting_free_kib &&
            starting_free_kib - current_free_kib > MAX_WORK_KIB )); then
            echo "Kani version-probe filesystem-growth threshold exceeded" >&2
            return 1
        fi
    done
    return 0
}

# This preflight deliberately precedes `cargo kani --version`: the Kani proxy
# may install a missing runtime while answering that probe, and no setup-capable
# command may run when the host is already below the free-space floor.
if ! available_kib=$(filesystem_free_kib); then
    echo "could not determine available filesystem space" >&2
    exit 1
fi
if (( available_kib < MIN_START_FREE_KIB )); then
    echo "refusing Kani run: ${available_kib} KiB free; ${MIN_START_FREE_KIB} KiB required" >&2
    exit 1
fi

# Run the setup-capable version probe in its own session. The supervisor holds
# the only FIFO writer; the child inherits a pre-opened read endpoint so there
# is no parent-death race around opening the FIFO. Its watchdog is armed before
# Cargo starts and kills the whole session on supervisor EOF.
exec 8<>"$version_ready_fifo"
exec 9<>"$supervisor_fifo"
exec 7<"$supervisor_fifo"
exec 6<>"$validation_fifo"
exec 5<"$validation_fifo"
version_probe_deadline=$((SECONDS + VERSION_PROBE_TIMEOUT_SECONDS))
setsid --wait bash -c '
    set -euo pipefail
    version_output=$1
    probe_tmp=$2
    max_file_kib=$3
    max_wall_seconds=$4
    max_output_bytes=$5
    timeout_marker=$6
    exec 8>&-

    (
        trap "exit 0" HUP INT TERM
        IFS= read -r _ <&7 || true
        trap "" HUP INT TERM
        kill -TERM -- "-$$" 2>/dev/null || true
        sleep 5
        kill -KILL -- "-$$" 2>/dev/null || true
    ) &
    watchdog_pid=$!
    (
        trap "exit 0" HUP INT TERM
        IFS= read -r -t "$max_wall_seconds" _ <&7 || true
        trap "" HUP INT TERM
        printf "%s\n" timeout >"$timeout_marker" || true
        kill -TERM -- "-$$" 2>/dev/null || true
        sleep 5
        kill -KILL -- "-$$" 2>/dev/null || true
    ) &
    timeout_watchdog_pid=$!
    exec 7<&-
    stop_watchdogs() {
        kill -HUP "$watchdog_pid" "$timeout_watchdog_pid" 2>/dev/null || true
        wait "$watchdog_pid" 2>/dev/null || true
        wait "$timeout_watchdog_pid" 2>/dev/null || true
    }
    trap stop_watchdogs EXIT

    ulimit -c 0
    ulimit -f "$max_file_kib"
    ulimit -t "$max_wall_seconds"
    printf "%s\n" "$$" >&3
    exec 3>&-
    if ! IFS= read -r validation <&5 || [[ "$validation" != validated ]]; then
        exit 1
    fi
    exec 5<&-
    env CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never NO_COLOR=1 \
        TMPDIR="$probe_tmp" cargo kani --version 2>&1 \
        | head -c "$max_output_bytes" >"$version_output"
' anubis-kani-version "$version_output" "$work_dir/tmp" "$MAX_WORK_KIB" \
    "$VERSION_PROBE_TIMEOUT_SECONDS" "$MAX_VERSION_OUTPUT_BYTES" "$version_timeout_marker" \
    3>"$version_ready_fifo" 6>&- 9>&- &
launcher_pid=$!
proof_pid=$launcher_pid
proof_group_validated=0
exec 7<&-
exec 5<&-

candidate_pid=""
if ! IFS= read -r -t 10 candidate_pid <&8; then
    exec 8>&-
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "Kani version-probe startup handshake failed" >&2
    exit 1
fi
exec 8>&-
if [[ ! "$candidate_pid" =~ ^[1-9][0-9]*$ ]]; then
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "Kani version probe reported an invalid process-group ID" >&2
    exit 1
fi
if [[ "$candidate_pid" != "$launcher_pid" ]]; then
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "Kani version-probe startup changed process identity" >&2
    exit 1
fi
if ! candidate_identity=$({ process_identity "$candidate_pid"; } 9>&-); then
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "could not identify the Kani version-probe session" >&2
    exit 1
fi
read -r actual_pgid actual_sid <<<"$candidate_identity"
if [[ "$actual_pgid" != "$candidate_pid" ||
    "$actual_sid" != "$candidate_pid" ||
    "$actual_pgid" == "$runner_pgid" ||
    "$actual_pgid" == "$runner_parent_pgid" ||
    "$actual_sid" == "$runner_sid" ||
    "$actual_sid" == "$runner_parent_sid" ]]; then
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "Kani version probe did not enter a safely isolated process group and session" >&2
    exit 1
fi
proof_group_validated=1
if ! printf '%s\n' validated >&6; then
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "could not release the validated Kani version-probe session" >&2
    exit 1
fi
exec 6>&-

version_probe_limit_hit=0
while proof_group_alive; do
    if (( SECONDS >= version_probe_deadline )); then
        echo "Kani version probe exceeded its wall-time limit" >&2
        version_probe_limit_hit=1
        stop_proof_group
        break
    fi
    if ! target_parent_valid; then
        echo "Kani proof target parent changed during the version probe" >&2
        version_probe_limit_hit=1
        stop_proof_group
        break
    fi
    if ! probe_storage_within_limits; then
        version_probe_limit_hit=1
        stop_proof_group
        break
    fi
    if ! version_probe_rss_kib=$({ ps -eo pgid=,rss= | awk -v wanted="$proof_pid" '
        $1 == wanted { total += $2; found = 1 }
        END { if (!found) exit 2; print total + 0 }
    '; } 9>&-); then
        if proof_group_alive; then
            echo "Kani RSS measurement failed during the version probe" >&2
            version_probe_limit_hit=1
            stop_proof_group
        fi
        break
    fi
    if [[ ! "$version_probe_rss_kib" =~ ^[0-9]+$ ]]; then
        echo "Kani RSS measurement was invalid during the version probe" >&2
        version_probe_limit_hit=1
        stop_proof_group
        break
    fi
    if (( version_probe_rss_kib > MAX_PROOF_RSS_KIB )); then
        echo "Kani RSS threshold exceeded during the version probe" >&2
        version_probe_limit_hit=1
        stop_proof_group
        break
    fi
    sleep 2 9>&-
done

set +e
wait "$launcher_pid"
version_probe_status=$?
set -e
exec 9>&-
proof_pid=""
launcher_pid=""
proof_group_validated=0

if [[ -L "$version_timeout_marker" ||
    ( -e "$version_timeout_marker" && ! -f "$version_timeout_marker" ) ]]; then
    echo "Kani version probe produced an unsafe wall-time marker" >&2
    version_probe_limit_hit=1
elif [[ -f "$version_timeout_marker" ]]; then
    if (( version_probe_limit_hit == 0 )); then
        echo "Kani version probe exceeded its wall-time limit" >&2
    fi
    version_probe_limit_hit=1
fi

# A final measurement closes the interval between the last poll and process
# exit. Keep the resource failure authoritative over the child status.
if ! target_parent_valid || ! probe_storage_within_limits; then
    version_probe_limit_hit=1
fi
if (( version_probe_limit_hit != 0 )); then
    exit 1
fi
if (( version_probe_status != 0 )); then
    exit "$version_probe_status"
fi
if [[ ! -f "$version_output" || -L "$version_output" ]]; then
    echo "Kani version probe completed without safe bounded output" >&2
    exit 1
fi
kani_version=$(<"$version_output")
if [[ "$kani_version" != "cargo-kani $REQUIRED_KANI_VERSION" ]]; then
    echo "Kani version probe did not return the exact required version string" >&2
    exit 1
fi

# Recheck because a first-run version probe may have installed the runtime in
# the user's tool home outside the disposable proof target.
if ! available_kib=$(filesystem_free_kib); then
    echo "could not determine available filesystem space after Kani version check" >&2
    exit 1
fi
if (( available_kib < MIN_START_FREE_KIB )); then
    echo "refusing Kani run after version check: ${available_kib} KiB free; ${MIN_START_FREE_KIB} KiB required" >&2
    exit 1
fi

echo "Kani $REQUIRED_KANI_VERSION; disposable target: $work_dir"
echo "Storage threshold: ${MAX_WORK_KIB} KiB; starting free space: ${available_kib} KiB"
echo "Runtime free-space floor: ${MIN_RUNTIME_FREE_KIB} KiB"
echo "Proof-process RSS threshold: ${MAX_PROOF_RSS_KIB} KiB"

# `setsid --wait` becomes the proof session leader (job control is disabled)
# while the wrapper confirms that exact ID through a private FIFO. A second
# FIFO is held open only by this supervisor. The proof-side watchdog reads its
# EOF if the supervisor disappears even under SIGKILL, then terminates the
# otherwise-orphaned solver group. Monitoring begins only after that watchdog
# is armed. The wrapper tees a terse, colorless log into the disposable tree so
# required cover reachability can be checked before success is returned.
exec 8<>"$ready_fifo"
exec 9<>"$supervisor_fifo"
exec 7<"$supervisor_fifo"
exec 6<>"$validation_fifo"
exec 5<"$validation_fifo"
setsid --wait bash -c '
    set -o pipefail
    proof_log=$1
    proof_tmp=$2
    proof_target=$3
    shift 3
    exec 8>&-

    # The read-only liveness endpoint was opened before launch while the real
    # supervisor held the only writer, closing the watchdog startup race.
    (
        trap "exit 0" HUP INT TERM
        IFS= read -r _ <&7 || true
        # EOF is the liveness verdict. Ignore the graceful signals we now send
        # to our own group long enough to enforce the escalation deadline.
        trap "" HUP INT TERM
        kill -TERM -- "-$$" 2>/dev/null || true
        sleep 5
        kill -KILL -- "-$$" 2>/dev/null || true
    ) &
    watchdog_pid=$!
    exec 7<&-
    stop_watchdog() {
        kill -HUP "$watchdog_pid" 2>/dev/null || true
        wait "$watchdog_pid" 2>/dev/null || true
    }
    trap stop_watchdog EXIT

    printf "%s\n" "$$" >&3
    exec 3>&-
    if ! IFS= read -r validation <&5 || [[ "$validation" != validated ]]; then
        exit 1
    fi
    exec 5<&-
    env CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never NO_COLOR=1 \
        TMPDIR="$proof_tmp" cargo kani --workspace \
        -j 1 \
        --output-format terse \
        -Z unstable-options \
        --harness-timeout 15m \
        --target-dir "$proof_target" \
        "$@" 2>&1 | tee "$proof_log"
' anubis-kani "$proof_log" "$work_dir/tmp" "$work_dir" "${kani_args[@]}" \
    3>"$ready_fifo" 6>&- 9>&- &
launcher_pid=$!
proof_pid=$launcher_pid
proof_group_validated=0
exec 7<&-
exec 5<&-

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
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "Kani session startup changed process identity" >&2
    exit 1
fi
actual_pgid=$({ ps -o pgid= -p "$candidate_pid" | awk '{$1=$1; print}'; } 9>&-)
actual_sid=$({ ps -o sid= -p "$candidate_pid" | awk '{$1=$1; print}'; } 9>&-)
if [[ "$actual_pgid" != "$candidate_pid" ||
    "$actual_sid" != "$candidate_pid" ||
    "$actual_pgid" == "$runner_pgid" ||
    "$actual_pgid" == "$runner_parent_pgid" ||
    "$actual_sid" == "$runner_sid" ||
    "$actual_sid" == "$runner_parent_sid" ]]; then
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "Kani session did not enter a safely isolated process group and session" >&2
    exit 1
fi
proof_group_validated=1
if ! printf '%s\n' validated >&6; then
    stop_proof_group
    wait "$launcher_pid" 2>/dev/null || true
    echo "could not release the validated Kani proof session" >&2
    exit 1
fi
exec 6>&-

resource_limit_hit=0
while proof_group_alive; do
    if ! target_parent_valid; then
        echo "Kani proof target parent changed while the proof group was live" >&2
        resource_limit_hit=1
        stop_proof_group
        break
    fi

    if ! used_kib=$({ du -sk "$work_dir" | awk '{ print $1 }'; } 9>&-) ||
        [[ ! "$used_kib" =~ ^[0-9]+$ ]]; then
        echo "Kani storage measurement failed while the proof group was live" >&2
        resource_limit_hit=1
        stop_proof_group
        break
    fi
    if (( used_kib > MAX_WORK_KIB )); then
        echo "Kani storage threshold exceeded: ${used_kib} KiB > ${MAX_WORK_KIB} KiB" >&2
        resource_limit_hit=1
        stop_proof_group
        break
    fi

    if ! runtime_free_kib=$(filesystem_free_kib); then
        echo "Kani free-space measurement failed while the proof group was live" >&2
        resource_limit_hit=1
        stop_proof_group
        break
    fi
    if (( runtime_free_kib < MIN_RUNTIME_FREE_KIB )); then
        echo "Kani runtime free-space floor breached: ${runtime_free_kib} KiB < ${MIN_RUNTIME_FREE_KIB} KiB" >&2
        resource_limit_hit=1
        stop_proof_group
        break
    fi

    if ! proof_rss_kib=$({ ps -eo pgid=,rss= | awk -v wanted="$proof_pid" '
        $1 == wanted { total += $2; found = 1 }
        END { if (!found) exit 2; print total + 0 }
    '; } 9>&-); then
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
    sleep 2 9>&-
done

set +e
wait "$launcher_pid"
proof_status=$?
set -e
exec 9>&-
proof_pid=""
launcher_pid=""
proof_group_validated=0

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
