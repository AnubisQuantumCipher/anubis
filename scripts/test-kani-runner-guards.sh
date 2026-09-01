#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly repo_root
test_child_pid=""
test_child_pgid=""
test_child_sid=""
test_child_group_isolated=0
supervisor_pid=""

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

invoking_parent_pid=$PPID
readonly invoking_parent_pid
if ! test_shell_identity=$(process_identity "$$"); then
    echo "could not identify the Kani guard test process" >&2
    exit 1
fi
read -r test_shell_pgid test_shell_sid <<<"$test_shell_identity"
readonly test_shell_pgid test_shell_sid
if ! invoking_parent_identity=$(process_identity "$invoking_parent_pid"); then
    echo "could not identify the process invoking the Kani guard test" >&2
    exit 1
fi
read -r invoking_parent_pgid invoking_parent_sid <<<"$invoking_parent_identity"
readonly invoking_parent_pgid invoking_parent_sid
fixture_root=$(mktemp -d /tmp/anubis-kani-guards.XXXXXX)
readonly fixture_root

child_group_is_isolated_now() {
    local current_args
    local current_identity
    local current_pgid
    local current_sid

    (( test_child_group_isolated != 0 )) || return 1
    [[ "$test_child_pgid" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ "$test_child_sid" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ "$test_child_pgid" == "$test_child_sid" ]] || return 1
    [[ "$test_child_pgid" != "$test_shell_pgid" ]] || return 1
    [[ "$test_child_pgid" != "$invoking_parent_pgid" ]] || return 1
    [[ "$test_child_sid" != "$test_shell_sid" ]] || return 1
    [[ "$test_child_sid" != "$invoking_parent_sid" ]] || return 1
    current_identity=$(process_identity "$test_child_pgid") || return 1
    read -r current_pgid current_sid <<<"$current_identity"
    [[ "$current_pgid" == "$test_child_pgid" ]] || return 1
    [[ "$current_sid" == "$test_child_sid" ]] || return 1
    current_args=$(ps -o args= -p "$test_child_pgid" 2>/dev/null) || return 1
    case "$current_args" in
        *"$fixture_root"/*) return 0 ;;
        *) return 1 ;;
    esac
}

record_isolated_child_group() {
    local child_identity
    local supervisor_identity
    local supervisor_pgid
    local supervisor_sid

    child_identity=$(process_identity "$test_child_pid") || return 1
    read -r test_child_pgid test_child_sid <<<"$child_identity"
    supervisor_identity=$(process_identity "$supervisor_pid") || return 1
    read -r supervisor_pgid supervisor_sid <<<"$supervisor_identity"

    [[ "$test_child_pgid" == "$test_child_sid" ]] || return 1
    [[ "$test_child_pgid" != "$test_shell_pgid" ]] || return 1
    [[ "$test_child_pgid" != "$invoking_parent_pgid" ]] || return 1
    [[ "$test_child_pgid" != "$supervisor_pgid" ]] || return 1
    [[ "$test_child_sid" != "$test_shell_sid" ]] || return 1
    [[ "$test_child_sid" != "$invoking_parent_sid" ]] || return 1
    [[ "$test_child_sid" != "$supervisor_sid" ]] || return 1
    test_child_group_isolated=1
    if ! child_group_is_isolated_now; then
        test_child_group_isolated=0
        return 1
    fi
}

clear_test_child_group() {
    test_child_pid=""
    test_child_pgid=""
    test_child_sid=""
    test_child_group_isolated=0
}

wait_for_recorded_child_group_exit() {
    local diagnostic=$1
    local deadline=$((SECONDS + 5))

    (( test_child_group_isolated != 0 )) || return 1
    while kill -0 -- "-$test_child_pgid" 2>/dev/null; do
        if (( SECONDS >= deadline )); then
            echo "$diagnostic" >&2
            if child_group_is_isolated_now; then
                kill -KILL -- "-$test_child_pgid" 2>/dev/null || true
            fi
            return 1
        fi
        sleep 0.1
    done
}

cleanup() {
    local original_status=$?
    local child_args=""
    local supervisor_args=""
    set +e
    if child_group_is_isolated_now; then
        kill -KILL -- "-$test_child_pgid" 2>/dev/null || true
    elif [[ "$test_child_pid" =~ ^[1-9][0-9]*$ ]] &&
        [[ "$test_child_pid" != "$$" ]] &&
        [[ "$test_child_pid" != "$invoking_parent_pid" ]] &&
        kill -0 "$test_child_pid" 2>/dev/null; then
        child_args=$(ps -o args= -p "$test_child_pid" 2>/dev/null || true)
        case "$child_args" in
            *"$fixture_root"/fakebin/cargo* | *"$fixture_root"/*/fakebin/cargo*)
                echo "refusing unsafe process-group cleanup; stopping only the recorded fake Cargo process" >&2
                kill -KILL "$test_child_pid" 2>/dev/null || true
                ;;
        esac
    fi
    if [[ "$supervisor_pid" =~ ^[1-9][0-9]*$ ]] &&
        [[ "$supervisor_pid" != "$$" ]] &&
        [[ "$supervisor_pid" != "$invoking_parent_pid" ]] &&
        kill -0 "$supervisor_pid" 2>/dev/null; then
        supervisor_args=$(ps -o args= -p "$supervisor_pid" 2>/dev/null || true)
        case "$supervisor_args" in
            *"$fixture_root"/scripts/kani-bounded.sh* | \
                *"$fixture_root"/*/scripts/kani-bounded.sh*)
                kill -KILL "$supervisor_pid" 2>/dev/null || true
                wait "$supervisor_pid" 2>/dev/null || true
                ;;
        esac
    fi
    case "$fixture_root" in
        /tmp/anubis-kani-guards.*) ;;
        *) echo "refusing unsafe test cleanup path: $fixture_root" >&2; return 1 ;;
    esac
    if [[ -d "$fixture_root" && ! -L "$fixture_root" ]]; then
        find "$fixture_root" -xdev -depth -delete
    fi
    return "$original_status"
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

make_fake_repo() {
    local root=$1
    mkdir -p "$root/scripts/test-fixtures" "$root/crates/empty" "$root/fakebin"
    cp "$repo_root/scripts/kani-bounded.sh" "$root/scripts/kani-bounded.sh"
    cp "$repo_root/scripts/kani-cover-gate.awk" "$root/scripts/kani-cover-gate.awk"
    cp "$repo_root/scripts/test-fixtures/fake-kani-cargo.sh" "$root/fakebin/cargo"
    cp "$repo_root/scripts/test-fixtures/fake-df.sh" "$root/fakebin/df"
    cp "$repo_root/scripts/test-fixtures/fake-du.sh" "$root/fakebin/du"
    cp "$repo_root/scripts/test-fixtures/fake-ps.sh" "$root/fakebin/ps"
    cp "$repo_root/Cargo.lock" "$root/Cargo.lock"
    : >"$root/crates/empty/lib.rs"
    chmod +x "$root/scripts/kani-bounded.sh" "$root/fakebin/cargo" \
        "$root/fakebin/df" "$root/fakebin/du" "$root/fakebin/ps"
}

fake_path="$fixture_root/fakebin"
make_fake_repo "$fixture_root"
real_df=$(command -v df)
readonly real_df
real_du=$(command -v du)
readonly real_du
real_ps=$(command -v ps)
readonly real_ps
real_setsid=$(command -v setsid)
readonly real_setsid
marker="$fixture_root/kani-invocations.log"

marker_has_process() {
    local marker_path=$1
    local process_kind=$2
    local record
    [[ -f "$marker_path" ]] || return 1
    while IFS= read -r record; do
        if [[ "$record" =~ ^${process_kind}\ [1-9][0-9]*$ ]]; then
            return 0
        fi
    done <"$marker_path"
    return 1
}

last_marker_pid() {
    local marker_path=$1
    local process_kind=$2
    awk -v kind="$process_kind" \
        '$1 == kind && $2 ~ /^[1-9][0-9]*$/ { pid = $2 } END { print pid }' \
        "$marker_path" 2>/dev/null
}

marker_process_count() {
    local marker_path=$1
    local process_kind=$2
    awk -v kind="$process_kind" \
        '$1 == kind && $2 ~ /^[1-9][0-9]*$/ { count += 1 } END { print count + 0 }' \
        "$marker_path" 2>/dev/null
}

wait_for_marker_process() {
    local marker_path=$1
    local process_kind=$2
    local diagnostic=$3
    local deadline=$((SECONDS + 10))

    while ! marker_has_process "$marker_path" "$process_kind"; do
        if (( SECONDS >= deadline )); then
            echo "$diagnostic" >&2
            return 1
        fi
        sleep 0.1
    done
}

# A completed fake proof exercises the real session, monitor, cover gate, and
# cleanup path without retaining any solver output.
env PATH="$fake_path:$PATH" \
    ANUBIS_REAL_DF="$real_df" \
    ANUBIS_REAL_DU="$real_du" \
    ANUBIS_REAL_PS="$real_ps" \
    ANUBIS_FAKE_KANI_MARKER="$marker" \
    ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$marker.isolation" \
    ANUBIS_FAKE_KANI_MODE=success \
    "$fixture_root/scripts/kani-bounded.sh" >/dev/null
if ! awk '
    /^version [1-9][0-9]*$/ { versions += 1; version_line = NR }
    /^proof [1-9][0-9]*$/ { proofs += 1; proof_line = NR }
    END { exit !(versions == 1 && proofs == 1 && version_line < proof_line) }
' "$marker"; then
    echo "successful run did not perform exactly one bounded version probe before its proof" >&2
    exit 1
fi
test ! -e "$fixture_root/target/kani-bounded-work"
test ! -e "$fixture_root/target/.kani-bounded.lockdir"

# The version probe's own nonzero status is preserved, and proof execution is
# never reached after that handled child exit.
version_status_case="$fixture_root/version-status"
make_fake_repo "$version_status_case"
version_status_marker="$version_status_case/kani-invocations.log"
expect_status 17 env PATH="$version_status_case/fakebin:$PATH" \
    ANUBIS_REAL_DF="$real_df" \
    ANUBIS_REAL_DU="$real_du" \
    ANUBIS_REAL_PS="$real_ps" \
    ANUBIS_FAKE_KANI_MARKER="$version_status_marker" \
    ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$version_status_marker.isolation" \
    ANUBIS_FAKE_KANI_VERSION_MODE=failure \
    "$version_status_case/scripts/kani-bounded.sh"
test "$(marker_process_count "$version_status_marker" version)" = 1
test "$(marker_process_count "$version_status_marker" proof)" = 0
test ! -e "$version_status_case/target/kani-bounded-work"
test ! -e "$version_status_case/target/.kani-bounded.lockdir"

run_version_output_rejection() {
    local case_name=$1
    local version_mode=$2
    local expected_diagnostic=$3
    local case_root="$fixture_root/$case_name"
    local case_marker="$case_root/kani-invocations.log"
    local case_output="$case_root/runner-output.log"
    local observed_status

    make_fake_repo "$case_root"
    set +e
    env PATH="$case_root/fakebin:$PATH" \
        ANUBIS_REAL_DF="$real_df" \
        ANUBIS_REAL_DU="$real_du" \
        ANUBIS_REAL_PS="$real_ps" \
        ANUBIS_FAKE_KANI_MARKER="$case_marker" \
        ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$case_marker.isolation" \
        ANUBIS_FAKE_KANI_VERSION_MODE="$version_mode" \
        "$case_root/scripts/kani-bounded.sh" >"$case_output" 2>&1
    observed_status=$?
    set -e

    if [[ "$observed_status" != 1 ]]; then
        echo "unexpected status $observed_status for $case_name version rejection" >&2
        return 1
    fi
    if ! grep -Fq -- "$expected_diagnostic" "$case_output"; then
        echo "$case_name version output was not rejected with the expected diagnostic" >&2
        return 1
    fi
    test "$(marker_process_count "$case_marker" version)" = 1
    test "$(marker_process_count "$case_marker" proof)" = 0
    test ! -e "$case_root/target/kani-bounded-work"
    test ! -e "$case_root/target/.kani-bounded.lockdir"
}

run_version_output_rejection \
    version-wrong \
    wrong \
    "Kani version probe did not return the exact required version string"
run_version_output_rejection \
    version-multiline \
    multiline \
    "Kani version probe did not return the exact required version string"

shorten_fixture_probe_timeout() {
    local runner=$1
    local production_line='readonly VERSION_PROBE_TIMEOUT_SECONDS="900"'
    local fixture_line='readonly VERSION_PROBE_TIMEOUT_SECONDS="1"'

    if [[ "$(grep -Fxc -- "$production_line" "$runner")" != 1 ]]; then
        echo "refusing to alter an unexpected version-probe timeout fixture" >&2
        return 1
    fi
    sed -i \
        's/^readonly VERSION_PROBE_TIMEOUT_SECONDS="900"$/readonly VERSION_PROBE_TIMEOUT_SECONDS="1"/' \
        "$runner"
    grep -Fxq -- "$fixture_line" "$runner"
}

# Only this disposable runner copy receives a short wall limit. The production
# constant remains unchanged, while GNU timeout prevents a broken regression
# from stalling this self-test indefinitely.
version_timeout_case="$fixture_root/version-timeout"
make_fake_repo "$version_timeout_case"
shorten_fixture_probe_timeout "$version_timeout_case/scripts/kani-bounded.sh"
version_timeout_marker="$version_timeout_case/kani-invocations.log"
version_timeout_output="$version_timeout_case/runner-output.log"
timeout --signal=TERM --kill-after=5 20 \
    env PATH="$version_timeout_case/fakebin:$PATH" \
    ANUBIS_REAL_DF="$real_df" \
    ANUBIS_REAL_DU="$real_du" \
    ANUBIS_REAL_PS="$real_ps" \
    ANUBIS_FAKE_KANI_MARKER="$version_timeout_marker" \
    ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$version_timeout_marker.isolation" \
    ANUBIS_FAKE_KANI_VERSION_MODE=block \
    "$version_timeout_case/scripts/kani-bounded.sh" >"$version_timeout_output" 2>&1 &
supervisor_pid=$!
wait_for_marker_process "$version_timeout_marker" version \
    "blocking fake Kani version probe did not start before timeout"
test_child_pid=$(last_marker_pid "$version_timeout_marker" version)
[[ "$test_child_pid" =~ ^[1-9][0-9]*$ ]]
if ! record_isolated_child_group; then
    echo "timed version probe did not enter an isolated process group" >&2
    exit 1
fi
set +e
wait "$supervisor_pid"
version_timeout_status=$?
set -e
supervisor_pid=""
if ! wait_for_recorded_child_group_exit \
    "timed-out Kani version group survived its supervisor"; then
    exit 1
fi
if [[ "$version_timeout_status" != 1 ]]; then
    echo "unexpected status $version_timeout_status for bounded version-probe timeout" >&2
    exit 1
fi
if ! grep -Fq -- "Kani version probe exceeded its wall-time limit" \
    "$version_timeout_output"; then
    echo "blocking version probe did not report its wall-time limit" >&2
    exit 1
fi
if kill -0 "$test_child_pid" 2>/dev/null; then
    echo "timed-out fake Kani version process remained outside its recorded group" >&2
    exit 1
fi
clear_test_child_group
test "$(marker_process_count "$version_timeout_marker" proof)" = 0
test ! -e "$version_timeout_case/target/kani-bounded-work"
test ! -e "$version_timeout_case/target/.kani-bounded.lockdir"

# A fake setsid that merely execs its command proves that validation rejects a
# launcher in the runner's group/session before Cargo crosses the barrier.
nonisolated_case="$fixture_root/version-nonisolated"
make_fake_repo "$nonisolated_case"
cp "$repo_root/scripts/test-fixtures/fake-setsid.sh" "$nonisolated_case/fakebin/setsid"
chmod +x "$nonisolated_case/fakebin/setsid"
nonisolated_marker="$nonisolated_case/kani-invocations.log"
nonisolated_output="$nonisolated_case/runner-output.log"
set +e
"$real_setsid" --wait env PATH="$nonisolated_case/fakebin:$PATH" \
    ANUBIS_REAL_DF="$real_df" \
    ANUBIS_REAL_DU="$real_du" \
    ANUBIS_REAL_PS="$real_ps" \
    ANUBIS_FAKE_KANI_MARKER="$nonisolated_marker" \
    ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$nonisolated_marker.isolation" \
    "$nonisolated_case/scripts/kani-bounded.sh" >"$nonisolated_output" 2>&1
nonisolated_status=$?
set -e
if [[ "$nonisolated_status" != 1 ]]; then
    echo "unexpected status $nonisolated_status for non-isolated fake setsid" >&2
    exit 1
fi
if ! grep -Fq -- \
    "Kani version probe did not enter a safely isolated process group and session" \
    "$nonisolated_output"; then
    echo "non-isolated fake setsid was not rejected by the version barrier" >&2
    exit 1
fi
test ! -e "$nonisolated_marker"
test ! -e "$nonisolated_case/target/kani-bounded-work"
test ! -e "$nonisolated_case/target/.kani-bounded.lockdir"

# Verifier failure is also a handled exit and must leave neither work nor lock.
expect_status 17 env PATH="$fake_path:$PATH" \
    ANUBIS_REAL_DF="$real_df" \
    ANUBIS_REAL_DU="$real_du" \
    ANUBIS_REAL_PS="$real_ps" \
    ANUBIS_FAKE_KANI_MARKER="$marker" \
    ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$marker.isolation" \
    ANUBIS_FAKE_KANI_MODE=failure \
    "$fixture_root/scripts/kani-bounded.sh"
test ! -e "$fixture_root/target/kani-bounded-work"
test ! -e "$fixture_root/target/.kani-bounded.lockdir"

# The version-side liveness watchdog must also reap its entire isolated group
# when the supervisor is uncatchably killed. The resulting lock is deliberately
# stale, and a second invocation must refuse without starting another probe.
version_sigkill_case="$fixture_root/version-sigkill"
make_fake_repo "$version_sigkill_case"
version_sigkill_marker="$version_sigkill_case/kani-invocations.log"
env PATH="$version_sigkill_case/fakebin:$PATH" \
    ANUBIS_REAL_DF="$real_df" \
    ANUBIS_REAL_DU="$real_du" \
    ANUBIS_REAL_PS="$real_ps" \
    ANUBIS_FAKE_KANI_MARKER="$version_sigkill_marker" \
    ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$version_sigkill_marker.isolation" \
    ANUBIS_FAKE_KANI_VERSION_MODE=block \
    "$version_sigkill_case/scripts/kani-bounded.sh" >/dev/null 2>&1 &
supervisor_pid=$!

wait_for_marker_process "$version_sigkill_marker" version \
    "fake Kani version probe did not start before timeout"
test_child_pid=$(last_marker_pid "$version_sigkill_marker" version)
[[ "$test_child_pid" =~ ^[1-9][0-9]*$ ]]
if ! record_isolated_child_group; then
    echo "fake Kani version probe did not enter a group isolated from the test and its invoker" >&2
    exit 1
fi
kill -KILL "$supervisor_pid"
set +e
wait "$supervisor_pid" 2>/dev/null
killed_status=$?
set -e
supervisor_pid=""
test "$killed_status" = 137

deadline=$((SECONDS + 15))
while (( test_child_group_isolated != 0 )) &&
    kill -0 -- "-$test_child_pgid" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
        echo "version-probe group survived supervisor SIGKILL" >&2
        exit 1
    fi
    sleep 0.1
done
clear_test_child_group
test -d "$version_sigkill_case/target/kani-bounded-work"
test -d "$version_sigkill_case/target/.kani-bounded.lockdir"
version_starts_before=$(marker_process_count "$version_sigkill_marker" version)
expect_status 1 env PATH="$version_sigkill_case/fakebin:$PATH" \
    ANUBIS_REAL_DF="$real_df" \
    ANUBIS_REAL_DU="$real_du" \
    ANUBIS_REAL_PS="$real_ps" \
    ANUBIS_FAKE_KANI_MARKER="$version_sigkill_marker" \
    ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$version_sigkill_marker.isolation" \
    ANUBIS_FAKE_KANI_VERSION_MODE=success \
    "$version_sigkill_case/scripts/kani-bounded.sh"
version_starts_after=$(marker_process_count "$version_sigkill_marker" version)
test "$version_starts_after" = "$version_starts_before"
test "$(marker_process_count "$version_sigkill_marker" proof)" = 0
test -d "$version_sigkill_case/target/kani-bounded-work"
test -d "$version_sigkill_case/target/.kani-bounded.lockdir"

# SIGKILL cannot run the supervisor's trap. The proof-side liveness watchdog
# must still stop the otherwise-orphaned process group. Residue and the stale
# lock intentionally remain, so another run refuses rather than piling up.
: >"$marker"
env PATH="$fake_path:$PATH" \
    ANUBIS_REAL_DF="$real_df" \
    ANUBIS_REAL_DU="$real_du" \
    ANUBIS_REAL_PS="$real_ps" \
    ANUBIS_FAKE_KANI_MARKER="$marker" \
    ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$marker.isolation" \
    ANUBIS_FAKE_KANI_MODE=block \
    "$fixture_root/scripts/kani-bounded.sh" >/dev/null 2>&1 &
supervisor_pid=$!

wait_for_marker_process "$marker" proof \
    "fake Kani proof did not start before timeout"
test_child_pid=$(last_marker_pid "$marker" proof)
[[ "$test_child_pid" =~ ^[1-9][0-9]*$ ]]
if ! record_isolated_child_group; then
    echo "fake Kani proof did not enter a process group isolated from the test and its invoker" >&2
    exit 1
fi
kill -KILL "$supervisor_pid"
set +e
wait "$supervisor_pid" 2>/dev/null
killed_status=$?
set -e
supervisor_pid=""
test "$killed_status" = 137

deadline=$((SECONDS + 15))
while (( test_child_group_isolated != 0 )) &&
    kill -0 -- "-$test_child_pgid" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
        echo "proof group survived supervisor SIGKILL" >&2
        exit 1
    fi
    sleep 0.1
done
clear_test_child_group
test -d "$fixture_root/target/kani-bounded-work"
test -d "$fixture_root/target/.kani-bounded.lockdir"
starts_before=$(marker_process_count "$marker" proof)
expect_status 1 env PATH="$fake_path:$PATH" \
    ANUBIS_REAL_DF="$real_df" \
    ANUBIS_REAL_DU="$real_du" \
    ANUBIS_REAL_PS="$real_ps" \
    ANUBIS_FAKE_KANI_MARKER="$marker" \
    ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$marker.isolation" \
    ANUBIS_FAKE_KANI_MODE=success \
    "$fixture_root/scripts/kani-bounded.sh"
starts_after=$(marker_process_count "$marker" proof)
test "$starts_after" = "$starts_before"

# A separate fixture proves the free-space check runs before the Kani proxy,
# so a low-space host cannot trigger an implicit runtime installation.
low_space_case="$fixture_root/low-space"
make_fake_repo "$low_space_case"
low_space_marker="$low_space_case/kani-invocations.log"
expect_status 1 env PATH="$low_space_case/fakebin:$PATH" \
    ANUBIS_REAL_DF="$real_df" \
    ANUBIS_REAL_DU="$real_du" \
    ANUBIS_REAL_PS="$real_ps" \
    ANUBIS_FAKE_LOW_SPACE=1 \
    ANUBIS_FAKE_KANI_MARKER="$low_space_marker" \
    ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$low_space_marker.isolation" \
    ANUBIS_FAKE_KANI_MODE=success \
    "$low_space_case/scripts/kani-bounded.sh"
test ! -e "$low_space_marker"
test ! -e "$low_space_case/target/kani-bounded-work"
test ! -e "$low_space_case/target/.kani-bounded.lockdir"

run_probe_measurement_failure() {
    local case_name=$1
    local expected_diagnostic=$2
    local case_root="$fixture_root/$case_name"
    local case_marker="$case_root/kani-invocations.log"
    local case_output="$case_root/runner-output.log"
    local failure_arm="$case_root/failure.arm"
    local observed_status
    shift 2

    make_fake_repo "$case_root"
    timeout --signal=TERM --kill-after=5 30 \
        env PATH="$case_root/fakebin:$PATH" \
        ANUBIS_REAL_DF="$real_df" \
        ANUBIS_REAL_DU="$real_du" \
        ANUBIS_REAL_PS="$real_ps" \
        ANUBIS_FAKE_FAILURE_ARM="$failure_arm" \
        ANUBIS_FAKE_KANI_MARKER="$case_marker" \
        ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$case_marker.isolation" \
        ANUBIS_FAKE_KANI_VERSION_MODE=block \
        "$@" \
        "$case_root/scripts/kani-bounded.sh" >"$case_output" 2>&1 &
    supervisor_pid=$!
    wait_for_marker_process "$case_marker" version \
        "$case_name fake version process did not start before timeout"
    test_child_pid=$(last_marker_pid "$case_marker" version)
    [[ "$test_child_pid" =~ ^[1-9][0-9]*$ ]]
    if ! record_isolated_child_group; then
        echo "$case_name fake version process did not enter an isolated group" >&2
        return 1
    fi
    : >"$failure_arm"
    set +e
    wait "$supervisor_pid"
    observed_status=$?
    set -e
    supervisor_pid=""
    if ! wait_for_recorded_child_group_exit \
        "$case_name version-probe failure left its process group running"; then
        return 1
    fi

    if [[ "$observed_status" != 1 ]]; then
        echo "unexpected status $observed_status for $case_name version-probe failure" >&2
        return 1
    fi
    if ! grep -Fq -- "$expected_diagnostic" "$case_output"; then
        echo "$case_name did not report its version-probe fail-closed diagnostic" >&2
        return 1
    fi
    if [[ "$(marker_process_count "$case_marker" proof)" != 0 ]]; then
        echo "$case_name version-probe failure allowed the fake proof to start" >&2
        return 1
    fi
    clear_test_child_group
    test ! -e "$case_root/target/kani-bounded-work"
    test ! -e "$case_root/target/.kani-bounded.lockdir"
}

run_probe_measurement_failure \
    probe-du \
    "Kani version-probe storage measurement failed" \
    ANUBIS_FAKE_DU_MODE=probe-failure
run_probe_measurement_failure \
    probe-df \
    "Kani version-probe free-space measurement failed" \
    ANUBIS_FAKE_DF_MODE=probe-failure
run_probe_measurement_failure \
    probe-rss \
    "Kani RSS measurement failed during the version probe" \
    ANUBIS_FAKE_PS_MODE=probe-rss-failure

run_live_measurement_failure() {
    local case_name=$1
    local expected_diagnostic=$2
    local case_root="$fixture_root/$case_name"
    local case_marker="$case_root/kani-invocations.log"
    local case_output="$case_root/runner-output.log"
    local failure_arm="$case_root/failure.arm"
    local observed_status
    shift 2

    make_fake_repo "$case_root"
    timeout --signal=TERM --kill-after=5 30 \
        env PATH="$case_root/fakebin:$PATH" \
        ANUBIS_REAL_DF="$real_df" \
        ANUBIS_REAL_DU="$real_du" \
        ANUBIS_REAL_PS="$real_ps" \
        ANUBIS_FAKE_FAILURE_ARM="$failure_arm" \
        ANUBIS_FAKE_KANI_MARKER="$case_marker" \
        ANUBIS_FAKE_KANI_ISOLATION_SIGNAL="$case_marker.isolation" \
        ANUBIS_FAKE_KANI_MODE=block \
        "$@" \
        "$case_root/scripts/kani-bounded.sh" >"$case_output" 2>&1 &
    supervisor_pid=$!
    wait_for_marker_process "$case_marker" proof \
        "$case_name fake proof did not start before timeout"
    test_child_pid=$(last_marker_pid "$case_marker" proof)
    [[ "$test_child_pid" =~ ^[1-9][0-9]*$ ]]
    if ! record_isolated_child_group; then
        echo "$case_name fake proof did not enter an isolated group" >&2
        return 1
    fi
    : >"$failure_arm"
    set +e
    wait "$supervisor_pid"
    observed_status=$?
    set -e
    supervisor_pid=""
    if ! wait_for_recorded_child_group_exit \
        "live $case_name measurement failure left the proof group running"; then
        return 1
    fi

    if [[ "$observed_status" != 1 ]]; then
        echo "unexpected status $observed_status for live $case_name measurement failure" >&2
        return 1
    fi
    if ! grep -Fq -- "$expected_diagnostic" "$case_output"; then
        echo "live $case_name measurement did not report its fail-closed diagnostic" >&2
        return 1
    fi
    clear_test_child_group
    test ! -e "$case_root/target/kani-bounded-work"
    test ! -e "$case_root/target/.kani-bounded.lockdir"
}

run_live_measurement_failure \
    du \
    "Kani storage measurement failed while the proof group was live" \
    ANUBIS_FAKE_DU_MODE=failure
run_live_measurement_failure \
    df \
    "Kani free-space measurement failed while the proof group was live" \
    ANUBIS_FAKE_DF_MODE=runtime-failure
run_live_measurement_failure \
    rss \
    "Kani RSS measurement failed while the proof group was live" \
    ANUBIS_FAKE_PS_MODE=rss-failure

echo "Kani runner path, lifecycle, liveness, and storage guard self-test: ok"
