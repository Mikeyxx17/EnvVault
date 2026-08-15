#!/usr/bin/env bash
#
# Crash / power-loss fault-injection harness for EnvVault recovery verification.
# Linux/macOS port of scripts/fault-injection.ps1.
#
# Runs a scenario script as a child process, force-kills it exactly when a
# named checkpoint marker appears, then runs a recovery verifier and records a
# value-free verdict per injection point (recovered / fail_closed / data_loss).
#
# This is the M1.2 engineering companion: real forced-termination and
# power-loss evidence still requires running it against EnvVault on
# Windows/Linux VMs and real disks in a full-permission environment; this
# harness performs no I/O that requires elevation and never records Secret
# Values.
#
# Contract (same as the PowerShell harness):
#   - The scenario script receives $FAULT_WORK_ROOT and $FAULT_CHECKPOINTS. It
#     performs one operation and writes a marker file named <checkpoint> into
#     the checkpoints directory at each injection window it declares.
#   - The recovery script receives $FAULT_WORK_ROOT, prints one value-free
#     JSON line {"verdict":"...","detail":"..."} and exits:
#       0 = recovered (safe, consistent)
#       2 = fail_closed (no usable state, acceptable)
#       3 = data_loss (invariant violated, must investigate)
#     any other exit code is recorded as an error.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: fault-injection.sh --scenario <path> --recovery <path> --work-root <dir> \
       --inject-at <checkpoint[,checkpoint...]> [options]

  --scenario <path>       Scenario script (bash) implementing the operation.
  --recovery <path>       Recovery verifier script (bash).
  --work-root <dir>       Parent directory for per-run work directories.
  --inject-at <list>      Comma-separated checkpoint names; one run per checkpoint.
  --delay-ms <ms>         Extra delay between marker detection and the kill.
  --watch-timeout <sec>   Upper bound on waiting for a checkpoint marker.
  --runs-root <dir>       Where run records are written (default fault-injection-runs).
  --poweroff <cmd>        Execute this instead of killing (VM power-off hook).
  --interactive           Run children on the inherited console (real EnvVault TTY).
EOF
}

SCENARIO=""
RECOVERY=""
WORK_ROOT=""
INJECT_LIST=""
DELAY_MS=0
WATCH_TIMEOUT=600
RUNS_ROOT="fault-injection-runs"
POWEROFF_CMD=""
INTERACTIVE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --scenario) SCENARIO="$2"; shift 2 ;;
        --recovery) RECOVERY="$2"; shift 2 ;;
        --work-root) WORK_ROOT="$2"; shift 2 ;;
        --inject-at) INJECT_LIST="$2"; shift 2 ;;
        --delay-ms) DELAY_MS="$2"; shift 2 ;;
        --watch-timeout) WATCH_TIMEOUT="$2"; shift 2 ;;
        --runs-root) RUNS_ROOT="$2"; shift 2 ;;
        --poweroff) POWEROFF_CMD="$2"; shift 2 ;;
        --interactive) INTERACTIVE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "fault-injection.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

: "${SCENARIO:?--scenario is required}"
: "${RECOVERY:?--recovery is required}"
: "${WORK_ROOT:?--work-root is required}"
: "${INJECT_LIST:?--inject-at is required}"

SCENARIO=$(cd "$(dirname "$SCENARIO")" && pwd)/$(basename "$SCENARIO")
RECOVERY=$(cd "$(dirname "$RECOVERY")" && pwd)/$(basename "$RECOVERY")
[ -f "$SCENARIO" ] || { echo "scenario not found: $SCENARIO" >&2; exit 2; }
[ -f "$RECOVERY" ] || { echo "recovery not found: $RECOVERY" >&2; exit 2; }

mkdir -p "$WORK_ROOT"
WORK_ROOT=$(cd "$WORK_ROOT" && pwd)

IFS=',' read -r -a INJECT_AT <<<"$INJECT_LIST"

started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_id=$(date -u +%Y%m%d-%H%M%S)
run_dir="$RUNS_ROOT/$run_id"
mkdir -p "$run_dir"
results_file="$run_dir/results.jsonl"
: >"$results_file"

append_result() {
    jq -nc \
        --arg checkpoint "$1" \
        --arg kill_mode "$2" \
        --argjson marker_seen "$3" \
        --argjson scenario_exit "$4" \
        --argjson recovery_exit "$5" \
        --arg verdict "$6" \
        --arg detail "$7" \
        --arg out "$8" \
        --arg err "$9" \
        '{checkpoint:$checkpoint, kill_mode:$kill_mode, marker_seen:$marker_seen,
          scenario_exit_code:$scenario_exit, recovery_exit_code:$recovery_exit,
          recovery:{verdict:$verdict, detail:$detail},
          recovery_stdout:$out, recovery_stderr:$err}' >>"$results_file"
}

for checkpoint in "${INJECT_AT[@]}"; do
    checkpoint=$(printf '%s' "$checkpoint" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -z "$checkpoint" ] && continue

    work="$WORK_ROOT/$run_id-$checkpoint"
    checkpoints="$work/checkpoints"
    mkdir -p "$work" "$checkpoints"

    FAULT_WORK_ROOT="$work" FAULT_CHECKPOINTS="$checkpoints" \
        setsid bash "$SCENARIO" \
        >"$run_dir/$checkpoint.scenario.out.log" \
        2>"$run_dir/$checkpoint.scenario.err.log" &
    child=$!

    marker="$checkpoints/$checkpoint"
    marker_seen=0
    deadline=$(( $(date +%s) + WATCH_TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if ! kill -0 "$child" 2>/dev/null; then break; fi
        if [ -f "$marker" ]; then marker_seen=1; break; fi
        sleep 0.05
    done

    kill_applied=0
    if [ "$marker_seen" -eq 1 ] && kill -0 "$child" 2>/dev/null; then
        if [ "$DELAY_MS" -gt 0 ]; then
            sleep "$(awk -v ms="$DELAY_MS" 'BEGIN { printf "%.3f", ms / 1000 }')"
        fi
        if [ -n "$POWEROFF_CMD" ]; then
            append_result "$checkpoint" poweroff true null null \
                pending_vm_restart \
                'power-off executed; run the recovery script manually after restart' \
                '' ''
            continue
        fi
        kill -9 -- "-$child" 2>/dev/null || kill -9 "$child" 2>/dev/null || true
        for _ in $(seq 1 100); do
            if ! kill -0 "$child" 2>/dev/null; then kill_applied=1; break; fi
            sleep 0.05
        done
    fi

    set +e
    wait "$child" 2>/dev/null
    scenario_exit=$?
    set -e

    if [ "$marker_seen" -eq 1 ] && [ "$kill_applied" -eq 0 ] && [ -z "$POWEROFF_CMD" ]; then
        append_result "$checkpoint" kill_failed true null null \
            kill_failed \
            'the scenario process could not be terminated; this entry is NOT a valid injection, rerun in a full-permission environment' \
            '' ''
        continue
    fi

    set +e
    recovery_out=$(
        FAULT_WORK_ROOT="$work" FAULT_CHECKPOINTS="$checkpoints" \
            bash "$RECOVERY" 2>"$run_dir/$checkpoint.recovery.err.log"
    )
    recovery_exit=$?
    set -e
    printf '%s\n' "$recovery_out" >"$run_dir/$checkpoint.recovery.out.log"

    verdict=$(printf '%s' "$recovery_out" | jq -r '.verdict // "error"' 2>/dev/null || printf 'error')
    detail=$(printf '%s' "$recovery_out" | jq -r '.detail // ""' 2>/dev/null || printf '')
    if [ "$verdict" = "error" ] && [ "$recovery_exit" -eq 2 ]; then verdict="fail_closed"; fi
    if [ "$verdict" = "error" ] && [ "$recovery_exit" -eq 3 ]; then verdict="data_loss"; fi

    append_result "$checkpoint" force_terminate "$marker_seen" "$scenario_exit" "$recovery_exit" \
        "$verdict" "$detail" \
        "$checkpoint.recovery.out.log" "$checkpoint.recovery.err.log"

    echo "==> $checkpoint : marker=$marker_seen scenario_exit=$scenario_exit recovery_exit=$recovery_exit verdict=$verdict"
done

finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)

jq -s \
    --arg run_id "$run_id" \
    --arg started "$started_utc" \
    --arg finished "$finished_utc" \
    --arg scenario "$(basename "$SCENARIO")" \
    --arg recovery "$(basename "$RECOVERY")" \
    '{schema:"envvault-fault-injection-run-v1", run_id:$run_id, started_at:$started,
      finished_at:$finished, scenario:$scenario, recovery:$recovery, results:.}' \
    "$results_file" >"$run_dir/run.json"

{
    printf '# Fault-injection Run Record\n\n'
    printf -- '- Run: `%s`\n' "$run_id"
    printf -- '- Started (UTC): `%s`\n' "$started_utc"
    printf -- '- Finished (UTC): `%s`\n' "$finished_utc"
    printf -- '- Scenario: `%s`\n' "$(basename "$SCENARIO")"
    printf -- '- Recovery: `%s`\n\n' "$(basename "$RECOVERY")"
    printf '| Checkpoint | Marker seen | Scenario exit | Recovery exit | Verdict | Detail |\n'
    printf '|---|---|---|---|---|---|\n'
    jq -r '.results[] | "| \(.checkpoint) | \(.marker_seen) | \(.scenario_exit_code) | \(.recovery_exit_code) | \(.recovery.verdict) | \(.recovery.detail) |"' "$run_dir/run.json"
} >"$run_dir/run.md"

echo ''
echo "==> Run record: $run_dir/run.json"
echo "==> Markdown:   $run_dir/run.md"

data_loss=$(jq '[.results[] | select(.recovery.verdict == "data_loss")] | length' "$run_dir/run.json")
errors=$(jq '[.results[] | select(.recovery.verdict == "error")] | length' "$run_dir/run.json")
kill_failed=$(jq '[.results[] | select(.recovery.verdict == "kill_failed")] | length' "$run_dir/run.json")

if [ "$data_loss" -gt 0 ]; then
    echo 'WARNING: at least one injection point violated a recovery invariant; investigate.' >&2
    exit 3
fi
if [ "$errors" -gt 0 ]; then
    echo 'WARNING: at least one injection point could not be classified; investigate.' >&2
    exit 4
fi
if [ "$kill_failed" -gt 0 ]; then
    echo 'WARNING: at least one kill was denied or ineffective; these entries are not valid injections.' >&2
    exit 5
fi
exit 0
