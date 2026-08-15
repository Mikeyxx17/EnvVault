#!/usr/bin/env bash
#
# Synthetic fault-injection scenario (Linux/macOS port of scenario.ps1).
#
# A toy journal/manifest/segment/descriptor/anchor writer that declares the
# same injection windows as EnvVault's rotation state machine, for
# smoke-testing the harness itself. It contains no secret values and touches
# only $FAULT_WORK_ROOT.
#
# Marker semantics (each marker means "the critical window begins now"):
#   before-manifest   nothing durable written yet
#   manifest-written  manifest.json exists; journal/segment/descriptor absent
#   segment-half      journal.log partially written; segment.dat absent
#   segment-written   segment.dat complete; descriptor absent
#   vault-committed   descriptor.json committed; anchor absent
#   anchor-confirmed  anchor.json written; operation complete

set -euo pipefail

work="${FAULT_WORK_ROOT:?FAULT_WORK_ROOT must be set by the harness}"
checkpoints="${FAULT_CHECKPOINTS:?FAULT_CHECKPOINTS must be set by the harness}"

mark() {
    : >"$checkpoints/$1"
    # Keep the injection window open long enough for the harness watcher.
    sleep 0.25
}

mark before-manifest

printf '%s\n' '{"operation_id":1,"state":"prepared"}' >"$work/manifest.json"
mark manifest-written

for i in $(seq 1 50); do
    printf 'seq=%d payload=%d\n' "$i" "$(( (i * 31) % 1000003 ))" >>"$work/journal.log"
    if [ "$i" -eq 10 ]; then
        mark segment-half
    fi
done

cp "$work/journal.log" "$work/segment.dat"
mark segment-written

printf '%s\n' '{"committed":50}' >"$work/descriptor.json"
mark vault-committed

printf '%s\n' '{"generation":1}' >"$work/anchor.json"
mark anchor-confirmed

printf '%s\n' 'ok' >"$work/done"
