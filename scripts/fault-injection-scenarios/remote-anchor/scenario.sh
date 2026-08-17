#!/usr/bin/env bash
#
# Synthetic remote-anchor CAS fault-injection scenario (no TTY, no secrets).
#
# Models the durable files of the loopback reference CAS and last-confirmed
# sidecar: store state, client confirmation, then a simulated server rollback.
# It never talks to EnvVault or reads a Secret Value.
#
# Marker semantics (each marker means "the critical window begins now"):
#   before-cas          nothing durable written yet
#   store-written       CAS store has generation 1; client has not confirmed
#   confirmed-written   last-confirmed matches store generation 1
#   store-rolled-back   store is gone; rollback evidence is present

set -euo pipefail

work="${FAULT_WORK_ROOT:?FAULT_WORK_ROOT must be set by the harness}"
checkpoints="${FAULT_CHECKPOINTS:?FAULT_CHECKPOINTS must be set by the harness}"

mark() {
    : >"$checkpoints/$1"
    sleep 0.25
}

store_dir="$work/store/vaults/00"
mkdir -p "$store_dir"

mark before-cas

printf '%s\n' '{"generation":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' \
    >"$store_dir/state.json"
mark store-written

printf '%s\n' '{"generation":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' \
    >"$work/confirmed.json"
mark confirmed-written

rm -f "$store_dir/state.json"
printf '%s\n' '{"expected_generation":1,"observed_generation":null}' \
    >"$work/rollback.json"
mark store-rolled-back
