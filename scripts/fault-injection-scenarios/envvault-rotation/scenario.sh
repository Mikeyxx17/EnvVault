#!/usr/bin/env bash
#
# Real EnvVault Audit rotation fault-injection scenario.
# Uses the feature-gated `envvault-fault-target` binary so the harness can
# kill a process that is running actual Vault rotation, without a TTY and
# without reading a password from the environment.
#
# Build first:
#   cargo build --features fault-injection --bin envvault-fault-target
#   export ENVVAULT_FAULT_TARGET=$PWD/target/debug/envvault-fault-target
#
# Markers (written by the target as real sidecars appear):
#   prepared-manifest  recovery manifest appears
#   sealed-segment     sealed segment file appears
#   vault-committed    Vault file length changes
#   anchor-confirmed   local-mirror or last-confirmed sidecar appears

set -euo pipefail

work="${FAULT_WORK_ROOT:?FAULT_WORK_ROOT must be set}"
checkpoints="${FAULT_CHECKPOINTS:?FAULT_CHECKPOINTS must be set}"

find_target() {
    if [ -n "${ENVVAULT_FAULT_TARGET:-}" ] && [ -x "$ENVVAULT_FAULT_TARGET" ]; then
        printf '%s' "$ENVVAULT_FAULT_TARGET"
        return 0
    fi
    for candidate in \
        "${CARGO_TARGET_DIR:-target}/debug/envvault-fault-target" \
        target/debug/envvault-fault-target
    do
        if [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

target=$(find_target) || {
    echo "envvault-fault-target not found; build with --features fault-injection" >&2
    exit 2
}

export ENVVAULT_FAULT_PAUSE_MS="${ENVVAULT_FAULT_PAUSE_MS:-400}"
"$target" init --work-root "$work"
"$target" rotate --work-root "$work" --checkpoints "$checkpoints"
