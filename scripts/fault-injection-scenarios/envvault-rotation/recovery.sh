#!/usr/bin/env bash
#
# Recovery verifier for the real EnvVault rotation scenario.
# Reopens the throwaway Vault through envvault-fault-target and prints one
# value-free JSON verdict. Never prints Secret Values or the test password.

set -uo pipefail

work="${FAULT_WORK_ROOT:?FAULT_WORK_ROOT must be set}"

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
    printf '{"verdict":"error","detail":"envvault-fault-target not found"}\n'
    exit 1
}

set +e
"$target" recover --work-root "$work"
exit_code=$?
set -e
exit "$exit_code"
