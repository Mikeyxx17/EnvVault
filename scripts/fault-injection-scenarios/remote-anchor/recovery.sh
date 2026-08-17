#!/usr/bin/env bash
#
# Recovery verifier for the remote-anchor synthetic scenario.
# Prints one value-free JSON line and exits 0 / 2 / 3.

set -uo pipefail

work="${FAULT_WORK_ROOT:?FAULT_WORK_ROOT must be set by the harness}"

store="$work/store/vaults/00/state.json"
confirmed="$work/confirmed.json"
rollback="$work/rollback.json"

emit() {
    local verdict="$1" detail="$2" code="$3"
    printf '{"verdict":"%s","detail":"%s"}\n' "$verdict" "$detail"
    exit "$code"
}

generation_of() {
    if [ ! -f "$1" ]; then
        printf ''
        return 0
    fi
    sed -n 's/.*"generation"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$1" | head -1
}

digest_of() {
    if [ ! -f "$1" ]; then
        printf ''
        return 0
    fi
    sed -n 's/.*"digest"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]*\)".*/\1/p' "$1" | head -1
}

if [ -f "$store" ]; then
    if ! grep -q '"generation"' "$store" 2>/dev/null; then
        emit fail_closed 'store is present but not a usable generation record' 2
    fi
fi

store_gen=$(generation_of "$store")
confirmed_gen=$(generation_of "$confirmed")
store_digest=$(digest_of "$store")
confirmed_digest=$(digest_of "$confirmed")

if [ -z "$confirmed_gen" ] && [ -z "$store_gen" ]; then
    emit fail_closed 'no store and no last-confirmed; nothing can be lost' 2
fi

if [ -n "$confirmed_gen" ]; then
    if [ "$store_gen" = "$confirmed_gen" ] && [ "$store_digest" = "$confirmed_digest" ]; then
        emit recovered "store and last-confirmed both at generation $confirmed_gen" 0
    fi
    if [ -f "$rollback" ]; then
        emit fail_closed "last-confirmed $confirmed_gen is not matched by the store; rollback evidence present" 2
    fi
    emit data_loss "last-confirmed $confirmed_gen has no matching store and no rollback evidence" 3
fi

emit recovered "store generation ${store_gen:-0} is present without last-confirmed" 0
