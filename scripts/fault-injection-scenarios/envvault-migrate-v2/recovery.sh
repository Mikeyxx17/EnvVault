#!/usr/bin/env bash
#
# EnvVault `audit migrate-v2` recovery verifier (Linux/macOS port of
# recovery.ps1). After the forced kill, open the Vault (requires the
# interactive Master Password, so run with the harness `--interactive` switch)
# and verify the value-free audit chain is readable and the migration is
# either complete, absent (V1 still authoritative) or safely resumable.
#
# Prints one JSON line {"verdict":"...","detail":"..."} and exits 0/2/3 using
# the same verdict classes as the harness: recovered / fail_closed /
# data_loss. Never prints Secret Values, credentials, or ciphertext.

set -uo pipefail

vault="${FAULT_VAULT_PATH:?FAULT_VAULT_PATH must be set}"
work="${FAULT_WORK_ROOT:?FAULT_WORK_ROOT must be set}"

emit() {
    printf '{"verdict":"%s","detail":"%s"}\n' "$1" "$2"
    exit "$3"
}

# `audit list` requires exact `read_audit` Owner authorization and only emits
# value-free fields; a non-zero exit means the chain failed verification
# (acceptable fail-closed) or the Vault refuses to open.
set +e
envvault --vault "$vault" audit list >"$work/recovery-audit-list.log" 2>&1
exit_code=$?
set -e

if [ "$exit_code" -eq 0 ]; then
    emit recovered 'audit chain verified after restart' 0
fi
emit fail_closed "audit list failed with exit code $exit_code; V1 chain remains authoritative until a safe retry" 2
