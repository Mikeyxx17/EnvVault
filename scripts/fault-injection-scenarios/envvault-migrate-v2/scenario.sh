#!/usr/bin/env bash
#
# EnvVault `audit migrate-v2` fault-injection scenario (Linux/macOS port of
# scenario.ps1). Run `envvault --vault <PATH> audit migrate-v2` and declare
# checkpoint markers by observing the real sidecar file lifecycle, mirroring
# the audit fault matrix injection points.
#
# MUST be run with the harness `--interactive` switch so the Master Password
# TTY prompt works. Requires FAULT_VAULT_PATH (a throwaway Vault created for
# this test - never a Vault holding real secrets) and FAULT_VAULT_DIR (the
# directory containing it).
#
# Markers:
#   prepared-manifest  <vault>.audit-rotation-recovery.json appears
#   sealed-segment     a new non-vault sidecar file appears (segment staging)
#   vault-committed    the Vault file content changes (descriptor commit)
#   anchor-confirmed   <vault>.audit-anchor-v2.json is written/updated
#
# Template: validated against the synthetic scenario only; the real sidecar
# lifecycle must be confirmed on a TTY-equipped Linux VM before treating any
# run as evidence.

set -euo pipefail

vault="${FAULT_VAULT_PATH:?FAULT_VAULT_PATH must be set}"
vault_dir="${FAULT_VAULT_DIR:?FAULT_VAULT_DIR must be set}"
checkpoints="${FAULT_CHECKPOINTS:?FAULT_CHECKPOINTS must be set}"
work="${FAULT_WORK_ROOT:?FAULT_WORK_ROOT must be set}"

mark() { : >"$checkpoints/$1"; }

vault_base=$(basename "$vault")
manifest_name="$vault_base.audit-rotation-recovery.json"
anchor_name="$vault_base.audit-anchor-v2.json"
descriptor_name="$vault_base.audit-descriptor-v3.json"

known() {
    case "$1" in
        "$vault_base"|"$manifest_name"|"$anchor_name"|"$descriptor_name") return 0 ;;
        *) return 1 ;;
    esac
}

vault_length_before=0
[ -f "$vault" ] && vault_length_before=$(wc -c <"$vault" | tr -d ' ')

(
    reported_manifest=0
    reported_sealed=0
    reported_vault=0
    reported_anchor=0
    end=$((SECONDS + 1800))
    while [ "$SECONDS" -lt "$end" ]; do
        if [ "$reported_manifest" -eq 0 ] && [ -f "$vault_dir/$manifest_name" ]; then
            mark prepared-manifest
            reported_manifest=1
        fi
        if [ "$reported_sealed" -eq 0 ]; then
            for f in "$vault_dir"/*; do
                [ -f "$f" ] || continue
                bn=$(basename "$f")
                if ! known "$bn"; then
                    mark sealed-segment
                    reported_sealed=1
                    break
                fi
            done
        fi
        if [ "$reported_vault" -eq 0 ] && [ -f "$vault" ]; then
            len=$(wc -c <"$vault" | tr -d ' ')
            if [ "$len" -ne "$vault_length_before" ]; then
                mark vault-committed
                reported_vault=1
            fi
        fi
        if [ "$reported_anchor" -eq 0 ] && [ -f "$vault_dir/$anchor_name" ]; then
            mark anchor-confirmed
            reported_anchor=1
        fi
        sleep 0.1
    done
) &
watcher=$!

set +e
envvault --vault "$vault" audit migrate-v2
set -e

kill "$watcher" 2>/dev/null || true
wait "$watcher" 2>/dev/null || true
