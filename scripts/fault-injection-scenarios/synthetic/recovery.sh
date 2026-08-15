#!/usr/bin/env bash
#
# Synthetic fault-injection recovery verifier (Linux/macOS port of
# recovery.ps1). Prints one value-free JSON line
# {"verdict":"...","detail":"..."} and exits 0 (recovered), 2 (fail_closed)
# or 3 (data_loss). Invariants mirror the audit fault matrix:
#
#   - No descriptor        => nothing committed, nothing can be lost
#   - Descriptor committed => journal count >= committed,
#                             segment.dat exists and matches journal,
#                             anchor exists before "done" is allowed

set -uo pipefail

work="${FAULT_WORK_ROOT:?FAULT_WORK_ROOT must be set by the harness}"

journal="$work/journal.log"
segment="$work/segment.dat"
descriptor="$work/descriptor.json"
anchor="$work/anchor.json"
done_file="$work/done"

emit() {
    local verdict="$1" detail="$2" code="$3"
    printf '{"verdict":"%s","detail":"%s"}\n' "$verdict" "$detail"
    exit "$code"
}

journal_count=0
if [ -f "$journal" ]; then
    journal_count=$(wc -l <"$journal" | tr -d ' ')
fi

if [ ! -f "$descriptor" ]; then
    emit fail_closed 'no committed descriptor; nothing can be lost' 2
fi

committed=$(sed -n 's/.*"committed"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$descriptor" | head -1)
committed="${committed:-0}"

if [ ! -f "$segment" ]; then
    emit data_loss 'descriptor references a missing segment' 3
fi

segment_content=$(cat "$segment" 2>/dev/null || true)
journal_content=$(cat "$journal" 2>/dev/null || true)

if [ "$journal_count" -lt "$committed" ]; then
    emit data_loss "journal behind descriptor ($journal_count < $committed)" 3
fi
if [ "$segment_content" != "$journal_content" ]; then
    emit data_loss 'segment does not match the journal' 3
fi
if [ -f "$done_file" ] && [ ! -f "$anchor" ]; then
    emit data_loss 'operation completed without an anchor' 3
fi
emit recovered "consistent state with $committed committed events" 0
