<#
.SYNOPSIS
Synthetic fault-injection recovery verifier. Prints one value-free JSON line
{"verdict":"...","detail":"..."} and exits 0 (recovered), 2 (fail_closed)
or 3 (data_loss). Invariants mirror the audit fault matrix:

  - No descriptor        => nothing committed, nothing can be lost
  - Descriptor committed => journal count >= committed,
                            segment.dat exists and matches journal,
                            anchor exists before "done" is allowed
#>

$ErrorActionPreference = 'Stop'

$work = $env:FAULT_WORK_ROOT
if (-not $work) {
    throw 'FAULT_WORK_ROOT must be set by the harness.'
}

function Emit {
    param(
        [Parameter(Mandatory)][string]$Verdict,
        [Parameter(Mandatory)][string]$Detail,
        [Parameter(Mandatory)][int]$ExitCode
    )
    @{ verdict = $Verdict; detail = $Detail } | ConvertTo-Json -Compress
    exit $ExitCode
}

$journal = Join-Path $work 'journal.log'
$segment = Join-Path $work 'segment.dat'
$descriptor = Join-Path $work 'descriptor.json'
$anchor = Join-Path $work 'anchor.json'
$done = Join-Path $work 'done'

$journalCount = 0
if (Test-Path -LiteralPath $journal) {
    $journalCount = @(Get-Content -LiteralPath $journal).Count
}

if (-not (Test-Path -LiteralPath $descriptor)) {
    Emit 'fail_closed' 'no committed descriptor; nothing can be lost' 2
}

$committed = (Get-Content -LiteralPath $descriptor -Raw | ConvertFrom-Json).committed
if (-not (Test-Path -LiteralPath $segment)) {
    Emit 'data_loss' 'descriptor references a missing segment' 3
}
$segmentContent = if (Test-Path -LiteralPath $segment) {
    @(Get-Content -LiteralPath $segment) -join "`n"
} else {
    ''
}
$journalContent = if ($journalCount -gt 0) {
    @(Get-Content -LiteralPath $journal) -join "`n"
} else {
    ''
}
if ($journalCount -lt $committed) {
    Emit 'data_loss' "journal behind descriptor ($journalCount < $committed)" 3
}
if ($segmentContent -ne $journalContent) {
    Emit 'data_loss' 'segment does not match the journal' 3
}
if ((Test-Path -LiteralPath $done) -and -not (Test-Path -LiteralPath $anchor)) {
    Emit 'data_loss' 'operation completed without an anchor' 3
}
Emit 'recovered' "consistent state with $committed committed events" 0
