<#
.SYNOPSIS
Synthetic fault-injection scenario: a toy journal/manifest/segment/descriptor
/anchor writer that declares the same injection windows as EnvVault's
rotation state machine, for smoke-testing the harness itself. It contains no
secret values and touches only $env:FAULT_WORK_ROOT.

Marker semantics (each marker means "the critical window begins now"):

  before-manifest   nothing durable written yet
  manifest-written  manifest.json exists; journal/segment/descriptor absent
  segment-half      journal.log partially written; segment.dat absent
  segment-written   segment.dat complete; descriptor absent
  vault-committed   descriptor.json committed; anchor absent
  anchor-confirmed  anchor.json written; operation complete
#>

$ErrorActionPreference = 'Stop'

$work = $env:FAULT_WORK_ROOT
$checkpoints = $env:FAULT_CHECKPOINTS
if (-not $work -or -not $checkpoints) {
    throw 'FAULT_WORK_ROOT and FAULT_CHECKPOINTS must be set by the harness.'
}

function Write-Checkpoint {
    param([Parameter(Mandatory)][string]$Name)
    New-Item -ItemType File -Force -Path (Join-Path $checkpoints $Name) | Out-Null
    # Keep the injection window open long enough for the harness watcher.
    Start-Sleep -Milliseconds 250
}

Write-Checkpoint 'before-manifest'

Set-Content -Path (Join-Path $work 'manifest.json') `
    -Value '{"operation_id":1,"state":"prepared"}' -Encoding UTF8
Write-Checkpoint 'manifest-written'

$journal = Join-Path $work 'journal.log'
1..50 | ForEach-Object {
    Add-Content -Path $journal -Value "seq=$_ payload=$(($_ * 31) % 1000003)" -Encoding UTF8
    if ($_ -eq 10) {
        Write-Checkpoint 'segment-half'
    }
}
Set-Content -Path (Join-Path $work 'segment.dat') `
    -Value (Get-Content -Path $journal -Raw) -Encoding UTF8 -NoNewline
Write-Checkpoint 'segment-written'

Set-Content -Path (Join-Path $work 'descriptor.json') `
    -Value '{"committed":50}' -Encoding UTF8
Write-Checkpoint 'vault-committed'

Set-Content -Path (Join-Path $work 'anchor.json') `
    -Value '{"generation":1}' -Encoding UTF8
Write-Checkpoint 'anchor-confirmed'

Set-Content -Path (Join-Path $work 'done') -Value 'ok' -Encoding UTF8
