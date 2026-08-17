<#
.SYNOPSIS
Synthetic remote-anchor CAS fault-injection scenario (no TTY, no secrets).

.DESCRIPTION
Models the durable files of the loopback reference CAS and last-confirmed
sidecar. It never talks to EnvVault or reads a Secret Value.

Marker semantics (each marker means "the critical window begins now"):

  before-cas          nothing durable written yet
  store-written       CAS store has generation 1; client has not confirmed
  confirmed-written   last-confirmed matches store generation 1
  store-rolled-back   store is gone; rollback evidence is present
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
    Start-Sleep -Milliseconds 250
}

$storeDir = Join-Path $work 'store/vaults/00'
New-Item -ItemType Directory -Force -Path $storeDir | Out-Null

Write-Checkpoint 'before-cas'

Set-Content -Path (Join-Path $storeDir 'state.json') `
    -Value '{"generation":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' `
    -Encoding utf8
Write-Checkpoint 'store-written'

Set-Content -Path (Join-Path $work 'confirmed.json') `
    -Value '{"generation":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' `
    -Encoding utf8
Write-Checkpoint 'confirmed-written'

Remove-Item -LiteralPath (Join-Path $storeDir 'state.json') -Force
Set-Content -Path (Join-Path $work 'rollback.json') `
    -Value '{"expected_generation":1,"observed_generation":null}' `
    -Encoding utf8
Write-Checkpoint 'store-rolled-back'
