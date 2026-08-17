<#
.SYNOPSIS
Recovery verifier for the remote-anchor synthetic scenario.
#>

$ErrorActionPreference = 'Stop'

$work = $env:FAULT_WORK_ROOT
if (-not $work) {
    throw 'FAULT_WORK_ROOT must be set by the harness.'
}

function Write-Verdict {
    param(
        [Parameter(Mandatory)][string]$Verdict,
        [Parameter(Mandatory)][string]$Detail,
        [Parameter(Mandatory)][int]$Code
    )
    Write-Output ('{{"verdict":"{0}","detail":"{1}"}}' -f $Verdict, $Detail)
    exit $Code
}

function Read-Generation {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -match '"generation"\s*:\s*(\d+)') { return [int]$Matches[1] }
    return $null
}

function Read-Digest {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -match '"digest"\s*:\s*"([0-9a-fA-F]*)"') { return $Matches[1] }
    return $null
}

$store = Join-Path $work 'store/vaults/00/state.json'
$confirmed = Join-Path $work 'confirmed.json'
$rollback = Join-Path $work 'rollback.json'

if ((Test-Path -LiteralPath $store) -and -not (Get-Content -LiteralPath $store -Raw | Select-String -Pattern '"generation"')) {
    Write-Verdict -Verdict fail_closed -Detail 'store is present but not a usable generation record' -Code 2
}

$storeGen = Read-Generation $store
$confirmedGen = Read-Generation $confirmed
$storeDigest = Read-Digest $store
$confirmedDigest = Read-Digest $confirmed

if ($null -eq $confirmedGen -and $null -eq $storeGen) {
    Write-Verdict -Verdict fail_closed -Detail 'no store and no last-confirmed; nothing can be lost' -Code 2
}

if ($null -ne $confirmedGen) {
    if ($storeGen -eq $confirmedGen -and $storeDigest -eq $confirmedDigest) {
        Write-Verdict -Verdict recovered -Detail ("store and last-confirmed both at generation {0}" -f $confirmedGen) -Code 0
    }
    if (Test-Path -LiteralPath $rollback) {
        Write-Verdict -Verdict fail_closed -Detail ("last-confirmed {0} is not matched by the store; rollback evidence present" -f $confirmedGen) -Code 2
    }
    Write-Verdict -Verdict data_loss -Detail ("last-confirmed {0} has no matching store and no rollback evidence" -f $confirmedGen) -Code 3
}

Write-Verdict -Verdict recovered -Detail ("store generation {0} is present without last-confirmed" -f $(if ($null -eq $storeGen) { 0 } else { $storeGen })) -Code 0
