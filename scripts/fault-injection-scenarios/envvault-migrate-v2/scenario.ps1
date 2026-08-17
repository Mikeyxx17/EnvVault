<#
.SYNOPSIS
EnvVault `audit migrate-v2` fault-injection scenario template (M1.2).

.DESCRIPTION
Run `envvault --vault <PATH> audit migrate-v2` and declare checkpoint
markers by observing the real sidecar file lifecycle, mirroring the audit
fault matrix injection points. MUST be run with the harness `-Interactive`
switch so the Master Password TTY prompt works. Requires $env:FAULT_VAULT_PATH
(a throwaway Vault created for this test - never a Vault holding real secrets)
and $env:FAULT_VAULT_DIR (the directory containing it).

Markers:

  prepared-manifest  <vault>.audit-rotation-recovery.json appears
  sealed-segment     a new sidecar file appears (segment staging/sealed)
  vault-committed    the Vault file content changes (descriptor commit)
  anchor-confirmed   <vault>.audit-anchor-v2.json is written/updated
#>

$ErrorActionPreference = 'Stop'

$vault = $env:FAULT_VAULT_PATH
$vaultDir = $env:FAULT_VAULT_DIR
$checkpoints = $env:FAULT_CHECKPOINTS
$work = $env:FAULT_WORK_ROOT
if (-not $vault -or -not $vaultDir -or -not $checkpoints) {
    throw 'FAULT_VAULT_PATH, FAULT_VAULT_DIR and FAULT_CHECKPOINTS must be set.'
}

function Write-Checkpoint {
    param([Parameter(Mandatory)][string]$Name)
    New-Item -ItemType File -Force -Path (Join-Path $checkpoints $Name) | Out-Null
}

$manifestName = "$vault.audit-rotation-recovery.json"
$anchorName = "$vault.audit-anchor-v2.json"
$confirmedName = "$vault.audit-anchor-confirmed.json"
$known = @{
    $manifestName = $true
    $anchorName   = $true
    $confirmedName = $true
    "$vault.audit-descriptor-v3.json" = $true
}
$vaultLengthBefore = if (Test-Path -LiteralPath $vault) {
    (Get-Item -LiteralPath $vault).Length
} else {
    0
}

$watcher = Start-Job -ScriptBlock {
    param($dir, $knownNames, $manifestName, $anchorName, $confirmedName, $vaultPath, $vaultLengthBefore)
    $checkpoints = $env:FAULT_CHECKPOINTS
    $reportedManifest = $false
    $reportedSealed = $false
    $reportedVault = $false
    $reportedAnchor = $false
    $end = (Get-Date).AddMinutes(30)
    while ((Get-Date) -lt $end) {
        $entries = Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue
        if (-not $reportedManifest) {
            if ($entries | Where-Object { $_.Name -eq $manifestName }) {
                New-Item -ItemType File -Force `
                    -Path (Join-Path $checkpoints 'prepared-manifest') | Out-Null
                $reportedManifest = $true
            }
        }
        if (-not $reportedSealed) {
            if ($entries | Where-Object { -not $knownNames.ContainsKey($_.Name) }) {
                New-Item -ItemType File -Force `
                    -Path (Join-Path $checkpoints 'sealed-segment') | Out-Null
                $reportedSealed = $true
            }
        }
        if (-not $reportedVault -and (Test-Path -LiteralPath $vaultPath)) {
            if ((Get-Item -LiteralPath $vaultPath).Length -ne $vaultLengthBefore) {
                New-Item -ItemType File -Force `
                    -Path (Join-Path $checkpoints 'vault-committed') | Out-Null
                $reportedVault = $true
            }
        }
        if (-not $reportedAnchor) {
            $anchor = $entries | Where-Object {
                $_.Name -eq $anchorName -or $_.Name -eq $confirmedName
            }
            if ($anchor) {
                New-Item -ItemType File -Force `
                    -Path (Join-Path $checkpoints 'anchor-confirmed') | Out-Null
                $reportedAnchor = $true
            }
        }
        Start-Sleep -Milliseconds 100
    }
} -ArgumentList $vaultDir, $known, $manifestName, $anchorName, $confirmedName, $vault, $vaultLengthBefore

try {
    & envvault --vault $vault audit migrate-v2
} finally {
    Stop-Job -Job $watcher -ErrorAction SilentlyContinue
    Remove-Job -Job $watcher -Force -ErrorAction SilentlyContinue
}
