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

  prepared-manifest  migration or rotation recovery sidecar appears
  sealed-segment     a new sidecar file appears (segment staging/sealed)
  vault-committed    Vault length changes or descriptor appears
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

function Find-EnvVault {
    if ($env:ENVVAULT -and (Test-Path -LiteralPath $env:ENVVAULT)) {
        return $env:ENVVAULT
    }
    $cmd = Get-Command envvault -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw 'envvault not found; add target\debug to PATH or set ENVVAULT'
}

function Find-FaultTarget {
    if ($env:ENVVAULT_FAULT_TARGET -and (Test-Path -LiteralPath $env:ENVVAULT_FAULT_TARGET)) {
        return $env:ENVVAULT_FAULT_TARGET
    }
    $debugDir = $null
    if ($env:ENVVAULT -and (Test-Path -LiteralPath $env:ENVVAULT)) {
        $debugDir = Split-Path -Parent $env:ENVVAULT
    }
    $candidates = @(
        (if ($debugDir) { Join-Path $debugDir 'envvault-fault-target.exe' }),
        (if ($debugDir) { Join-Path $debugDir 'envvault-fault-target' })
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }
    throw 'envvault-fault-target not found; set ENVVAULT_FAULT_TARGET or ENVVAULT to the debug binaries'
}

function Reset-ThrowawayV1 {
    $target = Find-FaultTarget
    $leaf = Split-Path -Leaf $vault
    Get-ChildItem -LiteralPath $vaultDir -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -eq $leaf -or
            $_.Name.StartsWith("$leaf.") -or
            $_.Name.StartsWith('envvault-audit-segment-')
        } |
        Remove-Item -Force
    & $target init-v1 --work-root $vaultDir
    if ($LASTEXITCODE -ne 0) { throw "init-v1 failed with exit $LASTEXITCODE" }
    if (-not (Test-Path -LiteralPath $vault)) {
        throw "init-v1 did not create $vault (expected vault.json under FAULT_VAULT_DIR)"
    }
}

if (-not $env:ENVVAULT_FAULT_PAUSE_MS) {
    $env:ENVVAULT_FAULT_PAUSE_MS = '400'
}
Reset-ThrowawayV1
$envvault = Find-EnvVault

# Sidecar names are the vault *file name* plus a suffix. Comparing
# $_.Name to the full vault path never matches on Windows.
$vaultLeaf = Split-Path -Leaf $vault
$manifestName = "$vaultLeaf.audit-rotation-recovery.json"
$migrationName = "$vaultLeaf.audit-migration-v2.json"
$anchorName = "$vaultLeaf.audit-anchor-v2.json"
$confirmedName = "$vaultLeaf.audit-anchor-confirmed.json"
$descriptorName = "$vaultLeaf.audit-descriptor-v3.json"
$known = @{
    $vaultLeaf      = $true
    $manifestName   = $true
    $migrationName  = $true
    $anchorName     = $true
    $confirmedName  = $true
    $descriptorName = $true
}
$vaultLengthBefore = if (Test-Path -LiteralPath $vault) {
    (Get-Item -LiteralPath $vault).Length
} else {
    0
}

$descriptorExisted = Test-Path -LiteralPath (Join-Path $vaultDir $descriptorName)

$watcher = Start-Job -ScriptBlock {
    param($dir, $knownNames, $manifestName, $migrationName, $anchorName, $confirmedName, $descriptorName, $vaultPath, $vaultLengthBefore, $descriptorExisted, $checkpointDir)
    $reportedManifest = $false
    $reportedSealed = $false
    $reportedVault = $false
    $reportedAnchor = $false
    $end = (Get-Date).AddMinutes(30)
    while ((Get-Date) -lt $end) {
        $entries = Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue
        if (-not $reportedManifest) {
            if ($entries | Where-Object { $_.Name -eq $manifestName -or $_.Name -eq $migrationName }) {
                New-Item -ItemType File -Force `
                    -Path (Join-Path $checkpointDir 'prepared-manifest') | Out-Null
                $reportedManifest = $true
            }
        }
        if (-not $reportedSealed) {
            if ($entries | Where-Object { -not $knownNames.ContainsKey($_.Name) }) {
                New-Item -ItemType File -Force `
                    -Path (Join-Path $checkpointDir 'sealed-segment') | Out-Null
                $reportedSealed = $true
            }
        }
        if (-not $reportedVault) {
            $vaultChanged = (Test-Path -LiteralPath $vaultPath) -and
                ((Get-Item -LiteralPath $vaultPath).Length -ne $vaultLengthBefore)
            $descriptorNow = Test-Path -LiteralPath (Join-Path $dir $descriptorName)
            if ($vaultChanged -or ($descriptorNow -and -not $descriptorExisted)) {
                New-Item -ItemType File -Force `
                    -Path (Join-Path $checkpointDir 'vault-committed') | Out-Null
                $reportedVault = $true
            }
        }
        if (-not $reportedAnchor) {
            $anchor = $entries | Where-Object {
                $_.Name -eq $anchorName -or $_.Name -eq $confirmedName
            }
            if ($anchor) {
                New-Item -ItemType File -Force `
                    -Path (Join-Path $checkpointDir 'anchor-confirmed') | Out-Null
                $reportedAnchor = $true
            }
        }
        Start-Sleep -Milliseconds 100
    }
} -ArgumentList $vaultDir, $known, $manifestName, $migrationName, $anchorName, $confirmedName, $descriptorName, $vault, $vaultLengthBefore, $descriptorExisted, $checkpoints

try {
    & $envvault --vault $vault --masked-input audit migrate-v2
} finally {
    Stop-Job -Job $watcher -ErrorAction SilentlyContinue
    Remove-Job -Job $watcher -Force -ErrorAction SilentlyContinue
}
