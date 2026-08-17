<#
.SYNOPSIS
Recovery verifier for the real EnvVault rotation scenario.
#>

$ErrorActionPreference = 'Stop'

$work = $env:FAULT_WORK_ROOT
if (-not $work) {
    throw 'FAULT_WORK_ROOT must be set.'
}

function Find-FaultTarget {
    if ($env:ENVVAULT_FAULT_TARGET -and (Test-Path -LiteralPath $env:ENVVAULT_FAULT_TARGET)) {
        return $env:ENVVAULT_FAULT_TARGET
    }
    $candidates = @(
        (Join-Path ($env:CARGO_TARGET_DIR) 'debug/envvault-fault-target.exe'),
        'target/debug/envvault-fault-target.exe',
        'target/debug/envvault-fault-target'
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }
    Write-Output '{"verdict":"error","detail":"envvault-fault-target not found"}'
    exit 1
}

$target = Find-FaultTarget
& $target recover --work-root $work
exit $LASTEXITCODE
