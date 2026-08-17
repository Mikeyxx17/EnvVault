<#
.SYNOPSIS
Real EnvVault Audit rotation fault-injection scenario.

Build first:

  cargo build --features fault-injection --bin envvault-fault-target
  $env:ENVVAULT_FAULT_TARGET = "$PWD\target\debug\envvault-fault-target.exe"
#>

$ErrorActionPreference = 'Stop'

$work = $env:FAULT_WORK_ROOT
$checkpoints = $env:FAULT_CHECKPOINTS
if (-not $work -or -not $checkpoints) {
    throw 'FAULT_WORK_ROOT and FAULT_CHECKPOINTS must be set.'
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
    throw 'envvault-fault-target not found; build with --features fault-injection'
}

if (-not $env:ENVVAULT_FAULT_PAUSE_MS) {
    $env:ENVVAULT_FAULT_PAUSE_MS = '400'
}
$target = Find-FaultTarget
& $target init --work-root $work
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $target rotate --work-root $work --checkpoints $checkpoints
exit $LASTEXITCODE
