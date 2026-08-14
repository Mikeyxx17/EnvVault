<#
.SYNOPSIS
Crash / power-loss fault-injection harness for EnvVault recovery verification.

.DESCRIPTION
Runs a scenario script as a child process, force-kills it exactly when a
named checkpoint marker appears, then runs a recovery verifier and records a
value-free verdict per injection point (recovered / fail_closed / data_loss).
This is the M1.2 engineering companion: real forced-termination and power-loss
evidence still requires running it against EnvVault on Windows/Linux VMs and
real disks in a full-permission environment; this harness performs no I/O
that requires elevation and never records Secret Values.

Contract:
  - The scenario script receives $env:FAULT_WORK_ROOT and
    $env:FAULT_CHECKPOINTS. It performs one operation and writes a marker
    file named <checkpoint> into the checkpoints directory at each injection
    window it declares (marker = the window begins).
  - The recovery script receives $env:FAULT_WORK_ROOT, prints one
    value-free JSON line {"verdict":"...","detail":"..."} and exits:
      0 = recovered (safe, consistent)
      2 = fail_closed (no usable state, acceptable)
      3 = data_loss (invariant violated, must investigate)
    any other exit code is recorded as an error.

.PARAMETER ScenarioScript
PowerShell script implementing the operation and checkpoint markers.

.PARAMETER RecoveryScript
PowerShell script implementing the post-restart verifier.

.PARAMETER WorkRoot
Parent directory for per-run work directories (created as needed).

.PARAMETER InjectAt
Checkpoint names to inject at; one run per checkpoint.

.PARAMETER DelayMsAfterCheckpoint
Extra delay between marker detection and the kill, in milliseconds.

.PARAMETER WatchTimeoutSeconds
Upper bound on waiting for a checkpoint marker.

.PARAMETER RunsRoot
Where run records are written (value-free JSON + Markdown).

.PARAMETER PoweroffCommand
When set, executes this command instead of Stop-Process (VM power-off
hook, e.g. VBoxManage controlvm <vm> poweroff). Local collection then stops:
the record is written with recovery = pending_vm_restart and the recovery
script must be run manually after the VM restarts.

.PARAMETER Interactive
Run children with an inherited console so TTY Master Password prompts work.
Required for real EnvVault scenarios; the synthetic scenario is headless.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ScenarioScript,

    [Parameter(Mandatory)]
    [string]$RecoveryScript,

    [Parameter(Mandatory)]
    [string]$WorkRoot,

    [Parameter(Mandatory)]
    [string[]]$InjectAt,

    [int]$DelayMsAfterCheckpoint = 0,

    [int]$WatchTimeoutSeconds = 600,

    [string]$RunsRoot = 'fault-injection-runs',

    [string]$PoweroffCommand = '',

    [switch]$Interactive
)

$ErrorActionPreference = 'Stop'

$scenarioPath = (Resolve-Path $ScenarioScript).Path
$recoveryPath = (Resolve-Path $RecoveryScript).Path
New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
$workRoot = (Resolve-Path $WorkRoot).Path
$runsRootPath = if ([System.IO.Path]::IsPathRooted($RunsRoot)) {
    $RunsRoot
} else {
    Join-Path (Get-Location) $RunsRoot
}
$pwsh = (Get-Command pwsh).Source

$startedUtc = (Get-Date).ToUniversalTime()
$runId = $startedUtc.ToString('yyyyMMdd-HHmmss')
$runDir = Join-Path $runsRootPath $runId
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

function Get-UtcIso {
    (Get-Date).ToUniversalTime().ToString('o')
}

$results = @()

foreach ($checkpoint in $InjectAt) {
    $work = Join-Path $workRoot "$runId-$checkpoint"
    $checkpoints = Join-Path $work 'checkpoints'
    foreach ($dir in @($work, $checkpoints)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $env:FAULT_WORK_ROOT = $work
    $env:FAULT_CHECKPOINTS = $checkpoints

    $startArgs = if ($Interactive) {
        @('-NoProfile', '-File', $scenarioPath)
    } else {
        @('-NoProfile', '-NonInteractive', '-File', $scenarioPath)
    }
    $child = Start-Process -FilePath $pwsh -ArgumentList $startArgs `
        -PassThru -WorkingDirectory $work -WindowStyle Hidden

    $marker = Join-Path $checkpoints $checkpoint
    $deadline = (Get-Date).AddSeconds($WatchTimeoutSeconds)
    $markerSeen = $false
    while ((Get-Date) -lt $deadline) {
        if ($child.HasExited) {
            break
        }
        if (Test-Path -LiteralPath $marker) {
            $markerSeen = $true
            break
        }
        Start-Sleep -Milliseconds 50
    }

    $killApplied = $false
    if ($markerSeen -and -not $child.HasExited) {
        if ($DelayMsAfterCheckpoint -gt 0) {
            Start-Sleep -Milliseconds $DelayMsAfterCheckpoint
        }
        if ($PoweroffCommand) {
            Invoke-Expression $PoweroffCommand
            $results += [ordered]@{
                checkpoint            = $checkpoint
                kill_mode             = 'poweroff'
                marker_seen           = $true
                scenario_exit_code    = $null
                recovery              = [ordered]@{
                    verdict = 'pending_vm_restart'
                    detail  = 'power-off executed; run the recovery script manually after the VM restarts'
                }
            }
            $record = [ordered]@{
                schema        = 'envvault-fault-injection-run-v1'
                run_id        = $runId
                started_at    = $startedUtc.ToString('o')
                scenario      = (Split-Path $scenarioPath -Leaf)
                recovery      = (Split-Path $recoveryPath -Leaf)
                poweroff      = $PoweroffCommand
                results       = $results
            }
            $record | ConvertTo-Json -Depth 6 |
                Set-Content -Path (Join-Path $runDir 'run.json') -Encoding UTF8
            Write-Host "==> Power-off requested at '$checkpoint'; record: $runDir\run.json"
            exit 0
        }
        if ($IsWindows) {
            & taskkill /PID $child.Id /T /F 2>$null | Out-Null
        } else {
            Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue
        }
        Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue
        $grace = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $grace) {
            Start-Sleep -Milliseconds 50
            $child.Refresh()
            if ($child.HasExited) {
                $killApplied = $true
                break
            }
        }
        if (-not $killApplied) {
            $results += [ordered]@{
                checkpoint         = $checkpoint
                kill_mode          = 'kill_failed'
                marker_seen        = $true
                scenario_exit_code = $null
                recovery           = [ordered]@{
                    verdict = 'kill_failed'
                    detail  = 'the scenario process could not be terminated (permission denied or already finished); this entry is NOT a valid injection, rerun in a full-permission environment'
                }
            }
            Write-Host "==> $checkpoint : kill failed (denied or already exited); entry recorded as kill_failed"
            continue
        }
    }
    if (-not $child.HasExited) {
        $child.WaitForExit()
    }
    $scenarioExit = $child.ExitCode

    $stdout = Join-Path $runDir "$checkpoint.recovery.out.log"
    $stderr = Join-Path $runDir "$checkpoint.recovery.err.log"
    $recoveryArgs = if ($Interactive) {
        @('-NoProfile', '-File', $recoveryPath)
    } else {
        @('-NoProfile', '-NonInteractive', '-File', $recoveryPath)
    }
    $output = & $pwsh @recoveryArgs 2>$stderr | Out-String
    $recoveryExit = $LASTEXITCODE
    $output | Set-Content -Path $stdout -Encoding UTF8
    $verdict = 'error'
    $detail = ''
    $parsed = $output | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($null -ne $parsed.verdict) {
        $verdict = [string]$parsed.verdict
        $detail = [string]$parsed.detail
    }
    if ($verdict -eq 'error' -and $recoveryExit -eq 2) {
        $verdict = 'fail_closed'
    }
    if ($verdict -eq 'error' -and $recoveryExit -eq 3) {
        $verdict = 'data_loss'
    }

    $results += [ordered]@{
        checkpoint         = $checkpoint
        kill_mode          = 'force_terminate'
        marker_seen        = $markerSeen
        scenario_exit_code = $scenarioExit
        recovery_exit_code = $recoveryExit
        recovery           = [ordered]@{
            verdict = $verdict
            detail  = $detail
        }
        recovery_stdout    = "$checkpoint.recovery.out.log"
        recovery_stderr    = "$checkpoint.recovery.err.log"
    }

    Write-Host "==> $checkpoint : marker=$markerSeen kill=$scenarioExit verdict=$verdict"
}

$finishedUtc = (Get-Date).ToUniversalTime()
$record = [ordered]@{
    schema     = 'envvault-fault-injection-run-v1'
    run_id     = $runId
    started_at = $startedUtc.ToString('o')
    finished_at = $finishedUtc.ToString('o')
    scenario   = (Split-Path $scenarioPath -Leaf)
    recovery   = (Split-Path $recoveryPath -Leaf)
    results    = $results
}
$record | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $runDir 'run.json') -Encoding UTF8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# Fault-injection Run Record')
[void]$md.AppendLine()
[void]$md.AppendLine("- Run: ``$runId``")
[void]$md.AppendLine("- Started (UTC): ``$($startedUtc.ToString('o'))``")
[void]$md.AppendLine("- Scenario: ``$(Split-Path $scenarioPath -Leaf)``")
[void]$md.AppendLine("- Recovery: ``$(Split-Path $recoveryPath -Leaf)``")
[void]$md.AppendLine()
[void]$md.AppendLine('| Checkpoint | Marker seen | Scenario exit | Recovery exit | Verdict | Detail |')
[void]$md.AppendLine('|---|---|---|---|---|---|')
foreach ($result in $results) {
    [void]$md.AppendLine("| $($result.checkpoint) | $($result.marker_seen) | $($result.scenario_exit_code) | $($result.recovery_exit_code) | $($result.recovery.verdict) | $($result.recovery.detail) |")
}
Set-Content -Path (Join-Path $runDir 'run.md') -Value $md.ToString() -Encoding UTF8

Write-Host ''
Write-Host "==> Run record: $(Join-Path $runDir 'run.json')"
Write-Host "==> Markdown:   $(Join-Path $runDir 'run.md')"

$dataLoss = $results | Where-Object { $_.recovery.verdict -eq 'data_loss' }
if ($dataLoss) {
    Write-Warning 'At least one injection point violated a recovery invariant; investigate before proceeding.'
    exit 3
}
$errors = $results | Where-Object { $_.recovery.verdict -eq 'error' }
if ($errors) {
    Write-Warning 'At least one injection point could not be classified; investigate before proceeding.'
    exit 4
}
$killFailures = $results | Where-Object { $_.recovery.verdict -eq 'kill_failed' }
if ($killFailures) {
    Write-Warning 'At least one kill was denied or ineffective; these entries are not valid injections. Rerun in a full-permission environment.'
    exit 5
}
exit 0
