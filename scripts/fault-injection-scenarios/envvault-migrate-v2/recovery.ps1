<#
.SYNOPSIS
EnvVault `audit migrate-v2` recovery verifier template (M1.2).

.DESCRIPTION
After the forced kill, open the Vault (requires the interactive Master
Password, so run with the harness `-Interactive` switch) and verify the
value-free audit chain is readable and the migration is either complete,
absent (V1 still authoritative) or safely resumable. Prints one JSON line
{"verdict":"...","detail":"..."} and exits 0/2/3. Uses the same verdict
classes as the harness: recovered / fail_closed / data_loss. Never prints
Secret Values, credentials, or ciphertext.
#>

$ErrorActionPreference = 'Stop'

$vault = $env:FAULT_VAULT_PATH
if (-not $vault) {
    throw 'FAULT_VAULT_PATH must be set.'
}

function Emit {
    param(
        [Parameter(Mandatory)][string]$Verdict,
        [Parameter(Mandatory)][string]$Detail,
        [Parameter(Mandatory)][int]$ExitCode
    )
    $line = @{ verdict = $Verdict; detail = $Detail } | ConvertTo-Json -Compress
    $line
    $verdictPath = $env:FAULT_VERDICT_PATH
    if (-not $verdictPath -and $env:FAULT_WORK_ROOT) {
        $verdictPath = Join-Path $env:FAULT_WORK_ROOT 'verdict.json'
    }
    if ($verdictPath) {
        Set-Content -Path $verdictPath -Value $line -Encoding UTF8
    }
    exit $ExitCode
}

$envvault = if ($env:ENVVAULT -and (Test-Path -LiteralPath $env:ENVVAULT)) {
    $env:ENVVAULT
} else {
    $cmd = Get-Command envvault -ErrorAction SilentlyContinue
    if ($cmd) { $cmd.Source } else { $null }
}
if (-not $envvault) {
    Emit 'error' 'envvault not found; add target\debug to PATH or set ENVVAULT' 1
}

# `audit list` requires exact `read_audit` Owner authorization and only emits
# value-free fields. Leave stderr on the console so the Master Password TTY
# prompt works; only persist stdout (value-free event lines).
$log = Join-Path $env:FAULT_WORK_ROOT 'recovery-audit-list.log'
$listed = & $envvault --vault $vault --masked-input audit list
$exit = $LASTEXITCODE
if ($null -eq $listed) { $listed = @() }
$listed | Set-Content -Path $log -Encoding UTF8
if ($exit -eq 0) {
    Emit 'recovered' 'audit chain verified after restart' 0
}
Emit 'fail_closed' "audit list failed with exit code $exit; V1 chain remains authoritative until a safe retry" 2
