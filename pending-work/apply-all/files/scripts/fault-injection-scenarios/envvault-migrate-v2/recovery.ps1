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
    @{ verdict = $Verdict; detail = $Detail } | ConvertTo-Json -Compress
    exit $ExitCode
}

# `audit list` requires exact `read_audit` Owner authorization and only emits
# value-free fields; a non-zero exit means the chain failed verification
# (acceptable fail-closed) or the Vault refuses to open.
& envvault --vault $vault audit list *> (Join-Path $env:FAULT_WORK_ROOT 'recovery-audit-list.log')
$exit = $LASTEXITCODE
if ($exit -eq 0) {
    Emit 'recovered' 'audit chain verified after restart' 0
}
Emit 'fail_closed' "audit list failed with exit code $exit; V1 chain remains authoritative until a safe retry" 2
