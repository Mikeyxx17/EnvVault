param(
    [switch]$IncludeFuzz,
    [switch]$IncludeWindowsCredentialStore,
    [switch]$Release,
    [ValidateRange(1, 3600)]
    [int]$SecondsPerFuzzTarget = 15
)

$ErrorActionPreference = 'Stop'

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$Description,
        [Parameter(Mandatory)]
        [scriptblock]$Command
    )

    Write-Host "==> $Description"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Security check failed: $Description"
    }
}

Invoke-Checked 'Locked dependency vulnerability audit' { cargo audit }
Invoke-Checked 'License, source, ban, and advisory policy' { cargo deny check }
Invoke-Checked 'Strict linting for all targets and features' {
    cargo clippy --workspace --all-targets --all-features -- -D warnings
}
Invoke-Checked 'Debug tests for all features' { cargo test --workspace --all-features --locked }

if ($Release) {
    Invoke-Checked 'Release tests for all features' {
        cargo test --workspace --all-features --locked --release
    }
}

if ($IncludeWindowsCredentialStore) {
    if (-not $IsWindows) {
        throw 'The real credential-store lifecycle gate is currently available only on Windows.'
    }
    Invoke-Checked 'Real Windows Credential Manager lifecycle' {
        cargo test --workspace --all-features `
            real_windows_credential_manager_supports_the_full_machine_unlock_lifecycle `
            -- --ignored
    }
}

if ($IncludeFuzz) {
    Invoke-Checked 'Build fuzz targets under nightly' { cargo +nightly fuzz build }
    Invoke-Checked 'AddressSanitizer fuzz smoke' {
        & "$PSScriptRoot\fuzz-smoke.ps1" -SecondsPerTarget $SecondsPerFuzzTarget
    }
}
