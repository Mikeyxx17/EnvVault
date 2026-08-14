<#
.SYNOPSIS
One-step installer: copies all pending-work files into the EnvVault repo.

.DESCRIPTION
This script copies the 16 final files (items 01-08: ADR 0015, anchor protocol
client, adversarial tests, fault-injection harness, runtime matrix, review
checklist, and the two fixes) from the `files` directory next to this script
into the repository, overwriting the corresponding tracked files. It does not
require git or patches. All content is value-free.

Usage (from anywhere):
    powershell -ExecutionPolicy Bypass -File "D:\vscode\EnvVault\pending-work\apply-all\apply-all.ps1"

Options:
    -Verify   After copying, run `cargo test --workspace --all-features`.
    -Commit   After copying, stage and commit the changes with git.
#>

[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [switch]$Verify,
    [switch]$Commit
)

$ErrorActionPreference = 'Continue'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $RepoRoot) {
    # apply-all.ps1 lives at <repo>\pending-work\apply-all\apply-all.ps1
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $scriptDir)
}
$RepoRoot = (Resolve-Path $RepoRoot).Path
$filesDir = Join-Path $scriptDir 'files'
if (-not (Test-Path $filesDir)) {
    Write-Host "ERROR: files bundle not found: $filesDir" -ForegroundColor Red
    exit 1
}

Write-Host "==> Installing pending-work files into: $RepoRoot" -ForegroundColor Cyan

$failed = @()
$ok = 0
$sourceFiles = Get-ChildItem $filesDir -Recurse -File
foreach ($source in $sourceFiles) {
    $relative = $source.FullName.Substring($filesDir.Length).TrimStart('\', '/')
    $destination = Join-Path $RepoRoot $relative
    try {
        New-Item -ItemType Directory -Force -Path (Split-Path $destination) | Out-Null
        Copy-Item -LiteralPath $source.FullName -Destination $destination -Force -ErrorAction Stop
        Write-Host "  OK   $relative" -ForegroundColor Green
        $ok++
    }
    catch {
        Write-Host "  FAIL $relative : $($_.Exception.Message)" -ForegroundColor Red
        $failed += $relative
    }
}

Write-Host ''
Write-Host "==> Copied: $ok / $($sourceFiles.Count) files" -ForegroundColor Cyan

if ($failed.Count -gt 0) {
    Write-Host ''
    Write-Host 'Some files could not be copied. Fix one of these and run this script again:' -ForegroundColor Yellow
    Write-Host '  1. Open PowerShell as Administrator, or'
    Write-Host '  2. Run PowerShell as the account that owns the repository folders, or'
    Write-Host '  3. Take ownership: takeown /F D:\vscode\EnvVault /R /D Y   (in an elevated prompt)'
    exit 2
}

if ($Verify) {
    Write-Host ''
    Write-Host '==> Running cargo tests (this takes a few minutes)...' -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        cargo test --workspace --all-features
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'WARNING: cargo test reported failures.' -ForegroundColor Yellow
        }
    }
    finally {
        Pop-Location
    }
}

if ($Commit) {
    Write-Host ''
    Write-Host '==> Committing with git...' -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        $safe = "-c", "safe.directory=$RepoRoot"
        $identity = @()
        $name = & git $safe config user.name 2>$null
        $email = & git $safe config user.email 2>$null
        if (-not $name) { $identity += '-c', 'user.name=envvault-adopter' }
        if (-not $email) { $identity += '-c', 'user.email=adopter@envvault.local' }
        & git $safe add -A
        & git $safe @identity commit -m 'Adopt pending-work items 01-08'
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'git commit failed; the changes are staged. You can commit later with: git commit -m "..."' -ForegroundColor Yellow
        }
    }
    finally {
        Pop-Location
    }
}

Write-Host ''
Write-Host '==> Done. Next steps:' -ForegroundColor Cyan
Write-Host '    cargo test --workspace --all-features'
Write-Host '    .\scripts\security-check.ps1'
Write-Host '    git status'
