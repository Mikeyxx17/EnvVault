<#
.SYNOPSIS
Run a bounded, auditable fuzz campaign across EnvVault's libFuzzer targets.

.DESCRIPTION
For each target this script:
  1. Runs `cargo +nightly fuzz run` for a bounded duration.
  2. Minimizes the persistent corpus in place (unless -SkipMinimize).
  3. Optionally generates an llvm-cov line-coverage report (unless -SkipCoverage).
  4. Emits a value-free run record (JSON + Markdown) under fuzz/runs/<timestamp>/.

The script never emits, collects, or commits secret values. Generated run
directories and coverage data are git-ignored work products.

.PARAMETER SecondsPerTarget
Seconds to fuzz each target. Default 900.

.PARAMETER MaxLen
Maximum input length passed to libFuzzer. Default 32768.

.PARAMETER Targets
Fuzz targets to run. Defaults to all four.

.PARAMETER SkipMinimize
Do not minimize the persistent fuzz/corpus/<target> directory.

.PARAMETER SkipCoverage
Do not generate line-coverage reports.

.PARAMETER RunsRoot
Directory under the repo root where run records are written. Default fuzz/runs.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 86400)]
    [int]$SecondsPerTarget = 900,

    [ValidateRange(1, 1048576)]
    [int]$MaxLen = 32768,

    [string[]]$Targets = @('vault', 'identity_audit', 'policy_profile', 'dotenv'),

    [switch]$SkipMinimize,

    [switch]$SkipCoverage,

    [string]$RunsRoot = 'fuzz/runs'
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fuzzDir = Join-Path $repoRoot 'fuzz'
$corpusRoot = Join-Path $fuzzDir 'corpus'

foreach ($target in $Targets) {
    $corpusDir = Join-Path $corpusRoot $target
    if (-not (Test-Path $corpusDir)) {
        throw "Corpus directory not found for target '$target': $corpusDir"
    }
}

$onWindows = ($env:OS -eq 'Windows_NT')
if ($onWindows) {
    $asanRuntime = Get-ChildItem 'C:\Program Files\Microsoft Visual Studio' `
        -Recurse -File -Filter 'clang_rt.asan_dynamic-x86_64.dll' `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -like '*\Hostx64\x64' } |
        Select-Object -First 1
    if ($null -eq $asanRuntime) {
        throw 'x64 AddressSanitizer runtime was not found in Visual Studio.'
    }
    $env:PATH = "$($asanRuntime.DirectoryName);$env:PATH"
}

function Get-CorpusCount {
    param([Parameter(Mandatory)][string]$Dir)
    if (-not (Test-Path $Dir)) {
        return 0
    }
    return @(Get-ChildItem $Dir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne '.gitkeep' }).Count
}

Write-Host '==> Building fuzz targets under nightly'
& cargo +nightly fuzz build
if ($LASTEXITCODE -ne 0) {
    throw 'cargo fuzz build failed.'
}

$startedUtc = (Get-Date).ToUniversalTime()
$runId = $startedUtc.ToString('yyyyMMdd-HHmmss')
$runDir = Join-Path (Join-Path $repoRoot $RunsRoot) $runId
$logsDir = Join-Path $runDir 'logs'
$artifactsDir = Join-Path $runDir 'artifacts'
$coverageDir = Join-Path $runDir 'coverage'
foreach ($dir in @($runDir, $logsDir, $artifactsDir, $coverageDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

$rustcVersion = (& rustc +nightly --version).Trim()
$cargoFuzzVersion = (& cargo fuzz --version).Trim()

$results = @()

foreach ($target in $Targets) {
    Write-Host "==> Fuzzing target: $target"

    $logFile = Join-Path $logsDir "$target.log"
    $corpusDir = Join-Path $corpusRoot $target
    $targetArtifactDir = Join-Path $fuzzDir "artifacts/$target"
    $runArtifactDir = Join-Path $artifactsDir $target
    New-Item -ItemType Directory -Force -Path $runArtifactDir | Out-Null

    $corpusBefore = Get-CorpusCount $corpusDir
    $artifactsBefore = @()
    if (Test-Path $targetArtifactDir) {
        $artifactsBefore = @(Get-ChildItem $targetArtifactDir -File | ForEach-Object { $_.Name })
    }

    $output = & cargo +nightly fuzz run $target -- "-max_total_time=$SecondsPerTarget" "-max_len=$MaxLen" 2>&1
    $runExit = $LASTEXITCODE
    $output | Set-Content -Path $logFile -Encoding UTF8

    $newArtifacts = @()
    if (Test-Path $targetArtifactDir) {
        $newArtifacts = @(Get-ChildItem $targetArtifactDir -File |
            Where-Object { $artifactsBefore -notcontains $_.Name })
    }
    foreach ($artifact in $newArtifacts) {
        Copy-Item -LiteralPath $artifact.FullName -Destination $runArtifactDir
    }

    if (-not $SkipMinimize) {
        Write-Host "    Minimizing corpus: $corpusDir"
        & cargo +nightly fuzz cmin $target $corpusDir
        if ($LASTEXITCODE -ne 0) {
            throw "cargo fuzz cmin failed for target '$target'."
        }
    }

    $corpusAfter = Get-CorpusCount $corpusDir

    $coverage = $null
    if (-not $SkipCoverage) {
        try {
            Write-Host "    Generating coverage: $target"
            $coverageLog = Join-Path $logsDir "$target.coverage.log"
            $coverageCapture = @()

            $sysroot = (& rustc +nightly --print sysroot).Trim()
            $llvmTools = Get-ChildItem (Join-Path $sysroot 'lib/rustlib') `
                -Recurse -File -ErrorAction SilentlyContinue
            $llvmCov = $llvmTools | Where-Object { $_.Name -like 'llvm-cov*' } |
                Select-Object -First 1
            $llvmProfdata = $llvmTools | Where-Object { $_.Name -like 'llvm-profdata*' } |
                Select-Object -First 1

            $hostTriple = ''
            $rustcVv = & rustc +nightly -vV 2>&1
            foreach ($line in $rustcVv) {
                if ($line -match '^host:\s+(.+)$') {
                    $hostTriple = $Matches[1].Trim()
                    break
                }
            }

            # Build the coverage-instrumented binary. cargo-fuzz's own corpus
            # execution is deliberately avoided for the real corpus: it expands
            # every corpus file into one argv entry, which exceeds Windows
            # command-line limits for large corpora. A one-seed mini corpus
            # keeps the build step fast and succeeds on every platform.
            $miniDir = Join-Path ([System.IO.Path]::GetTempPath()) `
                "envvault-cov-mini-$target-$PID"
            New-Item -ItemType Directory -Force -Path $miniDir | Out-Null
            $firstSeed = Get-ChildItem $corpusDir -File |
                Where-Object { $_.Name -ne '.gitkeep' } |
                Select-Object -First 1
            if ($null -ne $firstSeed) {
                Copy-Item -LiteralPath $firstSeed.FullName -Destination $miniDir
            }
            $covBuild = & cargo +nightly fuzz coverage $target $miniDir 2>&1
            $coverageCapture += $covBuild
            Remove-Item -LiteralPath $miniDir -Recurse -Force -ErrorAction SilentlyContinue
            # A non-zero exit here is tolerated: the instrumented binary is
            # already built; the real corpus profiling happens below.

            $coverageBin = $null
            $candidateBins = @(
                (Join-Path $repoRoot "target/$hostTriple/coverage/$hostTriple/release/$target"),
                (Join-Path $repoRoot "target/$hostTriple/coverage/$hostTriple/release/$target.exe")
            )
            foreach ($candidate in $candidateBins) {
                if (Test-Path $candidate) {
                    $coverageBin = $candidate
                    break
                }
            }

            if (($null -eq $llvmCov) -or ($null -eq $llvmProfdata) -or ($null -eq $coverageBin)) {
                throw 'Coverage tools or binary were not found; skipping report generation.'
            }

            # Directory-mode profiling: the binary accepts the corpus as one
            # directory argument (-runs=0 executes every input exactly once),
            # so no argv explosion occurs regardless of corpus size.
            $profrawPattern = Join-Path $coverageDir "$target-%p.profraw"
            $previousProfileFile = $env:LLVM_PROFILE_FILE
            $env:LLVM_PROFILE_FILE = $profrawPattern
            $profileOutput = & $coverageBin -runs=0 $corpusDir 2>&1
            $profileExit = $LASTEXITCODE
            $env:LLVM_PROFILE_FILE = $previousProfileFile
            $coverageCapture += $profileOutput
            if ($profileExit -ne 0) {
                throw "coverage profile run exited $profileExit."
            }

            $profdata = Join-Path $fuzzDir "coverage/$target/coverage.profdata"
            New-Item -ItemType Directory -Force -Path (Split-Path $profdata) | Out-Null
            $mergeOutput = & $llvmProfdata.FullName merge -sparse `
                "$coverageDir\$target-*.profraw" -o $profdata 2>&1
            $coverageCapture += $mergeOutput
            if ($LASTEXITCODE -ne 0) {
                throw 'llvm-profdata merge failed.'
            }

            $reportFile = Join-Path $coverageDir "$target.txt"
            $htmlDir = Join-Path $coverageDir "$target-html"

            $rawReport = & $llvmCov.FullName report $coverageBin `
                "-instr-profile=$profdata" `
                '-ignore-filename-regex=registry|toolchains|rustlib' 2>&1
            $coverageCapture += $rawReport
            $report = $rawReport | ForEach-Object {
                ([string]$_) -replace '\x1b\[[0-9;]*m', ''
            }
            $report | Set-Content -Path $reportFile -Encoding UTF8

            & $llvmCov.FullName show $coverageBin `
                "-instr-profile=$profdata" `
                '-ignore-filename-regex=registry|toolchains|rustlib' `
                -format=html "-output-dir=$htmlDir"

            $totalLine = $report |
                Where-Object { $_ -match '^TOTAL' } |
                Select-Object -Last 1
            $coverage = [ordered]@{
                report = "coverage/$target.txt"
                html   = "coverage/$target-html"
                total  = if ($totalLine) { [string]$totalLine } else { 'unavailable' }
            }
            $coverageCapture | Set-Content -Path $coverageLog -Encoding UTF8
        }
        catch {
            $failure = @($coverageCapture) + "ERROR: $($_.Exception.Message)"
            $failure | Set-Content -Path $coverageLog -Encoding UTF8
            Write-Warning "Coverage generation skipped for '$target': $($_.Exception.Message)"
            $coverage = [ordered]@{
                report = $null
                html   = $null
                total  = 'unavailable'
                note   = $_.Exception.Message
            }
        }
    }

    if ($newArtifacts.Count -gt 0) {
        $status = 'artifacts_found'
    }
    elseif ($runExit -ne 0) {
        $status = 'run_failed'
    }
    else {
        $status = 'clean'
    }

    $results += [ordered]@{
        target        = $target
        status        = $status
        run_exit_code = $runExit
        corpus_before = $corpusBefore
        corpus_after  = $corpusAfter
        new_artifacts = @($newArtifacts | ForEach-Object { $_.Name })
        coverage      = $coverage
        log           = "logs/$target.log"
    }
}

$finishedUtc = (Get-Date).ToUniversalTime()

$overall = 'clean'
if ($results | Where-Object { $_.status -eq 'artifacts_found' }) {
    $overall = 'artifacts_found'
}
elseif ($results | Where-Object { $_.status -eq 'run_failed' }) {
    $overall = 'run_failed'
}

$record = [ordered]@{
    schema           = 'envvault-fuzz-run-v1'
    started_at_utc   = $startedUtc.ToString('o')
    finished_at_utc  = $finishedUtc.ToString('o')
    duration_seconds = [int](($finishedUtc - $startedUtc).TotalSeconds)
    toolchain        = $rustcVersion
    cargo_fuzz       = $cargoFuzzVersion
    host             = [ordered]@{
        os   = if ($onWindows) { 'windows' } else { 'non-windows' }
        asan = if ($onWindows) { $asanRuntime.DirectoryName } else { 'n/a' }
    }
    parameters       = [ordered]@{
        seconds_per_target = $SecondsPerTarget
        max_len            = $MaxLen
        targets            = @($Targets)
        minimize           = (-not $SkipMinimize)
        coverage           = (-not $SkipCoverage)
    }
    overall          = $overall
    results          = $results
}

$jsonFile = Join-Path $runDir 'run.json'
$record | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonFile -Encoding UTF8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# EnvVault Fuzz Run Record')
[void]$md.AppendLine()
[void]$md.AppendLine("- Run: ``$runId``")
[void]$md.AppendLine("- Started (UTC): ``$($startedUtc.ToString('o'))``")
[void]$md.AppendLine("- Duration: ``$([int](($finishedUtc - $startedUtc).TotalSeconds))s``")
[void]$md.AppendLine("- Toolchain: ``$rustcVersion``")
[void]$md.AppendLine("- cargo-fuzz: ``$cargoFuzzVersion``")
[void]$md.AppendLine("- Parameters: ``$SecondsPerTarget``s/target, max_len ``$MaxLen``")
[void]$md.AppendLine("- Overall: ``$overall``")
[void]$md.AppendLine()
[void]$md.AppendLine('## Results')
[void]$md.AppendLine()
[void]$md.AppendLine('| Target | Status | Corpus before | Corpus after | New artifacts | Coverage total |')
[void]$md.AppendLine('|---|---|---:|---:|---:|---|')
foreach ($r in $results) {
    $covTotal = if ($r['coverage'] -and $r['coverage']['total']) { $r['coverage']['total'] } else { '-' }
    [void]$md.AppendLine("| $($r['target']) | $($r['status']) | $($r['corpus_before']) | $($r['corpus_after']) | $($r['new_artifacts'].Count) | $covTotal |")
}
[void]$md.AppendLine()
[void]$md.AppendLine('## Notes')
[void]$md.AppendLine()
[void]$md.AppendLine('- "artifacts_found" means libFuzzer produced crash/timeout/OOM artifacts; review them before reuse.')
[void]$md.AppendLine('- Minimized corpus is written in place under `fuzz/corpus/<target>`; review and commit intentionally.')
[void]$md.AppendLine('- Coverage percentages cover the `envvault` crate sources only; third-party code is filtered out.')

Set-Content -Path (Join-Path $runDir 'run.md') -Value $md.ToString() -Encoding UTF8

Write-Host ''
Write-Host "==> Run record: $jsonFile"
Write-Host "==> Markdown:   $(Join-Path $runDir 'run.md')"
Write-Host "==> Overall:    $overall"

if ($overall -ne 'clean') {
    exit 1
}
