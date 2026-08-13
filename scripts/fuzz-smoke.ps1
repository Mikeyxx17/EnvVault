param(
    [ValidateRange(1, 3600)]
    [int]$SecondsPerTarget = 15
)

$ErrorActionPreference = 'Stop'

$asanRuntime = Get-ChildItem 'C:\Program Files\Microsoft Visual Studio' `
    -Recurse `
    -File `
    -Filter 'clang_rt.asan_dynamic-x86_64.dll' `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DirectoryName -like '*\Hostx64\x64' } |
    Select-Object -First 1

if ($null -eq $asanRuntime) {
    throw 'x64 AddressSanitizer runtime was not found in Visual Studio.'
}

$env:PATH = "$($asanRuntime.DirectoryName);$env:PATH"
$targets = @('vault', 'identity_audit', 'policy_profile', 'dotenv')

foreach ($target in $targets) {
    cargo +nightly fuzz run $target -- "-max_total_time=$SecondsPerTarget" '-max_len=32768'
    if ($LASTEXITCODE -ne 0) {
        throw "Fuzz target failed: $target"
    }
}
