$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrEmpty($env:TEST_TOKEN)) {
    Write-Output 'TEST_TOKEN received: no'
    exit 1
}

Write-Output 'TEST_TOKEN received: yes'
