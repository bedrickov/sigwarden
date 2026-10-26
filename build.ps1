param (
    [switch]$Test,
    [switch]$Clean,
    [string]$Config = "release"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$env:PATH = "$env:USERPROFILE\.cargo\bin;" + $env:PATH
$env:CARGO_TARGET_DIR = "$env:TEMP\sigwarden_target"

if ($Clean) {
    if (Test-Path $env:CARGO_TARGET_DIR) {
        Write-Host "Cleaning $env:CARGO_TARGET_DIR..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $env:CARGO_TARGET_DIR
    }
    Write-Host "Clean complete." -ForegroundColor Green
    exit 0
}

Write-Host "=== SigWarden Build Pipeline ===" -ForegroundColor Cyan

if ($Config -eq "release") {
    Write-Host "Compiling binaries (Release)..." -ForegroundColor DarkGray
    cargo build --release
    $BinPath = Join-Path $env:CARGO_TARGET_DIR "release\sigwarden.exe"
} else {
    Write-Host "Compiling binaries (Debug)..." -ForegroundColor DarkGray
    cargo build
    $BinPath = Join-Path $env:CARGO_TARGET_DIR "debug\sigwarden.exe"
}

# Copy compiled binary to project root/bin
$BinDir = Join-Path $ProjectRoot "bin"
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir | Out-Null
}
Copy-Item $BinPath (Join-Path $BinDir "sigwarden.exe") -Force

Write-Host "Build finished successfully! Binary copied to bin\sigwarden.exe" -ForegroundColor Green

if ($Test) {
    Write-Host "`nRunning Test Suite..." -ForegroundColor Cyan
    cargo test
}
