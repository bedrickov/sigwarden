@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo        Building SigWarden (Rust Security Auditor)
echo ========================================================

set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
set "CARGO_TARGET_DIR=%TEMP%\sigwarden_target"

if "%1"=="clean" (
    echo Cleaning target directory...
    if exist "%CARGO_TARGET_DIR%" rmdir /s /q "%CARGO_TARGET_DIR%"
    if exist bin rmdir /s /q bin
    echo Clean complete.
    exit /b 0
)

cargo build --release
if %errorlevel% neq 0 (
    echo Build failed.
    exit /b 1
)

if not exist bin mkdir bin
copy /y "%CARGO_TARGET_DIR%\release\sigwarden.exe" bin\sigwarden.exe >nul

echo Build succeeded! Binary located at bin\sigwarden.exe
if "%1"=="test" (
    echo Running unit and integration tests...
    cargo test
)
