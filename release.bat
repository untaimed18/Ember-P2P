@echo off
setlocal

:: ── Configuration ──────────────────────────────────────────────
set "BUNDLE_DIR=%~dp0src-tauri\target\release\bundle\nsis"
set "MSI_DIR=%~dp0src-tauri\target\release\bundle\msi"
set "OUT_DIR=%~dp0release-out"

:: ── Read version from package.json ─────────────────────────────
for /f "tokens=2 delims=:, " %%a in ('findstr /c:"\"version\"" "%~dp0package.json"') do (
    set "RAW_VER=%%~a"
    goto :got_version
)
:got_version
set "VERSION=%RAW_VER%"
if "%VERSION%"=="" (
    echo ERROR: Could not read version from package.json
    exit /b 1
)

echo.
echo ============================================================
echo   Ember Release Builder  -  v%VERSION%
echo ============================================================
echo.

:: ── Clean old artifacts ───────────────────────────────────────
if exist "%BUNDLE_DIR%" del /q "%BUNDLE_DIR%\*.exe" 2>nul

:: ── Build ──────────────────────────────────────────────────────
echo Building Ember v%VERSION% ...
echo.
call npm run tauri build
if errorlevel 1 (
    echo.
    echo ERROR: Build failed.
    exit /b 1
)

:: ── Locate artifacts ───────────────────────────────────────────
set "NSIS_EXE="
set "MSI_FILE="
for %%f in ("%BUNDLE_DIR%\*_x64-setup.exe") do set "NSIS_EXE=%%f"
for %%f in ("%MSI_DIR%\*.msi") do set "MSI_FILE=%%f"

if "%NSIS_EXE%"=="" (
    echo.
    echo ERROR: No installer found in %BUNDLE_DIR%
    dir /b "%BUNDLE_DIR%" 2>nul
    exit /b 1
)

:: ── Copy artifacts to output folder ────────────────────────────
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
copy "%NSIS_EXE%" "%OUT_DIR%\" >nul
if not "%MSI_FILE%"=="" copy "%MSI_FILE%" "%OUT_DIR%\" >nul

:: ── Done ───────────────────────────────────────────────────────
echo.
echo ============================================================
echo   Build complete!
echo.
echo   Output folder:  %OUT_DIR%
echo.
echo   Artifacts:
for %%f in ("%NSIS_EXE%") do echo     - %%~nxf
if not "%MSI_FILE%"=="" for %%f in ("%MSI_FILE%") do echo     - %%~nxf
echo.
echo   These are for local testing only. Do NOT upload them to a GitHub
echo   Release: a manual upload has no signed latest.json carrying the
echo   security_epoch and per-platform target/sha256/size the updater
echo   requires, so every installed client's update check would fail.
echo.
echo   To publish, push the version tag and let the workflow sign it. The
echo   version must already be bumped with "npm run bump-version -- X.Y.Z"
echo   and committed, then:
echo     git tag v%VERSION% ^&^& git push origin main --tags
echo.
echo   .github\workflows\release.yml then verifies release policy, builds
echo   and signs the installers, hardens latest.json via
echo   scripts\harden-update-manifest.mjs, signs that too, and leaves a
echo   DRAFT release. Review it and press Publish to hand the update to
echo   installed clients.
echo ============================================================
echo.

endlocal
