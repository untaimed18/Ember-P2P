@echo off
setlocal

:: ── Configuration ──────────────────────────────────────────────
set "GITHUB_OWNER=untaimed18"
set "GITHUB_REPO=Ember-KAD"
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
echo   Upload to GitHub Release "v%VERSION%"
echo   Tag the release as: v%VERSION%
echo ============================================================
echo.

endlocal
