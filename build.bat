@echo off
title Ember P2P - Production Build

:: Initialize Visual Studio Build Tools environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

:: Add Rust/Cargo to PATH
set PATH=%USERPROFILE%\.cargo\bin;%PATH%

:: Build production release
cd /d "%~dp0"
npm run tauri build

echo.
echo ========================================
echo  Build complete! Installers are located in:
echo  src-tauri\target\release\bundle\nsis\
echo  src-tauri\target\release\bundle\msi\
echo ========================================
echo.
pause
