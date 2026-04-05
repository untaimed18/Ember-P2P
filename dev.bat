@echo off
title Ember P2P - Dev Build

:: Initialize Visual Studio Build Tools environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

:: Add Rust/Cargo to PATH
set PATH=%USERPROFILE%\.cargo\bin;%PATH%

:: Launch Tauri dev mode
cd /d "%~dp0"
npm run tauri dev
