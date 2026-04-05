@echo off
setlocal

echo.
echo ============================================================
echo   Reset main branch to a single "Initial commit"
echo ============================================================
echo.
echo WARNING: This will force-push to origin/main, destroying
echo          all existing commit history on the main branch.
echo.
set /p "CONFIRM=Type YES to continue: "
if /I not "%CONFIRM%"=="YES" (
    echo Aborted.
    exit /b 1
)
echo.

:: ── Remember current branch ──────────────────────────────────
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set "ORIGINAL_BRANCH=%%b"

:: ── Switch to main ───────────────────────────────────────────
git checkout main
if errorlevel 1 (
    echo ERROR: Could not checkout main.
    exit /b 1
)

:: ── Create orphan branch (no parents) ────────────────────────
git checkout --orphan temp-fresh-main
if errorlevel 1 (
    echo ERROR: Could not create orphan branch.
    git checkout "%ORIGINAL_BRANCH%"
    exit /b 1
)

:: ── Stage everything and commit ──────────────────────────────
git add -A
git commit -m "Initial commit"
if errorlevel 1 (
    echo ERROR: Commit failed.
    git checkout "%ORIGINAL_BRANCH%"
    git branch -D temp-fresh-main 2>nul
    exit /b 1
)

:: ── Replace main with the single-commit branch ───────────────
git branch -D main
git branch -m main

:: ── Force push ───────────────────────────────────────────────
echo.
echo Pushing to origin/main ...
git push --force origin main
if errorlevel 1 (
    echo ERROR: Force push failed.
    exit /b 1
)

:: ── Return to original branch if it still exists ─────────────
if /I not "%ORIGINAL_BRANCH%"=="main" (
    git checkout "%ORIGINAL_BRANCH%" 2>nul
)

echo.
echo ============================================================
echo   Done. main branch now has a single "Initial commit".
echo ============================================================
echo.

endlocal
