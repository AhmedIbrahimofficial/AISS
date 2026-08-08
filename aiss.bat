@echo off
:: ═══════════════════════════════════════════════════════════════════
:: AISS — Full Stack Launcher
:: Just type:  aiss   from this folder to start everything
:: ═══════════════════════════════════════════════════════════════════

title AISS — Starting...
chcp 65001 >nul 2>&1

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "BACKEND=%ROOT%\aiss backend"
set "FRONTEND=%ROOT%\frontend"

:: ── Python (prefer venv) ─────────────────────────────────────────
if exist "%BACKEND%\.venv\Scripts\python.exe" (
    set "PYTHON=%BACKEND%\.venv\Scripts\python.exe"
) else (
    set "PYTHON=python"
)

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║   AISS — AI Integrated Security System       ║
echo  ╚══════════════════════════════════════════════╝
echo.
echo  [1/2] Starting backend on http://localhost:8000 ...
start "AISS Backend" cmd /k "cd /d "%BACKEND%" && "%PYTHON%" main.py"

echo  [2/2] Starting frontend on http://localhost:8081 ...
start "AISS Frontend" cmd /k "cd /d "%FRONTEND%" && npm run dev"

echo.
echo  ✅  Both services are starting in separate windows.
echo.
echo  Backend  →  http://localhost:8000
echo  API Docs →  http://localhost:8000/docs
echo  Frontend →  http://localhost:8081
echo.
echo  Close this window or press Ctrl+C to stop watching.
pause
