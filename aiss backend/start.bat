@echo off
chcp 65001 >nul 2>&1
title AISS
setlocal enabledelayedexpansion
color 0A
cls

echo.
echo   +================================================+
echo   ^|   A I S S  -  AI Integrated Security System   ^|
echo   ^|   Version 1.0.0  ^|  FastAPI + Claude AI       ^|
echo   +================================================+
echo.

:: ── Step 1: Python ───────────────────────────────────────────────────
echo   [1/4]  Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo          [ERROR] Python not found. Install Python 3.10+
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo          [OK] %%v

:: ── Step 2: Python deps ──────────────────────────────────────────────
echo   [2/4]  Checking Python dependencies...
pip install -r requirements.txt -q --disable-pip-version-check >nul 2>&1
echo          [OK] Dependencies ready

:: ── Step 3: .env ─────────────────────────────────────────────────────
echo   [3/4]  Checking config...
if not exist ".env" (
    (
        echo DATABASE_URL=sqlite+aiosqlite:///./logs/cybersecurity.db
        echo SECRET_KEY=aiss-secret-key-change-this
        echo ANTHROPIC_API_KEY=your-key-here
        echo ALLOWED_ORIGINS=http://localhost:3000
    ) > .env
    echo          [OK] Config created
) else (
    echo          [OK] Config found
)

:: ── Step 4: Frontend ─────────────────────────────────────────────────
echo   [4/4]  Starting frontend dashboard...

set "FRONTEND_DIR=d:\aiss"
if not exist "%FRONTEND_DIR%\package.json" set "FRONTEND_DIR=%~dp0frontend"

if exist "%FRONTEND_DIR%\package.json" (
    :: Start frontend silently in background — no visible terminal
    start /min cmd /c "cd /d "%FRONTEND_DIR%" && set NODE_OPTIONS=--max-old-space-size=2048 && npm run dev > nul 2>&1"
    echo          [OK] Frontend starting in background...
) else (
    echo          [WARN] Frontend not found at %FRONTEND_DIR%
)

:: ── Open browser after 25s (Next.js needs time to compile) ───────────
start /min cmd /c "timeout /t 25 >nul 2>&1 && start "" http://localhost:3000/monitor"

echo.
echo   +================================================+
echo   ^|   AISS IS RUNNING                             ^|
echo   ^|                                               ^|
echo   ^|   Dashboard : http://localhost:3000/monitor   ^|
echo   ^|   API       : http://localhost:8000           ^|
echo   ^|                                               ^|
echo   ^|   Browser opens in ~25 seconds                ^|
echo   ^|   Press Ctrl+C to stop everything             ^|
echo   +================================================+
echo.

:: ── Backend starts here (keeps this terminal alive) ──────────────────
python main.py
