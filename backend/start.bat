@echo off
chcp 65001 >nul 2>&1
title AISS — Backend
setlocal enabledelayedexpansion
color 0A
cls

echo.
echo   +================================================+
echo   ^|   A I S S  -  AI Integrated Security System   ^|
echo   ^|   Version 2.0.0  ^|  FastAPI + OpenRouter AI  ^|
echo   +================================================+
echo.

set "BACKEND_DIR=%~dp0"
if "%BACKEND_DIR:~-1%"=="\" set "BACKEND_DIR=%BACKEND_DIR:~0,-1%"
set "ROOT_DIR=%BACKEND_DIR%\.."
set "FRONTEND_DIR=%ROOT_DIR%\frontend"

:: ── Python: prefer .venv ──────────────────────────────────────────────────────
if exist "%BACKEND_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON=%BACKEND_DIR%\.venv\Scripts\python.exe"
) else (
    set "PYTHON=python"
)

:: ── Step 1: Python check ──────────────────────────────────────────────────────
echo   [1/4]  Checking Python...
"%PYTHON%" --version >nul 2>&1
if %errorlevel% neq 0 (
    echo          [ERROR] Python 3.11+ not found.
    echo          Download: https://python.org/downloads
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('"%PYTHON%" --version 2^>^&1') do echo          [OK] %%v

:: ── Step 2: Python deps ──────────────────────────────────────────────────────
echo   [2/4]  Checking Python dependencies...
"%PYTHON%" -m pip install fastapi uvicorn sqlalchemy aiosqlite python-jose argon2-cffi pydantic python-dotenv -q --disable-pip-version-check >nul 2>&1
echo          [OK] Core dependencies ready

:: ── Step 3: .env check ───────────────────────────────────────────────────────
echo   [3/4]  Checking config...
if not exist "%BACKEND_DIR%\.env" (
    copy "%BACKEND_DIR%\.env.example" "%BACKEND_DIR%\.env" >nul 2>&1
    echo          [OK] .env created from .env.example
) else (
    echo          [OK] .env found
)

:: ── Step 4: Frontend (if present) ────────────────────────────────────────────
echo   [4/4]  Starting frontend...
if exist "%FRONTEND_DIR%\package.json" (
    start "AISS Frontend" /min cmd /c "cd /d "%FRONTEND_DIR%" && npm run dev -- --host 127.0.0.1 --port 5173 > nul 2>&1"
    echo          [OK] Frontend starting at http://localhost:5173
) else (
    echo          [WARN] Frontend not found at %FRONTEND_DIR%
)

:: ── Open browser after 20s ────────────────────────────────────────────────────
start /min cmd /c "timeout /t 20 >nul 2>&1 && start "" http://localhost:5173"

echo.
echo   +================================================+
echo   ^|   AISS IS RUNNING                             ^|
echo   ^|                                               ^|
echo   ^|   Dashboard : http://localhost:5173           ^|
echo   ^|   API       : http://localhost:8000           ^|
echo   ^|   API Docs  : http://localhost:8000/docs      ^|
echo   ^|                                               ^|
echo   ^|   Press Ctrl+C to stop                       ^|
echo   +================================================+
echo.

:: ── Backend starts here (keeps terminal alive) ────────────────────────────────
cd /d "%BACKEND_DIR%"
"%PYTHON%" -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
