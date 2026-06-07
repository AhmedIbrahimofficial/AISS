@echo off
chcp 65001 >nul 2>&1
title AISS - AI Integrated Security System
setlocal enabledelayedexpansion

:: ════════════════════════════════════════════════════════════════════
::  STEP 1 — BANNER
:: ════════════════════════════════════════════════════════════════════
color 0B
cls
echo.
echo    ___    ___   ___   ___
echo   /  /\  /  /\ /  /\ /  /\
echo  /  /:/ /  /:/ \  \:\\  \:\
echo /__/:/ /__/:/   \  \:\\  \:\
echo \  \:\ \  \:\   /  /:/  /  /
echo  \  \:\ \  \:\ /__/:/  /__/:/ 
echo   \__\/  \__\/ \__\/   \__\/
echo.
echo    A  I  S  S   -   v 1 . 0 . 0
echo.
color 0A
echo              AI Integrated Security System
echo         Version 1.0.0  ^|  FastAPI + Claude AI
echo    ================================================
echo.

:: ════════════════════════════════════════════════════════════════════
::  STEP 2 — PYTHON CHECK
:: ════════════════════════════════════════════════════════════════════
color 0B
echo   [1/5]  Checking Python...
color 0A
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0E
    echo          [AISS] Python not found. Installing automatically...
    color 0A
    winget install Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements >nul 2>&1
    call refreshenv >nul 2>&1
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        color 0E
        echo          [WARN] Python installed. Please restart this script.
        color 0A
        timeout /t 3 >nul
    ) else (
        echo          [OK] Python installed successfully
    )
) else (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo          [OK] %%v found
)
echo.

:: ════════════════════════════════════════════════════════════════════
::  STEP 3 — DEPENDENCIES
:: ════════════════════════════════════════════════════════════════════
color 0B
echo   [2/5]  Checking dependencies...
color 0A
pip install -r requirements.txt -q --disable-pip-version-check --dry-run >nul 2>&1
if %errorlevel% equ 0 (
    echo          [OK] All dependencies already installed
) else (
    color 0E
    echo          Installing missing packages...
    color 0A
    pip install -r requirements.txt -q --disable-pip-version-check >nul 2>&1
    if %errorlevel% neq 0 (
        pip install -r requirements.txt -q --disable-pip-version-check >nul 2>&1
    )
    echo          [OK] Dependencies ready
)
echo.

:: ════════════════════════════════════════════════════════════════════
::  STEP 4 — .ENV FILE
:: ════════════════════════════════════════════════════════════════════
color 0B
echo   [3/5]  Checking config...
color 0A
if not exist ".env" (
    (
        echo DATABASE_URL=postgresql://postgres:password@localhost:5432/aiss
        echo SECRET_KEY=aiss-secret-key-change-in-production
        echo ANTHROPIC_API_KEY=your-anthropic-key-here
        echo ALLOWED_ORIGINS=http://localhost:3000
    ) > .env
    echo          [OK] Config created automatically
) else (
    echo          [OK] Config found
)
echo.

:: ════════════════════════════════════════════════════════════════════
::  STEP 5 — BOOT PERMISSION (ONE TIME ONLY)
:: ════════════════════════════════════════════════════════════════════
color 0B
echo   [4/5]  Checking startup preference...
color 0A
reg query "HKCU\Software\AISS" /v "AutoStart" >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    color 0B
    echo   ^+------------------------------------------^+
    echo   ^|   AISS Boot Permission                   ^|
    echo   ^|                                          ^|
    echo   ^|   Allow AISS to start automatically      ^|
    echo   ^|   when Windows boots?                    ^|
    echo   ^|                                          ^|
    echo   ^|   Y = Yes, start on boot                 ^|
    echo   ^|   N = No, manual start only              ^|
    echo   ^+------------------------------------------^+
    echo.
    color 0A
    choice /c YN /n /m "          Your choice (Y/N): "
    if errorlevel 2 (
        reg add "HKCU\Software\AISS" /v "AutoStart" /t REG_SZ /d "no" /f >nul 2>&1
        echo          [OK] Manual start mode selected
    ) else (
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AISS" /t REG_SZ /d "%~f0" /f >nul 2>&1
        reg add "HKCU\Software\AISS" /v "AutoStart" /t REG_SZ /d "yes" /f >nul 2>&1
        echo          [OK] AISS will start automatically on boot
    )
) else (
    echo          [OK] Startup preference already set
)
echo.

:: ════════════════════════════════════════════════════════════════════
::  STEP 6 — LAUNCH
:: ════════════════════════════════════════════════════════════════════
color 0B
echo   [5/5]  Launching AISS...
echo.
color 0A
echo   ^+════════════════════════════════════════════════^+
echo   ^|        AISS IS NOW STARTING...                ^|
echo   ^|                                               ^|
echo   ^|   SERVER    :  http://localhost:8000          ^|
echo   ^|   API DOCS  :  http://localhost:8000/docs     ^|
echo   ^|   WEBSOCKET :  ws://localhost:8000/ws         ^|
echo   ^|                                               ^|
echo   ^|   Press Ctrl+C to stop AISS                  ^|
echo   ^+════════════════════════════════════════════════^+
echo.

::  Open Live Monitor in second terminal window
start cmd /k "title AISS Live Monitor && color 0A && python monitor.py"

::  Open GUI Threat Monitor (click-based resolve)
start pythonw gui_monitor.py

color 0B
echo   Starting backend server...
echo   ════════════════════════════════════════════════
color 0A
echo.

python main.py

:: ════════════════════════════════════════════════════════════════════
::  STEP 7 — SHUTDOWN
:: ════════════════════════════════════════════════════════════════════
echo.
color 0C
echo   ════════════════════════════════════════════════
echo      [STOPPED] AISS Shutdown Complete.
echo   ════════════════════════════════════════════════
color 0A
