@echo off
:: ═══════════════════════════════════════════════════════════════════
:: AISS — AI Intelligent Security System
:: Single-command launcher.  Just type:  aiss
::
:: Flags:
::   aiss                 Start normally (check & install updates, then launch)
::   aiss --wizard        Re-run configuration wizard
::   aiss --reinstall     Force reinstall all packages
::   aiss --install-only  Install/update without starting the server
::   aiss --no-wizard     Skip configuration questions
::   aiss --no-start      Same as --install-only
:: ═══════════════════════════════════════════════════════════════════

title AISS — AI Intelligent Security System
chcp 65001 >nul 2>&1
set "PYTHONIOENCODING=utf-8"

set "AISS_DIR=%~dp0"
if "%AISS_DIR:~-1%"=="\" set "AISS_DIR=%AISS_DIR:~0,-1%"

:: Prefer venv python, fall back to system python
if exist "%AISS_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON=%AISS_DIR%\.venv\Scripts\python.exe"
) else if exist "%AISS_DIR%\venv\Scripts\python.exe" (
    set "PYTHON=%AISS_DIR%\venv\Scripts\python.exe"
) else (
    set "PYTHON=python"
)

:: Check python is available
"%PYTHON%" --version >nul 2>&1
if %errorlevel% neq 0 (
    where python >nul 2>&1
    if %errorlevel% neq 0 (
        echo.
        echo  [ERROR] Python not found.
        echo  Install Python 3.11+ from https://python.org/downloads
        echo  Make sure "Add Python to PATH" is checked during install.
        echo.
        pause
        exit /b 1
    )
    set "PYTHON=python"
)

:: Launch AISS with all passed arguments
cd /d "%AISS_DIR%"
"%PYTHON%" "%AISS_DIR%\aiss.py" %*
