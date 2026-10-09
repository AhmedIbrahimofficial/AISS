@echo off
:: ═══════════════════════════════════════════════════════════════════
:: AISS — AI Integrated Security System
:: Single-command launcher.  Double-click or type:  aiss
::
:: Flags:
::   aiss                  Start backend + frontend, open browser
::   aiss --minimized      Start backend hidden, open browser only
::   aiss --backend-only   Start only the backend
::   aiss --frontend-only  Start only the frontend
::   aiss --setup          Create desktop shortcut + register global command
:: ═══════════════════════════════════════════════════════════════════

title AISS — AI Integrated Security System
chcp 65001 >nul 2>&1
set "PYTHONIOENCODING=utf-8"

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "BACKEND=%ROOT%\backend"
set "FRONTEND=%ROOT%\frontend"
set "BACKEND_PORT=8000"
set "FRONTEND_PORT=5173"

:: ── Handle --setup flag ──────────────────────────────────────────────
if /i "%~1"=="--setup" goto :setup

:: ── Python (prefer .venv inside backend) ────────────────────────────
if exist "%BACKEND%\.venv\Scripts\python.exe" (
    set "PYTHON=%BACKEND%\.venv\Scripts\python.exe"
) else (
    set "PYTHON=python"
)

:: Check python is available
"%PYTHON%" --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Python not found.
    echo  Install Python 3.11+ from https://python.org/downloads
    echo  Make sure "Add Python to PATH" is checked during install.
    echo.
    pause
    exit /b 1
)

:: ── Parse flags ───────────────────────────────────────────────────────
set "START_BACKEND=1"
set "START_FRONTEND=1"
set "MINIMIZED=0"
set "OPEN_BROWSER=1"

if /i "%~1"=="--minimized"     set "MINIMIZED=1"
if /i "%~1"=="--backend-only"  set "START_FRONTEND=0" & set "OPEN_BROWSER=0"
if /i "%~1"=="--frontend-only" set "START_BACKEND=0"

:: ── Display banner ───────────────────────────────────────────────────
echo.
echo  ========================================================
echo   AISS — AI Integrated Security System  v2.0.0
echo  ========================================================
echo.

:: ── Start backend ────────────────────────────────────────────────────
if "%START_BACKEND%"=="1" (
    echo  [1] Starting backend on http://localhost:%BACKEND_PORT% ...
    if "%MINIMIZED%"=="1" (
        start "AISS Backend" /min cmd /c "cd /d "%BACKEND%" && "%PYTHON%" -m uvicorn main:app --host 127.0.0.1 --port %BACKEND_PORT%"
    ) else (
        start "AISS Backend" cmd /k "cd /d "%BACKEND%" && "%PYTHON%" -m uvicorn main:app --host 127.0.0.1 --port %BACKEND_PORT%"
    )
)

:: ── Start frontend ───────────────────────────────────────────────────
if "%START_FRONTEND%"=="1" (
    echo  [2] Starting frontend on http://localhost:%FRONTEND_PORT% ...
    if "%MINIMIZED%"=="1" (
        start "AISS Frontend" /min cmd /c "cd /d "%FRONTEND%" && npm run dev -- --host 127.0.0.1 --port %FRONTEND_PORT%"
    ) else (
        start "AISS Frontend" cmd /k "cd /d "%FRONTEND%" && npm run dev -- --host 127.0.0.1 --port %FRONTEND_PORT%"
    )
)

:: ── Wait for backend health + auto-open browser ──────────────────────
if "%OPEN_BROWSER%"=="1" (
    echo.
    echo  Waiting for backend to be ready...
    set "RETRIES=0"
    :wait_loop
    if %RETRIES% GEQ 60 (
        echo  [WARNING] Backend did not respond in 60s. Opening browser anyway.
        goto :open_browser
    )
    timeout /t 1 /nobreak >nul
    curl -s -o nul http://localhost:%BACKEND_PORT%/api/health >nul 2>&1
    if %errorlevel% equ 0 goto :open_browser
    set /a RETRIES+=1
    goto :wait_loop

    :open_browser
    echo.
    echo  Backend ready! Opening dashboard...
    timeout /t 3 /nobreak >nul
    start "" "http://localhost:%FRONTEND_PORT%"
)

echo.
echo  ========================================================
echo   Backend   http://localhost:%BACKEND_PORT%
echo   API Docs  http://localhost:%BACKEND_PORT%/docs
echo   Frontend  http://localhost:%FRONTEND_PORT%
echo  ========================================================
echo.
echo  Close the backend/frontend windows to stop AISS.
if "%MINIMIZED%"=="0" pause
exit /b 0

:: ═══════════════════════════════════════════════════════════════════
:: --setup: Create desktop shortcut and register global command
:: ═══════════════════════════════════════════════════════════════════
:setup
echo.
echo  AISS Setup — Creating shortcuts and registering command...
echo.

set "DESKTOP=%USERPROFILE%\Desktop"
set "SHORTCUT=%DESKTOP%\AISS.lnk"

powershell -NoProfile -Command ^
  "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT%'); $s.TargetPath = '%ROOT%\aiss.bat'; $s.WorkingDirectory = '%ROOT%'; $s.IconLocation = 'shell32.dll,14'; $s.Description = 'AISS - AI Integrated Security System'; $s.Save()"

if exist "%SHORTCUT%" (
    echo  [OK] Desktop shortcut created: %SHORTCUT%
) else (
    echo  [WARN] Could not create desktop shortcut.
)

set "STARTMENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs"
powershell -NoProfile -Command ^
  "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%STARTMENU%\AISS.lnk'); $s.TargetPath = '%ROOT%\aiss.bat'; $s.WorkingDirectory = '%ROOT%'; $s.IconLocation = 'shell32.dll,14'; $s.Description = 'AISS - AI Integrated Security System'; $s.Save()"

echo  [OK] Start Menu shortcut created.

echo.
echo  Registering 'aiss' command globally...
setx AISS_HOME "%ROOT%" >nul 2>&1

echo %PATH% | findstr /i /c:"%ROOT%" >nul 2>&1
if %errorlevel% equ 0 (
    echo  [OK] AISS directory already in PATH.
) else (
    for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "CURRENT_PATH=%%b"
    echo %CURRENT_PATH% | findstr /i /c:"%ROOT%" >nul 2>&1
    if %errorlevel% equ 0 (
        echo  [OK] Already in PATH.
    ) else (
        setx Path "%CURRENT_PATH%;%ROOT%" >nul 2>&1
        echo  [OK] Added %ROOT% to user PATH.
        echo  [INFO] Open a NEW terminal for 'aiss' command to work.
    )
)

echo.
echo  ========================================================
echo   Setup complete!
echo   Desktop shortcut: AISS
echo   Global command:   aiss  (in new terminals)
echo  ========================================================
echo.
pause
exit /b 0
