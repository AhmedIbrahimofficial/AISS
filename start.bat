@echo off
chcp 65001 >nul
cls

:: Set project directory to wherever this bat file is
cd /d "%~dp0"

echo.
echo  [92m
echo   ██████╗██╗   ██╗██████╗ ███████╗██████╗
echo  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
echo  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
echo  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
echo  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
echo   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
echo  [0m
echo  [96m        ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗[0m
echo  [96m        ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║[0m
echo  [96m        ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║[0m
echo  [96m        ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║[0m
echo  [96m        ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗[0m
echo  [96m        ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝[0m
echo.
echo  [93m        AI-Powered Cybersecurity Threat Detection Platform[0m
echo  [90m        =================================================[0m
echo.
timeout /t 2 >nul

:: ── Step 1: Smart dependency check ───────────────────────────────────
echo  [97m [1/3] Checking dependencies...[0m

:: Check if fastapi is installed (proxy for all deps)
python -c "import fastapi" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [93m  Dependencies not found. Installing...[0m
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo  [91m  ERROR: Failed to install dependencies![0m
        echo  [91m  Make sure Python and pip are installed.[0m
        pause
        exit /b 1
    )
    echo  [92m  Dependencies installed![0m
) else (
    :: Quick check for recently added packages
    python -c "import fastapi, sqlalchemy, asyncpg, jose, argon2, psutil, slowapi" >nul 2>&1
    if %errorlevel% neq 0 (
        echo  [93m  Some packages missing. Updating...[0m
        pip install -r requirements.txt --quiet
        echo  [92m  Updated![0m
    ) else (
        echo  [92m  All dependencies already installed. Skipping.[0m
    )
)
echo.

:: ── Step 2: Database check ────────────────────────────────────────────
echo  [97m [2/3] Checking database...[0m
psql -U postgres -c "CREATE DATABASE cybersentinel;" 2>nul
echo  [92m  Done![0m
echo.

:: ── Step 3: Auto-start setup ──────────────────────────────────────────
echo  [97m [3/3] Launching CyberSentinel...[0m
echo.

:: Only ask about autostart if NOT already scheduled
schtasks /query /tn "CyberSentinel" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [93m =================================================[0m
    echo  [93m  Would you like CyberSentinel to start[0m
    echo  [93m  automatically when your PC boots up?[0m
    echo  [93m =================================================[0m
    echo.
    echo  [97m  Press Y for Yes, N for No[0m
    echo.
    choice /c YN /m "  Your choice"
    if errorlevel 2 goto SKIP_AUTOSTART
    if errorlevel 1 goto SET_AUTOSTART
) else (
    echo  [92m  Auto-start already configured.[0m
    goto LAUNCH
)

:SET_AUTOSTART
echo.
echo  [97m  Setting up auto-start...[0m
schtasks /create /tn "CyberSentinel" /tr "cmd /k python \"%~dp0monitor.py\"" /sc onlogon /rl highest /ru "%USERNAME%" /f >nul 2>&1
if %errorlevel% == 0 (
    echo  [92m  Done! CyberSentinel will start on every boot.[0m
) else (
    echo  [93m  Trying with admin rights...[0m
    powershell -Command "Start-Process cmd -ArgumentList '/c schtasks /create /tn CyberSentinel /tr \"cmd /k python \"%~dp0monitor.py\"\" /sc onlogon /rl highest /f' -Verb RunAs -Wait"
    echo  [92m  Done![0m
)
goto LAUNCH

:SKIP_AUTOSTART
echo.
echo  [97m  Skipped. You can run start.bat anytime manually.[0m

:LAUNCH
echo.
echo  [92m  Starting all components...[0m
echo.

:: Kill any process already using port 8000
echo  [97m  Checking port 8000...[0m
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000 " ^| findstr "LISTENING"') do (
    echo  [93m  Stopping existing server on port 8000 (PID %%a)...[0m
    taskkill /F /PID %%a >nul 2>&1
)
timeout /t 1 >nul

:: Start monitor in new window
start "CyberSentinel Monitor" cmd /k "cd /d \"%~dp0\" && python monitor.py"

:: Start kill chain viewer in new window
start "CyberSentinel Kill Chain" cmd /k "cd /d \"%~dp0\" && python kill_chain_cli.py"

:: Small delay so windows open first
timeout /t 2 >nul

:: Start main server IN THIS WINDOW (keeps it running, visible)
echo  [92m  Backend starting on http://localhost:8000[0m
echo  [97m  Press Ctrl+C to stop all services.[0m
echo.
python main.py

:: If python main.py exits, pause so user can see error
echo.
echo  [91m  Server stopped. See error above.[0m
pause
