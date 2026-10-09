@echo off
:: ═══════════════════════════════════════════════════════════════════
:: AISS — Full Installer Builder
:: Builds backend exe + frontend + creates Windows Setup.exe
:: Run from d:\aiss directory
:: ═══════════════════════════════════════════════════════════════════

title AISS Installer Builder
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "BACKEND=%ROOT%\backend"
set "FRONTEND=%ROOT%\frontend"
set "INSTALLER=%ROOT%\installer"
set "OUTPUT=%ROOT%\installer\output"

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║   AISS Installer Builder v2.0                                ║
echo  ║   Building: Backend + Frontend + Windows Installer           ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.

:: ── Step 1: Check prerequisites ─────────────────────────────────────
echo [1/7] Checking prerequisites...

set "PYTHON=%BACKEND%\.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
    echo  ERROR: Python venv not found at %PYTHON%
    echo  Run: cd "aiss backend" ^&^& python -m venv .venv ^&^& .venv\Scripts\pip install -r requirements.txt
    pause & exit /b 1
)

node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  ERROR: Node.js not found. Install from https://nodejs.org
    pause & exit /b 1
)

echo  ✓ Python venv found
echo  ✓ Node.js found

:: ── Step 2: Build Frontend ───────────────────────────────────────────
echo.
echo [2/7] Building frontend (React/Vite)...
cd /d "%FRONTEND%"
call npm run build
if %errorlevel% neq 0 (
    echo  ERROR: Frontend build failed
    pause & exit /b 1
)
echo  ✓ Frontend built → frontend\.output\

:: ── Step 3: Download portable Node.js ───────────────────────────────
echo.
echo [3/7] Downloading portable Node.js for bundling...
mkdir "%INSTALLER%\node" 2>nul

if not exist "%INSTALLER%\node\node.exe" (
    echo  Downloading Node.js v20 LTS portable...
    :: Get current node version
    for /f "tokens=*" %%v in ('node --version') do set NODE_VER=%%v
    echo  Using Node.js !NODE_VER!
    
    :: Copy current node.exe (fastest approach — use installed one)
    for /f "delims=" %%p in ('where node 2^>nul') do (
        copy "%%p" "%INSTALLER%\node\node.exe" >nul
        echo  ✓ Copied node.exe from %%p
        goto :node_done
    )
    :: If not found, use PowerShell to download
    powershell -Command "& { $url='https://nodejs.org/dist/v20.19.2/node-v20.19.2-win-x64.zip'; $out='%INSTALLER%\node.zip'; Invoke-WebRequest $url -OutFile $out; Expand-Archive $out -DestinationPath '%INSTALLER%\node_tmp' -Force; Get-ChildItem '%INSTALLER%\node_tmp' -Filter 'node.exe' -Recurse | Copy-Item -Destination '%INSTALLER%\node\node.exe'; Remove-Item $out,%INSTALLER%\node_tmp -Recurse -Force }"
    :node_done
) else (
    echo  ✓ Node.js already downloaded
)

:: ── Step 4: Install PyInstaller ──────────────────────────────────────
echo.
echo [4/7] Installing PyInstaller...
cd /d "%BACKEND%"
"%PYTHON%" -m pip install pyinstaller --quiet
echo  ✓ PyInstaller ready

:: ── Step 5: Build backend exe with PyInstaller ──────────────────────
echo.
echo [5/7] Building backend executable (PyInstaller)...
echo  This may take 5-10 minutes for a large project...
cd /d "%BACKEND%"

"%BACKEND%\.venv\Scripts\pyinstaller.exe" ^
    --noconfirm ^
    --clean ^
    --distpath "%BACKEND%\dist" ^
    --workpath "%BACKEND%\build" ^
    --name "AISS" ^
    --console ^
    --add-data "rules;rules" ^
    --add-data "static;static" ^
    --add-data "alembic;alembic" ^
    --add-data "alembic.ini;." ^
    --add-data "data;data" ^
    --hidden-import "uvicorn.logging" ^
    --hidden-import "uvicorn.loops" ^
    --hidden-import "uvicorn.loops.auto" ^
    --hidden-import "uvicorn.protocols.http" ^
    --hidden-import "uvicorn.protocols.http.auto" ^
    --hidden-import "uvicorn.protocols.websockets.auto" ^
    --hidden-import "uvicorn.lifespan.on" ^
    --hidden-import "sqlalchemy.dialects.sqlite" ^
    --hidden-import "aiosqlite" ^
    --hidden-import "passlib.handlers.bcrypt" ^
    --hidden-import "passlib.handlers.argon2" ^
    --hidden-import "jose.jwt" ^
    --hidden-import "anyio._backends._asyncio" ^
    --hidden-import "psutil" ^
    --exclude-module "torch" ^
    --exclude-module "transformers" ^
    --exclude-module "tensorflow" ^
    --exclude-module "matplotlib" ^
    aiss_launcher.py

if %errorlevel% neq 0 (
    echo  ERROR: PyInstaller build failed
    pause & exit /b 1
)
echo  ✓ Backend exe built → aiss backend\dist\AISS\

:: ── Step 6: Copy frontend to dist ───────────────────────────────────
echo.
echo [6/7] Copying frontend to dist folder...
mkdir "%BACKEND%\dist\AISS\frontend\.output" 2>nul
xcopy /E /I /Y "%FRONTEND%\.output" "%BACKEND%\dist\AISS\frontend\.output" >nul
copy "%INSTALLER%\node\node.exe" "%BACKEND%\dist\AISS\node\node.exe" >nul 2>&1
mkdir "%BACKEND%\dist\AISS\node" 2>nul
copy "%INSTALLER%\node\node.exe" "%BACKEND%\dist\AISS\node\node.exe" >nul
echo  ✓ Frontend + Node.js included in dist

:: ── Step 7: Create Inno Setup installer ─────────────────────────────
echo.
echo [7/7] Creating Windows installer (.exe setup)...
mkdir "%OUTPUT%" 2>nul

:: Check if Inno Setup is installed
set "INNO="
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set "INNO=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if exist "C:\Program Files\Inno Setup 6\ISCC.exe"       set "INNO=C:\Program Files\Inno Setup 6\ISCC.exe"

if "%INNO%"=="" (
    echo.
    echo  ⚠  Inno Setup not found.
    echo  Download from: https://jrsoftware.org/isdl.php
    echo.
    echo  After installing Inno Setup, run:
    echo  "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" "%INSTALLER%\aiss_setup.iss"
    echo.
    echo  ──────────────────────────────────────────────
    echo  PARTIAL BUILD COMPLETE (no .exe installer yet)
    echo  The portable folder is ready at:
    echo  %BACKEND%\dist\AISS\
    echo  ──────────────────────────────────────────────
    echo.
    echo  Creating a ZIP archive instead...
    powershell -Command "Compress-Archive -Path '%BACKEND%\dist\AISS\*' -DestinationPath '%OUTPUT%\AISS_v2.0_Portable.zip' -Force"
    if exist "%OUTPUT%\AISS_v2.0_Portable.zip" (
        echo  ✓ Portable ZIP created: %OUTPUT%\AISS_v2.0_Portable.zip
    )
    goto :done
)

echo  Found Inno Setup: %INNO%
"%INNO%" "%INSTALLER%\aiss_setup.iss"

if %errorlevel% neq 0 (
    echo  ERROR: Inno Setup compilation failed
    pause & exit /b 1
)

:done
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║   BUILD COMPLETE!                                            ║
echo  ╠══════════════════════════════════════════════════════════════╣
if exist "%OUTPUT%\AISS_Setup_v2.0.0_Windows.exe" (
echo  ║   Windows Installer: installer\output\AISS_Setup_*.exe      ║
) else (
echo  ║   Portable ZIP:      installer\output\AISS_v2.0_Portable.zip║
)
echo  ║   Portable Folder:   aiss backend\dist\AISS\                ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  Upload AISS_Setup_*.exe to your website download button.
echo.
pause
