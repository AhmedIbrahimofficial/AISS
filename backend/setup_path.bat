@echo off
:: AISS PATH Setup
:: Run this ONCE as Administrator to make "aiss" available in any terminal
:: Alternatively, run:  aiss --setup

set "AISS_DIR=d:\aiss"

echo.
echo   +==========================================+
echo   ^|   AISS - PATH Setup                     ^|
echo   +==========================================+
echo.

:: Check if already in PATH
echo %PATH% | findstr /i /c:"%AISS_DIR%" >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] AISS is already in your PATH.
    echo        Type "aiss" in any terminal to start.
    echo.
    pause
    exit /b 0
)

:: Also set AISS_HOME for scripts that need it
setx AISS_HOME "%AISS_DIR%" >nul 2>&1

:: Add to user PATH permanently (HKCU\Environment\Path)
for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "CURRENT_PATH=%%b"
echo %CURRENT_PATH% | findstr /i /c:"%AISS_DIR%" >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] AISS directory already in user PATH.
) else (
    echo   [>>] Adding AISS to user PATH...
    setx Path "%CURRENT_PATH%;%AISS_DIR%" >nul 2>&1
    if %errorlevel% neq 0 (
        echo   [ERROR] Could not add to PATH automatically.
        echo.
        echo   Manual fix: Add this folder to PATH yourself:
        echo   %AISS_DIR%
        echo.
        pause
        exit /b 1
    )
    echo   [OK] Added to USER PATH successfully.
)

echo.
echo   +==========================================+
echo   ^|  Done! Open a NEW terminal and type:    ^|
echo   ^|                                         ^|
echo   ^|              aiss                       ^|
echo   ^|                                         ^|
echo   ^|  AISS will start instantly.             ^|
echo   +==========================================+
echo.
pause
