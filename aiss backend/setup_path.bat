@echo off
:: AISS PATH Setup
:: Run this ONCE as Administrator to make "aiss" available in any terminal

set "AISS_DIR=d:\aiss\aiss backend"

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

:: Add to system PATH permanently (requires admin)
echo   [>>] Adding AISS to system PATH...
setx PATH "%PATH%;%AISS_DIR%" /M >nul 2>&1
if %errorlevel% neq 0 (
    echo   [!] System PATH failed. Trying user PATH instead...
    setx PATH "%PATH%;%AISS_DIR%" >nul 2>&1
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
) else (
    echo   [OK] Added to SYSTEM PATH successfully.
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
