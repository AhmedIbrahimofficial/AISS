@echo off
:: AISS Global Launcher — type "aiss" from anywhere to start
set "AISS_DIR=d:\aiss\aiss backend"

if not exist "%AISS_DIR%\main.py" (
    echo [AISS] ERROR: Backend not found at %AISS_DIR%
    pause & exit /b 1
)

cd /d "%AISS_DIR%"
call "%AISS_DIR%\start.bat"
