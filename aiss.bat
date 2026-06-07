@echo off
:: AISS Global Launcher
:: Kisi bhi terminal se "aiss" type karo — backend khud start ho jata hai

set "AISS_DIR=d:\aiss\aiss backend"

if not exist "%AISS_DIR%\main.py" (
    echo [AISS] ERROR: main.py not found at "%AISS_DIR%"
    echo [AISS] Check that the backend folder exists.
    pause
    exit /b 1
)

cd /d "%AISS_DIR%"
call "%AISS_DIR%\start.bat"
