@echo off
echo Installing CyberSentinel auto-start on Windows boot...

set PROJECT_DIR=%~dp0
set PYTHON_PATH=python

schtasks /create /tn "CyberSentinel" /tr "%PYTHON_PATH% %PROJECT_DIR%main.py" /sc onstart /ru SYSTEM /f

echo.
echo ✅ Done! CyberSentinel will now start automatically on boot.
echo Run this file as Administrator once.
pause
