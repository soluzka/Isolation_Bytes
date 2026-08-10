@echo off
setlocal
cd /d "%~dp0"
echo Starting Conditional Antivirus...
python quick_start.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Conditional Antivirus exited with error code %ERRORLEVEL%.
    pause
)
