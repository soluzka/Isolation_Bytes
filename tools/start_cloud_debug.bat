@echo off
setlocal
set "ROOT=C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c"

taskkill /f /im python.exe >nul 2>&1
timeout /t 2 /nobreak >nul

cd /d "%ROOT%"
start /b cmd /c "python tools\license_server.py > license_log.txt 2>&1"
timeout /t 1 /nobreak >nul
start /b cmd /c "python cloud\cloud_server.py > cloud_log.txt 2>&1"
timeout /t 2 /nobreak >nul

echo Cloud started. If it fails, see %ROOT%\cloud_log.txt
type %ROOT%\cloud_log.txt 2>nul
pause
