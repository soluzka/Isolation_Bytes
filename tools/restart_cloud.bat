@echo off
setlocal
set "ROOT=C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c"

taskkill /f /im python.exe >nul 2>&1
timeout /t 2 /nobreak >nul

start "" python "%ROOT%\tools\license_server.py"
timeout /t 1 /nobreak >nul
start "" python "%ROOT%\cloud\cloud_server.py"

echo Cloud server restarted.
pause
