@echo off
setlocal
cd /d "%~dp0"
echo Starting YARA Scanner server...
start /min "" python quick_start.py

echo Waiting for the server to start...
set attempts=0
:wait
powershell -Command "try { (New-Object System.Net.Sockets.TcpClient).Connect('127.0.0.1', 5000); exit 0 } catch { exit 1 }" >nul 2>&1
if %ERRORLEVEL% EQU 0 goto open
timeout /t 1 /nobreak >nul
set /a attempts+=1
if %attempts% lss 30 goto wait

echo Timed out waiting for the server to start on port 5000.
pause
exit /b 1

:open
echo Opening YARA Scanner in your default browser...
start http://127.0.0.1:5000/yara-scanner
