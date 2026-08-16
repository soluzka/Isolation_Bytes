@echo off
title Start Antivirus Server
if exist "%~dp0Start Antivirus Server.exe" (
    "%~dp0Start Antivirus Server.exe"
    exit /b %errorlevel%
)
if exist "%~dp0dist\Start Antivirus Server.exe" (
    "%~dp0dist\Start Antivirus Server.exe"
    exit /b %errorlevel%
)
python "%~dp0tools\start_antivirus_server.py"
