@echo off
title Antivirus Server Installer
if exist "%~dp0Run SFX Installer.exe" (
    "%~dp0Run SFX Installer.exe"
    exit /b %errorlevel%
)
if exist "%~dp0dist\Run SFX Installer.exe" (
    "%~dp0dist\Run SFX Installer.exe"
    exit /b %errorlevel%
)
python "%~dp0tools\run_sfx_installer.py"
