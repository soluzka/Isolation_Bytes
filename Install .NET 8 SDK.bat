@echo off
title Install .NET 8 SDK
if exist "%~dp0Install .NET 8 SDK.exe" (
    "%~dp0Install .NET 8 SDK.exe" %*
    exit /b %errorlevel%
)
if exist "%~dp0dist\Install .NET 8 SDK.exe" (
    "%~dp0dist\Install .NET 8 SDK.exe" %*
    exit /b %errorlevel%
)
python "%~dp0tools\install_dotnet_sdk.py"
