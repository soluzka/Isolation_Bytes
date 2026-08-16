@echo off
setlocal

REM Compile the Inno Setup installer. The onedir must already be built at dist\antivirus_server.

if not exist "dist\antivirus_server\antivirus_server.exe" (
    echo dist\antivirus_server\antivirus_server.exe not found.
    echo Run "python build_config.py" first, then run this script again.
    exit /b 1
)

REM Remove any existing setup build artifacts so the compiler isn't blocked writing the .tmp file.
if exist "dist\AntivirusServer_Setup.exe" del /f "dist\AntivirusServer_Setup.exe"
if exist "dist\AntivirusServer_Setup.e32.tmp" del /f "dist\AntivirusServer_Setup.e32.tmp"

set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\iscc.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\iscc.exe"
if exist "%ProgramFiles%\Inno Setup 6\iscc.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\iscc.exe"

if "%ISCC%"=="" (
    echo Inno Setup compiler ^(iscc.exe^) not found.
    echo Download it from https://jrsoftware.org/isinfo.php and install it, then run this script again.
    exit /b 1
)

"%ISCC%" installer.iss
