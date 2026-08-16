@echo off
setlocal

REM Build an MSI from the onedir package using WiX Toolset v3.11.
REM The onedir must already be built at dist\antivirus_server.

set "ROOT=%~dp0"
set "ONEDIR=%ROOT%dist\antivirus_server"
if not exist "%ONEDIR%\antivirus_server.exe" (
    echo dist\antivirus_server\antivirus_server.exe not found.
    echo Run "python build_config.py" first.
    exit /b 1
)

set "WIX=%ProgramFiles(x86)%\WiX Toolset v3.11\bin"
if not exist "%WIX%\heat.exe" (
    set "WIX=%ProgramFiles%\WiX Toolset v3.11\bin"
)

if not exist "%WIX%\heat.exe" (
    echo WiX Toolset v3.11 not found.
    echo Download it from https://wixtoolset.org/docs/wix3/ and install it, then run this script again.
    exit /b 1
)

REM Use a local temp build directory so WiX can write its intermediate files
REM without being tripped up by OneDrive reparse points.
set "BUILD_DIR=%TEMP%\antivirus_msi_build"
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"

echo Harvesting dist\antivirus_server ...
"%WIX%\heat.exe" dir "%ONEDIR%" -cg ProductComponents -gg -sfrag -srd -scom -sreg -dr INSTALLFOLDER -var var.SourceDir -out "%BUILD_DIR%\components.wxs"
if errorlevel 1 (
    echo heat failed.
    exit /b 1
)

echo Compiling ...
cd /d "%ROOT%"
"%WIX%\candle.exe" -nologo -arch x64 -dSourceDir=%ONEDIR% -dProductVersion=1.0.0 -out "%BUILD_DIR%\\" "%ROOT%installer.wxs" "%BUILD_DIR%\components.wxs"
if errorlevel 1 (
    echo candle failed.
    exit /b 1
)

echo Linking ...
"%WIX%\light.exe" -nologo -ext WixUIExtension -cultures:en-us -out "%BUILD_DIR%\AntivirusServer.msi" "%BUILD_DIR%\installer.wixobj" "%BUILD_DIR%\components.wixobj"
if errorlevel 1 (
    echo light failed.
    exit /b 1
)

REM Copy the finished MSI to dist; keep the temp copy as a fallback if OneDrive locks dist.
if exist "%ROOT%dist\AntivirusServer.msi" del /f "%ROOT%dist\AntivirusServer.msi"
copy /y "%BUILD_DIR%\AntivirusServer.msi" "%ROOT%dist\AntivirusServer.msi" >nul
if errorlevel 1 (
    echo Could not copy MSI to dist. It is available at:
    echo %BUILD_DIR%\AntivirusServer.msi
    exit /b 1
)

echo MSI created: %ROOT%dist\AntivirusServer.msi
