@echo off
setlocal
set "ROOT=C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c"
set "DIST=%ROOT%\dist"
set "DOTNET=C:\Users\bpier\AppData\Local\Microsoft\dotnet\dotnet.exe"
set "PYTHON=C:\Users\bpier\AppData\Local\Programs\Python\Python311\python.exe"
set "LOG=%ROOT%\build_and_run_log.txt"
set "BUILD=%TEMP%\antivirus_build_%RANDOM%"

taskkill /f /im python.exe >nul 2>&1
taskkill /f /im "Antivirus Server Login.exe" >nul 2>&1
taskkill /f /im AntivirusServerLogin.exe >nul 2>&1
timeout /t 3 /nobreak >nul

cd /d "%ROOT%"

>"%LOG%" 2>&1 (
    echo === Build and run ===
    echo.
    echo Building launcher...
    "%PYTHON%" "tools\embed_resources.py"
    if not exist "%DIST%" mkdir "%DIST%"
    if exist "%DIST%\*.exe" del /q "%DIST%\*.exe" 2>nul
    mkdir "%BUILD%"
    "%DOTNET%" publish "%ROOT%\native\AntivirusServerLogin\AntivirusServerLogin.csproj" -c Release -r win-x64 --self-contained false -o "%BUILD%"
    echo publish exit code: %ERRORLEVEL%
    echo.
    echo Files in build temp:
    dir "%BUILD%" /b
    echo.
    if exist "%BUILD%\AntivirusServerLogin.exe" (
        copy /y "%BUILD%\AntivirusServerLogin.exe" "%DIST%\Antivirus Server Login.exe"
        echo copied to %DIST%\Antivirus Server Login.exe
    ) else (
        echo ERROR: AntivirusServerLogin.exe not produced
    )
    rmdir /s /q "%BUILD%"
    echo.
    echo Starting cloud server...
    start /b cmd /c "python tools\license_server.py > license_log.txt 2>&1"
    timeout /t 1 /nobreak >nul
    start /b cmd /c "python cloud\cloud_server.py > cloud_log.txt 2>&1"
    timeout /t 2 /nobreak >nul
    echo done.
)
type "%LOG%"
pause
