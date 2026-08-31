@echo off
setlocal
set "ROOT=C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c"
set "DIST=%ROOT%\dist"
set "DOTNET=C:\Users\bpier\AppData\Local\Microsoft\dotnet\dotnet.exe"
set "PYTHON=C:\Users\bpier\AppData\Local\Programs\Python\Python311\python.exe"
set "LOG=%ROOT%\build_log.txt"
>"%LOG%" 2>&1 (
    echo === Antivirus Launcher Build Log ===
    echo DOTNET=%DOTNET%
    echo PYTHON=%PYTHON%
    echo DIST=%DIST%
    echo.
    if not exist "%DOTNET%" (
        echo ERROR: dotnet not found at %DOTNET%
        exit /b 1
    )
    "%DOTNET%" --version
    if not exist "%PYTHON%" (
        echo ERROR: python not found at %PYTHON%
        exit /b 1
    )
    "%PYTHON%" --version
    echo.
    echo === Embedding resources ===
    cd /d "%ROOT%"
    "%PYTHON%" "tools\embed_resources.py"
    echo embed exit code: %ERRORLEVEL%
    echo.
    echo === Cleaning dist ===
    taskkill /f /im AntivirusServerLogin.exe >nul 2>&1
    timeout /t 1 /nobreak >nul
    if exist "%DIST%" rmdir /s /q "%DIST%"
    mkdir "%DIST%"
    echo.
    echo === Publishing launcher ===
    "%DOTNET%" publish "%ROOT%\native\AntivirusServerLogin\AntivirusServerLogin.csproj" -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o "%DIST%"
    echo publish exit code: %ERRORLEVEL%
    echo.
    echo === Files in dist ===
    dir "%DIST%" /b
    echo.
    if exist "%DIST%\AntivirusServerLogin.exe" (
        copy /y "%DIST%\AntivirusServerLogin.exe" "%DIST%\IsolationBytesLogin.exe"
        echo Copied to: %DIST%\IsolationBytesLogin.exe
    ) else (
        echo ERROR: AntivirusServerLogin.exe not found in dist
    )
    echo.
    echo === Done ===
)
notepad "%LOG%"
