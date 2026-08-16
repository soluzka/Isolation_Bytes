@echo off
setlocal
set "ROOT=C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c"
set "DIST=%ROOT%\dist"
set "DOTNET=C:\Users\bpier\AppData\Local\Microsoft\dotnet\dotnet.exe"
set "PYTHON=C:\Users\bpier\AppData\Local\Programs\Python\Python311\python.exe"
mkdir "%DIST%" 2>nul

cd /d "%ROOT%"
echo Embedding resources...
"%PYTHON%" "tools\embed_resources.py"

echo Publishing launcher...
"%DOTNET%" publish "%ROOT%\native\AntivirusServerLogin\AntivirusServerLogin.csproj" -c Release -o "%DIST%" /p:UseAppHost=true

dir "%DIST%\*.exe" 2>nul
if exist "%DIST%\AntivirusServerLogin.exe" (
    copy /y "%DIST%\AntivirusServerLogin.exe" "%DIST%\Antivirus Server Login.exe"
    echo Launcher built: %DIST%\Antivirus Server Login.exe
) else (
    echo Build failed or output file not found. Check the messages above.
)
pause
