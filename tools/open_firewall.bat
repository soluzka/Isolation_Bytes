@echo off
netsh advfirewall firewall add rule name="Antivirus HTTPS" dir=in action=allow protocol=TCP localport=8443
netsh advfirewall firewall add rule name="Certbot HTTP" dir=in action=allow protocol=TCP localport=80
findstr /i /c:"soluzka.com" "%SystemRoot%\System32\drivers\etc\hosts" >nul 2>&1 || (
    echo 192.168.1.133 soluzka.com >> "%SystemRoot%\System32\drivers\etc\hosts"
)
ipconfig /flushdns
echo Firewall rules added. Press any key.
pause
