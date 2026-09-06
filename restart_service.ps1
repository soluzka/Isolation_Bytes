Write-Output "Stopping service..."
sc.exe stop AntivirusCloudServer
Start-Sleep -Seconds 10

Write-Output "Killing all cloud_server and cloudflared processes..."
taskkill /F /IM cloud_server.exe /T 2>&1
taskkill /F /IM cloudflared.exe /T 2>&1
Start-Sleep -Seconds 5

Write-Output "Deleting old EXE from C:\AntivirusServer..."
Remove-Item "C:\AntivirusServer\cloud_server.exe" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

if (Test-Path "C:\AntivirusServer\cloud_server.exe") {
    Write-Output "ERROR: Old EXE still exists - cannot delete!"
} else {
    Write-Output "Old EXE deleted successfully."
}

Write-Output "Starting service..."
sc.exe start AntivirusCloudServer
Start-Sleep -Seconds 70

Write-Output "---SERVICE STATE---"
sc.exe query AntivirusCloudServer

Write-Output "---C:\AntivirusServer EXE---"
Get-ChildItem "C:\AntivirusServer\cloud_server.exe" -ErrorAction SilentlyContinue | Select-Object Length,LastWriteTime

Write-Output "---PROCESSES---"
Get-Process cloud_server,cloudflared -ErrorAction SilentlyContinue | Select-Object Id,ProcessName

Write-Output "---LOCAL CHECK---"
try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8000/" -TimeoutSec 15
    Write-Output "Status: $($r.StatusCode)"
    $m = $r.Content | Select-String -Pattern "Get [Ll]icense|stripe|Stripe|redeem|Redeem" -AllMatches
    if ($m) {
        Write-Output "STILL FOUND:"
        $m.Matches.Value | Sort-Object -Unique
    } else {
        Write-Output "CLEAN - no Stripe/redeem/Get License found!"
    }
} catch {
    $_.Exception.Message
}

Write-Output "---PUBLIC CHECK---"
try {
    (Invoke-WebRequest -UseBasicParsing -Uri "https://isolation-bytes.com/" -TimeoutSec 30).StatusCode
} catch {
    $_.Exception.Message
}
