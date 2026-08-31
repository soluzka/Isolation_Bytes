# Stop the service and wait for it to fully stop
Write-Output "Stopping service..."
sc.exe stop AntivirusCloudServer
Start-Sleep -Seconds 15

# Force kill all cloud_server processes
Write-Output "Killing cloud_server processes..."
$attempts = 0
while ($attempts -lt 10) {
    $procs = Get-Process cloud_server -ErrorAction SilentlyContinue
    if (-not $procs) { break }
    taskkill /F /IM cloud_server.exe /T 2>&1
    Start-Sleep -Seconds 3
    $attempts++
}

# Also kill cloudflared
taskkill /F /IM cloudflared.exe /T 2>&1
Start-Sleep -Seconds 3

# Now replace the EXE
Write-Output "Replacing EXE..."
$dest = "C:\AntivirusServer\cloud_server.exe"
$src = "C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c\dist\cloud_server.exe"

if (Test-Path $dest) {
    Remove-Item $dest -Force
    Start-Sleep -Seconds 2
}

if (Test-Path $dest) {
    Write-Output "ERROR: Still can't delete old EXE!"
    exit 1
}

Copy-Item $src $dest -Force
Start-Sleep -Seconds 2

Write-Output "Verification:"
Write-Output "  Dest:"
Get-ChildItem $dest | Select-Object Length,LastWriteTime
Write-Output "  Src:"
Get-ChildItem $src | Select-Object Length,LastWriteTime

# Start the service
Write-Output "Starting service..."
sc.exe start AntivirusCloudServer
Start-Sleep -Seconds 60

Write-Output "---SERVICE---"
sc.exe query AntivirusCloudServer

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
