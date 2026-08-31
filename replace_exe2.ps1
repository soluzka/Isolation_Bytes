# Stop the service
Write-Output "Stopping service..."
sc.exe stop AntivirusCloudServer
Start-Sleep -Seconds 15

# Force kill all cloud_server processes
Write-Output "Killing cloud_server processes..."
$attempts = 0
while ($attempts -lt 15) {
    $procs = Get-Process cloud_server -ErrorAction SilentlyContinue
    if (-not $procs) { 
        Write-Output "All cloud_server processes killed."
        break 
    }
    Write-Output "Attempt $($attempts+1): killing PID(s) $($procs.Id -join ', ')"
    taskkill /F /IM cloud_server.exe /T 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    $attempts++
}

# Kill cloudflared too
taskkill /F /IM cloudflared.exe /T 2>&1 | Out-Null
Start-Sleep -Seconds 3

# Delete the old EXE
$dest = "C:\AntivirusServer\cloud_server.exe"
$src = "C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c\dist\cloud_server.exe"

Write-Output "Deleting old EXE..."
if (Test-Path $dest) {
    Remove-Item $dest -Force
    Start-Sleep -Seconds 3
}

if (Test-Path $dest) {
    Write-Output "ERROR: Old EXE still exists after delete!"
    exit 1
}
Write-Output "Old EXE deleted."

# Copy the new EXE using robocopy (more reliable than Copy-Item)
Write-Output "Copying new EXE with robocopy..."
robocopy "C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c\dist" "C:\AntivirusServer" "cloud_server.exe" /R:3 /W:5 /NFL /NDL /NJH /NJS 2>&1
Start-Sleep -Seconds 3

# Verify the copy
Write-Output "Verification:"
Write-Output "  Dest (should be 302423244 bytes, 8/22):"
if (Test-Path $dest) {
    $f = Get-ChildItem $dest
    Write-Output "    Length: $($f.Length)  LastWriteTime: $($f.LastWriteTime)"
    if ($f.Length -eq 302423244) {
        Write-Output "    MATCH - new EXE copied successfully!"
    } else {
        Write-Output "    MISMATCH - old EXE or wrong file!"
    }
} else {
    Write-Output "    FILE DOES NOT EXIST - copy failed!"
    exit 1
}

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
