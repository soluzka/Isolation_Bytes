# Rebuild and restart the deployed Isolation Bytes cloud server.
# This deliberately rebuilds cloud_server.exe from the checked-out source so
# Python-source fixes cannot be masked by a stale EXE in C:\AntivirusServer.

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path (Join-Path $ProjectRoot "buildconfig.py"))) {
    $ProjectRoot = "C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c"
}
if (-not (Test-Path (Join-Path $ProjectRoot "buildconfig.py"))) {
    throw "Isolation Bytes project root could not be found."
}

Write-Output "Project: $ProjectRoot"

# Locate Python.
$python = $null
foreach ($candidate in @(
    (Join-Path $ProjectRoot ".venv\Scripts\python.exe"),
    (Join-Path $ProjectRoot "venv\Scripts\python.exe"),
    "python"
)) {
    if ($candidate -eq "python" -or (Test-Path $candidate)) {
        $python = $candidate
        break
    }
}
if (-not $python) { throw "Python was not found." }

Write-Output "Stopping AntivirusCloudServer..."
sc.exe stop AntivirusCloudServer | Out-Host
Start-Sleep -Seconds 10

Write-Output "Stopping stale server/tunnel processes..."
taskkill /F /IM cloud_server.exe /T 2>&1 | Out-Host
taskkill /F /IM cloudflared.exe /T 2>&1 | Out-Host
Start-Sleep -Seconds 5

Write-Output "Building cloud_server.exe from current source..."
Push-Location $ProjectRoot
try {
    & $python .\buildconfig.py --cloud
    if ($LASTEXITCODE -ne 0) {
        throw "cloud_server.exe build failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$source = Join-Path $ProjectRoot "dist\cloud_server.exe"
$dest = "C:\AntivirusServer\cloud_server.exe"
if (-not (Test-Path $source)) { throw "Fresh cloud_server.exe was not produced: $source" }

New-Item -ItemType Directory -Force -Path "C:\AntivirusServer" | Out-Null
Remove-Item $dest -Force -ErrorAction SilentlyContinue
Copy-Item $source $dest -Force

Write-Output "Deployed EXE:"
Get-Item $dest | Select-Object Length, LastWriteTime | Format-List

Write-Output "Starting AntivirusCloudServer..."
sc.exe start AntivirusCloudServer | Out-Host
Start-Sleep -Seconds 70

Write-Output "--- SERVICE STATE ---"
sc.exe query AntivirusCloudServer | Out-Host

Write-Output "--- PROCESSES ---"
Get-Process cloud_server,cloudflared -ErrorAction SilentlyContinue |
    Select-Object Id,ProcessName,StartTime | Format-Table -AutoSize

Write-Output "--- LOCAL ORIGIN CHECK ---"
$healthy = $false
foreach ($url in @("http://127.0.0.1:8000/", "http://127.0.0.1:5002/")) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 15
        Write-Output "$url -> HTTP $($response.StatusCode)"
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
            $healthy = $true
        }
    } catch {
        Write-Output "$url -> $($_.Exception.Message)"
    }
}
if (-not $healthy) {
    Write-Output "--- SERVICE LOG ---"
    Get-Content (Join-Path $ProjectRoot "cloud\service.log") -Tail 120 -ErrorAction SilentlyContinue
    throw "Cloud server did not answer locally; Cloudflare 502 will continue until the origin is healthy."
}

Write-Output "--- PUBLIC CHECK ---"
try {
    $public = Invoke-WebRequest -UseBasicParsing -Uri "https://isolation-bytes.com/" -TimeoutSec 30
    Write-Output "https://isolation-bytes.com/ -> HTTP $($public.StatusCode)"
} catch {
    Write-Output "Public check failed: $($_.Exception.Message)"
    Write-Output "The local origin is healthy; inspect Caddy/cloudflared/Cloudflare routing if this remains a 502."
}

Write-Output "Deployment repair complete."
