# Isolation Bytes — Universal Windows Installer
# Downloads the MSIX + certificate from isolation-bytes.com, trusts the
# certificate, installs the MSIX, and launches the app.
#
# Usage:
#   .\install-windows.ps1                              # download from web
#   .\install-windows.ps1 -Local                       # use local dist\ files
#   iwr https://isolation-bytes.com/download/install-windows.ps1 -UseBasicParsing | iex
[CmdletBinding()]
param(
    [switch]$Local,
    [string]$BaseUrl = 'https://isolation-bytes.com',
    [string]$DistDir,
    [string]$ApiKey,
    [string]$PairCode = '{pair_code}'
)

$ErrorActionPreference = 'Stop'

# ─── Elevate to Administrator ──────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Requesting Administrator privileges...'
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($Local) { $args += '-Local' }
    if ($DistDir) { $args += '-DistDir', $DistDir }
    if ($BaseUrl -ne 'https://isolation-bytes.com') { $args += '-BaseUrl', $BaseUrl }
    if ($ApiKey) { $args += '-ApiKey', $ApiKey }
    if ($PairCode) { $args += '-PairCode', $PairCode }
    $proc = Start-Process powershell.exe -ArgumentList $args -Verb RunAs -Wait -PassThru
    exit $proc.ExitCode
}

# ─── Determine source: local dist\ or download from web ────────────────
if ($Local) {
    if (-not $DistDir) {
        $DistDir = Join-Path $PSScriptRoot 'dist'
        if (-not (Test-Path $DistDir)) {
            $DistDir = Split-Path -Parent $PSScriptRoot
            $DistDir = Join-Path $DistDir 'dist'
        }
    }
    $MsixPath = Join-Path $DistDir 'IsolationBytes.msix'
    $CerPath  = Join-Path $DistDir 'IsolationBytes.cer'
} else {
    $tempDir = Join-Path $env:TEMP 'IsolationBytes_Install'
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    Write-Host "Downloading Isolation Bytes from $BaseUrl..."
    $MsixPath = Join-Path $tempDir 'IsolationBytes.msix'
    $CerPath  = Join-Path $tempDir 'IsolationBytes.cer'

    try {
        Invoke-WebRequest -Uri "$BaseUrl/download/IsolationBytes.msix" -OutFile $MsixPath -UseBasicParsing -TimeoutSec 120
        Invoke-WebRequest -Uri "$BaseUrl/download/IsolationBytes.cer"  -OutFile $CerPath  -UseBasicParsing -TimeoutSec 30
    } catch {
        Write-Warning "Desktop app download unavailable: $($_.Exception.Message)"
        Remove-Item $MsixPath, $CerPath -Force -ErrorAction SilentlyContinue
    }
}

$hasDesktopPackage = (Test-Path $MsixPath) -and (Test-Path $CerPath)

# ─── Verify checksums ───────────────────────────────────────────────────
if (-not $Local -and $hasDesktopPackage) {
    Write-Host 'Verifying file integrity...'
    try {
        $checksumsResp = Invoke-WebRequest -Uri "$BaseUrl/download/checksums.json" -UseBasicParsing -TimeoutSec 10
        $checksums = ($checksumsResp.Content | ConvertFrom-Json).files
        foreach ($fileInfo in @(
            @{ Path = $MsixPath; Name = 'IsolationBytes.msix' },
            @{ Path = $CerPath;  Name = 'IsolationBytes.cer' }
        )) {
            $expected = $checksums.($fileInfo.Name)
            if ($expected -and $expected.sha256) {
                $actual = (Get-FileHash -Path $fileInfo.Path -Algorithm SHA256).Hash.ToLower()
                if ($actual -ne $expected.sha256.ToLower()) {
                    throw "Checksum mismatch for $($fileInfo.Name): expected $($expected.sha256), got $actual"
                }
                Write-Host "  $($fileInfo.Name) verified (SHA-256 OK)"
            }
        }
    } catch {
        Write-Warning 'Could not verify checksums (server unreachable). Proceeding with install.'
    }
}

if ($hasDesktopPackage) {
    $msixSize = [math]::Round((Get-Item $MsixPath).Length / 1MB, 1)
    Write-Host "MSIX: $MsixPath ($msixSize MB)"
    Write-Host "Cert: $CerPath"

    # ─── 1. Trust the certificate ──────────────────────────────────────
    Write-Host 'Installing certificate to trusted stores...'
    Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
    Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\CurrentUser\TrustedPeople' | Out-Null
    Write-Host '  Certificate trusted.'

    # ─── 2. Remove and install the desktop package ─────────────────────
    $pkgName = 'soluzka.IsolationBytes'
    $existing = Get-AppxPackage -Name $pkgName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Removing previous version ($($existing.Version))..."
        Remove-AppxPackage -Package $existing.PackageFullName -ErrorAction SilentlyContinue
    }
    Write-Host 'Installing Isolation Bytes MSIX...'
    Add-AppxPackage -Path $MsixPath -ForceApplicationShutdown -ForceUpdateFromAnyVersion
    Write-Host '  Installed.'

    # ─── 3. Launch the desktop package ─────────────────────────────────
    $pkg = Get-AppxPackage -Name $pkgName
    if ($pkg) {
        $aumid = $pkg.PackageFamilyName + '!IsolationBytes'
        Start-Process -FilePath 'explorer.exe' -ArgumentList "shell:AppsFolder\$aumid"
        Write-Host 'Isolation Bytes launched.'
    } else {
        Write-Warning 'Could not locate the installed package to launch.'
    }
} else {
    $pkg = $null
    Write-Warning 'Desktop package unavailable; continuing with the network agent installation.'
}

# ─── 6. Install the network monitoring agent ───────────────────────────
$agentDir = Join-Path $env:LOCALAPPDATA 'IsolationBytes'
New-Item -ItemType Directory -Path $agentDir -Force | Out-Null

Write-Host 'Installing network monitoring agent...'
$agentExe = Join-Path $agentDir 'IsolationBytesAgent.exe'
try {
    Invoke-WebRequest -Uri "$BaseUrl/download/IsolationBytesAgent.exe" -OutFile $agentExe -UseBasicParsing -TimeoutSec 120
    if ((Get-Item $agentExe).Length -lt 100000) { throw 'Downloaded agent is unexpectedly small' }
    Write-Host '  Agent EXE downloaded.'
} catch {
    Write-Warning "Could not download IsolationBytesAgent.exe: $($_.Exception.Message)"
}

# Create a scheduled task to auto-start the agent on login
$taskName = 'IsolationBytesAgent'
$taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($taskExists) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
if (Test-Path $agentExe) {
    # Register a per-user URI handler so the website can launch this agent
    # without requiring administrator rights or exposing the API key.
    $protocolKey = 'HKCU:\Software\Classes\isolationbytes'
    New-Item -Path $protocolKey -Force | Out-Null
    New-ItemProperty -Path $protocolKey -Name '(Default)' -Value 'URL:Isolation Bytes Pairing' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $protocolKey -Name 'URL Protocol' -Value '' -PropertyType String -Force | Out-Null
    New-Item -Path "$protocolKey\shell\open\command" -Force | Out-Null
    New-ItemProperty -Path "$protocolKey\shell\open\command" -Name '(Default)' -Value "`"$agentExe`" `"%1`"" -PropertyType String -Force | Out-Null

    if (-not $PairCode -and -not $ApiKey) {
        $PairCode = Read-Host 'Enter the one-time pairing code from the website (leave blank for API key)'
    }
    if (-not $PairCode -and -not $ApiKey) { $ApiKey = Read-Host 'Enter your CLOUD_API_KEY' }
    if (-not $PairCode -and -not $ApiKey) { throw 'A pairing code or CLOUD_API_KEY is required to connect this PC' }
    $credentialFile = Join-Path $agentDir 'device.token'
    if ($PairCode) {
        $agentArgs = "--server `"$BaseUrl`" --pair-code `"$($PairCode.Trim())`" --credential-file `"$credentialFile`" --auto-start"
    } else {
        $keyFile = Join-Path $agentDir 'cloud_api_key.txt'
        [System.IO.File]::WriteAllText($keyFile, $ApiKey.Trim(), [System.Text.UTF8Encoding]::new($false))
        icacls $keyFile /inheritance:r /grant:r "$env:USERNAME:(R)" | Out-Null
        $agentArgs = "--server `"$BaseUrl`" --key-file `"$keyFile`" --auto-start"
    }
    $action = New-ScheduledTaskAction -Execute $agentExe -Argument $agentArgs
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host '  Network monitoring agent scheduled to start on login (admin privileges).'

    # Start it now
    $started = Start-Process -FilePath $agentExe -ArgumentList $agentArgs -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 3
    if ($started.HasExited -and $started.ExitCode -ne 0) {
        Write-Warning "Agent exited immediately with code $($started.ExitCode). Run it from a terminal to see the error."
    } else {
        Write-Host '  Network monitoring agent started.'
    }
} else {
    Write-Warning 'Agent executable was not installed; download it separately before expecting this PC to appear online.'
}

Write-Host ''
Write-Host 'Installation complete!' -ForegroundColor Green
Write-Host 'Isolation Bytes is available in your Start menu and on your Desktop.'