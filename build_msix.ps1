# Build the AntivirusServer Store and Test Launcher MSIX packages from the
# PyInstaller onedir at dist\antivirus_server, then sign them.
# The Store package is signed with soluzka.pfx (Publisher: Soluzka) for upload
# to Microsoft Partner Center. Partner Center will re-sign it with the official
# Store cert.
# The Test Launcher package is signed with soluzka_test.pfx and that cert is
# trusted, so it will install and launch locally.
# Run this from the repo root (same directory as build_config.py) as Administrator.
[CmdletBinding(PositionalBinding=$false)]
param(
    [switch]$SkipBuild,
    [switch]$SkipStore,
    [switch]$SkipTest,
    [switch]$NoCertManagement,
    [Parameter(Mandatory=$false)]
    [string]$StoreCertFile,
    [Parameter(Mandatory=$false)]
    [string]$StoreCertPassword,
    [Parameter(Mandatory=$false)]
    [string]$StorePublisher = 'CN=soluzka',
    [Parameter(ValueFromRemainingArguments=$true, Position=0)]
    [string[]]$RemainingArguments
)

if ($RemainingArguments) {
    Write-Warning "Unexpected extra arguments were ignored: $RemainingArguments"
}

# Always run from the script's own directory so relative paths work.
Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $NoCertManagement -and -not $isAdmin) {
    # Prompt for UAC elevation and re-run this script as Administrator so it
    # can trust the certificate, install, and launch the MSIX automatically.
    $reArgs = @('-ExecutionPolicy', 'Bypass', '-File', $MyInvocation.MyCommand.Path)
    if ($SkipBuild) { $reArgs += '-SkipBuild' }
    if ($SkipStore) { $reArgs += '-SkipStore' }
    if ($SkipTest) { $reArgs += '-SkipTest' }
    if ($StoreCertFile) { $reArgs += '-StoreCertFile', $StoreCertFile }
    if ($StoreCertPassword) { $reArgs += '-StoreCertPassword', $StoreCertPassword }
    if ($StorePublisher -ne 'CN=soluzka') { $reArgs += '-StorePublisher', $StorePublisher }

    Write-Host 'Requesting Administrator privileges via UAC...'
    $stdOut = Join-Path $env:TEMP 'antivirus_server_elevate_out.log'
    $stdErr = Join-Path $env:TEMP 'antivirus_server_elevate_err.log'
    try {
        $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $reArgs -Verb 'RunAs' -Wait -PassThru -RedirectStandardOutput $stdOut -RedirectStandardError $stdErr
        if (Test-Path $stdOut) { Write-Host (Get-Content -Path $stdOut -Raw) }
        if (Test-Path $stdErr) { $err = Get-Content -Path $stdErr -Raw; if ($err) { Write-Warning $err } }
        exit $proc.ExitCode
    } catch {
        if (Test-Path $stdOut) { Write-Host (Get-Content -Path $stdOut -Raw) }
        if (Test-Path $stdErr) { $err = Get-Content -Path $stdErr -Raw; if ($err) { Write-Warning $err } }
        throw "Could not elevate to Administrator. Run PowerShell as Administrator, or use -NoCertManagement to pack/sign only."
    } finally {
        Remove-Item -Path $stdOut, $stdErr -ErrorAction SilentlyContinue
    }
}

$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$Dist = Join-Path $Root 'dist'
$Onedir = Join-Path $Dist 'antivirus_server'
$Sdk = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64'
$MakeAppx = Join-Path $Sdk 'makeappx.exe'
$SignTool = Join-Path $Sdk 'signtool.exe'
$Mt = Join-Path $Sdk 'mt.exe'

if (-not (Test-Path $Onedir)) {
    throw "dist\antivirus_server not found. Run 'python build_config.py' first."
}

if (-not (Test-Path $MakeAppx) -or -not (Test-Path $SignTool)) {
    throw "Windows SDK 10.0.22621.0 tools not found at $Sdk"
}

if ($StoreCertFile -and -not (Test-Path $StoreCertFile)) {
    Write-Warning "Store cert file not found at $StoreCertFile; using default soluzka.pfx."
    $StoreCertFile = $null
}

if ($StoreCertFile) {
    $StorePfx = $StoreCertFile
} else {
    $StorePfx = Join-Path $Root 'soluzka.pfx'
}

if (-not (Test-Path $StorePfx)) { throw "Store .pfx not found at $StorePfx" }

$TestPfx = Join-Path $Root 'soluzka_test.pfx'
if (-not $SkipTest -and -not (Test-Path $TestPfx)) {
    Write-Warning "soluzka_test.pfx not found at $TestPfx; skipping Test Launcher."
    $SkipTest = $true
}

function Read-PfxSubject($Pfx, [SecureString]$Password) {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Pfx, $Password)
    return $cert
}

if ($StoreCertPassword) {
    $StorePassword = ConvertTo-SecureString -String $StoreCertPassword -AsPlainText -Force
} else {
    $StorePassword = ConvertTo-SecureString -String 'password' -AsPlainText -Force
}
$StoreCert = Read-PfxSubject $StorePfx $StorePassword

# If the real cert has a different publisher in its subject, use that when provided.
if ($StorePublisher -eq 'CN=soluzka' -and $StoreCert.Subject) {
    $StorePublisher = $StoreCert.Subject
}

if (-not $SkipTest) {
    $TestPassword = ConvertTo-SecureString -String 'Test1234!' -AsPlainText -Force
    $TestCert = Read-PfxSubject $TestPfx $TestPassword
}

function Export-PublicCer($Cert, $OutPath) {
    $bytes = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [System.IO.File]::WriteAllBytes($OutPath, $bytes)
}

$StoreCer = Join-Path $Root 'soluzka.cer'
Export-PublicCer $StoreCert $StoreCer

if (-not $SkipTest) {
    $TestCer = Join-Path $Root 'soluzka_test.cer'
    Export-PublicCer $TestCert $TestCer
}

if (-not $NoCertManagement) {
    Write-Host 'Managing certificate trust...'

    # Trust the store certificate in the machine stores so the package is
    # installable/launchable locally for testing. Partner Center will re-sign
    # the Store package with the official Store certificate when it is published.
    $stores = @(
        'Cert:\CurrentUser\Root',
        'Cert:\CurrentUser\TrustedPeople',
        'Cert:\LocalMachine\Root',
        'Cert:\LocalMachine\TrustedPeople'
    )

    # Remove any stale duplicates first.
    $certs = @($StoreCert)
    if (-not $SkipTest) { $certs += $TestCert }
    foreach ($cert in $certs) {
        foreach ($store in $stores) {
            try {
                Get-ChildItem $store | Where-Object { $_.Subject -eq $cert.Subject -or $_.Thumbprint -eq $cert.Thumbprint } | Remove-Item -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Could not clean $store : $_"
            }
        }
    }

    # Store cert (soluzka) - makes the Store MSIX installable/launchable locally for testing.
    Import-Certificate -FilePath $StoreCer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Import-Certificate -FilePath $StoreCer -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
    Import-Certificate -FilePath $StoreCer -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    Import-Certificate -FilePath $StoreCer -CertStoreLocation 'Cert:\CurrentUser\TrustedPeople' | Out-Null
    Write-Host '  soluzka (store) cert added to trust stores.'

    if (-not $SkipTest) {
        # Test cert (soluzka_test) - makes the Test Launcher MSIX installable/launchable locally.
        Import-Certificate -FilePath $TestCer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
        Import-Certificate -FilePath $TestCer -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
        Import-Certificate -FilePath $TestCer -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
        Import-Certificate -FilePath $TestCer -CertStoreLocation 'Cert:\CurrentUser\TrustedPeople' | Out-Null
        Write-Host '  soluzka_test (test) cert added to trust stores.'
    }
}

# The onedir EXE is expected to be built already (e.g. by build_config.py).
# This script only packages and signs it.

# Stage the package contents in a temp directory so makeappx has a clean root.
$StageRoot = Join-Path $env:TEMP 'antivirus_server_msix'
if (Test-Path $StageRoot) {
    Remove-Item -Recurse -Force $StageRoot
}
New-Item -ItemType Directory -Path $StageRoot | Out-Null

Write-Host 'Staging dist\antivirus_server ...'
Copy-Item -Path "$Onedir\*" -Destination $StageRoot -Recurse -Force

# MSIX packaged full-trust apps cannot launch an EXE that requests
# requireAdministrator. Strip the UAC admin manifest from the staged copies
# so the Store package can start, while leaving dist\antivirus_server\antivirus_server.exe
# with its admin manifest for the standalone desktop EXE.
if (Test-Path $Mt) {
    $stageExes = Get-ChildItem -Path $StageRoot -Filter '*.exe' -File -Recurse
    foreach ($exe in $stageExes) {
        # mt.exe will merge any <base>.exe.manifest file found next to the EXE,
        # so remove side-by-side manifests first to avoid "level" mismatches.
        $sideBySide = "$($exe.FullName).manifest"
        if (Test-Path $sideBySide) { Remove-Item -Path $sideBySide -Force }

        $StageManifest = Join-Path $StageRoot "$($exe.BaseName).manifest"
        $StageManifestTmp = "$StageManifest.tmp"

        & $Mt -nologo -inputresource:"$($exe.FullName);#1" -out:$StageManifestTmp
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $StageManifestTmp)) { throw "mt.exe failed to extract manifest from $($exe.FullName)" }

        $manifest = Get-Content -Path $StageManifestTmp -Raw
        if ($manifest -notmatch 'requireAdministrator' -and $manifest -notmatch 'level\s*=\s*"highestAvailable"') {
            Remove-Item -Path $StageManifestTmp -ErrorAction SilentlyContinue
            continue
        }
        # Force every requested execution level to asInvoker so they all match.
        $manifest = $manifest -replace 'level\s*=\s*"requireAdministrator"', 'level="asInvoker"'
        $manifest = $manifest -replace 'level\s*=\s*"highestAvailable"', 'level="asInvoker"'
        $manifest = $manifest -replace 'uiAccess\s*=\s*"true"', 'uiAccess="false"'
        $manifest | Set-Content -Path $StageManifest -Encoding utf8 -NoNewline

        # Output the manifest resource from scratch so mt does not try to merge.
        & $Mt -nologo -manifest $StageManifest -outputresource:"$($exe.FullName);#1"
        if ($LASTEXITCODE -ne 0) { throw "mt.exe failed to update manifest for $($exe.FullName)" }

        Remove-Item -Path $StageManifest, $StageManifestTmp -ErrorAction SilentlyContinue
        Write-Host "  Set manifest to asInvoker for: $($exe.Name)"
    }
} else {
    Write-Warning 'mt.exe not found in SDK; staged EXEs still have admin manifests. The MSIX may fail to launch.'
}

# Create a simple placeholder 256x256 PNG logo.
$Assets = Join-Path $StageRoot 'Assets'
New-Item -ItemType Directory -Path $Assets | Out-Null

Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap(256, 256)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.Clear([System.Drawing.Color]::DarkCyan)
$g.Dispose()
$logo = Join-Path $Assets 'Logo.png'
$bmp.Save($logo, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()

function New-AppxManifest($Path, $PackageName, $Publisher, $PublisherDisplayName, $DisplayName, $Version) {
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap rescap">
  <Identity Name="$PackageName" Publisher="$Publisher" Version="$Version" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>$DisplayName</DisplayName>
    <PublisherDisplayName>$PublisherDisplayName</PublisherDisplayName>
    <Logo>Assets\Logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.22621.0" />
  </Dependencies>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
  <Applications>
    <Application Id="App" Executable="antivirus_server.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="$DisplayName" Description="$DisplayName"
                          BackgroundColor="transparent"
                          Square150x150Logo="Assets\Logo.png"
                          Square44x44Logo="Assets\Logo.png" />
    </Application>
  </Applications>
</Package>
"@
    $xml | Out-File -FilePath $Path -Encoding utf8
}

if (-not $SkipStore) {
    $now = Get-Date
    $days = ($now - [DateTime]::new(2024, 1, 1)).Days
    $minutes = $now.Hour * 60 + $now.Minute
    $Version = "1.0.$days.$minutes"

    # Build the Store package (soluzka cert) for Partner Center.
    $StoreMsix = Join-Path $Dist 'AntivirusServer_Store.msix'
    $StoreManifest = Join-Path $StageRoot 'AppxManifest.xml'
    New-AppxManifest -Path $StoreManifest `
        -PackageName 'soluzka.AntivirusServer' `
        -Publisher $StorePublisher `
        -PublisherDisplayName 'soluzka' `
        -DisplayName 'Antivirus Server' `
        -Version $Version

    Write-Host 'Packing Store MSIX...'
    & $MakeAppx pack /d $StageRoot /p $StoreMsix /nv /o
    if ($LASTEXITCODE -ne 0) { throw "makeappx failed for Store package" }

    Write-Host 'Signing Store MSIX (placeholder for Partner Center)...'
    & $SignTool sign /f $StorePfx /p 'password' /fd sha256 $StoreMsix
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for Store package" }

    Write-Host 'Verifying Store MSIX signature...'
    & $SignTool verify /pa $StoreMsix
    if ($LASTEXITCODE -ne 0) { throw "signtool verify failed for Store package" }
}

if (-not $SkipTest) {
    # Build the Test Launcher package (soluzka_test cert) for local install.
    $TestMsix = Join-Path $Dist 'AntivirusServer_Test_Launcher.msix'
    $TestManifest = Join-Path $StageRoot 'AppxManifest.xml'
    New-AppxManifest -Path $TestManifest `
        -PackageName 'soluzka.AntivirusServer.Test' `
        -Publisher $TestCert.Subject `
        -PublisherDisplayName 'soluzka test' `
        -DisplayName 'Antivirus Server Test Launcher' `
        -Version $Version

    Write-Host 'Packing Test Launcher MSIX...'
    & $MakeAppx pack /d $StageRoot /p $TestMsix /nv /o
    if ($LASTEXITCODE -ne 0) { throw "makeappx failed for Test Launcher package" }

    Write-Host 'Signing Test Launcher MSIX...'
    & $SignTool sign /f $TestPfx /p 'Test1234!' /fd sha256 $TestMsix
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for Test Launcher package" }
}

Write-Host "Done. MSIX files are in:"
if (-not $SkipStore) { Write-Host "  $StoreMsix" }
if (-not $SkipTest) { Write-Host "  $TestMsix" }

# Create a redistributable sideload installer script for other machines.
if (-not $SkipStore) {
    Copy-Item -Path $StoreCer -Destination (Join-Path $Dist 'soluzka.cer') -Force

    $InstallPs1 = Join-Path $Dist 'Install_AntivirusServer.ps1'
    @"
# Trust the package certificate and install the MSIX.
# Run this PowerShell as Administrator on the target machine.
`$ErrorActionPreference = 'Stop'
`$package = Join-Path `$PSScriptRoot 'AntivirusServer_Store.msix'
`$cert = Join-Path `$PSScriptRoot 'soluzka.cer'

Import-Certificate -FilePath `$cert -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Import-Certificate -FilePath `$cert -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
Import-Certificate -FilePath `$cert -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
Import-Certificate -FilePath `$cert -CertStoreLocation 'Cert:\CurrentUser\TrustedPeople' | Out-Null

Add-AppxPackage -Path `$package
Write-Host 'Antivirus Server installed. Start it from the Start menu or desktop shortcut.'
"@ | Out-File -FilePath $InstallPs1 -Encoding utf8

    $InstallBat = Join-Path $Dist 'Install_AntivirusServer.bat'
    @"
@echo off
powershell -ExecutionPolicy Bypass -File "%~dp0Install_AntivirusServer.ps1"
pause
"@ | Out-File -FilePath $InstallBat -Encoding ascii

    Write-Host "Sideload installer created:"
    Write-Host "  $InstallBat"
    Write-Host "  $InstallPs1"
    Write-Host "  $(Join-Path $Dist 'soluzka.cer')"
}

# Hide the standalone onedir in AppData\Local and create a desktop shortcut.
# This keeps the desktop clean while still allowing direct launch of the EXE.
$Desktop = [Environment]::GetFolderPath('Desktop')
$LocalAppDir = Join-Path $env:LOCALAPPDATA 'antivirus_server'
$ExeSource = Join-Path $Onedir 'antivirus_server.exe'
$InstalledExe = Join-Path $LocalAppDir 'antivirus_server.exe'
$DesktopExe = $InstalledExe
if (Test-Path $ExeSource) {
    if (Test-Path $LocalAppDir) {
        Remove-Item -Recurse -Force $LocalAppDir
    }
    Copy-Item -Path $Onedir -Destination $LocalAppDir -Recurse -Force
    $InternalDir = Join-Path $LocalAppDir '_internal'
    if (Test-Path $InternalDir) {
        $item = Get-Item $InternalDir -Force
        $item.Attributes = $item.Attributes -bor [System.IO.FileAttributes]::Hidden
        Get-ChildItem -Path $InternalDir -Recurse -Force | ForEach-Object {
            $_.Attributes = $_.Attributes -bor [System.IO.FileAttributes]::Hidden
        }
        Write-Host "Set _internal and all contents to Hidden: $InternalDir"
    }
    $Wsh = New-Object -ComObject WScript.Shell
    $Shortcut = $Wsh.CreateShortcut((Join-Path $Desktop 'Antivirus Server (standalone).lnk'))
    $Shortcut.TargetPath = $InstalledExe
    $Shortcut.IconLocation = "$InstalledExe,0"
    $Shortcut.WorkingDirectory = $LocalAppDir
    $Shortcut.Description = 'Antivirus Server (standalone)'
    $Shortcut.Save()
    Write-Host "Copied standalone onedir to: $LocalAppDir"
    Write-Host "Created desktop shortcut: Antivirus Server (standalone).lnk"
} else {
    Write-Warning "antivirus_server.exe not found at $ExeSource; nothing copied."
}

# Install the Store package if running as Administrator; otherwise print instructions.
if (-not $SkipStore) {
    if ($isAdmin) {
        Write-Host "Installing Store MSIX..."
        Get-Process -Name 'antivirus_server' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Get-AppxPackage -Name 'soluzka.AntivirusServer' | Remove-AppxPackage -ErrorAction SilentlyContinue
        Add-AppxPackage -Path $StoreMsix -ForceApplicationShutdown -ForceUpdateFromAnyVersion -ErrorAction Stop
        Write-Host "Installed $StoreMsix"
        # Launch the installed app by AUMID.
        $InstalledPkg = Get-AppxPackage -Name 'soluzka.AntivirusServer'
        $Aumid = $InstalledPkg.PackageFamilyName + '!App'
        Write-Host "AUMID: $Aumid"
        try {
            Start-Process "explorer.exe" "shell:AppsFolder\$Aumid"
            Write-Host "Launched Antivirus Server."
        } catch {
            Write-Warning "Could not auto-launch the app: $_"
        }

        # Create a desktop shortcut to the installed Store app.
        $Wsh = New-Object -ComObject WScript.Shell
        $Shortcut = $Wsh.CreateShortcut((Join-Path $Desktop 'Antivirus Server.lnk'))
        $Shortcut.TargetPath = "$env:SystemRoot\explorer.exe"
        $Shortcut.Arguments = "shell:AppsFolder\$Aumid"
        if (Test-Path $DesktopExe) {
            $Shortcut.IconLocation = "$DesktopExe,0"
        }
        $Shortcut.Description = 'Antivirus Server'
        $Shortcut.Save()
        Write-Host "Desktop shortcut created: Antivirus Server.lnk"
    } else {
        Write-Host "Install the Store MSIX (run as Administrator) with:"
        Write-Host "  Add-AppxPackage -Path '$StoreMsix'"
    }
}

# If the desktop EXE was copied and we are not installing the MSIX, start the EXE so it also launches.
if (-not $SkipStore -and -not $isAdmin -and (Test-Path $DesktopExe)) {
    Write-Host "Desktop EXE is ready. Start it manually with:"
    Write-Host "  & '$DesktopExe'"
}

if ($SkipStore -and (Test-Path $DesktopExe)) {
    Write-Host "Starting the desktop EXE..."
    Start-Process $DesktopExe
}

if (-not $NoCertManagement -and -not $SkipTest) {
    Write-Host "Install the test launcher with:"
    Write-Host "  Add-AppxPackage -Path '$TestMsix'"
}


