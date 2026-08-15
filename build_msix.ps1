# Build the AntivirusServer Store and Test Launcher MSIX packages from the
# PyInstaller onedir at dist\antivirus_server, then sign them.
# The Store package is signed with soluzka.pfx (Publisher: Soluzka) for upload
# to Microsoft Partner Center. Partner Center will re-sign it with the official
# Store cert.
# The Test Launcher package is signed with soluzka_test.pfx and that cert is
# trusted, so it will install and launch locally.
# Run this from the repo root (same directory as build_config.py) as Administrator.
[CmdletBinding()]
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
    [Parameter(ValueFromRemainingArguments=$true)]
    [array]$RemainingArguments
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $NoCertManagement -and -not $isAdmin) {
    throw 'Administrator privileges are required to manage certificate trust. Run with -NoCertManagement to pack/sign only, or as Administrator.'
}

$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$Dist = Join-Path $Root 'dist'
$Onedir = Join-Path $Dist 'antivirus_server'
$Sdk = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64'
$MakeAppx = Join-Path $Sdk 'makeappx.exe'
$SignTool = Join-Path $Sdk 'signtool.exe'

if (-not (Test-Path $Onedir)) {
    throw "dist\antivirus_server not found. Run 'python build_config.py' first."
}

if (-not (Test-Path $MakeAppx) -or -not (Test-Path $SignTool)) {
    throw "Windows SDK 10.0.22621.0 tools not found at $Sdk"
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

# Re-run PyInstaller build unless skipped, so the EXE is fresh.
if (-not $SkipBuild) {
    Write-Host 'Running build_config.py to refresh EXE...'
    python (Join-Path $Root 'build_config.py')
    if ($LASTEXITCODE -ne 0) {
        throw "build_config.py failed with exit code $LASTEXITCODE"
    }
}

# Stage the package contents in a temp directory so makeappx has a clean root.
$StageRoot = Join-Path $env:TEMP 'antivirus_server_msix'
if (Test-Path $StageRoot) {
    Remove-Item -Recurse -Force $StageRoot
}
New-Item -ItemType Directory -Path $StageRoot | Out-Null

Write-Host 'Staging dist\antivirus_server ...'
Copy-Item -Path "$Onedir\*" -Destination $StageRoot -Recurse -Force

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

# Copy the standalone EXE to the desktop for easy access.
$Desktop = [Environment]::GetFolderPath('Desktop')
$ExeSource = Join-Path $Onedir 'antivirus_server.exe'
$DesktopExe = Join-Path $Desktop 'antivirus_server.exe'
if (Test-Path $ExeSource) {
    Copy-Item -Path $ExeSource -Destination $DesktopExe -Force
    Write-Host "Copied standalone EXE to desktop: $DesktopExe"
} else {
    Write-Warning "antivirus_server.exe not found at $ExeSource; nothing copied to desktop."
}

# Install the Store package if running as Administrator; otherwise print instructions.
if (-not $SkipStore) {
    if ($isAdmin) {
        Write-Host "Installing Store MSIX..."
        Add-AppxPackage -Path $StoreMsix
        Write-Host "Installed $StoreMsix"
        # Launch the installed app by AUMID.
        $Aumid = 'soluzka.AntivirusServer!App'
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

# Build the one-file installer EXE that bundles the cert and MSIX.
$InstallerBuilder = Join-Path $Root 'tools' 'build_installer_exe.py'
$OneFileInstaller = Join-Path $Dist 'Install_AntivirusServer.exe'
if (Test-Path $InstallerBuilder) {
    Write-Host "Building one-file installer EXE..."
    python $InstallerBuilder
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "One-file installer build failed."
    }
} else {
    Write-Warning "tools\build_installer_exe.py not found; skipping one-file installer build."
}

# Also run the one-file installer on the build machine so the package is
# installed through the same path an end user would use.
if ($isAdmin -and (Test-Path $OneFileInstaller)) {
    Write-Host "Running one-file installer on build machine..."
    Start-Process -FilePath $OneFileInstaller -Wait
    Write-Host "One-file installer completed."
}

# Copy the one-file installer EXE to the desktop so it is easy to find and distribute.
if (Test-Path $OneFileInstaller) {
    $DesktopInstaller = Join-Path $Desktop 'Install_AntivirusServer.exe'
    Copy-Item -Path $OneFileInstaller -Destination $DesktopInstaller -Force
    Write-Host "Copied one-file installer EXE to desktop: $DesktopInstaller"
}
