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
    [switch]$IncludeLocalModel,
    [switch]$NoCertManagement,
    [Parameter(Mandatory=$false)]
    [string]$BuildDist,
    [Parameter(Mandatory=$false)]
    [string]$StoreCertFile,
    [Parameter(Mandatory=$false)]
    [SecureString]$StoreCertPassword,
    [Parameter(Mandatory=$false)]
    [string]$StorePublisher = 'CN=soluzka',
    [string]$StoreVersion,
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
    if ($IncludeLocalModel) { $reArgs += '-IncludeLocalModel' }
    if ($BuildDist) { $reArgs += '-BuildDist', $BuildDist }
    if ($StoreCertFile) { $reArgs += '-StoreCertFile', $StoreCertFile }
    if ($StoreCertPassword) {
        # UAC re-elevation requires a plain string for the command line; extract and zero the BSTR immediately.
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($StoreCertPassword)
        try {
            $reArgs += '-StoreCertPassword', [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    if ($StorePublisher -ne 'CN=soluzka') { $reArgs += '-StorePublisher', $StorePublisher }
    if ($StoreVersion) { $reArgs += '-StoreVersion', $StoreVersion }

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
$Dist = if ($BuildDist) { $BuildDist } elseif ($env:ANTIVIRUS_BUILD_DIST) { $env:ANTIVIRUS_BUILD_DIST } else { Join-Path $Root 'dist' }
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
    $StorePassword = $StoreCertPassword
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

# Keep the optional multi-gigabyte assistant model out of the signed MSIX by
# default. The onedir installer can carry it separately without enlarging the
# Store package beyond Windows signing tool limits.
if (-not $IncludeLocalModel) {
    $MsixAssistantModel = Join-Path $StageRoot 'models\assistant.gguf'
    if (Test-Path $MsixAssistantModel) {
        Remove-Item -Force $MsixAssistantModel
        Write-Host 'Excluded models\assistant.gguf from MSIX.'
    }
}

# Keep administrator-only unpacked helpers out of the MSIX. They are installed
# by the traditional MSI/Inno installers and cannot be elevated from a package.
$MsixAdminHelper = Join-Path $StageRoot 'AntivirusServer_AdminHelper.exe'
if (Test-Path $MsixAdminHelper) { Remove-Item -Force $MsixAdminHelper }
$MsixSsdeepRunner = Join-Path $StageRoot '_internal\ssdeep_runner.exe'
if (Test-Path $MsixSsdeepRunner) { Remove-Item -Force $MsixSsdeepRunner }

# The EXE is intentionally built as asInvoker for MSIX compatibility. Windows
# does not support requireAdministrator for packaged full-trust applications.
# Do not rewrite the embedded PyInstaller executable manifest after packaging.
Write-Host "Using EXE as-is (asInvoker) for MSIX packaging."

# Create a simple placeholder 256x256 PNG logo.
$Assets = Join-Path $StageRoot 'Assets'
New-Item -ItemType Directory -Path $Assets -Force | Out-Null

Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap(256, 256)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.Clear([System.Drawing.Color]::DarkCyan)
$g.Dispose()
$logo = Join-Path $Assets 'Logo.png'
$bmp.Save($logo, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
if (-not (Test-Path $logo)) { throw "MSIX logo was not created: $logo" }

function New-AppxManifest($Path, $PackageName, $Publisher, $PublisherDisplayName, $DisplayName, $Version) {
    if ([string]::IsNullOrWhiteSpace($PublisherDisplayName)) {
        $PublisherDisplayName = 'soluzka'
    }
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap5="http://schemas.microsoft.com/appx/manifest/uap/windows10/5"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap uap5 rescap">
  <Identity Name="$PackageName" Publisher="$Publisher" Version="$Version" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>$DisplayName</DisplayName>
    <PublisherDisplayName>$PublisherDisplayName</PublisherDisplayName>
    <Logo>Assets\Logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.22621.0" />
  </Dependencies>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
  <Applications>
    <Application Id="App" Executable="antivirus_server.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="$DisplayName" Description="$DisplayName"
                          BackgroundColor="transparent"
                          Square150x150Logo="Assets\Logo.png"
                          Square44x44Logo="Assets\Logo.png" />
      <Extensions>
        <uap5:Extension Category="windows.appExecutionAlias">
          <uap5:AppExecutionAlias>
            <uap5:ExecutionAlias Alias="antivirus-server.exe" />
          </uap5:AppExecutionAlias>
        </uap5:Extension>
      </Extensions>
    </Application>
  </Applications>
</Package>
"@
    $xml | Out-File -FilePath $Path -Encoding utf8
}

if (-not $SkipStore) {
    $now = Get-Date
    $days = ($now - [DateTime]::new(2024, 1, 1)).Days
    # Partner Center requires the revision component to be zero. Supply a
    # higher -StoreVersion when publishing more than one build on the same day.
    if (-not $StoreVersion) { $StoreVersion = "1.0.$days.0" }
    if ($StoreVersion -notmatch '^\d+\.\d+\.\d+\.0$') {
        throw "StoreVersion must use four numeric components and end in .0, for example 1.0.958.0"
    }
    $Version = $StoreVersion

    # Build the Store package (soluzka cert) for Partner Center.
    $StoreMsix = Join-Path $Dist 'AntivirusServer_Store.msix'
    # Build outside OneDrive, then copy the completed package into dist. This
    # prevents MakeAppx from encountering transient sync/path errors while it
    # creates and overwrites the package.
    $StoreMsixBuild = Join-Path $env:TEMP 'AntivirusServer_Store.msix'
    $StoreManifest = Join-Path $StageRoot 'AppxManifest.xml'
    New-AppxManifest -Path $StoreManifest `
        -PackageName 'soluzka.AntivirusServer' `
        -Publisher $StorePublisher `
        -PublisherDisplayName 'soluzka' `
        -DisplayName 'Antivirus Server' `
        -Version $Version

    Write-Host 'Packing Store MSIX...'
    if (Test-Path $StoreMsixBuild) { Remove-Item -Force $StoreMsixBuild }
    & $MakeAppx pack /d $StageRoot /p $StoreMsixBuild /nv /o
    if ($LASTEXITCODE -ne 0) { throw "makeappx failed for Store package" }

    Write-Host 'Signing Store MSIX (placeholder for Partner Center)...'
    & $SignTool sign /f $StorePfx /p 'password' /fd sha256 $StoreMsixBuild
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for Store package" }

    Write-Host 'Verifying Store MSIX signature...'
    if ($NoCertManagement) {
        Write-Host 'Skipping trust-chain verification because -NoCertManagement was specified.'
        Write-Host 'The package was signed; install soluzka.cer before local installation.'
    } else {
        Write-Host 'Verifying Store MSIX signature against the trusted certificate...'
        & $SignTool verify /pa $StoreMsixBuild
        if ($LASTEXITCODE -ne 0) { throw "signtool verify failed for Store package" }
    }
    Copy-Item -Path $StoreMsixBuild -Destination $StoreMsix -Force
}

if (-not $SkipTest) {
    # Build the Test Launcher package (soluzka_test cert) for local install.
    $TestMsix = Join-Path $Dist 'AntivirusServer_Test_Launcher.msix'
    $TestMsixBuild = Join-Path $env:TEMP 'AntivirusServer_Test_Launcher.msix'
    $TestManifest = Join-Path $StageRoot 'AppxManifest.xml'
    New-AppxManifest -Path $TestManifest `
        -PackageName 'soluzka.AntivirusServer.Test' `
        -Publisher $TestCert.Subject `
        -PublisherDisplayName 'soluzka test' `
        -DisplayName 'Antivirus Server Test Launcher' `
        -Version $Version

    Write-Host 'Packing Test Launcher MSIX...'
    if (Test-Path $TestMsixBuild) { Remove-Item -Force $TestMsixBuild }
    & $MakeAppx pack /d $StageRoot /p $TestMsixBuild /nv /o
    if ($LASTEXITCODE -ne 0) { throw "makeappx failed for Test Launcher package" }

    Write-Host 'Signing Test Launcher MSIX...'
    & $SignTool sign /f $TestPfx /p 'Test1234!' /fd sha256 $TestMsixBuild
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for Test Launcher package" }
    Copy-Item -Path $TestMsixBuild -Destination $TestMsix -Force
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
# Elevate automatically when launched directly rather than from the EXE installer.
`$ErrorActionPreference = 'Stop'
`$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not `$isAdmin) {
    `$proc = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', `$PSCommandPath)
    exit `$proc.ExitCode
}
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
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0Install_AntivirusServer.ps1\"'"
pause
"@ | Out-File -FilePath $InstallBat -Encoding ascii

    Write-Host "Sideload installer created:"
    Write-Host "  $InstallBat"
    Write-Host "  $InstallPs1"
    Write-Host "  $(Join-Path $Dist 'soluzka.cer')"
}

$script:ShortcutRunAsLoaded = $false
function Set-ShortcutRunAs($Path) {
    if (-not $script:ShortcutRunAsLoaded) {
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;

            [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
            public class ShellLink { }

            [ComImport, Guid("45E2B4AE-B1C3-11D0-B92F-00A0C90312E1"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
            public interface IShellLinkDataList {
                void GetFlags(out uint dwFlags);
                void SetFlags(uint dwFlags);
                void AddDataBlock(IntPtr pDataBlock);
                void CopyDataBlock(uint dwSig, out IntPtr ppDataBlock);
                void RemoveDataBlock(uint dwSig);
            }

            [ComImport, Guid("0000010B-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
            public interface IPersistFile {
                void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, uint dwMode);
                void Save([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, [MarshalAs(UnmanagedType.Bool)] bool fRemember);
            }

            public class ShortcutRunAs {
                public const uint SLDF_RUNAS_USER = 0x00002000;
                public static void Set(string path) {
                    Update(path, true);
                }
                public static void Clear(string path) {
                    Update(path, false);
                }
                private static void Update(string path, bool runAs) {
                    var sl = new ShellLink();
                    var pf = (IPersistFile)sl;
                    pf.Load(path, 2);
                    var dl = (IShellLinkDataList)sl;
                    uint flags;
                    dl.GetFlags(out flags);
                    if (runAs) flags |= SLDF_RUNAS_USER;
                    else flags &= ~SLDF_RUNAS_USER;
                    dl.SetFlags(flags);
                    pf.Save(path, true);
                }
            }
"@
        $script:ShortcutRunAsLoaded = $true
    }
    [ShortcutRunAs]::Set($Path)
}
function Clear-ShortcutRunAs($Path) {
    if (-not $script:ShortcutRunAsLoaded) { Set-ShortcutRunAs $Path }
    [ShortcutRunAs]::Clear($Path)
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
    # Hide the standalone launcher EXE and the root AppData folder too.
    $LauncherExe = Join-Path $LocalAppDir 'antivirus_server.exe'
    if (Test-Path $LauncherExe) {
        $exeItem = Get-Item $LauncherExe -Force
        $exeItem.Attributes = $exeItem.Attributes -bor [System.IO.FileAttributes]::Hidden
        Write-Host "Set launcher EXE to Hidden: $LauncherExe"
    }
    $rootItem = Get-Item $LocalAppDir -Force
    $rootItem.Attributes = $rootItem.Attributes -bor [System.IO.FileAttributes]::Hidden
    Write-Host "Set root app folder to Hidden: $LocalAppDir"
    $Wsh = New-Object -ComObject WScript.Shell
    $Shortcut = $Wsh.CreateShortcut((Join-Path $Desktop 'Antivirus Server (standalone).lnk'))
    $Shortcut.TargetPath = $InstalledExe
    $Shortcut.Arguments = ''
    $Shortcut.IconLocation = "$InstalledExe,0"
    $Shortcut.WorkingDirectory = $LocalAppDir
    $Shortcut.Description = 'Antivirus Server (standalone)'
    $Shortcut.Save()
    Set-ShortcutRunAs $Shortcut.FullName
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
        # Launch the packaged app through its registered MSIX AUMID. Windows
        # does not support RunAs/requireAdministrator for packaged full-trust apps.
        $InstalledPkg = Get-AppxPackage -Name 'soluzka.AntivirusServer'
        if (-not $InstalledPkg) { throw 'Installed MSIX package could not be located.' }
        $Aumid = $InstalledPkg.PackageFamilyName + '!App'
        Write-Host "AUMID: $Aumid"
        try {
            Start-Process -FilePath 'explorer.exe' -ArgumentList "shell:AppsFolder\$Aumid"
            Write-Host "Launched Antivirus Server through MSIX."
        } catch {
            Write-Warning "Could not auto-launch the MSIX app: $_"
        }

        # Create a desktop shortcut that launches the installed MSIX app.
        $Wsh = New-Object -ComObject WScript.Shell
        $Shortcut = $Wsh.CreateShortcut((Join-Path $Desktop 'Antivirus Server.lnk'))
        $Shortcut.TargetPath = 'explorer.exe'
        $Shortcut.Arguments = "shell:AppsFolder\$Aumid"
        if (Test-Path $DesktopExe) {
            $Shortcut.IconLocation = "$DesktopExe,0"
        }
        $Shortcut.Description = 'Antivirus Server'
        $Shortcut.Save()
        Clear-ShortcutRunAs $Shortcut.FullName
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


