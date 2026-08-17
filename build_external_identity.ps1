# Build a sparse/external-location identity MSIX for the unpacked Antivirus Server.
# The real application and administrator helper remain outside the package.
[CmdletBinding(PositionalBinding=$false)]
param(
    [switch]$NoCertManagement,
    [string]$StoreCertFile,
    [string]$StorePublisher = 'CN=soluzka',
    [string]$StoreVersion
)

Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition)
$ErrorActionPreference = 'Stop'
$Root = (Get-Location).Path
$Dist = if ($env:ANTIVIRUS_BUILD_DIST) { $env:ANTIVIRUS_BUILD_DIST } else { Join-Path $Root 'dist' }
$Onedir = Join-Path $Dist 'antivirus_server'
$Sdk = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64'
$MakeAppx = Join-Path $Sdk 'makeappx.exe'
$SignTool = Join-Path $Sdk 'signtool.exe'
$Pfx = if ($StoreCertFile) { $StoreCertFile } else { Join-Path $Root 'soluzka.pfx' }
$StageRoot = Join-Path $env:TEMP 'antivirus_server_external_identity'
$IdentityMsix = Join-Path $Dist 'AntivirusServer_Identity.msix'

if (-not (Test-Path $Onedir)) { throw "Standalone bundle not found: $Onedir" }
if (-not (Test-Path $MakeAppx) -or -not (Test-Path $SignTool)) { throw "Windows SDK tools not found at $Sdk" }
if (-not (Test-Path $Pfx)) { throw "Signing certificate not found: $Pfx" }
if (Test-Path $StageRoot) { Remove-Item -Recurse -Force $StageRoot }
New-Item -ItemType Directory -Path (Join-Path $StageRoot 'Assets') -Force | Out-Null

Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap(256, 256)
$graphics = [System.Drawing.Graphics]::FromImage($bmp)
$graphics.Clear([System.Drawing.Color]::DarkCyan)
$graphics.Dispose()
$logo = Join-Path $StageRoot 'Assets\Logo.png'
$bmp.Save($logo, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
if (-not (Test-Path $logo)) { throw "Identity package logo was not created: $logo" }

$now = Get-Date
$days = ($now - [DateTime]::new(2024, 1, 1)).Days
if (-not $StoreVersion) { $StoreVersion = "1.0.$days.0" }
if ($StoreVersion -notmatch '^\d+\.\d+\.\d+\.0$') {
    throw "StoreVersion must use four numeric components and end in .0, for example 1.0.958.0"
}
$version = $StoreVersion
$manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package IgnorableNamespaces="uap uap5 uap10 rescap"
         xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap5="http://schemas.microsoft.com/appx/manifest/uap/windows10/5"
         xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="soluzka.AntivirusServer.External" Publisher="$StorePublisher" Version="$version" ProcessorArchitecture="neutral" />
  <Properties>
    <DisplayName>Antivirus Server</DisplayName>
    <PublisherDisplayName>soluzka</PublisherDisplayName>
    <Logo>Assets\Logo.png</Logo>
    <uap10:AllowExternalContent>true</uap10:AllowExternalContent>
  </Properties>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0" />
  </Dependencies>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
    <rescap:Capability Name="unvirtualizedResources" />
  </Capabilities>
  <Applications>
    <Application Id="AntivirusServer" Executable="antivirus_server.exe" uap10:TrustLevel="mediumIL" uap10:RuntimeBehavior="win32App">
      <uap:VisualElements AppListEntry="none" DisplayName="Antivirus Server" Description="Antivirus Server" BackgroundColor="transparent" Square150x150Logo="Assets\Logo.png" Square44x44Logo="Assets\Logo.png" />
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
$manifest | Out-File -FilePath (Join-Path $StageRoot 'AppxManifest.xml') -Encoding utf8

if (Test-Path $IdentityMsix) { Remove-Item -Force $IdentityMsix }
Write-Host "Packing external-location identity package..."
& $MakeAppx pack /d $StageRoot /p $IdentityMsix /nv /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed for external identity package" }

Write-Host "Signing external-location identity package..."
& $SignTool sign /f $Pfx /p 'password' /fd sha256 $IdentityMsix
if ($LASTEXITCODE -ne 0) { throw "signtool failed for external identity package" }

Write-Host "Created: $IdentityMsix"
if (-not $NoCertManagement) {
    Write-Host 'Registering identity package against the unpacked application folder...'
    $installRoot = Join-Path $env:ProgramFiles 'Antivirus Server'
    if (-not (Test-Path $installRoot)) { throw "External application folder not found: $installRoot" }
    Add-AppxPackage -Path $IdentityMsix -ExternalLocation $installRoot -ErrorAction Stop
    Write-Host "Registered external identity at: $installRoot"
}
