[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Install', 'Uninstall', 'Start', 'Stop', 'Restart', 'Status')]
    [string]$Action,
    [string]$Python = "",
    [string]$ProtectedScanRoots = "",
    [string]$QuarantineRestoreRoots = ""
)

# Manual, administrator-run lifecycle management.  This script never accepts
# a command line to execute; it invokes only the fixed service module below.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$module = Join-Path $repo 'windows_admin_service.py'
if (-not (Test-Path -LiteralPath $module -PathType Leaf)) {
    throw "Service module not found: $module"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window (Run as Administrator).'
}

if ([string]::IsNullOrWhiteSpace($Python)) {
    $Python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
}
if ([string]::IsNullOrWhiteSpace($Python)) {
    throw 'python.exe was not found. Pass -Python with the trusted interpreter used to install pywin32.'
}

function Invoke-ServiceModule {
    param([string[]]$Arguments)
    & $Python $module @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Service command failed with exit code $LASTEXITCODE"
    }
}

if ($ProtectedScanRoots -and $Action -eq 'Install') {
    $resolvedRoots = foreach ($root in $ProtectedScanRoots -split ';') {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        $resolved = Resolve-Path -LiteralPath $root -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
            throw "Protected scan root is not a directory: $root"
        }
        $resolved.Path
    }
    if (-not $resolvedRoots) {
        throw 'ProtectedScanRoots must contain at least one existing directory.'
    }
    [Environment]::SetEnvironmentVariable(
        'ANTIVIRUS_PROTECTED_SCAN_ROOTS',
        ($resolvedRoots -join ';'),
        [EnvironmentVariableTarget]::Machine
    )
    Write-Host 'Configured machine-level protected scan roots for the service.'
}

if ($QuarantineRestoreRoots -and $Action -eq 'Install') {
    $resolvedRestoreRoots = foreach ($root in $QuarantineRestoreRoots -split ';') {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        $resolved = Resolve-Path -LiteralPath $root -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
            throw "Quarantine restore root is not a directory: $root"
        }
        $resolved.Path
    }
    if (-not $resolvedRestoreRoots) {
        throw 'QuarantineRestoreRoots must contain at least one existing directory.'
    }
    [Environment]::SetEnvironmentVariable(
        'ANTIVIRUS_QUARANTINE_RESTORE_ROOTS',
        ($resolvedRestoreRoots -join ';'),
        [EnvironmentVariableTarget]::Machine
    )
    Write-Host 'Configured machine-level quarantine restore roots for the service.'
}

Push-Location $repo
try {
    switch ($Action) {
        'Install'   { Invoke-ServiceModule @('install', '--startup', 'auto') }
        'Uninstall' { Invoke-ServiceModule @('remove') }
        'Start'     { Invoke-ServiceModule @('start') }
        'Stop'      { Invoke-ServiceModule @('stop') }
        'Restart'   { Invoke-ServiceModule @('restart') }
        'Status'    { & sc.exe query AntivirusProtectedAdmin }
    }
}
finally {
    Pop-Location
}
