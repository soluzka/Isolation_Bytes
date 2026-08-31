# Publish the MSI installer to Azure Blob Storage
# Usage:
#   .\publish_azure_blob.ps1 -AccountName "myaccount" -ContainerName "downloads" -Version "1.0.0"
param(
    [Parameter(Mandatory = $true)]
    [string]$AccountName,

    [Parameter(Mandatory = $true)]
    [string]$ContainerName,

    [string]$Version = "1.0.0",

    [string]$LocalFile = ".\dist\AntivirusServer.msi",

    [string]$BlobPrefix = "antivirus-server"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $LocalFile)) {
    throw "File not found: $LocalFile. Run .\build_msi.bat first."
}

$BlobName = "$BlobPrefix/$Version/AntivirusServer.msi"

Write-Host "Uploading $LocalFile to Azure Blob..."
az storage blob upload `
    --file $LocalFile `
    --account-name $AccountName `
    --container-name $ContainerName `
    --name $BlobName `
    --auth-mode login

Write-Host "Getting public URL..."
$Url = az storage blob url `
    --account-name $AccountName `
    --container-name $ContainerName `
    --name $BlobName `
    --protocol https

Write-Host "Public package URL:"
Write-Host $Url
