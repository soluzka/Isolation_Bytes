# Publish the MSI installer to Amazon S3
# Usage:
#   .\publish_s3.ps1 -Bucket "my-bucket" -Version "1.0.0"
param(
    [Parameter(Mandatory = $true)]
    [string]$Bucket,

    [string]$Version = "1.0.0",

    [string]$LocalFile = ".\dist\AntivirusServer.msi",

    [string]$KeyPrefix = "antivirus-server"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $LocalFile)) {
    throw "File not found: $LocalFile. Run .\build_msi.bat first."
}

$S3Key = "$KeyPrefix/$Version/AntivirusServer.msi"

Write-Host "Uploading $LocalFile to s3://$Bucket/$S3Key ..."
aws s3 cp $LocalFile "s3://$Bucket/$S3Key"

Write-Host "Making object public-read..."
aws s3api put-object-acl `
    --bucket $Bucket `
    --key $S3Key `
    --acl public-read

$Url = "https://$Bucket.s3.amazonaws.com/$S3Key"

Write-Host "Public package URL:"
Write-Host $Url
