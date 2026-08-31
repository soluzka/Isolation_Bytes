$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$assets = Join-Path $scriptDir "Assets"
Add-Type -AssemblyName System.Drawing

$sizes = @{
    "StoreLogo.png" = 50
    "Square150x150Logo.png" = 150
    "Square44x44Logo.png" = 44
    "Wide310x150Logo.png" = 310
    "LockScreenLogo.png" = 24
}

foreach ($entry in $sizes.GetEnumerator()) {
    $sz = [int]$entry.Value
    $bmp = New-Object System.Drawing.Bitmap($sz, $sz)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::FromArgb(11, 19, 33))
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(0, 180, 216))
    $fontSize = [float]($sz * 0.4)
    $font = New-Object System.Drawing.Font("Segoe UI", $fontSize, [System.Drawing.FontStyle]::Bold)
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = [System.Drawing.StringAlignment]::Center
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
    $rect = New-Object System.Drawing.RectangleF(0, 0, $sz, $sz)
    $g.DrawString("IB", $font, $brush, $rect, $sf)
    $path = Join-Path $assets $entry.Key
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
}

Write-Host "Assets created:"
Get-ChildItem $assets | Select-Object Name, Length
