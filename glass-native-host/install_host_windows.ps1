param(
    [Parameter(Mandatory = $true)]
    [string]$ExtensionId
)

$ErrorActionPreference = "Stop"

$cleanId = $ExtensionId.Trim()
if ($cleanId -match "^chrome-extension://") {
    $cleanId = $cleanId -replace "^chrome-extension://", ""
}
$cleanId = $cleanId.TrimEnd("/")
if (-not $cleanId) {
    throw "Extension ID is required."
}

$hostDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$batPath = Join-Path $hostDir "host.bat"
if (-not (Test-Path $batPath)) {
    throw "host.bat not found at $batPath"
}

$manifestDir = Join-Path $env:LOCALAPPDATA "Glass"
New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
$manifestPath = Join-Path $manifestDir "glass-scanner-manifest.json"

$manifest = @{
    name = "com.glass.scanner"
    description = "Glass local malware scanner for downloads"
    path = $batPath
    type = "stdio"
    allowed_origins = @("chrome-extension://$cleanId/")
}

$json = $manifest | ConvertTo-Json
$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($manifestPath, $json, $utf8)

$regPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.glass.scanner"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "(default)" -Value $manifestPath

Write-Host "Wrote native host manifest:"
Write-Host "  $manifestPath"
Write-Host "Registered:"
Write-Host "  $regPath"
Write-Host "Allowed origin:"
Write-Host "  chrome-extension://$cleanId/"
