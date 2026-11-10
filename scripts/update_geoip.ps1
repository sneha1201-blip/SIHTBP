# ==============================================================================
# AICTE Cyber Security Cell | Smart India Hackathon 2026 (SIH ID: 26106)
# MaxMind GeoLite2-City and GeoLite2-ASN Database Updater (PowerShell)
# ==============================================================================

[CmdletBinding()]
param (
    [string]$LicenseKey = $env:MAXMIND_LICENSE_KEY
)

$ErrorActionPreference = "Stop"

if (-not $LicenseKey) {
    Write-Error "ERROR: MAXMIND_LICENSE_KEY is not set. Usage: .\scripts\update_geoip.ps1 -LicenseKey <your_key>"
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$TargetDir = Join-Path $ProjectRoot "backend\storage\geoip"

if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    Write-Host "Updating MaxMind GeoLite2 Databases..." -ForegroundColor Cyan

    # 1. GeoLite2-City
    Write-Host "[1/2] Downloading GeoLite2-City..." -ForegroundColor Green
    $CityUrl = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$LicenseKey&suffix=tar.gz"
    $CityTar = Join-Path $TempDir "GeoLite2-City.tar.gz"
    Invoke-WebRequest -Uri $CityUrl -OutFile $CityTar

    tar -xzf $CityTar -C $TempDir
    $CityMmdb = Get-ChildItem -Path $TempDir -Filter "GeoLite2-City.mmdb" -Recurse | Select-Object -First 1
    if ($CityMmdb) {
        Copy-Item -Path $CityMmdb.FullName -Destination (Join-Path $TargetDir "GeoLite2-City.mmdb") -Force
    }

    # 2. GeoLite2-ASN
    Write-Host "[2/2] Downloading GeoLite2-ASN..." -ForegroundColor Green
    $AsnUrl = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=$LicenseKey&suffix=tar.gz"
    $AsnTar = Join-Path $TempDir "GeoLite2-ASN.tar.gz"
    Invoke-WebRequest -Uri $AsnUrl -OutFile $AsnTar

    tar -xzf $AsnTar -C $TempDir
    $AsnMmdb = Get-ChildItem -Path $TempDir -Filter "GeoLite2-ASN.mmdb" -Recurse | Select-Object -First 1
    if ($AsnMmdb) {
        Copy-Item -Path $AsnMmdb.FullName -Destination (Join-Path $TargetDir "GeoLite2-ASN.mmdb") -Force
    }

    Write-Host "MaxMind GeoLite2 databases successfully updated at $TargetDir" -ForegroundColor Cyan
} finally {
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

