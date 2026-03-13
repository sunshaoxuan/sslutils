<#
.SYNOPSIS
Downloads and installs portable OpenSSL into utils/bin/ for the SSL Toolkit.

.DESCRIPTION
Checks whether OpenSSL is already installed in utils/bin/.
If not found, downloads a portable OpenSSL build and extracts it.

.PARAMETER Force
Re-download even if utils/bin/openssl.exe already exists.

.PARAMETER Lang
Display language (ja / zh / en). Defaults to saved preference or system default.

.EXAMPLE
.\utils\Install-Dependencies.ps1
Check and install OpenSSL if needed.

.EXAMPLE
.\utils\Install-Dependencies.ps1 -Force
Force re-download of OpenSSL.
#>

param(
  [switch]$Force,
  [string]$Lang = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ToolkitRoot = Split-Path -Parent $PSScriptRoot

$runtimeModule = Join-Path $PSScriptRoot "lib\runtime.ps1"
if (Test-Path -LiteralPath $runtimeModule -PathType Leaf) { . $runtimeModule }
Assert-ToolkitPowerShell

. (Join-Path $PSScriptRoot "lib\defaults.ps1")

$__langFile = Join-Path $ToolkitRoot ".toolkit_lang"
if ([string]::IsNullOrWhiteSpace($Lang)) {
  if (Test-Path -LiteralPath $__langFile -PathType Leaf) {
    $Lang = (Get-Content -LiteralPath $__langFile -Raw -ErrorAction SilentlyContinue).Trim()
  }
  if ([string]::IsNullOrWhiteSpace($Lang)) { $Lang = $__DefaultLang }
}

$i18nModule = Join-Path $PSScriptRoot "lib\i18n.ps1"
if (Test-Path -LiteralPath $i18nModule -PathType Leaf) {
  . $i18nModule
  $__i18n = Initialize-I18n -Lang $Lang -BaseDir $ToolkitRoot
}
function T([string]$Key, [object[]]$FormatArgs = @()) {
  if ($null -ne $__i18n) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }
  return $Key
}

$BinDir = Join-Path $PSScriptRoot "bin"
$OpenSslExe = Join-Path $BinDir "openssl.exe"

function Test-OpenSslWorks([string]$path) {
  try {
    $ver = & $path version 2>&1
    return ($LASTEXITCODE -eq 0 -and $ver -match "OpenSSL")
  }
  catch { return $false }
}

Write-Host ""
Write-Host (T "Deps.Title") -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Cyan
Write-Host ""

if (-not $Force) {
  if (Test-Path -LiteralPath $OpenSslExe -PathType Leaf) {
    if (Test-OpenSslWorks $OpenSslExe) {
      $ver = & $OpenSslExe version 2>&1
      Write-Host (T "Deps.AlreadyInstalled" @($OpenSslExe)) -ForegroundColor Green
      Write-Host (T "Deps.Version" @($ver)) -ForegroundColor Green
      Write-Host ""
      Write-Host (T "Deps.UseForceHint") -ForegroundColor DarkGray
      exit 0
    }
  }
}

Write-Host (T "Deps.Downloading") -ForegroundColor Yellow
Write-Host ""

if (-not (Test-Path -LiteralPath $BinDir -PathType Container)) {
  New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

$downloadUrls = @(
  @{
    Name = "FireDaemon OpenSSL 3.4"
    Url  = "https://download.firedaemon.com/FireDaemon-OpenSSL/FireDaemon-OpenSSL-x64-3.4.1.zip"
    Type = "zip"
    BinSubPath = "openssl-3\x64\bin"
  },
  @{
    Name = "FireDaemon OpenSSL 3.3"
    Url  = "https://download.firedaemon.com/FireDaemon-OpenSSL/FireDaemon-OpenSSL-x64-3.3.2.zip"
    Type = "zip"
    BinSubPath = "openssl-3\x64\bin"
  }
)

$tempDir = Join-Path $ToolkitRoot "temp"
if (-not (Test-Path -LiteralPath $tempDir -PathType Container)) {
  New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
}

$downloaded = $false
foreach ($src in $downloadUrls) {
  Write-Host (T "Deps.TryingSource" @($src.Name)) -ForegroundColor White
  $zipFile = Join-Path $tempDir "openssl-download.zip"

  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $src.Url -OutFile $zipFile -UseBasicParsing -TimeoutSec 120
    $ProgressPreference = 'Continue'

    if (-not (Test-Path -LiteralPath $zipFile -PathType Leaf) -or (Get-Item $zipFile).Length -lt 1024) {
      Write-Host (T "Deps.DownloadTooSmall") -ForegroundColor Yellow
      continue
    }

    Write-Host (T "Deps.Extracting") -ForegroundColor White
    $extractDir = Join-Path $tempDir "openssl-extract"
    if (Test-Path -LiteralPath $extractDir) { Remove-Item -LiteralPath $extractDir -Recurse -Force }

    Expand-Archive -LiteralPath $zipFile -DestinationPath $extractDir -Force

    $binSrc = $null
    if (-not [string]::IsNullOrWhiteSpace($src.BinSubPath)) {
      $candidate = Join-Path $extractDir $src.BinSubPath
      if (Test-Path -LiteralPath $candidate -PathType Container) { $binSrc = $candidate }
    }
    if ($null -eq $binSrc) {
      $found = Get-ChildItem -Path $extractDir -Filter "openssl.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($null -ne $found) { $binSrc = $found.DirectoryName }
    }

    if ($null -eq $binSrc) {
      Write-Host (T "Deps.OpenSslNotFoundInArchive") -ForegroundColor Yellow
      continue
    }

    $essentialFiles = Get-ChildItem -LiteralPath $binSrc -File | Where-Object {
      $_.Name -match "^(openssl\.exe|libssl|libcrypto|legacy\.dll|capi\.dll)"
    }
    foreach ($ef in $essentialFiles) {
      Copy-Item -LiteralPath $ef.FullName -Destination $BinDir -Force
      Write-Host "  -> $($ef.Name)" -ForegroundColor DarkGray
    }

    $cnfSrc = Join-Path (Split-Path -Parent $binSrc) "ssl"
    if (Test-Path -LiteralPath $cnfSrc -PathType Container) {
      $cnfDest = Join-Path $BinDir "ssl"
      if (-not (Test-Path -LiteralPath $cnfDest)) {
        Copy-Item -LiteralPath $cnfSrc -Destination $cnfDest -Recurse -Force
      }
    }

    Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $zipFile -Force -ErrorAction SilentlyContinue

    if (Test-OpenSslWorks $OpenSslExe) {
      $downloaded = $true
      break
    }
    else {
      Write-Host (T "Deps.ExtractedButNotWorking") -ForegroundColor Yellow
    }
  }
  catch {
    Write-Host (T "Deps.DownloadFailed" @($_.Exception.Message)) -ForegroundColor Yellow
  }
}

if ($downloaded) {
  $ver = & $OpenSslExe version 2>&1
  Write-Host ""
  Write-Host (T "Deps.InstallSuccess") -ForegroundColor Green
  Write-Host (T "Deps.Version" @($ver)) -ForegroundColor Green
  Write-Host (T "Deps.InstalledTo" @($OpenSslExe)) -ForegroundColor Green
}
else {
  Write-Host ""
  Write-Host (T "Deps.AutoFailed") -ForegroundColor Red
  Write-Host ""
  Write-Host (T "Deps.ManualGuide") -ForegroundColor White
  Write-Host (T "Deps.ManualStep1") -ForegroundColor White
  Write-Host (T "Deps.ManualStep2" @($BinDir)) -ForegroundColor White
  Write-Host (T "Deps.ManualStep3") -ForegroundColor White
  Write-Host ""
  Write-Host (T "Deps.ManualAlt1") -ForegroundColor White
  Write-Host (T "Deps.ManualAlt2") -ForegroundColor White
  exit 1
}
