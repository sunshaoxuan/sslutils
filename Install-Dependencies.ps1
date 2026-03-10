<#
.SYNOPSIS
Downloads and installs portable OpenSSL into utils/bin/ for the SSL Toolkit.

.DESCRIPTION
Checks whether OpenSSL is available locally (utils/bin/) or on the system.
If not found, downloads a portable OpenSSL build and extracts it to utils/bin/.

Supports automatic detection of existing installations and provides
a manual fallback guide when automatic download fails.

.PARAMETER Force
Re-download even if utils/bin/openssl.exe already exists.

.PARAMETER Lang
Display language (ja / zh / en). Defaults to saved preference or system default.

.EXAMPLE
.\Install-Dependencies.ps1
Check and install OpenSSL if needed.

.EXAMPLE
.\Install-Dependencies.ps1 -Force
Force re-download of OpenSSL.
#>

param(
  [switch]$Force,
  [string]$Lang = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "utils\lib\defaults.ps1")

$__langFile = Join-Path $PSScriptRoot ".toolkit_lang"
if ([string]::IsNullOrWhiteSpace($Lang)) {
  if (Test-Path -LiteralPath $__langFile -PathType Leaf) {
    $Lang = (Get-Content -LiteralPath $__langFile -Raw -ErrorAction SilentlyContinue).Trim()
  }
  if ([string]::IsNullOrWhiteSpace($Lang)) { $Lang = $__DefaultLang }
}

$i18nModule = Join-Path $PSScriptRoot "utils\lib\i18n.ps1"
if (Test-Path -LiteralPath $i18nModule -PathType Leaf) {
  . $i18nModule
  $__i18n = Initialize-I18n -Lang $Lang -BaseDir $PSScriptRoot
}
function T([string]$Key, [object[]]$FormatArgs = @()) {
  if ($null -ne $__i18n) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }
  return $Key
}

$BinDir = Join-Path $PSScriptRoot "utils\bin"
$OpenSslExe = Join-Path $BinDir "openssl.exe"

function Test-OpenSslWorks([string]$path) {
  try {
    $ver = & $path version 2>&1
    return ($LASTEXITCODE -eq 0 -and $ver -match "OpenSSL")
  }
  catch { return $false }
}

function Get-ExistingOpenSsl {
  $candidates = @(
    $OpenSslExe,
    "C:\Program Files\Git\usr\bin\openssl.exe",
    "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe"
  )
  foreach ($c in $candidates) {
    if ((Test-Path -LiteralPath $c -PathType Leaf) -and (Test-OpenSslWorks $c)) {
      return $c
    }
  }
  $cmd = Get-Command openssl -ErrorAction SilentlyContinue
  if ($null -ne $cmd -and (Test-OpenSslWorks $cmd.Source)) {
    return $cmd.Source
  }
  return $null
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

$existing = Get-ExistingOpenSsl
if (-not $Force -and $null -ne $existing -and $existing -ne $OpenSslExe) {
  $ver = & $existing version 2>&1
  Write-Host (T "Deps.FoundSystem" @($existing)) -ForegroundColor Yellow
  Write-Host (T "Deps.Version" @($ver)) -ForegroundColor Yellow
  Write-Host ""
  Write-Host (T "Deps.CopyToLocal") -ForegroundColor White

  $answer = Read-Host (T "Deps.CopyPrompt")
  if ($answer -match "^[yY]") {
    if (-not (Test-Path -LiteralPath $BinDir -PathType Container)) {
      New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    }
    $srcDir = Split-Path -Parent $existing
    $filesToCopy = Get-ChildItem -LiteralPath $srcDir -File | Where-Object {
      $_.Name -match "^(openssl|libssl|libcrypto|msvcr|vcruntime|legacy)\." -or
      $_.Extension -in ".dll", ".exe" -and $_.Name -match "ssl|crypto"
    }
    foreach ($f in $filesToCopy) {
      Copy-Item -LiteralPath $f.FullName -Destination $BinDir -Force
      Write-Host "  -> $($f.Name)" -ForegroundColor DarkGray
    }
    if (-not (Test-Path -LiteralPath $OpenSslExe -PathType Leaf)) {
      Copy-Item -LiteralPath $existing -Destination $OpenSslExe -Force
    }
    if (Test-OpenSslWorks $OpenSslExe) {
      $ver2 = & $OpenSslExe version 2>&1
      Write-Host ""
      Write-Host (T "Deps.CopySuccess" @($ver2)) -ForegroundColor Green
      exit 0
    }
    else {
      Write-Host (T "Deps.CopyFailed") -ForegroundColor Red
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

$tempDir = Join-Path $PSScriptRoot "temp"
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
