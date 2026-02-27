<#
.SYNOPSIS
クライアント証明書と中間証明書を結合してフルチェーンを作成するスクリプト

.DESCRIPTION
このスクリプトは、クライアント証明書（サーバ証明書）と中間証明書（CA証明書）を
結合して、完全な証明書チェーンを作成します。必要に応じて交差ルート証明書を末尾に追加できます。

主な機能:
- クライアント証明書と中間証明書の自動結合
- 中間証明書の自動選択（issuer/subject による一致判定）
- 既に結合済みの証明書の検出とスキップ
- 一括処理モード（new/ 配下を自動走査）
- 改行コードの正規化（LF統一）

.PARAMETER ClientCert
クライアント証明書のパス（省略時：一括処理モード）

.PARAMETER IntermediateCert
中間証明書のパス（省略時：ルート直下から自動選択）

.PARAMETER OutFile
出力ファイルのパス（省略時：OutDir 配下に自動配置）

.PARAMETER OutDir
出力ディレクトリ（既定: .\output\merged）

.PARAMETER RootCert
末尾に追加するルート/交差ルート証明書（複数指定可、任意）

.PARAMETER RootDir
一括処理時の探索ルート（未指定ならスクリプト配下）

.PARAMETER OpenSsl
OpenSSL 実行ファイルのパス

.PARAMETER SkipIfAlreadyMerged
既にフルチェーン（複数 CERT ブロック）ならスキップ（既定: true）

.PARAMETER Force
自動判定を無視して強制結合

.PARAMETER Lang
出力言語（既定: ja）

.EXAMPLE
.\Merge-CertificateChain.ps1
new\ 配下のすべての .cer 証明書を自動結合

.EXAMPLE
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer
指定した証明書を結合

.EXAMPLE
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer -RootCert .\cross-root.cer
fullchain に交差ルートを追加

.NOTES
- 中間証明書の自動選択は、クライアント証明書の issuer と中間証明書の subject が一致するものを探します
- 既存の出力ファイルと内容が同一の場合は、バックアップせずにスキップします
- 誤結合防止のため、複数候補がある場合は自動選択しません
#>

param(
  # 省略した場合：new\ を走査して一括処理します
  [Parameter(Mandatory = $false, Position = 0)]
  [string]$ClientCert = "",

  # 中間証明書（省略可：ルート直下から自動選択します）
  [Parameter(Mandatory = $false, Position = 1)]
  [string]$IntermediateCert = "",

  # 出力先（未指定の場合は ./output/merged/<clientFileName>）
  [Parameter(Mandatory = $false)]
  [string]$OutFile = "",

  [Parameter(Mandatory = $false)]
  [string]$OutDir = "",

  # 末尾に追加するルート/交差ルート証明書（複数指定可）
  [Parameter(Mandatory = $false)]
  [string[]]$RootCert = @(),

  # 一括処理時の探索ルート（未指定ならスクリプト配下）
  [Parameter(Mandatory = $false)]
  [string]$RootDir = "",

  # OpenSSL（中間証明書の自動選択に使用）
  [Parameter(Mandatory = $false)]
  [string]$OpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe",

  # 既にクライアント証明書がフルチェーン（複数 CERT ブロック）なら、中間証明書を追加せずに出力だけ作成します
  [Parameter(Mandatory = $false)]
  [bool]$SkipIfAlreadyMerged = $true,

  # 自動判定を無視して強制結合
  [Parameter(Mandatory = $false)]
  [switch]$Force,

  # 出力言語（既定: ja）
  [Parameter(Mandatory = $false)]
  [string]$Lang = "en"
)


$ToolkitRoot = Split-Path -Parent $PSScriptRoot

# 出力の文字化け対策（環境差異があるため、失敗しても続行）
try {
  [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
  $OutputEncoding = [Console]::OutputEncoding
}
catch { }

$i18nModule = Join-Path $PSScriptRoot "lib\\i18n.ps1"
if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw (T "Common.I18nModuleNotFound" @($i18nModule)) }
. $i18nModule
$__i18n = Initialize-I18n -Lang $Lang -BaseDir $ToolkitRoot
$securityModule = Join-Path $PSScriptRoot "lib\security.ps1"
if (Test-Path -LiteralPath $securityModule -PathType Leaf) { . $securityModule }
$pathsModule = Join-Path $PSScriptRoot "lib\paths.ps1"
if (Test-Path -LiteralPath $pathsModule -PathType Leaf) { . $pathsModule }
function T([string]$Key, [object[]]$FormatArgs = @()) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }

$ToolkitPaths = if (Get-Command Get-ToolkitPaths -ErrorAction SilentlyContinue) { Get-ToolkitPaths -BaseDir $ToolkitRoot } else { $null }
if ([string]::IsNullOrWhiteSpace($OutDir)) {
  if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.Merged)) { $OutDir = $ToolkitPaths.Merged }
  else { $OutDir = Join-Path $ToolkitRoot "output\merged" }
}
$newDirName = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.NewName)) { $ToolkitPaths.NewName } else { "new" }
$oldDirName = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.OldName)) { $ToolkitPaths.OldName } else { "old" }

# 共通メニューモジュール読み込み
$menuModule = Join-Path $PSScriptRoot "lib\menu.ps1"
if (Test-Path -LiteralPath $menuModule -PathType Leaf) { . $menuModule }

# ===== Configuration Loading =====
$configPath = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace([string]$ToolkitPaths.CertConfig)) { [string]$ToolkitPaths.CertConfig } else { Join-Path $ToolkitRoot "CertConfig.psd1" }
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
  throw (T "Common.FileNotFound" @("Configuration file", $configPath))
}
$CertConfig = Import-PowerShellDataFile -Path $configPath

# Helper to get all patterns from config
function Get-AllCertPatterns() {
  $patterns = @()
  if ($CertConfig.Agencies) {
    foreach ($agency in $CertConfig.Agencies.Values) {
      if ($agency.Patterns) {
        $patterns += $agency.Patterns
      }
    }
  }
  return $patterns
}

# Helper to get search paths (agencies)
function Get-CertSearchPaths() {
  $paths = @()
  if ($CertConfig.Agencies) {
    $root = $CertConfig.CertStoreRoot
    if ([string]::IsNullOrWhiteSpace($root)) { $root = "CertStore" }
    $rootParams = Join-Path $ToolkitRoot $root
        
    foreach ($agency in $CertConfig.Agencies.Values) {
      if ($agency.Path) {
        $paths += Join-Path $rootParams $agency.Path
      }
    }
  }
  return $paths
}


# Intermediate cert patterns from config
$IntermediateCertFileNamePatterns = @(Get-AllCertPatterns)


function Backup-IfExists([string]$path) {
  if ([string]::IsNullOrWhiteSpace($path)) { return }
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
  $dir = Split-Path -Parent $path
  if ([string]::IsNullOrWhiteSpace($dir)) { $dir = "." }
  $base = [IO.Path]::GetFileNameWithoutExtension($path)
  $ext = [IO.Path]::GetExtension($path)
  $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
  $bak = Join-Path $dir ("{0}.bak_{1}{2}" -f $base, $ts, $ext)
  Rename-Item -Force -ErrorAction Stop -LiteralPath $path -NewName ([IO.Path]::GetFileName($bak))
}

function Assert-ExistsFile([string]$p, [string]$label) {
  if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
    throw (T "Common.FileNotFound" @($label, $p))
  }
}

function New-DirectoryIfMissing([string]$p) {
  if (-not (Test-Path -LiteralPath $p -PathType Container)) {
    New-Item -ItemType Directory -Path $p | Out-Null
  }
}

if (-not [string]::IsNullOrWhiteSpace($ClientCert)) {
  Assert-ExistsFile $ClientCert "Client certificate"
}
if (-not [string]::IsNullOrWhiteSpace($IntermediateCert)) { Assert-ExistsFile $IntermediateCert "Intermediate certificate" }
if ($RootCert.Count -gt 0) {
  foreach ($r in $RootCert) {
    if (-not [string]::IsNullOrWhiteSpace($r)) { Assert-ExistsFile $r "Root certificate" }
  }
}

New-DirectoryIfMissing $OutDir

if ([string]::IsNullOrWhiteSpace($RootDir)) { $RootDir = $ToolkitRoot }
if (-not (Test-Path -LiteralPath $RootDir -PathType Container)) { throw (T "MergeCert.RootDirNotFound" @($RootDir)) }

function Resolve-RelPath([string]$baseDir, [string]$fullPath) {
  $base = (Resolve-Path -LiteralPath $baseDir).Path.TrimEnd('\', '/')
  $full = (Resolve-Path -LiteralPath $fullPath).Path
  if ($full.Length -lt $base.Length) { return [IO.Path]::GetFileName($fullPath) }
  if ($full.Substring(0, $base.Length).ToLowerInvariant() -ne $base.ToLowerInvariant()) {
    return [IO.Path]::GetFileName($fullPath)
  }
  $rel = $full.Substring($base.Length).TrimStart('\', '/')
  return $rel
}

function Get-OutPathForClientCert([string]$clientCertPath) {
  if (-not [string]::IsNullOrWhiteSpace($OutFile)) { return $OutFile }
  $rel = Resolve-RelPath $RootDir $clientCertPath
  $prefixPattern = "^(?i){0}[\\/](.+)$" -f [regex]::Escape($newDirName)
  if ($rel -match $prefixPattern) { $rel = $matches[1] }
  $outPath = Join-Path $OutDir $rel
  $outParent = Split-Path -Parent $outPath
  if (-not [string]::IsNullOrWhiteSpace($outParent)) { New-DirectoryIfMissing $outParent }
  return $outPath
}

function Invoke-OpenSsl([string[]]$OpenSslArgs, [switch]$AllowFail) {
  $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    if ($AllowFail) { return $out }
    throw (T "Common.OpenSslCmdFailed" @(($OpenSslArgs -join " "), (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return $out
}

function Invoke-Pkcs12([string[]]$Pkcs12Args, [switch]$AllowFail) {
  $fullArgs = @("pkcs12") + $Pkcs12Args
  try {
    return Invoke-OpenSsl $fullArgs -AllowFail:$AllowFail
  }
  catch {
    $firstErr = $_
    if ($firstErr.Exception.Message -notmatch "unsupported|RC2|legacy") { throw }
  }
  try {
    return Invoke-OpenSsl ($fullArgs + @("-legacy")) -AllowFail:$AllowFail
  }
  catch {
    $legacyErr = $_
    if ($legacyErr.Exception.Message -notmatch "unable to load provider|ossl-modules") { throw }
  }
  $mingw = $OpenSsl -replace '[/\\]usr[/\\]bin[/\\]', '\mingw64\bin\'
  if ($mingw -eq $OpenSsl -or -not (Test-Path -LiteralPath $mingw)) { throw $legacyErr }
  $out = & $mingw @($fullArgs + @("-legacy")) 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    if ($AllowFail) { return $out }
    throw (T "Common.OpenSslCmdFailed" @(($fullArgs -join " "), (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return $out
}

function Get-CertNotBeforeFromFile([string]$certPath) {
  try {
    $out = Invoke-OpenSsl @("x509", "-in", $certPath, "-noout", "-dates")
    $line = ($out | Where-Object { $_ -match "^notBefore=" } | Select-Object -First 1)
    if ($line) { return ([string]$line).Trim().Replace("notBefore=", "") }
  }
  catch {}
  return ""
}

function Get-CertNotBeforeFromPfx([string]$pfxPath, [string[]]$phrases) {
  foreach ($p in @("") + $phrases) {
    try {
      $certPem = ""
      if ([string]::IsNullOrWhiteSpace($p)) {
        $certPem = Invoke-Pkcs12 @("-in", $pfxPath, "-nokeys", "-clcerts", "-passin", "pass:") | Out-String
      }
      else {
        $certPem = Invoke-TempPassFile $p { param($tmp)
          Invoke-Pkcs12 @("-in", $pfxPath, "-nokeys", "-clcerts", "-passin", "file:$tmp") | Out-String
        }
      }
      if ([string]::IsNullOrWhiteSpace($certPem)) { continue }
      $tmpCert = [IO.Path]::GetTempFileName()
      try {
        Set-Content -LiteralPath $tmpCert -Value $certPem -Encoding ASCII
        return Get-CertNotBeforeFromFile $tmpCert
      }
      finally { Remove-Item $tmpCert -Force -ErrorAction SilentlyContinue }
    }
    catch {}
  }
  return ""
}

function Copy-PfxDecrypted([string]$srcPfx, [string]$destPfx, [string[]]$phrases) {
  foreach ($p in @("") + $phrases) {
    try {
      $isPass = -not [string]::IsNullOrWhiteSpace($p)
      $tmpPem = [IO.Path]::GetTempFileName()
      try {
        if ($isPass) {
          Invoke-TempPassFile $p { param($tmp)
            Invoke-Pkcs12 @("-in", $srcPfx, "-out", $tmpPem, "-nodes", "-passin", "file:$tmp")
          } | Out-Null
        }
        else {
          Invoke-Pkcs12 @("-in", $srcPfx, "-out", $tmpPem, "-nodes", "-passin", "pass:") | Out-Null
        }
        if ($LASTEXITCODE -ne 0) { continue }
        Invoke-OpenSsl @("pkcs12", "-export", "-in", $tmpPem, "-out", $destPfx, "-passout", "pass:") | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
      }
      finally { Remove-Item $tmpPem -Force -ErrorAction SilentlyContinue }
    }
    catch {}
  }
  return $false
}

function NormalizeLf([string]$s) {
  return ($s -replace "`r`n", "`n" -replace "`r", "`n")
}

function Get-CertBlockCount([string]$pemText) {
  return [regex]::Matches($pemText, "-----BEGIN CERTIFICATE-----").Count
}

function Format-MergedText([string]$s) {
  $t = NormalizeLf $s
  if (-not $t.EndsWith("`n")) { $t += "`n" }
  return $t
}

function Read-TextIfExists([string]$path) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return "" }
  try {
    return (Get-Content -LiteralPath $path -Raw)
  }
  catch {
    return ""
  }
}

function Resolve-RootCertFiles([string]$baseCertPath) {
  $roots = @()
  if ($RootCert.Count -gt 0) {
    foreach ($r in $RootCert) {
      if (-not [string]::IsNullOrWhiteSpace($r)) { $roots += $r }
    }
  }
  return @($roots)
}

function Write-FileIfChanged([string]$path, [string]$content, [string]$outKey) {
  $existing = Read-TextIfExists $path
  if (-not [string]::IsNullOrWhiteSpace($existing)) {
    $existingNorm = Format-MergedText $existing
    if ($existingNorm -eq $content) {
      Write-Host (T "MergeCert.SameAsExistingSkip" @((Resolve-Path -LiteralPath $path)))
      return
    }
  }

  Backup-IfExists $path
  Set-Content -LiteralPath $path -Value $content -NoNewline -Encoding ASCII
  Write-Host (T $outKey @((Resolve-Path -LiteralPath $path)))
}

function Find-IntermediateCandidates() {
  $found = New-Object System.Collections.Generic.List[string]
  $searchPaths = @(Get-CertSearchPaths)
  
  # Add root search if needed, but primarily search in agency folders
  if ($searchPaths.Count -eq 0) { $searchPaths += $PSScriptRoot }

  foreach ($path in $searchPaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
      
    foreach ($pat in @($IntermediateCertFileNamePatterns)) {
      if ([string]::IsNullOrWhiteSpace($pat)) { continue }
      $items = @(Get-ChildItem -LiteralPath $path -File -Filter $pat -ErrorAction SilentlyContinue)
      foreach ($i in $items) { $found.Add($i.FullName) | Out-Null }
    }
  }
  return @($found | Select-Object -Unique)
}

function Find-RootCandidates() {
  $found = New-Object System.Collections.Generic.List[string]
  $searchPaths = @(Get-CertSearchPaths)
  if ($searchPaths.Count -eq 0) { $searchPaths += $PSScriptRoot }

  foreach ($path in $searchPaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
    $items = @(Get-ChildItem -LiteralPath $path -File -Include *.cer, *.crt, *.pem -ErrorAction SilentlyContinue)
    foreach ($i in $items) { $found.Add($i.FullName) | Out-Null }
  }
  return @($found | Select-Object -Unique)
}

function Select-RootCerts([string]$intermediateCertPath) {
  if ($RootCert.Count -gt 0) {
    return [PSCustomObject]@{ Status = "ok"; Files = @(Resolve-RootCertFiles $intermediateCertPath) }
  }

  $cands = @(Find-RootCandidates)
  if ($cands.Count -eq 0) { return [PSCustomObject]@{ Status = "none"; Files = @() } }

  $canUseOpenSsl = Test-Path -LiteralPath $OpenSsl -PathType Leaf
  if (-not $canUseOpenSsl) { return [PSCustomObject]@{ Status = "needopenssl"; Files = @() } }

  $issuerLine = (Invoke-OpenSsl @("x509", "-in", $intermediateCertPath, "-noout", "-issuer", "-nameopt", "RFC2253") -AllowFail | Select-Object -First 1)
  if ([string]::IsNullOrWhiteSpace($issuerLine)) { return [PSCustomObject]@{ Status = "issuerMissing"; Files = @() } }
  $issuer = ([string]$issuerLine).Trim().Replace("issuer=", "")
  if ([string]::IsNullOrWhiteSpace($issuer)) { return [PSCustomObject]@{ Status = "issuerMissing"; Files = @() } }

  $matched = @()
  foreach ($cand in $cands) {
    $subjLine = (Invoke-OpenSsl @("x509", "-in", $cand, "-noout", "-subject", "-nameopt", "RFC2253") -AllowFail | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($subjLine)) { continue }
    $subj = ([string]$subjLine).Trim().Replace("subject=", "")
    if (-not [string]::IsNullOrWhiteSpace($subj) -and $subj -eq $issuer) {
      $matched += $cand
    }
  }

  if ($matched.Count -eq 1) { return [PSCustomObject]@{ Status = "ok"; Files = @($matched[0]) } }
  if ($matched.Count -gt 1) { return [PSCustomObject]@{ Status = "multi"; Files = @($matched) } }

  return [PSCustomObject]@{ Status = "nomatch"; Files = @() }
}

function Select-FullChainRootCerts([string]$intermediateCertPath) {
  $result3 = Select-RootCerts $intermediateCertPath
  if ($result3.Status -ne "ok" -or $result3.Files.Count -eq 0) {
    return [PSCustomObject]@{ Status3 = $result3.Status; Files3 = @(); Status4 = "none"; Files4 = @() }
  }
  $crossRoot = $result3.Files[0]
  $result4Parent = Select-RootCerts $crossRoot
  $files4 = @()
  $status4 = "none"
  if ($result4Parent.Status -eq "ok" -and $result4Parent.Files.Count -gt 0) {
    $parentSubj = ""
    $parentLine = Invoke-OpenSsl @("x509", "-in", $result4Parent.Files[0], "-noout", "-subject", "-nameopt", "RFC2253") -AllowFail | Select-Object -First 1
    if ($parentLine) { $parentSubj = ([string]$parentLine).Trim().Replace("subject=", "") }
    $crossSubj = ""
    $crossLine = Invoke-OpenSsl @("x509", "-in", $crossRoot, "-noout", "-issuer", "-nameopt", "RFC2253") -AllowFail | Select-Object -First 1
    if ($crossLine) { $crossSubj = ([string]$crossLine).Trim().Replace("issuer=", "") }
    if ($parentSubj -eq $crossSubj -and -not [string]::IsNullOrWhiteSpace($parentSubj)) {
      $files4 = @($crossRoot, $result4Parent.Files[0])
      $status4 = "ok"
    }
  }
  return [PSCustomObject]@{
    Status3 = $result3.Status; Files3 = @($result3.Files)
    Status4 = $status4;        Files4 = $files4
  }
}

function Select-IntermediateCert([string]$clientCertPath) {
  if (-not [string]::IsNullOrWhiteSpace($IntermediateCert)) {
    return $IntermediateCert
  }

  $cands = @(Find-IntermediateCandidates)
  if ($cands.Count -eq 0) {
    throw (T "MergeCert.NoIntermediateCandidates")
  }

  # OpenSSL が使えるなら issuer/subject で最適候補を選ぶ（誤結合防止）
  $canUseOpenSsl = Test-Path -LiteralPath $OpenSsl -PathType Leaf
  if ($canUseOpenSsl) {
    # RFC2253 で正規化して比較（表記揺れ対策）
    $issuerLine = (Invoke-OpenSsl @("x509", "-in", $clientCertPath, "-noout", "-issuer", "-nameopt", "RFC2253") -AllowFail | Select-Object -First 1)
    $issuer = ([string]$issuerLine).Trim().Replace("issuer=", "")
    if (-not [string]::IsNullOrWhiteSpace($issuer)) {
      $matched = @()
      foreach ($cand in $cands) {
        $subjLine = (Invoke-OpenSsl @("x509", "-in", $cand, "-noout", "-subject", "-nameopt", "RFC2253") -AllowFail | Select-Object -First 1)
        $subj = ([string]$subjLine).Trim().Replace("subject=", "")
        if (-not [string]::IsNullOrWhiteSpace($subj) -and $subj -eq $issuer) {
          $matched += $cand
        }
      }
      if ($matched.Count -eq 1) { return $matched[0] }
      if ($matched.Count -gt 1) {
        $list = ($matched | ForEach-Object { "- " + $_ }) -join "`n"
        throw (T "MergeCert.MultiIntermediateMatched" @($list))
      }
      # issuer が取得できたが一致する subject が無い：絶対に適当な 1 つは選ばない
      $list = ($cands | ForEach-Object { "- " + $_ }) -join "`n"
      throw (T "MergeCert.NoIntermediateMatched" @($issuer, $list))
    }
  }

  # OpenSSL が使えない/issuer が取れない場合：誤結合防止のため自動選択しない
  if ($cands.Count -eq 1) {
    throw (T "MergeCert.OneCandidateButNoVerify" @($cands[0]))
  }

  $list = ($cands | ForEach-Object { "- " + $_ }) -join "`n"
  throw (T "MergeCert.MultiCandidatesNeedSpecify" @($list))
}

# Helper: Pretty Status Output
function Write-Step([string]$msg) {
  Write-Host "`n➜ $msg" -ForegroundColor Cyan
}

function Write-Success([string]$label, [string]$value = "") {
  Write-Host "  ✔ " -NoNewline -ForegroundColor Green
  Write-Host "$label" -NoNewline -ForegroundColor White
  if ($value) { Write-Host ": $value" -ForegroundColor Gray }
  else { Write-Host "" }
}

function Write-Info([string]$msg) {
  Write-Host "  ℹ $msg" -ForegroundColor Gray
}

function Write-Warn([string]$msg) {
  Write-Host "  ⚠ $msg" -ForegroundColor Yellow
}

function Merge-One([string]$clientCertPath, [string]$SelectedIntermediate = "", [string[]]$SelectedRootFiles = @(), [switch]$SkipAutoRoot) {
  Assert-ExistsFile $clientCertPath "Client certificate"
  $outPath = Get-OutPathForClientCert $clientCertPath

  # Header
  Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
  Write-Host "  $((T "MergeCert.TitleSingle"))" -ForegroundColor Cyan
  Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

  # Step 1: Input Check
  Write-Step (T "MergeCert.Step1")
  $clientName = [IO.Path]::GetFileName($clientCertPath)
  Write-Success (T "MergeCert.ClientCert") $clientName

  $a = Get-Content -LiteralPath $clientCertPath -Raw
  $a = Format-MergedText $a

  $blockCount = Get-CertBlockCount $a
  $alreadyMerged = ($blockCount -ge 2)

  $merged = $a

  $rootFiles = @()
  if ($SelectedRootFiles.Count -gt 0) {
    $rootFiles = @($SelectedRootFiles)
  }
  elseif ($RootCert.Count -gt 0) {
    $rootFiles = @(Resolve-RootCertFiles $clientCertPath)
  }

  if ($alreadyMerged -and $SkipIfAlreadyMerged -and -not $Force -and $rootFiles.Count -eq 0) {
    Write-Info (T "MergeCert.AlreadyHasChain" @($blockCount))
  }
  else {
    # Step 2: Merge
    Write-Step (T "MergeCert.Step2")
    
    $selectedIntermediate = $SelectedIntermediate
    if ([string]::IsNullOrWhiteSpace($selectedIntermediate) -and (-not $alreadyMerged -or $Force)) {
      $selectedIntermediate = Select-IntermediateCert $clientCertPath
    }

    if (-not $alreadyMerged -or $Force) {
      Assert-ExistsFile $selectedIntermediate "Intermediate certificate"
      $interName = [IO.Path]::GetFileName($selectedIntermediate)
      Write-Success (T "MergeCert.IntermediateCert") $interName

      $b = Get-Content -LiteralPath $selectedIntermediate -Raw
      $b = Format-MergedText $b
      $merged = $a + $b
    }
    else {
      # Already merged info
    }

    if ($rootFiles.Count -eq 0 -and -not $SkipAutoRoot -and -not [string]::IsNullOrWhiteSpace($selectedIntermediate)) {
      $rootFiles = @(Select-RootCerts $selectedIntermediate)
    }

    if ($rootFiles.Count -gt 0) {
      $rootResolved = @()
      foreach ($r in $rootFiles) {
        $rootText = Format-MergedText (Get-Content -LiteralPath $r -Raw)
        $needle = $rootText.TrimEnd()
        if (-not $merged.Contains($needle)) {
          $merged = Format-MergedText ($merged + $rootText)
        }
        $rootResolved += (Resolve-Path -LiteralPath $r)
      }
      $rootNames = ($rootResolved | ForEach-Object { [IO.Path]::GetFileName($_) }) -join ", "
      Write-Success (T "MergeCert.RootCerts") $rootNames
    }
  }

  $merged = Format-MergedText $merged
  
  # File Write Logic custom for logging
  $existing = Read-TextIfExists $outPath
  $changed = $true
  if (-not [string]::IsNullOrWhiteSpace($existing)) {
    $existingNorm = Format-MergedText $existing
    if ($existingNorm -eq $merged) {
      Write-Info (T "MergeCert.SameAsExistingSkip" @([IO.Path]::GetFileName($outPath)))
      $changed = $false
    }
  }

  if ($changed) {
    Backup-IfExists $outPath
    Set-Content -LiteralPath $outPath -Value $merged -NoNewline -Encoding ASCII
    Write-Success (T "MergeCert.OutFile") ([IO.Path]::GetFileName($outPath))
  }

  # PFX Generation / Copy
  $keyPath = [IO.Path]::ChangeExtension($clientCertPath, ".key")
  if (Test-Path -LiteralPath $keyPath -PathType Leaf) {
    $pfxPath = [IO.Path]::ChangeExtension($outPath, ".pfx")
    
    # Passwords
    $keyDir = Split-Path -Parent $keyPath
    $searchDirs = @($keyDir, (Split-Path -Parent $keyDir), $PSScriptRoot)
    $pFiles = @()
    foreach ($d in $searchDirs) {
      $pf = Find-PassFile $d
      if ($pf) { $pFiles += $pf }
    }
    $phrases = Get-Passphrases $pFiles
    
    $pfxHandled = $false
    
    # Check if source directory already has a customer-provided PFX
    $srcPfx = [IO.Path]::ChangeExtension($clientCertPath, ".pfx")
    if (Test-Path -LiteralPath $srcPfx -PathType Leaf) {
      $cerDate = Get-CertNotBeforeFromFile $clientCertPath
      $pfxDate = Get-CertNotBeforeFromPfx $srcPfx $phrases
      if (-not [string]::IsNullOrWhiteSpace($cerDate) -and -not [string]::IsNullOrWhiteSpace($pfxDate) -and $cerDate -eq $pfxDate) {
        Write-Host ""
        Write-Host (T "MergeCert.PfxFoundInSource" @([IO.Path]::GetFileName($srcPfx))) -ForegroundColor Yellow
        Write-Host (T "MergeCert.PfxRegenPrompt") -ForegroundColor Yellow -NoNewline
        $regenAns = Read-Host " "
        if ($regenAns -match "^[yY]") {
          Write-Info (T "MergeCert.PfxRegenChosen")
        }
        else {
          Backup-IfExists $pfxPath
          $ok = Copy-PfxDecrypted $srcPfx $pfxPath $phrases
          if ($ok) {
            Write-Success (T "MergeCert.PfxCopiedFromSource") ([IO.Path]::GetFileName($srcPfx))
            $pfxHandled = $true
          }
          else {
            Copy-Item -LiteralPath $srcPfx -Destination $pfxPath -Force
            Write-Success (T "MergeCert.PfxCopiedAsIs") ([IO.Path]::GetFileName($srcPfx))
            $pfxHandled = $true
          }
        }
      }
    }
    
    if (-not $pfxHandled) {
      $isEnc = Test-KeyEncrypted $keyPath
      $generated = $false
      
      if (-not $isEnc) {
        Invoke-OpenSsl @("pkcs12", "-export", "-in", $outPath, "-inkey", $keyPath, "-out", $pfxPath, "-passout", "pass:") -AllowFail | Out-Null
        if ($LASTEXITCODE -eq 0) { $generated = $true }
      }
      else {
        foreach ($p in $phrases) {
          Invoke-TempPassFile $p { param($tmp)
            Invoke-OpenSsl @("pkcs12", "-export", "-in", $outPath, "-inkey", $keyPath, "-out", $pfxPath, "-passin", "file:$tmp", "-passout", "file:$tmp") -AllowFail | Out-Null
          }
          if ($LASTEXITCODE -eq 0) { 
            $generated = $true
            break 
          }
        }
      }
      
      if ($generated) {
        Write-Success (T "MergeCert.PfxGenerated") ([IO.Path]::GetFileName($pfxPath))
      }
      else {
        Write-Warn (T "Common.Warn" @("Failed to generate PFX"))
      }
    }
    
    # Sync Suggestion
    Write-Host ""
    Write-Host (T "MergeCert.SyncPrompt") -ForegroundColor Yellow -NoNewline
    $syncAns = Read-Host " "
    if ($syncAns -match "^[yY]") {
      $sourceDir = Split-Path -Parent $clientCertPath
      $orgName = [IO.Path]::GetFileName($sourceDir)
        
      # Call Sync-ToMerged.ps1 with arguments
      $syncScript = Join-Path $PSScriptRoot "Sync-ToMerged.ps1"
      if (Test-Path -LiteralPath $syncScript -PathType Leaf) {
        # -NoPause to return immediately
        & $syncScript -Target $orgName -NoPause -Lang $Lang
      }
    }
  }

  Write-Host ""
  Write-Success (T "MergeCert.Done")
}

function Find-ClientCerts([string]$root, [switch]$OnlyNew, [switch]$OnlyCer) {
  $dirs = @()
  $new = Join-Path $root $newDirName
  if ($OnlyNew) {
    if (Test-Path -LiteralPath $new -PathType Container) { $dirs += $new }
  }
  else {
    $old = Join-Path $root $oldDirName
    if (Test-Path -LiteralPath $old -PathType Container) { $dirs += $old }
    if (Test-Path -LiteralPath $new -PathType Container) { $dirs += $new }
  }
  if ($dirs.Count -eq 0) { $dirs += $root }

  $patterns = if ($OnlyCer) { @("*.cer") } else { @("*.cer", "*.crt", "*.pem") }
  $all = New-Object System.Collections.Generic.List[string]
  foreach ($d in $dirs) {
    foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -Include $patterns -ErrorAction SilentlyContinue)) {
      $all.Add($f.FullName) | Out-Null
    }
  }
  return @($all | Select-Object -Unique)
}

function Get-MergePlan([string]$clientCertPath) {
  Assert-ExistsFile $clientCertPath "Client certificate"
  $a = Get-Content -LiteralPath $clientCertPath -Raw
  $a = Format-MergedText $a
  $blockCount = Get-CertBlockCount $a
  $alreadyMerged = ($blockCount -ge 2)

  $needIntermediate = (-not $alreadyMerged) -or $Force
  $selectedIntermediate = ""
  if ($needIntermediate) { $selectedIntermediate = Select-IntermediateCert $clientCertPath }

  $rootFiles3 = @()
  $rootFiles4 = @()
  $rootStatus3 = "none"
  $rootStatus4 = "none"
  if ($RootCert.Count -gt 0) {
    $rootFiles3 = @(Resolve-RootCertFiles $clientCertPath)
    $rootStatus3 = if ($rootFiles3.Count -gt 0) { "ok" } else { "none" }
  }
  elseif (-not [string]::IsNullOrWhiteSpace($selectedIntermediate)) {
    $fullChain = Select-FullChainRootCerts $selectedIntermediate
    $rootStatus3 = $fullChain.Status3
    $rootFiles3 = @($fullChain.Files3)
    $rootStatus4 = $fullChain.Status4
    $rootFiles4 = @($fullChain.Files4)
  }

  # Check PFX
  $pfxPath = [IO.Path]::ChangeExtension($clientCertPath, ".pfx")
  $pfxExists = Test-Path -LiteralPath $pfxPath -PathType Leaf

  $action = "Merge2"
  if ($rootFiles3.Count -gt 0) {
    $action = "Merge3"
  }
  elseif ($alreadyMerged -and $SkipIfAlreadyMerged -and -not $Force) {
    if ($pfxExists) {
      $action = "Skip"
    }
    else {
      $action = "Merge2"
    }
  }

  return [PSCustomObject]@{
    Action        = $action
    BlockCount    = $blockCount
    AlreadyMerged = $alreadyMerged
    Intermediate  = $selectedIntermediate
    RootFiles     = $rootFiles3
    RootFiles4    = $rootFiles4
    RootStatus    = $rootStatus3
    RootStatus4   = $rootStatus4
    PfxExists     = $pfxExists
  }
}

function Read-BatchProceed([string]$message) {
  Write-Host $message
  $raw = ""
  try {
    $raw = (Read-Host (T "MergeCert.BatchPrompt")).Trim()
  }
  catch {
    return "continue"
  }
  if ([string]::IsNullOrWhiteSpace($raw)) { return "continue" }
  if ($raw -match "^(q|quit|exit)$") { return "quit" }
  if ($raw -match "^(s|skip)$") { return "skip" }
  return "continue"
}

if ([string]::IsNullOrWhiteSpace($ClientCert)) {
  Write-Host ""
  Write-Host (T "MergeCert.TitleBatch")
  Write-Host (T "MergeCert.RootDir" @((Resolve-Path -LiteralPath $RootDir)))
  Write-Host (T "MergeCert.OutDir" @((Resolve-Path -LiteralPath $OutDir)))

  $targets = @(Find-ClientCerts $RootDir -OnlyNew -OnlyCer)
  if ($targets.Count -eq 0) {
    Write-Host (T "MergeCert.NoTargets")
    exit 0
  }

  $targetItems = New-Object System.Collections.Generic.List[string]
  foreach ($t in $targets) {
    $rel = Resolve-RelPath $RootDir $t
    $prefixPattern = "^(?i){0}[\\/](.+)$" -f [regex]::Escape($newDirName)
    if ($rel -match $prefixPattern) { $rel = $matches[1] }
    $targetItems.Add($rel) | Out-Null
  }
  $targetItems.Add((T "MergeCert.BatchMenuQuit")) | Out-Null

  while ($true) {
    $pick = Show-MenuSelect -title (T "MergeCert.BatchCertMenuTitle") -items $targetItems
    if ($null -eq $pick) { exit 99 }
    if ($pick -eq $targetItems.Count) { exit 99 }  # Last item is Quit

    $t = $targets[$pick - 1]  # Show-MenuSelect returns 1-based
    try {
      $plan = Get-MergePlan $t
      $actionText = switch ($plan.Action) {
        "Merge3" { (T "MergeCert.BatchPlanMerge3") }
        "Merge2" { (T "MergeCert.BatchPlanMerge2") }
        "Skip" { (T "MergeCert.BatchPlanSkip") }
        default { (T "MergeCert.BatchPlanMerge2") }
      }

      Write-Host ""
      $targetName = [IO.Path]::GetFileName($t)
      Write-Host (T "MergeCert.BatchTarget" @($targetName)) -ForegroundColor White
      if (-not [string]::IsNullOrWhiteSpace($plan.Intermediate)) {
        $interName = [IO.Path]::GetFileName($plan.Intermediate)
        Write-Host (T "MergeCert.BatchIntermediate" @($interName))
      }
      elseif ($plan.Action -ne "Skip") {
        Write-Host (T "MergeCert.BatchIntermediate" @((T "MergeCert.BatchIntermediateAuto")))
      }
      if ($plan.RootFiles.Count -gt 0) {
        $rootNames = @($plan.RootFiles | ForEach-Object { [IO.Path]::GetFileName($_) })
        Write-Host (T "MergeCert.BatchRoot" @(($rootNames -join "; ")))
      }
      if ($plan.RootFiles4.Count -gt 0) {
        $rootNames4 = @($plan.RootFiles4 | ForEach-Object { [IO.Path]::GetFileName($_) })
        Write-Host (T "MergeCert.BatchRootCA" @(($rootNames4[-1])))
      }

      $actions = New-Object System.Collections.Generic.List[object]
      $menuItems = New-Object System.Collections.Generic.List[string]
      $merge2Text = (T "MergeCert.BatchMenuMerge2")
      $merge3Text = (T "MergeCert.BatchMenuMerge3")
      if ($plan.Action -eq "Merge3") { $merge3Text = (T "MergeCert.BatchMenuMerge3Rec") }
      
      if ($plan.AlreadyMerged -and $plan.Action -ne "Skip") {
        $merge2Text = "{0} (PFX Only)" -f $merge2Text
      }

      $actions.Add("Merge2") | Out-Null
      $menuItems.Add($merge2Text) | Out-Null

      if ($plan.RootStatus -eq "ok" -and $plan.RootFiles.Count -gt 0) {
        $actions.Add("Merge3") | Out-Null
        $menuItems.Add($merge3Text) | Out-Null
      }

      if ($plan.RootStatus4 -eq "ok" -and $plan.RootFiles4.Count -gt 0) {
        $actions.Add("Merge4") | Out-Null
        $menuItems.Add((T "MergeCert.BatchMenuMerge4")) | Out-Null
      }

      $actions.Add("Skip") | Out-Null
      $menuItems.Add((T "MergeCert.BatchMenuSkip")) | Out-Null

      $actions.Add("Back") | Out-Null
      $menuItems.Add((T "MergeCert.BatchMenuBack")) | Out-Null

      $actions.Add("Quit") | Out-Null
      $menuItems.Add((T "MergeCert.BatchMenuQuit")) | Out-Null

      $title = (T "MergeCert.BatchMenuTitle")
      $choice = Show-MenuSelect -title $title -items $menuItems
      if ($null -eq $choice) { exit 99 }
      $selectedAction = $actions[$choice - 1]  # Show-MenuSelect returns 1-based
      if ($selectedAction -eq "Quit") { exit 99 }
      if ($selectedAction -eq "Back") { continue }
      if ($selectedAction -eq "Skip") { continue }

      $skipAutoRoot = $true
      $selIntermediate = $plan.Intermediate
      $selRoots = @()
      if ($selectedAction -eq "Merge3" -or $selectedAction -eq "Merge4") {
        if (-not [string]::IsNullOrWhiteSpace($selIntermediate)) {
          if ($selectedAction -eq "Merge4" -and $plan.RootFiles4.Count -gt 0) {
            $selRoots = @($plan.RootFiles4)
          }
          else {
            $selRoots = @($plan.RootFiles)
          }
          if ($selRoots.Count -eq 0) {
            throw (T "MergeCert.RootRequired")
          }
        }
        if ($selRoots.Count -eq 0) {
          throw (T "MergeCert.RootRequired")
        }
      }

      Merge-One $t -SelectedIntermediate $selIntermediate -SelectedRootFiles $selRoots -SkipAutoRoot:$skipAutoRoot
      Wait-AnyKey (T "Common.PressAnyKey")
    }
    catch {
      Write-Host (T "Common.ErrorNg" @($t))
      Write-Host (T "Common.ErrorNg" @($_.Exception.Message))
      Wait-AnyKey (T "Common.PressAnyKey")
    }
  }
  exit 99
}

Merge-One $ClientCert


