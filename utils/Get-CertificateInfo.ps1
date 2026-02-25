<#
.SYNOPSIS
証明書・秘密鍵・CSR ファイルの基本情報を表示するスクリプト

.DESCRIPTION
このスクリプトは、SSL/TLS 証明書（.cer/.crt/.pem）、秘密鍵（.key）、
証明書署名要求（.csr）の基本情報を確認・表示します。

主な機能:
- 証明書の有効期限、発行者、サブジェクトの表示
- 証明書チェーン（中間証明書同梱）の確認
- 秘密鍵の暗号化状態と無人運用可能性の判定
- CSR のサブジェクト情報表示
- 多機関対応（old/ と new/ の階層構造を自動認識）

出力形式:
- 既定: ツリー形式（フォルダ→ファイルの階層表示）
- -Table: 表形式（従来の形式）
- -Detail: 詳細表示（OpenSSL の生出力）

.PARAMETER Path
指定した場合：そのファイルだけを表示
省略した場合：old\ と new\ をそれぞれ走査して表示

.PARAMETER OpenSsl
OpenSSL 実行ファイルのパス（既定: C:\Program Files\Git\usr\bin\openssl.exe）

.PARAMETER ChainFile
証明書とは別のチェーンファイルを指定してチェック（単体チェック時のみ有効）

.PARAMETER Detail
詳細表示モード（OpenSSL の生出力をそのまま表示）

.PARAMETER Table
旧来の表形式で表示（既定はツリー表示）

.PARAMETER PrettyTable
罫線つきの見やすい表形式で表示（証明書のみ）

.PARAMETER Lang
出力言語（既定: ja / 選択肢: ja, zh, en）

.EXAMPLE
.\Get-CertificateInfo.ps1
old\ と new\ 配下を走査して、すべての証明書・鍵・CSR の情報を表示

.EXAMPLE
.\Get-CertificateInfo.ps1 -Path .\new\example.com\example.com.cer
指定した証明書ファイルのみ表示

.EXAMPLE
.\Get-CertificateInfo.ps1 -Path .\server.cer -ChainFile .\server.chain.cer
チェーンファイルを指定して表示

.EXAMPLE
.\Get-CertificateInfo.ps1 -Lang en -Table
英語で表形式表示

.EXAMPLE
.\Get-CertificateInfo.ps1 -Lang zh -PrettyTable
罫線つきの表形式で表示

.NOTES
- 暗号化された秘密鍵は、passphrase.txt または環境変数 PASS_FILE から自動的にパスワードを読み取ります
- 証明書チェーンの判定は、PEM 形式の BEGIN CERTIFICATE ブロック数をカウントします
- 中間証明書の候補は、ルート直下の nii*.cer, gs*.cer 等を自動検出します
#>

param(
  # 指定した場合：そのファイルだけを表示
  # 省略した場合：old\ と new\ をそれぞれ走査して表示
  [Parameter(Mandatory = $false, Position = 0)]
  [string]$Path = "",

  [Parameter(Mandatory = $false)]
  [string]$OpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe",

  [Parameter(Mandatory = $false)]
  [string]$ChainFile = "",

  # 詳細表示（従来の openssl 出力をそのまま表示）
  [Parameter(Mandatory = $false)]
  [switch]$Detail,


  # 出力言語（既定: ja）
  [Parameter(Mandatory = $false)]
  [ValidateSet("ja", "zh", "en")]
  [string]$Lang = "ja"
)


$ToolkitRoot = Split-Path -Parent $PSScriptRoot

# 出力の文字化け対策（環境差異があるため、失敗しても続行）
try {
  [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
  $OutputEncoding = [Console]::OutputEncoding
}
catch { }

$i18nModule = Join-Path $PSScriptRoot "lib\\i18n.ps1"
. $i18nModule
$__i18n = Initialize-I18n -Lang $Lang -BaseDir $ToolkitRoot
$securityModule = Join-Path $PSScriptRoot "lib\security.ps1"
if (Test-Path -LiteralPath $securityModule -PathType Leaf) { . $securityModule }
$pathsModule = Join-Path $PSScriptRoot "lib\paths.ps1"
if (Test-Path -LiteralPath $pathsModule -PathType Leaf) { . $pathsModule }

function T([string]$Key, $ArgList = @()) {
  # 明示的に配列化して Get-I18nText に渡す
  $arr = if ($null -eq $ArgList) { @() } else { @($ArgList) }
  $res = Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $arr
  return [string]$res
}

if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw (T "Common.I18nModuleNotFound" @($i18nModule)) }

$FixedPassFileName = "passphrase.txt"
$ToolkitPaths = if (Get-Command Get-ToolkitPaths -ErrorAction SilentlyContinue) { Get-ToolkitPaths -BaseDir $ToolkitRoot } else { $null }
$toolOldDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.Old)) { $ToolkitPaths.Old } else { Join-Path $ToolkitRoot "old" }
$toolNewDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.New)) { $ToolkitPaths.New } else { Join-Path $ToolkitRoot "new" }
$toolMergedDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.Merged)) { $ToolkitPaths.Merged } else { Join-Path $ToolkitRoot "output\merged" }
$toolSelfSignedDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.SelfSigned)) { $ToolkitPaths.SelfSigned } else { Join-Path $ToolkitRoot "output\self-signed" }
$toolMergedOldDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.MergedOld)) { $ToolkitPaths.MergedOld } else { Join-Path $toolMergedDir "old" }
$toolLegacyMergedNewDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.LegacyMergedNew)) { $ToolkitPaths.LegacyMergedNew } else { Join-Path $toolMergedDir "new" }
$runtimeConfig = $null
$runtimeConfigPath = Join-Path $ToolkitRoot "config.json"
if (Test-Path -LiteralPath $runtimeConfigPath -PathType Leaf) {
  try {
    $runtimeConfig = Get-Content -LiteralPath $runtimeConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
  }
  catch { }
}

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


function Format-YesNo([bool]$b) {
  if ($b) { return (T "Common.Yes") }
  return (T "Common.No")
}

function Format-AutoModeStatus([bool]$isEncrypted, [string[]]$passphrases) {
  if (-not $isEncrypted) { return (T "CheckBasic.Key.AutoOkNoPass") }
  $usable = @($passphrases | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
  if ($usable) { return (T "CheckBasic.Key.AutoOkNeedPass") }
  return (T "CheckBasic.Key.AutoNgNeedPass")
}

function Assert-ExistsFile([string]$p, [string]$label) {
  if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
    throw (T "Common.FileNotFound" @($label, $p))
  }
}

function Invoke-OpenSsl([string[]]$OpenSslArgs) {
  $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    throw (T "Common.OpenSslCmdFailed" @(($OpenSslArgs -join " "), (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return $out
}

function Invoke-Pkcs12([string[]]$Pkcs12Args) {
  $fullArgs = @("pkcs12") + $Pkcs12Args
  try {
    return Invoke-OpenSsl $fullArgs
  }
  catch {
    $firstErr = $_
    if ($firstErr.Exception.Message -notmatch "unsupported|RC2|legacy") { throw }
  }
  $legacyErr = $null
  try {
    return Invoke-OpenSsl ($fullArgs + @("-legacy"))
  }
  catch {
    $legacyErr = $_
    if ($legacyErr.Exception.Message -notmatch "unable to load provider|ossl-modules") { throw }
  }
  $mingw = $OpenSsl -replace '[/\\]usr[/\\]bin[/\\]', '\mingw64\bin\'
  if ($mingw -eq $OpenSsl -or -not (Test-Path -LiteralPath $mingw)) { throw $legacyErr }
  $out = & $mingw @($fullArgs + @("-legacy")) 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    throw (T "Common.OpenSslCmdFailed" @(($fullArgs -join " "), (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return $out
}

Assert-ExistsFile $OpenSsl "OpenSSL"

if (-not [string]::IsNullOrWhiteSpace($ChainFile) -and [string]::IsNullOrWhiteSpace($Path)) {
  Write-Host (T "CheckBasic.ChainFileIgnored") -ForegroundColor Yellow
  $ChainFile = ""
}

$script:ChainSearchDirs = @(
  $ToolkitRoot,
  $toolOldDir,
  $toolNewDir,
  $toolMergedOldDir,
  $toolMergedDir,
  $toolLegacyMergedNewDir
) | Select-Object -Unique

$script:ChainDirMappings = @(
  @{ Source = $toolOldDir; Target = $toolMergedOldDir },
  @{ Source = $toolNewDir; Target = $toolMergedDir },
  @{ Source = $toolNewDir; Target = $toolLegacyMergedNewDir }
)

function Get-CertContainerInfo([string]$certPath) {
  # 形式判定（PEM/DER）と、PEM の場合は証明書ブロック数を数える
  try {
    $bytes = [System.IO.File]::ReadAllBytes($certPath)
  }
  catch {
    return [PSCustomObject]@{
      Format        = "UNKNOWN"
      CertBlocks    = 0
      HasPrivateKey = $false
      IsPkcs7       = $false
    }
  }

  $isPem = $false
  if ($bytes.Length -ge 10) {
    # "-----BEGIN" = 2D 2D 2D 2D 2D 42 45 47 49 4E
    $isPem = ($bytes[0] -eq 0x2D -and $bytes[1] -eq 0x2D -and $bytes[2] -eq 0x2D -and $bytes[3] -eq 0x2D -and $bytes[4] -eq 0x2D)
  }

  if (-not $isPem) {
    return [PSCustomObject]@{
      Format        = "DER"
      CertBlocks    = 0
      HasPrivateKey = $false
      IsPkcs7       = $false
    }
  }

  $text = [System.Text.Encoding]::ASCII.GetString($bytes)
  $blocks = [regex]::Matches($text, "-----BEGIN CERTIFICATE-----").Count
  $hasKey = ($text -match "-----BEGIN (ENCRYPTED )?(RSA )?PRIVATE KEY-----")
  $isPkcs7 = ($text -match "-----BEGIN PKCS7-----")

  $fmt = "PEM"
  if ($isPkcs7) { $fmt = "PKCS7" }

  return [PSCustomObject]@{
    Format        = $fmt
    CertBlocks    = $blocks
    HasPrivateKey = [bool]$hasKey
    IsPkcs7       = [bool]$isPkcs7
  }
}

function Find-ChainFileForCert([string]$certPath, [string]$explicit, [string[]]$searchDirs = @()) {
  if (-not [string]::IsNullOrWhiteSpace($explicit)) {
    Assert-ExistsFile $explicit "Chain file"
    return (Resolve-Path -LiteralPath $explicit).Path
  }
  $dir = Split-Path -Parent $certPath
  $base = [IO.Path]::GetFileNameWithoutExtension($certPath)
  $ext = [IO.Path]::GetExtension($certPath)
  $cands = @(
    ("{0}.chain{1}" -f $base, $ext),
    ("{0}.chain.pem" -f $base),
    ("{0}.chain.cer" -f $base),
    ("{0}.chain.crt" -f $base)
  )
  foreach ($c in $cands) {
    $p = Join-Path $dir $c
    if (Test-Path -LiteralPath $p -PathType Leaf) { return (Resolve-Path -LiteralPath $p).Path }
  }

  if ($script:ChainDirMappings.Count -gt 0) {
    foreach ($m in $script:ChainDirMappings) {
      $rel = Get-RelPathIfUnder $m.Source $certPath
      if ([string]::IsNullOrWhiteSpace($rel)) { continue }
      $relDir = Split-Path -Parent $rel
      foreach ($c in $cands) {
        $p = if ([string]::IsNullOrWhiteSpace($relDir)) {
          (Join-Path $m.Target $c)
        }
        else {
          (Join-Path (Join-Path $m.Target $relDir) $c)
        }
        if (Test-Path -LiteralPath $p -PathType Leaf) { return (Resolve-Path -LiteralPath $p).Path }
      }
    }
  }

  if ($searchDirs.Count -gt 0) {
    $matches = New-Object System.Collections.Generic.List[string]
    foreach ($sd in $searchDirs) {
      if (-not (Test-Path -LiteralPath $sd -PathType Container)) { continue }
      foreach ($c in $cands) {
        $p = Join-Path $sd $c
        if (Test-Path -LiteralPath $p -PathType Leaf) {
          $matches.Add((Resolve-Path -LiteralPath $p).Path) | Out-Null
        }
      }
    }
    $uniq = @($matches | Select-Object -Unique)
    if ($uniq.Count -eq 1) { return $uniq[0] }
  }
  return ""
}

function Get-ChainFileSummary([string]$chainPath) {
  if ([string]::IsNullOrWhiteSpace($chainPath)) {
    return [PSCustomObject]@{ Found = $false; Format = ""; CertBlocks = "" }
  }
  $info = Get-CertContainerInfo $chainPath
  return [PSCustomObject]@{
    Found      = $true
    Format     = $info.Format
    CertBlocks = [string]$info.CertBlocks
  }
}

function Find-IntermediateCertFiles() {
  $found = New-Object System.Collections.Generic.List[string]
  $searchPaths = @(Get-CertSearchPaths)
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

function Get-IssuerRfc2253FromCert([string]$certPath) {
  try {
    $out = Invoke-OpenSsl @("x509", "-in", $certPath, "-noout", "-issuer", "-nameopt", "RFC2253")
    $line = ($out | Select-Object -First 1)
    return ([string]$line).Trim().Replace("issuer=", "")
  }
  catch { return "" }
}

function Get-SubjectRfc2253FromCert([string]$certPath) {
  try {
    $out = Invoke-OpenSsl @("x509", "-in", $certPath, "-noout", "-subject", "-nameopt", "RFC2253")
    $line = ($out | Select-Object -First 1)
    return ([string]$line).Trim().Replace("subject=", "")
  }
  catch { return "" }
}

function Get-SubjectAltNamesFromCert([string]$certPath) {
  $out = @()
  try {
    $out = Invoke-OpenSsl @("x509", "-in", $certPath, "-noout", "-ext", "subjectAltName")
  }
  catch {
    $out = @()
  }
  if ($out.Count -eq 0) {
    try {
      $out = Invoke-OpenSsl @("x509", "-in", $certPath, "-noout", "-text")
    }
    catch {
      return ""
    }
  }

  $items = New-Object System.Collections.Generic.List[string]
  foreach ($line in $out) {
    foreach ($m in [regex]::Matches([string]$line, "(DNS|IP Address|IP):\s*([^,]+)")) {
      $t = $m.Groups[1].Value
      $v = $m.Groups[2].Value.Trim()
      if ([string]::IsNullOrWhiteSpace($v)) { continue }
      if ($t -eq "IP Address") { $t = "IP" }
      $items.Add(("{0}={1}" -f $t, $v)) | Out-Null
    }
  }

  $uniq = @($items | Select-Object -Unique)
  if ($uniq.Count -eq 0) { return "" }
  return ($uniq -join "; ")
}

function Get-CertChainSummary([string]$certPath) {
  $info = Get-CertContainerInfo $certPath
  $format = $info.Format

  if ($info.IsPkcs7) {
    return [PSCustomObject]@{
      Format                = $format
      CertBlocks            = ""
      HasChain              = ""
      FinalUse              = "UNKNOWN_PKCS7"
      ExternalIntermediates = ""
      HasPrivateKey         = $info.HasPrivateKey
      Issuer                = ""
      IssuerCN              = ""
    }
  }

  if ($info.Format -eq "PEM") {
    $hasChain = ($info.CertBlocks -ge 2)
    $extIntermediates = @()
    $issuer = ""
    $issuerCN = ""
    if (-not $hasChain) {
      # issuer と subject が一致する中間証明書だけを候補として表示（張冠李戴防止）
      $issuer = Get-IssuerRfc2253FromCert $certPath
      # issuer から CN を抽出（例: CN=GlobalSign GCC R6 AlphaSSL CA 2023,O=... → GlobalSign GCC R6 AlphaSSL CA 2023）
      if ($issuer -match "(?:^|,)CN=([^,]+)") { $issuerCN = $matches[1].Trim() }
      $all = @(Find-IntermediateCertFiles)
      if (-not [string]::IsNullOrWhiteSpace($issuer) -and $all.Count -gt 0) {
        foreach ($cand in $all) {
          $subj = Get-SubjectRfc2253FromCert $cand
          if (-not [string]::IsNullOrWhiteSpace($subj) -and $subj -eq $issuer) { $extIntermediates += $cand }
        }
      }
    }
    $extText = if ($extIntermediates.Count -gt 0) { ($extIntermediates | ForEach-Object { [IO.Path]::GetFileName($_) } | Sort-Object | Select-Object -Unique) -join ";" } else { "" }

    return [PSCustomObject]@{
      Format                = $format
      CertBlocks            = [string]$info.CertBlocks
      HasChain              = $hasChain
      FinalUse              = if ($hasChain) { "FULLCHAIN_GUESS" } else { "SINGLE_CERT" }
      ExternalIntermediates = $extText
      HasPrivateKey         = $info.HasPrivateKey
      Issuer                = $issuer
      IssuerCN              = $issuerCN
    }
  }

  # DER の場合：ブロック数を数えられないため不明扱い
  return [PSCustomObject]@{
    Format                = $format
    CertBlocks            = ""
    HasChain              = ""
    FinalUse              = "UNKNOWN_DER"
    ExternalIntermediates = ""
    HasPrivateKey         = $false
    Issuer                = ""
    IssuerCN              = ""
  }
}

function Format-CertFormat([string]$fmt) {
  switch ($fmt) {
    "PEM" { return "PEM" }
    "DER" { return "DER" }
    "PKCS7" { return "PKCS7" }
    default { return (T "CheckBasic.Cert.FormatUnknown") }
  }
}

function Get-RelPathIfUnder([string]$baseDir, [string]$fullPath) {
  try {
    $base = (Resolve-Path -LiteralPath $baseDir).Path.TrimEnd('\', '/')
    $full = (Resolve-Path -LiteralPath $fullPath).Path
    if ($full.Length -lt $base.Length) { return "" }
    if ($full.Substring(0, $base.Length).ToLowerInvariant() -ne $base.ToLowerInvariant()) { return "" }
    return $full.Substring($base.Length).TrimStart('\', '/')
  }
  catch {
    return ""
  }
}

function Format-FinalUse([string]$code) {
  switch ($code) {
    "FULLCHAIN_GUESS" { return (T "CheckBasic.Cert.UsableGuess") }
    "SINGLE_CERT" { return (T "CheckBasic.Cert.NeedMerge") }
    "UNKNOWN_PKCS7" { return (T "CheckBasic.Cert.Unk") }
    "UNKNOWN_DER" { return (T "CheckBasic.Cert.Unk") }
    default { return (T "CheckBasic.Cert.Unk") }
  }
}

function Get-NotAfterFromCert([string]$certPath) {
  try {
    $out = Invoke-OpenSsl @("x509", "-in", $certPath, "-noout", "-dates")
    $line = ($out | Where-Object { $_ -match "^notAfter=" } | Select-Object -First 1)
    if (-not $line) { return "" }
    return ([string]$line).Trim().Replace("notAfter=", "")
  }
  catch {
    return ""
  }
}

function Convert-OpenSslDateToLocal([string]$opensslDate) {
  if ([string]::IsNullOrWhiteSpace($opensslDate)) { return "" }
  $raw = ([string]$opensslDate).Trim()
  $raw = [System.Text.RegularExpressions.Regex]::Replace($raw, "\s+", " ")
  $culture = [System.Globalization.CultureInfo]::InvariantCulture
  $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
  $dto = [datetimeoffset]::MinValue
  $ok = [datetimeoffset]::TryParseExact($raw, "MMM d HH:mm:ss yyyy 'GMT'", $culture, $styles, [ref]$dto)
  if (-not $ok) {
    $ok = [datetimeoffset]::TryParse($raw, $culture, $styles, [ref]$dto)
  }
  if (-not $ok) { return "" }
  $local = $dto.ToLocalTime()
  $tz = [System.TimeZoneInfo]::Local
  $zoneName = Get-LocalizedTimeZoneName $tz
  return [PSCustomObject]@{
    LocalTime = $local.ToString("yyyy-MM-dd HH:mm:ss")
    ZoneName  = $zoneName
  }
}

function Get-LocalizedTimeZoneName([System.TimeZoneInfo]$tz) {
  if ($null -eq $tz) { return "" }
  $tzId = [string]$tz.Id
  if ([string]::IsNullOrWhiteSpace($tzId)) { return "" }
  $canonicalId = Get-CanonicalTimeZoneId $tz

  # 1) config.json override: TimeZoneNames.{lang}.{TimeZoneId}
  try {
    if ($null -ne $runtimeConfig -and $null -ne $runtimeConfig.TimeZoneNames) {
      $langTable = $runtimeConfig.TimeZoneNames.$Lang
      if ($null -ne $langTable) {
        $override = $langTable.$canonicalId
        if ([string]::IsNullOrWhiteSpace([string]$override)) { $override = $langTable.$tzId }
        if (-not [string]::IsNullOrWhiteSpace([string]$override)) { return [string]$override }
      }
    }
  }
  catch { }

  # 2) fallback: stable global time zone id (prefer IANA)
  return $canonicalId
}

function Get-CanonicalTimeZoneId([System.TimeZoneInfo]$tz) {
  if ($null -eq $tz) { return "" }
  $tzId = [string]$tz.Id
  if ([string]::IsNullOrWhiteSpace($tzId)) { return "" }
  if ($tzId -match "/") { return $tzId }

  try {
    $m = [System.TimeZoneInfo].GetMethod("TryConvertWindowsIdToIanaId", [type[]]@([string], [string].MakeByRefType()))
    if ($null -ne $m) {
      $args = @($tzId, "")
      $ok = [bool]$m.Invoke($null, $args)
      if ($ok -and -not [string]::IsNullOrWhiteSpace([string]$args[1])) {
        return [string]$args[1]
      }
    }
  }
  catch { }

  return $tzId
}

function Format-CertDateForDisplay([string]$opensslDate) {
  if ([string]::IsNullOrWhiteSpace($opensslDate)) { return "" }
  $local = Convert-OpenSslDateToLocal $opensslDate
  if ($null -ne $local -and -not [string]::IsNullOrWhiteSpace([string]$local.LocalTime)) {
    return ("{0} [{1}] ({2})" -f [string]$local.LocalTime, [string]$local.ZoneName, $opensslDate)
  }
  return $opensslDate
}

function Write-Tag([string]$text, [string]$color) {
  if ([string]::IsNullOrWhiteSpace($text)) { return }
  try {
    Write-Host -NoNewline ("[{0}]" -f $text) -ForegroundColor $color
  }
  catch {
    Write-Host -NoNewline ("[{0}]" -f $text)
  }
}

function Write-TreeLine([int]$indent, [string]$name, [scriptblock]$emitTags) {
  $pad = (" " * $indent)
  Write-Host -NoNewline ($pad + $name)
  if ($emitTags) {
    Write-Host -NoNewline " "
    & $emitTags
  }
  Write-Host ""
}

function Test-KeyReadable([string]$keyPath, [string[]]$passphrases) {
  # 対話プロンプトを絶対に出さないため、暗号化鍵は必ず -passin で読む
  $isEnc = Test-KeyEncrypted $keyPath
  if (-not $isEnc) {
    try {
      Invoke-OpenSsl @("rsa", "-in", $keyPath, "-noout", "-text") | Out-Null
      return (T "Common.Success")
    }
    catch {
      return (T "Common.Failed")
    }
  }

  $usable = @($passphrases | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
  if (-not $usable) { return (T "CheckBasic.Key.SkipNoPass") }

  foreach ($p in @($passphrases)) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    try {
      Invoke-TempPassFile $p {
        param($tmpPass)
        Invoke-OpenSsl @("rsa", "-in", $keyPath, "-noout", "-text", "-passin", ("file:{0}" -f $tmpPass)) | Out-Null
      } | Out-Null
      return (T "Common.Success")
    }
    catch { }
  }
  return (T "Common.Failed")
}



# メニューモジュールを読み込む
$menuModule = Join-Path $PSScriptRoot "lib\\menu.ps1"
if (Test-Path -LiteralPath $menuModule -PathType Leaf) {
  . $menuModule
}

function Get-OrgEntries([string]$folderPath) {
  $orgDirs = @(Get-ChildItem -LiteralPath $folderPath -Directory -ErrorAction SilentlyContinue)
  
  $list = New-Object System.Collections.ArrayList
  
  # -Include の非互換性を避けるため、全ファイルを取得してからフィルタする
  $rootAll = @(Get-ChildItem -LiteralPath $folderPath -File -ErrorAction SilentlyContinue)
  $rootFiles = @($rootAll | Where-Object { $_.Name -match "\.(cer|crt|pem|csr|key|pfx)$" })

  if ($rootFiles.Count -gt 0) {
    $list.Add([PSCustomObject]@{ Name = "(root)"; FullName = $folderPath }) | Out-Null
  }
  foreach ($d in $orgDirs) { $list.Add($d) | Out-Null }
  return @($list)
}

function Get-OrgFiles([string]$orgPath, [string]$orgName, [bool]$hasOrgSubdirs) {
  $list = New-Object System.Collections.ArrayList
  
  $recurse = if ($orgName -eq "(root)" -and $hasOrgSubdirs) { $false } else { $true }
  
  if ($recurse) {
    $candidates = @(Get-ChildItem -LiteralPath $orgPath -Recurse -File -ErrorAction SilentlyContinue)
  }
  else {
    $candidates = @(Get-ChildItem -LiteralPath $orgPath -File -ErrorAction SilentlyContinue)
  }

  $found = @($candidates | Where-Object { $_.Name -match "\.(cer|crt|pem|csr|key|pfx)$" })
  foreach ($f in $found) { $list.Add($f) | Out-Null }
  
  return @($list | Select-Object -Unique)
}

function Get-RelPathUnder([string]$basePath, [string]$fullPath) {
  try {
    $base = [string]$basePath
    $full = [string]$fullPath
    if ($full.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
      $rel = $full.Substring($base.Length).TrimStart('\', '/')
      if (-not [string]::IsNullOrWhiteSpace($rel)) { return $rel }
    }
  }
  catch { }
  return [IO.Path]::GetFileName($fullPath)
}

function Get-PassFilesForOrg([string]$orgPath, [string]$folderPath, [string]$oldRootForNew, [string]$orgName) {
  $passFiles = @()
  $passFiles += (Find-PassFile $orgPath)
  $passFiles += (Find-PassFile $folderPath)
  $passFiles += (Find-PassFile $PSScriptRoot)
  if (-not [string]::IsNullOrWhiteSpace($oldRootForNew)) {
    $passFiles += (Find-PassFile $oldRootForNew)
    if ($orgName -ne "(root)") { $passFiles += (Find-PassFile (Join-Path $oldRootForNew $orgName)) }
  }
  return $passFiles
}

function Show-InteractiveMenu([string]$oldDir, [string]$newDir) {
  $mergedDir = $toolMergedDir
  $selfSignedDir = $toolSelfSignedDir
  
  try { $null = $host.UI.RawUI } catch {
    Show-Folder $oldDir (T "Label.Old") ""
    Show-Folder $newDir (T "Label.New") $oldDir
    if (Test-Path -LiteralPath $mergedDir -PathType Container) {
      Show-Folder $mergedDir (T "Label.Merged") ""
    }
    if (Test-Path -LiteralPath $selfSignedDir -PathType Container) {
      Show-Folder $selfSignedDir (T "Label.SelfSigned") ""
    }
    return
  }

  # カーソルを隠す
  try { [Console]::CursorVisible = $false } catch { }

  try {
    while ($true) {
      $rootItems = @(
        ("{0}" -f (T "Label.Old")),
        ("{0}" -f (T "Label.New")),
        ("{0}" -f (T "Label.Merged")),
        ("{0}" -f (T "Label.SelfSigned")),
        ("[ {0} ]" -f (T "Common.MenuQuit"))
      )
      $rootSel = Show-MenuSelect -title (T "CheckBasic.Menu.RootTitle") -items $rootItems -helpText (T "CheckBasic.Menu.Instruction")
      if ($null -eq $rootSel -or $rootSel -eq $rootItems.Count) { return }
  
      $label = switch ($rootSel) {
        1 { (T "Label.Old") }
        2 { (T "Label.New") }
        3 { (T "Label.Merged") }
        4 { (T "Label.SelfSigned") }
      }
      $folder = switch ($rootSel) {
        1 { $oldDir }
        2 { $newDir }
        3 { $mergedDir }
        4 { $selfSignedDir }
      }
      $oldRootForNew = if ($rootSel -eq 2) { $oldDir } else { "" }
  
      if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
        Write-Host (T "Common.FolderNotFound" @($label, $folder))
        continue
      }
  
      while ($true) {
        $orgEntries = @(Get-OrgEntries $folder)
        
        if ($orgEntries.Count -eq 0) {
          Write-Host (T "Common.NoTargetFiles")
          break
        }
        $hasOrgSubdirs = @($orgEntries | Where-Object { $_.Name -ne "(root)" }).Count -gt 0
  
        $orgItems = @()
        for ($i = 0; $i -lt $orgEntries.Count; $i++) {
          $org = $orgEntries[$i]
          $orgFiles = @(Get-OrgFiles $org.FullName $org.Name $hasOrgSubdirs)
          $count = $orgFiles.Count
          $orgItems += ("{0} (files={1})" -f $org.Name, $count)
        }
        $orgItems += ("[ {0} ]" -f (T "Common.MenuBack"))
        
        $orgSel = Show-MenuSelect -title (T "CheckBasic.Menu.OrgTitle" $label) -items $orgItems -helpText (T "CheckBasic.Menu.Instruction")
        if ($null -eq $orgSel -or $orgSel -eq $orgItems.Count) { break }
  
        $org = $orgEntries[$orgSel - 1]
        $files = @(Get-OrgFiles $org.FullName $org.Name $hasOrgSubdirs)
        if ($files.Count -eq 0) {
          Write-Host (T "Common.NoTargetFiles")
          continue
        }
  
        while ($true) {
          $fileItems = @()
          for ($i = 0; $i -lt $files.Count; $i++) {
            $rel = Get-RelPathUnder $org.FullName $files[$i].FullName
            $fileItems += $rel
          }
          $fileItems += ("[ {0} ]" -f (T "Common.MenuBack"))
          
          $fileSel = Show-MenuSelect -title (T "CheckBasic.Menu.FileTitle" $org.Name) -items $fileItems -helpText (T "CheckBasic.Menu.Instruction")
          if ($null -eq $fileSel -or $fileSel -eq $fileItems.Count) { break }
  
          $f = $files[$fileSel - 1]
          $passFiles = Get-PassFilesForOrg $org.FullName $folder $oldRootForNew $org.Name
          $passphrases = Get-Passphrases $passFiles
          Show-OneFile -FilePath $f.FullName -Passphrases $passphrases -PassFiles $passFiles
          Write-Host (T "CheckBasic.Menu.BackPrompt") -ForegroundColor DarkGray
          try { $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { }
        }
      }
    }
  }
  finally {
    # 終了時にカーソルと色を戻す
    try { [Console]::ResetColor() } catch { }
    try { [Console]::CursorVisible = $true } catch { }
  }
}





function Get-KeyBit([string]$keyPath, [string[]]$passphrases) {
  # OpenSSL の対話プロンプトを絶対に出さないため、暗号化鍵は必ず -passin で読む
  $isEnc = Test-KeyEncrypted $keyPath
  if (-not $isEnc) {
    try {
      $out = Invoke-OpenSsl @("rsa", "-in", $keyPath, "-noout", "-text")
      $line = ($out | Select-Object -First 1)
      if ($line) { $line | Write-Output }
      return $true
    }
    catch { }
  }

  foreach ($p in @($passphrases)) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    try {
      Invoke-TempPassFile $p {
        param($tmpPass)
        $out = Invoke-OpenSsl @("rsa", "-in", $keyPath, "-noout", "-text", "-passin", ("file:{0}" -f $tmpPass))
        $line = ($out | Select-Object -First 1)
        if ($line) { $line | Write-Output }
      }
      return $true
    }
    catch { }
  }

  if ($isEnc) {
    Write-Host (T "CheckBasic.Detail.Key.CannotReadNeedPass" @($FixedPassFileName))
  }
  else {
    Write-Host (T "CheckBasic.Detail.Key.CannotRead")
  }
  return $false
}

# === 暗号化対応キー Modulus 取得 ===
function Get-KeyModulus([string]$keyPath, [string[]]$passphrases) {
  $isEnc = Test-KeyEncrypted $keyPath
  if (-not $isEnc) {
    try {
      $out = (Invoke-OpenSsl @("rsa", "-in", $keyPath, "-noout", "-modulus") | Out-String) -replace "Modulus=", ""
      return $out.Trim()
    }
    catch { return $null }
  }

  foreach ($p in @($passphrases)) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    try {
      $result = Invoke-TempPassFile $p {
        param($tmpPass)
        $out = (Invoke-OpenSsl @("rsa", "-in", $keyPath, "-noout", "-modulus", "-passin", ("file:{0}" -f $tmpPass)) | Out-String) -replace "Modulus=", ""
        $out.Trim()
      }
      if (-not [string]::IsNullOrWhiteSpace($result)) { return $result }
    }
    catch { }
  }
  return $null
}

# === ファイル整合性検証 ===
function Show-FileMatching([string]$filePath, [string[]]$passphrases = @()) {
  $dir = [IO.Path]::GetDirectoryName($filePath)
  if ([string]::IsNullOrWhiteSpace($dir)) { return }
  
  # 同一ディレクトリ内の関連ファイルを検索（同一ベースネーム優先）
  $base = [IO.Path]::GetFileNameWithoutExtension($filePath)
  $csrFile = Get-ChildItem -LiteralPath $dir -Filter "$base.csr" -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $csrFile) { $csrFile = Get-ChildItem -LiteralPath $dir -Filter "*.csr" -File -ErrorAction SilentlyContinue | Select-Object -First 1 }
  $keyFile = Get-ChildItem -LiteralPath $dir -Filter "$base.key" -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $keyFile) { $keyFile = Get-ChildItem -LiteralPath $dir -Filter "*.key" -File -ErrorAction SilentlyContinue | Select-Object -First 1 }
  $cerFile = Get-ChildItem -LiteralPath $dir -Filter "$base.cer" -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $cerFile) { $cerFile = Get-ChildItem -LiteralPath $dir -Filter "$base.crt" -File -ErrorAction SilentlyContinue | Select-Object -First 1 }
  if (-not $cerFile) { $cerFile = Get-ChildItem -LiteralPath $dir -Filter "*.cer" -File -ErrorAction SilentlyContinue | Select-Object -First 1 }
  if (-not $cerFile) { $cerFile = Get-ChildItem -LiteralPath $dir -Filter "*.crt" -File -ErrorAction SilentlyContinue | Select-Object -First 1 }
  $tsvFile = Get-ChildItem -LiteralPath $dir -Filter "$base.tsv" -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $tsvFile) { $tsvFile = Get-ChildItem -LiteralPath $dir -Filter "*.tsv" -File -ErrorAction SilentlyContinue | Select-Object -First 1 }
  $pfxFile = Get-ChildItem -LiteralPath $dir -Filter "$base.pfx" -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $pfxFile) { $pfxFile = Get-ChildItem -LiteralPath $dir -Filter "*.pfx" -File -ErrorAction SilentlyContinue | Select-Object -First 1 }
  
  # 比較には2つ以上のファイルが必要
  $foundCount = @($csrFile, $keyFile, $cerFile, $tsvFile, $pfxFile | Where-Object { $_ }).Count
  if ($foundCount -lt 2) { return }
  
  Write-Host ""
  Write-HeaderBar (T "Matching.Title") ""
  
  $results = @()
  
  # 1. KEY-CSR Modulus Check
  if ($keyFile -and $csrFile) {
    try {
      $keyMod = Get-KeyModulus $keyFile.FullName $passphrases
      if ($null -eq $keyMod) { throw "Cannot read key modulus" }
      $csrMod = (Invoke-OpenSsl @("req", "-in", $csrFile.FullName, "-noout", "-modulus") | Out-String) -replace "Modulus=", ""
      $match = ($keyMod.Trim() -eq $csrMod.Trim())
      $label = "{0} [{1} / {2}]" -f (T "Matching.KeyCsr"), $keyFile.Name, $csrFile.Name
      $results += @{ Name = $label; Pass = $match }
    }
    catch { $results += @{ Name = (T "Matching.KeyCsr"); Pass = $false } }
  }
  
  # 2. KEY-CER Modulus Check
  if ($keyFile -and $cerFile) {
    try {
      $keyMod = Get-KeyModulus $keyFile.FullName $passphrases
      if ($null -eq $keyMod) { throw "Cannot read key modulus" }
      $cerMod = (Invoke-OpenSsl @("x509", "-in", $cerFile.FullName, "-noout", "-modulus") | Out-String) -replace "Modulus=", ""
      $match = ($keyMod.Trim() -eq $cerMod.Trim())
      $label = "{0} [{1} / {2}]" -f (T "Matching.KeyCer"), $keyFile.Name, $cerFile.Name
      $results += @{ Name = $label; Pass = $match }
    }
    catch { $results += @{ Name = (T "Matching.KeyCer"); Pass = $false } }
  }
  
  # 3. CSR-TSV Check (CN and CSR content)
  if ($csrFile -and $tsvFile) {
    try {
      # CSRからCNを取得
      $csrSubj = (Invoke-OpenSsl @("req", "-in", $csrFile.FullName, "-noout", "-subject") | Out-String)
      $cnMatch = [regex]::Match($csrSubj, "CN\s*=\s*([^,/\r\n]+)")
      $csrCn = if ($cnMatch.Success) { $cnMatch.Groups[1].Value.Trim() } else { "" }
      
      # Read TSV (Shift-JIS)
      $sjis = [System.Text.Encoding]::GetEncoding(932)
      $tsvContent = [System.IO.File]::ReadAllText($tsvFile.FullName, $sjis)
      $tsvParts = $tsvContent -split "`t"
      
      if ($tsvParts.Count -ge 13) {
        $tsvCn = $tsvParts[10].Trim()
        $tsvCsr = $tsvParts[6].Trim()
        
        # CN一致チェック
        $cnOk = ($csrCn -eq $tsvCn)
        $labelCn = "{0} [{1} / {2}]" -f (T "Matching.CsrTsvCn"), $csrFile.Name, $tsvFile.Name
        $results += @{ Name = $labelCn; Pass = $cnOk }
        
        # CSR内容一致チェック
        $csrLines = Get-Content -LiteralPath $csrFile.FullName
        $csrBase64 = ($csrLines | Where-Object { $_ -notmatch "^----" }) -join ""
        $csrOk = ($csrBase64 -eq $tsvCsr)
        $labelContent = "{0} [{1} / {2}]" -f (T "Matching.CsrTsvContent"), $csrFile.Name, $tsvFile.Name
        $results += @{ Name = $labelContent; Pass = $csrOk }
      }
    }
    catch { }
  }


  # 4. KEY-PFX Modulus Check
  if ($keyFile -and $pfxFile) {
    try {
      $keyMod = Get-KeyModulus $keyFile.FullName $passphrases
      if ($null -eq $keyMod) { throw "Cannot read key modulus" }
       
      $pfxMod = ""
      foreach ($p in @("") + $passphrases) {
        $isPass = -not [string]::IsNullOrWhiteSpace($p)
        try {
          $certOut = ""
          if ($isPass) {
            $certOut = Invoke-TempPassFile $p { param($tmp)
              Invoke-Pkcs12 @("-in", $pfxFile.FullName, "-nokeys", "-clcerts", "-passin", "file:$tmp")
            }
          }
          else {
            $certOut = Invoke-Pkcs12 @("-in", $pfxFile.FullName, "-nokeys", "-clcerts", "-passin", "pass:")
          }
             
          if (-not [string]::IsNullOrWhiteSpace($certOut)) {
            $tmpCert = [IO.Path]::GetTempFileName()
            try {
              Set-Content -LiteralPath $tmpCert -Value $certOut -Encoding ASCII
              $pfxMod = (Invoke-OpenSsl @("x509", "-in", $tmpCert, "-noout", "-modulus") | Out-String) -replace "Modulus=", ""
            }
            finally {
              Remove-Item $tmpCert -Force -ErrorAction SilentlyContinue
            }
            if (-not [string]::IsNullOrWhiteSpace($pfxMod)) { break }
          }
        }
        catch {}
      }

      if (-not [string]::IsNullOrWhiteSpace($pfxMod)) {
        $match = ($keyMod.Trim() -eq $pfxMod.Trim())
        $label = "KEY ⇔ PFX [{0} / {1}]" -f $keyFile.Name, $pfxFile.Name
        $results += @{ Name = $label; Pass = $match }
      }
      else {
        $results += @{ Name = "KEY ⇔ PFX (Locked)"; Pass = $false }
      }
    }
    catch { 
      $results += @{ Name = "KEY ⇔ PFX (Error)"; Pass = $false } 
    }
  }
  
  # 結果表示
  for ($i = 0; $i -lt $results.Count; $i++) {
    $r = $results[$i]
    $isLast = ($i -eq ($results.Count - 1))
    $mark = if ($r.Pass) { "[OK]" } else { "[NG]" }
    $col = if ($r.Pass) { "Green" } else { "Red" }
    Write-TreeProp $isLast $r.Name $mark $col
  }
}

function Show-OneFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [Parameter(Mandatory = $false)]
    [string[]]$Passphrases = @(),
    [Parameter(Mandatory = $false)]
    [string[]]$PassFiles = @()
  )
  Assert-ExistsFile $FilePath "入力ファイル"

  # 画面をクリアして専用ビューとして表示（メニューとの混在を防ぐ）
  Clear-Host

  # --- Local UI Helpers ---
  function Write-HeaderBar([string]$title, [string]$path) {
    Write-Host " " -NoNewline -BackgroundColor White
    Write-Host (" {0} " -f $title) -NoNewline -BackgroundColor White -ForegroundColor Black
    Write-Host " " -NoNewline -BackgroundColor White
    Write-Host (" {0}" -f $path)
  }

  function Write-TreeProp([bool]$last, [string]$label, [string]$value, [ConsoleColor]$valColor = [ConsoleColor]::Gray, [string]$indent = "") {
    $mark = if ($last) { "└──" } else { "├──" }
    Write-Host ("{0}{1} {2}: " -f $indent, $mark, $label) -NoNewline -ForegroundColor DarkGray
    Write-Host $value -ForegroundColor $valColor
  }

  # Subject や Issuer を階層表示する関数
  function Write-TreeDN([bool]$last, [string]$label, [string]$dn, [string]$indent = "") {
    $mark = if ($last) { "└──" } else { "├──" }
    $connector = if ($last) { "    " } else { "│   " }
    $prefix = $indent + $connector
    
    Write-Host ("{0}{1} {2}" -f $indent, $mark, $label) -ForegroundColor DarkGray
    
    # DN を解析 (RFC2253 形式: CN=xxx,O=xxx,L=xxx,ST=xxx,C=xx)
    # カンマで分割するが、エスケープされたカンマは除外
    $parts = @()
    $current = ""
    $escaped = $false
    foreach ($c in $dn.ToCharArray()) {
      if ($escaped) {
        $current += $c
        $escaped = $false
      }
      elseif ($c -eq '\') {
        $current += $c
        $escaped = $true
      }
      elseif ($c -eq ',') {
        if ($current.Trim()) { $parts += $current.Trim() }
        $current = ""
      }
      else {
        $current += $c
      }
    }
    if ($current.Trim()) { $parts += $current.Trim() }
    
    # 各パートを表示
    for ($i = 0; $i -lt $parts.Count; $i++) {
      $isLastPart = ($i -eq ($parts.Count - 1))
      $subMark = if ($isLastPart) { "└──" } else { "├──" }
      $part = $parts[$i]
      
      # キーと値に分割
      if ($part -match "^([^=]+)=(.*)$") {
        $key = $Matches[1].Trim()
        $val = $Matches[2].Trim()
        # キー名を分かりやすく
        $keyName = switch ($key) {
          "CN" { "CN (Common Name)" }
          "O" { "O (Organization)" }
          "OU" { "OU (Org Unit)" }
          "L" { "L (Locality)" }
          "ST" { "ST (State)" }
          "C" { "C (Country)" }
          "emailAddress" { "Email" }
          default { $key }
        }
        Write-Host ("{0}{1} {2}: " -f $prefix, $subMark, $keyName) -NoNewline -ForegroundColor DarkGray
        Write-Host $val -ForegroundColor Gray
      }
      else {
        Write-Host ("{0}{1} {2}" -f $prefix, $subMark, $part) -ForegroundColor Gray
      }
    }
  }

  # CertStore からブロックの元ファイルを検索
  function Find-CertSourceFile([string]$pemBlock) {
    $certStoreRoot = $CertConfig.CertStoreRoot
    if ([string]::IsNullOrWhiteSpace($certStoreRoot)) { $certStoreRoot = "CertStore" }
    $storeDir = Join-Path $ToolkitRoot $certStoreRoot
    if (-not (Test-Path -LiteralPath $storeDir -PathType Container)) { return "" }
    $needle = $pemBlock.Trim() -replace "`r`n", "`n" -replace "`r", "`n"
    $cerFiles = @(Get-ChildItem -LiteralPath $storeDir -Recurse -File -Include *.cer, *.crt, *.pem -ErrorAction SilentlyContinue)
    foreach ($f in $cerFiles) {
      $content = (Get-Content -LiteralPath $f.FullName -Raw) -replace "`r`n", "`n" -replace "`r", "`n"
      if ($content.Contains($needle)) {
        return $f.Name
      }
    }
    return ""
  }

  # PEM ファイルから個々の証明書ブロックを抽出
  function Split-PemCertBlocks([string]$pemPath) {
    $content = Get-Content -LiteralPath $pemPath -Raw
    $blocks = @()
    $re = [regex]::new("-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    foreach ($m in $re.Matches($content)) {
      $blocks += $m.Value
    }
    return $blocks
  }

  # チェーン内の各ブロックのラベルを返す
  function Get-ChainBlockLabel([int]$index, [int]$total) {
    if ($index -eq 0) {
      return "{0} ({1}/{2})" -f (T "Label.ChainBlockServer"), ($index + 1), $total
    }
    if ($index -eq ($total - 1) -and $total -ge 3) {
      return "{0} ({1}/{2})" -f (T "Label.ChainBlockRoot"), ($index + 1), $total
    }
    return "{0} ({1}/{2})" -f (T "Label.ChainBlockIntermediate"), ($index + 1), $total
  }

  # PEM ブロックから証明書情報を解析
  function Parse-CertBlockData([string]$pemContent) {
    $tmpBlock = [IO.Path]::GetTempFileName()
    try {
      Set-Content -LiteralPath $tmpBlock -Value $pemContent -Encoding ASCII
      $blockRaw = Invoke-OpenSsl @("x509", "-in", $tmpBlock, "-noout", "-subject", "-issuer", "-dates", "-nameopt", "RFC2253")
    }
    finally {
      Remove-Item $tmpBlock -Force -ErrorAction SilentlyContinue
    }
    $bd = @{}
    foreach ($line in $blockRaw) {
      if ($line -match "^subject=(.*)") { $bd["subject"] = $matches[1] }
      if ($line -match "^issuer=(.*)") { $bd["issuer"] = $matches[1] }
      if ($line -match "^notBefore=(.*)") { $bd["notBefore"] = $matches[1] }
      if ($line -match "^notAfter=(.*)") { $bd["notAfter"] = $matches[1] }
    }
    return $bd
  }

  # 1つの証明書ブロックの詳細を表示（解析済みデータを受け取る）
  function Show-OneCertBlockDetail([hashtable]$bd, [string]$blockLabel, [string]$blockPrefix, [bool]$isLastBlock, [bool]$showIssuer = $true) {
    $blockMark = if ($isLastBlock) { "└──" } else { "├──" }
    $connector = if ($isLastBlock) { "    " } else { "│   " }
    $childPrefix = $blockPrefix + $connector

    Write-Host ("{0}{1} {2}" -f $blockPrefix, $blockMark, $blockLabel) -ForegroundColor Cyan

    Write-TreeDN $false (T "Label.Subject") ([string]$bd["subject"]) $childPrefix
    if ($showIssuer) {
      Write-TreeDN $false (T "Label.Issuer") ([string]$bd["issuer"]) $childPrefix
    }
    Write-TreeProp $false (T "Label.NotBefore") (Format-CertDateForDisplay ([string]$bd["notBefore"])) ([ConsoleColor]::Gray) $childPrefix
    Write-TreeProp $true  (T "Label.NotAfter")  (Format-CertDateForDisplay ([string]$bd["notAfter"])) ([ConsoleColor]::Gray) $childPrefix
  }

  function Show-OpenSslDetails([string]$path, [string[]]$passphrases = @()) {
    Write-Host ""
    Write-HeaderBar (T "Label.OpenSslDetails") ""
    $ext = [IO.Path]::GetExtension($path).ToLowerInvariant()
    $isCsr = ($ext -eq ".csr")
    $isPfx = ($ext -eq ".pfx")

    try {
      $raw = @()
      $sanList = @()
      if ($isCsr) {
        $raw = Invoke-OpenSsl @("req", "-in", $path, "-noout", "-text", "-nameopt", "RFC2253")
        # Parse SAN from CSR text output
        $inSanBlock = $false
        foreach ($line in $raw) {
          if ($line -match "X509v3 Subject Alternative Name") {
            $inSanBlock = $true
            continue
          }
          if ($inSanBlock) {
            if ($line -match "DNS:|IP Address:|IP:") {
              $entries = $line -split ", "
              foreach ($e in $entries) {
                $sanList += $e.Trim()
              }
              $inSanBlock = $false
            }
          }
        }

        $data = @{}
        foreach ($line in $raw) {
          if ($line -match "^\s*subject=(.*)") { $data["subject"] = $matches[1] }
          if ($line -match "^subject=(.*)") { $data["subject"] = $matches[1] }
        }
        $subjRaw = Invoke-OpenSsl @("req", "-in", $path, "-noout", "-subject", "-nameopt", "RFC2253")
        if ($subjRaw -match "^subject=(.*)") { $data["subject"] = $matches[1] }

        $hasSan = ($sanList.Count -gt 0)
        $isLastParams = -not $hasSan
        Write-TreeDN $isLastParams (T "Label.Subject") ([string]$data["subject"])

        if ($hasSan) {
          Write-TreeProp $false (T "CheckBasic.Cert.SAN") ""
          for ($i = 0; $i -lt $sanList.Count; $i++) {
            $isLast = ($i -eq ($sanList.Count - 1))
            $mark = if ($isLast) { "└──" } else { "├──" }
            Write-Host ("│   {0} {1}" -f $mark, $sanList[$i]) -ForegroundColor Gray
          }
        }
      }
      elseif ($isPfx) {
        # Extract ALL certificates from PFX (not just client cert)
        $allCertPem = ""
        foreach ($p in @("") + $passphrases) {
          try {
            if ([string]::IsNullOrWhiteSpace($p)) {
              $allCertPem = Invoke-Pkcs12 @("-in", $path, "-nokeys", "-passin", "pass:") | Out-String
            }
            else {
              $allCertPem = Invoke-TempPassFile $p { param($tmp)
                Invoke-Pkcs12 @("-in", $path, "-nokeys", "-passin", "file:$tmp") | Out-String
              }
            }
            if (-not [string]::IsNullOrWhiteSpace($allCertPem)) { break }
          }
          catch {}
        }
        
        if ([string]::IsNullOrWhiteSpace($allCertPem)) {
          Write-Host (T "CheckBasic.Detail.Key.CannotReadNeedPass" @("PassFile")) -ForegroundColor Red
          return
        }

        $tmpPfxCert = [IO.Path]::GetTempFileName()
        try {
          Set-Content -LiteralPath $tmpPfxCert -Value $allCertPem -Encoding ASCII
          $pemBlocks = @(Split-PemCertBlocks $tmpPfxCert)
        }
        finally {
          Remove-Item $tmpPfxCert -Force -ErrorAction SilentlyContinue
        }

        if ($pemBlocks.Count -gt 1) {
          $allBlockData = @()
          foreach ($block in $pemBlocks) {
            $allBlockData += Parse-CertBlockData $block
          }
          for ($bi = 0; $bi -lt $pemBlocks.Count; $bi++) {
            $isLastBlock = ($bi -eq ($pemBlocks.Count - 1))
            $blockLabel = Get-ChainBlockLabel $bi $pemBlocks.Count
            if ($bi -gt 0) {
              $srcFile = Find-CertSourceFile $pemBlocks[$bi]
              if (-not [string]::IsNullOrWhiteSpace($srcFile)) {
                $blockLabel = "{0} [{1}]" -f $blockLabel, $srcFile
              }
            }
            $showIssuer = $true
            if (-not $isLastBlock) {
              $myIssuer = ([string]$allBlockData[$bi]["issuer"]).Trim()
              $nextSubject = ([string]$allBlockData[$bi + 1]["subject"]).Trim()
              if ($myIssuer -eq $nextSubject) { $showIssuer = $false }
            }
            Show-OneCertBlockDetail $allBlockData[$bi] $blockLabel "" $isLastBlock $showIssuer
          }
        }
        else {
          $tmpSingle = [IO.Path]::GetTempFileName()
          try {
            Set-Content -LiteralPath $tmpSingle -Value $pemBlocks[0] -Encoding ASCII
            $raw = Invoke-OpenSsl @("x509", "-in", $tmpSingle, "-noout", "-subject", "-issuer", "-dates", "-nameopt", "RFC2253")
          }
          finally {
            Remove-Item $tmpSingle -Force -ErrorAction SilentlyContinue
          }
          $data = @{}
          foreach ($line in $raw) {
            if ($line -match "^subject=(.*)") { $data["subject"] = $matches[1] }
            if ($line -match "^issuer=(.*)") { $data["issuer"] = $matches[1] }
            if ($line -match "^notBefore=(.*)") { $data["notBefore"] = $matches[1] }
            if ($line -match "^notAfter=(.*)") { $data["notAfter"] = $matches[1] }
          }
          Write-TreeDN $false (T "Label.Subject") ([string]$data["subject"])
          Write-TreeDN $false (T "Label.Issuer") ([string]$data["issuer"])
          Write-TreeProp $false (T "Label.NotBefore") (Format-CertDateForDisplay ([string]$data["notBefore"]))
          Write-TreeProp $true  (T "Label.NotAfter")  (Format-CertDateForDisplay ([string]$data["notAfter"]))
        }
      }
      else {
        # 証明書ファイル：複数ブロックの場合は個別に表示
        $pemBlocks = @(Split-PemCertBlocks $path)
        if ($pemBlocks.Count -gt 1) {
          # 全ブロックを先に解析
          $allBlockData = @()
          foreach ($block in $pemBlocks) {
            $allBlockData += Parse-CertBlockData $block
          }
          # 各ブロックを表示（Issuer が次ブロックの Subject と一致する場合は省略）
          for ($bi = 0; $bi -lt $pemBlocks.Count; $bi++) {
            $isLastBlock = ($bi -eq ($pemBlocks.Count - 1))
            $blockLabel = Get-ChainBlockLabel $bi $pemBlocks.Count
            if ($bi -gt 0) {
              $srcFile = Find-CertSourceFile $pemBlocks[$bi]
              if (-not [string]::IsNullOrWhiteSpace($srcFile)) {
                $blockLabel = "{0} [{1}]" -f $blockLabel, $srcFile
              }
            }
            $showIssuer = $true
            if (-not $isLastBlock) {
              $myIssuer = ([string]$allBlockData[$bi]["issuer"]).Trim()
              $nextSubject = ([string]$allBlockData[$bi + 1]["subject"]).Trim()
              if ($myIssuer -eq $nextSubject) { $showIssuer = $false }
            }
            Show-OneCertBlockDetail $allBlockData[$bi] $blockLabel "" $isLastBlock $showIssuer
          }
        }
        else {
          $raw = Invoke-OpenSsl @("x509", "-in", $path, "-noout", "-subject", "-issuer", "-dates", "-nameopt", "RFC2253")

          $data = @{}
          foreach ($line in $raw) {
            if ($line -match "^subject=(.*)") { $data["subject"] = $matches[1] }
            if ($line -match "^issuer=(.*)") { $data["issuer"] = $matches[1] }
            if ($line -match "^notBefore=(.*)") { $data["notBefore"] = $matches[1] }
            if ($line -match "^notAfter=(.*)") { $data["notAfter"] = $matches[1] }
          }

          Write-TreeDN $false (T "Label.Subject") ([string]$data["subject"])
          Write-TreeDN $false (T "Label.Issuer") ([string]$data["issuer"])
          Write-TreeProp $false (T "Label.NotBefore") (Format-CertDateForDisplay ([string]$data["notBefore"]))
          Write-TreeProp $true  (T "Label.NotAfter")  (Format-CertDateForDisplay ([string]$data["notAfter"]))
        }
      }
    }
    catch {
      $cmd = if ($isCsr) { "req" } else { "x509" }
      Write-Host (T "Common.OpenSslCmdFailed" @($cmd, $_)) -ForegroundColor Red
    }
  }
  # ------------------------

  $ext = [IO.Path]::GetExtension($FilePath).ToLowerInvariant()
  # ヘッダー表示
  Write-HeaderBar (T "Label.File") ""

  switch ($ext) {
    ".cer" {
      $sum = Get-CertChainSummary $FilePath
      $san = Get-SubjectAltNamesFromCert $FilePath
      
      # [Improvement] Show Filename clearly at the top
      Write-TreeProp $false (T "CheckBasic.Pretty.File") ([IO.Path]::GetFileName($FilePath)) "Cyan"
      Write-TreeProp $false (T "CheckBasic.Pretty.Path") (Split-Path -Parent $FilePath) "DarkGray"
      Write-TreeProp $false (T "Label.FileType") (T "Label.Cert") "Cyan"

      $chainPath = Find-ChainFileForCert $FilePath $ChainFile $script:ChainSearchDirs
      $chainSum = Get-ChainFileSummary $chainPath

      # Properties
      Write-TreeProp $false (T "Label.Format") (Format-CertFormat $sum.Format)
      
      if (-not [string]::IsNullOrWhiteSpace($sum.CertBlocks)) {
        Write-TreeProp $false (T "Label.Blocks") $sum.CertBlocks
      }
      
      $hasChainStr = if ($sum.HasChain -is [bool]) { Format-YesNo $sum.HasChain } else { "-" }
      Write-TreeProp $false (T "Label.HasChain") $hasChainStr
      
      Write-TreeProp $false (T "Label.FinalUse") (Format-FinalUse $sum.FinalUse) "Cyan"

      if ($chainSum.Found) {
        Write-TreeProp $false (T "CheckBasic.Cert.ChainFile") $chainPath
        if (-not [string]::IsNullOrWhiteSpace($chainSum.CertBlocks)) {
          Write-TreeProp $false (T "CheckBasic.Cert.ChainBlocks") $chainSum.CertBlocks
        }
        Write-TreeProp $false (T "CheckBasic.Cert.ChainFormat") (Format-CertFormat $chainSum.Format)
      }

      if (-not [string]::IsNullOrWhiteSpace($san)) {
        $sanList = $san -split "; "
        if ($sanList.Count -eq 1) {
          Write-TreeProp $false (T "CheckBasic.Cert.SAN") $sanList[0]
        }
        else {
          Write-TreeProp $false (T "CheckBasic.Cert.SAN") ""
          for ($i = 0; $i -lt $sanList.Count; $i++) {
            $isLast = ($i -eq ($sanList.Count - 1))
            $mark = if ($isLast) { "└──" } else { "├──" }
            Write-Host ("│   {0} {1}" -f $mark, $sanList[$i]) -ForegroundColor Gray
          }
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($sum.ExternalIntermediates)) {
        $cands = ($sum.ExternalIntermediates -split ";" | Select-Object -Unique -First 5) -join "; "
        Write-TreeProp $false (T "Label.ExtChainCand") $cands
      }

      $hasKeyStr = if ($sum.HasPrivateKey) { (T "Common.Yes") } else { (T "Common.No") }
      $hasKeyColor = if ($sum.HasPrivateKey) { [ConsoleColor]::Red } else { [ConsoleColor]::Green }
      Write-TreeProp $true (T "CheckBasic.Detail.Cert.HasPrivateKey") $hasKeyStr $hasKeyColor
      
      Show-OpenSslDetails $FilePath
      break
    }
    ".crt" {
      $sum = Get-CertChainSummary $FilePath
      $san = Get-SubjectAltNamesFromCert $FilePath
      
      Write-TreeProp $false (T "CheckBasic.Pretty.File") ([IO.Path]::GetFileName($FilePath)) "Cyan"
      Write-TreeProp $false (T "CheckBasic.Pretty.Path") (Split-Path -Parent $FilePath) "DarkGray"
      Write-TreeProp $false (T "Label.FileType") (T "Label.Cert") "Cyan"

      $chainPath = Find-ChainFileForCert $FilePath $ChainFile $script:ChainSearchDirs
      $chainSum = Get-ChainFileSummary $chainPath

      Write-TreeProp $false (T "Label.Format") (Format-CertFormat $sum.Format)
      if (-not [string]::IsNullOrWhiteSpace($sum.CertBlocks)) {
        Write-TreeProp $false (T "Label.Blocks") $sum.CertBlocks
      }
      $hasChainStr = if ($sum.HasChain -is [bool]) { Format-YesNo $sum.HasChain } else { "-" }
      Write-TreeProp $false (T "Label.HasChain") $hasChainStr
      
      Write-TreeProp $false (T "Label.FinalUse") (Format-FinalUse $sum.FinalUse) "Cyan"

      if ($chainSum.Found) {
        Write-TreeProp $false (T "CheckBasic.Cert.ChainFile") $chainPath
        if (-not [string]::IsNullOrWhiteSpace($chainSum.CertBlocks)) {
          Write-TreeProp $false (T "CheckBasic.Cert.ChainBlocks") $chainSum.CertBlocks
        }
        Write-TreeProp $false (T "CheckBasic.Cert.ChainFormat") (Format-CertFormat $chainSum.Format)
      }

      if (-not [string]::IsNullOrWhiteSpace($san)) {
        $sanList = $san -split "; "
        if ($sanList.Count -eq 1) {
          Write-TreeProp $false (T "CheckBasic.Cert.SAN") $sanList[0]
        }
        else {
          Write-TreeProp $false (T "CheckBasic.Cert.SAN") ""
          for ($i = 0; $i -lt $sanList.Count; $i++) {
            $isLast = ($i -eq ($sanList.Count - 1))
            $mark = if ($isLast) { "└──" } else { "├──" }
            Write-Host ("│   {0} {1}" -f $mark, $sanList[$i]) -ForegroundColor Gray
          }
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($sum.ExternalIntermediates)) {
        $cands = ($sum.ExternalIntermediates -split ";" | Select-Object -Unique -First 5) -join "; "
        Write-TreeProp $false (T "Label.ExtChainCand") $cands
      }
      
      $hasKeyStr = if ($sum.HasPrivateKey) { (T "Common.Yes") } else { (T "Common.No") }
      $hasKeyColor = if ($sum.HasPrivateKey) { [ConsoleColor]::Red } else { [ConsoleColor]::Green }
      Write-TreeProp $true (T "CheckBasic.Detail.Cert.HasPrivateKey") $hasKeyStr $hasKeyColor

      Show-OpenSslDetails $FilePath
      break
    }
    ".pem" {
      $sum = Get-CertChainSummary $FilePath
      $san = Get-SubjectAltNamesFromCert $FilePath
      
      Write-TreeProp $false (T "CheckBasic.Pretty.File") ([IO.Path]::GetFileName($FilePath)) "Cyan"
      Write-TreeProp $false (T "CheckBasic.Pretty.Path") (Split-Path -Parent $FilePath) "DarkGray"
      Write-TreeProp $false (T "Label.FileType") (T "Label.Cert") "Cyan"

      $chainPath = Find-ChainFileForCert $FilePath $ChainFile $script:ChainSearchDirs
      $chainSum = Get-ChainFileSummary $chainPath

      Write-TreeProp $false (T "Label.Format") (Format-CertFormat $sum.Format)
      if (-not [string]::IsNullOrWhiteSpace($sum.CertBlocks)) {
        Write-TreeProp $false (T "Label.Blocks") $sum.CertBlocks
      }
      $hasChainStr = if ($sum.HasChain -is [bool]) { Format-YesNo $sum.HasChain } else { "-" }
      Write-TreeProp $false (T "Label.HasChain") $hasChainStr
      
      Write-TreeProp $false (T "Label.FinalUse") (Format-FinalUse $sum.FinalUse) "Cyan"

      if ($chainSum.Found) {
        Write-TreeProp $false (T "CheckBasic.Cert.ChainFile") $chainPath
        if (-not [string]::IsNullOrWhiteSpace($chainSum.CertBlocks)) {
          Write-TreeProp $false (T "CheckBasic.Cert.ChainBlocks") $chainSum.CertBlocks
        }
        Write-TreeProp $false (T "CheckBasic.Cert.ChainFormat") (Format-CertFormat $chainSum.Format)
      }

      if (-not [string]::IsNullOrWhiteSpace($san)) {
        $sanList = $san -split "; "
        if ($sanList.Count -eq 1) {
          Write-TreeProp $false (T "CheckBasic.Cert.SAN") $sanList[0]
        }
        else {
          Write-TreeProp $false (T "CheckBasic.Cert.SAN") ""
          for ($i = 0; $i -lt $sanList.Count; $i++) {
            $isLast = ($i -eq ($sanList.Count - 1))
            $mark = if ($isLast) { "└──" } else { "├──" }
            Write-Host ("│   {0} {1}" -f $mark, $sanList[$i]) -ForegroundColor Gray
          }
        }
      }
      
      if (-not [string]::IsNullOrWhiteSpace($sum.ExternalIntermediates)) {
        $cands = ($sum.ExternalIntermediates -split ";" | Select-Object -Unique -First 5) -join "; "
        Write-TreeProp $false (T "Label.ExtChainCand") $cands
      }
      
      $hasKeyStr = if ($sum.HasPrivateKey) { (T "Common.Yes") } else { (T "Common.No") }
      $hasKeyColor = if ($sum.HasPrivateKey) { [ConsoleColor]::Red } else { [ConsoleColor]::Green }
      Write-TreeProp $true (T "CheckBasic.Detail.Cert.HasPrivateKey") $hasKeyStr $hasKeyColor

      Show-OpenSslDetails $FilePath
      break
    }
    ".csr" {
      Write-TreeProp $false (T "CheckBasic.Pretty.File") ([IO.Path]::GetFileName($FilePath)) "Cyan"
      Write-TreeProp $false (T "CheckBasic.Pretty.Path") (Split-Path -Parent $FilePath) "DarkGray"
      Write-TreeProp $false (T "Label.FileType") (T "Label.Csr") "Cyan"
      Show-OpenSslDetails $FilePath
      break
    }
    ".key" {
      Write-TreeProp $false (T "CheckBasic.Pretty.File") ([IO.Path]::GetFileName($FilePath)) "Cyan"
      Write-TreeProp $false (T "CheckBasic.Pretty.Path") (Split-Path -Parent $FilePath) "DarkGray"
      Write-TreeProp $false (T "Label.FileType") (T "Label.Key") "Cyan"
      $isEnc = Test-KeyEncrypted $FilePath
      $existingPassFiles = @($PassFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique)
      $passFileText = if ($existingPassFiles.Count -gt 0) { ($existingPassFiles -join "; ") } else { (T "Common.None") }

      Write-TreeProp $false (T "Label.Encrypted") (Format-YesNo $isEnc)
      Write-TreeProp $false (T "Label.PassFile") $passFileText
      
      if (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE)) {
        $envPassExists = Test-Path -LiteralPath $env:PASS_FILE -PathType Leaf
        $envPassName = [IO.Path]::GetFileName($env:PASS_FILE)
        $msg = if ($envPassExists) { (T "Common.Exists") } else { (T "Common.NotExists") }
        Write-TreeProp $false "PASS_FILE" ("{0} ({1})" -f $envPassName, $msg)
      }
      else {
        Write-TreeProp $false "PASS_FILE" (T "Common.NotSet")
      }
      
      Write-TreeProp $false (T "Label.AutoMode") (Format-AutoModeStatus $isEnc $Passphrases)

      $ok = Get-KeyBit $FilePath $Passphrases
      $usable = @($Passphrases | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
      $decryptStatus = if ($ok) { (T "Common.Success") } elseif ($isEnc -and -not $usable) { (T "CheckBasic.Key.SkipNoPassLong") } else { (T "Common.Failed") }
      
      $col = if ($ok) { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
      Write-TreeProp $true (T "Label.DecryptCheck") $decryptStatus $col
      break
    }
    ".pfx" {
      Write-TreeProp $false (T "CheckBasic.Pretty.File") ([IO.Path]::GetFileName($FilePath)) "Cyan"
      Write-TreeProp $false (T "CheckBasic.Pretty.Path") (Split-Path -Parent $FilePath) "DarkGray"
      Write-TreeProp $false (T "Label.FileType") "PFX" "Cyan"
      
      $pfxOk = $false
      $pfxInfo = ""
      
      try {
        $out = Invoke-Pkcs12 @("-info", "-in", $FilePath, "-nokeys", "-clcerts", "-passin", "pass:")
        $pfxInfo = $out
        $pfxOk = $true
      }
      catch {}
      
      if (-not $pfxOk) {
        foreach ($p in $Passphrases) {
          if ([string]::IsNullOrWhiteSpace($p)) { continue }
          try {
            $pfxInfo = Invoke-TempPassFile $p { param($tmp)
              Invoke-Pkcs12 @("-info", "-in", $FilePath, "-nokeys", "-clcerts", "-passin", "file:$tmp")
            }
            $pfxOk = $true
            break
          }
          catch {}
        }
      }
      
      if ($pfxOk) {
        Write-TreeProp $true (T "Label.DecryptCheck") (T "Common.Success") "Green"
      }
      else {
        Write-TreeProp $true (T "Label.DecryptCheck") (T "Common.Failed") "Red"
      }
      
      Show-OpenSslDetails $FilePath $Passphrases
      break
    }
    default {
      Write-Warning (T "CheckBasic.Detail.UnsupportedExt" @($ext))
      return
    }
  }

  # 同一ディレクトリ内のファイル整合性を検証
  Show-FileMatching $FilePath $Passphrases

  Write-Host ""
}


function Show-Folder([string]$folderPath, [string]$label, [string]$oldRootForNew = "", [string[]]$TargetOrgs = @()) {
  if (-not (Test-Path -LiteralPath $folderPath -PathType Container)) {
    Write-Host (T "Common.FolderNotFound" @($label, $folderPath))
    Write-Host ""
    return
  }

  Write-Host (T "CheckBasic.Header" @($label))
  Write-Host (T "CheckBasic.Dir" @((Resolve-Path -LiteralPath $folderPath)))
  Write-Host ""

  # 機関（第一階層）
  $orgDirs = @(Get-ChildItem -LiteralPath $folderPath -Directory -ErrorAction SilentlyContinue)
  $rootFiles = @(Get-ChildItem -LiteralPath $folderPath -File -Include *.cer, *.crt, *.pem, *.csr, *.key -ErrorAction SilentlyContinue)
  if ($rootFiles.Count -gt 0) {
    $orgDirs = @([PSCustomObject]@{ FullName = $folderPath; Name = "(root)" }) + $orgDirs
  }
  if ($orgDirs.Count -eq 0) {
    Write-Host (T "Common.NoTargetFiles")
    Write-Host ""
    return
  }

  if ($TargetOrgs.Count -gt 0) {
    $orgDirs = @($orgDirs | Where-Object { $TargetOrgs -contains $_.Name })
    if ($orgDirs.Count -eq 0) {
      Write-Host (T "Common.NoTargetFiles")
      Write-Host ""
      return
    }
  }

  $hasOrgSubdirs = @($orgDirs | Where-Object { $_.Name -ne "(root)" }).Count -gt 0

  foreach ($org in $orgDirs) {
    $orgPath = $org.FullName
    $orgName = $org.Name

    $passFiles = @()
    $passFiles += (Find-PassFile $orgPath)
    $passFiles += (Find-PassFile $folderPath)
    $passFiles += (Find-PassFile $PSScriptRoot)
    if (-not [string]::IsNullOrWhiteSpace($oldRootForNew)) {
      $passFiles += (Find-PassFile $oldRootForNew)
      if ($orgName -ne "(root)") { $passFiles += (Find-PassFile (Join-Path $oldRootForNew $orgName)) }
    }
    $existingPassFiles = @($passFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique)
    $passphrases = Get-Passphrases $passFiles

    $files = @()
    if ($orgName -eq "(root)" -and $hasOrgSubdirs) {
      # (root) は直下のみ（サブフォルダ機関と重複させない）
      $files = @(Get-ChildItem -LiteralPath $orgPath -File -Include *.cer, *.crt, *.pem, *.csr, *.key -ErrorAction SilentlyContinue)
    }
    else {
      $files = @(Get-ChildItem -LiteralPath $orgPath -Recurse -File -Include *.cer, *.crt, *.pem, *.csr, *.key -ErrorAction SilentlyContinue)
    }
    if ($files.Count -eq 0) {
      Write-TreeLine 0 ("{0}\{1}\" -f $label, $orgName) {
        Write-Tag (T "CheckBasic.NotFound") "DarkYellow"
      }
      continue
    }

    if ($Detail) {
      Write-Host ("---- 機関: {0} ----" -f $orgName)
      if ($existingPassFiles.Count -gt 0) {
        Write-Host ("[PASS] パスワードファイル({0}): {1}" -f $FixedPassFileName, ($existingPassFiles -join "; "))
      }
      else {
        Write-Host ("[PASS] パスワードファイル({0}): (なし)" -f $FixedPassFileName)
      }
      if (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE)) {
        $envPassExists = Test-Path -LiteralPath $env:PASS_FILE -PathType Leaf
        $envPassName = [IO.Path]::GetFileName($env:PASS_FILE)
        $envPassExistText = if ($envPassExists) { (T "Common.Exists") } else { (T "Common.NotExists") }
        Write-Host ("[PASS] 環境変数 PASS_FILE: 設定あり（{0} / {1}）" -f $envPassName, $envPassExistText)
      }
      else {
        Write-Host "[PASS] 環境変数 PASS_FILE: 未設定"
      }
      Write-Host ""
      foreach ($f in $files) {
        Show-OneFile -FilePath $f.FullName -Passphrases $passphrases -PassFiles $passFiles
      }
      continue
    }

    $certRows = New-Object System.Collections.Generic.List[object]
    $csrRows = New-Object System.Collections.Generic.List[object]
    $keyRows = New-Object System.Collections.Generic.List[object]
    foreach ($f in ($files | Sort-Object FullName)) {
      $ext = [IO.Path]::GetExtension($f.FullName).ToLowerInvariant()
      # 機関フォルダからの相対パス（サブフォルダがある場合でも見やすくする）
      $name = $f.Name
      try {
        $full = [string]$f.FullName
        $base = [string]$orgPath
        if ($full.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
          $rel = $full.Substring($base.Length).TrimStart('\', '/')
          if (-not [string]::IsNullOrWhiteSpace($rel)) { $name = $rel }
        }
      }
      catch { }

      if ($ext -in @(".cer", ".crt", ".pem")) {
        $sum = Get-CertChainSummary $f.FullName
        $subject = Get-SubjectRfc2253FromCert $f.FullName
        $san = Get-SubjectAltNamesFromCert $f.FullName
        $chainPath = Find-ChainFileForCert $f.FullName "" $script:ChainSearchDirs
        $chainSum = Get-ChainFileSummary $chainPath
        $notAfter = Get-NotAfterFromCert $f.FullName
        $notAfterLocal = Format-CertDateForDisplay $notAfter
        $chainText = ""
        if ($sum.HasChain -is [bool]) { $chainText = Format-YesNo $sum.HasChain }
        $certRows.Add([PSCustomObject]@{
            File            = $name
            FullPath        = $f.FullName
            Dir             = Split-Path -Parent $f.FullName
            FileName        = $f.Name
            NotAfter        = $notAfter
            NotAfterLocal   = $notAfterLocal
            Format          = Format-CertFormat $sum.Format
            Blocks          = $sum.CertBlocks
            Chain           = $chainText
            ChainBool       = $sum.HasChain
            ExtIntermediate = $sum.ExternalIntermediates
            FinalUse        = Format-FinalUse $sum.FinalUse
            FinalUseCode    = $sum.FinalUse
            IssuerCN        = $sum.IssuerCN
            Subject         = $subject
            SAN             = $san
            ChainFile       = if ($chainSum.Found) { [IO.Path]::GetFileName($chainPath) } else { "" }
            ChainFileBlocks = if ($chainSum.Found) { $chainSum.CertBlocks } else { "" }
            ChainFileFormat = if ($chainSum.Found) { Format-CertFormat $chainSum.Format } else { "" }
          }) | Out-Null
        continue
      }

      if ($ext -eq ".csr") {
        $subj = ""
        $cn = ""
        $note = ""
        try {
          $out = Invoke-OpenSsl @("req", "-in", $f.FullName, "-noout", "-subject")
          $subj = (($out | Select-Object -First 1) -replace "^subject=", "").Trim()
          if ($subj -match "(?:^|[,/\\s])CN\\s*=\\s*([^,\\/]+)") { $cn = $matches[1].Trim() }
        }
        catch { $subj = "" }
        if (-not [string]::IsNullOrWhiteSpace($cn)) { $note = "CN=$cn" } else { $note = $subj }
        $csrRows.Add([PSCustomObject]@{
            File     = $name
            Dir      = Split-Path -Parent $f.FullName
            FileName = $f.Name
            Subject  = $note
          }) | Out-Null
        continue
      }

      if ($ext -eq ".key") {
        $isEnc = Test-KeyEncrypted $f.FullName
        $encText = Format-YesNo $isEnc
        $autoText = Format-AutoModeStatus $isEnc $passphrases
        $decText = Test-KeyReadable $f.FullName $passphrases
        $keyRows.Add([PSCustomObject]@{
            File         = $name
            Dir          = Split-Path -Parent $f.FullName
            FileName     = $f.Name
            Encrypted    = $encText
            AutoMode     = $autoText
            DecryptCheck = $decText
          }) | Out-Null
        continue
      }
    }



    # 既定：ツリー表示（フォルダ -> ファイル、タグは色付き）
    $orgHeader = if ($orgName -eq "(root)") { ("{0}\" -f $label) } else { ("{0}\{1}\" -f $label, $orgName) }
    Write-TreeLine 0 $orgHeader {
      if ($existingPassFiles.Count -gt 0) {
        Write-Tag (T "CheckBasic.PassFilePresent" @($FixedPassFileName)) "Green"
      }
      else {
        Write-Tag (T "CheckBasic.PassFileMissing" @($FixedPassFileName)) "DarkYellow"
      }
      if (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE)) {
        $envPassExists = Test-Path -LiteralPath $env:PASS_FILE -PathType Leaf
        if ($envPassExists) { Write-Tag (T "CheckBasic.PassEnvPresent") "Green" } else { Write-Tag (T "CheckBasic.PassEnvMissingFile") "DarkYellow" }
      }
    }

    # 証明書
    Write-TreeLine 2 (T "Label.Cert") { }
    if ($certRows.Count -eq 0) {
      Write-TreeLine 4 (T "CheckBasic.None") { Write-Tag (T "CheckBasic.NotFound") "DarkYellow" }
    }
    else {
      foreach ($r in ($certRows | Sort-Object File)) {
        $chainBool = $r.ChainBool
        $finalCode = [string]$r.FinalUseCode
        $exti = [string]$r.ExtIntermediate
        $notAfter = [string]$r.NotAfter
        $notAfterLocal = [string]$r.NotAfterLocal
        $issuerCN = [string]$r.IssuerCN
        $chainFileName = [string]$r.ChainFile
        $chainBlocks = [string]$r.ChainFileBlocks
        Write-TreeLine 4 $r.File {
          $expiryText = if (-not [string]::IsNullOrWhiteSpace($notAfterLocal)) { $notAfterLocal } else { $notAfter }
          if (-not [string]::IsNullOrWhiteSpace($expiryText)) { Write-Tag (T "CheckBasic.Cert.Expiry" @($expiryText)) "Cyan" }
          if ($chainBool -is [bool] -and $chainBool) { Write-Tag (T "CheckBasic.Cert.HasChain") "Green" }
          elseif ($chainBool -is [bool] -and -not $chainBool) { Write-Tag (T "CheckBasic.Cert.NotMerged") "Red" }
          else { Write-Tag (T "CheckBasic.Cert.Unk") "DarkYellow" }
          $finalText = Format-FinalUse $finalCode
          if ($finalCode -eq "FULLCHAIN_GUESS") { Write-Tag $finalText "Green" }
          elseif ($finalCode -eq "SINGLE_CERT") { Write-Tag $finalText "Red" }
          else { Write-Tag $finalText "DarkYellow" }
          if (-not [string]::IsNullOrWhiteSpace($exti)) {
            # 厳密一致の候補がある → 使える中間証明書
            $first = ($exti -split ";" | Select-Object -First 1)
            if (-not [string]::IsNullOrWhiteSpace($first)) { Write-Tag (T "CheckBasic.Cert.Candidate" @($first)) "Green" }
          }
          elseif ($finalCode -eq "SINGLE_CERT" -and -not [string]::IsNullOrWhiteSpace($issuerCN)) {
            # 候補がないが中間証明書が必要な場合、発行機関を表示（この機関の中間証明書が必要）
            Write-Tag (T "CheckBasic.Cert.Issuer" @($issuerCN)) "Magenta"
          }
          if (-not [string]::IsNullOrWhiteSpace($chainFileName)) {
            if (-not [string]::IsNullOrWhiteSpace($chainBlocks)) {
              Write-Tag (T "CheckBasic.Cert.ChainFileBlocks" @($chainBlocks)) "Green"
            }
            else {
              Write-Tag (T "CheckBasic.Cert.ChainFileFound") "Green"
            }
          }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$r.Subject)) {
          Write-TreeLine 6 ("{0} {1}" -f (T "CheckBasic.Detail.Subject"), [string]$r.Subject) { }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$r.SAN)) {
          Write-TreeLine 6 ("{0} {1}" -f (T "CheckBasic.Detail.SAN"), [string]$r.SAN) { }
        }
      }
    }

    # CSR（証明書署名要求）
    Write-TreeLine 2 (T "Label.Csr") { }
    if ($csrRows.Count -eq 0) {
      Write-TreeLine 4 (T "CheckBasic.None") { Write-Tag (T "CheckBasic.NotFound") "DarkYellow" }
    }
    else {
      foreach ($r in ($csrRows | Sort-Object File)) {
        Write-TreeLine 4 $r.File {
          if (-not [string]::IsNullOrWhiteSpace([string]$r.Subject)) { Write-Tag ([string]$r.Subject) "Gray" }
        }
      }
    }

    # 秘密鍵
    Write-TreeLine 2 (T "Label.Key") { }
    if ($keyRows.Count -eq 0) {
      Write-TreeLine 4 (T "CheckBasic.None") { Write-Tag (T "CheckBasic.NotFound") "DarkYellow" }
    }
    else {
      foreach ($r in ($keyRows | Sort-Object File)) {
        $enc = [string]$r.Encrypted
        $auto = [string]$r.AutoMode
        $dec = [string]$r.DecryptCheck
        Write-TreeLine 4 $r.File {
          if ($enc -eq (T "Common.Yes")) { Write-Tag (T "CheckBasic.Key.Encrypted") "DarkYellow" } else { Write-Tag (T "CheckBasic.Key.Plain") "Green" }
          $autoOk = ($auto -eq (T "CheckBasic.Key.AutoOkNoPass")) -or ($auto -eq (T "CheckBasic.Key.AutoOkNeedPass"))
          if ($autoOk) { Write-Tag $auto "Green" } else { Write-Tag $auto "Red" }
          if ($dec -eq (T "Common.Success")) { Write-Tag (T "CheckBasic.Key.DecOk") "Green" }
          elseif ($dec -match (T "Common.Skip")) { Write-Tag (T "CheckBasic.Key.DecSkip" @($dec)) "DarkYellow" }
          else { Write-Tag (T "CheckBasic.Key.DecFail") "Red" }
        }
      }
    }

    Write-Host ""
  }
}

if (-not [string]::IsNullOrWhiteSpace($Path)) {
  Show-OneFile -FilePath $Path -Passphrases (Get-Passphrases @(
      (Find-PassFile (Split-Path -Parent $Path)),
      (Find-PassFile $toolOldDir),
      (Find-PassFile $toolNewDir),
      (Find-PassFile $PSScriptRoot)
    )) -PassFiles @(
    (Find-PassFile (Split-Path -Parent $Path)),
    (Find-PassFile $toolOldDir),
    (Find-PassFile $toolNewDir),
    (Find-PassFile $PSScriptRoot)
  )
  exit 0
}

# パラメータ未指定：old/new をそれぞれチェック
$oldDir = $toolOldDir
$newDir = $toolNewDir

if (-not $Detail) {
  Show-InteractiveMenu $oldDir $newDir
  exit 0
}

Show-Folder $oldDir (T "Label.Old") ""
Show-Folder $newDir (T "Label.New") $oldDir
Show-Folder $toolMergedDir (T "Label.Merged") ""
Show-Folder $toolSelfSignedDir (T "Label.SelfSigned") ""




