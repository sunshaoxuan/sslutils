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

  # 旧来の表形式で表示（既定はツリー表示）
  [Parameter(Mandatory = $false)]
  [switch]$Table,

  # 罫線つきの表形式（証明書のみ）
  [Parameter(Mandatory = $false)]
  [switch]$PrettyTable,

  # 出力言語（既定: ja）
  [Parameter(Mandatory = $false)]
  [ValidateSet("ja", "zh", "en")]
  [string]$Lang = "ja"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# 出力の文字化け対策（環境差異があるため、失敗しても続行）
try {
  [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
  $OutputEncoding = [Console]::OutputEncoding
} catch { }

$i18nModule = Join-Path $PSScriptRoot "lib\\i18n.ps1"
if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw (T "Common.I18nModuleNotFound" @($i18nModule)) }
. $i18nModule
$__i18n = Initialize-I18n -Lang $Lang -BaseDir $PSScriptRoot
function T([string]$Key, [object[]]$FormatArgs = @()) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }

$FixedPassFileName = "passphrase.txt"

# ===== 設定（静的パラメータ表）=====
# 中間証明書が「ルート直下に別ファイルで置かれている」運用を想定し、候補ファイル名をここで管理します。
# 例: NII Open Domain CA 系が nii*.cer のような名前で置かれている場合。
# 将来ファイル名が変わったら、この配列を編集するだけでチェック結果を調整できます。
$IntermediateCertFileNamePatterns = @(
  "nii*.cer",
  "nii*.crt",
  "nii*.pem",
  "gs*.cer",
  "gs*.crt",
  "gs*.pem",
  "globalsign*.cer",
  "globalsign*.crt",
  "globalsign*.pem"
)

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

function Run-OpenSsl([string[]]$OpenSslArgs) {
  $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    throw (T "Common.OpenSslCmdFailed" @(($OpenSslArgs -join " "), (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return $out
}

Assert-ExistsFile $OpenSsl "OpenSSL"

if (-not [string]::IsNullOrWhiteSpace($ChainFile) -and [string]::IsNullOrWhiteSpace($Path)) {
  Write-Host (T "CheckBasic.ChainFileIgnored") -ForegroundColor Yellow
  $ChainFile = ""
}

$script:ChainSearchDirs = @(
  $PSScriptRoot,
  (Join-Path $PSScriptRoot "old"),
  (Join-Path $PSScriptRoot "new"),
  (Join-Path $PSScriptRoot "merged\\old"),
  (Join-Path $PSScriptRoot "merged\\new")
) | Select-Object -Unique

$script:ChainDirMappings = @(
  @{ Source = (Join-Path $PSScriptRoot "old"); Target = (Join-Path $PSScriptRoot "merged\\old") },
  @{ Source = (Join-Path $PSScriptRoot "new"); Target = (Join-Path $PSScriptRoot "merged\\new") }
)

function Get-CertContainerInfo([string]$certPath) {
  # 形式判定（PEM/DER）と、PEM の場合は証明書ブロック数を数える
  try {
    $bytes = [System.IO.File]::ReadAllBytes($certPath)
  } catch {
    return [PSCustomObject]@{
      Format = "UNKNOWN"
      CertBlocks = 0
      HasPrivateKey = $false
      IsPkcs7 = $false
    }
  }

  $isPem = $false
  if ($bytes.Length -ge 10) {
    # "-----BEGIN" = 2D 2D 2D 2D 2D 42 45 47 49 4E
    $isPem = ($bytes[0] -eq 0x2D -and $bytes[1] -eq 0x2D -and $bytes[2] -eq 0x2D -and $bytes[3] -eq 0x2D -and $bytes[4] -eq 0x2D)
  }

  if (-not $isPem) {
    return [PSCustomObject]@{
      Format = "DER"
      CertBlocks = 0
      HasPrivateKey = $false
      IsPkcs7 = $false
    }
  }

  $text = [System.Text.Encoding]::ASCII.GetString($bytes)
  $blocks = [regex]::Matches($text, "-----BEGIN CERTIFICATE-----").Count
  $hasKey = ($text -match "-----BEGIN (ENCRYPTED )?(RSA )?PRIVATE KEY-----")
  $isPkcs7 = ($text -match "-----BEGIN PKCS7-----")

  $fmt = "PEM"
  if ($isPkcs7) { $fmt = "PKCS7" }

  return [PSCustomObject]@{
    Format = $fmt
    CertBlocks = $blocks
    HasPrivateKey = [bool]$hasKey
    IsPkcs7 = [bool]$isPkcs7
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
        } else {
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
    Found = $true
    Format = $info.Format
    CertBlocks = [string]$info.CertBlocks
  }
}

function Find-IntermediateCertFiles() {
  $found = New-Object System.Collections.Generic.List[string]
  foreach ($pat in @($IntermediateCertFileNamePatterns)) {
    if ([string]::IsNullOrWhiteSpace($pat)) { continue }
    $items = @(Get-ChildItem -LiteralPath $PSScriptRoot -File -Filter $pat -ErrorAction SilentlyContinue)
    foreach ($i in $items) { $found.Add($i.FullName) | Out-Null }
  }
  return @($found | Select-Object -Unique)
}

function Get-IssuerRfc2253FromCert([string]$certPath) {
  try {
    $out = Run-OpenSsl @("x509","-in",$certPath,"-noout","-issuer","-nameopt","RFC2253")
    $line = ($out | Select-Object -First 1)
    return ([string]$line).Trim().Replace("issuer=","")
  } catch { return "" }
}

function Get-SubjectRfc2253FromCert([string]$certPath) {
  try {
    $out = Run-OpenSsl @("x509","-in",$certPath,"-noout","-subject","-nameopt","RFC2253")
    $line = ($out | Select-Object -First 1)
    return ([string]$line).Trim().Replace("subject=","")
  } catch { return "" }
}

function Get-CertChainSummary([string]$certPath) {
  $info = Get-CertContainerInfo $certPath
  $format = $info.Format

  if ($info.IsPkcs7) {
    return [PSCustomObject]@{
      Format = $format
      CertBlocks = ""
      HasChain = ""
      FinalUse = "UNKNOWN_PKCS7"
      ExternalIntermediates = ""
      HasPrivateKey = $info.HasPrivateKey
      Issuer = ""
      IssuerCN = ""
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
      Format = $format
      CertBlocks = [string]$info.CertBlocks
      HasChain = $hasChain
      FinalUse = if ($hasChain) { "FULLCHAIN_GUESS" } else { "SINGLE_CERT" }
      ExternalIntermediates = $extText
      HasPrivateKey = $info.HasPrivateKey
      Issuer = $issuer
      IssuerCN = $issuerCN
    }
  }

  # DER の場合：ブロック数を数えられないため不明扱い
  return [PSCustomObject]@{
    Format = $format
    CertBlocks = ""
    HasChain = ""
    FinalUse = "UNKNOWN_DER"
    ExternalIntermediates = ""
    HasPrivateKey = $false
    Issuer = ""
    IssuerCN = ""
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
    $base = (Resolve-Path -LiteralPath $baseDir).Path.TrimEnd('\','/')
    $full = (Resolve-Path -LiteralPath $fullPath).Path
    if ($full.Length -lt $base.Length) { return "" }
    if ($full.Substring(0, $base.Length).ToLowerInvariant() -ne $base.ToLowerInvariant()) { return "" }
    return $full.Substring($base.Length).TrimStart('\','/')
  } catch {
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

function Normalize-Cell([object]$v) {
  if ($null -eq $v) { return "" }
  return ([string]$v)
}

function Write-PrettyTable([string]$title, [object[]]$rows, [string[]]$headers, [string[]]$fields) {
  Write-Host ("---- {0} ----" -f $title)
  if ($rows.Count -eq 0) {
    Write-Host (T "Common.NoCertFiles")
    Write-Host ""
    return
  }

  $widths = @()
  for ($i = 0; $i -lt $headers.Count; $i++) {
    $w = ($headers[$i]).Length
    foreach ($r in $rows) {
      $val = Normalize-Cell ($r | Select-Object -ExpandProperty $fields[$i] -ErrorAction SilentlyContinue)
      if ($val.Length -gt $w) { $w = $val.Length }
    }
    $widths += $w
  }

  function Line([string]$sep, [string]$fill, [int[]]$ws) {
    $parts = @()
    foreach ($w in $ws) {
      $parts += ($fill * ($w + 2))
    }
    return ($sep + ($parts -join $sep) + $sep)
  }

  $top = Line "+" "-" $widths
  $mid = Line "+" "-" $widths
  $bot = Line "+" "-" $widths
  Write-Host $top

  $headerCells = @()
  for ($i = 0; $i -lt $headers.Count; $i++) {
    $headerCells += (" {0} " -f $headers[$i].PadRight($widths[$i]))
  }
  Write-Host ("|" + ($headerCells -join "|") + "|")
  Write-Host $mid

  foreach ($r in $rows) {
    $cells = @()
    for ($i = 0; $i -lt $fields.Count; $i++) {
      $val = Normalize-Cell ($r | Select-Object -ExpandProperty $fields[$i] -ErrorAction SilentlyContinue)
      $cells += (" {0} " -f $val.PadRight($widths[$i]))
    }
    Write-Host ("|" + ($cells -join "|") + "|")
  }
  Write-Host $bot
  Write-Host ""
}

function Get-NotAfterFromCert([string]$certPath) {
  try {
    $out = Run-OpenSsl @("x509","-in",$certPath,"-noout","-dates")
    $line = ($out | Where-Object { $_ -match "^notAfter=" } | Select-Object -First 1)
    if (-not $line) { return "" }
    return ([string]$line).Trim().Replace("notAfter=","")
  } catch {
    return ""
  }
}

function Write-Tag([string]$text, [string]$color) {
  if ([string]::IsNullOrWhiteSpace($text)) { return }
  try {
    Write-Host -NoNewline ("[{0}]" -f $text) -ForegroundColor $color
  } catch {
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

function Try-TestKeyReadable([string]$keyPath, [string[]]$passphrases) {
  # 対話プロンプトを絶対に出さないため、暗号化鍵は必ず -passin で読む
  $isEnc = Test-KeyEncrypted $keyPath
  if (-not $isEnc) {
    try {
      Run-OpenSsl @("rsa","-in",$keyPath,"-noout","-text") | Out-Null
      return (T "Common.Success")
    } catch {
      return (T "Common.Failed")
    }
  }

  $usable = @($passphrases | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
  if (-not $usable) { return (T "CheckBasic.Key.SkipNoPass") }

  foreach ($p in @($passphrases)) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    try {
      With-TempPassFile $p {
        param($tmpPass)
        Run-OpenSsl @("rsa","-in",$keyPath,"-noout","-text","-passin",("file:{0}" -f $tmpPass)) | Out-Null
      } | Out-Null
      return (T "Common.Success")
    } catch { }
  }
  return (T "Common.Failed")
}

function Get-Passphrase([string]$passFilePath) {
  if ([string]::IsNullOrWhiteSpace($passFilePath)) { return "" }
  if (-not (Test-Path -LiteralPath $passFilePath -PathType Leaf)) { return "" }
  $line = (Get-Content -LiteralPath $passFilePath -TotalCount 1 -ErrorAction SilentlyContinue)
  if ($null -eq $line) { return "" }
  $arr = @($line)
  if ($arr.Count -eq 0) { return "" }
  $first = $arr[0]
  if ($null -eq $first) { return "" }
  return ([string]$first).Trim()
}

function With-TempPassFile([string]$passphrase, [scriptblock]$action) {
  if ([string]::IsNullOrWhiteSpace($passphrase)) {
    return & $action ""
  }
  $tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), ("ssl_maker_pass_{0}.txt" -f ([Guid]::NewGuid().ToString("N"))))
  try {
    Set-Content -LiteralPath $tmp -Value $passphrase -NoNewline -Encoding ASCII
    return & $action $tmp
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $tmp
  }
}

function Find-PassFile([string]$dir) {
  # 誤検出防止のため、パスワードファイル名は固定（推奨: passphrase.txt）
  $fixed = Join-Path $dir $FixedPassFileName
  if (Test-Path -LiteralPath $fixed -PathType Leaf) { return $fixed }
  return ""
}

function Collect-Passphrases([string[]]$passFiles) {
  $phrases = New-Object System.Collections.Generic.List[string]
  foreach ($f in @($passFiles)) {
    $p = Get-Passphrase $f
    if (-not [string]::IsNullOrWhiteSpace($p)) { $phrases.Add($p) | Out-Null }
  }
  if (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE)) {
    $p = Get-Passphrase $env:PASS_FILE
    if (-not [string]::IsNullOrWhiteSpace($p)) { $phrases.Add($p) | Out-Null }
  }
  return ($phrases | Select-Object -Unique)
}

function Test-KeyEncrypted([string]$keyPath) {
  try {
    $head = @(Get-Content -LiteralPath $keyPath -TotalCount 40 -ErrorAction Stop)
  } catch {
    return $false
  }
  $text = ($head -join "`n")
  if ($text -match "BEGIN ENCRYPTED PRIVATE KEY") { return $true }
  if ($text -match "Proc-Type:\s*4,ENCRYPTED") { return $true }
  if ($text -match "\bENCRYPTED\b") { return $true }
  return $false
}

function Try-ShowKeyBit([string]$keyPath, [string[]]$passphrases) {
  # OpenSSL の対話プロンプトを絶対に出さないため、暗号化鍵は必ず -passin で読む
  $isEnc = Test-KeyEncrypted $keyPath
  if (-not $isEnc) {
    try {
      $out = Run-OpenSsl @("rsa","-in",$keyPath,"-noout","-text")
      $line = ($out | Select-Object -First 1)
      if ($line) { $line | Write-Output }
      return $true
    } catch { }
  }

  foreach ($p in @($passphrases)) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    try {
      With-TempPassFile $p {
        param($tmpPass)
        $out = Run-OpenSsl @("rsa","-in",$keyPath,"-noout","-text","-passin",("file:{0}" -f $tmpPass))
        $line = ($out | Select-Object -First 1)
        if ($line) { $line | Write-Output }
      }
      return $true
    } catch { }
  }

  if ($isEnc) {
    Write-Host (T "CheckBasic.Detail.Key.CannotReadNeedPass" @($FixedPassFileName))
  } else {
    Write-Host (T "CheckBasic.Detail.Key.CannotRead")
  }
  return $false
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

  $ext = [IO.Path]::GetExtension($FilePath).ToLowerInvariant()
  $chainPath = Find-ChainFileForCert $FilePath $ChainFile $script:ChainSearchDirs
  $chainSum = Get-ChainFileSummary $chainPath
  Write-Host (T "CheckBasic.Detail.File" @((Resolve-Path -LiteralPath $FilePath)))

  switch ($ext) {
    ".cer" {
      $sum = Get-CertChainSummary $FilePath
      if ($PrettyTable) {
        $chainMode = if ($sum.HasChain -is [bool] -and $sum.HasChain) { "fullchain" } elseif ($chainSum.Found) { "chainfile" } else { "none" }
        $row = [PSCustomObject]@{
          Path = Split-Path -Parent $FilePath
          File = [IO.Path]::GetFileName($FilePath)
          Expiry = Get-NotAfterFromCert $FilePath
          Chain = $chainMode
          ChainFile = if ($chainSum.Found) { [IO.Path]::GetFileName($chainPath) } else { "" }
          Blocks = $sum.CertBlocks
          ChainBlocks = if ($chainSum.Found) { $chainSum.CertBlocks } else { "" }
          Issuer = $sum.IssuerCN
          Format = Format-CertFormat $sum.Format
        }
        Write-PrettyTable (T "CheckBasic.Pretty.CertTitle") @($row) @(
          (T "CheckBasic.Pretty.Path"),
          (T "CheckBasic.Pretty.File"),
          (T "CheckBasic.Pretty.Expiry"),
          (T "CheckBasic.Pretty.Chain"),
          (T "CheckBasic.Pretty.ChainFile"),
          (T "CheckBasic.Pretty.Blocks"),
          (T "CheckBasic.Pretty.ChainBlocks"),
          (T "CheckBasic.Pretty.Issuer"),
          (T "CheckBasic.Pretty.Format")
        ) @("Path","File","Expiry","Chain","ChainFile","Blocks","ChainBlocks","Issuer","Format")
        break
      }
      Write-Host ("[{0}] 形式: {1}" -f (T "Label.Cert"), (Format-CertFormat $sum.Format))
      if (-not [string]::IsNullOrWhiteSpace($sum.CertBlocks)) { Write-Host ("[{0}] 証明書ブロック数: {1}" -f (T "Label.Cert"), $sum.CertBlocks) }
      if ($sum.HasChain -is [bool]) { Write-Host ("[{0}] 中間証明書同梱: {1}" -f (T "Label.Cert"), (Format-YesNo $sum.HasChain)) }
      Write-Host ("[{0}] 最終利用: {1}" -f (T "Label.Cert"), (Format-FinalUse $sum.FinalUse))
      if ($chainSum.Found) {
        Write-Host ("[{0}] {1}: {2}" -f (T "Label.Cert"), (T "CheckBasic.Cert.ChainFile"), $chainPath)
        if (-not [string]::IsNullOrWhiteSpace($chainSum.CertBlocks)) { Write-Host ("[{0}] {1}: {2}" -f (T "Label.Cert"), (T "CheckBasic.Cert.ChainBlocks"), $chainSum.CertBlocks) }
        Write-Host ("[{0}] {1}: {2}" -f (T "Label.Cert"), (T "CheckBasic.Cert.ChainFormat"), (Format-CertFormat $chainSum.Format))
      }
      if (-not [string]::IsNullOrWhiteSpace($sum.ExternalIntermediates)) {
        Write-Host ("[{0}] 外部中間証明書（候補）: {1}" -f (T "Label.Cert"), (($sum.ExternalIntermediates -split ";" | Select-Object -Unique -First 5) -join "; "))
      }
      if ($sum.HasPrivateKey) { Write-Host (T "CheckBasic.Detail.Cert.HasPrivateKey") }
      Run-OpenSsl @("x509","-in",$FilePath,"-noout","-subject","-issuer","-dates") | Write-Output
      break
    }
    ".crt" {
      $sum = Get-CertChainSummary $FilePath
      if ($PrettyTable) {
        $chainMode = if ($sum.HasChain -is [bool] -and $sum.HasChain) { "fullchain" } elseif ($chainSum.Found) { "chainfile" } else { "none" }
        $row = [PSCustomObject]@{
          Path = Split-Path -Parent $FilePath
          File = [IO.Path]::GetFileName($FilePath)
          Expiry = Get-NotAfterFromCert $FilePath
          Chain = $chainMode
          ChainFile = if ($chainSum.Found) { [IO.Path]::GetFileName($chainPath) } else { "" }
          Blocks = $sum.CertBlocks
          ChainBlocks = if ($chainSum.Found) { $chainSum.CertBlocks } else { "" }
          Issuer = $sum.IssuerCN
          Format = Format-CertFormat $sum.Format
        }
        Write-PrettyTable (T "CheckBasic.Pretty.CertTitle") @($row) @(
          (T "CheckBasic.Pretty.Path"),
          (T "CheckBasic.Pretty.File"),
          (T "CheckBasic.Pretty.Expiry"),
          (T "CheckBasic.Pretty.Chain"),
          (T "CheckBasic.Pretty.ChainFile"),
          (T "CheckBasic.Pretty.Blocks"),
          (T "CheckBasic.Pretty.ChainBlocks"),
          (T "CheckBasic.Pretty.Issuer"),
          (T "CheckBasic.Pretty.Format")
        ) @("Path","File","Expiry","Chain","ChainFile","Blocks","ChainBlocks","Issuer","Format")
        break
      }
      Write-Host ("[証明書] 形式: {0}" -f $sum.Format)
      if (-not [string]::IsNullOrWhiteSpace($sum.CertBlocks)) { Write-Host ("[証明書] 証明書ブロック数: {0}" -f $sum.CertBlocks) }
      if (-not [string]::IsNullOrWhiteSpace($sum.HasChain)) { Write-Host ("[証明書] 中間証明書同梱: {0}" -f $sum.HasChain) }
      Write-Host ("[証明書] 最終利用: {0}" -f $sum.FinalUse)
      if ($chainSum.Found) {
        Write-Host ("[証明書] {0}: {1}" -f (T "CheckBasic.Cert.ChainFile"), $chainPath)
        if (-not [string]::IsNullOrWhiteSpace($chainSum.CertBlocks)) { Write-Host ("[証明書] {0}: {1}" -f (T "CheckBasic.Cert.ChainBlocks"), $chainSum.CertBlocks) }
        Write-Host ("[証明書] {0}: {1}" -f (T "CheckBasic.Cert.ChainFormat"), (Format-CertFormat $chainSum.Format))
      }
      if (-not [string]::IsNullOrWhiteSpace($sum.ExternalIntermediates)) {
        Write-Host ("[証明書] 外部中間証明書（候補）: {0}" -f ($sum.ExternalIntermediates -split ";" | ForEach-Object { Join-Path $PSScriptRoot $_ } | Select-Object -Unique -First 5 -Skip 0) -join "; ")
        Write-Host (T "CheckBasic.Detail.Cert.NoChainHint")
      }
      if ($sum.HasPrivateKey) { Write-Host (T "CheckBasic.Detail.Cert.HasPrivateKey") }
      Run-OpenSsl @("x509","-in",$FilePath,"-noout","-subject","-issuer","-dates") | Write-Output
      break
    }
    ".pem" {
      $sum = Get-CertChainSummary $FilePath
      if ($PrettyTable) {
        $chainMode = if ($sum.HasChain -is [bool] -and $sum.HasChain) { "fullchain" } elseif ($chainSum.Found) { "chainfile" } else { "none" }
        $row = [PSCustomObject]@{
          Path = Split-Path -Parent $FilePath
          File = [IO.Path]::GetFileName($FilePath)
          Expiry = Get-NotAfterFromCert $FilePath
          Chain = $chainMode
          ChainFile = if ($chainSum.Found) { [IO.Path]::GetFileName($chainPath) } else { "" }
          Blocks = $sum.CertBlocks
          ChainBlocks = if ($chainSum.Found) { $chainSum.CertBlocks } else { "" }
          Issuer = $sum.IssuerCN
          Format = Format-CertFormat $sum.Format
        }
        Write-PrettyTable (T "CheckBasic.Pretty.CertTitle") @($row) @(
          (T "CheckBasic.Pretty.Path"),
          (T "CheckBasic.Pretty.File"),
          (T "CheckBasic.Pretty.Expiry"),
          (T "CheckBasic.Pretty.Chain"),
          (T "CheckBasic.Pretty.ChainFile"),
          (T "CheckBasic.Pretty.Blocks"),
          (T "CheckBasic.Pretty.ChainBlocks"),
          (T "CheckBasic.Pretty.Issuer"),
          (T "CheckBasic.Pretty.Format")
        ) @("Path","File","Expiry","Chain","ChainFile","Blocks","ChainBlocks","Issuer","Format")
        break
      }
      Write-Host ("[証明書] 形式: {0}" -f $sum.Format)
      if (-not [string]::IsNullOrWhiteSpace($sum.CertBlocks)) { Write-Host ("[証明書] 証明書ブロック数: {0}" -f $sum.CertBlocks) }
      if (-not [string]::IsNullOrWhiteSpace($sum.HasChain)) { Write-Host ("[証明書] 中間証明書同梱: {0}" -f $sum.HasChain) }
      Write-Host ("[証明書] 最終利用: {0}" -f $sum.FinalUse)
      if ($chainSum.Found) {
        Write-Host ("[証明書] {0}: {1}" -f (T "CheckBasic.Cert.ChainFile"), $chainPath)
        if (-not [string]::IsNullOrWhiteSpace($chainSum.CertBlocks)) { Write-Host ("[証明書] {0}: {1}" -f (T "CheckBasic.Cert.ChainBlocks"), $chainSum.CertBlocks) }
        Write-Host ("[証明書] {0}: {1}" -f (T "CheckBasic.Cert.ChainFormat"), (Format-CertFormat $chainSum.Format))
      }
      if (-not [string]::IsNullOrWhiteSpace($sum.ExternalIntermediates)) {
        Write-Host ("[証明書] 外部中間証明書（候補）: {0}" -f ($sum.ExternalIntermediates -split ";" | ForEach-Object { Join-Path $PSScriptRoot $_ } | Select-Object -Unique -First 5 -Skip 0) -join "; ")
        Write-Host (T "CheckBasic.Detail.Cert.NoChainHint")
      }
      if ($sum.HasPrivateKey) { Write-Host (T "CheckBasic.Detail.Cert.HasPrivateKey") }
      Run-OpenSsl @("x509","-in",$FilePath,"-noout","-subject","-issuer","-dates") | Write-Output
      break
    }
    ".csr" {
      if ($PrettyTable) {
        $subj = ""
        try {
          $out = Run-OpenSsl @("req","-in",$FilePath,"-noout","-subject")
          $subj = (($out | Select-Object -First 1) -replace "^subject=","").Trim()
        } catch { $subj = "" }
        $row = [PSCustomObject]@{
          Path = Split-Path -Parent $FilePath
          File = [IO.Path]::GetFileName($FilePath)
          Subject = $subj
        }
        Write-PrettyTable (T "CheckBasic.Pretty.CsrTitle") @($row) @(
          (T "CheckBasic.Pretty.Path"),
          (T "CheckBasic.Pretty.File"),
          (T "CheckBasic.Pretty.Subject")
        ) @("Path","File","Subject")
        break
      }
      Run-OpenSsl @("req","-in",$FilePath,"-noout","-subject") | Write-Output
      break
    }
    ".key" {
      $isEnc = Test-KeyEncrypted $FilePath
      $existingPassFiles = @($PassFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique)
      $passFileText = if ($existingPassFiles.Count -gt 0) { ($existingPassFiles -join "; ") } else { "(なし)" }

      Write-Host ("[KEY] 暗号化: {0}" -f (Format-YesNo $isEnc))
      Write-Host ("[KEY] パスワードファイル({0}): {1}" -f $FixedPassFileName, $passFileText)
      if (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE)) {
        $envPassExists = Test-Path -LiteralPath $env:PASS_FILE -PathType Leaf
        $envPassName = [IO.Path]::GetFileName($env:PASS_FILE)
        $envPassExistText = if ($envPassExists) { (T "Common.Exists") } else { (T "Common.NotExists") }
        Write-Host ("[KEY] 環境変数 PASS_FILE: 設定あり（{0} / {1}）" -f $envPassName, $envPassExistText)
      } else {
        Write-Host "[KEY] 環境変数 PASS_FILE: 未設定"
      }
      Write-Host ("[KEY] 無人運用: {0}" -f (Format-AutoModeStatus $isEnc $Passphrases))

      if ($PrettyTable) {
        $ok = Try-TestKeyReadable $FilePath $Passphrases
        $usable = @($Passphrases | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
        $decText = if ($ok -eq (T "Common.Success")) { (T "Common.Success") } elseif ($isEnc -and -not $usable) { (T "CheckBasic.Key.SkipNoPassLong") } else { (T "Common.Failed") }
        $row = [PSCustomObject]@{
          Path = Split-Path -Parent $FilePath
          File = [IO.Path]::GetFileName($FilePath)
          Encrypted = Format-YesNo $isEnc
          AutoMode = Format-AutoModeStatus $isEnc $Passphrases
          Decrypt = $decText
        }
        Write-PrettyTable (T "CheckBasic.Pretty.KeyTitle") @($row) @(
          (T "CheckBasic.Pretty.Path"),
          (T "CheckBasic.Pretty.File"),
          (T "CheckBasic.Pretty.Encrypted"),
          (T "CheckBasic.Pretty.AutoMode"),
          (T "CheckBasic.Pretty.Decrypt")
        ) @("Path","File","Encrypted","AutoMode","Decrypt")
        break
      }

      $ok = Try-ShowKeyBit $FilePath $Passphrases
      $usable = @($Passphrases | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
      $decryptStatus = if ($ok) { (T "Common.Success") } elseif ($isEnc -and -not $usable) { (T "CheckBasic.Key.SkipNoPassLong") } else { (T "Common.Failed") }
      Write-Host ("[KEY] 復号チェック: {0}" -f $decryptStatus)
      break
    }
    default {
      Write-Warning (T "CheckBasic.Detail.UnsupportedExt" @($ext))
      return
    }
  }
  Write-Host ""
}

function Show-Folder([string]$folderPath, [string]$label, [string]$oldRootForNew = "") {
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
  $rootFiles = @(Get-ChildItem -LiteralPath $folderPath -File -Include *.cer,*.crt,*.pem,*.csr,*.key -ErrorAction SilentlyContinue)
  if ($rootFiles.Count -gt 0) {
    $orgDirs = @([PSCustomObject]@{ FullName = $folderPath; Name="(root)" }) + $orgDirs
  }
  if ($orgDirs.Count -eq 0) {
    Write-Host (T "Common.NoTargetFiles")
    Write-Host ""
    return
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
    $passphrases = Collect-Passphrases $passFiles

    $files = @()
    if ($orgName -eq "(root)" -and $hasOrgSubdirs) {
      # (root) は直下のみ（サブフォルダ機関と重複させない）
      $files = @(Get-ChildItem -LiteralPath $orgPath -File -Include *.cer,*.crt,*.pem,*.csr,*.key -ErrorAction SilentlyContinue)
    } else {
      $files = @(Get-ChildItem -LiteralPath $orgPath -Recurse -File -Include *.cer,*.crt,*.pem,*.csr,*.key -ErrorAction SilentlyContinue)
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
      } else {
        Write-Host ("[PASS] パスワードファイル({0}): (なし)" -f $FixedPassFileName)
      }
      if (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE)) {
        $envPassExists = Test-Path -LiteralPath $env:PASS_FILE -PathType Leaf
        $envPassName = [IO.Path]::GetFileName($env:PASS_FILE)
        $envPassExistText = if ($envPassExists) { (T "Common.Exists") } else { (T "Common.NotExists") }
        Write-Host ("[PASS] 環境変数 PASS_FILE: 設定あり（{0} / {1}）" -f $envPassName, $envPassExistText)
      } else {
        Write-Host "[PASS] 環境変数 PASS_FILE: 未設定"
      }
      Write-Host ""
      foreach ($f in $files) {
        Show-OneFile -FilePath $f.FullName -Passphrases $passphrases -PassFiles $passFiles
      }
      continue
    }

    if ($PrettyTable) {
      $prettyRows = @()
      foreach ($r in ($certRows | Sort-Object File)) {
        $chainMode = if ($r.ChainBool -is [bool] -and $r.ChainBool) { "fullchain" } elseif (-not [string]::IsNullOrWhiteSpace($r.ChainFile)) { "chainfile" } else { "none" }
        $prettyRows += [PSCustomObject]@{
          Path = $r.Dir
          File = $r.FileName
          Expiry = $r.NotAfter
          Chain = $chainMode
          ChainFile = $r.ChainFile
          Blocks = $r.Blocks
          ChainBlocks = $r.ChainFileBlocks
          Issuer = $r.IssuerCN
          Format = $r.Format
        }
      }
      Write-PrettyTable (T "CheckBasic.Pretty.CertTitle") $prettyRows @(
        (T "CheckBasic.Pretty.Path"),
        (T "CheckBasic.Pretty.File"),
        (T "CheckBasic.Pretty.Expiry"),
        (T "CheckBasic.Pretty.Chain"),
        (T "CheckBasic.Pretty.ChainFile"),
        (T "CheckBasic.Pretty.Blocks"),
        (T "CheckBasic.Pretty.ChainBlocks"),
        (T "CheckBasic.Pretty.Issuer"),
        (T "CheckBasic.Pretty.Format")
      ) @("Path","File","Expiry","Chain","ChainFile","Blocks","ChainBlocks","Issuer","Format")

      $csrPretty = @()
      foreach ($r in ($csrRows | Sort-Object File)) {
        $csrPretty += [PSCustomObject]@{
          Path = $r.Dir
          File = $r.FileName
          Subject = $r.Subject
        }
      }
      Write-PrettyTable (T "CheckBasic.Pretty.CsrTitle") $csrPretty @(
        (T "CheckBasic.Pretty.Path"),
        (T "CheckBasic.Pretty.File"),
        (T "CheckBasic.Pretty.Subject")
      ) @("Path","File","Subject")

      $keyPretty = @()
      foreach ($r in ($keyRows | Sort-Object File)) {
        $keyPretty += [PSCustomObject]@{
          Path = $r.Dir
          File = $r.FileName
          Encrypted = $r.Encrypted
          AutoMode = $r.AutoMode
          Decrypt = $r.DecryptCheck
        }
      }
      Write-PrettyTable (T "CheckBasic.Pretty.KeyTitle") $keyPretty @(
        (T "CheckBasic.Pretty.Path"),
        (T "CheckBasic.Pretty.File"),
        (T "CheckBasic.Pretty.Encrypted"),
        (T "CheckBasic.Pretty.AutoMode"),
        (T "CheckBasic.Pretty.Decrypt")
      ) @("Path","File","Encrypted","AutoMode","Decrypt")
      continue
    }

    if ($Table) {
      # 旧来：要点だけを表で表示
      Write-Host ("---- 機関: {0} ----" -f $orgName)
      if ($existingPassFiles.Count -gt 0) {
        Write-Host ("[PASS] パスワードファイル({0}): {1}" -f $FixedPassFileName, ($existingPassFiles -join "; "))
      } else {
        Write-Host ("[PASS] パスワードファイル({0}): (なし)" -f $FixedPassFileName)
      }
      if (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE)) {
        $envPassExists = Test-Path -LiteralPath $env:PASS_FILE -PathType Leaf
        $envPassName = [IO.Path]::GetFileName($env:PASS_FILE)
        $envPassExistText = if ($envPassExists) { (T "Common.Exists") } else { (T "Common.NotExists") }
        Write-Host ("[PASS] 環境変数 PASS_FILE: 設定あり（{0} / {1}）" -f $envPassName, $envPassExistText)
      } else {
        Write-Host "[PASS] 環境変数 PASS_FILE: 未設定"
      }
      Write-Host ""
    }

    $certRows = New-Object System.Collections.Generic.List[object]
    $csrRows  = New-Object System.Collections.Generic.List[object]
    $keyRows  = New-Object System.Collections.Generic.List[object]
    foreach ($f in ($files | Sort-Object FullName)) {
      $ext = [IO.Path]::GetExtension($f.FullName).ToLowerInvariant()
      # 機関フォルダからの相対パス（サブフォルダがある場合でも見やすくする）
      $name = $f.Name
      try {
        $full = [string]$f.FullName
        $base = [string]$orgPath
        if ($full.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
          $rel = $full.Substring($base.Length).TrimStart('\','/')
          if (-not [string]::IsNullOrWhiteSpace($rel)) { $name = $rel }
        }
      } catch { }

      if ($ext -in @(".cer",".crt",".pem")) {
        $sum = Get-CertChainSummary $f.FullName
        $chainPath = Find-ChainFileForCert $f.FullName "" $script:ChainSearchDirs
        $chainSum = Get-ChainFileSummary $chainPath
        $notAfter = Get-NotAfterFromCert $f.FullName
        $chainText = ""
        if ($sum.HasChain -is [bool]) { $chainText = Format-YesNo $sum.HasChain }
        $certRows.Add([PSCustomObject]@{
          File = $name
          FullPath = $f.FullName
          Dir = Split-Path -Parent $f.FullName
          FileName = $f.Name
          NotAfter = $notAfter
          Format = Format-CertFormat $sum.Format
          Blocks = $sum.CertBlocks
          Chain = $chainText
          ChainBool = $sum.HasChain
          ExtIntermediate = $sum.ExternalIntermediates
          FinalUse = Format-FinalUse $sum.FinalUse
          FinalUseCode = $sum.FinalUse
          IssuerCN = $sum.IssuerCN
          ChainFile = if ($chainSum.Found) { [IO.Path]::GetFileName($chainPath) } else { "" }
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
          $out = Run-OpenSsl @("req","-in",$f.FullName,"-noout","-subject")
          $subj = (($out | Select-Object -First 1) -replace "^subject=","").Trim()
          if ($subj -match "(?:^|[,/\\s])CN\\s*=\\s*([^,\\/]+)") { $cn = $matches[1].Trim() }
        } catch { $subj = "" }
        if (-not [string]::IsNullOrWhiteSpace($cn)) { $note = "CN=$cn" } else { $note = $subj }
        $csrRows.Add([PSCustomObject]@{
          File = $name
          Dir = Split-Path -Parent $f.FullName
          FileName = $f.Name
          Subject = $note
        }) | Out-Null
        continue
      }

      if ($ext -eq ".key") {
        $isEnc = Test-KeyEncrypted $f.FullName
        $encText = Format-YesNo $isEnc
        $autoText = Format-AutoModeStatus $isEnc $passphrases
        $decText = Try-TestKeyReadable $f.FullName $passphrases
        $keyRows.Add([PSCustomObject]@{
          File = $name
          Dir = Split-Path -Parent $f.FullName
          FileName = $f.Name
          Encrypted = $encText
          AutoMode = $autoText
          DecryptCheck = $decText
        }) | Out-Null
        continue
      }
    }

    if ($Table) {
      # 表形式
      if ($certRows.Count -eq 0) {
        Write-Host (T "Common.NoCertFiles")
      }
      if ($certRows.Count -gt 0) {
        Write-Host "[証明書]"
        $certRows | Format-Table -AutoSize | Out-String | Write-Output
      }
      if ($csrRows.Count -gt 0) {
        Write-Host "[CSR]"
        $csrRows | Format-Table -AutoSize | Out-String | Write-Output
      }
      if ($keyRows.Count -gt 0) {
        Write-Host "[秘密鍵]"
        $keyRows | Format-Table -AutoSize | Out-String | Write-Output
      }
      Write-Host ""
      continue
    }

    # 既定：ツリー表示（フォルダ -> ファイル、タグは色付き）
    $orgHeader = if ($orgName -eq "(root)") { ("{0}\" -f $label) } else { ("{0}\{1}\" -f $label, $orgName) }
    Write-TreeLine 0 $orgHeader {
      if ($existingPassFiles.Count -gt 0) {
        Write-Tag (T "CheckBasic.PassFilePresent" @($FixedPassFileName)) "Green"
      } else {
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
    } else {
      foreach ($r in ($certRows | Sort-Object File)) {
        $chainBool = $r.ChainBool
        $finalCode = [string]$r.FinalUseCode
        $exti = [string]$r.ExtIntermediate
        $notAfter = [string]$r.NotAfter
        $issuerCN = [string]$r.IssuerCN
        $chainFileName = [string]$r.ChainFile
        $chainBlocks = [string]$r.ChainFileBlocks
        Write-TreeLine 4 $r.File {
          if (-not [string]::IsNullOrWhiteSpace($notAfter)) { Write-Tag (T "CheckBasic.Cert.Expiry" @($notAfter)) "Cyan" }
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
          } elseif ($finalCode -eq "SINGLE_CERT" -and -not [string]::IsNullOrWhiteSpace($issuerCN)) {
            # 候補がないが中間証明書が必要な場合、発行機関を表示（この機関の中間証明書が必要）
            Write-Tag (T "CheckBasic.Cert.Issuer" @($issuerCN)) "Magenta"
          }
          if (-not [string]::IsNullOrWhiteSpace($chainFileName)) {
            if (-not [string]::IsNullOrWhiteSpace($chainBlocks)) {
              Write-Tag (T "CheckBasic.Cert.ChainFileBlocks" @($chainBlocks)) "Green"
            } else {
              Write-Tag (T "CheckBasic.Cert.ChainFileFound") "Green"
            }
          }
        }
      }
    }

    # CSR
    Write-TreeLine 2 (T "Label.Csr") { }
    if ($csrRows.Count -eq 0) {
      Write-TreeLine 4 (T "CheckBasic.None") { Write-Tag (T "CheckBasic.NotFound") "DarkYellow" }
    } else {
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
    } else {
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
  Show-OneFile -FilePath $Path -Passphrases (Collect-Passphrases @(
    (Find-PassFile (Split-Path -Parent $Path)),
    (Find-PassFile (Join-Path $PSScriptRoot "old")),
    (Find-PassFile (Join-Path $PSScriptRoot "new")),
    (Find-PassFile $PSScriptRoot)
  )) -PassFiles @(
    (Find-PassFile (Split-Path -Parent $Path)),
    (Find-PassFile (Join-Path $PSScriptRoot "old")),
    (Find-PassFile (Join-Path $PSScriptRoot "new")),
    (Find-PassFile $PSScriptRoot)
  )
  exit 0
}

# パラメータ未指定：old/new をそれぞれチェック
$oldDir = Join-Path $PSScriptRoot "old"
$newDir = Join-Path $PSScriptRoot "new"

Show-Folder $oldDir (T "Label.Old") ""
Show-Folder $newDir (T "Label.New") $oldDir


