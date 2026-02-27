<#
.SYNOPSIS
汎用的な CSR（証明書署名要求）と秘密鍵を生成するスクリプト

.DESCRIPTION
このスクリプトは、指定した CN（Common Name）と Subject 情報から、
CSR と秘密鍵のペアを生成します。

主な機能:
- RSA 鍵の生成（鍵長指定可能、既定: 2048bit）
- CSR の生成（Subject と SAN 対応）
- 秘密鍵の暗号化オプション（AES-256）
- 既存ファイルの自動バックアップ（-Overwrite 時）

.PARAMETER CN
必須：対象 FQDN（Common Name）

.PARAMETER Subject
明示的な Subject（推奨）
例: "/C=JP/ST=Hyogo/L=Kato-city/O=Org Name/CN=example.domain.tld"

.PARAMETER C
国コード（Subject 未指定時のみ使用）

.PARAMETER ST
都道府県（Subject 未指定時のみ使用）

.PARAMETER L
市区町村（Subject 未指定時のみ使用）

.PARAMETER O
組織名（Subject 未指定時のみ使用）

.PARAMETER WithSAN
SAN（Subject Alternative Name）を CSR に含める（既定: true / DNS:CN）


.PARAMETER PassFile
パスフレーズファイル（指定すると秘密鍵を AES-256 で暗号化）

.PARAMETER OutDir
出ディレクトリ（既定: .\new）

.PARAMETER Overwrite
既存の <CN>.key / <CN>.csr が存在する場合に、バックアップして再生成

.PARAMETER RsaBits
RSA 鍵長（既定: 2048）

.PARAMETER OpenSsl
OpenSSL 実行ファイルのパス

.PARAMETER Lang
出力言語（既定: ja）

.EXAMPLE
.\New-CertificateSigningRequest.ps1 -CN example.com -Subject "/C=JP/ST=Tokyo/L=Tokyo/O=Example Corp/CN=example.com"
Subject を明示指定して CSR 生成

.EXAMPLE
.\New-CertificateSigningRequest.ps1 -CN example.com -C JP -ST Tokyo -L Tokyo -O "Example Corp"
個別パラメータで CSR 生成

.EXAMPLE
.\New-CertificateSigningRequest.ps1 -CN example.com -PassFile .\passphrase.txt -Overwrite
暗号化鍵で CSR 生成（既存ファイルはバックアップ）

.NOTES
- Subject が未指定の場合は、-C/-ST/-L/-O を全て指定する必要があります
- OpenSSL 3.x 対応：暗号化鍵生成時は genpkey + req を使用します
- 既存ファイルの上書きは、-Overwrite を指定しない限り行いません
#>

param(
  # 必須：対象FQDN（CN）
  # ESC キャンセル機能に対応するため Optional に変更し、未指定時に Read-HostWithEsc で入力を受け付ける
  [Parameter(Mandatory = $false, Position = 0)]
  [string]$CN = "",

  # 任意：明示的な Subject（推奨）
  # 例: "/C=JP/ST=Hyogo/L=Kato-city/O=Org Name/CN=example.domain.tld"
  [Parameter(Mandatory = $false, Position = 1)]
  [string]$Subject = "",

  # Subject を渡さない場合のみ使用（= 業務デフォルトではなく、実行者が明示的に指定する値）
  [Parameter(Mandatory = $false)]
  [string]$C = "",
  [Parameter(Mandatory = $false)]
  [string]$ST = "",
  [Parameter(Mandatory = $false)]
  [string]$L = "",
  [Parameter(Mandatory = $false)]
  [string]$O = "",

  # SAN を CSR に書く（デフォルト：true / DNS:CN）
  [Parameter(Mandatory = $false)]
  [bool]$WithSAN = $true,

  # 任意：指定すると秘密鍵をAES-256で暗号化
  [Parameter(Mandatory = $false)]
  [string]$PassFile = "",

  # 出力ディレクトリ（デフォルト：カレント）
  [Parameter(Mandatory = $false)]
  [string]$OutDir = "",

  # 既存の <CN>.key / <CN>.csr が存在する場合に、バックアップして再生成する
  [Parameter(Mandatory = $false)]
  [switch]$Overwrite,

  [Parameter(Mandatory = $false)]
  [int]$RsaBits = 2048,

  [Parameter(Mandatory = $false)]
  [string]$OpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe",

  # 出力言語（既定: ja）
  [Parameter(Mandatory = $false)]
  [string]$Lang = ""
)


$ToolkitRoot = Split-Path -Parent $PSScriptRoot

$pathsModule = Join-Path $PSScriptRoot "lib\paths.ps1"
if (Test-Path -LiteralPath $pathsModule -PathType Leaf) { . $pathsModule }
$ToolkitPaths = if (Get-Command Get-ToolkitPaths -ErrorAction SilentlyContinue) { Get-ToolkitPaths -BaseDir $ToolkitRoot } else { $null }

$i18nModule = Join-Path $PSScriptRoot "lib\\i18n.ps1"
if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw (T "Common.I18nModuleNotFound" @($i18nModule)) }
. $i18nModule
$__i18n = Initialize-I18n -Lang $Lang -BaseDir $ToolkitRoot
function T([string]$Key, [object[]]$FormatArgs = @()) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }

# メニューモジュールを読み込む
$menuModule = Join-Path $PSScriptRoot "lib\\menu.ps1"
if (Test-Path -LiteralPath $menuModule -PathType Leaf) {
  . $menuModule
}

# CN が空の場合（メニューから起動された場合など）、ECSキャンセルのカスタムプロンプト表示
# CN が空の場合（メニューから起動された場合など）、ECSキャンセルのカスタムプロンプト表示
if ([string]::IsNullOrWhiteSpace($CN)) {
  # DEBUG
  Write-Host "DEBUG: CN is empty, entering input block" -ForegroundColor Magenta
  Write-Host "DEBUG: Checking for Read-HostWithEsc..." -ForegroundColor Magenta

  # メニューモジュールの Read-HostWithEsc を利用
  if (Get-Command Read-HostWithEsc -ErrorAction SilentlyContinue) {
    Write-Host "DEBUG: Read-HostWithEsc found." -ForegroundColor Magenta
    Write-Host (T "MakeCsr.InputCnPrompt")
    Write-Host (T "MakeCsr.InputCnHint") -ForegroundColor Gray
    
    # Force Flush again just in case
    try { $host.UI.RawUI.FlushInputBuffer() } catch { }
    
    $CN = Read-HostWithEsc "CN"
    
    Write-Host "DEBUG: Read-HostWithEsc returned: '$CN' ($($CN.GetType().Name))" -ForegroundColor Magenta
        
    # ESC 押下時は $null が返る -> 99 (キャンセル) で終了
    if ($null -eq $CN) { 
      Write-Host "DEBUG: CN was null (ESC detected). Exiting 99." -ForegroundColor Red
      if ($env:DEBUG_MODE -eq 'true') { Read-Host "Press Enter to exit..." }
      exit 99 
    }
    $CN = $CN.Trim()
  }
  else {
    Write-Host "DEBUG: Read-HostWithEsc NOT found. Using fallback." -ForegroundColor Magenta
    # フォールバック (通常入力)
    $CN = Read-Host "CN"
    Write-Host "DEBUG: Read-Host returned: '$CN'" -ForegroundColor Magenta
  }
}

if ([string]::IsNullOrWhiteSpace($CN)) {
  Write-Host "DEBUG: CN is still empty. Exiting 99." -ForegroundColor Red
  # Pause to see output
  Write-Host "Press Enter to exit..."
  try { $host.UI.RawUI.FlushInputBuffer(); $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Read-Host }
  
  exit 99
}

if ([string]::IsNullOrWhiteSpace($OutDir)) {
  if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.New)) { $OutDir = $ToolkitPaths.New }
  else { $OutDir = Join-Path $ToolkitRoot "new" }
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

function Backup-IfExists([string]$path) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
  $dir = Split-Path -Parent $path
  $base = [IO.Path]::GetFileNameWithoutExtension($path)
  $ext = [IO.Path]::GetExtension($path)  # .key / .csr
  $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
  $bak = Join-Path $dir ("{0}.bak_{1}{2}" -f $base, $ts, $ext)
  Rename-Item -Force -ErrorAction Stop -LiteralPath $path -NewName ([IO.Path]::GetFileName($bak))
}

function Invoke-OpenSsl([string[]]$OpenSslArgs) {
  $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    throw (T "Common.OpenSslCmdFailed" @(($OpenSslArgs -join " "), (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return $out
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

function Invoke-TempPassFile([string]$passphrase, [scriptblock]$action) {
  if ([string]::IsNullOrWhiteSpace($passphrase)) {
    return & $action ""
  }
  $tmpRoot = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace([string]$ToolkitPaths.Temp)) { [string]$ToolkitPaths.Temp } else { Join-Path $ToolkitRoot "temp" }
  if (-not (Test-Path -LiteralPath $tmpRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null
  }
  $tmp = Join-Path $tmpRoot ("ssl_maker_pass_{0}.tmp" -f ([Guid]::NewGuid().ToString("N")))
  try {
    Set-Content -LiteralPath $tmp -Value $passphrase -NoNewline -Encoding ASCII
    return & $action $tmp
  }
  finally {
    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $tmp
  }
}

function Format-SanItem([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { return "" }
  $t = $s.Trim()
  if ($t -match "^(DNS|IP|IP Address|URI|EMAIL):") {
    $prefix = $matches[1]
    $value = $t.Substring($prefix.Length + 1).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { return "" }
    if ($prefix -eq "IP Address") { $prefix = "IP" }
    return ("{0}:{1}" -f $prefix, $value)
  }
  return ("DNS:{0}" -f $t)
}

function Build-SanOpt([string[]]$sans) {
  if ($null -eq $sans -or $sans.Count -eq 0) { return @() }
  $items = New-Object System.Collections.Generic.List[string]
  foreach ($s in $sans) {
    $n = Format-SanItem $s
    if ([string]::IsNullOrWhiteSpace($n)) { continue }
    $items.Add($n) | Out-Null
  }
  $uniq = @($items | Select-Object -Unique)
  if ($uniq.Count -eq 0) { return @() }
  $value = "subjectAltName=" + ($uniq -join ",")
  return @("-addext", $value)
}

function ConvertFrom-SanInput([string]$raw) {
  if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
  return @($raw -split "[,;\s]+" | Where-Object { $_ -ne "" })
}

function Read-SanSelection([string]$cn) {
  # メニューモジュールが利用可能かチェック
  $useMenu = $false
  try {
    if (Get-Command Show-MenuSelect -ErrorAction SilentlyContinue) {
      $null = $host.UI.RawUI
      $useMenu = $true
    }
  }
  catch { }

  if ($useMenu) {
    # 反転表示メニューを使用
    $items = @(
      (T "MakeCsr.SanMenuOptionCn"),
      (T "MakeCsr.SanMenuOptionNone"),
      (T "MakeCsr.SanMenuOptionDns"),
      (T "MakeCsr.SanMenuOptionMixed"),
      ("[ {0} ]" -f (T "Common.MenuCancel"))
    )
    $choice = Show-MenuSelect -title (T "MakeCsr.SanMenuTitle") -items $items
    if ($null -eq $choice -or $choice -eq $items.Count) { 
      # キャンセル または ESC = デフォルト (CN のみ)
      return @($cn)
    }
    
    switch ($choice) {
      1 { return @($cn) }  # CN のみ (SAN なし)
      2 { return @() }  # SAN なし
      3 {
        $raw = (Read-Host (T "MakeCsr.SanInputDns")).Trim()
        $list = ConvertFrom-SanInput $raw
        return @($cn) + $list
      }
      4 {
        $raw = (Read-Host (T "MakeCsr.SanInputMixed")).Trim()
        $list = ConvertFrom-SanInput $raw
        return @($cn) + $list
      }
      default { return @($cn) }
    }
  }
  else {
    # フォールバック: 従来の数字入力方式
    Write-Host ""
    Write-Host (T "MakeCsr.SanMenuTitle")
    Write-Host (T "MakeCsr.SanMenuOptionCn")
    Write-Host (T "MakeCsr.SanMenuOptionNone")
    Write-Host (T "MakeCsr.SanMenuOptionDns")
    Write-Host (T "MakeCsr.SanMenuOptionMixed")
    $choice = ""
    try {
      $choice = (Read-Host (T "MakeCsr.SanMenuPrompt")).Trim()
    }
    catch {
      return @($cn)
    }
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }

    switch ($choice) {
      "2" { return @() }
      "3" {
        $raw = (Read-Host (T "MakeCsr.SanInputDns")).Trim()
        $list = ConvertFrom-SanInput $raw
        return @($cn) + $list
      }
      "4" {
        $raw = (Read-Host (T "MakeCsr.SanInputMixed")).Trim()
        $list = ConvertFrom-SanInput $raw
        return @($cn) + $list
      }
      default { return @($cn) }
    }
  }
}

Assert-ExistsFile $OpenSsl "OpenSSL"
New-DirectoryIfMissing $OutDir

# (CN check moved to top)

$sanItems = @()
if ($WithSAN) {
  $sanItems = Read-SanSelection $CN
}
$sanOpt = Build-SanOpt $sanItems

$subj = $Subject
if ([string]::IsNullOrWhiteSpace($subj)) {
  # Load defaults from config if available
  $configPath = Join-Path $PSScriptRoot "config.json"
  if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    try {
      $cfg = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
      if ($cfg.DefaultSubject) {
        if ([string]::IsNullOrWhiteSpace($C) -and $cfg.DefaultSubject.C) { $C = $cfg.DefaultSubject.C }
        if ([string]::IsNullOrWhiteSpace($ST) -and $cfg.DefaultSubject.ST) { $ST = $cfg.DefaultSubject.ST }
        if ([string]::IsNullOrWhiteSpace($L) -and $cfg.DefaultSubject.L) { $L = $cfg.DefaultSubject.L }
        if ([string]::IsNullOrWhiteSpace($O) -and $cfg.DefaultSubject.O) { $O = $cfg.DefaultSubject.O }
      }
    }
    catch { 
      Write-Host "Warning: Failed to load config.json: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }

  if ([string]::IsNullOrWhiteSpace($C) -or [string]::IsNullOrWhiteSpace($ST) -or [string]::IsNullOrWhiteSpace($L) -or [string]::IsNullOrWhiteSpace($O)) {
    throw (T "MakeCsr.SubjectMissing")
  }
  $subj = "/C=$C/ST=$ST/L=$L/O=$O/CN=$CN"
}

$keyPath = Join-Path $OutDir ($CN + ".key")
$csrPath = Join-Path $OutDir ($CN + ".csr")

if ((Test-Path -LiteralPath $keyPath -PathType Leaf) -or (Test-Path -LiteralPath $csrPath -PathType Leaf)) {
  $needsOverwrite = $true
  if (-not $Overwrite) {
    # 対話的に選択
    $conflictItems = @(
      (T "Renew.ConflictOverwrite"),
      (T "Renew.ConflictCancel")
    )
    $conflictTitle = (T "Renew.OutExistsPrompt" @((Resolve-Path -LiteralPath $OutDir)))
    $conflictSel = Show-MenuSelect -title $conflictTitle -items $conflictItems -helpText (T "Renew.MenuPrompt")
    
    if ($null -eq $conflictSel -or $conflictSel -eq 2) {
      # キャンセル
      Write-Host (T "Common.Cancelled")
      exit 0
    }
  }

  # Overwrite またはメニューで Overwrite を選択した場合
  # 事故防止：拡張子は維持し、ファイル名にタイムスタンプを入れてバックアップ
  $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
  if (Test-Path -LiteralPath $keyPath -PathType Leaf) {
    try { Rename-Item -Force -ErrorAction Stop -LiteralPath $keyPath -NewName ("{0}.bak_{1}.key" -f $CN, $ts) }
    catch { throw (T "Renew.BackupKeyFail" @($keyPath)) }
  }
  if (Test-Path -LiteralPath $csrPath -PathType Leaf) {
    try { Rename-Item -Force -ErrorAction Stop -LiteralPath $csrPath -NewName ("{0}.bak_{1}.csr" -f $CN, $ts) }
    catch { throw (T "Renew.BackupCsrFail" @($csrPath)) }
  }
}

if (-not [string]::IsNullOrWhiteSpace($PassFile)) {
  Assert-ExistsFile $PassFile "PassFile"
  $passphrase = Get-Passphrase $PassFile
  if ([string]::IsNullOrWhiteSpace($passphrase)) {
    throw (T "MakeCsr.PassFileUnreadable" @($PassFile))
  }

  # OpenSSL 3.x の req は -aes256 を受け付けないため、genpkey + req で生成する
  Invoke-TempPassFile $passphrase {
    param($tmpPass)
    Invoke-OpenSsl @(
      "genpkey",
      "-algorithm", "RSA",
      "-pkeyopt", ("rsa_keygen_bits:{0}" -f $RsaBits),
      "-out", $keyPath,
      "-aes-256-cbc",
      "-pass", ("file:{0}" -f $tmpPass)
    ) | Out-Null

    $reqArgs = @("req", "-new", "-sha256", "-key", $keyPath, "-passin", ("file:{0}" -f $tmpPass), "-out", $csrPath, "-subj", $subj)
    if ($sanOpt.Count -gt 0) { $reqArgs += $sanOpt }
    Invoke-OpenSsl $reqArgs | Out-Null
  } | Out-Null
}
else {
  $args = @("req", "-new", "-newkey", ("rsa:{0}" -f $RsaBits), "-sha256", "-nodes", "-keyout", $keyPath, "-out", $csrPath, "-subj", $subj)
  if ($sanOpt.Count -gt 0) { $args += $sanOpt }
  Invoke-OpenSsl $args | Out-Null
}

Write-Host (T "MakeCsr.DoneKey" @((Resolve-Path -LiteralPath $keyPath)))
Write-Host (T "MakeCsr.DoneCsr" @((Resolve-Path -LiteralPath $csrPath)))
Write-Host ""
Write-Host (T "MakeCsr.PreviewTitle")
Invoke-OpenSsl @("req", "-in", $csrPath, "-noout", "-subject") | Write-Output
Invoke-OpenSsl @("req", "-in", $csrPath, "-noout", "-text") | Select-String -Pattern "Subject Alternative Name" -Context 0, 2 | ForEach-Object { $_.ToString() } | Write-Output


