<#
.SYNOPSIS
すべての証明書と秘密鍵の Modulus 値を一覧表示するスクリプト

.DESCRIPTION
このスクリプトは、指定ディレクトリ配下のすべての証明書（.cer/.crt/.pem）と
秘密鍵（.key）から Modulus 値を抽出し、テキストファイルに一覧出力します。

主な機能:
- 証明書と秘密鍵の Modulus 値の抽出
- 暗号化鍵の自動処理（パスワードファイル対応）
- 一覧レポートの生成（modulus_list.txt）

用途:
- 証明書と秘密鍵のペア確認（Modulus が一致すればペア）
- 証明書と CSR の一致確認
- 鍵の重複チェック

.PARAMETER RootDir
探索ルートディレクトリ（既定: .）

.PARAMETER OutFile
出力ファイル名（既定: modulus_list.txt）

.PARAMETER OpenSsl
OpenSSL 実行ファイルのパス

.PARAMETER PassFile
暗号化鍵用のパスフレーズファイル（指定しない場合はパスフレーズ無しで試行）

.PARAMETER Lang
出力言語（既定: ja）

.EXAMPLE
.\show_all_modulus.ps1 -RootDir .\old
old\ 配下のすべての証明書・鍵の Modulus を抽出

.EXAMPLE
.\show_all_modulus.ps1 -RootDir . -PassFile .\passphrase.txt
パスワードファイルを指定して暗号化鍵も処理

.NOTES
- 暗号化された秘密鍵は、-PassFile または環境変数 PASS_FILE が必要です
- 無効な証明書や複数証明書を含むファイルは "[無効な証明書...]" と表示されます
- 出力ファイルは既存の場合、自動的にバックアップされます
#>

param(
  [Parameter(Mandatory = $false)]
  [string]$RootDir = ".",

  [Parameter(Mandatory = $false)]
  [string]$OutFile = "modulus_list.txt",

  [Parameter(Mandatory = $false)]
  [string]$OpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe",

  # 任意：暗号化鍵用のパスフレーズファイル（指定しない場合はパスフレーズ無しで試行）
  [Parameter(Mandatory = $false)]
  [string]$PassFile = "",

  # 出力言語（既定: ja）
  [Parameter(Mandatory = $false)]
  [ValidateSet("ja","zh","en")]
  [string]$Lang = "ja"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$i18nModule = Join-Path $PSScriptRoot "lib\\i18n.ps1"
if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw (T "Common.I18nModuleNotFound" @($i18nModule)) }
. $i18nModule
$__i18n = Initialize-I18n -Lang $Lang -BaseDir $PSScriptRoot
function T([string]$Key, [object[]]$FormatArgs = @()) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }

$FixedPassFileName = "passphrase.txt"

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

function Run-OpenSsl([string[]]$OpenSslArgs) {
  $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) { return $null }
  return $out
}

Assert-ExistsFile $OpenSsl "OpenSSL"

$passFileToUse = ""
if (-not [string]::IsNullOrWhiteSpace($PassFile)) {
  if (-not (Test-Path -LiteralPath $PassFile -PathType Leaf)) {
    throw (T "Common.FileNotFound" @("PassFile", $PassFile))
  }
  $passFileToUse = $PassFile
} elseif (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE) -and (Test-Path -LiteralPath $env:PASS_FILE -PathType Leaf)) {
  $passFileToUse = $env:PASS_FILE
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

$root = Resolve-Path -LiteralPath $RootDir

$certFiles = Get-ChildItem -LiteralPath $root -Recurse -File -Include *.cer,*.crt,*.pem -ErrorAction SilentlyContinue
$keyFiles  = Get-ChildItem -LiteralPath $root -Recurse -File -Include *.key -ErrorAction SilentlyContinue

$sb = New-Object System.Text.StringBuilder
function AddLine([string]$s="") { [void]$sb.AppendLine($s) }

AddLine (T "ShowModulus.Title")
AddLine (T "ShowModulus.CreatedAt" @((Get-Date)))
AddLine ""
AddLine ""
AddLine "================================================"
AddLine (T "ShowModulus.SectionCert")
AddLine "================================================"
AddLine ""

$certCount = 0
foreach ($f in $certFiles) {
  AddLine "------------------------------------------------"
  AddLine ("File: {0}" -f $f.FullName)
  AddLine ""
  $out = Run-OpenSsl @("x509","-in",$f.FullName,"-noout","-modulus")
  if ($out) {
    $certCount++
    $out | ForEach-Object { AddLine $_ }
  } else {
    AddLine (T "ShowModulus.InvalidCert")
  }
  AddLine ""
}

AddLine ""
AddLine ""
AddLine "================================================"
AddLine (T "ShowModulus.SectionKey")
AddLine "================================================"
AddLine ""

$keyCount = 0
foreach ($f in $keyFiles) {
  AddLine "------------------------------------------------"
  AddLine ("File: {0}" -f $f.FullName)
  AddLine ""

  # OpenSSL の対話プロンプトを絶対に出さないため、暗号化鍵は必ず -passin で読む
  $isEnc = Test-KeyEncrypted $f.FullName
  if ($isEnc -and [string]::IsNullOrWhiteSpace($passFileToUse)) {
    AddLine (T "ShowModulus.SkipEncryptedKey" @($FixedPassFileName))
    AddLine ""
    continue
  }

  $args = @("rsa","-in",$f.FullName,"-noout","-modulus")
  if ($isEnc -and -not [string]::IsNullOrWhiteSpace($passFileToUse)) {
    $args = @("rsa","-in",$f.FullName,"-noout","-modulus","-passin",("file:{0}" -f $passFileToUse))
  }

  $out = Run-OpenSsl $args
  if ($out) {
    $keyCount++
    $out | ForEach-Object { AddLine $_ }
  } else {
    AddLine (T "ShowModulus.KeyReadError")
  }
  AddLine ""
}

AddLine ""
AddLine ""
AddLine "================================================"
AddLine (T "ShowModulus.SummaryTitle")
AddLine "================================================"
AddLine (T "ShowModulus.SummaryCertCount" @($certCount))
AddLine (T "ShowModulus.SummaryKeyCount" @($keyCount))
AddLine ""
AddLine (T "ShowModulus.Advice1")
AddLine (T "ShowModulus.Advice2")
AddLine ""

Backup-IfExists $OutFile
Set-Content -LiteralPath $OutFile -Value $sb.ToString() -Encoding UTF8

Write-Host ""
Write-Host "==============================================="
Write-Host (T "ShowModulus.ConsoleTitle")
Write-Host "==============================================="
Write-Host (T "ShowModulus.SummaryCertCount" @($certCount))
Write-Host (T "ShowModulus.SummaryKeyCount" @($keyCount))
Write-Host ""
Write-Host (T "ShowModulus.SavedTo" @((Resolve-Path -LiteralPath $OutFile)))


