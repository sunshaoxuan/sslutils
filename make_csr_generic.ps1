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
出力ディレクトリ（既定: カレント）

.PARAMETER Overwrite
既存の <CN>.key / <CN>.csr が存在する場合に、バックアップして再生成

.PARAMETER RsaBits
RSA 鍵長（既定: 2048）

.PARAMETER OpenSsl
OpenSSL 実行ファイルのパス

.PARAMETER Lang
出力言語（既定: ja）

.EXAMPLE
.\make_csr_generic.ps1 -CN example.com -Subject "/C=JP/ST=Tokyo/L=Tokyo/O=Example Corp/CN=example.com"
Subject を明示指定して CSR 生成

.EXAMPLE
.\make_csr_generic.ps1 -CN example.com -C JP -ST Tokyo -L Tokyo -O "Example Corp"
個別パラメータで CSR 生成

.EXAMPLE
.\make_csr_generic.ps1 -CN example.com -PassFile .\passphrase.txt -Overwrite
暗号化鍵で CSR 生成（既存ファイルはバックアップ）

.NOTES
- Subject が未指定の場合は、-C/-ST/-L/-O を全て指定する必要があります
- OpenSSL 3.x 対応：暗号化鍵生成時は genpkey + req を使用します
- 既存ファイルの上書きは、-Overwrite を指定しない限り行いません
#>

param(
  # 必須：対象FQDN（CN）
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$CN,

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
  [string]$OutDir = ".",

  # 既存の <CN>.key / <CN>.csr が存在する場合に、バックアップして再生成する
  [Parameter(Mandatory = $false)]
  [switch]$Overwrite,

  [Parameter(Mandatory = $false)]
  [int]$RsaBits = 2048,

  [Parameter(Mandatory = $false)]
  [string]$OpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe",

  # 出力言語（既定: ja）
  [Parameter(Mandatory = $false)]
  [ValidateSet("ja","zh","en")]
  [string]$Lang = "ja"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$i18nModule = Join-Path $PSScriptRoot "lib\\i18n.ps1"
if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw "i18n モジュールが見つかりません: $i18nModule" }
. $i18nModule
$__i18n = Initialize-I18n -Lang $Lang -BaseDir $PSScriptRoot
function T([string]$Key, [object[]]$FormatArgs = @()) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }

function Assert-ExistsFile([string]$p, [string]$label) {
  if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
    throw (T "Common.FileNotFound" @($label, $p))
  }
}

function Ensure-Dir([string]$p) {
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

function Run-OpenSsl([string[]]$OpenSslArgs) {
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

Assert-ExistsFile $OpenSsl "OpenSSL"
Ensure-Dir $OutDir

if ([string]::IsNullOrWhiteSpace($CN)) {
  throw (T "MakeCsr.CnRequired")
}

$subj = $Subject
if ([string]::IsNullOrWhiteSpace($subj)) {
  if ([string]::IsNullOrWhiteSpace($C) -or [string]::IsNullOrWhiteSpace($ST) -or [string]::IsNullOrWhiteSpace($L) -or [string]::IsNullOrWhiteSpace($O)) {
    throw (T "MakeCsr.SubjectMissing")
  }
  $subj = "/C=$C/ST=$ST/L=$L/O=$O/CN=$CN"
}

$keyPath = Join-Path $OutDir ($CN + ".key")
$csrPath = Join-Path $OutDir ($CN + ".csr")

if ((Test-Path -LiteralPath $keyPath -PathType Leaf) -or (Test-Path -LiteralPath $csrPath -PathType Leaf)) {
  if (-not $Overwrite) {
    throw (T "MakeCsr.OutExistsNoOverwrite" @((Resolve-Path -LiteralPath $OutDir)))
  }
  # 事故防止：拡張子は維持し、ファイル名にタイムスタンプを入れてバックアップ
  Backup-IfExists $keyPath
  Backup-IfExists $csrPath
}

if (-not [string]::IsNullOrWhiteSpace($PassFile)) {
  Assert-ExistsFile $PassFile "PassFile"
  $passphrase = Get-Passphrase $PassFile
  if ([string]::IsNullOrWhiteSpace($passphrase)) {
    throw (T "MakeCsr.PassFileUnreadable" @($PassFile))
  }

  # OpenSSL 3.x の req は -aes256 を受け付けないため、genpkey + req で生成する
  With-TempPassFile $passphrase {
    param($tmpPass)
    Run-OpenSsl @(
      "genpkey",
      "-algorithm","RSA",
      "-pkeyopt",("rsa_keygen_bits:{0}" -f $RsaBits),
      "-out",$keyPath,
      "-aes-256-cbc",
      "-pass",("file:{0}" -f $tmpPass)
    ) | Out-Null

    $reqArgs = @("req","-new","-sha256","-key",$keyPath,"-passin",("file:{0}" -f $tmpPass),"-out",$csrPath,"-subj",$subj)
    if ($WithSAN) { $reqArgs += @("-addext", ("subjectAltName=DNS:{0}" -f $CN)) }
    Run-OpenSsl $reqArgs | Out-Null
  } | Out-Null
} else {
  $args = @("req","-new","-newkey",("rsa:{0}" -f $RsaBits),"-sha256","-nodes","-keyout",$keyPath,"-out",$csrPath,"-subj",$subj)
  if ($WithSAN) { $args += @("-addext", ("subjectAltName=DNS:{0}" -f $CN)) }
  Run-OpenSsl $args | Out-Null
}

Write-Host (T "MakeCsr.DoneKey" @((Resolve-Path -LiteralPath $keyPath)))
Write-Host (T "MakeCsr.DoneCsr" @((Resolve-Path -LiteralPath $csrPath)))
Write-Host ""
Write-Host (T "MakeCsr.PreviewTitle")
Run-OpenSsl @("req","-in",$csrPath,"-noout","-subject") | Write-Output
Run-OpenSsl @("req","-in",$csrPath,"-noout","-text") | Select-String -Pattern "Subject Alternative Name" -Context 0,2 | ForEach-Object { $_.ToString() } | Write-Output


