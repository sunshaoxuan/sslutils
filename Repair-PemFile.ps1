<#
.SYNOPSIS
PEM ファイルのフォーマットを修復・正規化するスクリプト

.DESCRIPTION
このスクリプトは、破損または不正なフォーマットの PEM ファイルを修復します。

主な機能:
- UTF-8 BOM の除去
- ヘッダー/フッターの空白修正（例: "-----BEGINCERTIFICATE-----" → "-----BEGIN CERTIFICATE-----"）
- Base64 本文の改行正規化（64文字折り返し）
- 複数ブロック対応（fullchain など）
- 自動バックアップ

.PARAMETER Fullchain
修復対象の証明書（fullchain）ファイルパス（必須）

.PARAMETER Privkey
修復対象の秘密鍵ファイルパス（必須）

.PARAMETER NginxExe
nginx 実行ファイルパス（-TestNginx 使用時）

.PARAMETER NginxConf
nginx 設定ファイルパス（-TestNginx 使用時）

.PARAMETER TestNginx
修復後に nginx -t で構文チェックを実行

.PARAMETER Lang
出力言語（既定: ja）

.EXAMPLE
.\Repair-PemFile.ps1 -Fullchain .\fullchain.pem -Privkey .\privkey.pem
証明書と秘密鍵を修復

.EXAMPLE
.\Repair-PemFile.ps1 -Fullchain .\fullchain.pem -Privkey .\privkey.pem -TestNginx
修復後に nginx -t で検証

.NOTES
- 修復前に .bak_タイムスタンプ 形式でバックアップを作成します
- 修復に失敗した場合、バックアップファイルから復元できます
#>

param(
  [Parameter(Mandatory = $true)]
  [string]$Fullchain,

  [Parameter(Mandatory = $true)]
  [string]$Privkey,

  [Parameter(Mandatory = $false)]
  [string]$NginxExe = "",

  [Parameter(Mandatory = $false)]
  [string]$NginxConf = "",

  [Parameter(Mandatory = $false)]
  [switch]$TestNginx,

  [Parameter(Mandatory = $false)]
  [ValidateSet("ja", "zh", "en")]
  [string]$Lang = "ja"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# i18n 初期化
$i18nModule = Join-Path $PSScriptRoot "lib\i18n.ps1"
if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw "i18n module not found: $i18nModule" }
. $i18nModule
$__i18n = Initialize-I18n -Lang $Lang -BaseDir $PSScriptRoot
function T([string]$Key, [object[]]$FormatArgs = @()) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }

# ファイル存在確認
function Assert-FileExists([string]$path, [string]$label) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw (T "Common.FileNotFound" @($label, $path))
  }
}

# バックアップ作成
function Backup-File([string]$path) {
  Assert-FileExists $path "File"
  $bak = "$path.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
  Copy-Item -LiteralPath $path -Destination $bak -Force
  return $bak
}

# BOM 除去してバイト配列読み込み
function Read-BytesNoBom([string]$path) {
  $bytes = [System.IO.File]::ReadAllBytes($path)
  if ($null -eq $bytes) { throw (T "RepairPem.ReadFailed" @($path)) }
  if ($bytes.Length -eq 0) { throw (T "RepairPem.ZeroBytes" @($path)) }

  # UTF-8 BOM: EF BB BF
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    $newLen = $bytes.Length - 3
    if ($newLen -le 0) { throw (T "RepairPem.EmptyAfterBom" @($path)) }
    $nb = New-Object byte[] $newLen
    [System.Array]::Copy($bytes, 3, $nb, 0, $newLen)
    return $nb
  }
  return $bytes
}

# テキスト読み込み（BOM除去 + 改行正規化）
function Read-TextRaw([string]$path) {
  $bytes = Read-BytesNoBom $path
  $text = [System.Text.Encoding]::UTF8.GetString($bytes)
  $text = $text -replace "`r", ""
  return $text
}

# ASCII で書き込み
function Write-TextAscii([string]$path, [string]$text) {
  [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.ASCIIEncoding))
}

# ヘッダー修復（空白欠損）
function Repair-Headers([string]$text) {
  $text = $text -replace "-----BEGINCERTIFICATE-----", "-----BEGIN CERTIFICATE-----"
  $text = $text -replace "-----ENDCERTIFICATE-----", "-----END CERTIFICATE-----"
  $text = $text -replace "-----BEGINPRIVATEKEY-----", "-----BEGIN PRIVATE KEY-----"
  $text = $text -replace "-----ENDPRIVATEKEY-----", "-----END PRIVATE KEY-----"
  $text = $text -replace "-----BEGINECPRIVATEKEY-----", "-----BEGIN EC PRIVATE KEY-----"
  $text = $text -replace "-----ENDECPRIVATEKEY-----", "-----END EC PRIVATE KEY-----"
  $text = $text -replace "-----BEGINRSAPRIVATEKEY-----", "-----BEGIN RSA PRIVATE KEY-----"
  $text = $text -replace "-----ENDRSAPRIVATEKEY-----", "-----END RSA PRIVATE KEY-----"
  return $text
}

# PEM 正規化
function Normalize-Pem([string]$path, [string]$kind) {
  $orig = Read-TextRaw $path
  $t = Repair-Headers $orig

  # PEM ブロック検出
  $matches = [regex]::Matches($t, "-----BEGIN [^-]+-----.*?-----END [^-]+-----", "Singleline")
  if ($matches.Count -eq 0) {
    throw (T "RepairPem.NoPemBlock" @($kind, $path))
  }

  $out = New-Object System.Collections.Generic.List[string]

  foreach ($m in $matches) {
    $block = $m.Value

    $mm = [regex]::Match($block, "^(-----BEGIN [^-]+-----)\s*(.*?)\s*(-----END [^-]+-----)$", "Singleline")
    if (-not $mm.Success) { throw (T "RepairPem.ParseFailed" @($kind, $path)) }

    $begin = $mm.Groups[1].Value
    $body = $mm.Groups[2].Value
    $end = $mm.Groups[3].Value

    # 空白除去
    $body = [regex]::Replace($body, "\s+", "")

    # Base64 長さチェック
    if ($body.Length -lt 128) {
      throw (T "RepairPem.TooShort" @($kind, $body.Length, $path))
    }

    $out.Add($begin)
    for ($i = 0; $i -lt $body.Length; $i += 64) {
      $len = [Math]::Min(64, $body.Length - $i)
      $out.Add($body.Substring($i, $len))
    }
    $out.Add($end)
    $out.Add("")
  }

  $final = ($out -join "`n").TrimEnd() + "`n"
  Write-TextAscii $path $final

  return @{
    Path      = $path
    Blocks    = $matches.Count
    FirstLine = (Get-Content -LiteralPath $path -TotalCount 1)
    LastLine  = (Get-Content -LiteralPath $path -Tail 1)
    Size      = (Get-Item -LiteralPath $path).Length
  }
}

# クイックチェック
function Test-PemHeader([string]$path, [string]$kind) {
  $head = Get-Content -LiteralPath $path -TotalCount 1
  if ($kind -eq "fullchain") {
    if ($head -ne "-----BEGIN CERTIFICATE-----") {
      throw (T "RepairPem.InvalidHeader" @("fullchain", $head))
    }
  }
  elseif ($kind -eq "privkey") {
    if ($head -ne "-----BEGIN PRIVATE KEY-----" -and
      $head -ne "-----BEGIN EC PRIVATE KEY-----" -and
      $head -ne "-----BEGIN RSA PRIVATE KEY-----") {
      throw (T "RepairPem.InvalidHeader" @("privkey", $head))
    }
  }
}

# === メイン処理 ===

# ファイル存在確認
Assert-FileExists $Fullchain "Fullchain"
Assert-FileExists $Privkey "Privkey"

try {
  Write-Host (T "RepairPem.BackupSection") -ForegroundColor Cyan
  $bak1 = Backup-File $Fullchain
  $bak2 = Backup-File $Privkey
  Write-Host (T "RepairPem.BackupCreated" @("fullchain", $bak1))
  Write-Host (T "RepairPem.BackupCreated" @("privkey", $bak2))

  Write-Host ""
  Write-Host (T "RepairPem.NormalizeSection") -ForegroundColor Cyan
  $infoFc = Normalize-Pem $Fullchain "fullchain"
  $infoPk = Normalize-Pem $Privkey "privkey"

  Write-Host ""
  Write-Host (T "RepairPem.VerifySection") -ForegroundColor Cyan
  Test-PemHeader $Fullchain "fullchain"
  Test-PemHeader $Privkey "privkey"

  Write-Host (T "RepairPem.FileInfo" @("fullchain", $infoFc.Size, $infoFc.Blocks, $infoFc.FirstLine, $infoFc.LastLine))
  Write-Host (T "RepairPem.FileInfo" @("privkey", $infoPk.Size, $infoPk.Blocks, $infoPk.FirstLine, $infoPk.LastLine))

  if ($TestNginx) {
    if ([string]::IsNullOrWhiteSpace($NginxExe) -or [string]::IsNullOrWhiteSpace($NginxConf)) {
      throw (T "RepairPem.NginxParamsRequired")
    }
    Assert-FileExists $NginxExe "NginxExe"
    Assert-FileExists $NginxConf "NginxConf"

    Write-Host ""
    Write-Host (T "RepairPem.NginxTestSection") -ForegroundColor Cyan
    & $NginxExe -t -c $NginxConf
    if ($LASTEXITCODE -ne 0) {
      throw (T "RepairPem.NginxTestFailed" @($LASTEXITCODE))
    }
  }

  Write-Host ""
  Write-Host (T "RepairPem.Success") -ForegroundColor Green
}
catch {
  Write-Host ""
  Write-Host (T "RepairPem.Failed" @($_.Exception.Message)) -ForegroundColor Red
  Write-Host (T "RepairPem.RestoreHint") -ForegroundColor Yellow
  throw
}
