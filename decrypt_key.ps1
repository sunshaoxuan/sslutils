<#
.SYNOPSIS
暗号化された秘密鍵ファイルを復号化して平文鍵を作成するスクリプト

.DESCRIPTION
このスクリプトは、AES-256 等で暗号化された秘密鍵（.key）を復号化して、
平文（暗号化なし）の秘密鍵ファイルを作成します。

主な機能:
- 暗号化鍵の自動検出と復号化
- パスワードファイル（passphrase.txt）の自動探索
- 一括処理（ディレクトリ指定時の再帰処理）
- インプレース復号化（-InPlace オプション）
- 上書き前の自動バックアップ

.PARAMETER Path
処理対象の .key ファイルまたはディレクトリ（省略時：new\ を走査）

.PARAMETER OpenSsl
OpenSSL 実行ファイルのパス

.PARAMETER PassFile
パスフレーズファイルの明示指定（優先）

.PARAMETER OutPath
出力ファイルのパス（省略時：<元ファイル名>.decrypted.key）

.PARAMETER Overwrite
出力先が存在する場合に、バックアップして上書き

.PARAMETER InPlace
既存の暗号化鍵をそのまま平文化して上書き（危険：バックアップは行う）

.PARAMETER Recurse
ディレクトリ指定時に再帰処理

.PARAMETER Lang
出力言語（既定: ja）

.EXAMPLE
.\decrypt_key.ps1 -Path .\new\example.com\server.key
指定した鍵ファイルを復号化

.EXAMPLE
.\decrypt_key.ps1 -Path .\new -Recurse -Overwrite
new\ 配下のすべての .key を再帰的に復号化

.EXAMPLE
.\decrypt_key.ps1 -Path .\encrypted.key -InPlace -Overwrite
暗号化鍵を平文化して上書き（元ファイルはバックアップ）

.NOTES
- パスワードファイルは、鍵ファイルのディレクトリから上位階層を自動探索します
- 対話入力は行いません。passphrase.txt または PASS_FILE 環境変数が必要です
- -InPlace は危険な操作のため、必ず -Overwrite と併用してください
#>

param(
  # 指定した場合：そのファイル（.key）またはそのフォルダ配下の .key を処理
  # 省略した場合：new\ を走査（存在しなければカレント配下）
  [Parameter(Mandatory = $false, Position = 0)]
  [string]$Path = "",

  # 任意：OpenSSL のパス
  [Parameter(Mandatory = $false)]
  [string]$OpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe",

  # 任意：パスフレーズファイルを明示（優先）
  [Parameter(Mandatory = $false)]
  [string]$PassFile = "",

  # 任意：出力先（省略時は <元>.decrypted.key）
  [Parameter(Mandatory = $false)]
  [string]$OutPath = "",

  # 出力先が存在する場合に、バックアップして上書き
  [Parameter(Mandatory = $false)]
  [switch]$Overwrite,

  # 既存の暗号化 key をそのまま明文化して上書き（危険：バックアップは行う）
  [Parameter(Mandatory = $false)]
  [switch]$InPlace,

  # ディレクトリ指定時に再帰する
  [Parameter(Mandatory = $false)]
  [switch]$Recurse,

  # 出力言語（既定: ja）
  [Parameter(Mandatory = $false)]
  [ValidateSet("ja","zh","en")]
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

function Assert-ExistsFile([string]$p, [string]$label) {
  if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
    throw (T "Common.FileNotFound" @($label, $p))
  }
}

function Backup-IfExists([string]$path) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
  $dir = Split-Path -Parent $path
  $base = [IO.Path]::GetFileNameWithoutExtension($path)
  $ext = [IO.Path]::GetExtension($path)  # .key
  $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
  $bak = Join-Path $dir ("{0}.bak_{1}{2}" -f $base, $ts, $ext)
  Rename-Item -Force -ErrorAction Stop -LiteralPath $path -NewName ([IO.Path]::GetFileName($bak))
  return $bak
}

function Run-OpenSsl([string[]]$OpenSslArgs, [switch]$AllowFail) {
  $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    if ($AllowFail) { return $out }
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

function Test-KeyEncrypted([string]$keyPath) {
  try {
    $head = @(Get-Content -LiteralPath $keyPath -TotalCount 60 -ErrorAction Stop)
  } catch {
    return $false
  }
  $text = ($head -join "`n")
  if ($text -match "BEGIN ENCRYPTED PRIVATE KEY") { return $true }
  if ($text -match "Proc-Type:\s*4,ENCRYPTED") { return $true }
  if ($text -match "\bENCRYPTED\b") { return $true }
  return $false
}

function Find-PassFile([string]$dir) {
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

function Get-DefaultOutPath([string]$keyPath) {
  $dir = Split-Path -Parent $keyPath
  $base = [IO.Path]::GetFileNameWithoutExtension($keyPath)
  return (Join-Path $dir ($base + ".decrypted.key"))
}

function Get-KeyCandidates([string]$p) {
  if ([string]::IsNullOrWhiteSpace($p)) {
    $newDir = Join-Path $PSScriptRoot "new"
    if (Test-Path -LiteralPath $newDir -PathType Container) {
      $p = $newDir
    } else {
      $p = "."
    }
  }

  if (Test-Path -LiteralPath $p -PathType Leaf) {
    return @((Resolve-Path -LiteralPath $p).Path)
  }
  if (Test-Path -LiteralPath $p -PathType Container) {
    $recurse = $Recurse.IsPresent
    if (-not $Recurse.IsPresent) {
      # new/old の構造は階層が深いので、未指定でも再帰をデフォルト ON
      $recurse = $true
    }
    if ($recurse) {
      return @((Get-ChildItem -LiteralPath $p -Recurse -File -Filter "*.key" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName))
    }
    return @((Get-ChildItem -LiteralPath $p -File -Filter "*.key" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName))
  }
  throw (T "DecryptKey.PathNotFound" @($p))
}

function Get-PassFilesForKey([string]$keyPath) {
  $files = New-Object System.Collections.Generic.List[string]
  if (-not [string]::IsNullOrWhiteSpace($PassFile)) { $files.Add($PassFile) | Out-Null }

  $dir = Split-Path -Parent $keyPath
  # key のディレクトリから上へ 6 階層まで探索（org 直下 passphrase.txt を拾うため）
  $cur = $dir
  for ($i = 0; $i -lt 6; $i++) {
    $f = Find-PassFile $cur
    if (-not [string]::IsNullOrWhiteSpace($f)) { $files.Add($f) | Out-Null }
    $parent = Split-Path -Parent $cur
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cur) { break }
    $cur = $parent
  }

  # script root / old / new にも固定名があれば拾う
  foreach ($d in @($PSScriptRoot, (Join-Path $PSScriptRoot "old"), (Join-Path $PSScriptRoot "new"))) {
    $f = Find-PassFile $d
    if (-not [string]::IsNullOrWhiteSpace($f)) { $files.Add($f) | Out-Null }
  }

  return @($files | Select-Object -Unique)
}

function Decrypt-OneKey([string]$keyPath) {
  Assert-ExistsFile $keyPath (T "Label.Key")

  $isEnc = Test-KeyEncrypted $keyPath
  Write-Host (T "DecryptKey.KeyHeader" @((Resolve-Path -LiteralPath $keyPath)))
  $encText = if ($isEnc) { (T "Common.Yes") } else { (T "Common.No") }
  Write-Host (T "DecryptKey.EncryptedLine" @($encText))

  if (-not $isEnc) {
    Write-Host (T "DecryptKey.SkipPlain")
    Write-Host ""
    return
  }

  $passFiles = Get-PassFilesForKey $keyPath
  $existingPassFiles = @($passFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique)
  if ($existingPassFiles.Count -gt 0) {
    Write-Host (T "DecryptKey.PassFilesLine" @($FixedPassFileName, ($existingPassFiles -join "; ")))
  } else {
    Write-Host (T "DecryptKey.PassFilesLine" @($FixedPassFileName, (T "CheckBasic.None")))
  }
  if (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE)) {
    $envPassExists = Test-Path -LiteralPath $env:PASS_FILE -PathType Leaf
    $envPassExistText = if ($envPassExists) { (T "Common.Exists") } else { (T "Common.NotExists") }
    $envPassName = [IO.Path]::GetFileName($env:PASS_FILE)
    Write-Host (T "DecryptKey.PassEnvLine" @($envPassName, $envPassExistText))
  } else {
    Write-Host (T "DecryptKey.PassEnvUnset")
  }

  $passphrases = Collect-Passphrases $passFiles
  if (@($passphrases).Count -eq 0) {
    throw (T "DecryptKey.NoPassphrase" @($FixedPassFileName))
  }

  $srcKeyPath = $keyPath
  $out = $OutPath
  if ([string]::IsNullOrWhiteSpace($out)) { $out = Get-DefaultOutPath $keyPath }
  if ($InPlace) {
    if (-not $Overwrite) {
      throw (T "DecryptKey.InPlaceNeedOverwrite")
    }
    # 先に元ファイルをバックアップし、バックアップを入力として復号 → 元の名前へ出力
    $bak = Backup-IfExists $keyPath
    if ([string]::IsNullOrWhiteSpace($bak)) { throw (T "DecryptKey.BackupFailed" @($keyPath)) }
    $srcKeyPath = $bak
    $out = $keyPath
    Write-Host (T "DecryptKey.BackupLine" @($bak))
    Write-Host (T "DecryptKey.InPlaceLine" @($out))
  }

  if (-not $InPlace -and (Test-Path -LiteralPath $out -PathType Leaf)) {
    if (-not $Overwrite) {
      throw (T "DecryptKey.OutExistsNoOverwrite" @((Resolve-Path -LiteralPath $out)))
    }
    Backup-IfExists $out
  }

  $done = $false
  foreach ($p in @($passphrases)) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    try {
      With-TempPassFile $p {
        param($tmpPass)
        # まずは汎用の pkey を試す（PKCS#8 等に強い）
        Run-OpenSsl @("pkey","-in",$srcKeyPath,"-out",$out,"-passin",("file:{0}" -f $tmpPass)) -AllowFail | Out-Null
        if ($LASTEXITCODE -ne 0) {
          # フォールバック：rsa
          Run-OpenSsl @("rsa","-in",$srcKeyPath,"-out",$out,"-passin",("file:{0}" -f $tmpPass)) | Out-Null
        }
      } | Out-Null
      $done = $true
      break
    } catch { }
  }

  if (-not $done) {
    throw (T "DecryptKey.DecryptFailed")
  }

  # 復号後が本当に平文かチェック
  $stillEnc = Test-KeyEncrypted $out
  if ($stillEnc) {
    throw (T "DecryptKey.StillEncrypted" @($out))
  }

  Write-Host (T "DecryptKey.Done" @((Resolve-Path -LiteralPath $out)))
  Write-Host ""
}

Assert-ExistsFile $OpenSsl "OpenSSL"

$keys = Get-KeyCandidates $Path | Where-Object { $_.ToLowerInvariant().EndsWith(".key") }
if (@($keys).Count -eq 0) {
  Write-Host (T "DecryptKey.NoKeys")
  exit 0
}

foreach ($k in $keys) {
  try {
    Decrypt-OneKey $k
  } catch {
    Write-Host (T "DecryptKey.NgPath" @($k))
    Write-Host (T "DecryptKey.NgMsg" @($_.Exception.Message))
    Write-Host ""
  }
}

