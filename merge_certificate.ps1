<#
.SYNOPSIS
クライアント証明書と中間証明書を結合してフルチェーンを作成するスクリプト

.DESCRIPTION
このスクリプトは、クライアント証明書（サーバ証明書）と中間証明書（CA証明書）を
結合して、完全な証明書チェーンを作成します。

主な機能:
- クライアント証明書と中間証明書の自動結合
- 中間証明書の自動選択（issuer/subject による一致判定）
- 既に結合済みの証明書の検出とスキップ
- 一括処理モード（old/ と new/ 配下を自動走査）
- 改行コードの正規化（LF統一）

.PARAMETER ClientCert
クライアント証明書のパス（省略時：一括処理モード）

.PARAMETER IntermediateCert
中間証明書のパス（省略時：ルート直下から自動選択）

.PARAMETER OutFile
出力ファイルのパス（省略時：OutDir 配下に自動配置）

.PARAMETER OutDir
出力ディレクトリ（既定: .\merged）

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
.\merge_certificate.ps1
old\ と new\ 配下のすべての証明書を自動結合

.EXAMPLE
.\merge_certificate.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer
指定した証明書を結合

.NOTES
- 中間証明書の自動選択は、クライアント証明書の issuer と中間証明書の subject が一致するものを探します
- 既存の出力ファイルと内容が同一の場合は、バックアップせずにスキップします
- 誤結合防止のため、複数候補がある場合は自動選択しません
#>

param(
  # 省略した場合：old\ と new\ を走査して一括処理します
  [Parameter(Mandatory = $false, Position = 0)]
  [string]$ClientCert = "",

  # 中間証明書（省略可：ルート直下から自動選択します）
  [Parameter(Mandatory = $false, Position = 1)]
  [string]$IntermediateCert = "",

  # 出力先（未指定の場合は ./merged/<clientFileName>）
  [Parameter(Mandatory = $false)]
  [string]$OutFile = "",

  [Parameter(Mandatory = $false)]
  [string]$OutDir = ".\merged",

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

# ===== 設定（静的パラメータ表）=====
# ルート直下に置かれる「中間証明書候補」ファイル名パターン
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

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p -PathType Container)) {
    New-Item -ItemType Directory -Path $p | Out-Null
  }
}

if (-not [string]::IsNullOrWhiteSpace($ClientCert)) {
  Assert-ExistsFile $ClientCert "Client certificate"
}
if (-not [string]::IsNullOrWhiteSpace($IntermediateCert)) { Assert-ExistsFile $IntermediateCert "Intermediate certificate" }

Ensure-Dir $OutDir

if ([string]::IsNullOrWhiteSpace($RootDir)) { $RootDir = $PSScriptRoot }
if (-not (Test-Path -LiteralPath $RootDir -PathType Container)) { throw (T "MergeCert.RootDirNotFound" @($RootDir)) }

function Resolve-RelPath([string]$baseDir, [string]$fullPath) {
  $base = (Resolve-Path -LiteralPath $baseDir).Path.TrimEnd('\','/')
  $full = (Resolve-Path -LiteralPath $fullPath).Path
  if ($full.Length -lt $base.Length) { return [IO.Path]::GetFileName($fullPath) }
  if ($full.Substring(0, $base.Length).ToLowerInvariant() -ne $base.ToLowerInvariant()) {
    return [IO.Path]::GetFileName($fullPath)
  }
  $rel = $full.Substring($base.Length).TrimStart('\','/')
  return $rel
}

function Get-OutPathForClientCert([string]$clientCertPath) {
  if (-not [string]::IsNullOrWhiteSpace($OutFile)) { return $OutFile }
  $rel = Resolve-RelPath $RootDir $clientCertPath
  $outPath = Join-Path $OutDir $rel
  $outParent = Split-Path -Parent $outPath
  if (-not [string]::IsNullOrWhiteSpace($outParent)) { Ensure-Dir $outParent }
  return $outPath
}

function Run-OpenSsl([string[]]$OpenSslArgs, [switch]$AllowFail) {
  $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    if ($AllowFail) { return $out }
    throw (T "Common.OpenSslCmdFailed" @(($OpenSslArgs -join " "), (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return $out
}

function NormalizeLf([string]$s) {
  return ($s -replace "`r`n","`n" -replace "`r","`n")
}

function Get-CertBlockCount([string]$pemText) {
  return [regex]::Matches($pemText, "-----BEGIN CERTIFICATE-----").Count
}

function Normalize-MergedText([string]$s) {
  $t = NormalizeLf $s
  if (-not $t.EndsWith("`n")) { $t += "`n" }
  return $t
}

function Read-TextIfExists([string]$path) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return "" }
  try {
    return (Get-Content -LiteralPath $path -Raw)
  } catch {
    return ""
  }
}

function Find-IntermediateCandidates() {
  $found = New-Object System.Collections.Generic.List[string]
  foreach ($pat in @($IntermediateCertFileNamePatterns)) {
    if ([string]::IsNullOrWhiteSpace($pat)) { continue }
    $items = @(Get-ChildItem -LiteralPath $PSScriptRoot -File -Filter $pat -ErrorAction SilentlyContinue)
    foreach ($i in $items) { $found.Add($i.FullName) | Out-Null }
  }
  return @($found | Select-Object -Unique)
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
    $issuerLine = (Run-OpenSsl @("x509","-in",$clientCertPath,"-noout","-issuer","-nameopt","RFC2253") -AllowFail | Select-Object -First 1)
    $issuer = ([string]$issuerLine).Trim().Replace("issuer=","")
    if (-not [string]::IsNullOrWhiteSpace($issuer)) {
      $matched = @()
      foreach ($cand in $cands) {
        $subjLine = (Run-OpenSsl @("x509","-in",$cand,"-noout","-subject","-nameopt","RFC2253") -AllowFail | Select-Object -First 1)
        $subj = ([string]$subjLine).Trim().Replace("subject=","")
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

function Merge-One([string]$clientCertPath) {
  Assert-ExistsFile $clientCertPath "Client certificate"
  $outPath = Get-OutPathForClientCert $clientCertPath

  Write-Host ""
  Write-Host (T "MergeCert.TitleSingle")
  Write-Host ""
  Write-Host (T "MergeCert.Step1")
  Write-Host (T "MergeCert.ClientCert" @((Resolve-Path -LiteralPath $clientCertPath)))
  Write-Host ""
  Write-Host (T "MergeCert.Step2")

  $a = Get-Content -LiteralPath $clientCertPath -Raw
  $a = Normalize-MergedText $a

  $blockCount = Get-CertBlockCount $a
  $alreadyMerged = ($blockCount -ge 2)

  if ($alreadyMerged -and $SkipIfAlreadyMerged -and -not $Force) {
    Write-Host (T "MergeCert.AlreadyHasChain" @($blockCount))
    $merged = $a
  } else {
    $selectedIntermediate = Select-IntermediateCert $clientCertPath
    Assert-ExistsFile $selectedIntermediate "Intermediate certificate"
    Write-Host (T "MergeCert.IntermediateCert" @((Resolve-Path -LiteralPath $selectedIntermediate)))

    $b = Get-Content -LiteralPath $selectedIntermediate -Raw
    $b = Normalize-MergedText $b
    $merged = $a + $b
  }

  $merged = Normalize-MergedText $merged

  # 既存出力と同一なら何もしない（不要なバックアップ/更新を防ぐ）
  $existing = Read-TextIfExists $outPath
  if (-not [string]::IsNullOrWhiteSpace($existing)) {
    $existingNorm = Normalize-MergedText $existing
    if ($existingNorm -eq $merged) {
      Write-Host (T "MergeCert.SameAsExistingSkip" @((Resolve-Path -LiteralPath $outPath)))
      return
    }
  }

  Backup-IfExists $outPath
  Set-Content -LiteralPath $outPath -Value $merged -NoNewline -Encoding ASCII

  Write-Host ""
  Write-Host (T "MergeCert.Done")
  Write-Host (T "MergeCert.OutFile" @((Resolve-Path -LiteralPath $outPath)))
}

function Find-ClientCerts([string]$root) {
  $dirs = @()
  $old = Join-Path $root "old"
  $new = Join-Path $root "new"
  if (Test-Path -LiteralPath $old -PathType Container) { $dirs += $old }
  if (Test-Path -LiteralPath $new -PathType Container) { $dirs += $new }
  if ($dirs.Count -eq 0) { $dirs += $root }

  $all = New-Object System.Collections.Generic.List[string]
  foreach ($d in $dirs) {
    foreach ($f in @(Get-ChildItem -LiteralPath $d -Recurse -File -Include *.cer,*.crt,*.pem -ErrorAction SilentlyContinue)) {
      $all.Add($f.FullName) | Out-Null
    }
  }
  return @($all | Select-Object -Unique)
}

if ([string]::IsNullOrWhiteSpace($ClientCert)) {
  Write-Host ""
  Write-Host (T "MergeCert.TitleBatch")
  Write-Host (T "MergeCert.RootDir" @((Resolve-Path -LiteralPath $RootDir)))
  Write-Host (T "MergeCert.OutDir" @((Resolve-Path -LiteralPath $OutDir)))

  $targets = @(Find-ClientCerts $RootDir)
  if ($targets.Count -eq 0) {
    Write-Host (T "MergeCert.NoTargets")
    exit 0
  }

  foreach ($t in $targets) {
    try {
      Merge-One $t
    } catch {
      Write-Host (T "Common.ErrorNg" @($t))
      Write-Host (T "Common.ErrorNg" @($_.Exception.Message))
    }
  }
  exit 0
}

Merge-One $ClientCert


