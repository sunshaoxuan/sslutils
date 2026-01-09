<#
.SYNOPSIS
証明書・秘密鍵・CSR の Modulus 一致確認レポートを生成するスクリプト

.DESCRIPTION
このスクリプトは、old\ と new\ 配下の証明書・秘密鍵・CSR ファイルの
Modulus 値を比較し、ペアの一致/不一致を判定します。

主な機能:
- 証明書と秘密鍵の Modulus 一致確認
- 証明書と CSR の Modulus 一致確認
- 秘密鍵と CSR の Modulus 一致確認
- 多機関対応（階層構造の自動認識）
- 詳細レポートの生成（certificate_verification_report.txt）

.PARAMETER Mode
処理モード（既定: both / 選択肢: both, old, new）

.PARAMETER OldDir
old ディレクトリのパス（既定: .\old）

.PARAMETER NewDir
new ディレクトリのパス（既定: .\new）

.PARAMETER ReportFile
レポートファイルのパス（既定: certificate_verification_report.txt）

.PARAMETER OpenSsl
OpenSSL 実行ファイルのパス

.PARAMETER PassFile
暗号化鍵用のパスフレーズファイル

.PARAMETER Lang
出力言語（既定: ja）

.EXAMPLE
.\Test-CertificateKeyMatch.ps1 -Mode both
old\ と new\ の両方を確認

.EXAMPLE
.\Test-CertificateKeyMatch.ps1 -Mode old -PassFile .\passphrase.txt
old\ のみ確認（パスワードファイル指定）

.NOTES
- 暗号化された秘密鍵は、passphrase.txt または環境変数 PASS_FILE から自動的にパスワードを読み取ります
- レポートファイルは既存の場合、自動的にバックアップされます
- 機関（第一階層）とサーバ（第二階層）の階層構造を自動認識します
#>

param(
  # both / old / new
  [Parameter(Mandatory = $false, Position = 0)]
  [ValidateSet("both","old","new")]
  [string]$Mode = "both",

  [Parameter(Mandatory = $false)]
  [string]$OldDir = "",

  [Parameter(Mandatory = $false)]
  [string]$NewDir = "",

  [Parameter(Mandatory = $false)]
  [string]$ReportFile = "",

  [Parameter(Mandatory = $false)]
  [string]$OpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe",

  # 任意：暗号化鍵用のパスフレーズファイル
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

function Collect-Passphrases([string[]]$passFilePaths) {
  $phrases = New-Object System.Collections.Generic.List[string]

  foreach ($p in @($passFilePaths)) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    $pp = Get-Passphrase $p
    if (-not [string]::IsNullOrWhiteSpace($pp)) { $phrases.Add($pp) | Out-Null }
  }

  if (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE)) {
    $pp = Get-Passphrase $env:PASS_FILE
    if (-not [string]::IsNullOrWhiteSpace($pp)) { $phrases.Add($pp) | Out-Null }
  }

  return ($phrases | Select-Object -Unique)
}

function Run-OpenSsl([string[]]$OpenSslArgs, [switch]$AllowFail) {
  $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    if ($AllowFail) { return $null }
    throw (T "Common.OpenSslCmdFailed" @(($OpenSslArgs -join " "), (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return $out
}

function Get-ModulusFromCert([string]$path) {
  $out = Run-OpenSsl @("x509","-in",$path,"-noout","-modulus") -AllowFail
  if (-not $out) { return $null }
  return ($out | Select-Object -First 1) -replace "^Modulus=",""
}

function Get-ModulusFromCsr([string]$path) {
  $out = Run-OpenSsl @("req","-in",$path,"-noout","-modulus") -AllowFail
  if (-not $out) { return $null }
  return ($out | Select-Object -First 1) -replace "^Modulus=",""
}

function Get-ModulusFromKey([string]$path, [string[]]$passphrases) {
  # OpenSSL の対話プロンプトを絶対に出さないため、暗号化鍵は必ず -passin で読む
  $isEnc = Test-KeyEncrypted $path
  if (-not $isEnc) {
    $out = Run-OpenSsl @("rsa","-in",$path,"-noout","-modulus") -AllowFail
    if ($out) { return (($out | Select-Object -First 1) -replace "^Modulus=","") }
  }

  foreach ($p in @($passphrases)) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    $mod = With-TempPassFile $p {
      param($tmpPass)
      $o = Run-OpenSsl @("rsa","-in",$path,"-noout","-modulus","-passin",("file:{0}" -f $tmpPass)) -AllowFail
      if (-not $o) { return $null }
      return (($o | Select-Object -First 1) -replace "^Modulus=","")
    }
    if (-not [string]::IsNullOrWhiteSpace($mod)) { return $mod }
  }
  return $null
}

function Get-SubjectFromCert([string]$path) {
  $out = Run-OpenSsl @("x509","-in",$path,"-noout","-subject") -AllowFail
  if (-not $out) { return $null }
  return ($out | Select-Object -First 1)
}

function Get-SubjectFromCsr([string]$path) {
  $out = Run-OpenSsl @("req","-in",$path,"-noout","-subject") -AllowFail
  if (-not $out) { return $null }
  return ($out | Select-Object -First 1)
}

function Find-AllSetFiles([string]$dir) {
  # 全ての証明書/鍵/CSR を検出（複数対応）
  $certs = @(Get-ChildItem -LiteralPath $dir -File -Include *.cer,*.crt,*.pem -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "^(nii|gs|globalsign)" })
  $keys  = @(Get-ChildItem -LiteralPath $dir -File -Include *.key -ErrorAction SilentlyContinue)
  $csrs  = @(Get-ChildItem -LiteralPath $dir -File -Include *.csr -ErrorAction SilentlyContinue)
  return [PSCustomObject]@{
    Certs = @($certs | ForEach-Object { $_.FullName })
    Keys  = @($keys  | ForEach-Object { $_.FullName })
    Csrs  = @($csrs  | ForEach-Object { $_.FullName })
  }
}

Assert-ExistsFile $OpenSsl "OpenSSL"

if ([string]::IsNullOrWhiteSpace($OldDir)) { $OldDir = Join-Path $PSScriptRoot "old" }
if ([string]::IsNullOrWhiteSpace($NewDir)) { $NewDir = Join-Path $PSScriptRoot "new" }
if ([string]::IsNullOrWhiteSpace($ReportFile)) { $ReportFile = Join-Path $PSScriptRoot "certificate_verification_report.txt" }

$targets = @()
if ($Mode -eq "old" -or $Mode -eq "both") { $targets += [PSCustomObject]@{ Name="old"; Path=$OldDir } }
if ($Mode -eq "new" -or $Mode -eq "both") { $targets += [PSCustomObject]@{ Name="new"; Path=$NewDir } }

$serverCount = 0
$matchCount = 0
$mismatchCount = 0

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add((T "VerifyMatch.ReportTitle"))
$lines.Add((T "VerifyMatch.CreatedAt" @((Get-Date))))
$lines.Add((T "VerifyMatch.Separator"))
$lines.Add("")

Write-Host ""
Write-Host (T "VerifyMatch.ConsoleTitle")
Write-Host ""
Write-Host (T "VerifyMatch.Scanning" @($Mode))
Write-Host ""

foreach ($t in $targets) {
  if (-not (Test-Path -LiteralPath $t.Path -PathType Container)) {
    $lines.Add((T "VerifyMatch.FolderMissing" @($t.Path)))
    continue
  }

  # 機関（第一階層）を列挙。直下に対象ファイルがある場合は (root) も機関として扱う
  $orgDirs = @(Get-ChildItem -LiteralPath $t.Path -Directory -ErrorAction SilentlyContinue)
  $rootFiles = @(Get-ChildItem -LiteralPath $t.Path -File -Include *.cer,*.crt,*.csr,*.key -ErrorAction SilentlyContinue)
  if ($rootFiles.Count -gt 0) {
    $orgDirs = @([PSCustomObject]@{ FullName = $t.Path; Name="(root)" }) + $orgDirs
  }
  if ($orgDirs.Count -eq 0) {
    $orgDirs = @([PSCustomObject]@{ FullName = $t.Path; Name="(root)" })
  }

  foreach ($org in $orgDirs) {
    $orgPath = $org.FullName
    $orgName = $org.Name

    # 機関パスワード（任意）
    $passFilesToTry = @()
    if (-not [string]::IsNullOrWhiteSpace($PassFile)) {
      Assert-ExistsFile $PassFile "PassFile"
      $passFilesToTry += $PassFile
    }
    $passFilesToTry += (Find-PassFile $orgPath)
    $passFilesToTry += (Find-PassFile $t.Path)

    # 機関配下のサーバ（第二階層）を列挙。サブディレクトリが無い場合は機関直下を (root) サーバとして扱う
    $serverDirs = @(Get-ChildItem -LiteralPath $orgPath -Directory -ErrorAction SilentlyContinue)
    $orgHasFiles = @(Get-ChildItem -LiteralPath $orgPath -File -Include *.cer,*.crt,*.csr,*.key -ErrorAction SilentlyContinue)
    if ($serverDirs.Count -eq 0 -or $orgHasFiles.Count -gt 0) {
      $serverDirs = @([PSCustomObject]@{ FullName = $orgPath; Name="(root)" })
    }

    foreach ($d in $serverDirs) {
      $serverCount++
      $serverPath = $d.FullName
      $serverName = $d.Name

      Write-Host (T "VerifyMatch.Checking" @($serverCount, $t.Name, $orgName, $serverName))
      Write-Host ""

      $lines.Add((T "VerifyMatch.Separator"))
      $lines.Add((T "VerifyMatch.ReportHeader" @($serverCount, $t.Name, $orgName, $serverName)))
      $lines.Add((T "VerifyMatch.Separator"))
      $lines.Add("")

      $files = Find-AllSetFiles $serverPath
      $certCount = $files.Certs.Count
      $keyCount  = $files.Keys.Count
      $csrCount  = $files.Csrs.Count

      # ファイル一覧を表示（具体的なファイル名を列挙）
      $lines.Add((T "VerifyMatch.DetectedFiles"))
      if ($certCount -eq 0) {
        $lines.Add((T "VerifyMatch.DetectedCert" @((T "CheckBasic.None"))))
        Write-Host (T "VerifyMatch.ConsoleCertMissing")
      } else {
        foreach ($c in $files.Certs) {
          $lines.Add((T "VerifyMatch.DetectedCert" @([IO.Path]::GetFileName($c))))
        }
        Write-Host ("  " + (T "Label.Cert") + ": " + ($files.Certs | ForEach-Object { [IO.Path]::GetFileName($_) }) -join ", ")
      }
      if ($keyCount -eq 0) {
        $lines.Add((T "VerifyMatch.DetectedKey" @((T "CheckBasic.None"))))
        Write-Host (T "VerifyMatch.ConsoleKeyMissing")
      } else {
        foreach ($k in $files.Keys) {
          $lines.Add((T "VerifyMatch.DetectedKey" @([IO.Path]::GetFileName($k))))
        }
        Write-Host ("  " + (T "Label.Key") + ": " + ($files.Keys | ForEach-Object { [IO.Path]::GetFileName($_) }) -join ", ")
      }
      if ($csrCount -eq 0) {
        $lines.Add((T "VerifyMatch.DetectedCsr" @((T "CheckBasic.None"))))
        Write-Host (T "VerifyMatch.ConsoleCsrMissing")
      } else {
        foreach ($s in $files.Csrs) {
          $lines.Add((T "VerifyMatch.DetectedCsr" @([IO.Path]::GetFileName($s))))
        }
        Write-Host ("  " + (T "Label.Csr") + ": " + ($files.Csrs | ForEach-Object { [IO.Path]::GetFileName($_) }) -join ", ")
      }
      $lines.Add("")
      Write-Host ""

      # パスワード収集
      $passFilesLocal = @()
      $passFilesLocal += (Find-PassFile $serverPath)
      $passFilesLocal += $passFilesToTry
      $passFilesLocal += (Find-PassFile $OldDir)
      if ($orgName -ne "(root)") { $passFilesLocal += (Find-PassFile (Join-Path $OldDir $orgName)) }
      $passphrases = Collect-Passphrases $passFilesLocal

      # 全ファイルの Modulus を取得してマップ化
      $certModMap = @{}
      foreach ($c in $files.Certs) {
        $fn = [IO.Path]::GetFileName($c)
        $mod = Get-ModulusFromCert $c
        $subj = Get-SubjectFromCert $c
        $certModMap[$fn] = [PSCustomObject]@{ Path=$c; Modulus=$mod; Subject=$subj }
      }
      $keyModMap = @{}
      foreach ($k in $files.Keys) {
        $fn = [IO.Path]::GetFileName($k)
        $mod = Get-ModulusFromKey $k $passphrases
        $keyModMap[$fn] = [PSCustomObject]@{ Path=$k; Modulus=$mod }
      }
      $csrModMap = @{}
      foreach ($s in $files.Csrs) {
        $fn = [IO.Path]::GetFileName($s)
        $mod = Get-ModulusFromCsr $s
        $subj = Get-SubjectFromCsr $s
        $csrModMap[$fn] = [PSCustomObject]@{ Path=$s; Modulus=$mod; Subject=$subj }
      }

      # 詳細情報を出力
      foreach ($fn in ($certModMap.Keys | Sort-Object)) {
        $info = $certModMap[$fn]
        $lines.Add((T "VerifyMatch.Detail.CertInfo") + " " + $fn)
        $lines.Add((T "VerifyMatch.Detail.Subject"))
        $lines.Add($(if ($info.Subject) { $info.Subject } else { "" }))
        $lines.Add((T "VerifyMatch.Detail.Modulus"))
        $lines.Add(("Modulus={0}" -f $(if ($info.Modulus) { $info.Modulus } else { "" })))
        $lines.Add("")
      }
      foreach ($fn in ($keyModMap.Keys | Sort-Object)) {
        $info = $keyModMap[$fn]
        $lines.Add((T "VerifyMatch.Detail.KeyInfo") + " " + $fn)
        $lines.Add((T "VerifyMatch.Detail.Modulus"))
        $lines.Add(("Modulus={0}" -f $(if ($info.Modulus) { $info.Modulus } else { "" })))
        $lines.Add("")
      }
      foreach ($fn in ($csrModMap.Keys | Sort-Object)) {
        $info = $csrModMap[$fn]
        $lines.Add((T "VerifyMatch.Detail.CsrInfo") + " " + $fn)
        $lines.Add((T "VerifyMatch.Detail.Subject"))
        $lines.Add($(if ($info.Subject) { $info.Subject } else { "" }))
        $lines.Add((T "VerifyMatch.Detail.Modulus"))
        $lines.Add(("Modulus={0}" -f $(if ($info.Modulus) { $info.Modulus } else { "" })))
        $lines.Add("")
      }

      # 判定：交差比較（全ての組み合わせ）
      $ok = $true
      $comparisons = 0
      $lines.Add((T "VerifyMatch.Judgement"))

      if ($certCount -eq 0 -and $keyCount -eq 0 -and $csrCount -eq 0) {
        $lines.Add((T "VerifyMatch.NoFiles"))
        $ok = $false
      } else {
        # Cert <-> Key の比較（全組み合わせ）
        if ($certCount -gt 0 -and $keyCount -gt 0) {
          foreach ($certFn in ($certModMap.Keys | Sort-Object)) {
            $certInfo = $certModMap[$certFn]
            foreach ($keyFn in ($keyModMap.Keys | Sort-Object)) {
              $keyInfo = $keyModMap[$keyFn]
              $comparisons++
              if ($certInfo.Modulus -and $keyInfo.Modulus -and ($certInfo.Modulus -eq $keyInfo.Modulus)) {
                $msg = (T "VerifyMatch.MatchCertKeyDetail" @($certFn, $keyFn))
                $lines.Add($msg)
                Write-Host -ForegroundColor Green ("  [OK] {0} <-> {1}" -f $certFn, $keyFn)
              } else {
                $msg = (T "VerifyMatch.MismatchCertKeyDetail" @($certFn, $keyFn))
                $lines.Add($msg)
                Write-Host -ForegroundColor Red ("  [NG] {0} <-> {1}" -f $certFn, $keyFn)
                $ok = $false
              }
            }
          }
        }
        # Cert <-> CSR の比較（全組み合わせ）
        if ($certCount -gt 0 -and $csrCount -gt 0) {
          foreach ($certFn in ($certModMap.Keys | Sort-Object)) {
            $certInfo = $certModMap[$certFn]
            foreach ($csrFn in ($csrModMap.Keys | Sort-Object)) {
              $csrInfo = $csrModMap[$csrFn]
              $comparisons++
              if ($certInfo.Modulus -and $csrInfo.Modulus -and ($certInfo.Modulus -eq $csrInfo.Modulus)) {
                $msg = (T "VerifyMatch.MatchCertCsrDetail" @($certFn, $csrFn))
                $lines.Add($msg)
                Write-Host -ForegroundColor Green ("  [OK] {0} <-> {1}" -f $certFn, $csrFn)
              } else {
                $msg = (T "VerifyMatch.MismatchCertCsrDetail" @($certFn, $csrFn))
                $lines.Add($msg)
                Write-Host -ForegroundColor Red ("  [NG] {0} <-> {1}" -f $certFn, $csrFn)
                $ok = $false
              }
            }
          }
        }
        # Key <-> CSR の比較（全組み合わせ）
        if ($keyCount -gt 0 -and $csrCount -gt 0) {
          foreach ($keyFn in ($keyModMap.Keys | Sort-Object)) {
            $keyInfo = $keyModMap[$keyFn]
            foreach ($csrFn in ($csrModMap.Keys | Sort-Object)) {
              $csrInfo = $csrModMap[$csrFn]
              $comparisons++
              if ($keyInfo.Modulus -and $csrInfo.Modulus -and ($keyInfo.Modulus -eq $csrInfo.Modulus)) {
                $msg = (T "VerifyMatch.MatchKeyCsrDetail" @($keyFn, $csrFn))
                $lines.Add($msg)
                Write-Host -ForegroundColor Green ("  [OK] {0} <-> {1}" -f $keyFn, $csrFn)
              } else {
                $msg = (T "VerifyMatch.MismatchKeyCsrDetail" @($keyFn, $csrFn))
                $lines.Add($msg)
                Write-Host -ForegroundColor Red ("  [NG] {0} <-> {1}" -f $keyFn, $csrFn)
                $ok = $false
              }
            }
          }
        }
      }

      if ($comparisons -eq 0) {
        Write-Host (T "VerifyMatch.ConsoleInsufficient")
        $lines.Add((T "VerifyMatch.Insufficient"))
      }

      if ($ok) {
        $matchCount++
        Write-Host (T "VerifyMatch.ConsoleFinalOk")
        $lines.Add((T "VerifyMatch.FinalOk"))
      } else {
        $mismatchCount++
        Write-Host (T "VerifyMatch.ConsoleFinalNg")
        $lines.Add((T "VerifyMatch.FinalNg"))
      }

      $lines.Add("")
      Write-Host ""
    }
  }
}

$lines.Add((T "VerifyMatch.Separator"))
$lines.Add((T "VerifyMatch.SummaryTitle"))
$lines.Add((T "VerifyMatch.Separator"))
$lines.Add((T "VerifyMatch.SummaryTotal" @($serverCount)))
$lines.Add((T "VerifyMatch.SummaryOk" @($matchCount)))
$lines.Add((T "VerifyMatch.SummaryNg" @($mismatchCount)))
$lines.Add("")
$lines.Add((T "VerifyMatch.SavedTo" @($ReportFile)))

Backup-IfExists $ReportFile
Set-Content -LiteralPath $ReportFile -Value ($lines -join "`r`n") -Encoding UTF8

Write-Host (T "VerifyMatch.Separator")
Write-Host (T "VerifyMatch.SummaryTitle")
Write-Host (T "VerifyMatch.Separator")
Write-Host (T "VerifyMatch.SummaryTotal" @($serverCount))
Write-Host (T "VerifyMatch.SummaryOk" @($matchCount))
Write-Host (T "VerifyMatch.SummaryNg" @($mismatchCount))
Write-Host ""
Write-Host (T "VerifyMatch.ReportSavedTo" @($ReportFile))


