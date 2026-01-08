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
if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw "i18n モジュールが見つかりません: $i18nModule" }
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

function Find-SetFiles([string]$dir) {
  $cert = Get-ChildItem -LiteralPath $dir -File -Include server.cer,server.crt -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $cert) { $cert = Get-ChildItem -LiteralPath $dir -File -Include *.cer,*.crt -ErrorAction SilentlyContinue | Select-Object -First 1 }
  $key  = Get-ChildItem -LiteralPath $dir -File -Include server.key -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $key)  { $key  = Get-ChildItem -LiteralPath $dir -File -Include *.key -ErrorAction SilentlyContinue | Select-Object -First 1 }
  $csr  = Get-ChildItem -LiteralPath $dir -File -Include server.csr -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $csr)  { $csr  = Get-ChildItem -LiteralPath $dir -File -Include *.csr -ErrorAction SilentlyContinue | Select-Object -First 1 }
  return [PSCustomObject]@{
    Cert = if ($cert) { $cert.FullName } else { "" }
    Key  = if ($key)  { $key.FullName } else { "" }
    Csr  = if ($csr)  { $csr.FullName } else { "" }
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

      $files = Find-SetFiles $serverPath
    $certFound = -not [string]::IsNullOrWhiteSpace($files.Cert)
    $keyFound  = -not [string]::IsNullOrWhiteSpace($files.Key)
    $csrFound  = -not [string]::IsNullOrWhiteSpace($files.Csr)

    $certPathLabel = if ($certFound) { $files.Cert } else { (T "CheckBasic.None") }
      $keyPathLabel  = if ($keyFound)  { $files.Key  } else { (T "CheckBasic.None") }
      $csrPathLabel  = if ($csrFound)  { $files.Csr  } else { (T "CheckBasic.None") }

    $lines.Add((T "VerifyMatch.DetectedFiles"))
    $lines.Add((T "VerifyMatch.DetectedCert" @($certPathLabel)))
    $lines.Add((T "VerifyMatch.DetectedKey" @($keyPathLabel)))
    $lines.Add((T "VerifyMatch.DetectedCsr" @($csrPathLabel)))
    $lines.Add("")

    if (-not $certFound) { Write-Host (T "VerifyMatch.ConsoleCertMissing") } else { Write-Host (T "VerifyMatch.ConsoleCertFound") }
    if (-not $keyFound)  { Write-Host (T "VerifyMatch.ConsoleKeyMissing") } else { Write-Host (T "VerifyMatch.ConsoleKeyFound") }
    if (-not $csrFound)  { Write-Host (T "VerifyMatch.ConsoleCsrMissing") } else { Write-Host (T "VerifyMatch.ConsoleCsrFound") }
    Write-Host ""

    $certMod = if ($certFound) { Get-ModulusFromCert $files.Cert } else { $null }
    $passFilesLocal = @()
    $passFilesLocal += (Find-PassFile $serverPath)
    $passFilesLocal += $passFilesToTry
    # new の暗号化鍵は old 側のパスワードファイルが必要なケースがあるため old 直下/同名機関も候補に入れる
    $passFilesLocal += (Find-PassFile $OldDir)
    if ($orgName -ne "(root)") { $passFilesLocal += (Find-PassFile (Join-Path $OldDir $orgName)) }
    $passphrases = Collect-Passphrases $passFilesLocal

    $keyMod  = if ($keyFound)  { Get-ModulusFromKey  $files.Key  $passphrases } else { $null }
    $csrMod  = if ($csrFound)  { Get-ModulusFromCsr  $files.Csr  } else { $null }

    if ($certFound) {
      $certSubject = Get-SubjectFromCert $files.Cert
      $certSubjectLine = ""
      if ($null -ne $certSubject) { $certSubjectLine = $certSubject }
      $certModLine = ""
      if ($null -ne $certMod) { $certModLine = $certMod }
      $lines.Add("--- 証明書情報 ---")
      $lines.Add("Subject:")
      $lines.Add($certSubjectLine)
      $lines.Add("Modulus:")
      $lines.Add(("Modulus={0}" -f $certModLine))
      $lines.Add("")
    }

    if ($keyFound) {
      $keyModLine = ""
      if ($null -ne $keyMod) { $keyModLine = $keyMod }
      $lines.Add("--- 秘密鍵情報 ---")
      $lines.Add("Modulus:")
      $lines.Add(("Modulus={0}" -f $keyModLine))
      $lines.Add("")
    }

    if ($csrFound) {
      $csrSubject = Get-SubjectFromCsr $files.Csr
      $csrSubjectLine = ""
      if ($null -ne $csrSubject) { $csrSubjectLine = $csrSubject }
      $csrModLine = ""
      if ($null -ne $csrMod) { $csrModLine = $csrMod }
      $lines.Add("--- CSR 情報 ---")
      $lines.Add("Subject:")
      $lines.Add($csrSubjectLine)
      $lines.Add("Modulus:")
      $lines.Add(("Modulus={0}" -f $csrModLine))
      $lines.Add("")
    }

    $ok = $true
    $comparisons = 0
    $lines.Add((T "VerifyMatch.Judgement"))

    if (-not $certFound -and -not $keyFound -and -not $csrFound) {
      $lines.Add((T "VerifyMatch.NoFiles"))
      $ok = $false
    } else {
      if ($certFound -and $keyFound) {
        $comparisons++
        if ($certMod -and $keyMod -and ($certMod -eq $keyMod)) {
          $lines.Add((T "VerifyMatch.MatchCertKey"))
          Write-Host (T "VerifyMatch.ConsoleMatchCertKey")
        } else {
          $lines.Add((T "VerifyMatch.MismatchCertKey"))
          Write-Host (T "VerifyMatch.ConsoleMismatchCertKey")
          $ok = $false
        }
      }
      if ($certFound -and $csrFound) {
        $comparisons++
        if ($certMod -and $csrMod -and ($certMod -eq $csrMod)) {
          $lines.Add((T "VerifyMatch.MatchCertCsr"))
          Write-Host (T "VerifyMatch.ConsoleMatchCertCsr")
        } else {
          $lines.Add((T "VerifyMatch.MismatchCertCsr"))
          Write-Host (T "VerifyMatch.ConsoleMismatchCertCsr")
          $ok = $false
        }
      }
      if ($keyFound -and $csrFound) {
        $comparisons++
        if ($keyMod -and $csrMod -and ($keyMod -eq $csrMod)) {
          $lines.Add((T "VerifyMatch.MatchKeyCsr"))
          Write-Host (T "VerifyMatch.ConsoleMatchKeyCsr")
        } else {
          $lines.Add((T "VerifyMatch.MismatchKeyCsr"))
          Write-Host (T "VerifyMatch.ConsoleMismatchKeyCsr")
          $ok = $false
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


