<#
.SYNOPSIS
旧証明書情報から新しい CSR と秘密鍵を生成するスクリプト

.DESCRIPTION
このスクリプトは、old\ 配下の既存証明書・CSR・秘密鍵の情報を読み取り、
同じ Subject と SAN で新しい CSR と秘密鍵のペアを new\ 配下に生成します。

主な機能:
- 旧証明書からの Subject と SAN の自動抽出
- 旧秘密鍵からの鍵長（RSA bits）の自動検出
- 多機関対応（機関ごとの処理）
- 対話式メニュー（複数機関がある場合）
- 既存ファイルの自動バックアップ（-Overwrite 時）

.PARAMETER OldDir
old ディレクトリのパス（既定: .\old）

.PARAMETER NewDir
new ディレクトリのパス（既定: .\new）

.PARAMETER OpenSsl
OpenSSL 実行ファイルのパス

.PARAMETER PassFile
パスフレーズファイル（指定すると生成する秘密鍵を AES-256 で暗号化）

.PARAMETER DefaultRsaBits
旧秘密鍵が見つからない/解析できない場合のデフォルト鍵長（既定: 2048）

.PARAMETER ShowInfo
OpenSSL とディレクトリ情報を表示して終了

.PARAMETER Overwrite
出力先（new\<CN>\server.key/server.csr）が既に存在する場合に、バックアップして再生成

.PARAMETER Org
機関ディレクトリ名（指定した場合はその機関のみ処理）

.PARAMETER All
すべての機関を処理（未指定の場合、複数機関があるとメニューで選択）

.PARAMETER NonInteractive
非対話モード（複数機関がある場合は -Org か -All が必須）

.PARAMETER Lang
出力言語（既定: ja）

.EXAMPLE
.\renew_from_old.ps1
対話式メニューで機関を選択して CSR 生成

.EXAMPLE
.\renew_from_old.ps1 -Org example.com -Overwrite
指定機関のみ処理（既存ファイルはバックアップ）

.EXAMPLE
.\renew_from_old.ps1 -All -PassFile .\passphrase.txt
すべての機関を処理（暗号化鍵で生成）

.NOTES
- 旧証明書から Subject と SAN を自動抽出します
- 旧秘密鍵から鍵長を自動検出します（暗号化鍵の場合はパスワードが必要）
- 複数機関がある場合は、対話式メニューで選択します（-Org または -All で回避可能）
- -Overwrite と複数機関の組み合わせは、安全のため "YES" の入力が必要です
- 出力先は new\<機関名>\<CN>\server.key と server.csr です
#>

param(
  [Parameter(Mandatory = $false)]
  [string]$OldDir = "",

  [Parameter(Mandatory = $false)]
  [string]$NewDir = "",

  [Parameter(Mandatory = $false)]
  [string]$OpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe",

  # （任意）パスフレーズファイルを指定した場合は、生成する秘密鍵をAES-256で暗号化します
  [Parameter(Mandatory = $false)]
  [string]$PassFile = "",

  # 旧い秘密鍵が見つからない/解析できない場合のデフォルト鍵長
  [Parameter(Mandatory = $false)]
  [int]$DefaultRsaBits = 2048

  ,
  [Parameter(Mandatory = $false)]
  [switch]$ShowInfo

  ,
  # 出力先(new\<CN>\server.key/server.csr)が既に存在する場合に、削除して再生成する
  [Parameter(Mandatory = $false)]
  [switch]$Overwrite

  ,
  # 機関ディレクトリ名（指定した場合はその機関のみ処理）
  [Parameter(Mandatory = $false)]
  [string]$Org = ""

  ,
  # すべての機関を処理（未指定の場合、複数機関があるとメニューで選択します）
  [Parameter(Mandatory = $false)]
  [switch]$All

  ,
  # 非対話モード（複数機関がある場合は -Org か -All が必須）
  [Parameter(Mandatory = $false)]
  [switch]$NonInteractive,

  # 出力言語（既定: ja）
  [Parameter(Mandatory = $false)]
  [ValidateSet("ja","zh","en")]
  [string]$Lang = "ja"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OldDir)) { $OldDir = Join-Path $PSScriptRoot "old" }
if ([string]::IsNullOrWhiteSpace($NewDir)) { $NewDir = Join-Path $PSScriptRoot "new" }

$i18nModule = Join-Path $PSScriptRoot "lib\\i18n.ps1"
if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw (T "Common.I18nModuleNotFound" @($i18nModule)) }
. $i18nModule
$__i18n = Initialize-I18n -Lang $Lang -BaseDir $PSScriptRoot
function T([string]$Key, [object[]]$FormatArgs = @()) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }

$FixedPassFileName = "passphrase.txt"

function Assert-ExistsFile([string]$path, [string]$label) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw (T "Common.FileNotFound" @($label, $path))
  }
}

function Ensure-Dir([string]$path) {
  if (-not (Test-Path -LiteralPath $path -PathType Container)) {
    New-Item -ItemType Directory -Path $path | Out-Null
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

function Run-OpenSsl([string[]]$OpenSslArgs) {
  # PowerShell 5.1 / 7.x 両対応のため、& 呼び出し + 2>&1 で取得（文字列化）
  $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    $joined = ($OpenSslArgs -join " ")
    throw (T "Common.OpenSslCmdFailed" @($joined, (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return $out
}

function Parse-SubjectToMap([string]$subjectLine) {
  # 例: subject=C=JP, ST=Hyogo, L=Kato-city, O=..., CN=example
  $s = $subjectLine.Trim()
  if ($s.StartsWith("subject=")) { $s = $s.Substring(8) }
  $map = @{}
  foreach ($part in ($s -split ",\s*")) {
    if ($part -match "^\s*([^=]+)=(.*)\s*$") {
      $k = $matches[1].Trim()
      $v = $matches[2].Trim()
      $map[$k] = $v
    }
  }
  return $map
}

function SubjectMapToSubj([hashtable]$m) {
  # 最低限 CN は必須。他の項目は旧証明書に存在するものだけ引き継ぐ。
  if (-not $m.ContainsKey("CN") -or [string]::IsNullOrWhiteSpace([string]$m["CN"])) {
    throw (T "Renew.CnMissingInSubject")
  }
  $parts = New-Object System.Collections.Generic.List[string]
  foreach ($k in @("C","ST","L","O","OU","CN")) {
    if ($m.ContainsKey($k) -and -not [string]::IsNullOrWhiteSpace([string]$m[$k])) {
      $parts.Add(("/{0}={1}" -f $k, $m[$k])) | Out-Null
    }
  }
  return ($parts -join "")
}

function Get-CertSubject([string]$certPath) {
  $out = Run-OpenSsl @("x509","-in",$certPath,"-noout","-subject")
  $line = ($out | Where-Object { $_ -match "^subject=" } | Select-Object -First 1)
  if (-not $line) { $line = ($out | Select-Object -First 1) }
  return ([string]$line).Trim()
}

function Get-CertSANs([string]$certPath) {
  $out = Run-OpenSsl @("x509","-in",$certPath,"-noout","-ext","subjectAltName")
  $dns = New-Object System.Collections.Generic.List[string]
  foreach ($line in $out) {
    if ($line -match "DNS:") {
      $parts = $line -split ","
      foreach ($p in $parts) {
        $t = $p.Trim()
        if ($t -match "DNS:(.+)$") {
          $name = $matches[1].Trim()
          if (-not [string]::IsNullOrWhiteSpace($name)) { $dns.Add($name) }
        }
      }
    }
  }
  return $dns | Select-Object -Unique
}

function Get-CsrSubject([string]$csrPath) {
  $out = Run-OpenSsl @("req","-in",$csrPath,"-noout","-subject")
  $line = ($out | Where-Object { $_ -match "^subject=" } | Select-Object -First 1)
  if (-not $line) { $line = ($out | Select-Object -First 1) }
  return ([string]$line).Trim()
}

function Get-RsaBitsFromKey([string]$keyPath) {
  try {
    # OpenSSL の対話プロンプトを避けるため、暗号化鍵はここでは解析しない（必要なら別ロジックで -passin 付きで試行する）
    $head = @(Get-Content -LiteralPath $keyPath -TotalCount 40 -ErrorAction SilentlyContinue)
    $text = ($head -join "`n")
    if ($text -match "BEGIN ENCRYPTED PRIVATE KEY" -or $text -match "Proc-Type:\s*4,ENCRYPTED" -or $text -match "\bENCRYPTED\b") {
      return $null
    }

    $out = Run-OpenSsl @("rsa","-in",$keyPath,"-noout","-text")
    foreach ($line in $out) {
      if ($line -match "\((\d+)\s+bit\)") {
        return [int]$matches[1]
      }
    }
    return $null
  } catch {
    return $null
  }
}

function Build-SanOpt([string[]]$sans) {
  if ($null -eq $sans -or $sans.Count -eq 0) { return @() }
  $value = "subjectAltName=" + (($sans | ForEach-Object { "DNS:$_" }) -join ",")
  return @("-addext", $value)
}

function Find-OldSets([string]$dir, [bool]$recurse = $true) {
  # *.cer/*.crt を基準にセットを作ります
  $certs = @()
  if ($recurse) {
    $certs = @(Get-ChildItem -LiteralPath $dir -Recurse -File -Include *.cer,*.crt -ErrorAction SilentlyContinue)
  } else {
    $certs = @(Get-ChildItem -LiteralPath $dir -File -Include *.cer,*.crt -ErrorAction SilentlyContinue)
  }
  $sets = @()
  foreach ($c in $certs) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($c.Name)
    $csr = Get-ChildItem -LiteralPath $c.Directory.FullName -File -Filter ($base + ".csr") -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $csr) {
      # フォールバック：同一ディレクトリ内の単一CSRを拾う（1つだけある場合）
      $onlyCsr = @(Get-ChildItem -LiteralPath $c.Directory.FullName -File -Filter "*.csr" -ErrorAction SilentlyContinue)
      if ($onlyCsr.Count -eq 1) { $csr = $onlyCsr[0] }
    }
    $key = Get-ChildItem -LiteralPath $c.Directory.FullName -File -Filter ($base + ".key") -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $key) {
      $onlyKey = @(Get-ChildItem -LiteralPath $c.Directory.FullName -File -Filter "*.key" -ErrorAction SilentlyContinue)
      if ($onlyKey.Count -eq 1) { $key = $onlyKey[0] }
    }
    $sets += [PSCustomObject]@{
      Cert = $c.FullName
      Csr  = if ($csr) { $csr.FullName } else { "" }
      Key  = if ($key) { $key.FullName } else { "" }
    }
  }
  return $sets
}

function Get-OrgCandidates() {
  $list = New-Object System.Collections.Generic.List[object]

  # old 直下に証明書がある場合は (root) も機関として扱う
  $rootCerts = @(Get-ChildItem -LiteralPath $OldDir -File -Include *.cer,*.crt -ErrorAction SilentlyContinue)
  if ($rootCerts.Count -gt 0) {
    $list.Add([PSCustomObject]@{ Name="(root)"; FullName=$OldDir }) | Out-Null
  }

  foreach ($d in @(Get-ChildItem -LiteralPath $OldDir -Directory -ErrorAction SilentlyContinue)) {
    $list.Add([PSCustomObject]@{ Name=$d.Name; FullName=$d.FullName }) | Out-Null
  }

  # (root) を先頭、それ以外は名前順
  $roots = @($list | Where-Object { $_.Name -eq "(root)" })
  $others = @($list | Where-Object { $_.Name -ne "(root)" } | Sort-Object Name)
  return @($roots + $others)
}

function Get-NewStatusSummary([object]$candidate) {
  $name = $candidate.Name

  # (root) の場合：old直下の証明書ファイル名(base)が new\<base>\... に展開されるため、件数で表示する
  if ($name -eq "(root)") {
    $rootCerts = @(Get-ChildItem -LiteralPath $candidate.FullName -File -Include *.cer,*.crt -ErrorAction SilentlyContinue)
    if ($rootCerts.Count -eq 0) { return (T "Renew.New.NotGenerated") }

    $done = 0
    foreach ($c in $rootCerts) {
      $base = [IO.Path]::GetFileNameWithoutExtension($c.Name)
      $dir = Join-Path $NewDir $base
      if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
      $has = @(
        @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter "server.csr" -ErrorAction SilentlyContinue),
        @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter "server.key" -ErrorAction SilentlyContinue)
      ) | ForEach-Object { $_ } | Where-Object { $_ -ne $null }
      if ($has.Count -gt 0) { $done++ }
    }
    if ($done -eq 0) { return (T "Renew.New.NotGeneratedRoot" @($rootCerts.Count)) }
    return (T "Renew.New.GeneratedRoot" @($done, $rootCerts.Count))
  }

  $newOrgDir = Join-Path $NewDir $name
  if (-not (Test-Path -LiteralPath $newOrgDir -PathType Container)) {
    return (T "Renew.New.NotGenerated")
  }

  $csrs = @(Get-ChildItem -LiteralPath $newOrgDir -Recurse -File -Filter "server.csr" -ErrorAction SilentlyContinue)
  $keys = @(Get-ChildItem -LiteralPath $newOrgDir -Recurse -File -Filter "server.key" -ErrorAction SilentlyContinue)
  if ($csrs.Count -eq 0 -and $keys.Count -eq 0) {
    return (T "Renew.New.NotGenerated")
  }

  $latestItem = @($csrs + $keys | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
  $latest = if ($latestItem.Count -gt 0) { $latestItem[0].LastWriteTime.ToString("yyyy-MM-dd HH:mm") } else { "" }

  $cnDirs = 0
  if ($csrs.Count -gt 0) {
    $cnDirs = @($csrs | ForEach-Object { $_.Directory.FullName } | Select-Object -Unique).Count
  } elseif ($keys.Count -gt 0) {
    $cnDirs = @($keys | ForEach-Object { $_.Directory.FullName } | Select-Object -Unique).Count
  }

  if ([string]::IsNullOrWhiteSpace($latest)) {
    return (T "Renew.New.GeneratedNoLatest" @($cnDirs, $csrs.Count, $keys.Count))
  }
  return (T "Renew.New.GeneratedWithLatest" @($cnDirs, $csrs.Count, $keys.Count, $latest))
}

function Prompt-SelectOrgs([object[]]$candidates) {
  Write-Host ""
  Write-Host (T "Renew.MenuTitle")
  Write-Host (T "Renew.MenuHint")
  Write-Host ""

  for ($i = 0; $i -lt $candidates.Count; $i++) {
    $name = $candidates[$i].Name
    $certCount = 0
    if ($name -eq "(root)") {
      $certCount = @(Get-ChildItem -LiteralPath $candidates[$i].FullName -File -Include *.cer,*.crt -ErrorAction SilentlyContinue).Count
    } else {
      $certCount = @(Get-ChildItem -LiteralPath $candidates[$i].FullName -Recurse -File -Include *.cer,*.crt -ErrorAction SilentlyContinue).Count
    }
    $newStatus = Get-NewStatusSummary $candidates[$i]
    Write-Host ("[{0}] {1}  (certs={2}, {3})" -f ($i + 1), $name, $certCount, $newStatus)
  }

  while ($true) {
    $raw = ""
    try {
      $raw = (Read-Host (T "Renew.MenuPrompt")).Trim()
    } catch {
      throw (T "Renew.NoInteractive")
    }
    if ([string]::IsNullOrWhiteSpace($raw)) { continue }
    if ($raw -match "^(q|quit|exit)$") { throw (T "Renew.Cancelled") }
    if ($raw -match "^(all|a)$") { return $candidates }

    $picked = New-Object System.Collections.Generic.List[object]
    $tokens = $raw -split "[,\\s]+" | Where-Object { $_ -ne "" }
    $ok = $true
    foreach ($t in $tokens) {
      if ($t -notmatch "^[0-9]+$") { $ok = $false; break }
      $idx = [int]$t
      if ($idx -lt 1 -or $idx -gt $candidates.Count) { $ok = $false; break }
      $picked.Add($candidates[$idx - 1]) | Out-Null
    }
    if (-not $ok -or $picked.Count -eq 0) {
      Write-Host (T "Renew.InvalidInput")
      continue
    }

    # 重複排除（順序維持）
    $uniq = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($p in $picked) {
      if (-not $seen.ContainsKey($p.Name)) {
        $seen[$p.Name] = $true
        $uniq.Add($p) | Out-Null
      }
    }
    return @($uniq)
  }
}

Assert-ExistsFile $OpenSsl "OpenSSL"
Ensure-Dir $NewDir

if ($ShowInfo) {
  Write-Host ("OpenSSL: {0}" -f $OpenSsl)
  Write-Host ("OldDir : {0}" -f (Resolve-Path -LiteralPath $OldDir))
  Write-Host ("NewDir : {0}" -f (Resolve-Path -LiteralPath $NewDir))
  Write-Host ("OpenSSL version: {0}" -f ((Run-OpenSsl @("version")) -join " "))
  Write-Host ""
  exit 0
}

if (-not (Test-Path -LiteralPath $OldDir -PathType Container)) {
  throw (T "Renew.OldDirMissing" @($OldDir))
}

$generated = New-Object System.Collections.Generic.List[object]

# ==========================================================
# 機関（第一階層）ごとに処理
# ==========================================================
$orgDirs = @()
if (-not [string]::IsNullOrWhiteSpace($Org)) {
  if ($Org -eq "(root)" -or $Org -eq "." -or $Org -eq "root") {
    $rootCerts = @(Get-ChildItem -LiteralPath $OldDir -File -Include *.cer,*.crt -ErrorAction SilentlyContinue)
    if ($rootCerts.Count -eq 0) { throw (T "Renew.RootNoCerts") }
    $orgDirs = @([PSCustomObject]@{ Name="(root)"; FullName=$OldDir })
  } else {
    $p = Join-Path $OldDir $Org
    if (-not (Test-Path -LiteralPath $p -PathType Container)) { throw (T "Renew.OrgFolderMissing" @($p)) }
    $orgDirs = @([PSCustomObject]@{ Name=$Org; FullName=$p })
  }
} else {
  $cands = @(Get-OrgCandidates)
  if ($cands.Count -eq 0) { throw (T "Renew.NoOrgFound" @($OldDir)) }

  if ($All) {
    $orgDirs = $cands
  } elseif ($cands.Count -eq 1) {
    $orgDirs = $cands
  } else {
    if ($NonInteractive) {
      throw (T "Renew.MultiOrgNeedSpecify")
    }
    $orgDirs = @(Prompt-SelectOrgs $cands)
  }
}

if ($Overwrite -and $orgDirs.Count -gt 1) {
  if ($NonInteractive) {
    throw (T "Renew.MultiOverwriteForbidden")
  }
  Write-Host ""
  Write-Host (T "Renew.MultiOverwriteWarn")
  $ans = (Read-Host (T "Renew.MultiOverwriteConfirmPrompt")).Trim()
  if ($ans -ne "YES") { throw (T "Renew.Cancelled") }
}

foreach ($orgDir in $orgDirs) {
  $orgName = $orgDir.Name
  $orgPath = $orgDir.FullName

  $sets = @()
  if ($orgName -eq "(root)") {
    # (root) は直下のみ（サブフォルダの機関と重複させない）
    $sets = @(Find-OldSets $orgPath $false)
  } else {
    $sets = @(Find-OldSets $orgPath $true)
  }
  if ($sets.Count -eq 0) {
    continue
  }

  foreach ($set in $sets) {
    $certPath = $set.Cert
    $certSubjectLine = Get-CertSubject $certPath
    $subjectMap = Parse-SubjectToMap $certSubjectLine

    $cn = $subjectMap["CN"]
    if ([string]::IsNullOrWhiteSpace($cn)) {
      # フォールバック：証明書の subject が取れない場合、同一セットの CSR から subject を取る
      if (-not [string]::IsNullOrWhiteSpace($set.Csr) -and (Test-Path -LiteralPath $set.Csr -PathType Leaf)) {
        $csrSubjectLine = Get-CsrSubject $set.Csr
        $subjectMap = Parse-SubjectToMap $csrSubjectLine
        $cn = $subjectMap["CN"]
      }
      if ([string]::IsNullOrWhiteSpace($cn)) {
        throw (T "Renew.CnNotFound" @($certPath, $certSubjectLine, $set.Csr))
      }
    }

    $sans = @()
    try { $sans = @(Get-CertSANs $certPath) } catch { $sans = @() }
    if ($sans.Count -eq 0) {
      # SAN が取れない場合は CN のみを入れる
      $sans = @($cn)
    }

    # セット単位のパスワードファイル（任意）
    $setPassFile = ""
    if (-not [string]::IsNullOrWhiteSpace($PassFile)) {
      Assert-ExistsFile $PassFile "PassFile"
      $setPassFile = $PassFile
    } else {
      $setPassFile = Find-PassFile ([IO.Path]::GetDirectoryName($certPath))
      if ([string]::IsNullOrWhiteSpace($setPassFile)) { $setPassFile = Find-PassFile $orgPath }
      # (root) のみ old 直下も探す（他機関への誤適用を避ける）
      if ($orgName -eq "(root)" -and [string]::IsNullOrWhiteSpace($setPassFile)) { $setPassFile = Find-PassFile $OldDir }
    }
    $setPassphrase = Get-Passphrase $setPassFile

    $rsaBits = $DefaultRsaBits
    if (-not [string]::IsNullOrWhiteSpace($set.Key)) {
      $bits = $null
      # 暗号化鍵の場合、パスワードで読める可能性がある
      if (-not [string]::IsNullOrWhiteSpace($setPassphrase)) {
        $bits = With-TempPassFile $setPassphrase {
          param($tmpPass)
          try {
            $out = Run-OpenSsl @("rsa","-in",$set.Key,"-noout","-text","-passin",("file:{0}" -f $tmpPass))
            foreach ($line in $out) { if ($line -match "\((\d+)\s+bit\)") { return [int]$matches[1] } }
            return $null
          } catch { return $null }
        }
      }
      if (-not $bits) {
        $bits = Get-RsaBitsFromKey $set.Key
      }
      if ($bits) { $rsaBits = $bits }
    }

    $subj = SubjectMapToSubj $subjectMap
    $sanOpt = Build-SanOpt $sans

    # new\<機関>\<CN>\...  (root の場合は証明書ファイル名を機関名として扱う)
    $orgOut = $orgName
    if ($orgName -eq "(root)") { $orgOut = [IO.Path]::GetFileNameWithoutExtension($certPath) }
    $newOrgDir = Join-Path $NewDir $orgOut
    Ensure-Dir $newOrgDir
    $outDir = $newOrgDir
    if ($orgOut -ne $cn) { $outDir = Join-Path $newOrgDir $cn }
    Ensure-Dir $outDir

    $outKey = Join-Path $outDir "server.key"
    $outCsr = Join-Path $outDir "server.csr"

    # 既存ファイルがある場合は上書きしない（事故防止）
    if ((Test-Path -LiteralPath $outKey -PathType Leaf) -or (Test-Path -LiteralPath $outCsr -PathType Leaf)) {
      if ($Overwrite) {
        # 事故防止：削除ではなくバックアップしてから再生成する
        $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
        if (Test-Path -LiteralPath $outKey -PathType Leaf) {
          try {
            # 拡張子は維持（*.key）し、ファイル名にタイムスタンプを入れる
            Rename-Item -Force -ErrorAction Stop -LiteralPath $outKey -NewName ("server.bak_{0}.key" -f $ts)
          } catch {
            throw (T "Renew.BackupKeyFail" @($outKey))
          }
        }
        if (Test-Path -LiteralPath $outCsr -PathType Leaf) {
          try {
            # 拡張子は維持（*.csr）し、ファイル名にタイムスタンプを入れる
            Rename-Item -Force -ErrorAction Stop -LiteralPath $outCsr -NewName ("server.bak_{0}.csr" -f $ts)
          } catch {
            throw (T "Renew.BackupCsrFail" @($outCsr))
          }
        }
      } else {
        throw (T "Renew.OutExistsNoOverwrite" @($outDir))
      }
    }

    if (-not [string]::IsNullOrWhiteSpace($setPassphrase)) {
      # OpenSSL 3.x の req は -aes256 を受け付けないため、genpkey + req で生成する
      With-TempPassFile $setPassphrase {
        param($tmpPass)
        Run-OpenSsl @(
          "genpkey",
          "-algorithm","RSA",
          "-pkeyopt",("rsa_keygen_bits:{0}" -f $rsaBits),
          "-out",$outKey,
          "-aes-256-cbc",
          "-pass",("file:{0}" -f $tmpPass)
        ) | Out-Null

        $reqArgs = @("req","-new","-sha256","-key",$outKey,"-passin",("file:{0}" -f $tmpPass),"-out",$outCsr,"-subj",$subj)
        if ($sanOpt.Count -gt 0) { $reqArgs += $sanOpt }
        Run-OpenSsl $reqArgs | Out-Null
      } | Out-Null
    } else {
      $keyArgs = @("req","-new","-newkey","rsa:$rsaBits","-sha256","-nodes","-keyout",$outKey,"-out",$outCsr,"-subj",$subj)
      if ($sanOpt.Count -gt 0) { $keyArgs += $sanOpt }
      Run-OpenSsl $keyArgs | Out-Null
    }

    $generated.Add([PSCustomObject]@{
      Org = $orgOut
      CN = $cn
      Cert = $certPath
      OutDir = $outDir
      Key = $outKey
      Csr = $outCsr
      RsaBits = $rsaBits
      SANs = ($sans -join ", ")
      PassFile = $setPassFile
    }) | Out-Null
  }
}

Write-Host ""
Write-Host (T "Renew.DoneTitle")
$generated |
  Sort-Object Org,CN |
  Select-Object `
    @{Name="機関"; Expression = { $_.Org }}, `
    @{Name="CN"; Expression = { $_.CN }}, `
    @{Name="鍵長"; Expression = { $_.RsaBits }}, `
    @{Name="SAN"; Expression = { $_.SANs }}, `
    @{Name="出力先"; Expression = { $_.OutDir }} |
  Format-Table -AutoSize


