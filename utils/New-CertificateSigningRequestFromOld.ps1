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
出力先（new\<CN>\<base>.key/<base>.csr）が既に存在する場合に、バックアップして再生成

.PARAMETER Org
機関ディレクトリ名（指定した場合はその機関のみ処理）

.PARAMETER All
すべての機関を処理（未指定の場合、複数機関があるとメニューで選択）

.PARAMETER NonInteractive
非対話モード（複数機関がある場合は -Org か -All が必須）

.PARAMETER Lang
出力言語（既定: ja）

.EXAMPLE
.\New-CertificateSigningRequestFromOld.ps1
対話式メニューで機関を選択して CSR 生成

.EXAMPLE
.\New-CertificateSigningRequestFromOld.ps1 -Org example.com -Overwrite
指定機関のみ処理（既存ファイルはバックアップ）

.EXAMPLE
.\New-CertificateSigningRequestFromOld.ps1 -All -PassFile .\passphrase.txt
すべての機関を処理（暗号化鍵で生成）

.NOTES
- 旧証明書から Subject と SAN を自動抽出します
- 旧秘密鍵から鍵長を自動検出します（暗号化鍵の場合はパスワードが必要）
- 複数機関がある場合は、対話式メニューで選択します（-Org または -All で回避可能）
- -Overwrite と複数機関の組み合わせは、安全のため "YES" の入力が必要です
- 出力先は new\<機関名>\<CN>\<base>.key と <base>.csr です
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
  # 出力先(new\<CN>\<base>.key/<base>.csr)が既に存在する場合に、削除して再生成する
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
  [ValidateSet("ja", "zh", "en")]
  [string]$Lang = "ja"
)


$ToolkitRoot = Split-Path -Parent $PSScriptRoot

$pathsModule = Join-Path $PSScriptRoot "lib\paths.ps1"
if (Test-Path -LiteralPath $pathsModule -PathType Leaf) { . $pathsModule }
$ToolkitPaths = if (Get-Command Get-ToolkitPaths -ErrorAction SilentlyContinue) { Get-ToolkitPaths -BaseDir $ToolkitRoot } else { $null }
if ([string]::IsNullOrWhiteSpace($OldDir)) {
  if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.Old)) { $OldDir = $ToolkitPaths.Old }
  else { $OldDir = Join-Path $ToolkitRoot "old" }
}
if ([string]::IsNullOrWhiteSpace($NewDir)) {
  if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.New)) { $NewDir = $ToolkitPaths.New }
  else { $NewDir = Join-Path $ToolkitRoot "new" }
}

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

$FixedPassFileName = "passphrase.txt"


function Assert-ExistsFile([string]$path, [string]$label) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw (T "Common.FileNotFound" @($label, $path))
  }
}

function New-DirectoryIfMissing([string]$path) {
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

function Find-PassFile([string]$dir) {
  # 誤検出防止のため、パスワードファイル名は固定（推奨: passphrase.txt）
  $fixed = Join-Path $dir $FixedPassFileName
  if (Test-Path -LiteralPath $fixed -PathType Leaf) { return $fixed }
  return ""
}

function Invoke-OpenSsl([string[]]$OpenSslArgs) {
  # PowerShell 5.1 / 7.x 両対応のため、& 呼び出し + 2>&1 で取得（文字列化）
  $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    $joined = ($OpenSslArgs -join " ")
    throw (T "Common.OpenSslCmdFailed" @($joined, (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return $out
}

function ConvertFrom-SubjectToMap([string]$subjectLine) {
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
  foreach ($k in @("C", "ST", "L", "O", "OU", "CN")) {
    if ($m.ContainsKey($k) -and -not [string]::IsNullOrWhiteSpace([string]$m[$k])) {
      $parts.Add(("/{0}={1}" -f $k, $m[$k])) | Out-Null
    }
  }
  return ($parts -join "")
}

function Get-CertSubject([string]$certPath) {
  $out = Invoke-OpenSsl @("x509", "-in", $certPath, "-noout", "-subject")
  $line = ($out | Where-Object { $_ -match "^subject=" } | Select-Object -First 1)
  if (-not $line) { $line = ($out | Select-Object -First 1) }
  return ([string]$line).Trim()
}

function Get-CertSANs([string]$certPath) {
  $out = @()
  try {
    $out = @(Invoke-OpenSsl @("x509", "-in", $certPath, "-noout", "-ext", "subjectAltName"))
  }
  catch {
    $out = @()
  }
  if ($out.Count -eq 0) {
    try {
      $out = @(Invoke-OpenSsl @("x509", "-in", $certPath, "-noout", "-text"))
    }
    catch {
      return @()
    }
  }

  $items = New-Object System.Collections.Generic.List[string]
  foreach ($line in $out) {
    foreach ($m in [regex]::Matches([string]$line, "(DNS|IP Address|IP):\s*([^,]+)")) {
      $t = $m.Groups[1].Value
      $v = $m.Groups[2].Value.Trim()
      if ([string]::IsNullOrWhiteSpace($v)) { continue }
      if ($t -eq "IP Address") { $t = "IP" }
      $items.Add(("{0}:{1}" -f $t, $v)) | Out-Null
    }
  }
  return @($items | Select-Object -Unique)
}

function Get-CsrSubject([string]$csrPath) {
  $out = Invoke-OpenSsl @("req", "-in", $csrPath, "-noout", "-subject")
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

    $out = Invoke-OpenSsl @("rsa", "-in", $keyPath, "-noout", "-text")
    foreach ($line in $out) {
      if ($line -match "\((\d+)\s+bit\)") {
        return [int]$matches[1]
      }
    }
    return $null
  }
  catch {
    return $null
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

function Read-AdjustSans([string]$cn, [string[]]$current) {
  $currentText = if ($null -eq $current -or $current.Count -eq 0) { (T "CheckBasic.None") } else { ($current -join ", ") }
  
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
      (T "Renew.SanMenuOptionKeep"),
      (T "Renew.SanMenuOptionCn"),
      (T "Renew.SanMenuOptionAppend"),
      (T "Renew.SanMenuOptionReplace"),
      ("[ {0} ]" -f (T "Common.MenuCancel"))
    )
    $title = (T "Renew.SanMenuTitle") + "`n" + (T "Renew.SanMenuCurrent" @($currentText))
    $choice = Show-MenuSelect -title $title -items $items
    if ($null -eq $choice -or $choice -eq $items.Count) { 
      # キャンセル または ESC = 機関選択に戻る
      return @("__SKIP__")
    }
    
    switch ($choice) {
      1 { return $current }  # 現在の SAN を使用
      2 { return @("DNS:$cn") }  # CN のみ
      3 {
        $raw = (Read-Host (T "Renew.SanInputAppend")).Trim()
        $list = ConvertFrom-SanInput $raw
        return @($current) + $list
      }
      4 {
        $raw = (Read-Host (T "Renew.SanInputReplace")).Trim()
        $list = ConvertFrom-SanInput $raw
        if ($list.Count -eq 0) { return $current }
        return $list
      }
      default { return $current }
    }
  }
  else {
    # フォールバック: 従来の数字入力方式
    Write-Host ""
    Write-Host (T "Renew.SanMenuTitle")
    Write-Host (T "Renew.SanMenuCurrent" @($currentText))
    Write-Host (T "Renew.SanMenuOptionKeep")
    Write-Host (T "Renew.SanMenuOptionCn")
    Write-Host (T "Renew.SanMenuOptionAppend")
    Write-Host (T "Renew.SanMenuOptionReplace")
    $choice = ""
    try {
      $choice = (Read-Host (T "Renew.SanMenuPrompt")).Trim()
    }
    catch {
      return $current
    }
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }

    switch ($choice) {
      "2" { return @("DNS:$cn") }
      "3" {
        $raw = (Read-Host (T "Renew.SanInputAppend")).Trim()
        $list = ConvertFrom-SanInput $raw
        return @($current) + $list
      }
      "4" {
        $raw = (Read-Host (T "Renew.SanInputReplace")).Trim()
        $list = ConvertFrom-SanInput $raw
        if ($list.Count -eq 0) { return $current }
        return $list
      }
      default { return $current }
    }
  }
}

function Find-OldSets([string]$dir, [bool]$recurse = $true) {
  # *.cer/*.crt を基準にセットを作ります
  $certs = @()
  if ($recurse) {
    $certs = @(Get-ChildItem -LiteralPath $dir -Recurse -File | Where-Object { $_.Extension -match "^\.(cer|crt|pem)$" })
  }
  if ($recurse) {
    $certs = @(Get-ChildItem -LiteralPath $dir -Recurse -File | Where-Object { $_.Extension -match "^\.(cer|crt|pem)$" })
  }
  else {
    $certs = @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Extension -match "^\.(cer|crt|pem)$" })
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
  return @($sets)
}

function Get-OrgCandidates() {
  $list = New-Object System.Collections.Generic.List[object]

  # old 直下に証明書がある場合は (root) も機関として扱う
  $rootCerts = @(Get-ChildItem -LiteralPath $OldDir -File -Include *.cer, *.crt -ErrorAction SilentlyContinue)
  if ($rootCerts.Count -gt 0) {
    $list.Add([PSCustomObject]@{ Name = "(root)"; FullName = $OldDir }) | Out-Null
  }

  foreach ($d in @(Get-ChildItem -LiteralPath $OldDir -Directory -ErrorAction SilentlyContinue)) {
    $list.Add([PSCustomObject]@{ Name = $d.Name; FullName = $d.FullName }) | Out-Null
  }

  # (root) を先頭、それ以外は名前順
  $roots = @($list | Where-Object { $_.Name -eq "(root)" })
  $others = @($list | Where-Object { $_.Name -ne "(root)" } | Sort-Object Name)
  return @($roots + $others)
}

function Get-NotAfterFromCert([string]$certPath) {
  try {
    # Invoke-OpenSsl は既に定義済み
    $out = @(Invoke-OpenSsl @("x509", "-in", $certPath, "-noout", "-dates"))
    $line = @($out | Where-Object { $_ -match "^notAfter=" } | Select-Object -First 1)
    if ($line.Count -eq 0 -or [string]::IsNullOrWhiteSpace($line[0])) { return $null }
    $dateStr = ([string]$line[0]).Trim().Replace("notAfter=", "")
    
    # OpenSSL の日付形式 (MMM  d HH:mm:ss yyyy 'GMT') は日にちが 1 桁のときスペースが 2 つになるため正規化
    $normalizedDate = $dateStr -replace "\s+", " "
    
    # 形式: "Feb 9 13:51:42 2026 GMT"
    return [DateTime]::ParseExact($normalizedDate, "MMM d HH:mm:ss yyyy 'GMT'", [System.Globalization.CultureInfo]::InvariantCulture)
  }
  catch {
    return $null
  }
}

# ==========================================================
# TSV Helper Functions
# ==========================================================
$script:sessionTsvOverwrite = @{}  # Tracks if we have already handled overwrite/backup for a file path in this session

function ConvertFrom-LegacyTsv([string]$tsvPath) {
  # 戻り値: cn -> UPKI形式の13フィールド全てを含むハッシュ
  # UPKI TSV format (13 Tab-separated fields):
  # [0]=Subject, [1]=SAN数, [2]=空, [3]=SystemID, [4]=空, [5]=空
  # [6]=CSR(Base64), [7]=部門, [8]=機関名, [9]=Contact, [10]=CN, [11]=Software, [12]=SAN
  $index = @{}
  try {
    if (-not (Test-Path -LiteralPath $tsvPath -PathType Leaf)) { return $index }
    # Shift-JIS（コードページ932）で読み込み（日本Windowsファイル対応）
    $sjis = [System.Text.Encoding]::GetEncoding(932)
    $content = [System.IO.File]::ReadAllText($tsvPath, $sjis)
    $parts = $content -split "`t"
    
    # Validate UPKI format (13 fields)
    if ($parts.Count -ge 12) {
      $cn = $parts[10].Trim()
      if ($cn) {
        $index[$cn] = @{
          "Subject"  = $parts[0].Trim()
          "SanCount" = $parts[1].Trim()
          "Empty2"   = $parts[2].Trim()
          "SystemID" = $parts[3].Trim()
          "Empty4"   = $parts[4].Trim()
          "Empty5"   = $parts[5].Trim()
          "CSR"      = if ($parts.Count -gt 6) { $parts[6].Trim() } else { "" }
          "Dept"     = if ($parts.Count -gt 7) { $parts[7].Trim() } else { "" }
          "OrgName"  = if ($parts.Count -gt 8) { $parts[8].Trim() } else { "" }
          "Contact"  = if ($parts.Count -gt 9) { $parts[9].Trim() } else { "" }
          "CN"       = $cn
          "Software" = if ($parts.Count -gt 11) { $parts[11].Trim() } else { "" }
          "SAN"      = if ($parts.Count -gt 12) { $parts[12].Trim() } else { "" }
        }
      }
    }
  }
  catch {}
  return $index
}

function Confirm-TsvData([string]$cn, [hashtable]$legacyData) {
  if ($NonInteractive) { return $legacyData } # Return as-is in non-interactive
    
  Write-Host ""
  Write-Host (T "Renew.TsvConfirmTitle" @($cn)) -ForegroundColor Cyan
    
  # 旧データから全フィールドをコピー、編集可能フィールドのみ確認
  $result = $legacyData.Clone()

  # 入力プロンプトヘルパー
  $ask = { param($label, $current) 
    $p = Read-Host ("  {0} [{1}]" -f $label, $current)
    if ([string]::IsNullOrWhiteSpace($p)) { return $current }
    return $p.Trim()
  }

  # 編集可能フィールド
  $result["Dept"] = & $ask (T "Renew.TsvLabelDept") $result["Dept"]
  $result["OrgName"] = & $ask (T "Renew.TsvLabelOrgName") $result["OrgName"]
  $result["Contact"] = & $ask (T "Renew.TsvLabelContact") $result["Contact"]
  $result["Software"] = & $ask (T "Renew.TsvLabelSoftware") $result["Software"]
    
  return $result
}

function Read-TsvGeneration([string]$cn) {
  if ($NonInteractive) { return $true }

  $useMenu = $false
  try {
    if (Get-Command Show-MenuSelect -ErrorAction SilentlyContinue) {
      $null = $host.UI.RawUI
      $useMenu = $true
    }
  }
  catch { }

  if ($useMenu) {
    $items = @(
      (T "Renew.TsvGenerateYes"),
      (T "Renew.TsvGenerateNo"),
      ("[ {0} ]" -f (T "Common.MenuBack"))
    )
    $choice = Show-MenuSelect -title (T "Renew.TsvGenerateTitle" @($cn)) -items $items -helpText (T "CheckBasic.Menu.Instruction")
    if ($null -eq $choice -or $choice -eq $items.Count) { return $false }
    return ($choice -eq 1)
  }

  $ans = (Read-Host (T "Renew.TsvGeneratePrompt" @($cn))).Trim()
  if ([string]::IsNullOrWhiteSpace($ans)) { return $false } # default = No
  return ($ans -match "^[yY]")
}

function Export-TsvRow([string]$outPath, [string]$tsvLine) {
  # Safety Check (Once per session per file)
  if (Test-Path -LiteralPath $outPath) {
    if (-not $script:sessionTsvOverwrite.ContainsKey($outPath)) {
      if ($Overwrite) {
        # Auto Backup
        $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $bakName = "{0}.bak_{1}{2}" -f [IO.Path]::GetFileNameWithoutExtension($outPath), $ts, [IO.Path]::GetExtension($outPath)
        Rename-Item -LiteralPath $outPath -NewName $bakName -Force
        Write-Host (T "Renew.TsvBackedUp" @($bakName)) -ForegroundColor Gray
      }
      elseif (-not $NonInteractive) {
        Write-Host (T "Renew.TsvExistsWarn" @($outPath)) -ForegroundColor Yellow
        $ans = (Read-Host (T "Renew.TsvOverwritePrompt")).Trim()
        if ($ans -match "^[yY]") {
          # Backup
          $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
          $bakName = "{0}.bak_{1}{2}" -f [IO.Path]::GetFileNameWithoutExtension($outPath), $ts, [IO.Path]::GetExtension($outPath)
          Rename-Item -LiteralPath $outPath -NewName $bakName -Force
          Write-Host (T "Renew.TsvBackedUp" @($bakName)) -ForegroundColor Gray
        }
        else {
          Write-Host (T "Renew.TsvSkipped") -ForegroundColor Yellow
          return # Skip writing
        }
      }
      $script:sessionTsvOverwrite[$outPath] = $true
    }
  }
  else {
    $script:sessionTsvOverwrite[$outPath] = $true # Mark as 'owned' by session if we created it
  }

  # Ensure output directory exists
  $outDir = [IO.Path]::GetDirectoryName($outPath)
  if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
  }

  # UPKI互換性のためShift-JIS（コードページ932）で書き込み
  $sjis = [System.Text.Encoding]::GetEncoding(932)
  [System.IO.File]::WriteAllText($outPath, $tsvLine, $sjis)
  Write-Host (T "Renew.TsvAppended") -ForegroundColor Green
}


function Get-NextExpiryDate([object]$candidate) {
  $isRoot = ($candidate.Name -eq "(root)")
  $certs = @(if ($isRoot) {
      @(Get-ChildItem -LiteralPath $candidate.FullName -File -Include *.cer, *.crt, *.pem -ErrorAction SilentlyContinue)
    }
    else {
      @(Get-ChildItem -LiteralPath $candidate.FullName -Recurse -File -Include *.cer, *.crt, *.pem -ErrorAction SilentlyContinue)
    })
  if ($certs.Count -eq 0) { return $null }

  $dates = New-Object System.Collections.Generic.List[DateTime]
  foreach ($c in $certs) {
    if ($c.Name -match "nii-combined") { continue } # 結合済みは重複するので除外（任意）
    $d = Get-NotAfterFromCert $c.FullName
    if ($null -ne $d) { $dates.Add($d) }
  }

  if ($dates.Count -eq 0) { return $null }
  $sorted = @($dates | Sort-Object)
  return $sorted[0]
}

function Get-NewStatusSummary([object]$candidate) {
  $name = $candidate.Name

  # (root) の場合
  if ($name -eq "(root)") {
    $rootCerts = @(Get-ChildItem -LiteralPath $candidate.FullName -File -Include *.cer, *.crt -ErrorAction SilentlyContinue)
    if ($rootCerts.Count -eq 0) { return (T "Renew.New.NotGenerated") }

    $done = 0
    foreach ($c in $rootCerts) {
      $base = [IO.Path]::GetFileNameWithoutExtension($c.Name)
      $dir = Join-Path $NewDir $base
      if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
      $has = @(
        @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter "*.csr" -ErrorAction SilentlyContinue) +
        @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter "*.key" -ErrorAction SilentlyContinue) |
        Where-Object { $_ -ne $null }
      )
      if ($has.Count -gt 0) { $done++ }
    }
    if ($done -eq 0) { return (T "Renew.New.NotGeneratedRoot" @($rootCerts.Count)) }
    return (T "Renew.New.GeneratedRoot" @($done, $rootCerts.Count))
  }

  $newOrgDir = Join-Path $NewDir $name
  if (-not (Test-Path -LiteralPath $newOrgDir -PathType Container)) {
    return (T "Renew.New.NotGenerated")
  }

  $csrs = @(Get-ChildItem -LiteralPath $newOrgDir -Recurse -File -Filter "*.csr" -ErrorAction SilentlyContinue)
  $keys = @(Get-ChildItem -LiteralPath $newOrgDir -Recurse -File -Filter "*.key" -ErrorAction SilentlyContinue)
  if ($csrs.Count -eq 0 -and $keys.Count -eq 0) {
    return (T "Renew.New.NotGenerated")
  }

  $latestItem = @(
    $($csrs + $keys) | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  )
  $latest = if ($latestItem.Count -gt 0 -and $null -ne $latestItem[0]) { $latestItem[0].LastWriteTime.ToString("yyyy-MM-dd HH:mm") } else { "" }

  $cnDirs = 0
  if ($csrs.Count -gt 0) {
    $cnDirs = @($csrs | ForEach-Object { $_.Directory.FullName } | Select-Object -Unique).Count
  }
  elseif ($keys.Count -gt 0) {
    $cnDirs = @($keys | ForEach-Object { $_.Directory.FullName } | Select-Object -Unique).Count
  }

  if ([string]::IsNullOrWhiteSpace($latest)) {
    return (T "Renew.New.GeneratedNoLatest" @($cnDirs, $csrs.Count, $keys.Count))
  }
  return (T "Renew.New.GeneratedWithLatest" @($cnDirs, $csrs.Count, $keys.Count, $latest))
}

function Read-SelectOrgs([object[]]$candidates) {
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
    $items = @()
    $candidateList = @($candidates)
    for ($i = 0; $i -lt $candidateList.Count; $i++) {
      $cand = $candidateList[$i]
      $name = $cand.Name
      $certCount = 0
      if ($name -eq "(root)") {
        $certCount = @(Get-ChildItem -LiteralPath $cand.FullName -File -Include *.cer, *.crt -ErrorAction SilentlyContinue).Count
      }
      else {
        $certCount = @(Get-ChildItem -LiteralPath $cand.FullName -Recurse -File -Include *.cer, *.crt, *.pem -ErrorAction SilentlyContinue).Count
      }
      
      # 原始証明書の最早有効期限を取得
      $expiry = Get-NextExpiryDate $cand
      $expiryStr = if ($null -ne $expiry) { $expiry.ToString("yyyy-MM-dd") } else { "N/A" }
      
      $newStatus = Get-NewStatusSummary $cand
      
      # 改行を含むマルチライン形式を構築
      $itemText = "{0}`n(certs={1}, expires={2}, {3})" -f $name, $certCount, $expiryStr, $newStatus
      $items += $itemText
    }
    $items += ("[ {0} ]" -f (T "Common.MenuAll"))
    $items += ("[ {0} ]" -f (T "Common.MenuQuit"))
    
    $title = (T "Renew.MenuTitle") + "`n" + (T "Renew.MenuHint")
    # 1行目のみ反転表示されるようになったメニューを呼び出し
    $choice = Show-MenuSelect -title $title -items $items
    if ($null -eq $choice -or $choice -eq $items.Count) { 
      # "終了" を選択した場合 または ESC
      return $null
    }
    if ($choice -eq ($items.Count - 1)) { return $candidates }  # All
    
    return @($candidates[$choice - 1])
  }
  else {
    # フォールバック: 従来の数字入力方式
    Write-Host ""
    Write-Host (T "Renew.MenuTitle")
    Write-Host (T "Renew.MenuHint")
    Write-Host ""

    $candidateList = @($candidates)
    for ($i = 0; $i -lt $candidateList.Count; $i++) {
      $name = $candidateList[$i].Name
      $certCount = 0
      if ($name -eq "(root)") {
        $certCount = @(Get-ChildItem -LiteralPath $candidateList[$i].FullName -File -Include *.cer, *.crt -ErrorAction SilentlyContinue).Count
      }
      else {
        $certCount = @(Get-ChildItem -LiteralPath $candidateList[$i].FullName -Recurse -File -Include *.cer, *.crt -ErrorAction SilentlyContinue).Count
      }
      $newStatus = Get-NewStatusSummary $candidates[$i]
      Write-Host ("[{0}] {1}  (certs={2}, {3})" -f ($i + 1), $name, $certCount, $newStatus)
    }

    while ($true) {
      $raw = ""
      try {
        $raw = (Read-Host (T "Renew.MenuPrompt")).Trim()
      }
      catch {
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
      return $uniq.ToArray()
    }
  }
}

Assert-ExistsFile $OpenSsl "OpenSSL"
New-DirectoryIfMissing $NewDir

if ($ShowInfo) {
  Write-Host (T "Renew.ShowInfo.OpenSsl" @($OpenSsl))
  Write-Host (T "Renew.ShowInfo.OldDir" @((Resolve-Path -LiteralPath $OldDir)))
  Write-Host (T "Renew.ShowInfo.NewDir" @((Resolve-Path -LiteralPath $NewDir)))
  Write-Host (T "Renew.ShowInfo.Version" @(((Invoke-OpenSsl @("version")) -join " ")))
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
$interactive = $false
$validCands = $null

if (-not [string]::IsNullOrWhiteSpace($Org)) {
  if ($Org -eq "(root)" -or $Org -eq "." -or $Org -eq "root") {
    $rootCerts = @(Get-ChildItem -LiteralPath $OldDir -File -Include *.cer, *.crt -ErrorAction SilentlyContinue)
    if ($rootCerts.Count -eq 0) { throw (T "Renew.RootNoCerts") }
    $orgDirs = @([PSCustomObject]@{ Name = "(root)"; FullName = $OldDir })
  }
  else {
    $p = Join-Path $OldDir $Org
    if (-not (Test-Path -LiteralPath $p -PathType Container)) { throw (T "Renew.OrgFolderMissing" @($p)) }
    $orgDirs = @([PSCustomObject]@{ Name = $Org; FullName = $p })
  }
}
else {
  $validCands = @(Get-OrgCandidates)
  if ($validCands.Count -eq 0) { throw (T "Renew.NoOrgFound" @($OldDir)) }
  
  if ($All) {
    $orgDirs = $validCands
  }
  elseif ($validCands.Count -eq 1) {
    $orgDirs = $validCands
  }
  else {
    if ($NonInteractive) {
      throw (T "Renew.MultiOrgNeedSpecify")
    }
    $interactive = $true
  }
}

$script:returnToOrgMenu = $true
while ($script:returnToOrgMenu) {
  $script:returnToOrgMenu = $false
  
  if ($interactive) {
    $orgDirs = @(Read-SelectOrgs $validCands)
    if ($null -eq $orgDirs[0]) { exit 99 }
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
    }
    else {
      $sets = @(Find-OldSets $orgPath $true)
      if ($sets.Count -eq 0) { continue }
    }
    if ($sets.Count -eq 0) {
      continue
    }

    foreach ($set in $sets) {
      $certPath = $set.Cert
      $certSubjectLine = Get-CertSubject $certPath
      $subjectMap = ConvertFrom-SubjectToMap $certSubjectLine

      $cn = $subjectMap["CN"]
      if ([string]::IsNullOrWhiteSpace($cn)) {
        # フォールバック：証明書の subject が取れない場合、同一セットの CSR から subject を取る
        if (-not [string]::IsNullOrWhiteSpace($set.Csr) -and (Test-Path -LiteralPath $set.Csr -PathType Leaf)) {
          $csrSubjectLine = Get-CsrSubject $set.Csr
          $subjectMap = ConvertFrom-SubjectToMap $csrSubjectLine
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
        $sans = @("DNS:$cn")
      }
      if (-not $NonInteractive) {
        $sans = @(Read-AdjustSans $cn $sans)
        if ($sans.Count -eq 1 -and $sans[0] -eq "__SKIP__") {
          # ユーザーがキャンセル = 機関選択メニューに戻る
          $script:returnToOrgMenu = $true
          if ($orgDirs.Count -eq 1 -and $sets.Count -eq 1) { exit 99 }
          break  # foreach $set を抜ける
        }
      }

      # セット単位のパスワードファイル（任意）
      $setPassFile = ""
      if (-not [string]::IsNullOrWhiteSpace($PassFile)) {
        Assert-ExistsFile $PassFile "PassFile"
        $setPassFile = $PassFile
      }
      else {
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
          $bits = Invoke-TempPassFile $setPassphrase {
            param($tmpPass)
            try {
              $out = Invoke-OpenSsl @("rsa", "-in", $set.Key, "-noout", "-text", "-passin", ("file:{0}" -f $tmpPass))
              foreach ($line in $out) { if ($line -match "\((\d+)\s+bit\)") { return [int]$matches[1] } }
              return $null
            }
            catch { return $null }
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
      New-DirectoryIfMissing $newOrgDir
      $outDir = $newOrgDir
      if ($orgOut -ne $cn) { $outDir = Join-Path $newOrgDir $cn }
      New-DirectoryIfMissing $outDir

      $base = [IO.Path]::GetFileNameWithoutExtension($certPath)
      $outKey = Join-Path $outDir ("{0}.key" -f $base)
      $outCsr = Join-Path $outDir ("{0}.csr" -f $base)

      # 既存ファイルがある場合は上書きしない（事故防止）
      if ((Test-Path -LiteralPath $outKey -PathType Leaf) -or (Test-Path -LiteralPath $outCsr -PathType Leaf)) {
        if ($Overwrite) {
          # 事故防止：削除ではなくバックアップしてから再生成する
          $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
          if (Test-Path -LiteralPath $outKey -PathType Leaf) {
            try {
              # 拡張子は維持（*.key）し、ファイル名にタイムスタンプを入れる
              Rename-Item -Force -ErrorAction Stop -LiteralPath $outKey -NewName ("{0}.bak_{1}.key" -f $base, $ts)
            }
            catch {
              throw (T "Renew.BackupKeyFail" @($outKey))
            }
          }
          if (Test-Path -LiteralPath $outCsr -PathType Leaf) {
            try {
              # 拡張子は維持（*.csr）し、ファイル名にタイムスタンプを入れる
              Rename-Item -Force -ErrorAction Stop -LiteralPath $outCsr -NewName ("{0}.bak_{1}.csr" -f $base, $ts)
            }
            catch {
              throw (T "Renew.BackupCsrFail" @($outCsr))
            }
          }
        }
        else {
          # 対話的に選択
          $conflictItems = New-Object System.Collections.Generic.List[string]
          $conflictItems.Add((T "Renew.ConflictOverwrite")) | Out-Null
              
          # 複数件ある場合のみ「スキップ」を出す（現在の組織が複数件 or 処理対象組織が複数）
          $isBatchTask = ($orgDirs.Count -gt 1 -or $sets.Count -gt 1)
          if ($isBatchTask) {
            $conflictItems.Add((T "Renew.ConflictSkip")) | Out-Null
          }
              
          # 常に出す（いいえ / 戻る）
          $conflictItems.Add((T "Renew.ConflictCancel")) | Out-Null

          $conflictTitle = (T "Renew.OutExistsPrompt" @($outDir))
          $conflictSel = Show-MenuSelect -title $conflictTitle -items $conflictItems.ToArray() -helpText (T "Renew.MenuPrompt")
              
          if ($null -eq $conflictSel) {
            # ESC
            $script:returnToOrgMenu = $true
            break
          }

          if ($isBatchTask -and $conflictSel -eq 2) {
            # スキップ (batch mode Choice 2)
            continue
          }

          if (($isBatchTask -and $conflictSel -eq 3) -or (-not $isBatchTask -and $conflictSel -eq 2)) {
            # キャンセル / 戻る (batch Choice 3 or single Choice 2)
            $script:returnToOrgMenu = $true
            # 単一タスクの場合は即終了とみなして99を返す
            if (-not $isBatchTask) { exit 99 }
            break
          }
              
          # Overwrite を選択した場合（既存の $Overwrite=true 時のロジックを実行）
          $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
          if (Test-Path -LiteralPath $outKey -PathType Leaf) {
            try { Rename-Item -Force -ErrorAction Stop -LiteralPath $outKey -NewName ("{0}.bak_{1}.key" -f $base, $ts) }
            catch { throw (T "Renew.BackupKeyFail" @($outKey)) }
          }
          if (Test-Path -LiteralPath $outCsr -PathType Leaf) {
            try { Rename-Item -Force -ErrorAction Stop -LiteralPath $outCsr -NewName ("{0}.bak_{1}.csr" -f $base, $ts) }
            catch { throw (T "Renew.BackupCsrFail" @($outCsr)) }
          }
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($setPassphrase)) {
        # OpenSSL 3.x の req は -aes256 を受け付けないため、genpkey + req で生成する
        Invoke-TempPassFile $setPassphrase {
          param($tmpPass)
          Invoke-OpenSsl @(
            "genpkey",
            "-algorithm", "RSA",
            "-pkeyopt", ("rsa_keygen_bits:{0}" -f $rsaBits),
            "-out", $outKey,
            "-aes-256-cbc",
            "-pass", ("file:{0}" -f $tmpPass)
          ) | Out-Null

          $reqArgs = @("req", "-new", "-sha256", "-key", $outKey, "-passin", ("file:{0}" -f $tmpPass), "-out", $outCsr, "-subj", $subj)
          if ($sanOpt.Count -gt 0) { $reqArgs += $sanOpt }
          Invoke-OpenSsl $reqArgs | Out-Null
        } | Out-Null
      }
      else {
        $keyArgs = @("req", "-new", "-newkey", "rsa:$rsaBits", "-sha256", "-nodes", "-keyout", $outKey, "-out", $outCsr, "-subj", $subj)
        if ($sanOpt.Count -gt 0) { $keyArgs += $sanOpt }
        Invoke-OpenSsl $keyArgs | Out-Null
      }
          
      # --- INTEGRATED TSV GENERATION START ---
      try {
        $shouldGenerateTsv = Read-TsvGeneration $cn
        if (-not $shouldGenerateTsv) {
          Write-Host (T "Renew.TsvSkipped") -ForegroundColor DarkGray
        }
        else {
        # 1. Find TSV in Old Directory (Set -> Cert -> Directory)
        $oldCertDir = [IO.Path]::GetDirectoryName($certPath)
        $targetFilter = "*.tsv"
        $legacyTsvFiles = @(Get-ChildItem -LiteralPath $oldCertDir -Filter $targetFilter -File -ErrorAction SilentlyContinue)
              
        $tsvDefaults = @{ "Software" = "Apache"; "Contact" = "Admin"; "Term" = "1"; "SystemID" = "SYS-NEW" }
        $tsvOutName = "server_list.tsv" # Default name
        
        if ($legacyTsvFiles.Count -gt 0) {
          $legFile = $legacyTsvFiles[0]
          $tsvOutName = $legFile.Name
          $map = ConvertFrom-LegacyTsv $legFile.FullName
          if ($map.ContainsKey($cn)) {
            $tsvDefaults = $map[$cn]
          }
        }
        
        # 3. Confirm/Edit
        $finalData = Confirm-TsvData $cn $tsvDefaults
                  
        # 4. Build UPKI 13-field TSV Row
        # [0]=Subject, [1]=SAN数, [2]=空, [3]=SystemID, [4]=空, [5]=空
        # [6]=CSR(Base64), [7]=部門, [8]=機関名, [9]=Contact, [10]=CN, [11]=Software, [12]=SAN
        
        # CSR内容（Base64）を読み込み
        $csrBase64 = ""
        if (Test-Path -LiteralPath $outCsr) {
          $csrLines = Get-Content -LiteralPath $outCsr
          # Extract only base64 body (skip BEGIN/END lines)
          $csrBase64 = ($csrLines | Where-Object { $_ -notmatch "^----" }) -join ""
        }
        
        # SAN文字列を構築（dNSName=xxx,dNSName=yyy）
        $sanParts = @()
        foreach ($s in $sans) {
          if ($s -match "^DNS:(.*)") { $sanParts += "dNSName=$($matches[1])" }
          elseif ($s -match "^IP:(.*)") { $sanParts += "iPAddress=$($matches[1])" }
        }
        $sanConfig = $sanParts -join ","
        
        # UPKI形式の13フィールド配列を構築
        $fields = @(
          $finalData["Subject"]     # [0] Subject DN
          $finalData["SanCount"]    # [1] SAN count
          $finalData["Empty2"]      # [2] empty
          $finalData["SystemID"]    # [3] SystemID
          $finalData["Empty4"]      # [4] empty
          $finalData["Empty5"]      # [5] empty
          $csrBase64                # [6] CSR Base64
          $finalData["Dept"]        # [7] 部門
          $finalData["OrgName"]     # [8] 機関名
          $finalData["Contact"]     # [9] Contact
          $cn                       # [10] CN
          $finalData["Software"]    # [11] Software
          $sanConfig                # [12] SAN
        )
        
        # Join with Tab
        $tsvLine = $fields -join "`t"

        # 5. Export (Shift-JIS encoding)
        $tsvOutPath = Join-Path $newOrgDir $tsvOutName
        Export-TsvRow $tsvOutPath $tsvLine
        }
      }
      catch {
        Write-Warning "TSV Generation Failed: $_"
      }
      # --- INTEGRATED TSV GENERATION END ---

      $generated.Add([PSCustomObject]@{
          Org      = $orgOut
          CN       = $cn
          Cert     = $certPath
          OutDir   = $outDir
          Key      = $outKey
          Csr      = $outCsr
          RsaBits  = $rsaBits
          SANs     = ($sans -join ", ")
          PassFile = $setPassFile
        }) | Out-Null
    }
    # SAN メニューでキャンセルされた場合は機関ループを抜ける
    if ($script:returnToOrgMenu) { break }
  }
  # SAN メニューでキャンセルされた場合は機関選択に戻る
  if ($script:returnToOrgMenu) { continue }

  Write-Host ""
  Write-Host (T "Renew.DoneTitle")
  $generated |
  Sort-Object Org, CN |
  Select-Object `
  @{Name = (T "Renew.Table.Org"); Expression = { $_.Org } }, `
  @{Name = (T "Renew.Table.Cn"); Expression = { $_.CN } }, `
  @{Name = (T "Renew.Table.RsaBits"); Expression = { $_.RsaBits } }, `
  @{Name = (T "Renew.Table.San"); Expression = { $_.SANs } }, `
  @{Name = (T "Renew.Table.OutDir"); Expression = { $_.OutDir } } |
  Format-Table -AutoSize

  Write-Host ""
  if ($interactive) {
    Write-Host ""
    Write-Host (T "Renew.PressAnyKeyToReturn") -NoNewline
    try { $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { }
    Write-Host ""
    $script:returnToOrgMenu = $true
  }
}  # end while


