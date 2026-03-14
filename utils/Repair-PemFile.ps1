<#
.SYNOPSIS
PEM ファイルのフォーマットを修復・正規化するスクリプト

.DESCRIPTION
このスクリプトは、破損または不正なフォーマットの PEM ファイルを修復します。

主な機能:
- UTF-8 BOM の除去
- ヘッダー/フッターの空白修正
- Base64 本文の改行正規化（64文字折り返し）
- 複数ブロック対応（fullchain など）
- 自動バックアップ
- old / new / merged / self-signed からの対話選択

.PARAMETER Fullchain
修復対象の証明書（fullchain）ファイルパス

.PARAMETER Privkey
修復対象の秘密鍵ファイルパス

.PARAMETER NginxExe
nginx 実行ファイルパス（-TestNginx 使用時）

.PARAMETER NginxConf
nginx 設定ファイルパス（-TestNginx 使用時）

.PARAMETER TestNginx
修復後に nginx -t で構文チェックを実行

.PARAMETER Lang
出力言語（既定: ja）
#>

param(
  [Parameter(Mandatory = $false)]
  [string]$Fullchain = "",

  [Parameter(Mandatory = $false)]
  [string]$Privkey = "",

  [Parameter(Mandatory = $false)]
  [string]$NginxExe = "",

  [Parameter(Mandatory = $false)]
  [string]$NginxConf = "",

  [Parameter(Mandatory = $false)]
  [switch]$TestNginx,

  [Parameter(Mandatory = $false)]
  [string]$Lang = ""
)

$runtimeModule = Join-Path $PSScriptRoot "lib\runtime.ps1"
if (Test-Path -LiteralPath $runtimeModule -PathType Leaf) { . $runtimeModule }
$ModuleRoot = $PSScriptRoot
$ToolkitRoot = Get-ToolkitBaseDir -ModuleRoot $ModuleRoot
Initialize-ToolkitConsoleEncoding

$__i18n = Initialize-ToolkitI18nContext -ModuleRoot $ModuleRoot -Lang $Lang -BaseDir $ToolkitRoot
function T {
  param(
    [string]$Key,
    [object[]]$FormatArgs = @()
  )
  return Get-ToolkitText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs
}

$menuModule = Join-Path $PSScriptRoot "lib\menu.ps1"
if (Test-Path -LiteralPath $menuModule -PathType Leaf) { . $menuModule }
$ToolkitPaths = Get-ToolkitPathsContext -ModuleRoot $ModuleRoot -BaseDir $ToolkitRoot

function Assert-FileExists {
  param(
    [string]$Path,
    [string]$Label
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw (T "Common.FileNotFound" @($Label, $Path))
  }
}

function Backup-File {
  param([string]$Path)

  Assert-FileExists -Path $Path -Label "File"
  $bak = "$Path.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
  Copy-Item -LiteralPath $Path -Destination $bak -Force
  return $bak
}

function Read-BytesNoBom {
  param([string]$Path)

  $bytes = [System.IO.File]::ReadAllBytes($Path)
  if ($null -eq $bytes) { throw (T "RepairPem.ReadFailed" @($Path)) }
  if ($bytes.Length -eq 0) { throw (T "RepairPem.ZeroBytes" @($Path)) }

  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    $newLen = $bytes.Length - 3
    if ($newLen -le 0) { throw (T "RepairPem.EmptyAfterBom" @($Path)) }
    $newBytes = New-Object byte[] $newLen
    [System.Array]::Copy($bytes, 3, $newBytes, 0, $newLen)
    return $newBytes
  }

  return $bytes
}

function Read-TextRaw {
  param([string]$Path)

  $bytes = Read-BytesNoBom -Path $Path
  $text = [System.Text.Encoding]::UTF8.GetString($bytes)
  return ($text -replace "`r", "")
}

function Write-TextAscii {
  param(
    [string]$Path,
    [string]$Text
  )

  [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.ASCIIEncoding))
}

function Read-Input {
  param([string]$Prompt)

  if (Get-Command Read-HostWithEsc -ErrorAction SilentlyContinue) {
    return Read-HostWithEsc $Prompt
  }
  return (Read-Host $Prompt)
}

function Get-PemFileKind {
  param([string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "" }
  try {
    $head = @(Get-Content -LiteralPath $Path -TotalCount 3 -ErrorAction Stop)
  }
  catch {
    return ""
  }

  foreach ($line in $head) {
    if ($line -match "BEGIN CERTIFICATE") { return "cert" }
    if ($line -match "BEGIN (ENCRYPTED |RSA |EC )?PRIVATE KEY") { return "key" }
  }

  return ""
}

function Get-PemPairCandidates {
  param([string]$RootPath)

  if ([string]::IsNullOrWhiteSpace($RootPath) -or -not (Test-Path -LiteralPath $RootPath -PathType Container)) { return @() }

  $resolvedRoot = (Resolve-Path -LiteralPath $RootPath).Path.TrimEnd('\', '/')
  $pemFiles = @(Get-ChildItem -LiteralPath $RootPath -Recurse -File -Filter "*.pem" -ErrorAction SilentlyContinue)
  if ($pemFiles.Count -eq 0) { return @() }

  $dirMap = @{}
  foreach ($file in $pemFiles) {
    $kind = Get-PemFileKind -Path $file.FullName
    if ([string]::IsNullOrWhiteSpace($kind)) { continue }

    $dir = Split-Path -Parent $file.FullName
    if (-not $dirMap.ContainsKey($dir)) {
      $dirMap[$dir] = @{
        Certs = @()
        Keys  = @()
      }
    }

    if ($kind -eq "cert") {
      $dirMap[$dir].Certs += $file
    }
    elseif ($kind -eq "key") {
      $dirMap[$dir].Keys += $file
    }
  }

  $results = @()
  foreach ($dir in ($dirMap.Keys | Sort-Object)) {
    $entry = $dirMap[$dir]
    if ($entry.Certs.Count -eq 0 -or $entry.Keys.Count -eq 0) { continue }

    $cert = @($entry.Certs | Where-Object { $_.Name -ieq "fullchain.pem" } | Select-Object -First 1)[0]
    if ($null -eq $cert) { $cert = @($entry.Certs | Select-Object -First 1)[0] }

    $key = @($entry.Keys | Where-Object { $_.Name -ieq "privkey.pem" } | Select-Object -First 1)[0]
    if ($null -eq $key) { $key = @($entry.Keys | Select-Object -First 1)[0] }

    if ($null -eq $cert -or $null -eq $key) { continue }

    $resolvedDir = (Resolve-Path -LiteralPath $dir).Path
    $relative = "."
    if ($resolvedDir.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
      $relative = $resolvedDir.Substring($resolvedRoot.Length).TrimStart('\', '/')
      if ([string]::IsNullOrWhiteSpace($relative)) { $relative = "." }
    }

    $results += [PSCustomObject]@{
      Fullchain = $cert.FullName
      Privkey   = $key.FullName
      Label     = ("{0}`n  fullchain: {1}`n  privkey: {2}" -f $relative, $cert.Name, $key.Name)
    }
  }

  return @($results)
}

function Select-PemPairInteractively {
  $oldDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace([string]$ToolkitPaths.Old)) { [string]$ToolkitPaths.Old } else { Join-Path $ToolkitRoot "old" }
  $newDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace([string]$ToolkitPaths.New)) { [string]$ToolkitPaths.New } else { Join-Path $ToolkitRoot "new" }
  $mergedDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace([string]$ToolkitPaths.Merged)) { [string]$ToolkitPaths.Merged } else { Join-Path $ToolkitRoot "output\merged" }
  $selfSignedDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace([string]$ToolkitPaths.SelfSigned)) { [string]$ToolkitPaths.SelfSigned } else { Join-Path $ToolkitRoot "output\self-signed" }

  $sources = @(
    [PSCustomObject]@{ Label = (T "Label.Old"); Path = $oldDir },
    [PSCustomObject]@{ Label = (T "Label.New"); Path = $newDir },
    [PSCustomObject]@{ Label = (T "Label.Merged"); Path = $mergedDir },
    [PSCustomObject]@{ Label = (T "Label.SelfSigned"); Path = $selfSignedDir }
  )

  $fullchainPrompt = T "RepairPem.Menu.FullchainPrompt"
  $privkeyPrompt = T "RepairPem.Menu.PrivkeyPrompt"

  if (-not (Get-Command Show-MenuSelect -ErrorAction SilentlyContinue)) {
    $fc = Read-Input -Prompt $fullchainPrompt
    if ($null -eq $fc) { return $null }
    $pk = Read-Input -Prompt $privkeyPrompt
    if ($null -eq $pk) { return $null }
    return [PSCustomObject]@{ Fullchain = $fc.Trim(); Privkey = $pk.Trim() }
  }

  while ($true) {
    $menuItems = @()
    foreach ($src in $sources) {
      $suffix = if (Test-Path -LiteralPath $src.Path -PathType Container) { "" } else { " [N/A]" }
      $menuItems += ("{0}`n  {1}{2}" -f $src.Label, $src.Path, $suffix)
    }
    $menuItems += (T "RepairPem.Menu.Manual")
    $menuItems += ("[ {0} ]" -f (T "Common.MenuBack"))

    $pick = Show-MenuSelect -title (T "RepairPem.Menu.SelectSource") -items $menuItems -helpText (T "CheckBasic.Menu.Instruction")
    if ($null -eq $pick -or $pick -eq $menuItems.Count) { return $null }

    if ($pick -eq ($menuItems.Count - 1)) {
      $fc = Read-Input -Prompt $fullchainPrompt
      if ($null -eq $fc) { continue }
      $pk = Read-Input -Prompt $privkeyPrompt
      if ($null -eq $pk) { continue }
      return [PSCustomObject]@{ Fullchain = $fc.Trim(); Privkey = $pk.Trim() }
    }

    $selectedSource = $sources[$pick - 1]
    $candidates = @(Get-PemPairCandidates -RootPath $selectedSource.Path)
    if ($candidates.Count -eq 0) {
      Write-Host ""
      Write-Host (T "RepairPem.Menu.NoCandidates" @($selectedSource.Path)) -ForegroundColor Yellow
      Start-Sleep -Seconds 2
      continue
    }

    $candidateItems = @($candidates | ForEach-Object { $_.Label })
    $candidateItems += ("[ {0} ]" -f (T "Common.MenuBack"))

    $pairPick = Show-MenuSelect -title (T "RepairPem.Menu.SelectPair" @($selectedSource.Label)) -items $candidateItems -helpText (T "CheckBasic.Menu.Instruction")
    if ($null -eq $pairPick -or $pairPick -eq $candidateItems.Count) { continue }

    $selected = $candidates[$pairPick - 1]
    return [PSCustomObject]@{
      Fullchain = $selected.Fullchain
      Privkey   = $selected.Privkey
    }
  }
}

function Repair-Headers {
  param([string]$Text)

  $Text = $Text -replace "-----BEGINCERTIFICATE-----", "-----BEGIN CERTIFICATE-----"
  $Text = $Text -replace "-----ENDCERTIFICATE-----", "-----END CERTIFICATE-----"
  $Text = $Text -replace "-----BEGINPRIVATEKEY-----", "-----BEGIN PRIVATE KEY-----"
  $Text = $Text -replace "-----ENDPRIVATEKEY-----", "-----END PRIVATE KEY-----"
  $Text = $Text -replace "-----BEGINECPRIVATEKEY-----", "-----BEGIN EC PRIVATE KEY-----"
  $Text = $Text -replace "-----ENDECPRIVATEKEY-----", "-----END EC PRIVATE KEY-----"
  $Text = $Text -replace "-----BEGINRSAPRIVATEKEY-----", "-----BEGIN RSA PRIVATE KEY-----"
  $Text = $Text -replace "-----ENDRSAPRIVATEKEY-----", "-----END RSA PRIVATE KEY-----"
  return $Text
}

function Format-Pem {
  param(
    [string]$Path,
    [string]$Kind
  )

  $orig = Read-TextRaw -Path $Path
  $text = Repair-Headers -Text $orig

  $matches = [regex]::Matches($text, "-----BEGIN [^-]+-----.*?-----END [^-]+-----", "Singleline")
  if ($matches.Count -eq 0) {
    throw (T "RepairPem.NoPemBlock" @($Kind, $Path))
  }

  $lines = New-Object System.Collections.Generic.List[string]
  foreach ($match in $matches) {
    $block = $match.Value
    $parsed = [regex]::Match($block, "^(-----BEGIN [^-]+-----)\s*(.*?)\s*(-----END [^-]+-----)$", "Singleline")
    if (-not $parsed.Success) { throw (T "RepairPem.ParseFailed" @($Kind, $Path)) }

    $begin = $parsed.Groups[1].Value
    $body = [regex]::Replace($parsed.Groups[2].Value, "\s+", "")
    $end = $parsed.Groups[3].Value

    if ($body.Length -lt 128) {
      throw (T "RepairPem.TooShort" @($Kind, $body.Length, $Path))
    }

    $lines.Add($begin) | Out-Null
    for ($i = 0; $i -lt $body.Length; $i += 64) {
      $len = [Math]::Min(64, $body.Length - $i)
      $lines.Add($body.Substring($i, $len)) | Out-Null
    }
    $lines.Add($end) | Out-Null
    $lines.Add("") | Out-Null
  }

  $final = ($lines -join "`n").TrimEnd() + "`n"
  Write-TextAscii -Path $Path -Text $final

  return @{
    Path      = $Path
    Blocks    = $matches.Count
    FirstLine = (Get-Content -LiteralPath $Path -TotalCount 1)
    LastLine  = (Get-Content -LiteralPath $Path -Tail 1)
    Size      = (Get-Item -LiteralPath $Path).Length
  }
}

function Test-PemHeader {
  param(
    [string]$Path,
    [string]$Kind
  )

  $head = Get-Content -LiteralPath $Path -TotalCount 1
  if ($Kind -eq "fullchain") {
    if ($head -ne "-----BEGIN CERTIFICATE-----") {
      throw (T "RepairPem.InvalidHeader" @("fullchain", $head))
    }
    return
  }

  if ($Kind -eq "privkey") {
    if ($head -ne "-----BEGIN PRIVATE KEY-----" -and
      $head -ne "-----BEGIN EC PRIVATE KEY-----" -and
      $head -ne "-----BEGIN RSA PRIVATE KEY-----") {
      throw (T "RepairPem.InvalidHeader" @("privkey", $head))
    }
  }
}

if ([string]::IsNullOrWhiteSpace($Fullchain) -or [string]::IsNullOrWhiteSpace($Privkey)) {
  $selectedPair = Select-PemPairInteractively
  if ($null -eq $selectedPair) { Exit-ToolkitCancelled }
  $Fullchain = [string]$selectedPair.Fullchain
  $Privkey = [string]$selectedPair.Privkey
}

Assert-FileExists -Path $Fullchain -Label "Fullchain"
Assert-FileExists -Path $Privkey -Label "Privkey"

try {
  Write-Host (T "RepairPem.BackupSection") -ForegroundColor Cyan
  $bak1 = Backup-File -Path $Fullchain
  $bak2 = Backup-File -Path $Privkey
  Write-Host (T "RepairPem.BackupCreated" @("fullchain", $bak1))
  Write-Host (T "RepairPem.BackupCreated" @("privkey", $bak2))

  Write-Host ""
  Write-Host (T "RepairPem.NormalizeSection") -ForegroundColor Cyan
  $infoFc = Format-Pem -Path $Fullchain -Kind "fullchain"
  $infoPk = Format-Pem -Path $Privkey -Kind "privkey"

  Write-Host ""
  Write-Host (T "RepairPem.VerifySection") -ForegroundColor Cyan
  Test-PemHeader -Path $Fullchain -Kind "fullchain"
  Test-PemHeader -Path $Privkey -Kind "privkey"

  Write-Host (T "RepairPem.FileInfo" @("fullchain", $infoFc.Size, $infoFc.Blocks, $infoFc.FirstLine, $infoFc.LastLine))
  Write-Host (T "RepairPem.FileInfo" @("privkey", $infoPk.Size, $infoPk.Blocks, $infoPk.FirstLine, $infoPk.LastLine))

  if ($TestNginx) {
    if ([string]::IsNullOrWhiteSpace($NginxExe) -or [string]::IsNullOrWhiteSpace($NginxConf)) {
      throw (T "RepairPem.NginxParamsRequired")
    }

    Assert-FileExists -Path $NginxExe -Label "NginxExe"
    Assert-FileExists -Path $NginxConf -Label "NginxConf"

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
