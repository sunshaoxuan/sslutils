<#
.SYNOPSIS
自己署名証明書を生成するスクリプト（有効期間を選択可能）

.DESCRIPTION
OpenSSL を使って自己署名証明書を生成します。
有効期間は 90日 / 1年 / 3年 / 10年 から対話メニューで選択、または -Days で任意指定可能。
Quick モードでは old 配下の既存証明書から CN を抽出して、機関単位で生成します。
Custom モードでは手動入力で 1 件を生成します。
#>

param(
  [Parameter(Mandatory = $false)]
  [string]$CN = "",

  [Parameter(Mandatory = $false)]
  [string]$Subject = "",

  [Parameter(Mandatory = $false)]
  [string]$SAN = "",

  [Parameter(Mandatory = $false)]
  [string]$OutDir = "",

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 36500)]
  [int]$Days = 0,

  [Parameter(Mandatory = $false)]
  [ValidateRange(2048, 16384)]
  [int]$RsaBits = 2048,

  [Parameter(Mandatory = $false)]
  [string]$OpenSsl = "",

  [Parameter(Mandatory = $false)]
  [switch]$Overwrite,

  [Parameter(Mandatory = $false)]
  [string]$Lang = ""
)


$ToolkitRoot = Split-Path -Parent $PSScriptRoot

try {
  [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
  $OutputEncoding = [Console]::OutputEncoding
}
catch { }

$i18nModule = Join-Path $PSScriptRoot "lib\i18n.ps1"
if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw "i18n module not found: $i18nModule" }
. $i18nModule
$__i18n = Initialize-I18n -Lang $Lang -BaseDir $ToolkitRoot
function T([string]$Key, [object[]]$FormatArgs = @()) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }

$menuModule = Join-Path $PSScriptRoot "lib\menu.ps1"
if (Test-Path -LiteralPath $menuModule -PathType Leaf) { . $menuModule }
$pathsModule = Join-Path $PSScriptRoot "lib\paths.ps1"
if (Test-Path -LiteralPath $pathsModule -PathType Leaf) { . $pathsModule }
$ToolkitPaths = if (Get-Command Get-ToolkitPaths -ErrorAction SilentlyContinue) { Get-ToolkitPaths -BaseDir $ToolkitRoot } else { $null }
$OpenSsl = Resolve-OpenSsl -Explicit $OpenSsl -ToolkitPaths $ToolkitPaths

$__ValidityPresets = @(
  @{ Days = 90;   LabelKey = "SS.Validity.90d"  },
  @{ Days = 365;  LabelKey = "SS.Validity.1y"   },
  @{ Days = 1095; LabelKey = "SS.Validity.3y"   },
  @{ Days = 3650; LabelKey = "SS.Validity.10y"  }
)

$ValidityDays = if ($Days -gt 0) { $Days } else { 0 }

function Select-ValidityPeriod {
  $items = @($__ValidityPresets | ForEach-Object { T $_.LabelKey })
  $items += ("[ {0} ]" -f (T "Common.MenuBack"))

  $pick = Show-MenuSelect -title (T "SS.Menu.ValidityTitle") -items $items -helpText (T "CheckBasic.Menu.Instruction")
  if ($null -eq $pick -or $pick -eq $items.Count) { return -1 }
  return $__ValidityPresets[$pick - 1].Days
}

function Wait-Continue([string]$message) {
  if (Get-Command Wait-AnyKey -ErrorAction SilentlyContinue) {
    Wait-AnyKey $message
    return
  }
  Write-Host $message -NoNewline
  try { $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { }
  Write-Host ""
}

function Resolve-OpenSslCommand([string]$openSslPath) {
  if (-not [string]::IsNullOrWhiteSpace($openSslPath) -and (Test-Path -LiteralPath $openSslPath -PathType Leaf)) {
    return $openSslPath
  }
  $cmd = Get-Command openssl -ErrorAction SilentlyContinue
  if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
    return $cmd.Source
  }
  throw (T "SS.OpenSslNotFound" @($openSslPath))
}

function New-DirectoryIfMissing([string]$path) {
  if (-not (Test-Path -LiteralPath $path -PathType Container)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
  }
}

function Backup-IfExists([string]$path) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
  $dir = Split-Path -Parent $path
  if ([string]::IsNullOrWhiteSpace($dir)) { $dir = "." }
  $base = [IO.Path]::GetFileNameWithoutExtension($path)
  $ext = [IO.Path]::GetExtension($path)
  $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
  $bakName = "{0}.bak_{1}{2}" -f $base, $ts, $ext
  Rename-Item -LiteralPath $path -NewName $bakName -Force
}

function Invoke-OpenSsl([string]$openSslCmd, [string[]]$openSslArgs) {
  $out = & $openSslCmd @openSslArgs 2>&1 | ForEach-Object { $_.ToString() }
  if ($LASTEXITCODE -ne 0) {
    throw (T "Common.OpenSslCmdFailed" @(($openSslArgs -join " "), (($out | Where-Object { $_ -ne "" }) -join "`n")))
  }
  return @($out)
}

function Read-Input([string]$prompt, [bool]$allowEmpty) {
  if (Get-Command Read-HostWithEsc -ErrorAction SilentlyContinue) {
    $value = Read-HostWithEsc $prompt
    if ($null -eq $value) { return $null }
    $trimmed = ([string]$value).Trim()
    if (-not $allowEmpty -and [string]::IsNullOrWhiteSpace($trimmed)) { return "" }
    return $trimmed
  }
  $v = Read-Host $prompt
  $v = ([string]$v).Trim()
  if (-not $allowEmpty -and [string]::IsNullOrWhiteSpace($v)) { return "" }
  return $v
}

function ConvertFrom-SanList([string]$raw, [string]$cn) {
  $items = New-Object System.Collections.Generic.List[string]
  if (-not [string]::IsNullOrWhiteSpace($raw)) {
    $parts = @($raw -split "[,;]" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
    foreach ($p in $parts) {
      if ($p -match "^(DNS|IP|URI|EMAIL):") { $items.Add($p) | Out-Null }
      else { $items.Add("DNS:$p") | Out-Null }
    }
  }
  $cnSan = "DNS:$cn"
  if (-not ($items -contains $cnSan)) { $items.Insert(0, $cnSan) }
  return @($items | Select-Object -Unique)
}

function ConvertTo-SubjectWithCn([string]$subject, [string]$cn) {
  if ([string]::IsNullOrWhiteSpace($subject)) { return "/CN=$cn" }
  if ($subject -match "(^|/)CN=") { return $subject }
  return ($subject.TrimEnd('/')) + "/CN=$cn"
}

function Get-CnFromCert([string]$openSslCmd, [string]$certPath) {
  $subjectOut = @(Invoke-OpenSsl $openSslCmd @("x509", "-in", $certPath, "-noout", "-subject", "-nameopt", "RFC2253"))
  $line = ($subjectOut -join "`n")
  if ($line -match "CN\s*=\s*([^,]+)") {
    return $matches[1].Trim()
  }
  return ""
}

function New-SelfSignedForCn([string]$openSslCmd, [string]$cn, [string]$subject, [string]$sanRaw, [string]$targetOutDir) {
  $subjectFinal = ConvertTo-SubjectWithCn $subject $cn
  $sanItems = ConvertFrom-SanList $sanRaw $cn
  $sanLine = ($sanItems -join ",")

  New-DirectoryIfMissing $targetOutDir

  $safeName = ($cn -replace '[\\/:*?"<>|\s]+', '_')
  $keyPath = Join-Path $targetOutDir ("{0}.selfsigned.key" -f $safeName)
  $crtPath = Join-Path $targetOutDir ("{0}.selfsigned.crt" -f $safeName)

  $existsList = New-Object System.Collections.Generic.List[string]
  if (Test-Path -LiteralPath $keyPath -PathType Leaf) { $existsList.Add($keyPath) | Out-Null }
  if (Test-Path -LiteralPath $crtPath -PathType Leaf) { $existsList.Add($crtPath) | Out-Null }
  if ($existsList.Count -gt 0 -and -not $Overwrite) {
    throw (T "SS.OutExistsNoOverwrite" @(($existsList -join "`n")))
  }

  if ($Overwrite) {
    Backup-IfExists $keyPath
    Backup-IfExists $crtPath
  }

  $tmpRoot = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace([string]$ToolkitPaths.Temp)) { [string]$ToolkitPaths.Temp } else { Join-Path $ToolkitRoot "temp" }
  New-DirectoryIfMissing $tmpRoot
  $cfgPath = Join-Path $tmpRoot ("ssl_maker_selfsigned_{0}.cnf" -f ([Guid]::NewGuid().ToString("N")))
  $cfg = @"
[req]
distinguished_name = req_dn
x509_extensions = v3_req
prompt = no

[req_dn]
CN = $cn

[v3_req]
subjectAltName = $sanLine
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
basicConstraints = CA:FALSE
"@

  try {
    Set-Content -LiteralPath $cfgPath -Value $cfg -Encoding Ascii -NoNewline

    Write-Host ""
    Write-Host (T "SS.Starting" @($ValidityDays, [math]::Round($ValidityDays / 365, 1))) -ForegroundColor Cyan
    Write-Host (T "SS.Info.CN" @($cn))
    Write-Host (T "SS.Info.Subject" @($subjectFinal))
    Write-Host (T "SS.Info.SAN" @($sanLine))
    Write-Host (T "SS.Info.Validity" @($ValidityDays, [math]::Round($ValidityDays / 365, 1)))
    Write-Host (T "SS.Info.OutDir" @($targetOutDir))
    Write-Host ""

    $sslArgs = @(
      "req", "-x509", "-batch", "-newkey", "rsa:$RsaBits", "-sha256", "-nodes",
      "-days", "$ValidityDays", "-keyout", $keyPath, "-out", $crtPath,
      "-subj", $subjectFinal, "-extensions", "v3_req", "-config", $cfgPath
    )

    Invoke-OpenSsl $openSslCmd $sslArgs | Out-Null

    $endDateOut = @(Invoke-OpenSsl $openSslCmd @("x509", "-in", $crtPath, "-noout", "-enddate"))
    $endDate = ""
    if ($endDateOut.Count -gt 0 -and $endDateOut[0] -match "notAfter=(.+)$") { $endDate = $matches[1] }

    Write-Host (T "SS.Done.Key" @($keyPath)) -ForegroundColor Green
    Write-Host (T "SS.Done.Cert" @($crtPath)) -ForegroundColor Green
    if (-not [string]::IsNullOrWhiteSpace($endDate)) { Write-Host (T "SS.Done.NotAfter" @($endDate)) -ForegroundColor Green }
    Write-Host (T "SS.Done.Warning") -ForegroundColor Yellow

    return [PSCustomObject]@{ Success = $true; CN = $cn; Key = $keyPath; Cert = $crtPath }
  }
  finally {
    Remove-Item -LiteralPath $cfgPath -Force -ErrorAction SilentlyContinue
  }
}

function Get-OldOrgDirs() {
  $oldDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.Old)) { $ToolkitPaths.Old } else { Join-Path $ToolkitRoot "old" }
  if (-not (Test-Path -LiteralPath $oldDir -PathType Container)) { return @() }
  return @(Get-ChildItem -LiteralPath $oldDir -Directory | Sort-Object Name)
}

function Start-QuickMode([string]$openSslCmd, [string]$baseOutDir) {
  $orgDirs = @(Get-OldOrgDirs)
  if ($orgDirs.Count -eq 0) {
    Write-Host (T "SS.Menu.NoOrg") -ForegroundColor Yellow
    Wait-Continue (T "SS.PressAnyKeyReturnOrg")
    return
  }

  while ($true) {
    $orgItems = @($orgDirs | ForEach-Object { $_.Name })
    $orgItems += ("[ {0} ]" -f (T "Common.MenuBack"))

    $choice = Show-MenuSelect -title (T "SS.Menu.QuickSelectOrg") -items $orgItems -helpText (T "CheckBasic.Menu.Instruction")
    if ($null -eq $choice -or $choice -eq $orgItems.Count) { return }

    $selected = $orgDirs[$choice - 1]
    $orgOutDir = Join-Path $baseOutDir $selected.Name

    Write-Host ""
    Write-Host (T "SS.Quick.StartOrg" @($selected.Name)) -ForegroundColor Cyan

    $certFiles = @(Get-ChildItem -LiteralPath $selected.FullName -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.Extension -in $__CertExtensions })

    if ($certFiles.Count -eq 0) {
      Write-Host (T "SS.Menu.NoCertInOrg" @($selected.Name)) -ForegroundColor Yellow
      Wait-Continue (T "SS.PressAnyKeyReturnOrg")
      continue
    }

    $seen = @{}
    $ok = 0
    $ng = 0

    foreach ($cf in $certFiles) {
      try {
        $cn = Get-CnFromCert $openSslCmd $cf.FullName
        if ([string]::IsNullOrWhiteSpace($cn)) {
          Write-Host (T "SS.Quick.CnFromCertFailed" @($cf.FullName)) -ForegroundColor Yellow
          $ng++
          continue
        }
        if ($seen.ContainsKey($cn)) {
          Write-Host (T "SS.Quick.SkipDuplicateCn" @($cn)) -ForegroundColor DarkGray
          continue
        }
        $seen[$cn] = $true
        Write-Host (T "SS.Quick.ProcessingCert" @($cf.Name, $cn)) -ForegroundColor DarkGray
        $null = New-SelfSignedForCn $openSslCmd $cn "" "" $orgOutDir
        $ok++
      }
      catch {
        Write-Host (T "Common.ErrorNg" @($_.Exception.Message)) -ForegroundColor Red
        $ng++
      }
    }

    Write-Host ""
    Write-Host (T "SS.Quick.Completed" @($selected.Name)) -ForegroundColor Cyan
    Write-Host (T "SS.Quick.SuccessCount" @($ok)) -ForegroundColor Green
    Write-Host (T "SS.Quick.FailCount" @($ng)) -ForegroundColor Yellow
    Wait-Continue (T "SS.PressAnyKeyReturnOrg")
  }
}

function Start-CustomMode([string]$openSslCmd, [bool]$interactiveInput) {
  if ([string]::IsNullOrWhiteSpace($CN)) {
    Write-Host (T "SS.InputCnPrompt")
    $inputCn = Read-Input (T "SS.Prompt.CN") $false
    if ($null -eq $inputCn -or [string]::IsNullOrWhiteSpace($inputCn)) { exit 99 }
    $script:CN = $inputCn
  }

  if ($interactiveInput -and [string]::IsNullOrWhiteSpace($Subject)) {
    Write-Host (T "SS.InputSubjectPrompt")
    $inputSubject = Read-Input (T "SS.Prompt.SubjectOptional") $true
    if ($null -eq $inputSubject) { exit 99 }
    if (-not [string]::IsNullOrWhiteSpace($inputSubject)) { $script:Subject = $inputSubject }
  }

  if ($interactiveInput -and [string]::IsNullOrWhiteSpace($SAN)) {
    Write-Host (T "SS.InputSanPrompt")
    $inputSan = Read-Input (T "SS.Prompt.SANOptional") $true
    if ($null -eq $inputSan) { exit 99 }
    $script:SAN = $inputSan
  }

  $null = New-SelfSignedForCn $openSslCmd $CN $Subject $SAN $OutDir
}

try {
  if ([string]::IsNullOrWhiteSpace($OutDir)) {
    if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.SelfSigned)) { $OutDir = $ToolkitPaths.SelfSigned }
    else { $OutDir = Join-Path $ToolkitRoot "output\self-signed" }
  }

  $openSslCmd = Resolve-OpenSslCommand $OpenSsl

  if (-not [string]::IsNullOrWhiteSpace($CN)) {
    if ($ValidityDays -le 0) { $script:ValidityDays = 3650 }
    Start-CustomMode $openSslCmd $false
    exit 0
  }

  if (Get-Command Show-MenuSelect -ErrorAction SilentlyContinue) {
    :validityLoop while ($true) {
      if ($ValidityDays -le 0) {
        $chosen = Select-ValidityPeriod
        if ($chosen -lt 0) { exit 99 }
        $script:ValidityDays = $chosen
      }

      while ($true) {
        $menuItems = @(
          (T "SS.Menu.Quick"),
          (T "SS.Menu.Custom"),
          ("[ {0} ]" -f (T "Common.MenuBack"))
        )

        $modeTitle = T "SS.Menu.Title" @($ValidityDays, [math]::Round($ValidityDays / 365, 1))
        $pick = Show-MenuSelect -title $modeTitle -items $menuItems -helpText (T "CheckBasic.Menu.Instruction")
        if ($null -eq $pick -or $pick -eq $menuItems.Count) {
          if ($Days -gt 0) { exit 99 }
          $script:ValidityDays = 0
          continue validityLoop
        }

        switch ($pick) {
          1 { Start-QuickMode $openSslCmd $OutDir }
          2 { Start-CustomMode $openSslCmd $true }
        }
      }
    }
  }

  if ($ValidityDays -le 0) { $script:ValidityDays = 3650 }
  Start-CustomMode $openSslCmd $true
}
catch {
  Write-Host ""
  Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
  throw
}


