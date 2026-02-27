Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSVersion.Major -lt 7) {
  $__curLang = if (Test-Path variable:Lang) { $Lang } else { "ja" }
  $__msg = switch ($__curLang) {
    "zh" { "[错误] 需要 PowerShell 7.x 以上版本。" }
    "en" { "[ERROR] PowerShell 7.x or later is required." }
    default { "[エラー] PowerShell 7.x 以上が必要です。" }
  }
  $__cur = switch ($__curLang) {
    "zh" { "当前版本" }
    "en" { "Current" }
    default { "現在のバージョン" }
  }
  Write-Host $__msg -ForegroundColor Red
  Write-Host ("        {0}: {1}" -f $__cur, $PSVersionTable.PSVersion) -ForegroundColor Red
  Write-Host "        https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Yellow
  exit 1
}

function Initialize-I18n {
  param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("ja", "zh", "en")]
    [string]$Lang = "ja",

    [Parameter(Mandatory = $false)]
    [string]$BaseDir = ""
  )

  if ([string]::IsNullOrWhiteSpace($BaseDir)) { $BaseDir = $PSScriptRoot }
  $resDir = Join-Path $BaseDir "resources"
  $jaPath = Join-Path $resDir "strings.ja.psd1"
  $langPath = Join-Path $resDir ("strings.{0}.psd1" -f $Lang)

  if (-not (Test-Path -LiteralPath $jaPath -PathType Leaf)) {
    throw ("リソースファイルが見つかりません: {0}" -f $jaPath)
  }

  $ja = Import-PowerShellDataFile -LiteralPath $jaPath
  $langTable = @{}
  if ($Lang -ne "ja" -and (Test-Path -LiteralPath $langPath -PathType Leaf)) {
    $langTable = Import-PowerShellDataFile -LiteralPath $langPath
  }

  return [PSCustomObject]@{
    Lang      = $Lang
    Ja        = $ja
    LangTable = $langTable
  }
}

function Get-I18nText {
  param(
    [Parameter(Mandatory = $true)]
    $I18n,
    [Parameter(Mandatory = $true)]
    [string]$Key,
    [Parameter(Mandatory = $false)]
    [Alias("Args")]
    [object[]]$FormatArgs = @()
  )

  $s = $null
  try {
    if ($null -ne $I18n.LangTable -and $I18n.LangTable.ContainsKey($Key)) {
      $s = $I18n.LangTable[$Key]
    }
    elseif ($null -ne $I18n.Ja -and $I18n.Ja.ContainsKey($Key)) {
      $s = $I18n.Ja[$Key]
    }
  }
  catch { }

  if ([string]::IsNullOrWhiteSpace([string]$s)) { $s = $Key }

  $fmt = @()
  if ($null -ne $FormatArgs) { $fmt = @($FormatArgs) }
  if ($fmt.Length -gt 0) {
    try {
      if ($null -ne $s) {
        return ([string]$s -f $fmt)
      }
    }
    catch { }
  }
  return [string]$s
}

