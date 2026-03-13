Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "runtime.ps1")
Assert-ToolkitPowerShell

. (Join-Path $PSScriptRoot "defaults.ps1")

function Get-AvailableLanguages {
  param(
    [Parameter(Mandatory = $false)]
    [string]$BaseDir = ""
  )
  if ([string]::IsNullOrWhiteSpace($BaseDir)) { $BaseDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
  $resDir = Join-Path $BaseDir "resources"
  $langs = @()
  $files = @(Get-ChildItem -LiteralPath $resDir -Filter "strings.*.psd1" -File -ErrorAction SilentlyContinue)
  foreach ($f in $files) {
    if ($f.Name -match '^strings\.([a-z]{2,})\.psd1$') {
      $code = $matches[1]
      try {
        $data = Import-SafeDataFile -LiteralPath $f.FullName
        $displayName = if ($data.ContainsKey("Language.DisplayName")) { $data["Language.DisplayName"] } else { $code }
      }
      catch { $displayName = $code }
      $langs += [PSCustomObject]@{ Code = $code; DisplayName = $displayName }
    }
  }
  $primary = @($langs | Where-Object { $_.Code -eq $__DefaultLang })
  $others = @($langs | Where-Object { $_.Code -ne $__DefaultLang } | Sort-Object Code)
  return @($primary + $others)
}

function Initialize-I18n {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Lang = "",

    [Parameter(Mandatory = $false)]
    [string]$BaseDir = ""
  )

  if ([string]::IsNullOrWhiteSpace($Lang)) { $Lang = $__DefaultLang }
  if ([string]::IsNullOrWhiteSpace($BaseDir)) { $BaseDir = $PSScriptRoot }
  $resDir = Join-Path $BaseDir "resources"
  $jaPath = Join-Path $resDir "strings.ja.psd1"
  $langPath = Join-Path $resDir ("strings.{0}.psd1" -f $Lang)

  if (-not (Test-Path -LiteralPath $jaPath -PathType Leaf)) {
    throw ("リソースファイルが見つかりません: {0}" -f $jaPath)
  }

  $ja = Import-SafeDataFile -LiteralPath $jaPath
  $langTable = @{}
  if ($Lang -ne "ja" -and (Test-Path -LiteralPath $langPath -PathType Leaf)) {
    $langTable = Import-SafeDataFile -LiteralPath $langPath
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

