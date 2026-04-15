Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ToolkitPaths {
  param(
    [Parameter(Mandatory = $false)]
    [string]$BaseDir = ""
  )

  if ([string]::IsNullOrWhiteSpace($BaseDir)) { $BaseDir = $PSScriptRoot }

  $cfg = $null
  $cfgPath = Join-Path $BaseDir "config.json"
  if (Test-Path -LiteralPath $cfgPath -PathType Leaf) {
    try {
      $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch { }
  }

  function Get-CfgPathValue([object]$cfgObj, [string]$key, [string]$defaultValue) {
    try {
      if ($null -ne $cfgObj -and $null -ne $cfgObj.Paths) {
        $v = $cfgObj.Paths.$key
        if (-not [string]::IsNullOrWhiteSpace([string]$v)) { return [string]$v }
      }
    }
    catch { }
    return $defaultValue
  }

  function Resolve-FromBase([string]$base, [string]$candidate) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { return $base }
    if ([IO.Path]::IsPathRooted($candidate)) { return $candidate }
    return (Join-Path $base $candidate)
  }

  $oldRel = Get-CfgPathValue $cfg "Old" "old"
  $newRel = Get-CfgPathValue $cfg "New" "new"
  $outputRel = Get-CfgPathValue $cfg "OutputRoot" "output"
  $mergedRel = Get-CfgPathValue $cfg "Merged" ""
  $selfSignedRel = Get-CfgPathValue $cfg "SelfSigned" ""
  $tempRel = Get-CfgPathValue $cfg "Temp" "temp"
  $resourcesRel = Get-CfgPathValue $cfg "Resources" "resources"
  $certConfigRel = Get-CfgPathValue $cfg "CertConfig" "CertConfig.psd1"
  $acmeWebRoot   = Get-CfgPathValue $cfg "AcmeWebRoot" ""

  $oldAbs = Resolve-FromBase $BaseDir $oldRel
  $newAbs = Resolve-FromBase $BaseDir $newRel
  $outputAbs = Resolve-FromBase $BaseDir $outputRel
  $tempAbs = Resolve-FromBase $BaseDir $tempRel
  $resourcesAbs = Resolve-FromBase $BaseDir $resourcesRel
  $certConfigAbs = Resolve-FromBase $BaseDir $certConfigRel

  if ([string]::IsNullOrWhiteSpace($mergedRel)) {
    $mergedAbs = Join-Path $outputAbs "merged"
  }
  else {
    $mergedAbs = Resolve-FromBase $BaseDir $mergedRel
  }

  if ([string]::IsNullOrWhiteSpace($selfSignedRel)) {
    $selfSignedAbs = Join-Path $outputAbs "self-signed"
  }
  else {
    $selfSignedAbs = Resolve-FromBase $BaseDir $selfSignedRel
  }

  $toolsOpenSsl = ""
  try {
    if ($null -ne $cfg -and $null -ne $cfg.Tools) {
      $v = $cfg.Tools.OpenSsl
      if (-not [string]::IsNullOrWhiteSpace([string]$v)) { $toolsOpenSsl = [string]$v }
    }
  }
  catch { }

  return [PSCustomObject]@{
    Old             = $oldAbs
    New             = $newAbs
    OutputRoot      = $outputAbs
    Temp            = $tempAbs
    Resources       = $resourcesAbs
    CertConfig      = $certConfigAbs
    Merged          = $mergedAbs
    SelfSigned      = $selfSignedAbs
    LegacyMergedNew = (Join-Path $mergedAbs "new")
    MergedOld       = (Join-Path $mergedAbs "old")
    OldName         = [IO.Path]::GetFileName($oldAbs.TrimEnd('\','/'))
    NewName         = [IO.Path]::GetFileName($newAbs.TrimEnd('\','/'))
    ToolsOpenSsl    = $toolsOpenSsl
    BinDir          = (Join-Path $BaseDir "utils\bin")
    AcmeWebRoot     = $acmeWebRoot
  }
}

function Resolve-OpenSsl {
  param(
    [string]$Explicit = "",
    [object]$ToolkitPaths = $null
  )

  if (-not [string]::IsNullOrWhiteSpace($Explicit) -and (Test-Path -LiteralPath $Explicit -PathType Leaf)) {
    return $Explicit
  }

  $binDir = ""
  $cfgPath = ""
  if ($null -ne $ToolkitPaths) {
    if (-not [string]::IsNullOrWhiteSpace($ToolkitPaths.BinDir)) {
      $binDir = $ToolkitPaths.BinDir
    }
    if (-not [string]::IsNullOrWhiteSpace($ToolkitPaths.ToolsOpenSsl)) {
      $cfgPath = $ToolkitPaths.ToolsOpenSsl
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($binDir)) {
    $local = Join-Path $binDir "openssl.exe"
    if (Test-Path -LiteralPath $local -PathType Leaf) { return $local }
  }

  if (-not [string]::IsNullOrWhiteSpace($cfgPath) -and (Test-Path -LiteralPath $cfgPath -PathType Leaf)) {
    return $cfgPath
  }

  $gitDefault = "C:\Program Files\Git\usr\bin\openssl.exe"
  if (Test-Path -LiteralPath $gitDefault -PathType Leaf) { return $gitDefault }

  $cmd = Get-Command openssl -ErrorAction SilentlyContinue
  if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
    return $cmd.Source
  }

  return ""
}
