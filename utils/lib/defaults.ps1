$__DefaultLang = "en"

function Import-SafeDataFile {
  param([Parameter(Mandatory)][string]$LiteralPath)
  $params = @{ LiteralPath = $LiteralPath }
  $cmdInfo = Get-Command Import-PowerShellDataFile -ErrorAction SilentlyContinue
  if ($null -ne $cmdInfo -and $cmdInfo.Parameters.ContainsKey('SkipLimitCheck')) {
    $params['SkipLimitCheck'] = $true
  }
  Import-PowerShellDataFile @params
}
