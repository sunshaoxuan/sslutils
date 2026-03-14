Set-StrictMode -Version Latest

function Assert-ToolkitPowerShell {
  param(
    [Parameter(Mandatory = $false)]
    [string]$CommandHint = ""
  )

  if ($PSVersionTable.PSVersion.Major -ge 7) { return }

  Write-Host "[ERROR] PowerShell 7.x or later is required." -ForegroundColor Red
  Write-Host ("Current version: {0}" -f $PSVersionTable.PSVersion) -ForegroundColor Yellow
  if (-not [string]::IsNullOrWhiteSpace($CommandHint)) {
    Write-Host ("Run with: {0}" -f $CommandHint) -ForegroundColor Cyan
  }
  else {
    Write-Host "Run with PowerShell 7 (pwsh)." -ForegroundColor Cyan
  }
  Write-Host "https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Yellow
  exit 1
}

function Resolve-ToolkitLanguage {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Lang = "",

    [Parameter(Mandatory)]
    [string]$BaseDir,

    [Parameter(Mandatory = $false)]
    [string]$DefaultLang = "en"
  )

  if (-not [string]::IsNullOrWhiteSpace($Lang)) { return $Lang }

  $langFile = Join-Path $BaseDir ".toolkit_lang"
  if (Test-Path -LiteralPath $langFile -PathType Leaf) {
    $saved = (Get-Content -LiteralPath $langFile -Raw -ErrorAction SilentlyContinue).Trim()
    if (-not [string]::IsNullOrWhiteSpace($saved)) { return $saved }
  }

  return $DefaultLang
}

function Save-ToolkitLanguage {
  param(
    [Parameter(Mandatory)]
    [string]$Lang,

    [Parameter(Mandatory)]
    [string]$BaseDir
  )

  if ([string]::IsNullOrWhiteSpace($Lang)) { return }
  $langFile = Join-Path $BaseDir ".toolkit_lang"
  Set-Content -LiteralPath $langFile -Value $Lang -Encoding UTF8 -NoNewline -ErrorAction SilentlyContinue
}

function Initialize-ToolkitConsoleEncoding {
  try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $script:OutputEncoding = [Console]::OutputEncoding
  }
  catch { }
}

function Clear-ToolkitInputBuffer {
  if ($Host.Name -eq "ConsoleHost") {
    try {
      while ([Console]::KeyAvailable) { $null = [Console]::ReadKey($true) }
      return
    }
    catch { }
  }

  try { $host.UI.RawUI.FlushInputBuffer() } catch { }
}

function Wait-ToolkitAnyKey {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Message = "Press any key to continue..."
  )

  Write-Host $Message -NoNewline
  Clear-ToolkitInputBuffer

  if ($Host.Name -eq "ConsoleHost") {
    try {
      $null = [Console]::ReadKey($true)
      Write-Host ""
      return
    }
    catch { }
  }

  try {
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
  }
  catch {
    try { Read-Host | Out-Null } catch { }
  }
  Write-Host ""
}

function Exit-ToolkitWithPause {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Message = "Press any key to continue...",

    [Parameter(Mandatory = $false)]
    [int]$ExitCode = 99
  )

  Write-Host ""
  Wait-ToolkitAnyKey -Message $Message
  exit $ExitCode
}

function Write-ToolkitException {
  param(
    [Parameter(Mandatory)]
    [object]$ErrorRecord,

    [Parameter(Mandatory = $false)]
    [string]$Prefix = "Error"
  )

  $message = ""
  if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
    $message = $ErrorRecord.Exception.Message
  }
  elseif ($null -ne $ErrorRecord -and $null -ne $ErrorRecord.Exception) {
    $message = $ErrorRecord.Exception.Message
  }
  else {
    $message = [string]$ErrorRecord
  }

  Write-Host ("{0}: {1}" -f $Prefix, $message) -ForegroundColor Red
}
