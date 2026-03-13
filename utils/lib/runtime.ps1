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

function Initialize-ToolkitConsoleEncoding {
  try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $script:OutputEncoding = [Console]::OutputEncoding
  }
  catch { }
}
