<#
.SYNOPSIS
Creates a Server List TSV file from CSRs (supports legacy import and manual edit preservation).

.DESCRIPTION
Scans the 'new' directory for .csr files and generates a TSV file.
- Imports Legacy Data from 'old/' (manual fields like Contact/Software).
- Preserves manual edits if 'server_list.tsv' already exists.
- Interactive mode for new records defaults.
- Safety: Prompts before overwriting and creates backups.
   - If CN is new but present in Legacy Data, prompts user to inherit legacy values.
   - If completely new, applies Global Defaults (interactive).
4. Validates OpenSSL output robustly.

.PARAMETER Path
The root directory to search for .csr files. Default is ".\new".

.PARAMETER OldPath
The root directory to search for legacy .tsv files. Default is ".\old".

.PARAMETER TsvFile
The target TSV file path. Default is ".\server_list.tsv".

.PARAMETER Interactive
If set (default), prompts for defaults and legacy confirmation.
#>
param(
    [string]$Path = ".\new",
    [string]$OldPath = ".\old",
    # TsvFile not needed, filename deduced from Org name
    [switch]$Interactive = $true,
    [Parameter(Mandatory = $false)]
    [ValidateSet("ja", "zh", "en")]
    [string]$Lang = "ja",
    
    # Defaults for automation/testing
    [string]$DefaultSoftware = $null,
    [string]$DefaultContact = $null,
    [string]$DefaultTerm = $null,
    [string]$DefaultSystemId = $null,
    [string]$LegacyAction = "Ask", # Ask, Yes, No
    
    [switch]$Overwrite = $false # If set, skips prompt and backs up existing file
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSVersion.Major -lt 7) {
  Write-Host "[ERROR] PowerShell 7.x or later is required. / PowerShell 7.x 以上が必要です。" -ForegroundColor Red
  Write-Host "        Current: $($PSVersionTable.PSVersion)" -ForegroundColor Red
  Write-Host "        https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Yellow
  exit 1
}

$OpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe"
if (-not (Test-Path $OpenSsl)) { $OpenSsl = "openssl" }

# Define Schema
$Columns = @("Common Name", "SAN Config", "Software", "Contact", "Subject DN", "Term", "System ID", "Notes")

# --- Helper Functions ---

function Invoke-OpenSsl([string[]]$OpenSslArgs) {
    try {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $OpenSsl
        $pinfo.RedirectStandardError = $true; $pinfo.RedirectStandardOutput = $true; $pinfo.UseShellExecute = $false
        foreach ($a in $OpenSslArgs) { $pinfo.ArgumentList.Add($a) }
        $pinfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $p = New-Object System.Diagnostics.Process; $p.StartInfo = $pinfo
        $p.Start() | Out-Null
        $stdout = $p.StandardOutput.ReadToEnd(); $p.WaitForExit()
        return @($stdout -split "\r?\n" | Where-Object { $_.Trim() -ne "" })
    }
    catch { return @() }
}

function Get-CsrInfo([string]$csrPath) {
    # Extract Subject DN
    $subjRaw = @(Invoke-OpenSsl @("req", "-in", $csrPath, "-noout", "-subject", "-nameopt", "RFC2253"))
    $subjectDn = ""; $cn = ""
    foreach ($line in $subjRaw) {
        if ($line -match "^subject=(.*)") {
            $subjectDn = $matches[1]
            if ($subjectDn -match "(?:^|[,/])CN=([^,]+)") { $cn = $matches[1] }
        }
    }

    # Extract SANs
    $textRaw = @(Invoke-OpenSsl @("req", "-in", $csrPath, "-noout", "-text", "-nameopt", "RFC2253"))
    $sanList = @()
    $inSanBlock = $false
    foreach ($line in $textRaw) {
        if ($line -match "X509v3 Subject Alternative Name") { $inSanBlock = $true; continue }
        if ($inSanBlock) {
            if ($line -match "^\s*(X509v3|Signature Algorithm)") { $inSanBlock = $false; continue }
            if ($line -match "DNS:|IP Address:|IP:") {
                $entries = $line -split ",\s*"
                foreach ($e in $entries) {
                    if ($e -match "(DNS:|IP Address:|IP:)(.*)") {
                        $val = $matches[2].Trim()
                        if ($sanList -notcontains $val) { $sanList += $val }
                    }
                }
            }
        }
    }
    
    $sanParts = @("NSName=$cn"); foreach ($s in $sanList) { $sanParts += "dNSName=$s" }
    $sanConfig = $sanParts -join ","

    return [PSCustomObject]@{ CN = $cn; Info = @{ "Common Name" = $cn; "Subject DN" = $subjectDn; "SAN Config" = $sanConfig } }
}

function Build-LegacyIndex([string]$rootPath) {
    Write-Host "Scanning '$rootPath' for legacy TSV data..." -ForegroundColor Cyan
    $index = @{}
    if (-not (Test-Path $rootPath)) { return $index }
    
    $files = Get-ChildItem -LiteralPath $rootPath -Recurse -Filter *.tsv -File
    foreach ($f in $files) {
        try {
            # HOKKAIDO FORMAT PARSING
            # Read all lines
            $lines = Get-Content $f.FullName -Encoding UTF8 | Where-Object { $_.Trim() -ne "" }
            if ($lines.Count -ge 1) {
                # Line 1: Subject, Term, SystemID
                $parts1 = $lines[0] -split "`t"
                $term = if ($parts1.Count -gt 1) { $parts1[1].Trim() } else { "" }
                $sysId = if ($parts1.Count -gt 2) { $parts1[2].Trim() } else { "" }
                
                # Last Line: SAN, CN, Software, Contact
                $lastLine = $lines[$lines.Count - 1]
                $parts2 = $lastLine -split "`t"
                # Assuming index: 0=SAN, 1=CN, 2=Software, 3=Contact
                $cn = if ($parts2.Count -gt 1) { $parts2[1].Trim() } else { "" }
                $soft = if ($parts2.Count -gt 2) { $parts2[2].Trim() } else { "" }
                $contact = if ($parts2.Count -gt 3) { $parts2[3].Trim() } else { "" }
                
                if (-not [string]::IsNullOrEmpty($cn)) {
                    $index[$cn] = @{
                        "Software"  = $soft
                        "Contact"   = $contact
                        "Term"      = $term
                        "System ID" = $sysId
                        "Source"    = $f.Name
                    }
                }
            }
        }
        catch { Write-Host "Failed to parse legacy file: $($f.Name)" -ForegroundColor DarkGray }
    }
    Write-Host "Indexed $($index.Count) legacy records." -ForegroundColor Green
    return $index
}

# --- Main Logic ---

$legacyIndex = Build-LegacyIndex $OldPath
$defaults = @{ "Software" = "nginx"; "Contact" = ""; "Term" = "1"; "System ID" = "" }

if ($Interactive) {
    Write-Host "`n[Interactive Setup] Defaults for completely NEW records." -ForegroundColor Cyan
    $p = Read-Host "Default Software Name [nginx]"; if ($p) { $defaults.Software = $p }
    $p = Read-Host "Default Contact Person       "; if ($p) { $defaults.Contact = $p }
    $p = Read-Host "Default Term                 "; if ($p) { $defaults.Term = $p }
    $p = Read-Host "Default System ID            "; if ($p) { $defaults.'System ID' = $p }
}
else {
    if ($DefaultSoftware) { $defaults.Software = $DefaultSoftware }
    if ($DefaultContact) { $defaults.Contact = $DefaultContact }
    if ($DefaultTerm) { $defaults.Term = $DefaultTerm }
    if ($DefaultSystemId) { $defaults.'System ID' = $DefaultSystemId }
}

$existingData = @{}
if (Test-Path $TsvFile) {
    Write-Host "Loading existing server_list.tsv..."
    Import-Csv -LiteralPath $TsvFile -Delimiter "`t" | ForEach-Object {
        $cn = $_.'Common Name'
        if ($cn) { $existingData[$cn] = $_ }
    }
}

Write-Host "Scanning '$Path' for .csr files..."
$csrFiles = @(Get-ChildItem -LiteralPath $Path -Recurse -Filter *.csr -File)

$mergedList = New-Object System.Collections.Generic.List[object]
$processedCNs = @()

foreach ($f in $csrFiles) {
    $infoObj = Get-CsrInfo $f.FullName
    $cn = $infoObj.CN
    $autoData = $infoObj.Info
    if (-not $cn) { continue }

    $finalRow = New-Object psobject
    $processedCNs += $cn

    if ($existingData.ContainsKey($cn)) {
        # CASE 1: Exists in TSV -> Preserve edits
        $oldRow = $existingData[$cn]
        foreach ($col in $Columns) {
            if ($col -in @("Common Name", "Subject DN", "SAN Config")) {
                $finalRow | Add-Member -MemberType NoteProperty -Name $col -Value $autoData[$col]
            }
            else {
                $finalRow | Add-Member -MemberType NoteProperty -Name $col -Value $oldRow.$col
            }
        }
    }
    elseif ($legacyIndex.ContainsKey($cn)) {
        # CASE 2: New in TSV, but found in Legacy -> Prompt
        $leg = $legacyIndex[$cn]
        $useLeg = $false
        
        Write-Host "`n[Match Found] $cn" -ForegroundColor Cyan
        Write-Host "  Legacy Data: Contact='$($leg.Contact)', Software='$($leg.Software)', Term='$($leg.Term)'" -ForegroundColor Gray
        
        if ($Interactive -and $LegacyAction -eq "Ask") {
            $choice = Read-Host "  Use this legacy data? (Y/n/Edit)"
            if ($choice -eq "n") { 
                $useLeg = $false 
            }
            elseif ($choice -match "^e") {
                $useLeg = $true
                $p = Read-Host "  Contact  [$($leg.Contact)]"; if ($p) { $leg.Contact = $p }
                $p = Read-Host "  Software [$($leg.Software)]"; if ($p) { $leg.Software = $p }
            }
            else { 
                $useLeg = $true 
            }
        }
        elseif ($LegacyAction -eq "No") {
            $useLeg = $false
        }
        else {
            $useLeg = $true # Yes or Default
        }

        foreach ($col in $Columns) {
            $val = ""
            if ($autoData.ContainsKey($col)) { 
                $val = $autoData[$col] 
            }
            elseif ($useLeg -and $leg.ContainsKey($col)) {
                $val = $leg[$col]
            }
            elseif ($defaults.ContainsKey($col)) {
                $val = $defaults[$col]
            }
            $finalRow | Add-Member -MemberType NoteProperty -Name $col -Value $val
        }
    }
    else {
        # CASE 3: Completely New -> Defaults
        foreach ($col in $Columns) {
            $val = ""
            if ($autoData.ContainsKey($col)) { $val = $autoData[$col] }
            elseif ($defaults.ContainsKey($col)) { $val = $defaults[$col] }
            $finalRow | Add-Member -MemberType NoteProperty -Name $col -Value $val
        }
    }
    $mergedList.Add($finalRow)
}

# Orphans
foreach ($cn in $existingData.Keys) {
    if ($processedCNs -notcontains $cn) { $mergedList.Add($existingData[$cn]) }
}

$sortedList = $mergedList | Sort-Object "Common Name"

# --- Safety & Backup ---
if (Test-Path $TsvFile) {
    if ($Overwrite) {
        # Auto-Backup mode
        $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $base = [System.IO.Path]::GetFileNameWithoutExtension($TsvFile)
        $ext = [System.IO.Path]::GetExtension($TsvFile)
        $bakName = "$base.bak_$ts$ext"
        $bakPath = Join-Path (Split-Path $TsvFile -Parent) $bakName
        
        Write-Host "Backing up existing file to: $bakName" -ForegroundColor Gray
        Rename-Item -LiteralPath $TsvFile -NewName $bakName -Force
    }
    elseif ($Interactive) {
        # Prompt mode
        Write-Host "`n[File Exists] '$TsvFile'" -ForegroundColor Yellow
        $choice = Read-Host "  Overwrite this file? (Backups will be created) [y/N]"
        if ($choice -notmatch "^[yY]") {
            Write-Host "Operation cancelled by user." -ForegroundColor Yellow
            exit 0
        }
        
        # User accepted -> Backup
        $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $base = [System.IO.Path]::GetFileNameWithoutExtension($TsvFile)
        $ext = [System.IO.Path]::GetExtension($TsvFile)
        $bakName = "$base.bak_$ts$ext"
        $bakPath = Join-Path (Split-Path $TsvFile -Parent) $bakName
        
        Write-Host "Backing up existing file to: $bakName" -ForegroundColor Gray
        Rename-Item -LiteralPath $TsvFile -NewName $bakName -Force
    }
    else {
        # Non-interactive and no -Overwrite -> Fail safe
        Write-Error "Target file '$TsvFile' exists. Specify -Overwrite to proceed."
        exit 1
    }
}

Write-Host "`nSaving $($sortedList.Count) records to $TsvFile..." -ForegroundColor Cyan
$sortedList | Select-Object $Columns | Export-Csv -LiteralPath $TsvFile -Delimiter "`t" -NoTypeInformation -Encoding UTF8
Write-Host "Done." -ForegroundColor Green


