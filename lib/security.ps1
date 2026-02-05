
# Security helper functions
# Extracted from Get-CertificateInfo.ps1 to be shared with Merge-CertificateChain.ps1

function Find-PassFile([string]$dir) {
    # 誤検出防止のため、パスワードファイル名は固定（推奨: passphrase.txt）
    # Note: $FixedPassFileName needs to be defined in the caller scope or passed in.
    # For safety, we default it if not found, checking via Get-Variable to avoid strict mode errors.
    $name = "passphrase.txt"
    $val = Get-Variable -Name "FixedPassFileName" -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $val) { $name = $val }
    
    $fixed = Join-Path $dir $name
    if (Test-Path -LiteralPath $fixed -PathType Leaf) { return $fixed }
    return ""
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

function With-TempPassFile([string]$passphrase, [scriptblock]$action) {
    if ([string]::IsNullOrWhiteSpace($passphrase)) {
        return & $action ""
    }
    $tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), ("ssl_maker_pass_{0}.txt" -f ([Guid]::NewGuid().ToString("N"))))
    try {
        Set-Content -LiteralPath $tmp -Value $passphrase -NoNewline -Encoding ASCII
        return & $action $tmp
    }
    finally {
        Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $tmp
    }
}

function Collect-Passphrases([string[]]$passFiles) {
    $phrases = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($passFiles)) {
        $p = Get-Passphrase $f
        if (-not [string]::IsNullOrWhiteSpace($p)) { $phrases.Add($p) | Out-Null }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:PASS_FILE)) {
        $p = Get-Passphrase $env:PASS_FILE
        if (-not [string]::IsNullOrWhiteSpace($p)) { $phrases.Add($p) | Out-Null }
    }
    return ($phrases | Select-Object -Unique)
}

function Test-KeyEncrypted([string]$keyPath) {
    try {
        $head = @(Get-Content -LiteralPath $keyPath -TotalCount 40 -ErrorAction Stop)
    }
    catch {
        return $false
    }
    $text = ($head -join "`n")
    if ($text -match "BEGIN ENCRYPTED PRIVATE KEY") { return $true }
    if ($text -match "Proc-Type:\s*4,ENCRYPTED") { return $true }
    if ($text -match "\bENCRYPTED\b") { return $true }
    return $false
}
