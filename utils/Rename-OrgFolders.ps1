
# 自動リネームツール：ドメイン名から組織名を取得してフォルダ名を変更する
# 対象範囲：old, new, merged ディレクトリ
# ロジック：3つのディレクトリ内の同名フォルダを一括で変更し、整合性を保つ
# 依存：curl.exe (Windows 標準搭載または別途インストール済みであること)

param(
    [switch]$AutoYes = $false, # 自動確認（注意して使用してください）
    [switch]$DryRun = $false   # 試走のみ（変更は行いません）
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$runtimeModule = Join-Path $PSScriptRoot "lib\runtime.ps1"
if (Test-Path -LiteralPath $runtimeModule -PathType Leaf) { . $runtimeModule }
Assert-ToolkitPowerShell

. (Join-Path $PSScriptRoot "lib\defaults.ps1")

$ToolkitRoot = Split-Path -Parent $PSScriptRoot

$rootPath = $ToolkitRoot
$pathsModule = Join-Path $PSScriptRoot "lib\paths.ps1"
if (Test-Path -LiteralPath $pathsModule -PathType Leaf) { . $pathsModule }
$ToolkitPaths = if (Get-Command Get-ToolkitPaths -ErrorAction SilentlyContinue) { Get-ToolkitPaths -BaseDir $ToolkitRoot } else { $null }
$oldDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.Old)) { $ToolkitPaths.Old } else { Join-Path $rootPath "old" }
$newDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.New)) { $ToolkitPaths.New } else { Join-Path $rootPath "new" }
$mergedDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.Merged)) { $ToolkitPaths.Merged } else { Join-Path $rootPath "output\merged" }
$dirsToCheck = @($oldDir, $newDir, $mergedDir)

function Resolve-DirPath([string]$dirItem) {
    if ([IO.Path]::IsPathRooted($dirItem)) { return $dirItem }
    return (Join-Path $rootPath $dirItem)
}

function ConvertTo-SafeFileName([string]$name) {
    # ファイル名に使用できない文字を置換
    $name = $name -replace '[\\/:*?"<>|]', '_'
    # 空白をアンダースコアに置換 (ユーザー要望)
    return $name -replace '\s+', '_'
}

function Test-ContainsJapanese([string]$text) {
    # 簡易チェック: ひらがな、カタカナ、漢字が含まれているか
    return $text -match "[\p{IsHiragana}\p{IsKatakana}\p{IsCJKUnifiedIdeographs}]"
}

function Resolve-OrgName([string]$name) {
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }

    # 1. ブロックリストチェック
    $blocklist = @("Error", "The request could not be satisfied", "403 Forbidden", "404 Not Found", "500 Internal Server Error", "Access Denied")
    foreach ($b in $blocklist) {
        if ($name -match $b) { return $null }
    }

    # 2. 日本語優先ロジック
    $parts = $name -split "[\s_|\-]+"
    $jpParts = @()
    foreach ($p in $parts) {
        if (Test-ContainsJapanese $p) {
            $jpParts += $p
        }
    }

    if ($jpParts.Count -gt 0) {
        return ($jpParts -join "_")
    }

    return $name
}

function Get-WebInfo([string]$url) {
    try {
        # 1. curl -vI を使用して証明書情報を取得
        $pInfo = New-Object System.Diagnostics.ProcessStartInfo
        $pInfo.FileName = "curl.exe"
        $pInfo.Arguments = "-vI -L --insecure --max-time 5 `"$url`""
        $pInfo.RedirectStandardError = $true
        $pInfo.RedirectStandardOutput = $true
        $pInfo.UseShellExecute = $false
        $pInfo.CreateNoWindow = $true
        $pInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        
        $p = [System.Diagnostics.Process]::Start($pInfo)
        
        $errReader = New-Object System.IO.StreamReader($p.StandardError.BaseStream, [System.Text.Encoding]::UTF8)
        $stderr = $errReader.ReadToEnd()
        $errReader.Close()
        
        $p.WaitForExit()

        $info = @{}

        # curl のデバッグ出力から subject を解析
        # O=... または CN=... を取得
        if ($stderr -match "subject:.*O=([^;,/\n\r]+)") {
            $matched = $matches[1].Trim(' "')
            if (-not [string]::IsNullOrWhiteSpace($matched)) {
                $info["CertOrg"] = $matched
            }
        }
        if (-not $info.ContainsKey("CertOrg") -and $stderr -match "subject:.*CN=([^;,/\n\r]+)") {
            $matchedCN = $matches[1].Trim(' "')
            if (-not [string]::IsNullOrWhiteSpace($matchedCN)) {
                $info["CertOrg"] = $matchedCN
            }
        }

        # 証明書から組織名が取得できなかった場合、HTML Title を試行
        if (-not $info.ContainsKey("CertOrg")) {
             
            $pInfo2 = New-Object System.Diagnostics.ProcessStartInfo
            $pInfo2.FileName = "curl.exe"
            $pInfo2.Arguments = "-L --insecure --max-time 5 `"$url`""
            $pInfo2.RedirectStandardOutput = $true
            $pInfo2.UseShellExecute = $false
            $pInfo2.CreateNoWindow = $true
            $pInfo2.StandardOutputEncoding = [System.Text.Encoding]::UTF8
             
            $p2 = [System.Diagnostics.Process]::Start($pInfo2)
             
            $outReader = New-Object System.IO.StreamReader($p2.StandardOutput.BaseStream, [System.Text.Encoding]::UTF8)
            $body = $outReader.ReadToEnd()
            $outReader.Close()
            $p2.WaitForExit()
             
            if ($body) {
                $html = [string]$body -join " "
                if ($html -match "<title>(.*?)</title>") {
                    $title = $matches[1].Trim()
                    $title = $title -replace " - .*$", "" 
                    $title = $title -replace " \| .*$", ""
                    $info["Title"] = $title
                }
            }
        }
        
        if ($info.Keys.Count -gt 0) { return $info }
    }
    catch {}
    return $null
}

function Get-RootDomain([string]$domain) {
    if ([string]::IsNullOrWhiteSpace($domain)) { return $domain }
    $parts = $domain -split "\."
    $count = $parts.Count
    if ($count -le 2) { return $domain }

    $special2nd = @("ac", "co", "go", "or", "ne", "gr", "ed", "lg")
    $tld = $parts[$count - 1]
    $sld = $parts[$count - 2]

    if ($tld -eq "jp" -and $special2nd -contains $sld) {
        if ($count -ge 3) {
            return ($parts[($count - 3)..($count - 1)] -join ".")
        }
    }
    return ($parts[($count - 2)..($count - 1)] -join ".")
}

function Get-WhoisInfo([string]$domain) {
    # JPRS Web WHOIS 検索
    $url = "https://whois.jprs.jp/?type=DOM&key=$domain"
    
    try {
        $pInfo = New-Object System.Diagnostics.ProcessStartInfo
        $pInfo.FileName = "curl.exe"
        $pInfo.Arguments = "-L --insecure --max-time 10 -A `"Mozilla/5.0`" `"$url`""
        $pInfo.RedirectStandardOutput = $true
        $pInfo.UseShellExecute = $false
        $pInfo.CreateNoWindow = $true
        $pInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    
        $p = [System.Diagnostics.Process]::Start($pInfo)
        $reader = New-Object System.IO.StreamReader($p.StandardOutput.BaseStream, [System.Text.Encoding]::UTF8)
        $body = $reader.ReadToEnd()
        $reader.Close()
        $p.WaitForExit()
        
        # JPRS HTML解析
        $jpName = $null
        
        # 正規表現を緩和: [Label] ... (タグ/スペース) ... Value
        
        # 1. 日本語「登録者名」または「組織名」（日本語優先）
        # 例: [組織名] ... <br> ... 独立行政法人...
        if ($body -match "(?s)\[(?:登録者名|組織名)\](?:<[^>]+>|\s)+([^<\r\n]+)") {
            $val = $matches[1].Trim()
            if (-not [string]::IsNullOrWhiteSpace($val)) { $jpName = $val }
        }
        
        if ($jpName) {
            # JPRS自体のフッター等を誤検知していないかチェック
            if ($jpName -notmatch "日本レジストリサービス") {
                return $jpName
            }
        }
        
        # 3. 英語「Organization」
        if ($body -match "(?s)\[Organization\](?:<[^>]+>|\s)+([^<\r\n]+)") {
            $val = $matches[1].Trim()
            if ($val -notmatch "Japan Registry Services") {
                return $val
            }
        }
    }
    catch {}
    
    return $null
}

function Get-OrgFromLocalCert([string]$domain) {
    $openssl = Resolve-OpenSsl -ToolkitPaths $ToolkitPaths
    if ([string]::IsNullOrWhiteSpace($openssl)) { return $null }
    
    foreach ($d in $dirsToCheck) {
        $searchPath = Resolve-DirPath $d
        if (-not (Test-Path $searchPath)) { continue }
        
        $certs = Get-ChildItem -LiteralPath $searchPath -Recurse -File -Include $__CertPatterns -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match [regex]::Escape($domain) -or $_.Directory.Name -eq $domain }
        
        foreach ($cert in $certs) {
            try {
                $subj = & $openssl x509 -in $cert.FullName -noout -subject 2>&1
                if ($LASTEXITCODE -ne 0) { continue }
                
                # 提取 O= 组织名
                if ($subj -match "O\s*=\s*([^,/\r\n]+)") {
                    $orgName = $matches[1].Trim()
                    $validName = Resolve-OrgName $orgName
                    if ($validName) {
                        return $validName
                    }
                }
            }
            catch { }
        }
    }
    return $null
}

function Find-OrgName([string]$domain) {
    $fallbackName = $null
    
    # 1. 先从本地证书文件读取（作为英文备用）
    Write-Host "    Checking local certificates..." -NoNewline -ForegroundColor Gray
    $localOrg = Get-OrgFromLocalCert $domain
    if ($localOrg) {
        if (Test-ContainsJapanese $localOrg) {
            # 如果证书已经是日文，直接使用
            Write-Host " [LOCAL HIT/JP] -> $localOrg" -ForegroundColor Green
            return @{ Name = $localOrg }
        }
        else {
            # 英文名作为备用，继续寻找日文
            Write-Host " [LOCAL/EN] -> $localOrg" -ForegroundColor Yellow
            $fallbackName = $localOrg
        }
    }
    else {
        Write-Host " (not found)" -ForegroundColor DarkGray
    }
    
    # 2. 优先查询 WHOIS (JPRS) 获取日文名
    $root = Get-RootDomain $domain
    if ($root -match "\.jp$") {
        Write-Host "    Probing WHOIS (JPRS): $root ..." -NoNewline -ForegroundColor Gray
        try {
            $whoisName = Get-WhoisInfo $root
            if ($whoisName) {
                $validName = Resolve-OrgName $whoisName
                if ($validName -and (Test-ContainsJapanese $validName)) {
                    Write-Host " [WHOIS HIT/JP] -> $validName" -ForegroundColor Green
                    return @{ Name = $validName }
                }
                elseif ($validName -and -not $fallbackName) {
                    # 如果没有证书英文名，使用 WHOIS 结果作为备用
                    $fallbackName = $validName
                    Write-Host " [WHOIS/EN] -> $validName" -ForegroundColor Yellow
                }
                else {
                    Write-Host "" -ForegroundColor DarkGray
                }
            }
            else {
                Write-Host "" -ForegroundColor DarkGray
            }
        }
        catch { 
            Write-Host " [Error]" -ForegroundColor Red
        }
    }
    
    # 3. 网络查询 (网站证书/Title) - 寻找日文名
    $parts = $domain -split "\."
    for ($i = 0; $i -lt ($parts.Count - 1); $i++) {
        $checkDomain = ($parts[$i..($parts.Count - 1)] -join ".")
        Write-Host "    Probing: $checkDomain ..." -NoNewline -ForegroundColor Gray
        
        try {
            $res = Get-WebInfo ("https://" + $checkDomain)
            if ($res) {
                $candidate = if ($res.ContainsKey("CertOrg")) { $res.CertOrg } else { $res.Title }
                $validName = Resolve-OrgName $candidate
                
                if ($validName -and (Test-ContainsJapanese $validName)) {
                    Write-Host " [HIT/JP] -> $validName" -ForegroundColor Green
                    return @{ Name = $validName }
                }
                elseif ($validName) {
                    Write-Host " [EN: $validName]" -ForegroundColor DarkGray
                    if (-not $fallbackName) { $fallbackName = $validName }
                }
            }
        }
        catch {
            Write-Host " [Error]" -ForegroundColor Red
        }
        
        try {
            $resWWW = Get-WebInfo ("https://www." + $checkDomain)
            if ($resWWW) { 
                $candidate = if ($resWWW.ContainsKey("CertOrg")) { $resWWW.CertOrg } else { $resWWW.Title }
                $validName = Resolve-OrgName $candidate

                if ($validName -and (Test-ContainsJapanese $validName)) {
                    Write-Host " (www) [HIT/JP] -> $validName" -ForegroundColor Green
                    return @{ Name = $validName }
                }
                elseif ($validName) {
                    Write-Host " (www) [EN: $validName]" -ForegroundColor DarkGray
                    if (-not $fallbackName) { $fallbackName = $validName }
                }
            }
        }
        catch {
            Write-Host " (www) [Error]" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    # 4. 如果找到了英文名作为备用，使用它
    if ($fallbackName) {
        Write-Host "    Using fallback (EN): $fallbackName" -ForegroundColor Cyan
        return @{ Name = $fallbackName }
    }
    
    return $null
}

# 2. 全ディレクトリをスキャン
Write-Host "Scanning directories..." -ForegroundColor Cyan
$allDomains = @()
foreach ($d in $dirsToCheck) {
    $path = Resolve-DirPath $d
    if (Test-Path $path) {
        $subdirs = Get-ChildItem -LiteralPath $path -Directory
        foreach ($s in $subdirs) {
            $allDomains += $s.Name
        }
    }
}
$uniqueDomains = $allDomains | Select-Object -Unique | Sort-Object

if ($uniqueDomains.Count -eq 0) {
    Write-Host "No folders found." -ForegroundColor Yellow
    exit
}

# 3. 個別に処理
foreach ($domain in $uniqueDomains) {
    # 既にリネーム済み (例: "北見工業大学 (jinji)") や、ドメインでないフォルダはスキップ
    if ($domain -notmatch "\." -or $domain -match ".+\s\(.+\)$") {
        continue
    }

    Write-Host "`nProcessing: $domain" -ForegroundColor Cyan
    
    try {
        $info = Find-OrgName $domain
    }
    catch {
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        continue
    }
    
    if (-not $info) {
        Write-Host "  No organization info found." -ForegroundColor DarkGray
        continue
    }

    $orgName = $info.Name
    $orgName = ConvertTo-SafeFileName $orgName
    $orgName = $orgName.Trim('"').Trim("'")

    if ($orgName -eq $domain) {
        Write-Host "  Org name is same as domain, skipping."
        continue
    }
    
    $domainParts = $domain -split "\."
    $hostPart = $domainParts[0]
    
    $newName = "{0} ({1})" -f $orgName, $hostPart

    if ($orgName -eq $domain) {
        Write-Host "  Org name is same as domain, skipping."
        continue
    }

    Write-Host "  Found: $orgName" -ForegroundColor Yellow
    Write-Host "  Proposal: $domain -> $newName" -ForegroundColor Green

    if ($DryRun) {
        Write-Host "  [DryRun] Would rename in all folders." -ForegroundColor Magenta
        continue
    }
    
    if (-not $AutoYes) {
        $confirm = Read-Host "  Rename in all folders? (y/n)"
        if ($confirm -ne "y") { continue }
    }

    foreach ($type in $dirsToCheck) {
        $basePath = Resolve-DirPath $type
        $oldPath = Join-Path $basePath $domain
        $newPath = Join-Path $basePath $newName
        
        if (Test-Path -LiteralPath $oldPath) {
            if (Test-Path -LiteralPath $newPath) {
                Write-Host "    Skipping $type/$domain : Destination exists." -ForegroundColor Red
            }
            else {
                Rename-Item -LiteralPath $oldPath -NewName $newName
                Write-Host "    Renamed: $type/$domain" -ForegroundColor Gray
            }
        }
    }
}

Write-Host "`nDone." -ForegroundColor Green


