<#
.SYNOPSIS
new フォルダの key, csr, tsv を merged フォルダへ同期

.DESCRIPTION
同一組織の証明書関連ファイル（.key, .csr, .tsv）を
new フォルダから merged/new フォルダへコピーします。
発布・バックアップ時にすべてのファイルが同じ場所にあるようにします。

.EXAMPLE
.\Sync-ToMerged.ps1
対話的に同期を実行

.EXAMPLE
.\Sync-ToMerged.ps1 -AutoYes
確認なしで全て同期
#>

param(
    [switch]$AutoYes = $false,
    [switch]$DryRun = $false,
    [Parameter(Mandatory = $false)]
    [ValidateSet("ja", "zh", "en")]
    [string]$Lang = "ja"
)

$ErrorActionPreference = "Stop"

# UTF-8出力設定
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = [Console]::OutputEncoding
}
catch { }

$newDir = Join-Path $PSScriptRoot "new"
$mergedDir = Join-Path $PSScriptRoot "merged\new"

# i18n
$i18nModule = Join-Path $PSScriptRoot "lib\i18n.ps1"
if (Test-Path -LiteralPath $i18nModule -PathType Leaf) {
    . $i18nModule
    $__i18n = Initialize-I18n -Lang $Lang -BaseDir $PSScriptRoot
}
function T([string]$Key, $ArgList = @()) {
    if ($null -ne $__i18n) {
        $arr = if ($null -eq $ArgList) { @() } else { @($ArgList) }
        return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $arr
    }
    return $Key
}

function Get-OrgMapping {
    # new と merged/new のフォルダ名から組織名をマッピング
    # フォルダ名形式: "組織名 (ホスト名)" または "ドメイン名"
    $mapping = @{}
    
    if (-not (Test-Path $mergedDir)) { return $mapping }
    
    $mergedOrgs = Get-ChildItem -LiteralPath $mergedDir -Directory -ErrorAction SilentlyContinue
    foreach ($org in $mergedOrgs) {
        # "組織名 (ホスト名)" からホスト名を抽出
        if ($org.Name -match "^(.+)\s+\(([^)]+)\)$") {
            $hostPart = $Matches[2]
            $mapping[$hostPart] = $org.FullName
        }
        # ドメイン名そのままの場合
        elseif ($org.Name -match "\.") {
            $domainParts = $org.Name -split "\."
            $hostPart = $domainParts[0]
            $mapping[$hostPart] = $org.FullName
            $mapping[$org.Name] = $org.FullName
        }
    }
    
    return $mapping
}

function Find-MatchingMergedFolder([string]$newOrgPath, [hashtable]$mapping) {
    $orgName = (Get-Item $newOrgPath).Name
    
    # "組織名 (ホスト名)" からホスト名を抽出
    if ($orgName -match "^(.+)\s+\(([^)]+)\)$") {
        $hostPart = $Matches[2]
        if ($mapping.ContainsKey($hostPart)) {
            return $mapping[$hostPart]
        }
    }
    
    # ドメイン名そのままの場合
    if ($orgName -match "\.") {
        $domainParts = $orgName -split "\."
        $hostPart = $domainParts[0]
        if ($mapping.ContainsKey($hostPart)) {
            return $mapping[$hostPart]
        }
        if ($mapping.ContainsKey($orgName)) {
            return $mapping[$orgName]
        }
    }
    
    return $null
}

function Sync-FilesToMerged([string]$newOrgPath, [string]$mergedOrgPath) {
    $extensions = @("*.key", "*.csr", "*.tsv")
    $copied = @()
    
    foreach ($ext in $extensions) {
        # 直下のファイル
        $files = Get-ChildItem -LiteralPath $newOrgPath -Filter $ext -File -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            $destPath = Join-Path $mergedOrgPath $f.Name
            if (-not (Test-Path -LiteralPath $destPath)) {
                if (-not $DryRun) {
                    Copy-Item -LiteralPath $f.FullName -Destination $destPath
                }
                $copied += @{ File = $f.Name; Type = "new" }
            }
        }
        
        # サブフォルダ内のファイル
        $subDirs = Get-ChildItem -LiteralPath $newOrgPath -Directory -ErrorAction SilentlyContinue
        foreach ($sub in $subDirs) {
            $subFiles = Get-ChildItem -LiteralPath $sub.FullName -Filter $ext -File -ErrorAction SilentlyContinue
            foreach ($sf in $subFiles) {
                # merged 側にも同名のサブフォルダを作成
                $mergedSubDir = Join-Path $mergedOrgPath $sub.Name
                if (-not (Test-Path -LiteralPath $mergedSubDir) -and -not $DryRun) {
                    New-Item -ItemType Directory -Path $mergedSubDir -Force | Out-Null
                }
                $destPath = Join-Path $mergedSubDir $sf.Name
                if (-not (Test-Path -LiteralPath $destPath)) {
                    if (-not $DryRun) {
                        Copy-Item -LiteralPath $sf.FullName -Destination $destPath
                    }
                    $copied += @{ File = "$($sub.Name)/$($sf.Name)"; Type = "new" }
                }
            }
        }
    }
    
    return $copied
}

# メイン処理
Write-Host ""
$title = switch ($Lang) {
    "zh" { "同步 new -> merged/new (key, csr, tsv)" }
    "en" { "Sync new -> merged/new (key, csr, tsv)" }
    default { "new -> merged/new へ同期 (key, csr, tsv)" }
}
Write-Host $title -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $newDir)) {
    Write-Host "new フォルダが見つかりません" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $mergedDir)) {
    Write-Host "merged/new フォルダが見つかりません" -ForegroundColor Red
    exit 1
}

$mapping = Get-OrgMapping
$newOrgs = Get-ChildItem -LiteralPath $newDir -Directory -ErrorAction SilentlyContinue

$totalCopied = 0

foreach ($org in $newOrgs) {
    $mergedPath = Find-MatchingMergedFolder $org.FullName $mapping
    
    if (-not $mergedPath) {
        continue
    }
    
    $orgDisplayName = $org.Name
    if ($orgDisplayName.Length -gt 40) {
        $orgDisplayName = $orgDisplayName.Substring(0, 37) + "..."
    }
    
    Write-Host "  $orgDisplayName" -NoNewline
    
    $copied = Sync-FilesToMerged $org.FullName $mergedPath
    
    if ($copied.Count -gt 0) {
        $dryRunMark = if ($DryRun) { " [DryRun]" } else { "" }
        Write-Host " -> $($copied.Count) files$dryRunMark" -ForegroundColor Green
        foreach ($c in $copied) {
            Write-Host "      + $($c.File)" -ForegroundColor Gray
        }
        $totalCopied += $copied.Count
    }
    else {
        Write-Host " (up to date)" -ForegroundColor DarkGray
    }
}

Write-Host ""
$summary = switch ($Lang) {
    "zh" { "完成: 同步了 $totalCopied 个文件" }
    "en" { "Done: Synced $totalCopied files" }
    default { "完了: $totalCopied ファイルを同期しました" }
}
if ($DryRun) {
    $summary += " (DryRun)"
}
Write-Host $summary -ForegroundColor Cyan
