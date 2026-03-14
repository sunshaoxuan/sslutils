<#
.SYNOPSIS
new フォルダの key, csr, tsv を output\merged\<組織> へ同期

.DESCRIPTION
同一組織の証明書関連ファイル（.key, .csr, .tsv）を
new フォルダから output\merged フォルダへコピーします。
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
    [string]$Target = "",
    [switch]$NoPause = $false,
    [Parameter(Mandatory = $false)]
    [string]$OpenSsl = "",
    [Parameter(Mandatory = $false)]
    [string]$Lang = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$runtimeModule = Join-Path $PSScriptRoot "lib\runtime.ps1"
if (Test-Path -LiteralPath $runtimeModule -PathType Leaf) { . $runtimeModule }
$ModuleRoot = $PSScriptRoot
$ToolkitRoot = Get-ToolkitBaseDir -ModuleRoot $ModuleRoot
Initialize-ToolkitConsoleEncoding

$openSslContext = Resolve-ToolkitOpenSsl -ModuleRoot $ModuleRoot -Explicit $OpenSsl -BaseDir $ToolkitRoot
$ToolkitPaths = $openSslContext.ToolkitPaths
$OpenSsl = $openSslContext.OpenSsl

$newDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.New)) { $ToolkitPaths.New } else { Join-Path $ToolkitRoot "new" }
$mergedDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.Merged)) { $ToolkitPaths.Merged } else { Join-Path $ToolkitRoot "output\merged" }
$legacyMergedNewDir = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace($ToolkitPaths.LegacyMergedNew)) { $ToolkitPaths.LegacyMergedNew } else { Join-Path $mergedDir "new" }
$legacyNewName = [IO.Path]::GetFileName($legacyMergedNewDir.TrimEnd('\', '/'))

# i18n
$__i18n = Initialize-ToolkitI18nContext -ModuleRoot $ModuleRoot -Lang $Lang -BaseDir $ToolkitRoot

# Security helper (Find-PassFile, Get-Passphrases, Test-KeyEncrypted, Invoke-TempPassFile)
$securityModule = Join-Path $PSScriptRoot "lib\security.ps1"
if (Test-Path -LiteralPath $securityModule -PathType Leaf) { . $securityModule }

# Menu helper
$menuModule = Join-Path $PSScriptRoot "lib\menu.ps1"
if (Test-Path -LiteralPath $menuModule -PathType Leaf) {
    . $menuModule
}

$FixedPassFileName = "passphrase.txt"

function T([string]$Key, $ArgList = @()) {
    if ($null -ne $__i18n) {
        $arr = if ($null -eq $ArgList) { @() } else { @($ArgList) }
        return Get-ToolkitText -I18n $__i18n -Key $Key -FormatArgs $arr
    }
    return $Key
}

function Invoke-OpenSsl([string[]]$OpenSslArgs, [switch]$AllowFail) {
    $out = & $OpenSsl @OpenSslArgs 2>&1 | ForEach-Object { $_.ToString() }
    if ($LASTEXITCODE -ne 0) {
        if ($AllowFail) { return $out }
        throw ("OpenSSL failed: {0}" -f ($OpenSslArgs -join " "))
    }
    return $out
}

function Copy-DecryptedKey([string]$srcKeyPath, [string]$destPath, [string[]]$passphrases) {
    foreach ($p in @($passphrases)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        try {
            Invoke-TempPassFile $p {
                param($tmpPass)
                Invoke-OpenSsl @("pkey", "-in", $srcKeyPath, "-out", $destPath, "-passin", ("file:{0}" -f $tmpPass)) -AllowFail | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Invoke-OpenSsl @("rsa", "-in", $srcKeyPath, "-out", $destPath, "-passin", ("file:{0}" -f $tmpPass)) | Out-Null
                }
            } | Out-Null
            if ((Test-Path -LiteralPath $destPath -PathType Leaf) -and -not (Test-KeyEncrypted $destPath)) {
                return $true
            }
            Remove-Item -LiteralPath $destPath -Force -ErrorAction SilentlyContinue
        }
        catch {
            Remove-Item -LiteralPath $destPath -Force -ErrorAction SilentlyContinue
        }
    }
    return $false
}

function Get-OrgMapping {
    param([string]$mergedDir, [string]$legacyMergedNewDir = "")
    # new と output/merged のフォルダ名から組織名をマッピング
    # フォルダ名形式: "組織名 (ホスト名)" または "ドメイン名"
    $mapping = @{}
    
    if (-not (Test-Path $mergedDir)) { return $mapping }
    
    $mergedOrgs = @(Get-ChildItem -LiteralPath $mergedDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $legacyNewName })
    if (-not [string]::IsNullOrWhiteSpace($legacyMergedNewDir) -and (Test-Path -LiteralPath $legacyMergedNewDir -PathType Container)) {
        $mergedOrgs += @(Get-ChildItem -LiteralPath $legacyMergedNewDir -Directory -ErrorAction SilentlyContinue)
    }
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

function Copy-OrDecryptKey([string]$srcPath, [string]$destPath, [string[]]$passphrases, [switch]$DryRun) {
    $isEnc = Test-KeyEncrypted $srcPath
    if ($isEnc -and @($passphrases).Count -gt 0 -and (Test-Path -LiteralPath $OpenSsl -PathType Leaf)) {
        if (-not $DryRun) {
            $ok = Copy-DecryptedKey $srcPath $destPath $passphrases
            if ($ok) { return "decrypted" }
            Copy-Item -LiteralPath $srcPath -Destination $destPath
            return "new"
        }
        return "decrypted"
    }
    if (-not $DryRun) {
        Copy-Item -LiteralPath $srcPath -Destination $destPath
    }
    return "new"
}

function Sync-FilesToMerged([string]$newOrgPath, [string]$mergedOrgPath, [string[]]$passphrases = @(), [switch]$DryRun) {
    $extensions = @("*.key", "*.csr", "*.tsv")
    $copied = @()
    
    foreach ($ext in $extensions) {
        # 直下のファイル
        $files = Get-ChildItem -LiteralPath $newOrgPath -Filter $ext -File -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            $destPath = Join-Path $mergedOrgPath $f.Name
            if (-not (Test-Path -LiteralPath $destPath)) {
                if ($f.Extension -eq ".key") {
                    $type = Copy-OrDecryptKey $f.FullName $destPath $passphrases -DryRun:$DryRun
                    $copied += @{ File = $f.Name; Type = $type }
                }
                else {
                    if (-not $DryRun) {
                        Copy-Item -LiteralPath $f.FullName -Destination $destPath
                    }
                    $copied += @{ File = $f.Name; Type = "new" }
                }
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
                    if ($sf.Extension -eq ".key") {
                        $type = Copy-OrDecryptKey $sf.FullName $destPath $passphrases -DryRun:$DryRun
                        $copied += @{ File = "$($sub.Name)/$($sf.Name)"; Type = $type }
                    }
                    else {
                        if (-not $DryRun) {
                            Copy-Item -LiteralPath $sf.FullName -Destination $destPath
                        }
                        $copied += @{ File = "$($sub.Name)/$($sf.Name)"; Type = "new" }
                    }
                }
            }
        }
    }
    
    return $copied
}

# メイン処理
Write-Host ""
$title = switch ($Lang) {
    "zh" { "同步 new -> output/merged (key, csr, tsv)" }
    "en" { "Sync new -> output/merged (key, csr, tsv)" }
    default { "new -> output/merged へ同期 (key, csr, tsv)" }
}

function Backup-ExistingFile([string]$path, [switch]$DryRun) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
    $dir = Split-Path -Parent $path
    $base = [IO.Path]::GetFileNameWithoutExtension($path)
    $ext = [IO.Path]::GetExtension($path)
    $ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $bak = Join-Path $dir ("{0}.bak_{1}{2}" -f $base, $ts, $ext)
    if (-not $DryRun) {
        Move-Item -LiteralPath $path -Destination $bak -Force
    }
}

function Merge-LegacyOrgFolder([string]$srcDir, [string]$dstDir, [switch]$DryRun) {
    $moved = 0
    $files = @(Get-ChildItem -LiteralPath $srcDir -Recurse -File -ErrorAction SilentlyContinue)
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($srcDir.Length).TrimStart('\', '/')
        $destPath = Join-Path $dstDir $rel
        $destParent = Split-Path -Parent $destPath
        if (-not (Test-Path -LiteralPath $destParent) -and -not $DryRun) {
            New-Item -ItemType Directory -Path $destParent -Force | Out-Null
        }

        if (Test-Path -LiteralPath $destPath -PathType Leaf) {
            Backup-ExistingFile $destPath -DryRun:$DryRun
        }
        if (-not $DryRun) {
            Copy-Item -LiteralPath $f.FullName -Destination $destPath -Force
        }
        $moved++
    }

    if (-not $DryRun) {
        Remove-Item -LiteralPath $srcDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $moved
}

function Move-LegacyMergedNew([string]$mergedDir, [string]$legacyDir, [switch]$DryRun) {
    if (-not (Test-Path -LiteralPath $legacyDir -PathType Container)) { return 0 }
    $legacyOrgs = @(Get-ChildItem -LiteralPath $legacyDir -Directory -ErrorAction SilentlyContinue)
    if ($legacyOrgs.Count -eq 0) { return 0 }

    $migratedCount = 0
    foreach ($org in $legacyOrgs) {
        $dstOrg = Join-Path $mergedDir $org.Name
        if (-not (Test-Path -LiteralPath $dstOrg -PathType Container)) {
            if (-not $DryRun) {
                Move-Item -LiteralPath $org.FullName -Destination $dstOrg -Force
            }
            $migratedCount++
        }
        else {
            $migratedCount += Merge-LegacyOrgFolder $org.FullName $dstOrg -DryRun:$DryRun
        }
    }

    if (-not $DryRun) {
        $legacyKeep = Join-Path $legacyDir ".gitkeep"
        if (Test-Path -LiteralPath $legacyKeep -PathType Leaf) {
            Remove-Item -LiteralPath $legacyKeep -Force -ErrorAction SilentlyContinue
        }
        $remains = @(Get-ChildItem -LiteralPath $legacyDir -Force -ErrorAction SilentlyContinue)
        if ($remains.Count -eq 0) {
            Remove-Item -LiteralPath $legacyDir -Force -ErrorAction SilentlyContinue
        }
    }
    return $migratedCount
}
Write-Host $title -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $newDir)) {
    Write-Host "new フォルダが見つかりません" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $mergedDir)) {
    Write-Host "output/merged フォルダが見つかりません" -ForegroundColor Red
    exit 1
}

# Legacy migration: output/merged/new/* -> output/merged/*
$migrated = Move-LegacyMergedNew $mergedDir $legacyMergedNewDir -DryRun:$DryRun
if ($migrated -gt 0) {
    $migMsg = switch ($Lang) {
        "zh" { if ($DryRun) { "旧结构迁移预览: $migrated 项 [DryRun]" } else { "旧结构迁移完成: $migrated 项" } }
        "en" { if ($DryRun) { "Legacy layout migration planned: $migrated item(s) [DryRun]" } else { "Legacy layout migrated: $migrated item(s)" } }
        default { if ($DryRun) { "旧レイアウト移行予定: $migrated 件 [DryRun]" } else { "旧レイアウト移行完了: $migrated 件" } }
    }
    Write-Host $migMsg -ForegroundColor DarkYellow
}

$mapping = Get-OrgMapping $mergedDir $legacyMergedNewDir
$newOrgs = Get-ChildItem -LiteralPath $newDir -Directory -ErrorAction SilentlyContinue

if (-not [string]::IsNullOrWhiteSpace($Target)) {
    $newOrgs = @($newOrgs | Where-Object { $_.Name -eq $Target })
    if ($newOrgs.Count -eq 0) {
        Write-Host "Target not found: $Target" -ForegroundColor Red
        exit 1
    }
}

$totalCopied = 0

foreach ($org in $newOrgs) {
    $mergedPath = Find-MatchingMergedFolder $org.FullName $mapping
    
    if (-not $mergedPath) {
        $mergedPath = Join-Path $mergedDir $org.Name
        if (-not (Test-Path -LiteralPath $mergedPath) -and -not $DryRun) {
            New-Item -ItemType Directory -Path $mergedPath -Force | Out-Null
        }
    }
    
    $orgDisplayName = $org.Name
    if ($orgDisplayName.Length -gt 40) {
        $orgDisplayName = $orgDisplayName.Substring(0, 37) + "..."
    }
    
    Write-Host "  $orgDisplayName" -NoNewline
    
    # 組織フォルダからパスフレーズを探索
    $passFiles = @()
    $pf = Find-PassFile $org.FullName
    if ($pf) { $passFiles += $pf }
    $pf = Find-PassFile $newDir
    if ($pf) { $passFiles += $pf }
    $pf = Find-PassFile $PSScriptRoot
    if ($pf) { $passFiles += $pf }
    $passphrases = Get-Passphrases $passFiles
    
    $copied = @(Sync-FilesToMerged $org.FullName $mergedPath $passphrases -DryRun:$DryRun)
    
    if ($copied.Count -gt 0) {
        $dryRunMark = if ($DryRun) { " [DryRun]" } else { "" }
        Write-Host " -> $($copied.Count) files$dryRunMark" -ForegroundColor Green
        foreach ($c in $copied) {
            $suffix = ""
            if ($c.Type -eq "decrypted") {
                $suffix = " " + (T "SyncToMerged.KeyDecrypted")
            }
            Write-Host ("      + {0}{1}" -f $c.File, $suffix) -ForegroundColor Gray
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

if (-not $NoPause) {
    Wait-AnyKey (T "Common.PressAnyKey")
}


