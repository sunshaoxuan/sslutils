<#
.SYNOPSIS
SSL証明書管理ツールキット - 統合メニュー

.DESCRIPTION
このスクリプトは、SSL証明書関連の各種ツールを統合メニューから呼び出すことができます。
上下キーで選択し、Enterで実行、ESCで終了します。

.EXAMPLE
.\Invoke-SSLToolkit.ps1
メインメニューを表示

.EXAMPLE
.\Invoke-SSLToolkit.ps1 -Lang zh
中国語でメニューを表示
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("ja", "zh", "en")]
    [string]$Lang = "ja"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ToolkitVersion = "1.3.4"
$ToolkitLastUpdated = "2026-02-10"

# UTF-8出力設定
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = [Console]::OutputEncoding
}
catch { }

# 共通モジュール読み込み
$ScriptsDir = Join-Path $PSScriptRoot "utils"
$LibDir = Join-Path $ScriptsDir "lib"

$menuModule = Join-Path $LibDir "menu.ps1"
if (Test-Path -LiteralPath $menuModule -PathType Leaf) { . $menuModule }

$i18nModule = Join-Path $LibDir "i18n.ps1"
if (Test-Path -LiteralPath $i18nModule -PathType Leaf) {
    . $i18nModule
    $__i18n = Initialize-I18n -Lang $Lang -BaseDir $PSScriptRoot
}
function T([string]$Key, [object[]]$FormatArgs = @()) {
    if ($null -ne $__i18n) {
        return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs
    }
    return $Key
}

# ツール定義
$tools = @(
    @{
        Name   = "Get-CertificateInfo"
        Script = "utils\Get-CertificateInfo.ps1"
        DescJa = "証明書情報を確認"
        DescZh = "查看证书信息"
        DescEn = "View Certificate Info"
        Wait   = $false
    },
    @{
        Name   = "New-CSR-FromOld"
        Script = "utils\New-CertificateSigningRequestFromOld.ps1"
        DescJa = "既存証明書からCSR更新"
        DescZh = "从旧证书续期CSR"
        DescEn = "Renew CSR from Old Certificate"
        Wait   = $true
    },
    @{
        Name   = "New-CSR"
        Script = "utils\New-CertificateSigningRequest.ps1"
        DescJa = "新規CSR作成"
        DescZh = "创建新CSR"
        DescEn = "Create New CSR"
        Wait   = $true
    },
    @{
        Name   = "Merge-Chain"
        Script = "utils\Merge-CertificateChain.ps1"
        DescJa = "証明書チェーン結合"
        DescZh = "合并证书链"
        DescEn = "Merge Certificate Chain"
        Wait   = $true
    },
    @{
        Name   = "Convert-Key"
        Script = "utils\Convert-KeyToPlaintext.ps1"
        DescJa = "秘密鍵を平文に変換"
        DescZh = "密钥转换为明文"
        DescEn = "Convert Key to Plaintext"
        Wait   = $true
    },
    @{
        Name   = "Export-Modulus"
        Script = "utils\Export-CertificateModulus.ps1"
        DescJa = "証明書モジュラス出力"
        DescZh = "导出证书模数"
        DescEn = "Export Certificate Modulus"
        Wait   = $true
    },
    @{
        Name   = "Repair-PEM"
        Script = "utils\Repair-PemFile.ps1"
        DescJa = "PEMファイル修復"
        DescZh = "修复PEM文件"
        DescEn = "Repair PEM File"
        Wait   = $true
    },
    @{
        Name   = "New-ServerList"
        Script = "utils\New-ServerList.ps1"
        DescJa = "サーバー一覧作成"
        DescZh = "生成服务器列表"
        DescEn = "Generate Server List"
        Wait   = $true
    },
    @{
        Name   = "Sync-ToMerged"
        Script = "utils\Sync-ToMerged.ps1"
        DescJa = "new→output/merged同期 (key,csr,tsv)"
        DescZh = "同步到output/merged (key,csr,tsv)"
        DescEn = "Sync to output/merged (key,csr,tsv)"
        Wait   = $true
    },
    @{
        Name   = "Self-Signed (10Y)"
        Script = "utils\Request-SelfSignedCertificate.ps1"
        DescJa = "10年自己署名証明書を作成"
        DescZh = "生成10年期自签证书"
        DescEn = "Generate 10-Year Self-Signed Cert"
        Wait   = $true
    },
    @{
        Name   = "Let's Encrypt"
        Script = "utils\Request-LetsEncryptCertificate.ps1"
        DescJa = "Let's Encrypt証明書取得"
        DescZh = "获取Let's Encrypt证书"
        DescEn = "Request Let's Encrypt Certificate"
        Wait   = $true
    }
)

function Get-ToolDesc($tool) {
    switch ($Lang) {
        "zh" { return $tool.DescZh }
        "en" { return $tool.DescEn }
        default { return $tool.DescJa }
    }
}

function Get-EastAsianWidth([string]$str) {
    $len = 0
    $charArr = $str.ToCharArray()
    foreach ($c in $charArr) {
        # 簡易的な判定: ASCIIは1、それ以外は2
        if ([int]$c -le 127) { $len += 1 } else { $len += 2 }
    }
    return $len
}

function Format-BoxedLine([string]$text, [int]$innerContentWidth) {
    if ([string]::IsNullOrEmpty($text)) {
        return "  ║" + (" " * $innerContentWidth) + "║"
    }
    
    $visualLen = Get-EastAsianWidth $text
    $padTotal = $innerContentWidth - $visualLen
    
    if ($padTotal -lt 0) { $padTotal = 0 } # Should not happen if width is sufficient
    
    # Center alignment
    $padLeft = [math]::Floor($padTotal / 2)
    $padRight = $padTotal - $padLeft
    
    return "  ║" + (" " * $padLeft) + $text + (" " * $padRight) + "║"
}

function Get-BannerText {
    $title = (T "Toolkit.Banner.Title")
    $verRaw = (T "Toolkit.Banner.Version" @($ToolkitVersion))
    
    # Calculate required width
    # Min width 63 to match previous design, but expand if text is longer
    $minWidth = 63
    $titleLen = Get-EastAsianWidth $title
    $verLen = Get-EastAsianWidth $verRaw
    
    # Ensure inner width is at least minWidth + some padding
    $contentWidth = $minWidth
    if ($titleLen + 4 -gt $contentWidth) { $contentWidth = $titleLen + 4 }
    if ($verLen + 4 -gt $contentWidth) { $contentWidth = $verLen + 4 }
    
    # Odd/Even adjustment to ensure centering matches properly
    if ($contentWidth % 2 -ne 0) { $contentWidth++ }

    $topBorder = "  ╔" + ("═" * $contentWidth) + "╗"
    $bottomBorder = "  ╚" + ("═" * $contentWidth) + "╝"
    $emptyLine = Format-BoxedLine "" $contentWidth
    $titleLine = Format-BoxedLine $title $contentWidth
    $verLine = Format-BoxedLine $verRaw $contentWidth

    $banner = @"
$topBorder
$emptyLine
$titleLine
$verLine
$emptyLine
$bottomBorder
"@
    return $banner
}

function Show-MainMenu {
    $menuItems = @()
    foreach ($tool in $tools) {
        $scriptPath = Join-Path $PSScriptRoot $tool.Script
        $exists = Test-Path -LiteralPath $scriptPath -PathType Leaf
        $status = if ($exists) { "" } else { " [N/A]" }
        $menuItems += "{0,-20} - {1}{2}" -f $tool.Name, (Get-ToolDesc $tool), $status
    }
    $exitText = switch ($Lang) {
        "zh" { "[ 退出 ]" }
        "en" { "[ Exit ]" }
        default { "[ 終了 ]" }
    }
    $menuItems += $exitText
    
    return $menuItems
}

function Invoke-AutoRenameOnStartup {
    $renameScript = Join-Path $ScriptsDir "Rename-OrgFolders.ps1"
    if (-not (Test-Path -LiteralPath $renameScript -PathType Leaf)) { return }

    $msg = switch ($Lang) {
        "zh" { "启动时自动执行：组织文件夹重命名检查..." }
        "en" { "Startup auto task: organization folder rename check..." }
        default { "起動時自動処理: 組織フォルダのリネーム確認を実行します..." }
    }
    Write-Host $msg -ForegroundColor DarkGray

    try {
        & $renameScript -AutoYes
    }
    catch {
        $errMsg = switch ($Lang) {
            "zh" { "自动重命名检查失败，已跳过: {0}" }
            "en" { "Auto rename check failed and was skipped: {0}" }
            default { "自動リネーム確認に失敗したためスキップしました: {0}" }
        }
        Write-Host ($errMsg -f $_.Exception.Message) -ForegroundColor Yellow
    }
}

# メインループ
try {
    [Console]::CursorVisible = $false
}
catch { }

try {
    Invoke-AutoRenameOnStartup

    while ($true) {
        # Show-Banner call removed as it is now part of the title
        
        $menuItems = Show-MainMenu
        $titleText = switch ($Lang) {
            "zh" { "请选择工具 (↑↓选择, Enter确认, ESC退出)" }
            "en" { "Select Tool (↑↓ to select, Enter to confirm, ESC to exit)" }
            default { "ツールを選択 (↑↓で選択, Enterで実行, ESCで終了)" }
        }
        
        $fullTitle = (Get-BannerText) + "`n" + $titleText
        $selection = Show-MenuSelect -title $fullTitle -items $menuItems
        
        if ($null -eq $selection -or $selection -eq $menuItems.Count) {
            # 終了
            try { [Console]::Clear() } catch { Clear-Host }
            try { [Console]::SetCursorPosition(0, 0) } catch { }
            
            Write-Host ""
            Write-Host (T "Toolkit.Exit.Thanks") -ForegroundColor Green
            Write-Host "------------------------------------" -ForegroundColor Gray
            Write-Host (T "Toolkit.Banner.Title") -ForegroundColor Gray
            Write-Host (T "Toolkit.Exit.VersionLine" @($ToolkitVersion)) -ForegroundColor Gray
            Write-Host (T "Toolkit.Exit.UpdatedLine" @($ToolkitLastUpdated)) -ForegroundColor Gray
            Write-Host "------------------------------------" -ForegroundColor Gray
            Write-Host (T "Toolkit.Exit.Copyright") -ForegroundColor DarkGray
            Write-Host ""
            break
        }
        
        # ツール実行
        $selectedTool = $tools[$selection - 1]
        $scriptPath = Join-Path $PSScriptRoot $selectedTool.Script
        
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
            Clear-Host
            Write-Host ""
            Write-Host "Script not found: $scriptPath" -ForegroundColor Red
            Write-Host ""
            $pressKeyMsg = switch ($Lang) {
                "zh" { "按任意键返回菜单..." }
                "en" { "Press any key to return to menu..." }
                default { "任意のキーを押してメニューに戻る..." }
            }
            Write-Host $pressKeyMsg -ForegroundColor DarkGray
            try { $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { }
            continue
        }
        
        # 選択されたスクリプトを実行
        Clear-Host
        Write-Host ""
        $runMsg = switch ($Lang) {
            "zh" { "正在启动: {0}" }
            "en" { "Starting: {0}" }
            default { "起動中: {0}" }
        }
        Write-Host ($runMsg -f $selectedTool.Name) -ForegroundColor Yellow
        Write-Host ""
        
        try {
            try { $host.UI.RawUI.FlushInputBuffer() } catch { }
            & $scriptPath -Lang $Lang
        }
        catch {
            Write-Host ""
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }
        finally {
            # 99 = Skip Pause (Sub-menu return / Cancelled)
            if ($selectedTool.Wait -and $LASTEXITCODE -ne 99) {
                Write-Host ""
                $pressKeyMsg = switch ($Lang) {
                    "zh" { "按任意键返回菜单..." }
                    "en" { "Press any key to return to menu..." }
                    default { "任意のキーを押してメニューに戻る..." }
                }
                Write-Host $pressKeyMsg -ForegroundColor DarkGray
                try { $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { }
            }
        }
    }
}
finally {
    try { [Console]::CursorVisible = $true } catch { }
    try { [Console]::ResetColor() } catch { }
}
