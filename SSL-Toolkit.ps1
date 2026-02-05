<#
.SYNOPSIS
SSL証明書管理ツールキット - 統合メニュー

.DESCRIPTION
このスクリプトは、SSL証明書関連の各種ツールを統合メニューから呼び出すことができます。
上下キーで選択し、Enterで実行、ESCで終了します。

.EXAMPLE
.\SSL-Toolkit.ps1
メインメニューを表示

.EXAMPLE
.\SSL-Toolkit.ps1 -Lang zh
中国語でメニューを表示
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("ja", "zh", "en")]
    [string]$Lang = "ja"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ToolkitVersion = "1.2.0"

# UTF-8出力設定
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = [Console]::OutputEncoding
}
catch { }

# 共通モジュール読み込み
$menuModule = Join-Path $PSScriptRoot "lib\menu.ps1"
if (Test-Path -LiteralPath $menuModule -PathType Leaf) { . $menuModule }

$i18nModule = Join-Path $PSScriptRoot "lib\i18n.ps1"
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
        Script = "Get-CertificateInfo.ps1"
        DescJa = "証明書情報を確認"
        DescZh = "查看证书信息"
        DescEn = "View Certificate Info"
    },
    @{
        Name   = "New-CSR-FromOld"
        Script = "New-CertificateSigningRequestFromOld.ps1"
        DescJa = "既存証明書からCSR更新"
        DescZh = "从旧证书续期CSR"
        DescEn = "Renew CSR from Old Certificate"
    },
    @{
        Name   = "New-CSR"
        Script = "New-CertificateSigningRequest.ps1"
        DescJa = "新規CSR作成"
        DescZh = "创建新CSR"
        DescEn = "Create New CSR"
    },
    @{
        Name   = "Merge-Chain"
        Script = "Merge-CertificateChain.ps1"
        DescJa = "証明書チェーン結合"
        DescZh = "合并证书链"
        DescEn = "Merge Certificate Chain"
    },
    @{
        Name   = "Convert-Key"
        Script = "Convert-KeyToPlaintext.ps1"
        DescJa = "秘密鍵を平文に変換"
        DescZh = "密钥转换为明文"
        DescEn = "Convert Key to Plaintext"
    },
    @{
        Name   = "Export-Modulus"
        Script = "Export-CertificateModulus.ps1"
        DescJa = "証明書モジュラス出力"
        DescZh = "导出证书模数"
        DescEn = "Export Certificate Modulus"
    },
    @{
        Name   = "Repair-PEM"
        Script = "Repair-PemFile.ps1"
        DescJa = "PEMファイル修復"
        DescZh = "修复PEM文件"
        DescEn = "Repair PEM File"
    },
    @{
        Name   = "Rename-Folders"
        Script = "Rename-OrgFolders.ps1"
        DescJa = "組織フォルダリネーム"
        DescZh = "重命名组织文件夹"
        DescEn = "Rename Organization Folders"
    },
    @{
        Name   = "New-ServerList"
        Script = "New-ServerList.ps1"
        DescJa = "サーバー一覧作成"
        DescZh = "生成服务器列表"
        DescEn = "Generate Server List"
    },
    @{
        Name   = "Sync-ToMerged"
        Script = "Sync-ToMerged.ps1"
        DescJa = "new→merged同期 (key,csr,tsv)"
        DescZh = "同步到merged (key,csr,tsv)"
        DescEn = "Sync to Merged (key,csr,tsv)"
    },
    @{
        Name   = "Let's Encrypt"
        Script = "Request-LetsEncryptCertificate.ps1"
        DescJa = "Let's Encrypt証明書取得"
        DescZh = "获取Let's Encrypt证书"
        DescEn = "Request Let's Encrypt Certificate"
    }
)

function Get-ToolDesc($tool) {
    switch ($Lang) {
        "zh" { return $tool.DescZh }
        "en" { return $tool.DescEn }
        default { return $tool.DescJa }
    }
}

function Get-BannerText {
    return (T "Toolkit.Banner" @($ToolkitVersion))
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

# メインループ
try {
    [Console]::CursorVisible = $false
}
catch { }

try {
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
        
        if ($null -eq $selection -or $selection -eq $menuItems.Count -or $selection -eq ($menuItems.Count - 1)) {
            # 終了
            Clear-Host
            Write-Host ""
            $exitMsg = switch ($Lang) {
                "zh" { "感谢您的使用！" }
                "en" { "Thank you for using SSL Toolkit!" }
                default { "ご利用ありがとうございました！" }
            }
            Write-Host $exitMsg -ForegroundColor Green
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
            & $scriptPath -Lang $Lang
        }
        catch {
            Write-Host ""
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
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
finally {
    try { [Console]::CursorVisible = $true } catch { }
    try { [Console]::ResetColor() } catch { }
}
