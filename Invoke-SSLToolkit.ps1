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

# ツール定義 (DescKey → i18n キー参照)
$tools = @(
    @{
        Name    = "Get-CertificateInfo"
        Script  = "utils\Get-CertificateInfo.ps1"
        DescKey = "Toolkit.Tool.CertInfo"
        Wait    = $false
    },
    @{
        Name    = "New-CSR-FromOld"
        Script  = "utils\New-CertificateSigningRequestFromOld.ps1"
        DescKey = "Toolkit.Tool.CsrFromOld"
        Wait    = $true
    },
    @{
        Name    = "New-CSR"
        Script  = "utils\New-CertificateSigningRequest.ps1"
        DescKey = "Toolkit.Tool.NewCsr"
        Wait    = $true
    },
    @{
        Name    = "Merge-Chain"
        Script  = "utils\Merge-CertificateChain.ps1"
        DescKey = "Toolkit.Tool.MergeChain"
        Wait    = $true
    },
    @{
        Name    = "Convert-Key"
        Script  = "utils\Convert-KeyToPlaintext.ps1"
        DescKey = "Toolkit.Tool.ConvertKey"
        Wait    = $true
    },
    @{
        Name    = "Export-Modulus"
        Script  = "utils\Export-CertificateModulus.ps1"
        DescKey = "Toolkit.Tool.ExportModulus"
        Wait    = $true
    },
    @{
        Name    = "Repair-PEM"
        Script  = "utils\Repair-PemFile.ps1"
        DescKey = "Toolkit.Tool.RepairPem"
        Wait    = $true
    },
    @{
        Name    = "New-ServerList"
        Script  = "utils\New-ServerList.ps1"
        DescKey = "Toolkit.Tool.ServerList"
        Wait    = $true
    },
    @{
        Name    = "Sync-ToMerged"
        Script  = "utils\Sync-ToMerged.ps1"
        DescKey = "Toolkit.Tool.SyncMerged"
        Wait    = $true
    },
    @{
        Name    = "Self-Signed"
        DescKey = "Toolkit.Tool.SelfSigned"
        Wait    = $true
        SubMenu = @(
            @{
                Name    = "10-Year Self-Signed"
                Script  = "utils\Request-SelfSignedCertificate.ps1"
                DescKey = "Toolkit.SubTool.SelfSigned10Y"
            },
            @{
                Name    = "Let's Encrypt"
                Script  = "utils\Request-LetsEncryptCertificate.ps1"
                DescKey = "Toolkit.SubTool.LetsEncrypt"
            }
        )
    }
)

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
        $status = ""
        if ($null -ne $tool.SubMenu) {
            $status = " ▸"
        }
        elseif ($tool.Script) {
            $scriptPath = Join-Path $PSScriptRoot $tool.Script
            if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { $status = " [N/A]" }
        }
        $menuItems += "{0,-20} - {1}{2}" -f $tool.Name, (T $tool.DescKey), $status
    }
    $menuItems += "{0,-20} - {1} ({2}) ▸" -f "Language", (T "Toolkit.Menu.Language"), (T "Language.DisplayName")
    $menuItems += (T "Toolkit.Menu.Exit")
    
    return $menuItems
}

function Invoke-AutoRenameOnStartup {
    $renameScript = Join-Path $ScriptsDir "Rename-OrgFolders.ps1"
    if (-not (Test-Path -LiteralPath $renameScript -PathType Leaf)) { return }

    Write-Host (T "Toolkit.Menu.AutoRename") -ForegroundColor DarkGray

    try {
        & $renameScript -AutoYes
    }
    catch {
        Write-Host (T "Toolkit.Menu.AutoRenameFailed" @($_.Exception.Message)) -ForegroundColor Yellow
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
        $fullTitle = (Get-BannerText) + "`n" + (T "Toolkit.Menu.Title")
        $selection = Show-MenuSelect -title $fullTitle -items $menuItems
        
        $exitIdx = $menuItems.Count      # last item = Exit
        $langIdx = $menuItems.Count - 1   # second-to-last = Language

        if ($null -eq $selection -or $selection -eq $exitIdx) {
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
        
        if ($selection -eq $langIdx) {
            $availLangs = @(Get-AvailableLanguages -BaseDir $PSScriptRoot)
            $langItems = @()
            foreach ($al in $availLangs) {
                $mark = if ($al.Code -eq $Lang) { " *" } else { "" }
                $langItems += "{0} ({1}){2}" -f $al.DisplayName, $al.Code, $mark
            }
            $langItems += (T "Toolkit.Menu.Back")

            $langSel = Show-MenuSelect -title (T "Toolkit.Menu.SelectLanguage") -items $langItems
            if ($null -ne $langSel -and $langSel -le $availLangs.Count) {
                $newLang = $availLangs[$langSel - 1].Code
                if ($newLang -ne $Lang) {
                    $Lang = $newLang
                    $__i18n = Initialize-I18n -Lang $Lang -BaseDir $PSScriptRoot
                }
            }
            continue
        }
        
        # ツール実行
        $selectedTool = $tools[$selection - 1]
        
        # SubMenu がある場合は二級メニューを表示
        if ($null -ne $selectedTool.SubMenu -and $selectedTool.SubMenu.Count -gt 0) {
            $subItems = @()
            foreach ($sub in $selectedTool.SubMenu) {
                $subScript = Join-Path $PSScriptRoot $sub.Script
                $subStatus = if (Test-Path -LiteralPath $subScript -PathType Leaf) { "" } else { " [N/A]" }
                $subItems += "{0,-24} - {1}{2}" -f $sub.Name, (T $sub.DescKey), $subStatus
            }
            $subItems += (T "Toolkit.Menu.Back")

            $subTitle = T "Toolkit.Menu.SubMenuSelect" @((T $selectedTool.DescKey))
            $subSel = Show-MenuSelect -title $subTitle -items $subItems
            if ($null -eq $subSel -or $subSel -eq $subItems.Count) { continue }

            $chosenSub = $selectedTool.SubMenu[$subSel - 1]
            $scriptPath = Join-Path $PSScriptRoot $chosenSub.Script
            $runName = $chosenSub.Name
        }
        else {
            $scriptPath = Join-Path $PSScriptRoot $selectedTool.Script
            $runName = $selectedTool.Name
        }
        
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
            Clear-Host
            Write-Host ""
            Write-Host (T "Toolkit.Menu.ScriptNotFound" @($scriptPath)) -ForegroundColor Red
            Write-Host ""
            Write-Host (T "Toolkit.Menu.PressAnyKey") -ForegroundColor DarkGray
            try { $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { }
            continue
        }
        
        Clear-Host
        Write-Host ""
        Write-Host (T "Toolkit.Menu.Starting" @($runName)) -ForegroundColor Yellow
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
            if ($selectedTool.Wait -and $LASTEXITCODE -ne 99) {
                Write-Host ""
                Write-Host (T "Toolkit.Menu.PressAnyKey") -ForegroundColor DarkGray
                try { $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { }
            }
        }
    }
}
finally {
    try { [Console]::CursorVisible = $true } catch { }
    try { [Console]::ResetColor() } catch { }
}
