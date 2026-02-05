# menu.ps1
# 共通メニュー選択モジュール
# 上下キーで選択、Enter で確定、ESC でキャンセル

<#
.SYNOPSIS
反転表示メニューで項目を選択する

.DESCRIPTION
上下キーで項目を移動し、Enter で確定、ESC でキャンセルできるメニューを表示します。
マルチライン表示とブロックハイライトに対応。

.PARAMETER title
メニューのタイトル

.PARAMETER items
選択肢の配列

.PARAMETER helpText
ヘルプテキスト（省略可）

.PARAMETER blockHighlight
選択中アイテムの全行をハイライトするか（既定: false, 第一行のみ）

.OUTPUTS
選択された項目のインデックス (1-based)、またはキャンセル時は $null
#>
function Show-MenuSelect {
    param(
        [string]$title,
        [string[]]$items,
        [string]$helpText = ""
    )

    if ([string]::IsNullOrWhiteSpace($title)) { $title = "" }
    if ($null -eq $items -or $items.Count -eq 0) { return $null }
  
    $index = 0
    $readOpts = [System.Management.Automation.Host.ReadKeyOptions]5 # NoEcho, IncludeKeyDown

    $oldCursorVisible = $true
    try {
        $oldCursorVisible = $host.UI.RawUI.CursorVisible
        $host.UI.RawUI.CursorVisible = $false
    }
    catch { }

    try {
        while ($true) {
            Clear-Host
            Write-Host $title
            if (-not [string]::IsNullOrWhiteSpace($helpText)) { Write-Host $helpText }
            Write-Host ""
        
            for ($i = 0; $i -lt $items.Count; $i++) {
                $num = $i + 1
                $isSelected = ($i -eq $index)
                
                # アイテムを改行で分割
                $lines = @($items[$i] -split "`r?`n")
                
                for ($j = 0; $j -lt $lines.Count; $j++) {
                    $prefix = "      "  # デフォルトのインデント
                    if ($j -eq 0) {
                        $prefix = "  {0,2}) " -f $num
                    }
                    
                    $outLine = "{0}{1}" -f $prefix, $lines[$j]
                    
                    if ($isSelected) {
                        # 選択中アイテムの描画
                        if ($j -eq 0) {
                            # 1行目のみ反転：White背景 + Black文字（高コントラスト）
                            Write-Host $outLine -BackgroundColor White -ForegroundColor Black
                        }
                        else {
                            # 2行目以降は暗いグレー（DarkGray）で表示（反転なし）
                            Write-Host $outLine -ForegroundColor DarkGray
                        }
                    }
                    else {
                        if ($j -eq 0) {
                            # 非選択時の1行目
                            Write-Host $outLine
                        }
                        else {
                            # 2行目以降は常に暗いグレー（DarkGray）で表示
                            Write-Host $outLine -ForegroundColor DarkGray
                        }
                    }
                }
            }
    
            try {
                $host.UI.RawUI.FlushInputBuffer()
                $key = $host.UI.RawUI.ReadKey($readOpts)
            }
            catch { return $null }
        
            switch ($key.VirtualKeyCode) {
                38 { if ($index -le 0) { $index = $items.Count - 1 } else { $index-- } }  # Up
                40 { if ($index -ge ($items.Count - 1)) { $index = 0 } else { $index++ } }  # Down
                13 { Clear-Host; return [int]($index + 1) }  # Enter
                27 { Clear-Host; return $null }  # ESC
            }
        }
    }
    finally {
        try { $host.UI.RawUI.CursorVisible = $oldCursorVisible } catch { }
    }
}

<#
.SYNOPSIS
はい/いいえの選択メニューを表示
#>
function Show-YesNoMenu([string]$prompt) {
    # 互換性のため UTF-8 互換の書き方を維持
    $items = @("はい", "いいえ")
    $sel = Show-MenuSelect -title $prompt -items $items
    return ($sel -eq 1)
}
