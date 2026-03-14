# menu.ps1
# 共通メニュー選択モジュール
# 上下キーで選択、Enter で確定、ESC でキャンセル

. (Join-Path $PSScriptRoot "runtime.ps1")

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
    # IncludeKeyDown(4) + NoEcho(2) + AllowCtrlC(1) = 7
    $readOpts = [System.Management.Automation.Host.ReadKeyOptions]"IncludeKeyDown,NoEcho,AllowCtrlC"

    $oldCursorVisible = $true
    try {
        $oldCursorVisible = $host.UI.RawUI.CursorVisible
        $host.UI.RawUI.CursorVisible = $false
    }
    catch { }

    try {
        while ($true) {
            # Ensure no stray input affects rendering
            try { $host.UI.RawUI.FlushInputBuffer() } catch { }
            
            try { [Console]::Clear() } catch { Clear-Host }
            try { [Console]::SetCursorPosition(0, 0) } catch { }
            
            # Top margin
            Write-Host ""
            
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
                38 {
                    # Up
                    $index--
                    if ($index -lt 0) { $index = $items.Count - 1 }
                }
                40 {
                    # Down
                    $index++
                    if ($index -ge $items.Count) { $index = 0 }
                }
                13 {
                    # Enter
                    return ($index + 1)
                }
                27 {
                    # Esc
                    return $null
                }
            }
        }
    }
    finally {
        try { $host.UI.RawUI.CursorVisible = $oldCursorVisible } catch { }
    }
}

<#
.SYNOPSIS
ESCキーでキャンセル可能なテキスト入力
#>
function Read-HostWithEsc {
    param([string]$Prompt = "Input")
    
    Write-Host "$($Prompt): " -NoNewline
    $buffer = New-Object System.Text.StringBuilder
    $startX = $host.UI.RawUI.CursorPosition.X
    $startY = $host.UI.RawUI.CursorPosition.Y
    
    # Ensure clean slate
    try { $host.UI.RawUI.FlushInputBuffer() } catch { }

    while ($true) {
        $key = $host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
        
        # ESC (VirtualKeyCode 27)
        if ($key.VirtualKeyCode -eq 27) {
            Write-Host "" # Newline
            return $null
        }
        
        # Enter (VirtualKeyCode 13)
        if ($key.VirtualKeyCode -eq 13) {
            Write-Host "" # Newline
            return $buffer.ToString()
        }
        
        # Backspace (VirtualKeyCode 8)
        if ($key.VirtualKeyCode -eq 8) {
            if ($buffer.Length -gt 0) {
                $buffer.Length--
                # Handle visual backspace
                $pos = $host.UI.RawUI.CursorPosition
                if ($pos.X -gt 0) {
                    $pos.X--
                    $host.UI.RawUI.CursorPosition = $pos
                    Write-Host " " -NoNewline
                    $host.UI.RawUI.CursorPosition = $pos
                }
            }
            continue
        }
        
        # Valid char (check if char is not null/control)
        if ($key.Character -ne 0 -and -not [char]::IsControl($key.Character)) {
            $buffer.Append($key.Character) | Out-Null
            Write-Host $key.Character -NoNewline
        }
    }
}

<#
.SYNOPSIS
任意キー待機
#>
function Wait-AnyKey {
    param([string]$Message = "Press any key to continue...")

    Wait-ToolkitAnyKey -Message $Message
}

