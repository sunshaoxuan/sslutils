<#
.SYNOPSIS
Let's Encrypt 証明書を Docker で自動申請するスクリプト

.DESCRIPTION
このスクリプトは、Docker + certbot を使用して Let's Encrypt から
無料の SSL 証明書を取得します。HTTP-01 チャレンジ方式を使用し、
ローカル challenge ファイルの生成とローカル webroot への反映を自動化します。

主な機能:
- Docker コンテナで certbot を実行
- HTTP-01 チャレンジ用のファイル自動生成
- 公開 URL の検証待機（タイムアウト付き）
- 証明書と秘密鍵のエクスポート

.PARAMETER Domain
証明書を取得するドメイン名（必須）

.PARAMETER Email
Let's Encrypt 登録用メールアドレス（必須）

.PARAMETER ServerChallengeDir
サーバー側のチャレンジファイル配置ディレクトリ（ヒント表示用）

.PARAMETER WaitTimeoutSec
チャレンジファイル配置待機のタイムアウト（秒）

.PARAMETER PollIntervalSec
チャレンジファイル検証のポーリング間隔（秒）

.PARAMETER CaaServfailRetries
CAA SERVFAIL 発生時の certbot 自動再試行回数（初回実行を除く）

.PARAMETER CaaServfailRetryDelaySec
CAA SERVFAIL 再試行前の待機時間（秒）

.PARAMETER ExportDir
証明書エクスポート先ディレクトリ

.PARAMETER Clean
既存の作業ディレクトリを削除して新規作成（既定: false、既存ディレクトリを再利用）

.PARAMETER Lang
出力言語（既定: ja）

.EXAMPLE
.\Request-LetsEncryptCertificate.ps1 -Domain example.com -Email admin@example.com
example.com の証明書を申請

.EXAMPLE
.\Request-LetsEncryptCertificate.ps1 -Domain "*.example.com" -Email admin@example.com -ExportDir C:\certs
ワイルドカード証明書を申請し、C:\certs にエクスポート

.NOTES
- Docker Desktop がインストールされ、実行中である必要があります
- HTTP-01 チャレンジのため、ドメインの80番ポートがアクセス可能である必要があります
- Web サーバーが別ホストにある場合は、challenge ファイルの遠隔同期が別途必要です
#>

param(
  [Parameter(Mandatory = $false)]
  [string]$Domain = "",

  [Parameter(Mandatory = $false)]
  [string]$Email = "",

  [Parameter(Mandatory = $false)]
  [string]$ServerChallengeDir = "",

  [Parameter(Mandatory = $false)]
  [int]$WaitTimeoutSec = 900,

  [Parameter(Mandatory = $false)]
  [int]$PollIntervalSec = 3,

  [Parameter(Mandatory = $false)]
  [int]$CaaServfailRetries = 3,

  [Parameter(Mandatory = $false)]
  [int]$CaaServfailRetryDelaySec = 30,

  [Parameter(Mandatory = $false)]
  [string]$ExportDir = "",

  [Parameter(Mandatory = $false)]
  [string]$FallbackExportDir = "C:\le-out",

  [Parameter(Mandatory = $false)]
  [switch]$Clean,

  [Parameter(Mandatory = $false)]
  [string]$Lang = ""
)


$ModuleRoot = $PSScriptRoot
$runtimeModule = Join-Path $PSScriptRoot "lib\runtime.ps1"
if (Test-Path -LiteralPath $runtimeModule -PathType Leaf) { . $runtimeModule }
$ToolkitRoot = Get-ToolkitBaseDir -ModuleRoot $ModuleRoot

# Ensure clean buffer on start
Clear-ToolkitInputBuffer

# i18n 初期化
$__i18n = Initialize-ToolkitI18nContext -ModuleRoot $ModuleRoot -Lang $Lang -BaseDir $ToolkitRoot
function T([string]$Key, [object[]]$FormatArgs = @()) { return Get-ToolkitText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }

$ToolkitPaths = Get-ToolkitPathsContext -ModuleRoot $ModuleRoot -BaseDir $ToolkitRoot

# ServerChallengeDir の解決（優先順位: 参数 > 配置文件 > 既定)
if ([string]::IsNullOrWhiteSpace($ServerChallengeDir)) {
    if (-not [string]::IsNullOrWhiteSpace($ToolkitPaths.AcmeWebRoot)) {
        $ServerChallengeDir = $ToolkitPaths.AcmeWebRoot
    }
    else {
        # フォールバック既定値
        $ServerChallengeDir = "C:\acme-webroot\.well-known\acme-challenge"
    }
}

# Docker コマンドの存在確認
function Assert-CommandExists([string]$cmd) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    throw (T "LE.CommandNotFound" @($cmd))
  }
}

# Docker パス変換（Windows パス → Docker マウント用）
function ConvertTo-DockerPath([string]$path) {
  return ((Resolve-Path $path).Path -replace "\\", "/")
}

# UTF-8 BOM なし + LF で書き込み
function Write-Utf8NoBomLf([string]$path, [string]$content) {
  $c = $content -replace "`r`n", "`n"
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($path, $c, $enc)
}

function Write-AsciiLf([string]$path, [string]$content) {
  $c = ($content -replace "`r`n", "`n").TrimEnd("`r", "`n") + "`n"
  $enc = [System.Text.Encoding]::ASCII
  [System.IO.File]::WriteAllText($path, $c, $enc)
}

function Normalize-PemFile([string]$path, [string]$kind) {
  $text = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::ASCII) -replace "`r", ""
  $text = $text -replace "-----BEGINCERTIFICATE-----", "-----BEGIN CERTIFICATE-----"
  $text = $text -replace "-----ENDCERTIFICATE-----", "-----END CERTIFICATE-----"
  $text = $text -replace "-----BEGINPRIVATEKEY-----", "-----BEGIN PRIVATE KEY-----"
  $text = $text -replace "-----ENDPRIVATEKEY-----", "-----END PRIVATE KEY-----"
  $text = $text -replace "-----BEGINECPRIVATEKEY-----", "-----BEGIN EC PRIVATE KEY-----"
  $text = $text -replace "-----ENDECPRIVATEKEY-----", "-----END EC PRIVATE KEY-----"
  $text = $text -replace "-----BEGINRSAPRIVATEKEY-----", "-----BEGIN RSA PRIVATE KEY-----"
  $text = $text -replace "-----ENDRSAPRIVATEKEY-----", "-----END RSA PRIVATE KEY-----"
  $text = $text -replace "-----BEGINENCRYPTEDPRIVATEKEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----"
  $text = $text -replace "-----ENDENCRYPTEDPRIVATEKEY-----", "-----END ENCRYPTED PRIVATE KEY-----"

  $matches = [regex]::Matches($text, "-----BEGIN [^-]+-----.*?-----END [^-]+-----", "Singleline")
  if ($matches.Count -eq 0) {
    throw "No PEM block found in $path"
  }

  $lines = New-Object System.Collections.Generic.List[string]
  foreach ($match in $matches) {
    $parsed = [regex]::Match($match.Value, "^(-----BEGIN [^-]+-----)\s*(.*?)\s*(-----END [^-]+-----)$", "Singleline")
    if (-not $parsed.Success) {
      throw "Invalid PEM block in $path"
    }

    $begin = $parsed.Groups[1].Value
    $body = [regex]::Replace($parsed.Groups[2].Value, "\s+", "")
    $end = $parsed.Groups[3].Value

    if ($kind -eq "fullchain" -and $begin -notmatch "BEGIN CERTIFICATE") {
      throw "Unexpected PEM header in $path"
    }
    if ($kind -eq "privkey" -and $begin -notmatch "BEGIN (ENCRYPTED |RSA |EC )?PRIVATE KEY") {
      throw "Unexpected PEM header in $path"
    }

    $lines.Add($begin) | Out-Null
    for ($i = 0; $i -lt $body.Length; $i += 64) {
      $chunkLen = [Math]::Min(64, $body.Length - $i)
      $lines.Add($body.Substring($i, $chunkLen)) | Out-Null
    }
    $lines.Add($end) | Out-Null
    $lines.Add("") | Out-Null
  }

  Write-AsciiLf $path (($lines -join "`n").TrimEnd())
}

# コンテナから証明書をエクスポート
function Export-CertificateFromContainer([string]$dstDir, [string]$leMount, [string]$domain) {
  New-Item -ItemType Directory -Force -Path $dstDir | Out-Null

  $fullchain = Join-Path $dstDir "fullchain.pem"
  $privkey = Join-Path $dstDir "privkey.pem"

  # fullchain
  $fc = docker run --rm -v "${leMount}:/etc/letsencrypt:ro" alpine:3.19 sh -c "cat /etc/letsencrypt/live/$domain/fullchain.pem"
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($fc)) { return 10 }
  Write-AsciiLf $fullchain (@($fc) -join "`n")

  # privkey
  $pk = docker run --rm -v "${leMount}:/etc/letsencrypt:ro" alpine:3.19 sh -c "cat /etc/letsencrypt/live/$domain/privkey.pem"
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pk)) { return 11 }
  Write-AsciiLf $privkey (@($pk) -join "`n")

  try {
    Normalize-PemFile $fullchain "fullchain"
    Normalize-PemFile $privkey "privkey"
  }
  catch {
    return 15
  }

  # サイズ検証
  $len1 = (Get-Item $fullchain).Length
  $len2 = (Get-Item $privkey).Length
  if ($len1 -le 0 -or $len2 -le 0) { return 12 }

  # PEM ヘッダ検証
  $h1 = Get-Content $fullchain -TotalCount 1
  $h2 = Get-Content $privkey -TotalCount 1
  if ($h1 -notmatch "BEGIN CERTIFICATE") { return 13 }
  if ($h2 -notmatch "BEGIN .*PRIVATE KEY") { return 14 }

  return 0
}

# メニューモジュールを読み込む
$menuModule = Join-Path $PSScriptRoot "lib\\menu.ps1"
if (Test-Path -LiteralPath $menuModule -PathType Leaf) {
  . $menuModule
}

# Domain 入力確報 (バッファ対策付き)
try {
  if ([string]::IsNullOrWhiteSpace($Domain)) {
    if (Get-Command Read-HostWithEsc -ErrorAction SilentlyContinue) {
      Write-Host (T "LE.InputDomainPrompt")
      # 念のためバッファクリア
      Clear-ToolkitInputBuffer
      $Domain = Read-HostWithEsc (T "Common.Prompt.Domain")
      if ($null -eq $Domain) { Exit-ToolkitWithPause -Message (T "LE.PressAnyKeyToReturn") -ExitCode 99 }
    }
    else {
      $Domain = Read-Host (T "Common.Prompt.Domain")
    }
  }
  if ([string]::IsNullOrWhiteSpace($Domain)) { Exit-ToolkitWithPause -Message (T "LE.PressAnyKeyToReturn") -ExitCode 99 }

  # Email 入力確報
  if ([string]::IsNullOrWhiteSpace($Email)) {
    if (Get-Command Read-HostWithEsc -ErrorAction SilentlyContinue) {
      Write-Host (T "LE.InputEmailPrompt")
      # 念のためバッファクリア
      Clear-ToolkitInputBuffer
      $Email = Read-HostWithEsc (T "Common.Prompt.Email")
      if ($null -eq $Email) { Exit-ToolkitWithPause -Message (T "LE.PressAnyKeyToReturn") -ExitCode 99 }
    }
    else {
      $Email = Read-Host (T "Common.Prompt.Email")
    }
  }
  if ([string]::IsNullOrWhiteSpace($Email)) { Exit-ToolkitWithPause -Message (T "LE.PressAnyKeyToReturn") -ExitCode 99 }





  # === メイン処理 ===

  Assert-CommandExists "docker"

  # 作業ディレクトリ構築（既存ディレクトリを再利用、-Clean 指定時は削除）
  # 作業ディレクトリ構築
  $domainList = @($Domain -split "[\s,]+" | Where-Object { $_ -ne "" })
  if ($domainList.Count -eq 0) { Exit-ToolkitWithPause -Message (T "LE.PressAnyKeyToReturn") -ExitCode 99 }
  $primaryDomain = [string]$domainList[0]
  $safeDomain = $primaryDomain.Replace('*', '_').Replace('\', '_').Replace('/', '_').Replace(':', '_')
  $tempRoot = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace([string]$ToolkitPaths.Temp)) {
    [string]$ToolkitPaths.Temp
  }
  else {
    Join-Path $ToolkitRoot "temp"
  }
  $Base = Join-Path (Join-Path $tempRoot "lets-encrypt") ("le-work-" + $safeDomain)
  $Work = Join-Path $Base "work"
  $Challenges = Join-Path $Base "challenges"
  $LetsEncrypt = Join-Path $Base "letsencrypt"
  $Logs = Join-Path $Base "logs"

  # 既存ディレクトリの処理
  if (Test-Path -LiteralPath $Base -PathType Container) {
    if ($Clean) {
      Write-Host (T "LE.CleaningWorkDir" @($Base)) -ForegroundColor Yellow
      Remove-Item -LiteralPath $Base -Recurse -Force -ErrorAction Stop
      New-Item -ItemType Directory -Force -Path $Work, $Challenges, $LetsEncrypt, $Logs | Out-Null
    }
    else {
      Write-Host (T "LE.ReusingWorkDir" @($Base)) -ForegroundColor Cyan
      foreach ($p in ($Work, $Challenges, $LetsEncrypt, $Logs)) {
        if (-not (Test-Path -LiteralPath $p -PathType Container)) {
          New-Item -ItemType Directory -Force -Path $p | Out-Null
        }
      }
    }
  }
  else {
    New-Item -ItemType Directory -Force -Path $Work, $Challenges, $LetsEncrypt, $Logs | Out-Null
  }

  # エクスポート先（存在しない場合は自動作成、失敗時はフォールバック）
  if ([string]::IsNullOrWhiteSpace($ExportDir)) {
    $selfSignedRoot = if ($null -ne $ToolkitPaths -and -not [string]::IsNullOrWhiteSpace([string]$ToolkitPaths.SelfSigned)) {
      [string]$ToolkitPaths.SelfSigned
    }
    else {
      Join-Path $ToolkitRoot "output\self-signed"
    }
    $ExportDir = Join-Path (Join-Path $selfSignedRoot "lets-encrypt") $safeDomain
  }
  try {
    if (-not (Test-Path -LiteralPath $ExportDir -PathType Container)) {
      New-Item -ItemType Directory -Force -Path $ExportDir -ErrorAction Stop | Out-Null
    }
  }
  catch {
    Write-Host (T "LE.ExportDirCreateFailed" @($ExportDir, $FallbackExportDir)) -ForegroundColor Yellow
    $ExportDir = $FallbackExportDir
    try {
      if (-not (Test-Path -LiteralPath $ExportDir -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $ExportDir -ErrorAction Stop | Out-Null
      }
    }
    catch {
      # 最後の手段：カレントディレクトリ
      $ExportDir = Join-Path (Get-Location).Path "le-export-$(Get-Date -Format 'yyyyMMdd_HHmmss')"
      New-Item -ItemType Directory -Force -Path $ExportDir -ErrorAction Stop | Out-Null
      Write-Host (T "LE.ExportDirFallback" @($ExportDir)) -ForegroundColor Yellow
    }
  }

  # hook スクリプト生成（auth.sh / cleanup.sh）
  $authSh = @'
#!/bin/sh
set -eu
DOMAIN="${CERTBOT_DOMAIN}"
TOKEN="${CERTBOT_TOKEN}"
VALIDATION="${CERTBOT_VALIDATION}"

CHALL_DIR="/challenges"
CHALL_FILE="${CHALL_DIR}/${TOKEN}"
SERVER_CHALL_DIR="/server-challenges"
SERVER_CHALL_FILE="${SERVER_CHALL_DIR}/${TOKEN}"
INFO_FILE="/work/current-challenge.txt"

mkdir -p "${CHALL_DIR}"
mkdir -p "${SERVER_CHALL_DIR}"
printf "%s" "${VALIDATION}" > "${CHALL_FILE}"
cp "${CHALL_FILE}" "${SERVER_CHALL_FILE}"
cat > "${INFO_FILE}" <<EOF
TOKEN=${TOKEN}
CONTENT=${VALIDATION}
SERVER_PATH=/.well-known/acme-challenge/${TOKEN}
URL=http://${DOMAIN}/.well-known/acme-challenge/${TOKEN}
LOCAL_FILE=${CHALL_FILE}
SERVER_FILE=${SERVER_CHALL_FILE}
EOF

echo ""
echo "============================================================"
echo "[ACTION REQUIRED]"
echo "  Token file: ${TOKEN}"
echo "  Content: ${VALIDATION}"
echo ""
echo "Server path:"
echo "  /.well-known/acme-challenge/${TOKEN}"
echo "Mounted server file:"
echo "  ${SERVER_CHALL_FILE}"
echo ""
echo "Validation URL:"
echo "  http://${DOMAIN}/.well-known/acme-challenge/${TOKEN}"
echo "============================================================"
echo ""

URL="http://${DOMAIN}/.well-known/acme-challenge/${TOKEN}"
TIMEOUT="${WAIT_TIMEOUT_SEC:-900}"
INTERVAL="${POLL_INTERVAL_SEC:-3}"
START="$(date +%s)"

while true; do
  NOW="$(date +%s)"
  ELAPSED="$((NOW-START))"
  if [ "${ELAPSED}" -ge "${TIMEOUT}" ]; then
    echo "ERROR: Timeout (${TIMEOUT}s) - URL: ${URL}"
    exit 2
  fi

  if command -v curl >/dev/null 2>&1; then
    BODY="$(curl -fsS "${URL}" 2>/dev/null || true)"
  elif command -v wget >/dev/null 2>&1; then
    BODY="$(wget -qO- "${URL}" 2>/dev/null || true)"
  else
    echo "ERROR: Neither curl nor wget is available in the container."
    exit 3
  fi
  if [ "${BODY}" = "${VALIDATION}" ]; then
    echo "OK: Challenge verified, proceeding..."
    exit 0
  fi

  echo "WAIT: Not ready (${ELAPSED}s/${TIMEOUT}s), polling..."
  sleep "${INTERVAL}"
done
'@

  $cleanupSh = @'
#!/bin/sh
TOKEN="${CERTBOT_TOKEN}"
rm -f "/challenges/${TOKEN}" || true
rm -f "/server-challenges/${TOKEN}" || true
exit 0
'@

  $authPath = Join-Path $Work "auth.sh"
  $cleanupPath = Join-Path $Work "cleanup.sh"

  Write-Utf8NoBomLf $authPath $authSh
  Write-Utf8NoBomLf $cleanupPath $cleanupSh

  if (-not (Test-Path -LiteralPath $ServerChallengeDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $ServerChallengeDir -ErrorAction Stop | Out-Null
  }

  # Docker マウントパス
  $workMount = ConvertTo-DockerPath $Work
  $challengesMount = ConvertTo-DockerPath $Challenges
  $leMount = ConvertTo-DockerPath $LetsEncrypt
  $logsMount = ConvertTo-DockerPath $Logs
  $serverChallengeMount = ConvertTo-DockerPath $ServerChallengeDir

  Write-Host ""
  Write-Host (T "LE.Ready") -ForegroundColor Cyan
  Write-Host (T "LE.Domain" @($Domain))
  Write-Host (T "LE.ChallengeDir") -ForegroundColor Cyan
  Write-Host ("  " + $Challenges) -ForegroundColor Yellow
  Write-Host (T "LE.ServerChallengeDir") -ForegroundColor Cyan
  Write-Host ("  " + $ServerChallengeDir) -ForegroundColor Yellow
  Write-Host (T "LE.ExportDir") -ForegroundColor Cyan
  Write-Host ("  " + $ExportDir) -ForegroundColor Yellow
  Write-Host ""

  # 動作説明と確認
  Write-Host ("=" * 60) -ForegroundColor Gray
  Write-Host (T "LE.HowItWorksTitle") -ForegroundColor Magenta
  Write-Host (T "LE.HowItWorksDesc")
  Write-Host (T "LE.UrlPattern" @($Domain)) -ForegroundColor Gray
  Write-Host ("=" * 60) -ForegroundColor Gray
  Write-Host ""
  Write-Host (T "LE.ConfirmStartPrompt") -ForegroundColor Yellow
  $null = Read-Host (T "LE.PressEnterToProceed")
  Write-Host ""

  # Docker マウント自己チェック
  Write-Host (T "LE.DockerMountCheck") -ForegroundColor Cyan
  docker run --rm -v "${workMount}:/work" -v "${challengesMount}:/challenges" -v "${serverChallengeMount}:/server-challenges" alpine:3.19 sh -c "ls -la /work && test -f /work/auth.sh && ls -la /challenges && echo OK_AUTH_SH"
  if ($LASTEXITCODE -ne 0) {
    throw (T "LE.DockerMountFailed")
  }

  # certbot 実行
  Write-Host ""
  Write-Host (T "LE.StartingCertbot") -ForegroundColor Cyan

  $cmd = @(
    "run", "--rm", "-it",
    "-e", "WAIT_TIMEOUT_SEC=$WaitTimeoutSec",
    "-e", "POLL_INTERVAL_SEC=$PollIntervalSec",
    "-v", "${workMount}:/work",
    "-v", "${challengesMount}:/challenges",
    "-v", "${serverChallengeMount}:/server-challenges",
    "-v", "${leMount}:/etc/letsencrypt",
    "-v", "${logsMount}:/var/log/letsencrypt",
    "certbot/certbot:latest",
    "certonly",
    "--manual",
    "--preferred-challenges", "http",
    "--manual-auth-hook", "sh /work/auth.sh",
    "--manual-cleanup-hook", "sh /work/cleanup.sh"
  )
  foreach ($d in $domainList) {
    $cmd += "-d"
    $cmd += $d
  }
  $cmd += @(
    "--agree-tos",
    "--no-eff-email",
    "-m", $Email
  )

  # certbot 実行（CAA SERVFAIL のみ自動再試行）
  $logPath = Join-Path $Logs "letsencrypt.log"
  $maxAttempts = [Math]::Max(1, $CaaServfailRetries + 1)
  $attempt = 0
  $exitCode = 1

  while ($attempt -lt $maxAttempts) {
    $attempt++
    if ($maxAttempts -gt 1) {
      Write-Host (T "LE.CertbotAttempt" @($attempt, $maxAttempts)) -ForegroundColor Cyan
    }

    $dockerOutput = @()
    docker @cmd 2>&1 | Tee-Object -Variable dockerOutput
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
      break
    }

    $errorDetails = ""
    $logContent = @()
    if (Test-Path -LiteralPath $logPath -PathType Leaf) {
      $logContent = Get-Content -LiteralPath $logPath -Tail 50 -ErrorAction SilentlyContinue
      $errorDetails = ($logContent -join "`n")
    }

    $allOutput = ($dockerOutput -join "`n") + "`n" + $errorDetails

    if ($allOutput -match "too many certificates.*already issued" -or
      $allOutput -match "rate.*limit" -or
      $allOutput -match "retry after") {
      Write-Host ""
      Write-Host (T "LE.RateLimitError") -ForegroundColor Yellow
      Write-Host ""
      if ($allOutput -match "retry after ([0-9-]+ [0-9:]+ UTC)") {
        Write-Host (T "LE.RateLimitRetryAfter" @($matches[1])) -ForegroundColor Yellow
      }
      Write-Host (T "LE.RateLimitHint") -ForegroundColor Cyan
      Write-Host ""
      Write-Host (T "LE.RateLimitFailed") -ForegroundColor Yellow
      throw (T "LE.RateLimitFailed")
    }

    $isCaaServfail = ($allOutput -match "DNS problem: SERVFAIL looking up CAA")
    if ($isCaaServfail -and $attempt -lt $maxAttempts) {
      Write-Host ""
      Write-Host (T "LE.CaaServfailRetryDetected" @($attempt, $maxAttempts, $CaaServfailRetryDelaySec)) -ForegroundColor Yellow
      if (-not [string]::IsNullOrWhiteSpace($errorDetails)) {
        Write-Host ""
        Write-Host (T "LE.ErrorLogTail") -ForegroundColor Yellow
        Write-Host ($logContent -join "`n")
      }
      Start-Sleep -Seconds $CaaServfailRetryDelaySec
      Write-Host ""
      continue
    }

    Write-Host ""
    Write-Host (T "LE.CertbotFailed" @($exitCode, $logPath)) -ForegroundColor Red
    if ($isCaaServfail) {
      Write-Host (T "LE.CaaServfailRetryExhausted" @($maxAttempts)) -ForegroundColor Yellow
    }
    if (-not [string]::IsNullOrWhiteSpace($errorDetails)) {
      Write-Host ""
      Write-Host (T "LE.ErrorLogTail") -ForegroundColor Yellow
      Write-Host ($logContent -join "`n")
    }
    throw (T "LE.CertbotFailed" @($exitCode, $logPath))
  }

  # 証明書エクスポート
  Write-Host ""
  Write-Host (T "LE.Exporting") -ForegroundColor Cyan

  $rc = Export-CertificateFromContainer $ExportDir $leMount $safeDomain
  if ($rc -ne 0) {
    Write-Host (T "LE.ExportFailedTrying" @($ExportDir, $FallbackExportDir)) -ForegroundColor Yellow
    # フォールバック先の作成を試行
    try {
      if (-not (Test-Path -LiteralPath $FallbackExportDir -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $FallbackExportDir -ErrorAction Stop | Out-Null
      }
    }
    catch {
      Write-Host (T "LE.ExportDirCreateFailed" @($FallbackExportDir, "current directory")) -ForegroundColor Yellow
      $FallbackExportDir = Join-Path (Get-Location).Path "le-export-$(Get-Date -Format 'yyyyMMdd_HHmmss')"
      New-Item -ItemType Directory -Force -Path $FallbackExportDir -ErrorAction Stop | Out-Null
      Write-Host (T "LE.ExportDirFallback" @($FallbackExportDir)) -ForegroundColor Yellow
    }
  
    $rc2 = Export-CertificateFromContainer $FallbackExportDir $leMount $safeDomain
    if ($rc2 -ne 0) {
      # 最後の手段：カレントディレクトリ
      $finalFallback = Join-Path (Get-Location).Path "le-export-$(Get-Date -Format 'yyyyMMdd_HHmmss')"
      try {
        New-Item -ItemType Directory -Force -Path $finalFallback -ErrorAction Stop | Out-Null
        Write-Host (T "LE.ExportFailedTrying" @($FallbackExportDir, $finalFallback)) -ForegroundColor Yellow
        $rc3 = Export-CertificateFromContainer $finalFallback $leMount $safeDomain
        if ($rc3 -ne 0) {
          Write-Host (T "LE.ExportFailed" @($ExportDir, $FallbackExportDir)) -ForegroundColor Red
          # Write-Host handled in catch but good to log here too? Throw will pass message.
          throw (T "LE.ExportFailed" @($ExportDir, $FallbackExportDir))
        }
        else {
          $ExportDir = $finalFallback
        }
      }
      catch {
        Write-Host (T "LE.ExportFailed" @($ExportDir, $FallbackExportDir)) -ForegroundColor Red
        # Write-Host handled in catch
        throw (T "LE.ExportFailed" @($ExportDir, $FallbackExportDir))
      }
    }
    else {
      $ExportDir = $FallbackExportDir
    }
  }

  # 最終検証
  $fullchain = Join-Path $ExportDir "fullchain.pem"
  $privkey = Join-Path $ExportDir "privkey.pem"

  if (-not (Test-Path -LiteralPath $fullchain -PathType Leaf) -or
    -not (Test-Path -LiteralPath $privkey -PathType Leaf)) {
    Write-Host (T "LE.ExportFilesMissing" @($fullchain, $privkey)) -ForegroundColor Red
    throw (T "LE.ExportFilesMissing" @($fullchain, $privkey))
  }

  $len1 = (Get-Item $fullchain).Length
  $len2 = (Get-Item $privkey).Length
  if ($len1 -le 0 -or $len2 -le 0) {
    Write-Host (T "LE.ExportZeroBytes" @($fullchain, $len1, $privkey, $len2)) -ForegroundColor Red
    throw (T "LE.ExportZeroBytes" @($fullchain, $len1, $privkey, $len2))
  }

  Write-Host ""
  Write-Host (T "LE.ExportSuccess" @($fullchain, $len1)) -ForegroundColor Green
  Write-Host ""
  Write-Host (T "LE.ExportSuccess" @($privkey, $len2)) -ForegroundColor Green
  Write-Host ""

  try {
    $baseResolved = (Resolve-Path -LiteralPath $Base).Path.TrimEnd('\', '/')
    $exportResolved = (Resolve-Path -LiteralPath $ExportDir).Path.TrimEnd('\', '/')
    if (-not $exportResolved.StartsWith($baseResolved, [System.StringComparison]::OrdinalIgnoreCase)) {
      Remove-Item -LiteralPath $Base -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
  catch { }

  Write-Host (T "LE.CompletedMsg")
  Exit-ToolkitWithPause -Message (T "LE.PressAnyKeyToReturn") -ExitCode 99
}
catch {
  Write-Host ""
  Write-ToolkitException -ErrorRecord $_
  Exit-ToolkitWithPause -Message (T "LE.PressAnyKeyToReturn") -ExitCode 99
}
