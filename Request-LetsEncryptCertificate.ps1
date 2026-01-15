<#
.SYNOPSIS
Let's Encrypt 証明書を Docker で自動申請するスクリプト

.DESCRIPTION
このスクリプトは、Docker + certbot を使用して Let's Encrypt から
無料の SSL 証明書を取得します。HTTP-01 チャレンジ方式を使用し、
手動でチャレンジファイルをサーバーに配置する必要があります。

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

.PARAMETER ExportDir
証明書エクスポート先ディレクトリ

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
#>

param(
  [Parameter(Mandatory = $true)]
  [string]$Domain,

  [Parameter(Mandatory = $true)]
  [string]$Email,

  [Parameter(Mandatory = $false)]
  [string]$ServerChallengeDir = "C:\acme-webroot\.well-known\acme-challenge",

  [Parameter(Mandatory = $false)]
  [int]$WaitTimeoutSec = 900,

  [Parameter(Mandatory = $false)]
  [int]$PollIntervalSec = 3,

  [Parameter(Mandatory = $false)]
  [string]$ExportDir = "",

  [Parameter(Mandatory = $false)]
  [string]$FallbackExportDir = "C:\le-out",

  [Parameter(Mandatory = $false)]
  [ValidateSet("ja", "zh", "en")]
  [string]$Lang = "ja"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# i18n 初期化
$i18nModule = Join-Path $PSScriptRoot "lib\i18n.ps1"
if (-not (Test-Path -LiteralPath $i18nModule -PathType Leaf)) { throw "i18n module not found: $i18nModule" }
. $i18nModule
$__i18n = Initialize-I18n -Lang $Lang -BaseDir $PSScriptRoot
function T([string]$Key, [object[]]$FormatArgs = @()) { return Get-I18nText -I18n $__i18n -Key $Key -FormatArgs $FormatArgs }

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

# コンテナから証明書をエクスポート
function Export-CertificateFromContainer([string]$dstDir, [string]$leMount, [string]$domain) {
  New-Item -ItemType Directory -Force -Path $dstDir | Out-Null

  $fullchain = Join-Path $dstDir "fullchain.pem"
  $privkey = Join-Path $dstDir "privkey.pem"

  # fullchain
  $fc = docker run --rm -v "${leMount}:/etc/letsencrypt:ro" alpine:3.19 sh -c "cat /etc/letsencrypt/live/$domain/fullchain.pem"
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($fc)) { return 10 }
  $fc | Set-Content -Encoding ascii -NoNewline $fullchain

  # privkey
  $pk = docker run --rm -v "${leMount}:/etc/letsencrypt:ro" alpine:3.19 sh -c "cat /etc/letsencrypt/live/$domain/privkey.pem"
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pk)) { return 11 }
  $pk | Set-Content -Encoding ascii -NoNewline $privkey

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

# === メイン処理 ===

Assert-CommandExists "docker"

# 作業ディレクトリ構築
$safeDomain = $Domain.Replace('*', '_')
$Base = Join-Path $PSScriptRoot ("le-work-" + $safeDomain)
$Work = Join-Path $Base "work"
$Challenges = Join-Path $Work "challenges"
$LetsEncrypt = Join-Path $Base "letsencrypt"
$Logs = Join-Path $Base "logs"

New-Item -ItemType Directory -Force -Path $Challenges, $LetsEncrypt, $Logs | Out-Null

# エクスポート先
if ([string]::IsNullOrWhiteSpace($ExportDir)) {
  $ExportDir = Join-Path $Base "out"
}
New-Item -ItemType Directory -Force -Path $ExportDir | Out-Null

# hook スクリプト生成（auth.sh / cleanup.sh）
$authSh = @'
#!/bin/sh
set -eu
DOMAIN="${CERTBOT_DOMAIN}"
TOKEN="${CERTBOT_TOKEN}"
VALIDATION="${CERTBOT_VALIDATION}"

CHALL_DIR="/work/challenges"
CHALL_FILE="${CHALL_DIR}/${TOKEN}"

mkdir -p "${CHALL_DIR}"
printf "%s" "${VALIDATION}" > "${CHALL_FILE}"

echo ""
echo "============================================================"
echo "[ACTION REQUIRED]"
echo "  Token file: ${TOKEN}"
echo "  Content: ${VALIDATION}"
echo ""
echo "Server path:"
echo "  /.well-known/acme-challenge/${TOKEN}"
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

  BODY="$(curl -fsS "${URL}" 2>/dev/null || true)"
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
set -eu
TOKEN="${CERTBOT_TOKEN}"
rm -f "/work/challenges/${TOKEN}" || true
exit 0
'@

$authPath = Join-Path $Work "auth.sh"
$cleanupPath = Join-Path $Work "cleanup.sh"

Write-Utf8NoBomLf $authPath $authSh
Write-Utf8NoBomLf $cleanupPath $cleanupSh

# Docker マウントパス
$workMount = ConvertTo-DockerPath $Work
$leMount = ConvertTo-DockerPath $LetsEncrypt
$logsMount = ConvertTo-DockerPath $Logs

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

# Docker マウント自己チェック
Write-Host (T "LE.DockerMountCheck") -ForegroundColor Cyan
docker run --rm -v "${workMount}:/work" alpine:3.19 sh -c "ls -la /work && test -f /work/auth.sh && echo OK_AUTH_SH"
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
  "-v", "${leMount}:/etc/letsencrypt",
  "-v", "${logsMount}:/var/log/letsencrypt",
  "certbot/certbot:latest",
  "certonly",
  "--manual",
  "--preferred-challenges", "http",
  "--manual-auth-hook", "sh /work/auth.sh",
  "--manual-cleanup-hook", "sh /work/cleanup.sh",
  "-d", $Domain,
  "--agree-tos",
  "--no-eff-email",
  "-m", $Email
)

docker @cmd
if ($LASTEXITCODE -ne 0) {
  throw (T "LE.CertbotFailed" @($LASTEXITCODE, (Join-Path $Logs "letsencrypt.log")))
}

# 証明書エクスポート
Write-Host ""
Write-Host (T "LE.Exporting") -ForegroundColor Cyan

$rc = Export-CertificateFromContainer $ExportDir $leMount $safeDomain
if ($rc -ne 0) {
  Write-Host (T "LE.ExportFailedTrying" @($ExportDir, $FallbackExportDir)) -ForegroundColor Yellow
  $rc2 = Export-CertificateFromContainer $FallbackExportDir $leMount $safeDomain
  if ($rc2 -ne 0) {
    throw (T "LE.ExportFailed" @($ExportDir, $FallbackExportDir))
  }
  else {
    $ExportDir = $FallbackExportDir
  }
}

# 最終検証
$fullchain = Join-Path $ExportDir "fullchain.pem"
$privkey = Join-Path $ExportDir "privkey.pem"

$len1 = (Get-Item $fullchain).Length
$len2 = (Get-Item $privkey).Length
if ($len1 -le 0 -or $len2 -le 0) {
  throw (T "LE.ExportZeroBytes" @($fullchain, $len1, $privkey, $len2))
}

Write-Host ""
Write-Host (T "LE.ExportSuccess" @($fullchain, $len1)) -ForegroundColor Green
Write-Host (T "LE.ExportSuccess" @($privkey, $len2)) -ForegroundColor Green
Write-Host ""
