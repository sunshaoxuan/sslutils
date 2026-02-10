# SSL Certificate Management Tools

言語:
- 中文: README.md
- 日本語: README.ja.md
- English: README.en.md

## 概要
証明書・秘密鍵・CSR を扱う PowerShell スクリプト集です。多機関対応と多言語対応を前提にしています。

## 事前準備
- PowerShell 5.1 以上 または PowerShell 7.x
- OpenSSL（既定: `C:\Program Files\Git\usr\bin\openssl.exe`）
- 必要なら `passphrase.txt`（暗号化鍵用）

## フォルダ構成
```
ssl_maker/
├── old/                    # 旧証明書・鍵・CSR
│   └── org1/
│       ├── server.cer
│       ├── server.key
│       └── server.csr
├── new/                    # 新規生成 CSR・鍵
│   └── org1/
│       └── server.csr
├── output/                 # 出力ルート
│   ├── merged/             # 結合済みチェーン
│   └── self-signed/        # 自己署名証明書の出力
├── resources/
│   └── downloaded/         # AIA 自動取得の保存先
├── temp/                   # 一時ファイル置き場（実行後に自動削除）
└── *.ps1
```

## スクリプト一覧と使い方

1) `Get-CertificateInfo.ps1`  
証明書・秘密鍵・CSR の情報を表示。
```powershell
.\utils\Get-CertificateInfo.ps1
.\utils\Get-CertificateInfo.ps1 -Path .\new\example.com\example.com.cer -Table
.\utils\Get-CertificateInfo.ps1 -Lang ja -PrettyTable
.\utils\Get-CertificateInfo.ps1 -Path .\server.cer -ChainFile .\server.chain.cer
.\utils\Get-CertificateInfo.ps1 -Lang ja
```

2) `Merge-CertificateChain.ps1`  
fullchain を生成します（証明書 + 中間）。必要なら交差ルートを末尾に追加できます。
```powershell
# fullchain（証明書+中間）
.\utils\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer

# fullchain + 交差ルート
.\utils\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer -RootCert .\cross-root.cer
```

## Apache / Tomcat 設定（fullchain）
Apache と Tomcat はどちらも fullchain（証明書 + 中間、必要なら交差ルート）を使用します。

## Apache / Tomcat の設定例（fullchain）

Apache（fullchain 方式）:
```apache
SSLCertificateFile      /path/to/fullchain.cer
SSLCertificateKeyFile   /path/to/server.key
```

Tomcat（PKCS#12 方式、fullchain を入力）:
```bash
openssl pkcs12 -export \
  -in /path/to/server.cer \
  -inkey /path/to/server.key \
  -certfile /path/to/server.chain.cer \
  -out /path/to/server.p12
```
```xml
<Connector port="8443"
  protocol="org.apache.coyote.http11.Http11NioProtocol"
  SSLEnabled="true"
  keystoreFile="/path/to/server.p12"
  keystorePass="changeit"
  keystoreType="PKCS12" />
```

3) `Convert-KeyToPlaintext.ps1`  
暗号化鍵を平文に変換。
```powershell
.\utils\Convert-KeyToPlaintext.ps1 -Path .\new\example.com\server.key
.\utils\Convert-KeyToPlaintext.ps1 -Path .\new -Recurse -Overwrite
```

4) `New-CertificateSigningRequest.ps1`  
CSR と秘密鍵を生成。
```powershell
.\utils\New-CertificateSigningRequest.ps1 -CN example.com -C JP -ST Tokyo -L Tokyo -O "Example Corp"
.\utils\New-CertificateSigningRequest.ps1 -CN example.com -PassFile .\passphrase.txt -Overwrite
```

5) `Export-CertificateModulus.ps1`  
証明書/鍵の Modulus を一覧出力。
```powershell
.\utils\Export-CertificateModulus.ps1 -RootDir .\old
.\utils\Export-CertificateModulus.ps1 -RootDir . -PassFile .\passphrase.txt
```

6) `New-CertificateSigningRequestFromOld.ps1`  
旧証明書情報から新 CSR/鍵を生成。
```powershell
.\utils\New-CertificateSigningRequestFromOld.ps1
.\utils\New-CertificateSigningRequestFromOld.ps1 -Org example.com -Overwrite
```

7) `Request-LetsEncryptCertificate.ps1`  
Docker + certbot で Let's Encrypt を申請。
```powershell
.\utils\Request-LetsEncryptCertificate.ps1 -Domain example.com -Email admin@example.com
```

8) `Request-SelfSignedCertificate.ps1`  
10年有効の自己署名証明書を生成（Let's Encrypt / 公開 CA 署名とは別機能）。
```powershell
.\utils\Request-SelfSignedCertificate.ps1 -CN internal.example.local -Lang ja
```
簡易作成モード: `old/` 配下の機関を選択し、既存証明書の CN から自己署名証明書を生成。  
個別設定モード: CN/Subject/SAN を手動入力して生成。

9) `Repair-PemFile.ps1`  
PEM の修復・正規化。
```powershell
.\utils\Repair-PemFile.ps1 -Fullchain .\fullchain.pem -Privkey .\privkey.pem
```

## パスワードファイル
`passphrase.txt` の探索順序（最大 6 階層）:  
鍵と同階層 → 上位 → 機関直下 → old/new 直下 → スクリプト直下 → 環境変数 `PASS_FILE`

## パス設定（config.json）
ディレクトリ名は `config.json` の `Paths` で設定できます（既定値）:

```json
"Paths": {
  "Old": "old",
  "New": "new",
  "OutputRoot": "output",
  "Merged": "output/merged",
  "SelfSigned": "output/self-signed",
  "Temp": "temp",
  "Resources": "resources",
  "CertConfig": "CertConfig.psd1"
}
```

既定ではタイムゾーン名は地域依存の翻訳を使わず、グローバルに安定した TimeZone ID（IANA 優先）を表示します。  
任意設定として、`config.json` の `TimeZoneNames` で言語別表示名を上書きできます（キーは Windows/IANA の TimeZone ID）。

