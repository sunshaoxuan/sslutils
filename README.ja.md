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
├── merged/                 # 結合済みチェーン
│   ├── old/
│   └── new/
├── resources/
│   └── downloaded/         # AIA 自動取得の保存先
└── *.ps1
```

## スクリプト一覧と使い方

1) `Get-CertificateInfo.ps1`  
証明書・秘密鍵・CSR の情報を表示。
```powershell
.\Get-CertificateInfo.ps1
.\Get-CertificateInfo.ps1 -Path .\new\example.com\example.com.cer -Table
.\Get-CertificateInfo.ps1 -Lang ja -PrettyTable
.\Get-CertificateInfo.ps1 -Path .\server.cer -ChainFile .\server.chain.cer
.\Get-CertificateInfo.ps1 -Lang ja
```

2) `Merge-CertificateChain.ps1`  
fullchain を生成します（証明書 + 中間）。必要なら交差ルートを末尾に追加できます。
```powershell
# fullchain（証明書+中間）
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer

# fullchain + 交差ルート
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer -RootCert .\cross-root.cer
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
.\Convert-KeyToPlaintext.ps1 -Path .\new\example.com\server.key
.\Convert-KeyToPlaintext.ps1 -Path .\new -Recurse -Overwrite
```

4) `New-CertificateSigningRequest.ps1`  
CSR と秘密鍵を生成。
```powershell
.\New-CertificateSigningRequest.ps1 -CN example.com -C JP -ST Tokyo -L Tokyo -O "Example Corp"
.\New-CertificateSigningRequest.ps1 -CN example.com -PassFile .\passphrase.txt -Overwrite
```

5) `Export-CertificateModulus.ps1`  
証明書/鍵の Modulus を一覧出力。
```powershell
.\Export-CertificateModulus.ps1 -RootDir .\old
.\Export-CertificateModulus.ps1 -RootDir . -PassFile .\passphrase.txt
```

6) `Test-CertificateKeyMatch.ps1`  
証明書/鍵/CSR の一致確認レポート。
```powershell
.\Test-CertificateKeyMatch.ps1 -Mode both
.\Test-CertificateKeyMatch.ps1 -Mode old -PassFile .\passphrase.txt
```

7) `New-CertificateSigningRequestFromOld.ps1`  
旧証明書情報から新 CSR/鍵を生成。
```powershell
.\New-CertificateSigningRequestFromOld.ps1
.\New-CertificateSigningRequestFromOld.ps1 -Org example.com -Overwrite
```

8) `Request-LetsEncryptCertificate.ps1`  
Docker + certbot で Let's Encrypt を申請。
```powershell
.\Request-LetsEncryptCertificate.ps1 -Domain example.com -Email admin@example.com
```

9) `Repair-PemFile.ps1`  
PEM の修復・正規化。
```powershell
.\Repair-PemFile.ps1 -Fullchain .\fullchain.pem -Privkey .\privkey.pem
```

## パスワードファイル
`passphrase.txt` の探索順序（最大 6 階層）:  
鍵と同階層 → 上位 → 機関直下 → old/new 直下 → スクリプト直下 → 環境変数 `PASS_FILE`
