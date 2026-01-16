# SSL Certificate Management Tools

This repository provides PowerShell scripts to manage SSL/TLS certificates, keys, and CSRs.
The README includes Japanese, Chinese, and English usage guidance.

---

## 日本語 (JA)

### 概要
証明書・秘密鍵・CSR を扱う PowerShell スクリプト集です。多機関対応と多言語対応を前提にしています。

### 事前準備
- PowerShell 5.1 以上 または PowerShell 7.x
- OpenSSL（既定: `C:\Program Files\Git\usr\bin\openssl.exe`）
- 必要なら `passphrase.txt`（暗号化鍵用）

### フォルダ構成
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

### スクリプト一覧と使い方

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
フルチェーン生成／チェーンファイル分離（Apache chainfile 対応）。
```powershell
# fullchain（証明書+中間）
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer

# chainfile（証明書単体 + チェーンファイル）
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -OutputStyle chainfile -IntermediateCert .\intermediate.cer

# AIA から中間/ルートを自動取得
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -OutputStyle chainfile -AutoFetchChain
```

### Apache 設定の旧式/新式（fullchain / chainfile）
Apache では主に 2 つの配置方法があります。
- fullchain: `SSLCertificateFile` に「サーバ証明書 + 中間証明書」を結合したファイルを指定
- chainfile: `SSLCertificateFile` に「サーバ証明書単体」、`SSLCertificateChainFile` に「中間証明書（必要なら交差ルート）」を指定

本ツールでは `Merge-CertificateChain.ps1` の `-OutputStyle` で切り替えできます。  
Chrome などのブラウザ認識は「チェーンが完全か」に依存するため、証明書単体＋チェーンファイル方式でも問題なく運用可能です。

### Apache / Tomcat の設定例

Apache（fullchain 方式）:
```apache
SSLCertificateFile      /path/to/fullchain.cer
SSLCertificateKeyFile   /path/to/server.key
```

Apache（chainfile 方式）:
```apache
SSLCertificateFile      /path/to/server.cer
SSLCertificateKeyFile   /path/to/server.key
SSLCertificateChainFile /path/to/server.chain.cer
```

Tomcat（PKCS#12 方式）:
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

### パスワードファイル
`passphrase.txt` の探索順序（最大 6 階層）:  
鍵と同階層 → 上位 → 機関直下 → old/new 直下 → スクリプト直下 → 環境変数 `PASS_FILE`

---

## 中文 (ZH)

### 概览
用于管理证书、私钥、CSR 的 PowerShell 脚本集合，支持多机构、多语言。

### 准备
- PowerShell 5.1+ 或 PowerShell 7.x
- OpenSSL（默认: `C:\Program Files\Git\usr\bin\openssl.exe`）
- 如有加密私钥，准备 `passphrase.txt`

### 目录结构
```
ssl_maker/
├── old/                    # 旧证书/私钥/CSR
├── new/                    # 新生成的 CSR/私钥
├── merged/                 # 合并后的链文件
├── resources/
│   └── downloaded/         # AIA 自动下载缓存
└── *.ps1
```

### 脚本与用法

1) `Get-CertificateInfo.ps1`  
查看证书/私钥/CSR 信息。
```powershell
.\Get-CertificateInfo.ps1
.\Get-CertificateInfo.ps1 -Path .\new\example.com\example.com.cer -Table
.\Get-CertificateInfo.ps1 -Lang zh -PrettyTable
.\Get-CertificateInfo.ps1 -Path .\server.cer -ChainFile .\server.chain.cer
```

2) `Merge-CertificateChain.ps1`  
生成 fullchain 或 chainfile（Apache chainfile）。
```powershell
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -OutputStyle chainfile -IntermediateCert .\intermediate.cer
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -OutputStyle chainfile -AutoFetchChain
```

### Apache 配置方式（fullchain / chainfile）
Apache 常见有两种配置方式：
- fullchain：`SSLCertificateFile` 使用“服务器证书 + 中间证书”的合并文件
- chainfile：`SSLCertificateFile` 使用“服务器证书单体”，`SSLCertificateChainFile` 使用“中间证书（必要时可加交叉根）”

本工具通过 `Merge-CertificateChain.ps1` 的 `-OutputStyle` 切换。  
浏览器是否信任取决于链是否完整，与是否使用 chainfile 方式无冲突。

### Apache / Tomcat 配置示例

Apache（fullchain）:
```apache
SSLCertificateFile      /path/to/fullchain.cer
SSLCertificateKeyFile   /path/to/server.key
```

Apache（chainfile）:
```apache
SSLCertificateFile      /path/to/server.cer
SSLCertificateKeyFile   /path/to/server.key
SSLCertificateChainFile /path/to/server.chain.cer
```

Tomcat（PKCS#12）:
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
解密私钥。
```powershell
.\Convert-KeyToPlaintext.ps1 -Path .\new -Recurse -Overwrite
```

4) `New-CertificateSigningRequest.ps1`  
生成 CSR/私钥。
```powershell
.\New-CertificateSigningRequest.ps1 -CN example.com -C JP -ST Tokyo -L Tokyo -O "Example Corp"
```

5) `Export-CertificateModulus.ps1`  
导出 Modulus。
```powershell
.\Export-CertificateModulus.ps1 -RootDir .\old
```

6) `Test-CertificateKeyMatch.ps1`  
生成一致性检查报告。
```powershell
.\Test-CertificateKeyMatch.ps1 -Mode both
```

7) `New-CertificateSigningRequestFromOld.ps1`  
基于旧证书生成新 CSR/私钥。
```powershell
.\New-CertificateSigningRequestFromOld.ps1
```

8) `Request-LetsEncryptCertificate.ps1`  
Docker + certbot 申请证书。
```powershell
.\Request-LetsEncryptCertificate.ps1 -Domain example.com -Email admin@example.com
```

9) `Repair-PemFile.ps1`  
修复/规范化 PEM。
```powershell
.\Repair-PemFile.ps1 -Fullchain .\fullchain.pem -Privkey .\privkey.pem
```

### 密码文件
`passphrase.txt` 搜索顺序:  
同目录 → 上级 → 机构目录 → old/new → 脚本目录 → 环境变量 `PASS_FILE`

---

## English (EN)

### Overview
PowerShell scripts to manage certificates, keys, and CSRs with multi-org and multi-language support.

### Prerequisites
- PowerShell 5.1+ or PowerShell 7.x
- OpenSSL (default: `C:\Program Files\Git\usr\bin\openssl.exe`)
- `passphrase.txt` for encrypted keys if needed

### Folder layout
```
ssl_maker/
├── old/                    # Existing cert/key/CSR
├── new/                    # Newly generated CSR/key
├── merged/                 # Merged chains
├── resources/
│   └── downloaded/         # AIA auto-fetch cache
└── *.ps1
```

### Scripts and usage

1) `Get-CertificateInfo.ps1`  
Show certificate/key/CSR info.
```powershell
.\Get-CertificateInfo.ps1
.\Get-CertificateInfo.ps1 -Path .\new\example.com\example.com.cer -Table
.\Get-CertificateInfo.ps1 -Lang en -PrettyTable
.\Get-CertificateInfo.ps1 -Path .\server.cer -ChainFile .\server.chain.cer
```

2) `Merge-CertificateChain.ps1`  
Generate fullchain or chainfile (Apache chainfile).
```powershell
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -OutputStyle chainfile -IntermediateCert .\intermediate.cer
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -OutputStyle chainfile -AutoFetchChain
```

### Apache setup (fullchain / chainfile)
Apache commonly uses two styles:
- fullchain: `SSLCertificateFile` points to a file that includes “server cert + intermediates”
- chainfile: `SSLCertificateFile` points to “server cert only” and `SSLCertificateChainFile` points to “intermediate certs (optionally cross roots)”

This tool switches via `-OutputStyle` in `Merge-CertificateChain.ps1`.  
Browser trust depends on a complete chain, not on which Apache style you choose.

### Apache / Tomcat examples

Apache (fullchain):
```apache
SSLCertificateFile      /path/to/fullchain.cer
SSLCertificateKeyFile   /path/to/server.key
```

Apache (chainfile):
```apache
SSLCertificateFile      /path/to/server.cer
SSLCertificateKeyFile   /path/to/server.key
SSLCertificateChainFile /path/to/server.chain.cer
```

Tomcat (PKCS#12):
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
Decrypt encrypted private keys.
```powershell
.\Convert-KeyToPlaintext.ps1 -Path .\new -Recurse -Overwrite
```

4) `New-CertificateSigningRequest.ps1`  
Generate CSR and private key.
```powershell
.\New-CertificateSigningRequest.ps1 -CN example.com -C JP -ST Tokyo -L Tokyo -O "Example Corp"
```

5) `Export-CertificateModulus.ps1`  
Export modulus values.
```powershell
.\Export-CertificateModulus.ps1 -RootDir .\old
```

6) `Test-CertificateKeyMatch.ps1`  
Generate key/cert/CSR match report.
```powershell
.\Test-CertificateKeyMatch.ps1 -Mode both
```

7) `New-CertificateSigningRequestFromOld.ps1`  
Generate new CSR/key from existing cert info.
```powershell
.\New-CertificateSigningRequestFromOld.ps1
```

8) `Request-LetsEncryptCertificate.ps1`  
Request Let's Encrypt cert using Docker + certbot.
```powershell
.\Request-LetsEncryptCertificate.ps1 -Domain example.com -Email admin@example.com
```

9) `Repair-PemFile.ps1`  
Repair/normalize PEM files.
```powershell
.\Repair-PemFile.ps1 -Fullchain .\fullchain.pem -Privkey .\privkey.pem
```

### Passphrase file
`passphrase.txt` search order:  
same folder → parent folders → org folder → old/new → script root → env `PASS_FILE`
