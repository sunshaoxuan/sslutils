# SSL 证书管理工具

语言版本:
- 中文: README.md
- 日本語: README.ja.md
- English: README.en.md

## 概览
用于管理证书、私钥、CSR 的 PowerShell 脚本集合，支持多机构、多语言。

## 准备
- PowerShell 5.1+ 或 PowerShell 7.x
- OpenSSL（默认: `C:\Program Files\Git\usr\bin\openssl.exe`）
- 如有加密私钥，准备 `passphrase.txt`

## 目录结构
```
ssl_maker/
├── old/                    # 旧证书/私钥/CSR
├── new/                    # 新生成的 CSR/私钥
├── merged/                 # 合并后的链文件
├── resources/
│   └── downloaded/         # AIA 自动下载缓存
└── *.ps1
```

## 脚本与用法

1) `Get-CertificateInfo.ps1`  
查看证书/私钥/CSR 信息。
```powershell
.\Get-CertificateInfo.ps1
.\Get-CertificateInfo.ps1 -Path .\new\example.com\example.com.cer -Table
.\Get-CertificateInfo.ps1 -Lang zh -PrettyTable
.\Get-CertificateInfo.ps1 -Path .\server.cer -ChainFile .\server.chain.cer
```

2) `Merge-CertificateChain.ps1`  
生成 fullchain（服务器证书 + 中间证书），可选追加交叉根。
```powershell
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer

# fullchain + 交叉根
.\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer -RootCert .\cross-root.cer
```

## Apache / Tomcat 配置方式（fullchain）
Apache 与 Tomcat 都建议直接使用 fullchain（服务器证书 + 中间证书，可选交叉根）。

## Apache / Tomcat 配置示例（统一 fullchain）

Apache（fullchain）:
```apache
SSLCertificateFile      /path/to/fullchain.cer
SSLCertificateKeyFile   /path/to/server.key
```

Tomcat（PKCS#12，fullchain 作为输入）:
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

## 密码文件
`passphrase.txt` 搜索顺序:  
同目录 → 上级 → 机构目录 → old/new → 脚本目录 → 环境变量 `PASS_FILE`
