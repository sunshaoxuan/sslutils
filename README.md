# SSL 证书管理工具 (SSL Certificate Management Toolkit)

**Ver 1.2.0**  
**Dev:** TS2课・技管

这是一个功能强大的 PowerShell 脚本集合，用于自动化管理 SSL 证书、私钥和 CSR。支持多语言（中文/日语/英语）、多机构管理，并提供统一的菜单界面。

---

## 📅 版本更新 (v1.2.0)
- **多语言支持**: 全面支持 简体中文、日语、英语（自动根据参数切换）。
- **统一入口**: 新增 `SSL-Toolkit.ps1` 集成菜单，一键调用所有工具。
- **PFX 支持**: 证书合并时自动生成 `.pfx` (PKCS#12) 文件，支持密码保护和无密码模式。
- **智能合并**: `Merge-CertificateChain.ps1` 支持“PFX Only”模式（已合并证书仅生成 PFX）。

---

## 🚀 快速开始

推荐使用集成菜单工具，无需记忆复杂的参数：

```powershell
.\SSL-Toolkit.ps1
```

或者指定语言启动：
```powershell
.\SSL-Toolkit.ps1 -Lang zh  # 中文 (默认)
.\SSL-Toolkit.ps1 -Lang ja  # 日本语
.\SSL-Toolkit.ps1 -Lang en  # English
```

---

## 📂 目录结构

```
ssl_maker/
├── new/                    # 存放新生成的 CSR / 私钥 / 原始证书
├── old/                    # 存放旧证书（用于归档或提取信息）
├── merged/                 # [输出] 合并后的完整证书链 & PFX
├── CertStore/              # 根证书与中间证书库
├── resources/              # 资源文件 (语言包, 缓存)
├── CertConfig.psd1         # 证书匹配规则配置文件
├── SSL-Toolkit.ps1         # [入口] 主菜单工具
└── *.ps1                   # 各独立功能脚本
```

---

## 🛠️ 功能列表

此工具集包含以下独立脚本，既可以通过 `SSL-Toolkit.ps1` 调用，也可以单独使用：

### 1. 证书查看与校验
**脚本**: `Get-CertificateInfo.ps1`
- 查看 .cer, .key, .csr, .pfx 的详细信息（Subject, Issuer, 有效期）。
- 自动校验 **证书 ⇔ 私钥** 是否匹配（Modulus Check）。
- 支持解密 PFX 查看内容。

### 2. 证书链合并 & PFX 生成
**脚本**: `Merge-CertificateChain.ps1`
- 自动识别服务器证书，寻找匹配的中间证书并合并为 fullchain。
- **[新]** 自动查找对应的 `.key` 文件，生成 `.pfx` (PKCS#12) 文件（Tomcat/IIS 必需）。
- 支持批量处理 `new/` 目录下的所有证书。

### 3. CSR (证书签名请求) 生成
- **全新生成**: `New-CertificateSigningRequest.ps1`
- **基于旧证书续期**: `New-CertificateSigningRequestFromOld.ps1` (自动从 old 目录读取信息)。

### 4. 私钥管理
- **解密/去密**: `Convert-KeyToPlaintext.ps1` (将加密的私钥转换为无需密码的 RSA Key)。

### 5. 其他工具
- **Let's Encrypt 申请**: `Request-LetsEncryptCertificate.ps1` (Docker + Certbot 封装)。
- **PEM 修复**: `Repair-PemFile.ps1` (修复换行符问题)。
- **组织重命名**: `Rename-OrgFolders.ps1` (标准化文件夹命名)。
- **服务器列表**: `New-ServerList.ps1` (生成 CSV 格式列表)。

---

## 📝 配置示例 (Apache / Tomcat)

本工具生成的 `merged/` 目录下的文件可直接用于生产环境。

### Apache (httpd)
使用合并后的 `.cer` (Fullchain) 和无密码 `.key`：

```apache
SSLCertificateFile      /path/to/merged/server.cer
SSLCertificateKeyFile   /path/to/new/server.key
```

### Tomcat / IIS
使用生成的 `.pfx` 文件：

```xml
<!-- Tomcat server.xml -->
<Connector port="8443"
  protocol="org.apache.coyote.http11.Http11NioProtocol"
  SSLEnabled="true"
  keystoreFile="/path/to/merged/server.pfx"
  keystorePass="" 
  keystoreType="PKCS12" />
```
*(注：如果生成 PFX 时未设置密码，keystorePass 为空或省略；如有设置，请填写对应密码)*

---

## ⚙️ 环境要求
- Windows (PowerShell 5.1 或 PowerShell 7+)
- OpenSSL (推荐安装 Git for Windows，脚本默认查找 `C:\Program Files\Git\usr\bin\openssl.exe`)
