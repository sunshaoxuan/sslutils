# SSL 证书管理工具 (SSL Certificate Management Toolkit)

语言:
- English: [README.md](README.md)
- 中文: README.zh.md (本文件)
- 日本語: [README.ja.md](README.ja.md)

**Ver 1.5.3**
https://github.com/sunshaoxuan

这是一个功能强大的 PowerShell 脚本集合，用于自动化管理 SSL 证书、私钥和 CSR。支持多语言（可通过配置文件扩展）、多机构管理，并提供统一的菜单界面。

---

## 📅 版本更新 (v1.5.3)
- **Let's Encrypt 输出整理**: 默认导出到 `output/self-signed/lets-encrypt/<domain>`，临时工作目录移到 `temp/lets-encrypt/`，成功后自动清理。
- **PEM 自动修复**: 导出的 `fullchain.pem` 和 `privkey.pem` 会自动规范化换行和头尾格式，生成后可直接使用。
- **CAA SERVFAIL 自动重试**: 遇到临时性的 DNS `CAA SERVFAIL` 时，Let's Encrypt 申请会自动重试。
- **私钥识别改进**: `Get-CertificateInfo.ps1` 现在能更准确识别 PEM 私钥，并兼容 PKCS#8 / EC 私钥读取。
- **完整历史**: 详见 [CHANGELOG.md](CHANGELOG.md)。

## 📅 历史更新
- **v1.4.x**: 术语统一、TSV 默认文件名调整、仓库清理。
- **v1.3.x**: 输出目录统一到 `output/`，脚本重命名为 Verb-Noun 格式，新增自签证书生成。
- **v1.2.x**: 统一菜单入口、PFX 生成、全面多语言支持。

详细变更历史请参见 [CHANGELOG.md](CHANGELOG.md)。

---

## 🚀 快速开始

```powershell
.\utils\Install-Dependencies.ps1   # 首次使用：安装 OpenSSL
.\Invoke-SSLToolkit.ps1
```

推荐使用集成菜单工具，无需记忆复杂的参数。

首次启动默认为英语。可在主菜单中选择 **Language** 切换语言（中文/日语/英语等），选择会自动保存。

也可以通过启动参数指定语言：
```powershell
.\Invoke-SSLToolkit.ps1 -Lang zh  # 中文
.\Invoke-SSLToolkit.ps1 -Lang ja  # 日本語
.\Invoke-SSLToolkit.ps1 -Lang en  # English
```

---

## 📂 目录结构

```
ssl_maker/
├── new/                    # 存放新生成的 CSR / 私钥 / 原始证书
├── old/                    # 存放旧证书（用于归档或提取信息）
├── output/                 # [输出根目录]
│   ├── merged/             # 合并后的完整证书链 & PFX
│   └── self-signed/        # 自签证书输出
├── CertStore/              # 根证书与中间证书库
├── resources/              # 资源文件 (语言包)
│   ├── strings.ja.psd1     # 日语
│   ├── strings.zh.psd1     # 中文
│   └── strings.en.psd1     # 英语
├── CertConfig.psd1         # 证书匹配规则配置文件
├── config.json             # 路径与工具配置
├── Invoke-SSLToolkit.ps1   # [入口] 主菜单工具
└── utils/                  # 各独立功能脚本
    ├── Install-Dependencies.ps1 # OpenSSL 自动下载安装
    └── bin/                # 便携工具二进制文件
```

---

## 🛠️ 功能列表

此工具集包含以下独立脚本，既可以通过 `Invoke-SSLToolkit.ps1` 调用，也可以单独使用：

### 1. 证书查看与校验
**脚本**: `Get-CertificateInfo.ps1`
- 查看 .cer, .key, .csr, .pfx 的详细信息（Subject, Issuer, 有效期）。
- 多段式证书链逐块显示（服务器/中间/根），含源证书文件名标注。
- 自动校验 **证书 ⇔ 私钥** 是否匹配（Modulus Check）。
- 支持解密 PFX 查看完整证书链。

### 2. 证书链合并 & PFX 生成
**脚本**: `Merge-CertificateChain.ps1`
- 自动识别服务器证书，寻找匹配的中间证书并合并为 fullchain。
- 支持3段式（服务器+中间+交叉根）和4段式（+根CA）合并模式。
- 自动查找对应的 `.key` 文件，生成 `.pfx` (PKCS#12) 文件。
- 检测客户提供的 PFX，提示用户选择沿用或重新生成。
- 支持批量处理 `new/` 目录下的所有证书。

### 3. CSR (证书签名请求) 生成
- **全新生成**: `New-CertificateSigningRequest.ps1`
- **基于旧证书续期**: `New-CertificateSigningRequestFromOld.ps1` (自动从 old 目录读取信息)。

### 4. 私钥管理
- **解密/去密**: `Convert-KeyToPlaintext.ps1` (将加密的私钥转换为无需密码的 RSA Key)。

### 5. 自签证书
通过主菜单的"自签证书"子菜单选择：
- **自签证书**: `Request-SelfSignedCertificate.ps1` — 交互式选择有效期（90天 / 1年 / 3年 / 10年），支持 Quick 模式和 Custom 模式。CLI 可用 `-Days` 参数直接指定天数。
- **Let's Encrypt**: `Request-LetsEncryptCertificate.ps1` (Docker + Certbot 封装)。
  默认导出目录为 `output/self-signed/lets-encrypt/<domain>`；运行时工作文件位于 `temp/lets-encrypt/`，成功后自动删除。当前 challenge 信息会写入工作目录中的 `current-challenge.txt`。

### 6. 其他工具
- **PEM 修复**: `Repair-PemFile.ps1` (修复换行符问题)。
  不传参数时，会先让你从 `old`、`new`、`output/merged`、`output/self-signed` 中选来源，再选检测到的 PEM 配对；手工输入绝对路径是最后一个选项。
- **同步**: `Sync-ToMerged.ps1` (将 new/ 中的 key/csr/tsv 同步到 output/merged/)。
- **组织重命名**: 启动时自动执行（详见下方"文件夹命名约定"章节）。
- **证书更新清单**: `New-ServerList.ps1`（生成/维护证书更新用 TSV，保留人工字段）。

---

## 📁 文件夹命名约定（自动识别组织名）

将 `old/`、`new/` 或 `output/merged/` 下的子文件夹命名为**域名**（如 `example.co.jp`），工具启动时会自动查询该域名对应的组织名称，并提议重命名文件夹。

**工作原理：**

每次启动 `Invoke-SSLToolkit.ps1` 时，会自动运行 `Rename-OrgFolders.ps1 -AutoYes`：

1. 扫描 `old/`、`new/`、`output/merged/` 下所有看起来像域名的子文件夹（包含 `.`）
2. 按以下顺序查询组织名：
   - **本地证书**：从文件夹内的 `.cer` 文件中读取 `O=`（Organization）字段
   - **WHOIS (JPRS)**：对 `.jp` 域名，查询 JPRS WHOIS 注册信息中的组织名
   - **网站探测**：访问 `https://<域名>` 读取 TLS 证书中的组织名或页面标题
3. 查到后，建议将文件夹从 `example.co.jp` 重命名为 `Example Corp (example)`（组织名 + 主机名）
4. 在三个目录中同步重命名，保持一致性

**示例：**

```
重命名前:  old/mail.example.co.jp/   new/mail.example.co.jp/
重命名后:  old/Example Corp (mail)/  new/Example Corp (mail)/
```

这样可以一目了然地识别每个证书属于哪个组织。已重命名的文件夹（包含空格和括号）会被自动跳过。

---

## 🌐 多语言扩展

新增语言只需一步：创建 `resources/strings.xx.psd1` 文件（xx 为语言代码），包含所有翻译键和 `Language.DisplayName` 键。无需修改任何代码，语言会自动出现在主菜单的语言选择中。

---

## 📝 配置示例 (Apache / Tomcat)

本工具生成的 `output/merged/` 目录下的文件可直接用于生产环境。

### Apache (httpd)
使用合并后的 `.cer` (Fullchain) 和无密码 `.key`：

```apache
SSLCertificateFile      /path/to/output/merged/server.cer
SSLCertificateKeyFile   /path/to/new/server.key
```

### Tomcat（PEM：key + cer + chain）
当交付物是 `.key` + `.cer`（以及链文件）时，建议使用该配置：

```xml
<!-- Tomcat server.xml -->
<Connector port="8443"
  protocol="org.apache.coyote.http11.Http11NioProtocol"
  SSLEnabled="true">
  <SSLHostConfig>
    <Certificate
      certificateFile="/path/to/server.cer"
      certificateKeyFile="/path/to/server.key"
      certificateChainFile="/path/to/chain.cer"
      type="RSA" />
  </SSLHostConfig>
</Connector>
```

### Tomcat / IIS（PKCS#12 / PFX，可选）
当目标平台要求 keystore 时，可使用 `.pfx`：

```xml
<!-- Tomcat server.xml -->
<Connector port="8443"
  protocol="org.apache.coyote.http11.Http11NioProtocol"
  SSLEnabled="true"
  keystoreFile="/path/to/output/merged/server.pfx"
  keystorePass=""
  keystoreType="PKCS12" />
```
*(注：如果生成 PFX 时未设置密码，keystorePass 为空或省略；如有设置，请填写对应密码)*
*(注：真实部署通常还涉及证书链校验、文件权限、热更新/重载流程等，往往不止几行配置。)*

---

## ⚙️ 环境要求
- **PowerShell 7.x** 或更高版本（脚本启动时自动检查，低于此版本将报错退出）
- OpenSSL（自动解析: `utils/bin/` → `config.json` → Git for Windows → 系统 PATH）

### OpenSSL 安装

如果系统中没有 OpenSSL，可以运行以下命令自动下载便携版:

```powershell
.\utils\Install-Dependencies.ps1
```

这会将 OpenSSL 自动下载并安装到 `utils/bin/` 目录。也可以在 `config.json` 中自定义路径:

```json
"Tools": {
    "OpenSsl": "C:\\path\\to\\openssl.exe"
}
```

## 路径配置（config.json）
目录名和工具路径已支持配置化，默认如下：

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
},
"Tools": {
  "OpenSsl": ""
}
```

默认会显示全球稳定的时区 ID（优先 IANA），避免受操作系统语言影响。
可选配置：如需自定义 `Get-CertificateInfo.ps1` 中时区名称显示，可在 `config.json` 增加 `TimeZoneNames`（键使用 Windows/IANA 时区 ID）。

---

## 📜 公共证书库 (CertStore)

工具内置的根证书和中间证书，用于自动构建完整证书链。详见 [CertStore/README.md](CertStore/README.md)。

| 文件 | 说明 | 下载 |
|------|------|------|
| gsgccr3dvtlsca2020.cer | GlobalSign GCC R3 DV TLS CA 2020 | [下载](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/GlobalSign/gsgccr3dvtlsca2020.cer) |
| nii-odca4g7rsa.cer | NII Open Domain CA - G7 RSA | [下载](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/NII/nii-odca4g7rsa.cer) |
| nii-odca4g8rsa-pem.cer | NII Open Domain CA - G8 RSA | [下载](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/NII/nii-odca4g8rsa-pem.cer) |
| SCRoot2caPem.cer | Security Communication RootCA2 (Root) | [下载](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/Secom/SCRoot2caPem.cer) |
| tlsrsarootca2024cross-pem.cer | SECOM TLS RSA Root CA 2024 (Cross-signed) | [下载](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/Secom/tlsrsarootca2024cross-pem.cer) |

详细变更历史请参见 [CHANGELOG.md](CHANGELOG.md)。
