# SSL Certificate Management Tools

Languages:
- English: README.md (this file)
- 中文: [README.zh.md](README.zh.md)
- 日本語: [README.ja.md](README.ja.md)

## Overview
PowerShell scripts to manage certificates, keys, and CSRs with multi-org and multi-language support.

## What's New (v1.5.3)
- **Let's Encrypt Output Cleanup**: Issued certificates now go to `output/self-signed/lets-encrypt/<domain>`, while temporary work data moves to `temp/lets-encrypt/` and is cleaned automatically after success.
- **Automatic PEM Normalization**: Exported `fullchain.pem` and `privkey.pem` are normalized automatically, so they are usable without a separate repair step.
- **CAA SERVFAIL Retry**: Let's Encrypt requests now auto-retry on transient `CAA SERVFAIL` DNS failures.
- **Private Key Detection**: `Get-CertificateInfo.ps1` now recognizes PEM private keys more accurately, including PKCS#8 / EC keys.
- Full feature history: [CHANGELOG.md](CHANGELOG.md).

## Prerequisites
- **PowerShell 7.x** or later (auto-checked on startup; exits with error if below)
- OpenSSL (auto-resolved: `utils/bin/` → `config.json` → Git for Windows → system PATH)
- `passphrase.txt` for encrypted keys if needed

### OpenSSL Setup

If OpenSSL is not installed on your system, run the setup script to download a portable version:

```powershell
.\utils\Install-Dependencies.ps1
```

This will automatically download and install OpenSSL into `utils/bin/`. You can also configure a custom OpenSSL path in `config.json`:

```json
"Tools": {
    "OpenSsl": "C:\\path\\to\\openssl.exe"
}
```

## Folder layout
```
ssl_maker/
├── old/                    # Existing cert/key/CSR
├── new/                    # Newly generated CSR/key
├── output/                 # Output root
│   ├── merged/             # Merged chains & PFX
│   └── self-signed/        # Self-signed outputs
├── CertStore/              # Root & intermediate certificate store
├── resources/              # Resource files (language packs)
│   ├── strings.ja.psd1     # Japanese
│   ├── strings.zh.psd1     # Chinese
│   └── strings.en.psd1     # English
├── CertConfig.psd1         # Certificate matching rules
├── config.json             # Path & tool configuration
├── Invoke-SSLToolkit.ps1   # [Entry] Main menu
└── utils/                  # Individual scripts
    ├── Install-Dependencies.ps1 # Auto-download OpenSSL
    └── bin/                # Portable tool binaries
```

## Quick Start

```powershell
.\utils\Install-Dependencies.ps1   # First time: setup OpenSSL
.\Invoke-SSLToolkit.ps1
```

First launch defaults to English. Select **Language** in the main menu to switch (your choice is saved automatically).

You can also specify language via parameter:
```powershell
.\Invoke-SSLToolkit.ps1 -Lang en  # English
.\Invoke-SSLToolkit.ps1 -Lang ja  # 日本語
.\Invoke-SSLToolkit.ps1 -Lang zh  # 中文
```

## Scripts and usage

1) `Get-CertificateInfo.ps1`
Show certificate/key/CSR info. Displays per-block details for multi-cert chains with source filenames.
```powershell
.\utils\Get-CertificateInfo.ps1
.\utils\Get-CertificateInfo.ps1 -Path .\new\example.com\example.com.cer -Table
.\utils\Get-CertificateInfo.ps1 -Lang en -PrettyTable
```

2) `Merge-CertificateChain.ps1`
Generate fullchain (server cert + intermediates). Supports 3-block (recommended) and 4-block (with root CA) modes.
```powershell
.\utils\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer
.\utils\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer -RootCert .\cross-root.cer
```

3) `Convert-KeyToPlaintext.ps1`
Decrypt encrypted private keys.
```powershell
.\utils\Convert-KeyToPlaintext.ps1 -Path .\new -Recurse -Overwrite
```
This converts a passphrase-protected `.key` into a password-free deployment key. If `<name>.decrypted.key` already exists, the script now asks whether to back it up and overwrite it during execution.

4) `New-CertificateSigningRequest.ps1`
Generate CSR and private key.
```powershell
.\utils\New-CertificateSigningRequest.ps1 -CN example.com -C JP -ST Tokyo -L Tokyo -O "Example Corp"
```

5) `Export-CertificateModulus.ps1`
Export modulus values.
```powershell
.\utils\Export-CertificateModulus.ps1 -RootDir .\old
```

6) `New-CertificateSigningRequestFromOld.ps1`
Generate new CSR/key from existing cert info.
```powershell
.\utils\New-CertificateSigningRequestFromOld.ps1
```

7) `Request-LetsEncryptCertificate.ps1`
Request Let's Encrypt cert using Docker + certbot.
```powershell
.\utils\Request-LetsEncryptCertificate.ps1 -Domain example.com -Email admin@example.com
```
By default, issued files are exported to `output/self-signed/lets-encrypt/<domain>`. Runtime files are created under `temp/lets-encrypt/` and removed automatically after a successful export. The current challenge metadata is also written to `current-challenge.txt` inside the working directory.

8) `Request-SelfSignedCertificate.ps1`
Generate a self-signed certificate with selectable validity period (90 days / 1 year / 3 years / 10 years).
```powershell
.\utils\Request-SelfSignedCertificate.ps1 -CN internal.example.local -Days 365 -Lang en
```
Interactive menu lets you choose validity period, then Quick or Custom mode.
Quick mode: choose an organization under `old/`, then generate self-signed certs from existing certificate CNs.
Custom mode: manually input CN/Subject/SAN.

9) `Repair-PemFile.ps1`
Repair/normalize PEM files.
```powershell
.\utils\Repair-PemFile.ps1 -Fullchain .\fullchain.pem -Privkey .\privkey.pem
```
If you omit the parameters, the script first lets you pick a source area (`old`, `new`, `output/merged`, `output/self-signed`) and then select a detected PEM pair. Manual absolute path input is the fallback, not the default flow.

10) `New-ServerList.ps1`
Generate/maintain a certificate renewal TSV (with legacy field import and manual edit preservation).
```powershell
.\utils\New-ServerList.ps1 -Path .\new -OldPath .\old
```

## Folder Naming Convention (Auto Organization Lookup)

When you name subfolders under `old/`, `new/`, or `output/merged/` using a **domain name** (e.g., `example.co.jp`), the toolkit automatically attempts to identify the organization behind that domain on startup.

**How it works:**

On each launch, `Invoke-SSLToolkit.ps1` runs `Rename-OrgFolders.ps1 -AutoYes` which:

1. Scans `old/`, `new/`, and `output/merged/` for subfolders that look like domain names (contain `.`)
2. Looks up the organization name using the following sources (in order):
   - **Local certificates**: Reads the `O=` (Organization) field from `.cer` files matching the domain
   - **WHOIS (JPRS)**: For `.jp` domains, queries the JPRS WHOIS registry for the registrant organization
   - **Website probe**: Connects to `https://<domain>` to read the TLS certificate's organization or the page title
3. If found, proposes renaming the folder from `example.co.jp` to `ExampleCorp (example)` (organization name + hostname in parentheses)
4. Renames matching folders across all three directories (`old/`, `new/`, `output/merged/`) to keep them in sync

**Example:**

```
Before:  old/mail.example.co.jp/   new/mail.example.co.jp/
After:   old/Example Corp (mail)/  new/Example Corp (mail)/
```

This makes it easy to identify which organization each certificate belongs to at a glance. Already-renamed folders (containing spaces and parentheses) are automatically skipped.

## 🌐 Adding a New Language

To add a new language, simply create `resources/strings.xx.psd1` (where `xx` is the language code) containing all translation keys and a `Language.DisplayName` key. No code changes are required — the language will automatically appear in the main menu's language selector.

## Apache / Tomcat examples

Apache (fullchain):
```apache
SSLCertificateFile      /path/to/fullchain.cer
SSLCertificateKeyFile   /path/to/server.key
```

Tomcat (PEM: key + cert + chain):
```xml
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

Tomcat (PKCS#12 / PFX, optional):
```xml
<Connector port="8443"
  protocol="org.apache.coyote.http11.Http11NioProtocol"
  SSLEnabled="true"
  keystoreFile="/path/to/server.pfx"
  keystorePass=""
  keystoreType="PKCS12" />
```

Notes:
- Use PEM configuration when your delivery artifacts are `.key` + `.cer` (+ chain).
- PFX is still useful for specific environments, but real deployments usually also require cert reload strategy, file permissions, and chain/trust validation.

## Passphrase file
`passphrase.txt` search order:
same folder → parent folders → org folder → old/new → script root → env `PASS_FILE`

## Path Configuration (config.json)
Directory names are configurable via `Paths` in `config.json` (defaults):

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

By default, time zone output uses a globally stable TimeZone ID (IANA preferred) to avoid OS language dependence.
Optional: to override displayed names per language in `Get-CertificateInfo.ps1`, add `TimeZoneNames` in `config.json` (keys are Windows/IANA TimeZone IDs).

---

## 📜 Public Certificate Store (CertStore)

Built-in Root CA and Intermediate CA certificates used for automatic chain building. See [CertStore/README.md](CertStore/README.md) for details.

| File | Description | Download |
|------|-------------|----------|
| gsgccr3dvtlsca2020.cer | GlobalSign GCC R3 DV TLS CA 2020 | [Download](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/GlobalSign/gsgccr3dvtlsca2020.cer) |
| nii-odca4g7rsa.cer | NII Open Domain CA - G7 RSA | [Download](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/NII/nii-odca4g7rsa.cer) |
| nii-odca4g8rsa-pem.cer | NII Open Domain CA - G8 RSA | [Download](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/NII/nii-odca4g8rsa-pem.cer) |
| SCRoot2caPem.cer | Security Communication RootCA2 (Root) | [Download](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/Secom/SCRoot2caPem.cer) |
| tlsrsarootca2024cross-pem.cer | SECOM TLS RSA Root CA 2024 (Cross-signed) | [Download](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/Secom/tlsrsarootca2024cross-pem.cer) |

For the full change history, see [CHANGELOG.md](CHANGELOG.md).
