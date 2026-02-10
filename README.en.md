# SSL Certificate Management Tools

Languages:
- 中文: README.md
- 日本語: README.ja.md
- English: README.en.md

## Overview
PowerShell scripts to manage certificates, keys, and CSRs with multi-org and multi-language support.

## Prerequisites
- PowerShell 5.1+ or PowerShell 7.x
- OpenSSL (default: `C:\Program Files\Git\usr\bin\openssl.exe`)
- `passphrase.txt` for encrypted keys if needed

## Folder layout
```
ssl_maker/
├── old/                    # Existing cert/key/CSR
├── new/                    # Newly generated CSR/key
├── output/                 # Output root
│   ├── merged/             # Merged chains
│   └── self-signed/        # Self-signed outputs
├── resources/
│   └── downloaded/         # AIA auto-fetch cache
├── temp/                   # Temporary files (cleaned after script use)
└── *.ps1
```

## Scripts and usage

1) `Get-CertificateInfo.ps1`  
Show certificate/key/CSR info.
```powershell
.\utils\Get-CertificateInfo.ps1
.\utils\Get-CertificateInfo.ps1 -Path .\new\example.com\example.com.cer -Table
.\utils\Get-CertificateInfo.ps1 -Lang en -PrettyTable
.\utils\Get-CertificateInfo.ps1 -Path .\server.cer -ChainFile .\server.chain.cer
```

2) `Merge-CertificateChain.ps1`  
Generate fullchain (server cert + intermediates). Optionally append cross roots.
```powershell
.\utils\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer

# fullchain + cross root
.\utils\Merge-CertificateChain.ps1 -ClientCert .\client.cer -IntermediateCert .\intermediate.cer -RootCert .\cross-root.cer
```

## Apache / Tomcat setup (fullchain)
Use a fullchain file for both Apache and Tomcat (server cert + intermediates, optionally cross roots).

## Apache / Tomcat examples (fullchain)

Apache (fullchain):
```apache
SSLCertificateFile      /path/to/fullchain.cer
SSLCertificateKeyFile   /path/to/server.key
```

Tomcat (PKCS#12, fullchain as input):
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
.\utils\Convert-KeyToPlaintext.ps1 -Path .\new -Recurse -Overwrite
```

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

8) `Request-SelfSignedCertificate.ps1`  
Generate a 10-year self-signed certificate (separate from Let's Encrypt/public CA issuance).
```powershell
.\utils\Request-SelfSignedCertificate.ps1 -CN internal.example.local -Lang en
```
Quick mode: choose an organization under `old/`, then generate self-signed certs from existing certificate CNs.  
Custom mode: manually input CN/Subject/SAN.

9) `Repair-PemFile.ps1`  
Repair/normalize PEM files.
```powershell
.\utils\Repair-PemFile.ps1 -Fullchain .\fullchain.pem -Privkey .\privkey.pem
```

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

