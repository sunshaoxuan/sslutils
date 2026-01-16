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
├── merged/                 # Merged chains
├── resources/
│   └── downloaded/         # AIA auto-fetch cache
└── *.ps1
```

## Scripts and usage

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

## Apache setup (fullchain / chainfile)
Apache commonly uses two styles:
- fullchain: `SSLCertificateFile` points to a file that includes “server cert + intermediates”
- chainfile: `SSLCertificateFile` points to “server cert only” and `SSLCertificateChainFile` points to “intermediate certs (optionally cross roots)”

This tool switches via `-OutputStyle` in `Merge-CertificateChain.ps1`.  
Browser trust depends on a complete chain, not on which Apache style you choose.

## Apache / Tomcat examples

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

## Passphrase file
`passphrase.txt` search order:  
same folder → parent folders → org folder → old/new → script root → env `PASS_FILE`
