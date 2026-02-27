# Certificate Store (CertStore/)

## Purpose
This directory functions as a **local repository** for Root CA and Intermediate CA certificates.
The Toolkit uses these files to automatically build complete certificate chains.

## Certificates

### GlobalSign

| File | Subject | Issuer | Valid |
|------|---------|--------|-------|
| [gsgccr3dvtlsca2020.cer](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/GlobalSign/gsgccr3dvtlsca2020.cer) | GlobalSign GCC R3 DV TLS CA 2020 | GlobalSign Root CA - R3 | 2020-07-28 ~ 2029-03-18 |

### NII (National Institute of Informatics)

| File | Subject | Issuer | Valid |
|------|---------|--------|-------|
| [nii-odca4g7rsa.cer](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/NII/nii-odca4g7rsa.cer) | NII Open Domain CA - G7 RSA | Security Communication RootCA2 | 2020-12-15 ~ 2029-05-29 |
| [nii-odca4g8rsa-pem.cer](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/NII/nii-odca4g8rsa-pem.cer) | NII Open Domain CA - G8 RSA | SECOM TLS RSA Root CA 2024 | 2025-08-21 ~ 2040-08-21 |

### Secom (SECOM Trust Systems)

| File | Subject | Issuer | Valid |
|------|---------|--------|-------|
| [SCRoot2caPem.cer](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/Secom/SCRoot2caPem.cer) | Security Communication RootCA2 (Self-signed Root) | Security Communication RootCA2 | 2009-05-29 ~ 2029-05-29 |
| [tlsrsarootca2024cross-pem.cer](https://github.com/sunshaoxuan/sslutils/raw/main/CertStore/Secom/tlsrsarootca2024cross-pem.cer) | SECOM TLS RSA Root CA 2024 (Cross-signed) | Security Communication RootCA2 | 2025-04-09 ~ 2029-05-29 |

## Chain Relationships

```
3-block chain (recommended):
  Server Cert
  └── NII Open Domain CA - G8 RSA (nii-odca4g8rsa-pem.cer)
      └── SECOM TLS RSA Root CA 2024 [Cross-signed] (tlsrsarootca2024cross-pem.cer)

4-block chain (optional, with Root CA):
  Server Cert
  └── NII Open Domain CA - G8 RSA (nii-odca4g8rsa-pem.cer)
      └── SECOM TLS RSA Root CA 2024 [Cross-signed] (tlsrsarootca2024cross-pem.cer)
          └── Security Communication RootCA2 [Root CA] (SCRoot2caPem.cer)
```

## Rules
1. **Automation**: `Merge-CertificateChain.ps1` automatically scans this directory to find certificates that match the Issuer of your server certificate.
2. **Organization**: Create folders per CA (e.g., `GlobalSign/`, `NII/`, `Secom/`, `DigiCert/`).
3. **Git Policy**: Root and Intermediate certificates are **public information** — safe to commit and share.

## Maintenance
- When a CA issues a new Intermediate, download and place it in the appropriate folder.
- Obsolete intermediates can be removed or moved to a `_retired/` subfolder.
