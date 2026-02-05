# Certificate Store (CertStore/)

## Purpose
This directory functions as a **local repository** for Root CA and Intermediate CA certificates.
The Toolkit uses these files to automatically build complete certificate chains.

## Rules
1. **Automation**: `Merge-CertificateChain.ps1` automatically scans this directory to find intermediate certificates that match the Issuer of your server certificate.
2. **Organization**:
   - `GlobalSign/`: For GlobalSign roots and intermediates.
   - `NII/`: For NII (National Institute of Informatics) / UPKI specific chains.
   - `DigiCert/`, `Sectigo/`, etc.: Create folders as needed.
3. **Git Policy**:
   - **Public Keys Only**: Root and Intermediate certificates are public information.
   - It is generally **safe and recommended** to commit these `.cer`/`.crt`/`.pem` files so that the team shares the same chain building blocks.

## Maintenance
- When a CA issues a new Intermediate (e.g., "R3", "G2"), download and place it in the appropriate folder here.
- Obsolete intermediates can be removed or moved to a `_retired` subfolder.
