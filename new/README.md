# New Certificate Work Directory (new/)

## Purpose
This directory is the **staging area** for new certificate operations.
Unlike `old/` (archived data) or `merged/` (final output), this folder is for **input** and **work-in-progress**.

## Rules
1. **Organization Folders**: Certificates should be placed in subfolders named after the organization or department (e.g., `new/Finance`, `new/HR`).
2. **Input Files**: Place your newly received `.cer` (Server Certificate) files here.
3. **Generated Files**: The `New-CertificateSigningRequest` tool will generate `.key` and `.csr` files here.
4. **Git Policy**:
   - **Do NOT commit** `.key` (Private Keys), `.csr` (Requests), or `.cer` (Certificates).
   - This directory structure should remain, but without the sensitive data.

## Typical Workflow
1. Generate CSR: `New-CertificateSigningRequest.ps1` -> Output to `new/<Org>/<Domain>.csr` & `.key`
2. Receive Cert: Place receiving `.cer` into `new/<Org>/<Domain>.cer`
3. Merge Chain: Run `Merge-CertificateChain.ps1` -> Reads from `new/`, outputs to `merged/`
