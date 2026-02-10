# Archived Certificate Directory (old/)

## Purpose
This directory serves as an **archive** for previous years' certificates and keys.
It is primarily used as a source for **renewals** and reference.

## Rules
1. **Renewal Source**: `New-CertificateSigningRequestFromOld.ps1` scans this directory to extract Subject Information (O, OU, L, ST, C) to pre-fill CSR generation for renewals.
2. **Archive**: Move expired or superseded certificates/keys here from `new/` or `output/merged/`.
3. **Git Policy**:
   - **Do NOT commit** any private keys or sensitive certificates.
   - Public certificates (`.cer`) *could* be committed if policy allows, but generally discouraged to avoid clutter.

## Structure
Maintain the same `<Organization>/<Domain>` folder structure as `new/` for consistent automated processing.
