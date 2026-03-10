# Changelog

All notable changes to this project will be documented in this file.

## [1.5.0] - 2026-03-10

### Added
- **Portable OpenSSL**: Added `Install-Dependencies.ps1` to automatically download and install portable OpenSSL into `utils/bin/`, eliminating the need for a system-wide OpenSSL installation.
- **Unified Tool Resolution**: Added `Resolve-OpenSsl` function in `paths.ps1` with prioritized search order: explicit parameter → `utils/bin/` → `config.json` → Git for Windows → system PATH.
- **Tools Configuration**: Added `Tools.OpenSsl` option in `config.json` for custom OpenSSL path configuration.
- **utils/bin/**: New directory for portable tool binaries (excluded from Git).

### Changed
- **OpenSSL Default**: All 10 scripts now use `Resolve-OpenSsl` instead of hardcoded `C:\Program Files\Git\usr\bin\openssl.exe` default path.
- **Docs**: Updated all 3 README files with OpenSSL setup instructions, new folder layout, and Quick Start steps.
- **Docs**: Added "Folder Naming Convention" section to all READMEs explaining automatic organization name lookup via local certs, WHOIS/JPRS, and website probing.
- **PS7 Check**: `Install-Dependencies.ps1` includes PowerShell 7.x version check consistent with other scripts.

### Fixed
- **PS 7.4+ Compatibility**: Resolved `Import-PowerShellDataFile` 500-key limit error on PowerShell 7.4+ by adding `Import-SafeDataFile` wrapper with automatic `-SkipLimitCheck` support.

## [1.4.1] - 2026-02-27

### Changed
- **Terminology**: Renamed the TSV-related menu concept from "Server List" to "Certificate Renewal TSV" across menu labels, i18n strings, and README files.
- **Menu Label**: Updated launcher display name from `Export-ServerList` to `Export-CertTSV`.
- **TSV Default Name**: Preferred output filename is now `cert_renewal_list.tsv`, with backward compatibility for existing `server_list.tsv`.
- **Tomcat Docs**: Expanded README examples to include both PEM (`key` + `cer` + `chain`) and PKCS#12 (`.pfx`) configurations, with deployment caveats.

### Fixed
- **Repo Hygiene**: Removed unintended tracked local/runtime files (`.antigravity`, non-README files under `new/old/output`, and sample organization TSVs).
- **Docs Alignment**: Updated docs to reflect actual default language behavior and current release messaging.

## [1.4.0] - 2026-02-17

### Added
- **i18n Config**: Supported languages are now auto-discovered from `resources/strings.*.psd1` files. Adding a new language only requires creating a new resource file with `Language.DisplayName` — no code changes needed.
- **Language Persistence**: Selected language is saved to `.toolkit_lang` and restored on next launch.
- **Runtime Language Switching**: New "Language" menu item in the main menu allows switching display language without restarting.
- **4-Block Chain Merge**: `Merge-CertificateChain.ps1` now supports optional 4-block chains (server + intermediate + cross-root + root CA), while keeping 3-block as the recommended default.
- **Chain Source Filenames**: `Get-CertificateInfo.ps1` displays the source filename (e.g., `[nii-odca4g8rsa-pem.cer]`) for each intermediate/root block in multi-block certificate chains.
- **PFX Chain Display**: PFX files now show full certificate chain structure (server, intermediate, root) with source filenames, matching `.cer` display format.
- **Customer PFX Prompt**: `Merge-CertificateChain.ps1` detects customer-provided PFX in `new/` (by matching validity dates) and prompts whether to regenerate or use the existing one.
- **Legacy PFX Support**: Added `Invoke-Pkcs12` with 3-level fallback (standard → `-legacy` → mingw64 OpenSSL) for PFX files encrypted with older algorithms (e.g., RC2-40-CBC).
- **PS7 Version Check**: All entry-point scripts enforce PowerShell 7.x minimum version with localized error messages.
- **Secom CertStore**: Added `Secom` agency configuration in `CertConfig.psd1` for Secom root/cross-root certificate discovery.

### Changed
- **Self-Signed Submenu**: Merged "Self-Signed (10Y)" and "Let's Encrypt" into a single "Self-Signed" menu item with a submenu.
- **Tool Descriptions**: Moved all hardcoded `DescJa/DescZh/DescEn` to i18n resource keys (`Toolkit.Tool.*`).
- **ValidateSet Removed**: Removed `[ValidateSet("ja","zh","en")]` from all 14 scripts; language validation is now dynamic.
- **CSR Output Path**: `New-CertificateSigningRequestFromOld.ps1` no longer creates an extra CN subdirectory; files go directly under `new/<OrgName>/`.
- **Version Check Messages**: Version check error messages are loaded from resource files dynamically based on context language.

### Fixed
- **File Matching**: `Get-CertificateInfo.ps1` now prioritizes same-basename files when matching KEY ⇔ CER, preventing incorrect matches with intermediate certificates.
- **PFX Scope Bug**: Fixed PowerShell scoping issue in `Invoke-TempPassFile` scriptblocks where decrypted PFX data was lost.
- **Strict Mode**: Fixed `SubMenu` / `Script` property access errors under `Set-StrictMode -Version Latest` by using `ContainsKey()`.
- **Redundant Subject**: Removed duplicate Subject display from PFX file info section.
- **i18n**: Corrected Chinese translation for `HasPrivateKey` field.

## [1.3.5] - 2026-02-10
### Changed
- **Naming**: Renamed main launcher from `SSL-Toolkit.ps1` to `Invoke-SSLToolkit.ps1` (approved Verb-Noun).
- **Functions**: Updated script function names to approved PowerShell verbs and synchronized all call sites.
- **Docs**: Updated README command examples and removed stale references to `Test-CertificateKeyMatch.ps1`.
- **Time Display**: Simplified certificate date output to `local-time [time-zone-id] (GMT-original)`.

## [1.3.3] - 2026-02-10
### Changed
- **Menu**: Removed `Rename-Folders` from `SSL-Toolkit.ps1` main menu.
- **Startup Task**: `SSL-Toolkit.ps1` now runs `Rename-OrgFolders.ps1 -AutoYes` automatically on startup.

## [1.3.2] - 2026-02-10
### Changed
- **Config**: Added configurable directory paths via `config.json` (`Paths.Old`, `Paths.New`, `Paths.OutputRoot`, `Paths.Merged`, `Paths.SelfSigned`).
- **Path Resolver**: Added `lib/paths.ps1` with shared `Get-ToolkitPaths` helper.
- **Scripts**: Updated main scripts (`Merge-CertificateChain.ps1`, `Sync-ToMerged.ps1`, `Request-SelfSignedCertificate.ps1`, `Get-CertificateInfo.ps1`, `New-CertificateSigningRequest.ps1`, `New-CertificateSigningRequestFromOld.ps1`, `Convert-KeyToPlaintext.ps1`, `Rename-OrgFolders.ps1`) to use configured paths instead of hard-coded folder names.
- **Temp Handling**: Added `Paths.Temp` and switched temporary file generation to workspace `temp/` with automatic cleanup after use.

## [1.3.1] - 2026-02-10
### Changed
- **Output Layout**: Unified generated artifacts under `output/` at workspace root.
- **Merge**: Default `OutDir` changed from `.\merged` to `.\output\merged` in `Merge-CertificateChain.ps1`.
- **Self-Signed**: Default `OutDir` changed to `.\output\self-signed` in `Request-SelfSignedCertificate.ps1`.
- **Sync**: `Sync-ToMerged.ps1` now syncs `new` to `output/merged`.
- **Menu/Docs**: Updated menu labels and documentation for the new output structure.

## [1.3.0] - 2026-02-10
### Added
- **Self-Signed**: Added `Request-SelfSignedCertificate.ps1` to generate 10-year self-signed certificates (RSA, SAN support, multi-language prompts).
- **Menu**: Added `Self-Signed (10Y)` entry in `SSL-Toolkit.ps1` main menu.
- **I18n**: Added `SS.*` localization keys in `resources/strings.ja.psd1`, `resources/strings.zh.psd1`, and `resources/strings.en.psd1`.

### Changed
- **Toolkit**: Bumped toolkit banner version to `1.3.0`.
- **Docs**: Updated `README.md`, `README.ja.md`, and `README.en.md` for the new self-signed workflow and LE distinction.
- **Self-Signed**: Updated Quick flow to support organization selection from `old/` and CN extraction from existing certificates, then return to org list after each run.

## [1.2.1] - 2026-02-05
### Fixed
- **Let's Encrypt**: Fixed an issue where the script would exit immediately (flash close) if the input buffer contained residual key presses. Implemented robust `Flush` + `Sleep` + `ReadKey` logic.
- **Let's Encrypt**: Improved "Press any key" prompt reliability and neutralized the exit message (no longer displays "Completed" on cancellation).
- **I18n**: Fixed incorrect "Completed" message logic in `Request-LetsEncryptCertificate.ps1` to only appear on actual success.

## [1.2.0] - 2026-02-05
### Added
- **Global**: Unified `SSL-Toolkit.ps1` menu interface.
- **Global**: Full Internationalization (I18n) for menus and messages (ja/en/zh).
- **Merge**: PFX (PKCS#12) generation support in `Merge-CertificateChain.ps1`.
- **Merge**: Support for "PFX Only" generation when certs are already merged.
- **System**: Refactored password handling into `lib/security.ps1`.

## [0.9.5] - 2026-01-16
### Changed
- **Merge**: Simplified merge logic to default to "fullchain" (Server + Intermediate).
- **Merge**: Added optional Cross-Root certificate support.
- **View**: Added support for displaying chain files in `Get-CertificateInfo.ps1`.
- **Docs**: Split README by language.

## [0.9.0] - 2026-01-15
### Added
- **New Script**: `Request-LetsEncryptCertificate.ps1` for Docker-based cert application.
- **New Script**: `Repair-PemFile.ps1` for normalizing line endings in PEM files.
- **Utils**: Improved error handling and directory management.

## [0.6.0] - 2026-01-09
### Changed
- **Verify**: Improved report clarity in `Test-CertificateKeyMatch.ps1`.
- **View**: Added Issuer information display for matching logic.

## [0.5.0] - 2026-01-08
### Added
- **Initial Release**: Collection of individual management scripts.
- **Refactor**: Renamed scripts to follow PowerShell Verb-Noun convention.
- **I18n**: Added initial Japanese resource strings and comments.
