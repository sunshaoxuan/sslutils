# Changelog

All notable changes to this project will be documented in this file.

## [1.6.0] - 2026-04-15

### Added
- **Multi-Domain Let's Encrypt Support**: `Request-LetsEncryptCertificate.ps1` now supports requesting a single certificate for multiple domains. Input domains can be separated by spaces or commas.
- **LE Workflow Transparency**: Added an instructional preamble before the Let's Encrypt HTTP-01 challenge begins. It displays the challenge file path, expected validation URL, and a brief explanation of the mechanism.
- **User Confirmation Pause**: Added a mandatory "Press Enter to proceed" step before starting the certbot validation loop to ensure the user has time to verify their Nginx configuration.

### Changed
- **i18n Updates**: Added new instructional keys (`LE.HowItWorksTitle`, `LE.HowItWorksDesc`, `LE.UrlPattern`, etc.) to all language resources (en/ja/zh). Updated the domain input prompt to mention multi-domain support.
- **Centralized Configuration**: Moved Let's Encrypt challenge path from hardcoded default to `config.json` (`AcmeWebRoot`). Added fail-safe fallback logic to the script.

### Fixed
- **Path Alignment**: Fixed a discrepancy between the instructional path hint and the actual path used by Docker hooks.
- **PowerShell Array Unrolling**: Fixed a regression where a single domain input could cause a `System.Char` Replace method error.
- **Corrupted Hook Scripts**: Fixed an issue where `cleanup.sh` and duplicate script definitions were incorrectly written.

## [1.5.5] - 2026-04-02

### Added
- **ECC Certificate Support**: Full ECC (Elliptic Curve) support across the toolkit:
  - `Get-CertificateInfo.ps1`: Public key PEM comparison replaces RSA-only modulus check, correctly verifying KEY ⇔ CER / CSR / PFX matches for both RSA and ECC certificates.
  - `New-CertificateSigningRequest.ps1`: Added `-KeyType` (RSA/EC) and `-EcCurve` (prime256v1/secp384r1/secp521r1) parameters for ECC CSR generation.
  - `New-CertificateSigningRequestFromOld.ps1`: Auto-detects existing key algorithm (RSA/ECC) and preserves it when generating new CSR/key pairs.
  - `Export-CertificateModulus.ps1`: Rewritten to use universal public key PEM comparison instead of RSA-only modulus, supporting both RSA and ECC.
- **CER ⇔ PFX Consistency Check**: New verification in `Get-CertificateInfo.ps1` that compares certificate and PFX public keys without requiring a `.key` file. Useful for merged output directories that only contain `.cer` and `.pfx`.
- **ECC Certificate Store**: Added NII G7 ECC intermediate (`nii-odca4g7ecc.cer`) and SECOM ECC RootCA1 (`SCECCRoot1caPem.cer`) to `CertStore/` for ECC chain validation.

### Changed
- **Optional PFX Generation**: `Merge-CertificateChain.ps1` now asks "Generate PFX? (y/N)" instead of auto-generating. Added `-NoPfx` switch for CLI automation. Customer-provided PFX flow is unchanged.
- **i18n Updates**: Added ECC-related strings (`Matching.CerPfx`, `Renew.Table.KeySpec`, updated `ShowModulus.*` and `Matching.*`) to all language files (en/ja/zh). Fixed Japanese `MergeCert.OutFile` / `ChainOutFile` that had unformatted `{0}` placeholders.

### Fixed
- **3-Segment Chain Merge**: Fixed auto-merge of root certificates. `Select-RootCerts` returns a `PSCustomObject` but `Merge-One` was assigning it directly to `$rootFiles` without unwrapping `.Files`. Root certificates were never appended when auto-detected from `CertStore`.
- **4-Segment Merge Guard**: `Select-FullChainRootCerts` now checks whether the 3rd-segment certificate is self-signed before searching for a 4th segment. Prevents ECC chains from incorrectly offering a 4-segment option where the root CA would appear twice.
- **Sync Folder Mapping Collision**: `Sync-ToMerged.ps1` now checks for an exact folder name match before falling back to hostPart-based lookup. Fixes incorrect sync when multiple organizations share the same hostPart (e.g., two different orgs both named `(kyuyo)`).
- **RFC2253 DN Display**: Unescaped `\,` to `,` in distinguished name display for improved readability.

## [1.5.4] - 2026-03-31

### Changed
- **New CSR Interactive Flow**: `New-CertificateSigningRequest.ps1` now asks for complete Subject fields (`C/ST/L/O`) before SAN selection during interactive creation, instead of jumping from CN directly into SAN setup.
- **New CSR Folder Workflow**: Fresh CSR creation again starts from `new/<CN>/`, matching the documented domain-folder workflow, and then immediately triggers the folder rename logic for that single domain after generation completes.
- **Immediate Org Rename**: `Rename-OrgFolders.ps1` now accepts an optional `-Domain` filter so CSR creation can rename only the newly generated domain folder instead of waiting for the next toolkit launch.
- **SAN Menu Wording**: Updated SAN menu labels and missing CSR prompt strings in all language resources so the UI explains that option 1 means “add CN to SAN” rather than “only CN exists”.

### Fixed
- **CSR Subject Display**: `Get-CertificateInfo.ps1` now preserves and renders the full CSR Subject in both list/detail views instead of collapsing it to `CN=...` or leaving the detail view blank.
- **CSR Detail Parsing**: Fixed CSR Subject parsing in the OpenSSL detail view by flattening OpenSSL output correctly before regex extraction, so valid Subjects now display reliably.
- **Launcher Exit Handling**: `Invoke-SSLToolkit.ps1` now guards `$LASTEXITCODE` access so menu returns no longer crash when a child script exits without setting it.

## [1.5.3] - 2026-03-13

### Changed
- **Let's Encrypt Output Path**: `Request-LetsEncryptCertificate.ps1` now exports issued artifacts to `output/self-signed/lets-encrypt/<domain>` by default instead of leaving them under `utils/le-work-*`.
- **Let's Encrypt Temp Handling**: Working directories now live under `temp/lets-encrypt/` and are removed automatically after successful export, keeping `utils/` free of runtime leftovers.
- **Let's Encrypt Challenge Workflow**: The auth hook now records the active challenge in `current-challenge.txt` and copies challenge files into `ServerChallengeDir` automatically on the local machine.
- **PEM Export Normalization**: Exported `fullchain.pem` and `privkey.pem` are normalized automatically so they can be used directly without a separate repair step.
- **PEM Repair UX**: `Repair-PemFile.ps1` now offers interactive source selection (`old`, `new`, `output/merged`, `output/self-signed`) before falling back to manual path input.
- **Runtime Bootstrap**: Added shared `utils/lib/runtime.ps1` so entry scripts reuse the same PowerShell 7 guard, saved-language resolution, any-key wait handling, exception output, and UTF-8 console initialization instead of duplicating that logic.
- **Script Initialization Helpers**: Added shared runtime helpers for toolkit base-dir discovery, i18n initialization, toolkit path resolution, OpenSSL resolution, and common text lookup to reduce script entry boilerplate.
- **Wider Entry Cleanup**: Applied the shared initialization helpers to CSR generation, CSR-from-old, PEM repair, sync, and modulus export scripts, and removed stray debug output from `New-CertificateSigningRequest.ps1`.
- **Cancel Semantics**: Centralized the toolkit cancel exit code and related helpers in `runtime.ps1`, so scripts no longer scatter raw `exit 99` handling through business logic.
- **Entry Wrapper**: Added shared `Invoke-ToolkitMain` error wrapper in `runtime.ps1` and moved remaining legacy entry scripts onto the shared bootstrap/helpers path instead of each carrying bespoke startup and error handling.
- **Cleanup**: Removed dead helper code and outdated messages from `Convert-KeyToPlaintext.ps1`, `Request-SelfSignedCertificate.ps1`, and `Request-LetsEncryptCertificate.ps1` to keep the business scripts easier to maintain.

### Fixed
- **CAA Retry**: `Request-LetsEncryptCertificate.ps1` now detects `CAA SERVFAIL` responses from certbot and retries automatically with configurable backoff.
- **Docker Hook Compatibility**: The Let's Encrypt auth hook now falls back to `wget` when `curl` is unavailable in the certbot Docker image.
- **Private Key Viewing**: `Get-CertificateInfo.ps1` now classifies PEM private keys correctly and reads PKCS#8 / EC private keys via `openssl pkey` fallback instead of assuming RSA-only input.
- **Launcher Regression**: Fixed shared runtime scoping so OpenSSL resolution, language switching, and default certificate constants are available to menu-driven scripts again. This restores startup for the affected main-menu flows and prevents immediate exits from missing helper functions/variables.

## [1.5.2] - 2026-03-10

### Added
- **Selectable Certificate Validity**: Self-signed certificate generation now offers an interactive menu to choose validity period: 90 days, 1 year, 3 years, or 10 years. Also supports `-Days` parameter for CLI usage.

### Changed
- **Self-Signed Menu Refactor**: Removed hardcoded "10-Year" from menu labels. Validity period selection is now a separate interactive step within the self-signed workflow.
- **i18n Updates**: Added validity period selection strings (`SS.Menu.ValidityTitle`, `SS.Validity.*`) to all 3 language files (en/ja/zh). Updated `SS.Menu.Title` and `SS.Starting` to display the selected validity dynamically.

## [1.5.1] - 2026-03-10

### Changed
- **Multi-Format Certificate Support**: Centralized supported certificate file extensions (`.cer`, `.crt`, `.pem`) into shared constants `$__CertExtensions` and `$__CertPatterns` in `defaults.ps1`. All 7 scripts now use these constants instead of hardcoded extension lists.
- **Consistent Extension Handling**: Fixed `Rename-OrgFolders.ps1` (previously only searched `*.cer`), `Merge-CertificateChain.ps1` (removed `-OnlyCer` restriction), and `New-CertificateSigningRequestFromOld.ps1` (added missing `*.pem` support in 9+ locations) to consistently recognize all supported certificate formats.
- **Project Layout**: Moved `Install-Dependencies.ps1` from project root to `utils/` for consistent single-entry-point design.

### Fixed
- **PS 7.4+ Compatibility**: Resolved `Import-PowerShellDataFile` 500-key limit error on PowerShell 7.4+ by adding `Import-SafeDataFile` wrapper with automatic `-SkipLimitCheck` support.

## [1.5.0] - 2026-03-10

### Added
- **Portable OpenSSL**: Added `Install-Dependencies.ps1` to automatically download and install portable OpenSSL into `utils/bin/`, eliminating the need for a system-wide OpenSSL installation.
- **Unified Tool Resolution**: Added `Resolve-OpenSsl` function in `paths.ps1` with prioritized search order: explicit parameter → `utils/bin/` → `config.json` → Git for Windows → system PATH.
- **Tools Configuration**: Added `Tools.OpenSsl` option in `config.json` for custom OpenSSL path configuration.
- **utils/bin/**: New directory for portable tool binaries (excluded from Git).

### Changed
- **OpenSSL Default**: All 10 scripts now use `Resolve-OpenSsl` instead of hardcoded `C:\Program Files\Git\usr\bin\openssl.exe` default path.
- **Docs**: Updated all 3 README files with OpenSSL setup instructions, folder naming convention, and Quick Start steps.
- **PS7 Check**: `Install-Dependencies.ps1` includes PowerShell 7.x version check consistent with other scripts.

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
