# Changelog

All notable changes to this project will be documented in this file.

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
