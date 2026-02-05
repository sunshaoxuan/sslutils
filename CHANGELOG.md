# Changelog

All notable changes to this project will be documented in this file.

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
