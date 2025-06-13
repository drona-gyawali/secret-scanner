# Changelog
All notable changes to this project will be documented in this file.

## [2.0.0] - 2025-06-13
### Added
- **Automatic Binary Download**: Extension now automatically downloads scanner binaries when not found
- **Seamless Installation**: No more manual GitHub releases downloads required
- **Global Installation Support**: Automatically installs scanner to ~/.local/bin for CLI access
- **Download Progress Tracking**: Visual progress bar during binary downloads
- **Binary Integrity Verification**: SHA256 checksum validation for security
- **Smart Binary Detection**: Checks global installation first, then local copies
- **Cross-Platform Support**: Enhanced support for Linux and macOS automatic installation
- **Fallback Options**: Manual download links if automatic download fails
- **Retry Mechanism**: Option to retry failed downloads
- **New Regex API**: Enhanced pattern matching capabilities for better secret detection

### Changed
- **Improved User Experience**: One-click scanning without manual setup
- **Enhanced Error Handling**: Better error messages with actionable steps
- **Updated Binary Hashes**: New SHA256 checksums for v2 binaries

### Fixed
- **Eliminated Manual Setup Friction**: Users no longer need to visit GitHub releases
- **Removed Permission Hassles**: Automatic permission management for executables

## [1.0.0] - 2025-06-03
### Added
- Initial release of Secret Scanner
- Scan commands in palette and context menus
- Settings for auto-scan and notifications
- Custom scanner path support