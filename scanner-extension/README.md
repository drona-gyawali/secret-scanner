# Secret Scanner

**Secret Scanner** is a powerful VS Code extension that detects API keys, tokens, and other secrets in your codebase to prevent accidental leaks.


---

## Features

- Detects hardcoded secrets (API keys, tokens, credentials)
- Real-time scanning on file save or startup
- Context menu support for Explorer and Editor
- Custom secret scanner integration
- Notifies you with scan results

---

## Configuration

You can customize the extension from VS Code settings:

| Setting | Description | Default |
|--------|-------------|---------|
| `secret-scanner.autoScanOnSave` | Automatically scan when a file is saved | `false` |
| `secret-scanner.scanOnStartup` | Scan all files on startup | `false` |
| `secret-scanner.showNotifications` | Show scan result popups | `true` |
| `secret-scanner.customScannerPath` | Path to custom scanner binary | `""` |

---

## Commands

- `Secret Scanner: Scan for Secrets`
- `Secret Scanner: Scan Workspace for Secrets`
- `Secret Scanner: Clear Scan Results`

Use the command palette (`Ctrl+Shift+P`) or right-click in Explorer or Editor.

---

## 📦 Download Pre-built Binary

This extension expects a prebuilt binary of the underlying C++ secret scanner to be available on your system. The binary performs the actual scanning work and must be present for the extension to function properly.

To get the latest version of the compiled binary for your operating system, please visit the [Releases Page](https://github.com/drona-gyawali/secret-scanner/releases) and download the appropriate file.

Alternatively, if you'd like to build the scanner yourself, see the [Build Instructions](#-build-from-source-scanner-core) section.

---

## Screenshots

**Click the scanner**

![Image](https://raw.githubusercontent.com/drona-gyawali/abc/refs/heads/main/extension-img/Screenshot%20from%202025-06-03%2014-20-51_spotlight.png)

**See the details in terminal**

![Image](https://raw.githubusercontent.com/drona-gyawali/abc/refs/heads/main/extension-img/Screenshot%20from%202025-06-03%2014-21-46.png)

**Editor based cross mark**

![Image](https://raw.githubusercontent.com/drona-gyawali/abc/refs/heads/main/extension-img/Screenshot%20from%202025-06-03%2014-22-36.png)

---

**Connect with us**

[![GitHub](https://img.shields.io/badge/GitHub-Follow-blue?logo=github)](https://github.com/drona-gyawali)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://www.linkedin.com/in/dorna-gyawali/)
[![Twitter](https://img.shields.io/badge/Twitter-Follow-1DA1F2?logo=twitter)](https://x.com/dornaoffical)
