# **Secret Scanner**

**Secret Scanner** is a powerful VS Code extension that detects API keys, tokens, and other secrets in your codebase to prevent accidental leaks.

---

##  Features

* Detects hardcoded secrets (API keys, tokens, credentials)
* Real-time scanning on file save or startup
* Context menu support in Explorer and Editor
* Custom external scanner binary support
* Automatic binary installation (Linux/macOS only)
* Smart binary fallback: Global → Local → Auto-download
* SHA256 integrity verification for secure downloads
* Visual progress feedback during scans
* Cross-platform support (Linux and macOS)
* Seamless experience — no manual setup required on supported systems

> ❗ **Note:** Currently supported only on **Linux** and **macOS**. Prebuilt binaries are provided for these platforms. **Windows is not yet supported**.

---

##  Configuration

Customize the extension from VS Code settings:

| Setting                            | Description                             | Default |
| ---------------------------------- | --------------------------------------- | ------- |
| `secret-scanner.autoScanOnSave`    | Automatically scan when a file is saved | `false` |
| `secret-scanner.scanOnStartup`     | Scan all files on startup               | `false` |
| `secret-scanner.showNotifications` | Show scan result popups                 | `true`  |
| `secret-scanner.customScannerPath` | Path to custom scanner binary           | `""`    |

---

##  Commands

Use the Command Palette (`Ctrl+Shift+P`) or right-click in the Explorer/Editor:

* `Secret Scanner: Scan for Secrets`
* `Secret Scanner: Scan Workspace for Secrets`
* `Secret Scanner: Clear Scan Results`

---

## 📦 Binary Setup

The extension uses a native C++ binary to scan files efficiently.

### Supported Platforms

* **Linux** and **macOS** (automatic download supported)
* **Windows** not supported yet


---

### Manual Installation (Windows)

> **Note:** Currently, **Windows is not supported** for automatic binary setup.

To use **Secret Scanner** on Windows, you’ll need to set it up manually by building the scanner locally.

#### Steps:

1. Clone the project:

   ```bash
   git clone https://github.com/drona-gyawali/secret-scanner.git
   ```
2. Follow the build instructions provided in the repo's **README** to compile the scanner binary for Windows.
3. Once built, locate the output file (e.g., `secret_scanner.exe`).
4. Move it to a preferred location (e.g., `C:\Tools\SecretScanner`).
5. In **VS Code settings**, configure the path:

   ```
   secret-scanner.customScannerPath = "C:\\Tools\\SecretScanner\\secret_scanner.exe"
   ```
6. Restart VS Code.

> You can find full instructions and the source code at:
> [secret-scanner](https://github.com/drona-gyawali/secret-scanner)

---

###  How it Works

1. **Smart detection order:**

   * Uses globally installed binary (e.g., in `~/.local/bin`)
   * Falls back to local workspace binary
   * Automatically downloads from GitHub releases if needed

2. **Security**

   * Verifies the binary using **SHA256 hash**

3. **No Manual Setup**

   * If a supported OS is detected, everything is handled automatically

### Manual Download

If you'd prefer or need to install the binary manually, download the latest prebuilt version from the [GitHub Releases Page](https://github.com/drona-gyawali/secret-scanner/releases).

To build it yourself, follow [these instructions](#-build-from-source-scanner-core).

---

## Screenshots

**Trigger scan from sidebar**

![Image](https://raw.githubusercontent.com/drona-gyawali/abc/refs/heads/main/extension-img/Screenshot%20from%202025-06-03%2014-20-51_spotlight.png)

**Terminal with scan results**

![Image](https://raw.githubusercontent.com/drona-gyawali/abc/refs/heads/main/extension-img/Screenshot%20from%202025-06-03%2014-21-46.png)

**Editor highlighting**

![Image](https://raw.githubusercontent.com/drona-gyawali/abc/refs/heads/main/extension-img/Screenshot%20from%202025-06-03%2014-22-36.png)

---

## 🤝 Connect with Us

[![GitHub](https://img.shields.io/badge/GitHub-Follow-blue?logo=github)](https://github.com/drona-gyawali)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://www.linkedin.com/in/dorna-gyawali/)
[![Twitter](https://img.shields.io/badge/Twitter-Follow-1DA1F2?logo=twitter)](https://x.com/dornaoffical)

---
