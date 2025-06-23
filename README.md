<p align="center">
  <img src="https://github.com/user-attachments/assets/c3c1121b-e3d0-44bd-a3f9-18b55c5ca61b" alt="Secret Scanner" width="250"/>
</p>

Secret Scanner is an advanced security toolkit designed to detect hardcoded secrets like API keys, tokens, and credentials in your source code. It combines a powerful C++ scanning engine (`scanner-core`) with a user-friendly **Visual Studio Code extension** (`scanner-extension`) to provide both CLI and GUI interfaces.

---

## Why Two Parts?

* **`scanner-core`** is written in C++ for performance. It can be used independently in CI/CD, Docker, or custom tooling.
* **`scanner-extension`** is a VSCode extension that uses the core scanner as a backend. It gives developers a seamless in-editor experience.

---

## Getting Started

### 📦 Install Scanner Core (CLI Tool)

To use the secret scanner from the command line or within the VSCode extension, you need to install `scanner-core` globally.

#### Step 1: Build the Tool

```bash
git clone https://github.com/drona-gyawali/secret-scanner.git
cd secret-scanner
mkdir build && cd build
cmake ..
make
```

#### Step 2: Make It Global

```bash
cd build/scanner-core
sudo cp secret_scanner /usr/local/bin/
```

Now you can run it globally:

```bash
secret_scanner --help

Examples:
  ./scanner                   # Scan current 'src/' directory
  ./scanner /path/to/code     # Scan specific directory
  ./scanner .                 # Scan current directory
  ./scanner ../project        # Scan relative path

```

> **Note**: The instructions provided here are for Linux systems. If you are using Windows, please configure the build process accordingly based on your operating system’s CMake and compiler tools.
---

### Install VSCode Extension

> **Note:** Currently supported only on **Linux** and **macOS**. Prebuilt binaries are provided for these platforms. For windows setup the project and run locally.


You can install the VS Code extension from the Marketplace:

<p align="center">
  <a href="https://marketplace.visualstudio.com/items?itemName=drona-gyawali.secret-scanner-pro">
    <img src="https://img.shields.io/badge/-Install%20Now-blue?logo=visualstudiocode&style=for-the-badge" alt="Install Secret Scanner Pro from Marketplace">
  </a>
</p>

>  To see how to use it in VS Code, refer to the [`scanner-extension/README.md`](scanner-extension/README.md) or [Usage Section](https://marketplace.visualstudio.com/items?itemName=drona-gyawali.secret-scanner-pro&ssr=false#overview).

---

##  Features

* Detect common secret patterns (AWS keys, tokens, credentials, etc.)
* Scan files, folders, or entire workspaces
* Inline results with severity levels
* CLI + VS Code support
* Auto scan on save (optional)
* Lightweight, fast C++ core

---

## Tests

To run unit tests for the C++ core:

```bash
ctest
```

For the extension:

```bash
cd scanner-extension
npm install
npm test
```

---

## Feedback & Issues

Found a bug or want a feature? [Open an issue](https://github.com/drona-gyawali/secret-scanner/issues)

---

## License

Apache 2.0 – See the [LICENSE](LICENSE) file for details.
