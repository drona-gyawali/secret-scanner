# Secret Scanner

**Secret Scanner** is a powerful C++ command-line tool designed to scan source code files for potential secrets such as API keys, access tokens, private keys, and passwords using customizable regular expression patterns.

---

## Features

* Recursively scans directories
* Customizable regex patterns for secret detection
* **Multithreaded scanning using a thread pool** for high performance
* Outputs matched lines with corresponding file paths
* Lightweight, modular, and easy to extend

---

## Project Structure

```
secret-scanner/
├── .github/workflows/             # CI/CD
├── scanner-core/                  # C++ tool lives here
│   ├── src/                       # C++ source code
│   ├── include/                   # C++ headers
│   ├── test/                      # Unit tests
│   ├── build/                     # Build output (gitignored)
│   ├── CMakeLists.txt             # CMake config (build from the root)
│   └── README.md                  # C++ tool-specific README
├── scanner-extension/             # VS Code extension lives here
│   ├── src/                       # TypeScript source code
│   ├── out/                       # Compiled JS (gitignored)
│   ├── package.json               # Extension metadata
│   ├── tsconfig.json              # TypeScript config
│   ├── .vscodeignore              # For publishing
│   └── README.md                  # Extension-specific README
├── .gitignore
├── README.md                      # Root project overview
└── monorepo-config.md             # Optional docs or instructions

```

---

## Requirements

* C++17 or higher
* CMake 3.14+
* `pthread` library
* GoogleTest (for running unit tests)

> **Note:** This project leverages a custom **thread pool** to efficiently manage concurrent file scanning tasks, greatly improving performance on multi-core systems.

---

## Build Instructions

1. Clone the repository and build:

```bash
git clone `https://github.com/drona-gyawali/secret-scanner.git`
cd secret-scanner
mkdir build && cd build
cmake ..
make
```

---

## Running the Scanner

```bash
./secret_scanner [directory_path]
```

> If no path is provided, the scanner will use the default directory set in the source code.

---
### 📽️ Click the video to see how it works

[![Watch the video](https://img.youtube.com/vi/EN5O6NBdU4o/maxresdefault.jpg)](https://www.youtube.com/watch?v=EN5O6NBdU4o)

---
## Running Tests

```bash
./test_secret_scanner
```

or

```bash
ctest
```

> Tests are written using GoogleTest and verify the accuracy and reliability of secret detection.

---
### Usefulness

**For Users & Developers**
- Prevents accidental leaks of secrets like API keys, passwords, and tokens.
- Integrates into development workflows (e.g., pre-commit hooks, CI/CD), saving time and reducing human error.
- Makes open source contributions safer by scanning PRs for exposed credentials.
- Helps developers comply with security best practices.

**For Industry**
- Reduces the risk of security breaches caused by leaked secrets in source code.
- Automates a critical part of secure software development life cycle (SDLC).
- Can be integrated into enterprise DevSecOps pipelines for continuous monitoring.
- Minimizes potential damages, financial losses, and compliance violations.

---

## Future Plans

* **VS Code Extension**

  * Integrate the scanner as a Visual Studio Code extension to highlight secrets directly in the editor.

* **Repository Scanning via URL**

  * Enable scanning of Git repositories by accepting a repo URL as input.

Example:

```bash
./secret_scanner https://github.com/user/repo-name
```
---
## VSCode Extension

Install the extension from the VS Code Marketplace:

<p align="center">
  <a href="https://marketplace.visualstudio.com/items?itemName=drona-gyawali.secret-scanner-pro">
    <img src="https://img.shields.io/badge/-Install%20Now-blue?logo=visualstudiocode&style=for-the-badge" alt="Install Secret Scanner Pro from Marketplace">
  </a>
</p>

>  **To learn how to use this extension, please refer to the [Usage Section](https://marketplace.visualstudio.com/items?itemName=drona-gyawali.secret-scanner-pro)**.

---

## Contributing

Contributions are welcome! Feel free to:

* Enhance regex patterns
* Fix bugs
* Add new features

Please open an issue or submit a pull request for discussion.

---

## License

**Apache License 2.0**

---

## Author

This project is solely developed by **Dorna Raj Gyawali** <dronarajgyawali@gmail.com>  
GitHub: [@dronarajgyawali](https://github.com/drona-gyawali)
