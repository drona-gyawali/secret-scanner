"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const child_process_1 = require("child_process");
const util_1 = require("util");
const execAsync = (0, util_1.promisify)(child_process_1.exec);
function activate(context) {
    console.log('Secret Scanner extension is now active');
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('secret-scanner');
    context.subscriptions.push(diagnosticCollection);
    const outputChannel = vscode.window.createOutputChannel('Secret Scanner');
    context.subscriptions.push(outputChannel);
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'secret-scanner.scan';
    statusBarItem.text = '$(shield) Scan Secrets';
    statusBarItem.tooltip = 'Run Secret Scanner';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
    const scanCommand = vscode.commands.registerCommand('secret-scanner.scan', () => __awaiter(this, void 0, void 0, function* () {
        yield runSecretScanner(diagnosticCollection, outputChannel, statusBarItem);
    }));
    context.subscriptions.push(scanCommand);
    const scanWorkspaceCommand = vscode.commands.registerCommand('secret-scanner.scanWorkspace', () => __awaiter(this, void 0, void 0, function* () {
        yield runSecretScanner(diagnosticCollection, outputChannel, statusBarItem);
    }));
    context.subscriptions.push(scanWorkspaceCommand);
    const clearCommand = vscode.commands.registerCommand('secret-scanner.clearResults', () => {
        diagnosticCollection.clear();
        outputChannel.clear();
        statusBarItem.text = '$(shield) Scan Secrets';
        statusBarItem.backgroundColor = undefined;
        vscode.window.showInformationMessage('Secret Scanner results cleared');
    });
    context.subscriptions.push(clearCommand);
    const autoScanOnSave = vscode.workspace.onDidSaveTextDocument((document) => __awaiter(this, void 0, void 0, function* () {
        const config = vscode.workspace.getConfiguration('secret-scanner');
        if (config.get('autoScanOnSave', false)) {
            yield runSecretScanner(diagnosticCollection, outputChannel, statusBarItem);
        }
    }));
    context.subscriptions.push(autoScanOnSave);
    const config = vscode.workspace.getConfiguration('secret-scanner');
    if (config.get('scanOnStartup', false)) {
        setTimeout(() => runSecretScanner(diagnosticCollection, outputChannel, statusBarItem), 2000);
    }
}
exports.activate = activate;
function runSecretScanner(diagnosticCollection, outputChannel, statusBarItem) {
    var _a;
    return __awaiter(this, void 0, void 0, function* () {
        const workspaceFolder = (_a = vscode.workspace.workspaceFolders) === null || _a === void 0 ? void 0 : _a[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder found');
            return;
        }
        statusBarItem.text = 'Scanning...';
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        diagnosticCollection.clear();
        outputChannel.clear();
        outputChannel.show(true);
        outputChannel.appendLine('Starting Secret Scanner...');
        outputChannel.appendLine(`Workspace: ${workspaceFolder.uri.fsPath}`);
        outputChannel.appendLine('-'.repeat(60));
        try {
            const scannerPath = yield findScannerExecutable(workspaceFolder.uri.fsPath);
            if (!scannerPath) {
                const choice = yield vscode.window.showErrorMessage('Secret Scanner executable not found. Would you like to:', 'Show Debug Info', 'Download Pre-built', 'Build Instructions');
                if (choice === 'Show Debug Info') {
                    vscode.commands.executeCommand('workbench.action.output.toggleOutput');
                    const debugChannel = vscode.window.createOutputChannel('Secret Scanner Debug');
                    debugChannel.show();
                }
                else if (choice === 'Download Pre-built') {
                    vscode.env.openExternal(vscode.Uri.parse('https://github.com/drona-gyawali/secret-scanner/releases'));
                }
                else if (choice === 'Build Instructions') {
                    vscode.window.showInformationMessage('To build the scanner:\n1. cd scanner-core\n2. mkdir build && cd build\n3. cmake ..\n4. make', { modal: true });
                }
                throw new Error('Secret scanner executable not found. Check the debug output for detailed information.');
            }
            outputChannel.appendLine(`Using scanner: ${scannerPath}`);
            const results = yield executeScannerWithProgress(scannerPath, workspaceFolder.uri.fsPath, outputChannel);
            yield processResults(results, diagnosticCollection, outputChannel, workspaceFolder);
            const secretCount = results.secrets.length;
            if (secretCount > 0) {
                statusBarItem.text = `${secretCount} Secret${secretCount > 1 ? 's' : ''} Found`;
                statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                vscode.window.showWarningMessage(`Found ${secretCount} potential secret${secretCount > 1 ? 's' : ''} in your code`);
            }
            else {
                statusBarItem.text = 'No Secrets Found';
                statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.activeBackground');
                vscode.window.showInformationMessage('No secrets detected in your workspace');
            }
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            outputChannel.appendLine(`Error: ${errorMessage}`);
            statusBarItem.text = 'Scan Failed';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            vscode.window.showErrorMessage(`Secret Scanner failed: ${errorMessage}`);
        }
    });
}
function findScannerExecutable(workspacePath) {
    var _a;
    return __awaiter(this, void 0, void 0, function* () {
        const outputChannel = vscode.window.createOutputChannel('Secret Scanner Debug');
        try {
            const { stdout } = yield execAsync('which secret_scanner || where secret_scanner 2>/dev/null', { timeout: 5000 });
            if (stdout.trim()) {
                outputChannel.appendLine(`Found scanner in PATH: ${stdout.trim()}`);
                return 'secret_scanner';
            }
        }
        catch (error) {
            outputChannel.appendLine(`Scanner not in PATH: ${error}`);
        }
        const extensionPath = (_a = vscode.extensions.getExtension('your-publisher.secret-scanner')) === null || _a === void 0 ? void 0 : _a.extensionPath;
        if (extensionPath) {
            const platform = process.platform;
            let binaryName = 'secret_scanner';
            if (platform === 'win32')
                binaryName = 'secret_scanner.exe';
            const bundledPath = path.join(extensionPath, 'binaries', platform, binaryName);
            if (fs.existsSync(bundledPath)) {
                outputChannel.appendLine(`Found bundled scanner: ${bundledPath}`);
                if (platform !== 'win32') {
                    try {
                        fs.chmodSync(bundledPath, '755');
                    }
                    catch (_b) { }
                }
                return bundledPath;
            }
        }
        const possiblePaths = [
            path.join(workspacePath, 'scanner-core', 'build', 'secret_scanner'),
            path.join(workspacePath, 'scanner-core', 'build', 'secret_scanner.exe'),
            path.join(workspacePath, 'scanner-core', 'build', 'Release', 'secret_scanner.exe'),
            path.join(workspacePath, 'scanner-core', 'build', 'Debug', 'secret_scanner.exe'),
            path.join(workspacePath, 'build', 'secret_scanner'),
            path.join(workspacePath, 'build', 'secret_scanner.exe'),
            path.join(workspacePath, 'secret_scanner'),
            path.join(workspacePath, 'secret_scanner.exe'),
            path.join(path.dirname(workspacePath), 'scanner-core', 'build', 'secret_scanner'),
            path.join(path.dirname(workspacePath), 'scanner-core', 'build', 'secret_scanner.exe'),
            path.join(path.dirname(workspacePath), 'build', 'secret_scanner'),
            path.join(path.dirname(workspacePath), 'build', 'secret_scanner.exe'),
            path.join(require('os').homedir(), 'secret-scanner', 'scanner-core', 'build', 'secret_scanner'),
            path.join(require('os').homedir(), 'secret-scanner', 'build', 'secret_scanner'),
            '/usr/local/bin/secret_scanner',
            '/usr/bin/secret_scanner'
        ];
        outputChannel.appendLine(`Searching for scanner in ${possiblePaths.length} locations...`);
        for (const scannerPath of possiblePaths) {
            outputChannel.appendLine(`Checking: ${scannerPath}`);
            if (fs.existsSync(scannerPath)) {
                outputChannel.appendLine(`Found scanner: ${scannerPath}`);
                // Make executable if needed
                if (process.platform !== 'win32') {
                    try {
                        fs.chmodSync(scannerPath, '755');
                    }
                    catch (_c) { }
                }
                return scannerPath;
            }
        }
        outputChannel.appendLine(`Scanner not found in any location`);
        outputChannel.appendLine(`Workspace path: ${workspacePath}`);
        outputChannel.appendLine(`Platform: ${process.platform}`);
        outputChannel.appendLine(`Home directory: ${require('os').homedir()}`);
        outputChannel.appendLine(`\nAvailable directories in workspace:`);
        try {
            const items = fs.readdirSync(workspacePath);
            for (const item of items) {
                const itemPath = path.join(workspacePath, item);
                if (fs.statSync(itemPath).isDirectory()) {
                    outputChannel.appendLine(`Directory: ${item}`);
                    if (item === 'scanner-core') {
                        const buildPath = path.join(itemPath, 'build');
                        if (fs.existsSync(buildPath)) {
                            outputChannel.appendLine(`Build directory exists`);
                            const buildItems = fs.readdirSync(buildPath);
                            for (const buildItem of buildItems) {
                                outputChannel.appendLine(`Build item: ${buildItem}`);
                            }
                        }
                        else {
                            outputChannel.appendLine(`Build directory not found`);
                        }
                    }
                }
            }
        }
        catch (error) {
            outputChannel.appendLine(`Error listing directories: ${error}`);
        }
        outputChannel.show();
        return null;
    });
}
function cleanOutputLine(line) {
    return line
        .replace(/\u001b\[[0-9;]*m/g, '') // Remove ANSI color codes
        .replace(/[\u2500-\u257F]/g, '') // Remove box drawing characters
        .replace(/[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]/g, '') // Remove spinner characters
        .replace(/\r/g, '') // Remove carriage returns
        .trim();
}
function normalizeFilePath(filePath, workspacePath) {
    let absolutePath = path.isAbsolute(filePath) ? filePath : path.resolve(workspacePath, filePath);
    let relativePath = path.relative(workspacePath, absolutePath);
    relativePath = relativePath.replace(/\\/g, '/');
    if (relativePath.startsWith('./')) {
        relativePath = relativePath.substring(2);
    }
    return relativePath;
}
function executeScannerWithProgress(scannerPath, workspacePath, outputChannel) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, reject) => {
            var _a, _b;
            const child = (0, child_process_1.spawn)(scannerPath, [workspacePath], {
                cwd: workspacePath,
                stdio: 'pipe'
            });
            let output = '';
            let errorOutput = '';
            const secrets = [];
            (_a = child.stdout) === null || _a === void 0 ? void 0 : _a.on('data', (data) => {
                const text = data.toString();
                output += text;
                const lines = text.split('\n');
                for (const line of lines) {
                    const cleanLine = cleanOutputLine(line);
                    if (cleanLine.startsWith('{') && cleanLine.includes('"file"')) {
                        try {
                            let fixedJson = cleanLine;
                            const matchRegex = /"match":"([^"]*"[^"]*"[^"]*)"/g;
                            fixedJson = fixedJson.replace(matchRegex, (match, content) => {
                                const escapedContent = content.replace(/"/g, '\\"');
                                return `"match":"${escapedContent}"`;
                            });
                            const secretData = JSON.parse(fixedJson);
                            const normalizedPath = normalizeFilePath(secretData.file, workspacePath);
                            const secret = Object.assign(Object.assign({}, secretData), { file: normalizedPath });
                            secrets.push(secret);
                            outputChannel.appendLine(`Found ${secret.type} in ${secret.file}:${secret.line}`);
                        }
                        catch (e) {
                            try {
                                const fileMatch = cleanLine.match(/"file":"([^"]+)"/);
                                const lineMatch = cleanLine.match(/"line":(\d+)/);
                                const typeMatch = cleanLine.match(/"type":"([^"]+)"/);
                                const matchMatch = cleanLine.match(/"match":"(.+)"}/);
                                if (fileMatch && lineMatch && typeMatch && matchMatch) {
                                    const normalizedPath = normalizeFilePath(fileMatch[1], workspacePath);
                                    const secret = {
                                        file: normalizedPath,
                                        line: parseInt(lineMatch[1]),
                                        type: typeMatch[1],
                                        match: matchMatch[1]
                                    };
                                    secrets.push(secret);
                                    outputChannel.appendLine(`Found ${secret.type} in ${secret.file}:${secret.line}`);
                                }
                                else {
                                    outputChannel.appendLine(`Failed to parse JSON: ${cleanLine}`);
                                }
                            }
                            catch (manualError) {
                                outputChannel.appendLine(`Failed to parse secret data: ${cleanLine}`);
                            }
                        }
                    }
                    else if (cleanLine &&
                        !cleanLine.includes('SECRET SCANNER') &&
                        !cleanLine.includes('Advanced Security Code Analysis Tool') &&
                        !cleanLine.includes('Input:') &&
                        !cleanLine.includes('Resolved to:') &&
                        !cleanLine.includes('Scanning directory:') &&
                        !cleanLine.includes('Analyzing project structure...') &&
                        !cleanLine.includes('SCAN RESULTS') &&
                        !cleanLine.includes('Scanning files...') &&
                        !cleanLine.includes('Secrets found:') &&
                        !cleanLine.toLowerCase().includes('summary:') &&
                        !cleanLine.toLowerCase().includes('clean scan:') &&
                        !cleanLine.includes('progress:') &&
                        !cleanLine.includes('Files scanned:') &&
                        !cleanLine.includes('SECURITY ISSUES DETECTED:') &&
                        !cleanLine.includes('ACTION REQUIRED:') &&
                        !cleanLine.includes('Scan completed successfully!') &&
                        cleanLine.length > 2) {
                        outputChannel.appendLine(cleanLine);
                    }
                }
            });
            (_b = child.stderr) === null || _b === void 0 ? void 0 : _b.on('data', (data) => {
                const cleanError = cleanOutputLine(data.toString());
                if (cleanError) {
                    errorOutput += cleanError;
                    outputChannel.appendLine(`Error: ${cleanError}`);
                }
            });
            child.on('close', (code) => {
                outputChannel.appendLine('-'.repeat(60));
                outputChannel.appendLine(`Scan completed with exit code: ${code}`);
                outputChannel.appendLine(`Found ${secrets.length} potential secret${secrets.length !== 1 ? 's' : ''}`);
                if (code === 0 || code === 1) {
                    resolve({ secrets, output });
                }
                else {
                    reject(new Error(`Scanner exited with code ${code}. Error: ${errorOutput}`));
                }
            });
            child.on('error', (error) => {
                reject(new Error(`Failed to execute scanner: ${error.message}`));
            });
        });
    });
}
function processResults(results, diagnosticCollection, outputChannel, workspaceFolder) {
    return __awaiter(this, void 0, void 0, function* () {
        const diagnosticsMap = new Map();
        for (const secret of results.secrets) {
            const filePath = secret.file;
            const cleanPath = filePath.startsWith('./') ? filePath.substring(2) : filePath;
            const fileUri = vscode.Uri.file(path.join(workspaceFolder.uri.fsPath, cleanPath));
            const line = Math.max(0, secret.line - 1);
            const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
            const diagnostic = new vscode.Diagnostic(range, `Potential secret detected: ${secret.type} - "${secret.match}"`, vscode.DiagnosticSeverity.Error);
            diagnostic.code = 'secret-detected';
            diagnostic.source = 'Secret Scanner';
            diagnostic.tags = [vscode.DiagnosticTag.Deprecated];
            const key = fileUri.toString();
            if (!diagnosticsMap.has(key)) {
                diagnosticsMap.set(key, []);
            }
            diagnosticsMap.get(key).push(diagnostic);
        }
        for (const [fileUri, diagnostics] of diagnosticsMap) {
            diagnosticCollection.set(vscode.Uri.parse(fileUri), diagnostics);
        }
        if (results.secrets.length > 0) {
            outputChannel.appendLine('');
            outputChannel.appendLine('SECURITY ISSUES DETECTED:');
            outputChannel.appendLine('-'.repeat(60));
            for (const secret of results.secrets) {
                outputChannel.appendLine(`File: ${secret.file}`);
                outputChannel.appendLine(`Line: ${secret.line}`);
                outputChannel.appendLine(`Type: ${secret.type}`);
                outputChannel.appendLine(`Match: ${secret.match}`);
                outputChannel.appendLine('-'.repeat(40));
            }
            outputChannel.appendLine('');
            outputChannel.appendLine('ACTION REQUIRED: Please review and secure the detected secrets');
        }
    });
}
function deactivate() {
    console.log('Secret Scanner extension deactivated');
}
exports.deactivate = deactivate;
