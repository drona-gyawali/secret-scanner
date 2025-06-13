/**
* @file extension.ts
* @brief VSCode extension for automated secret scanning with binary management.
* 
* Provides seamless secret detection by automatically downloading and managing
* scanner binaries. Includes progress tracking, integrity verification, and
* global installation support for Linux and macOS platforms.
* 
* @author Dorna Raj Gyawali <dronarajgyawali@gmail.com>
* @date 2025
*/

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as https from 'https';
import * as crypto from 'crypto';
import { exec, spawn } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

interface SecretMatch {
    file: string;
    line: number;
    type: string;
    match: string;
}

interface BinaryInfo {
    name: string;
    sha256: string;
    downloadUrl: string;
}

const BINARY_INFO: { [key: string]: BinaryInfo } = {
    'linux': {
        name: 'secret_scanner-Linux',
        sha256: '8aa89b122b81a4e6598fb3e697c01636abd18804e1f35e3945c5886e5ca74a37',
        downloadUrl: 'https://github.com/drona-gyawali/secret-scanner/releases/latest/download/secret_scanner-Linux'
    },
    'darwin': {
        name: 'secret_scanner-macOS',
        sha256: '37e6b15f1bee9ae81f166c3ec9d7a6b83e7104ed363ac87052944a3ee2cd788d',
        downloadUrl: 'https://github.com/drona-gyawali/secret-scanner/releases/latest/download/secret_scanner-macOS'
    }
};

export function activate(context: vscode.ExtensionContext) {
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

    const scanCommand = vscode.commands.registerCommand('secret-scanner.scan', async () => {
        await runSecretScanner(diagnosticCollection, outputChannel, statusBarItem, context);
    });
    context.subscriptions.push(scanCommand);

    const scanWorkspaceCommand = vscode.commands.registerCommand('secret-scanner.scanWorkspace', async () => {
        await runSecretScanner(diagnosticCollection, outputChannel, statusBarItem, context);
    });
    context.subscriptions.push(scanWorkspaceCommand);

    const clearCommand = vscode.commands.registerCommand('secret-scanner.clearResults', () => {
        diagnosticCollection.clear();
        outputChannel.clear();
        statusBarItem.text = '$(shield) Scan Secrets';
        statusBarItem.backgroundColor = undefined;
        vscode.window.showInformationMessage('Secret Scanner results cleared');
    });
    context.subscriptions.push(clearCommand);

    const autoScanOnSave = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('secret-scanner');
        if (config.get('autoScanOnSave', false)) {
            await runSecretScanner(diagnosticCollection, outputChannel, statusBarItem, context);
        }
    });
    context.subscriptions.push(autoScanOnSave);

    const config = vscode.workspace.getConfiguration('secret-scanner');
    if (config.get('scanOnStartup', false)) {
        setTimeout(() => runSecretScanner(diagnosticCollection, outputChannel, statusBarItem, context), 2000);
    }
}

async function runSecretScanner(
    diagnosticCollection: vscode.DiagnosticCollection,
    outputChannel: vscode.OutputChannel,
    statusBarItem: vscode.StatusBarItem,
    context: vscode.ExtensionContext
) {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
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
        const scannerPath = await ensureScannerExecutable(context, outputChannel);
        if (!scannerPath) {
            throw new Error('Failed to obtain secret scanner executable');
        }

        outputChannel.appendLine(`Using scanner: ${scannerPath}`);
        
        const results = await executeScannerWithProgress(
            scannerPath, 
            workspaceFolder.uri.fsPath, 
            outputChannel
        );

        await processResults(results, diagnosticCollection, outputChannel, workspaceFolder);

        const secretCount = results.secrets.length;
        if (secretCount > 0) {
            statusBarItem.text = `${secretCount} Secret${secretCount > 1 ? 's' : ''} Found`;
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            vscode.window.showWarningMessage(`Found ${secretCount} potential secret${secretCount > 1 ? 's' : ''} in your code`);
        } else {
            statusBarItem.text = 'No Secrets Found';
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.activeBackground');
            vscode.window.showInformationMessage('No secrets detected in your workspace');
        }

    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        outputChannel.appendLine(`Error: ${errorMessage}`);
        statusBarItem.text = 'Scan Failed';
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        vscode.window.showErrorMessage(`Secret Scanner failed: ${errorMessage}`);
    }
}

async function ensureScannerExecutable(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel
): Promise<string | null> {
    //  checking  if scanner is globally available
    const globalScanner = await findGlobalScanner();
    if (globalScanner) {
        outputChannel.appendLine(`Found global scanner: ${globalScanner}`);
        return globalScanner;
    }

    // check  if we have a local copy in extension storage
    const localScanner = await findLocalScanner(context);
    if (localScanner) {
        outputChannel.appendLine(`Found local scanner: ${localScanner}`);
        return localScanner;
    }
    // downlaoding the scanner 
    outputChannel.appendLine('Scanner not found. Downloading...');
    return await downloadAndInstallScanner(context, outputChannel);
}

async function findGlobalScanner(): Promise<string | null> {
    try {
        const { stdout } = await execAsync('which secret_scanner || where secret_scanner 2>/dev/null', { timeout: 5000 });
        if (stdout.trim()) {
            return 'secret_scanner';
        }
    } catch (error) {
        // Scanner not in PATH
    }

    // checking  common installation paths: Assumation based 
    // TODO: if this extension get 50 install i will work on it fro robustness for now ok.
    const globalPaths = [
        '/usr/local/bin/secret_scanner',
        '/usr/bin/secret_scanner',
        path.join(require('os').homedir(), '.local/bin/secret_scanner'),
        path.join(require('os').homedir(), 'bin/secret_scanner')
    ];

    for (const scannerPath of globalPaths) {
        if (fs.existsSync(scannerPath)) {
            return scannerPath;
        }
    }

    return null;
}

async function findLocalScanner(context: vscode.ExtensionContext): Promise<string | null> {
    const platform = getPlatform();
    if (!platform) return null;

    const localBinaryPath = path.join(context.globalStorageUri.fsPath, 'binaries', 'secret_scanner');
    
    if (fs.existsSync(localBinaryPath)) {
        // Verify the binary integrity
        const isValid = await verifyBinaryIntegrity(localBinaryPath, platform);
        if (isValid) {
            // Ensure it's executable
            if (process.platform !== 'win32') {
                try {
                    fs.chmodSync(localBinaryPath, '755');
                } catch (error) {
                    console.error('Failed to make binary executable:', error);
                }
            }
            return localBinaryPath;
        } else {
            // Remove corrupted binary
            try {
                fs.unlinkSync(localBinaryPath);
            } catch (error) {
                console.error('Failed to remove corrupted binary:', error);
            }
        }
    }

    return null;
}

function getPlatform(): string | null {
    const platform = process.platform;
    if (platform === 'linux') return 'linux';
    if (platform === 'darwin') return 'darwin';
    // Windows not supported yet based on your binary list
    return null;
}

async function downloadAndInstallScanner(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel
): Promise<string | null> {
    const platform = getPlatform();
    if (!platform) {
        const message = 'Secret Scanner is not available for your platform yet. Currently supported: Linux, macOS';
        outputChannel.appendLine(message);
        vscode.window.showWarningMessage(message + '. Would you like to visit the releases page?', 'Open Releases')
            .then(choice => {
                if (choice === 'Open Releases') {
                    vscode.env.openExternal(vscode.Uri.parse('https://github.com/drona-gyawali/secret-scanner/releases'));
                }
            });
        return null;
    }

    const binaryInfo = BINARY_INFO[platform];
    const storageDir = path.join(context.globalStorageUri.fsPath, 'binaries');
    const binaryPath = path.join(storageDir, 'secret_scanner');

    try {
        // Create storage directory
        if (!fs.existsSync(storageDir)) {
            fs.mkdirSync(storageDir, { recursive: true });
        }

        outputChannel.appendLine(`Downloading ${binaryInfo.name}...`);
        
        // Show progress to user
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Secret Scanner',
            cancellable: false
        }, async (progress) => {
            progress.report({ message: 'Downloading scanner binary...' });
            
            await downloadFile(binaryInfo.downloadUrl, binaryPath, (downloaded, total) => {
                const percentage = total > 0 ? Math.round((downloaded / total) * 100) : 0;
                progress.report({ 
                    message: `Downloading... ${percentage}%`,
                    increment: percentage
                });
            });

            progress.report({ message: 'Verifying download...' });
            
            // Verify the downloaded file
            const isValid = await verifyBinaryIntegrity(binaryPath, platform);
            if (!isValid) {
                fs.unlinkSync(binaryPath);
                throw new Error('Downloaded binary failed integrity check');
            }

            // Make executable on Unix systems
            if (process.platform !== 'win32') {
                fs.chmodSync(binaryPath, '755');
            }

            progress.report({ message: 'Installing globally...' });
            
            // Try to install globally (optional)
            await tryInstallGlobally(binaryPath, outputChannel);
        });

        outputChannel.appendLine(`Successfully downloaded and installed scanner to: ${binaryPath}`);
        vscode.window.showInformationMessage('Secret Scanner binary downloaded and ready to use!');
        
        return binaryPath;

    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        outputChannel.appendLine(`Failed to download scanner: ${errorMessage}`);
        
        // Offer manual download option
        const choice = await vscode.window.showErrorMessage(
            'Failed to automatically download Secret Scanner. Would you like to download manually?',
            'Open Releases Page',
            'Retry Download'
        );
        
        if (choice === 'Open Releases Page') {
            vscode.env.openExternal(vscode.Uri.parse('https://github.com/drona-gyawali/secret-scanner/releases'));
        } else if (choice === 'Retry Download') {
            return await downloadAndInstallScanner(context, outputChannel);
        }
        
        return null;
    }
}

async function downloadFile(
    url: string, 
    destination: string, 
    onProgress?: (downloaded: number, total: number) => void
): Promise<void> {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(destination);
        let downloaded = 0;

        const request = https.get(url, (response) => {
            if (response.statusCode === 302 || response.statusCode === 301) {
                // Handle redirect
                const redirectUrl = response.headers.location;
                if (redirectUrl) {
                    file.close();
                    fs.unlinkSync(destination);
                    downloadFile(redirectUrl, destination, onProgress).then(resolve).catch(reject);
                    return;
                }
            }

            if (response.statusCode !== 200) {
                file.close();
                fs.unlinkSync(destination);
                reject(new Error(`Download failed with status: ${response.statusCode}`));
                return;
            }

            const totalSize = parseInt(response.headers['content-length'] || '0', 10);

            response.on('data', (chunk) => {
                downloaded += chunk.length;
                if (onProgress) {
                    onProgress(downloaded, totalSize);
                }
            });

            response.pipe(file);

            file.on('finish', () => {
                file.close();
                resolve();
            });

            file.on('error', (error) => {
                file.close();
                fs.unlinkSync(destination);
                reject(error);
            });
        });

        request.on('error', (error) => {
            file.close();
            fs.unlinkSync(destination);
            reject(error);
        });

        request.setTimeout(60000, () => {
            request.destroy();
            file.close();
            fs.unlinkSync(destination);
            reject(new Error('Download timeout'));
        });
    });
}

async function verifyBinaryIntegrity(filePath: string, platform: string): Promise<boolean> {
    try {
        const expectedHash = BINARY_INFO[platform].sha256;
        const fileBuffer = fs.readFileSync(filePath);
        const actualHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        return actualHash === expectedHash;
    } catch (error) {
        console.error('Failed to verify binary integrity:', error);
        return false;
    }
}

async function tryInstallGlobally(binaryPath: string, outputChannel: vscode.OutputChannel): Promise<void> {
    try {
        const globalBinDir = path.join(require('os').homedir(), '.local/bin');
        const globalBinaryPath = path.join(globalBinDir, 'secret_scanner');

        // Create bin directory if it doesn't exist
        if (!fs.existsSync(globalBinDir)) {
            fs.mkdirSync(globalBinDir, { recursive: true });
        }

        // Copy binary to global location
        fs.copyFileSync(binaryPath, globalBinaryPath);
        fs.chmodSync(globalBinaryPath, '755');

        outputChannel.appendLine(`Installed globally to: ${globalBinaryPath}`);
        outputChannel.appendLine('Note: Add ~/.local/bin to your PATH to use "secret_scanner" command globally');

    } catch (error) {
        outputChannel.appendLine(`Could not install globally (this is optional): ${error}`);
    }
}

function cleanOutputLine(line: string): string {
    return line
        .replace(/\u001b\[[0-9;]*m/g, '') // Remove ANSI color codes
        .replace(/[\u2500-\u257F]/g, '') // Remove box drawing characters
        .replace(/[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]/g, '') // Remove spinner characters
        .replace(/\r/g, '') // Remove carriage returns
        .trim();
}

function normalizeFilePath(filePath: string, workspacePath: string): string {
    let absolutePath = path.isAbsolute(filePath) ? filePath : path.resolve(workspacePath, filePath);
    
    let relativePath = path.relative(workspacePath, absolutePath);
    
    relativePath = relativePath.replace(/\\/g, '/');
    
    if (relativePath.startsWith('./')) {
        relativePath = relativePath.substring(2);
    }
    
    return relativePath;
}

async function executeScannerWithProgress(
    scannerPath: string, 
    workspacePath: string, 
    outputChannel: vscode.OutputChannel
): Promise<{ secrets: SecretMatch[], output: string }> {
    return new Promise((resolve, reject) => {
        const child = spawn(scannerPath, [workspacePath], {
            cwd: workspacePath,
            stdio: 'pipe'
        });

        let output = '';
        let errorOutput = '';
        const secrets: SecretMatch[] = [];

        child.stdout?.on('data', (data) => {
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
                        
                        const secretData: SecretMatch = JSON.parse(fixedJson);
                        
                        const normalizedPath = normalizeFilePath(secretData.file, workspacePath);
                        
                        const secret: SecretMatch = {
                            ...secretData,
                            file: normalizedPath
                        };
                        
                        secrets.push(secret);
                        outputChannel.appendLine(`Found ${secret.type} in ${secret.file}:${secret.line}`);
                    } catch (e) {
                        try {
                            const fileMatch = cleanLine.match(/"file":"([^"]+)"/);
                            const lineMatch = cleanLine.match(/"line":(\d+)/);
                            const typeMatch = cleanLine.match(/"type":"([^"]+)"/);
                            const matchMatch = cleanLine.match(/"match":"(.+)"}/);
                            
                            if (fileMatch && lineMatch && typeMatch && matchMatch) {
                                const normalizedPath = normalizeFilePath(fileMatch[1], workspacePath);
                                const secret: SecretMatch = {
                                    file: normalizedPath,
                                    line: parseInt(lineMatch[1]),
                                    type: typeMatch[1],
                                    match: matchMatch[1]
                                };
                                secrets.push(secret);
                                outputChannel.appendLine(`Found ${secret.type} in ${secret.file}:${secret.line}`);
                            } else {
                                outputChannel.appendLine(`Failed to parse JSON: ${cleanLine}`);
                            }
                        } catch (manualError) {
                            outputChannel.appendLine(`Failed to parse secret data: ${cleanLine}`);
                        }
                    }
                } else if (cleanLine && 
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

        child.stderr?.on('data', (data) => {
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
            } else {
                reject(new Error(`Scanner exited with code ${code}. Error: ${errorOutput}`));
            }
        });

        child.on('error', (error) => {
            reject(new Error(`Failed to execute scanner: ${error.message}`));
        });
    });
}

async function processResults(
    results: { secrets: SecretMatch[], output: string },
    diagnosticCollection: vscode.DiagnosticCollection,
    outputChannel: vscode.OutputChannel,
    workspaceFolder: vscode.WorkspaceFolder
) {
    const diagnosticsMap = new Map<string, vscode.Diagnostic[]>();

    for (const secret of results.secrets) {
        const filePath = secret.file;
        
        const cleanPath = filePath.startsWith('./') ? filePath.substring(2) : filePath;
        
        const fileUri = vscode.Uri.file(path.join(workspaceFolder.uri.fsPath, cleanPath));
        
        const line = Math.max(0, secret.line - 1);
        const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
        
        const diagnostic = new vscode.Diagnostic(
            range,
            `Potential secret detected: ${secret.type} - "${secret.match}"`,
            vscode.DiagnosticSeverity.Error
        );
        
        diagnostic.code = 'secret-detected';
        diagnostic.source = 'Secret Scanner';
        diagnostic.tags = [vscode.DiagnosticTag.Deprecated];

        const key = fileUri.toString();
        if (!diagnosticsMap.has(key)) {
            diagnosticsMap.set(key, []);
        }
        diagnosticsMap.get(key)!.push(diagnostic);
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
}

export function deactivate() {
    console.log('Secret Scanner extension deactivated');
}