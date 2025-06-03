/**
 * @file constants.cpp
 * @brief Constants for file extensions and ignored directories used in secret scanning.
 *
 * Defines constant vectors for valid file extensions and directories to ignore during
 * source code scanning. These lists help the scanner focus on relevant files and skip
 * unnecessary or commonly excluded directories, improving performance and accuracy.
 *
 * @author Dorna Raj Gyawali <dronarajgyawali@gmail.com>
 * @date 2025
 * @
 */

#include "constants.h"

const std::unordered_set<std::string> valid_extensions = {
    ".py", ".js", ".ts", ".json", ".txt", ".cpp", ".c", ".h", ".java", ".cs",".go", ".rb", 
    ".php", ".swift", ".kt", ".scala", ".rs", ".sh", ".bat", ".pl", ".xml",".yml", ".yaml", 
    ".ini", ".conf", ".md", ".html", ".css",".dockerfile", ".toml", ".cfg", ".properties", 
    ".gradle", ".make", ".mk", ".ps1",".asp", ".aspx", ".jsp", ".vue", ".svelte", ".tsx", 
    ".jsx", ".lock", ".config", ".rc"
};

const std::unordered_set<std::string> ignored_dirs = {
    ".git", "node_modules", "dist", "__pycache__",
    "venv", "env", "virtualenv", ".idea", ".vscode", "build", "out", "target",
    ".svn", ".hg", ".tox", ".mypy_cache", ".pytest_cache", "coverage","logs", 
    "tmp", "temp", "cache", ".DS_Store", "ruff_cache", "migrations","migration",
    ".gradle", ".settings", ".classpath", ".project", "bin", "gen", 
    ".metadata", ".nb-gradle", ".nbproject"
};