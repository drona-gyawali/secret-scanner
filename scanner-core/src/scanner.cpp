/**
 * @file scanner.cpp
 * @brief Implements the SecretScanner class for detecting secrets in source files.
 *
 * This file contains the implementation of the SecretScanner, which scans files for potential
 * secrets such as API keys, passwords, or other sensitive information using configurable
 * regular expression patterns. The scanner supports ignoring specified directories, filtering
 * by file extension, and respecting .gitignore rules.
 *
 * Features:
 * - Directory and file extension filtering.
 * - Detection of secrets using user-defined regex patterns.
 * - Integration with git to skip ignored files.
 * - Outputs findings in a structured JSON format.
 *
 * @author Dorna Raj Gyawali <dronarajgyawali@gmail.com>
 * @date 2025
 */

#include "scanner.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <sstream>

SecretScanner::SecretScanner(
    const std::unordered_set<std::string>& ignored_dirs_,
    const std::unordered_set<std::string>& valid_extensions_,
    const std::vector<std::pair<std::string, std::regex>>& secret_patterns_)
    : ignored_dirs(ignored_dirs_), valid_extensions(valid_extensions_), secret_patterns(secret_patterns_) 
    {}

bool SecretScanner::is_ignored_dir(const fs::path& path) const {
    std::string path_str = path.generic_string();
    for (const auto& d : ignored_dirs) {
        if (path_str.find("/" + d + "/") != std::string::npos ||
            (path_str.size() >= d.size() + 1 &&
             path_str.compare(path_str.size() - d.size() - 1, d.size() + 1, "/" + d) == 0)) {
            return true;
        }
    }
    return false;
}

bool SecretScanner::is_valid_extension(const fs::path& path) const {
    return valid_extensions.find(path.extension().string()) != valid_extensions.end();
}

bool SecretScanner::is_git_ignored(const std::string& file) const {
    std::string cmd = "git check-ignore \"" + file + "\" > /dev/null 2>&1";
    return system(cmd.c_str()) == 0;
}

void SecretScanner::report_secret(const std::string& file_path, int line_number, 
                                 const std::string& pattern_name, const std::string& match_str) const {
    std::lock_guard<std::mutex> lock(output_mutex);
    
    // cleaning up the match string for JSON output
    std::string cleaned_match = match_str;
    
    // replacing quotes and backslashes for JSON safety
    std::stringstream ss;
    for (char c : cleaned_match) {
        if (c == '"') {
            ss << "\\\"";
        } else if (c == '\\') {
            ss << "\\\\";
        } else if (c == '\n') {
            ss << "\\n";
        } else if (c == '\r') {
            ss << "\\r";
        } else if (c == '\t') {
            ss << "\\t";
        } else {
            ss << c;
        }
    }
    cleaned_match = ss.str();
    
    std::cout << "{"
              << R"("file":")" << file_path << "\","
              << R"("line":)" << line_number << ","
              << R"("type":")" << pattern_name << "\","
              << R"("match":")" << cleaned_match << "\""
              << "}" << std::endl;
}

void SecretScanner::scan_file(const std::string& file_path) const {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        // silently skip files that can't be opened (they might be binary or locked)
        return;
    }

    std::string line;
    int line_number = 0;

    while (std::getline(file, line)) {
        ++line_number;
        
        for (const auto& [pattern_name, pattern] : secret_patterns) {
            std::smatch match;
            std::string::const_iterator start = line.cbegin();
            
            // lets find all matches in the line
            while (std::regex_search(start, line.cend(), match, pattern)) {
                std::string match_str = match.str();
                report_secret(file_path, line_number, pattern_name, match_str);
                start = match.suffix().first;
            }
        }
    }
}