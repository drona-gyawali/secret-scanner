#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <unordered_set>
#include <filesystem>
#include <regex>
#include <utility>
#include <mutex>

namespace fs = std::filesystem;

class SecretScanner {
private:
    std::unordered_set<std::string> ignored_dirs;
    std::unordered_set<std::string> valid_extensions;
    std::vector<std::pair<std::string, std::regex>> secret_patterns;
    mutable std::mutex output_mutex;

public:
    /**
     * @brief Constructor for SecretScanner
     * @param ignored_dirs_ Set of directory names to ignore during scanning
     * @param valid_extensions_ Set of valid file extensions to scan
     * @param secret_patterns_ Vector of pattern name and regex pairs for secret detection
     */
    SecretScanner(
        const std::unordered_set<std::string>& ignored_dirs_,
        const std::unordered_set<std::string>& valid_extensions_,
        const std::vector<std::pair<std::string, std::regex>>& secret_patterns_
    );

    /**
     * @brief Check if a directory path should be ignored
     * @param path The filesystem path to check
     * @return true if the directory should be ignored, false otherwise
     */
    bool is_ignored_dir(const fs::path& path) const;

    /**
     * @brief Check if a file has a valid extension for scanning
     * @param path The filesystem path to check
     * @return true if the file extension is valid, false otherwise
     */
    bool is_valid_extension(const fs::path& path) const;

    /**
     * @brief Check if a file is ignored by git
     * @param file The file path to check
     * @return true if the file is git-ignored, false otherwise
     */
    bool is_git_ignored(const std::string& file) const;

    /**
     * @brief Scan a single file for secrets
     * @param file_path Path to the file to scan
     */
    void scan_file(const std::string& file_path) const;

    /**
     * @brief Virtual method for reporting found secrets (can be overridden)
     * @param file_path Path to the file containing the secret
     * @param line_number Line number where the secret was found
     * @param pattern_name Name of the pattern that matched
     * @param match_str The actual matched string
     */
    virtual void report_secret(const std::string& file_path, int line_number, 
                              const std::string& pattern_name, const std::string& match_str) const;
};

#endif // SCANNER_H