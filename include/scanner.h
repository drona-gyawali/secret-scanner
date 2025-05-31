#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <unordered_set>
#include <vector>
#include <regex>
#include <filesystem>

namespace fs = std::filesystem;

class SecretScanner {
public:
    SecretScanner(
        const std::unordered_set<std::string>& ignored_dirs,
        const std::unordered_set<std::string>& valid_extensions,
        const std::vector<std::pair<std::string, std::regex>>& secret_patterns);

    bool is_ignored_dir(const fs::path& path) const;
    bool is_valid_extension(const fs::path& path) const;
    bool is_git_ignored(const std::string& file) const;
    void scan_file(const std::string& file_path) const;

private:
    std::unordered_set<std::string> ignored_dirs;
    std::unordered_set<std::string> valid_extensions;
    std::vector<std::pair<std::string, std::regex>> secret_patterns;
};

#endif // SCANNER_H
