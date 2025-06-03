#include <iostream>
#include <filesystem>
#include <vector>
#include <future>
#include <unordered_set>
#include <chrono>
#include <thread>
#include <atomic>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include "threadpool.h"
#include "scanner.h"
#include "constants.h"
#include "regexpattern.h"

namespace fs = std::filesystem;

class CLIInterface {
private:
    std::atomic<int> files_scanned{0};
    std::atomic<int> total_files{0};
    std::atomic<int> secrets_found{0};
    std::atomic<bool> scanning_complete{false};
    std::vector<std::string> found_secrets;
    std::mutex secrets_mutex;

    // ANSI color codes
    const std::string RESET = "\033[0m";
    const std::string BOLD = "\033[1m";
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string WHITE = "\033[37m";
    const std::string BG_RED = "\033[41m";
    const std::string BG_GREEN = "\033[42m";

public:
    void print_banner() {
        std::cout << CYAN << BOLD;
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                       SECRET SCANNER                         ║\n";
        std::cout << "║              Advanced Security Code Analysis Tool            ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        std::cout << RESET << "\n";
    }

    void print_help() {
        std::cout << BOLD << "Usage:\n" << RESET;
        std::cout << "  " << CYAN << "./scanner" << RESET << " [directory]\n\n";
        std::cout << BOLD << "Examples:\n" << RESET;
        std::cout << "  " << GREEN << "./scanner" << RESET << "                    # Scan current 'src/' directory\n";
        std::cout << "  " << GREEN << "./scanner /path/to/code" << RESET << "    # Scan specific directory\n";
        std::cout << "  " << GREEN << "./scanner ." << RESET << "                 # Scan current directory\n";
        std::cout << "  " << GREEN << "./scanner ../project" << RESET << "       # Scan relative path\n\n";
    }

    std::string resolve_directory(const std::string& input) {
        if (input.empty()) {
            return "src/";
        }
        
        fs::path path(input);
        
        if (path.is_absolute()) {
            return path.string();
        }
        
        fs::path current = fs::current_path();
        std::vector<fs::path> search_paths = {
            current / path,                    
            current.parent_path() / path,      
            current.parent_path().parent_path() / path
        };
        
        for (const auto& search_path : search_paths) {
            try {
                if (fs::exists(search_path) && fs::is_directory(search_path)) {
                    return fs::canonical(search_path).string();
                }
            } catch (const fs::filesystem_error&) {
                continue;
            }
        }
        
        try {
            fs::path resolved = fs::canonical(current / path);
            return resolved.string();
        } catch (const fs::filesystem_error&) {
            return (current / path).string();
        }
    }

    void start_progress_indicator() {
        std::thread([this]() {
            const std::vector<std::string> spinner = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
            int i = 0;
            
            while (!scanning_complete.load()) {
                std::cout << "\r" << YELLOW << spinner[i % spinner.size()] << " " 
                         << BOLD << "Scanning files... " << RESET 
                         << CYAN << "[" << files_scanned.load() << "/" << total_files.load() << "]" << RESET
                         << " | " << RED << "Secrets found: " << secrets_found.load() << RESET;
                std::cout.flush();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                i++;
            }
            std::cout << "\r" << std::string(80, ' ') << "\r";
        }).detach();
    }

    void count_files(const std::string& root_dir, const std::unordered_set<std::string>& ignored_dirs_set,
                    const std::unordered_set<std::string>& valid_ext_set, SecretScanner& scanner) {
        try {
            for (const auto& entry : fs::recursive_directory_iterator(root_dir)) {
                if (!entry.is_regular_file()) continue;
                const auto& path = entry.path();
                if (scanner.is_ignored_dir(path.parent_path())) continue;
                if (!scanner.is_valid_extension(path)) continue;
                if (scanner.is_git_ignored(path.string())) continue;
                total_files++;
            }
        } catch (const fs::filesystem_error&) {
        }
    }

    void add_secret_result(const std::string& file_path, int line_number, 
                          const std::string& pattern_name, const std::string& match_str) {
        std::lock_guard<std::mutex> lock(secrets_mutex);
        
        std::stringstream ss;
        ss << "{"
           << R"("file":")" << file_path << "\","
           << R"("line":)" << line_number << ","
           << R"("type":")" << pattern_name << "\","
           << R"("match":")" << match_str << "\""
           << "}";
        
        found_secrets.push_back(ss.str());
        secrets_found++;
    }

    void increment_files_scanned() {
        files_scanned++;
    }

    void set_scanning_complete() {
        scanning_complete = true;
    }

    int get_files_scanned() const {
        return files_scanned.load();
    }

    int get_total_files() const {
        return total_files.load();
    }

    int get_secrets_found() const {
        return secrets_found.load();
    }

    void print_results() {
        std::cout << "\n";
        std::cout << CYAN << BOLD << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                        SCAN RESULTS                          ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n" << RESET;
        
        std::cout << BOLD << " Summary:\n" << RESET;
        std::cout << "  • Files scanned: " << GREEN << files_scanned.load() << RESET << "\n";
        std::cout << "  • Secrets found: " << RED << secrets_found.load() << RESET << "\n\n";

        if (secrets_found.load() > 0) {
            std::cout << RED << BOLD << "  SECURITY ISSUES DETECTED:\n" << RESET;
            std::cout << YELLOW << "═══════════════════════════════════════════════════════════════\n" << RESET;
            
            for (const auto& secret : found_secrets) {
                std::cout << secret << "\n";
            }
            
            std::cout << YELLOW << "═══════════════════════════════════════════════════════════════\n" << RESET;
            std::cout << RED << BOLD << "\n ACTION REQUIRED: " << RESET 
                      << "Please review and secure the detected secrets!\n";
        } else {
            std::cout << GREEN << BOLD << " CLEAN SCAN: " << RESET 
                      << "No secrets detected in the scanned files.\n";
        }
        
        std::cout << "\n" << CYAN << "Scan completed successfully!" << RESET << "\n";
    }

    void print_error(const std::string& message) {
        std::cout << RED << BOLD << " ERROR: " << RESET << message << "\n";
    }

    void print_info(const std::string& message) {
        std::cout << BLUE << "" << RESET << message << "\n";
    }
};

class CLISecretScanner : public SecretScanner {
private:
    CLIInterface* cli_interface;

public:
    CLISecretScanner(const std::unordered_set<std::string>& ignored_dirs,
                    const std::unordered_set<std::string>& valid_extensions,
                    const std::vector<std::pair<std::string, std::regex>>& patterns,
                    CLIInterface* cli) 
        : SecretScanner(ignored_dirs, valid_extensions, patterns), cli_interface(cli) {}

    void scan_file_with_callback(const std::string& file_path) {
        scan_file(file_path);
        cli_interface->increment_files_scanned();
    }

    void report_secret(const std::string& file_path, int line_number, 
                      const std::string& pattern_name, const std::string& match_str) const override {
        cli_interface->add_secret_result(file_path, line_number, pattern_name, match_str);
    }
};

int main(int argc, char* argv[]) {
    CLIInterface cli;
    
    cli.print_banner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        cli.print_help();
        return 0;
    }
    
    std::string input_dir = (argc > 1) ? argv[1] : "";
    std::string root_dir = cli.resolve_directory(input_dir);
    
    if (!input_dir.empty()) {
        cli.print_info("Input: '" + input_dir + "' → Resolved to: '" + root_dir + "'");
    }
    
    if (!fs::exists(root_dir)) {
        cli.print_error("Directory '" + root_dir + "' does not exist!");
        
        fs::path current = fs::current_path();
        cli.print_info("Current directory: " + current.string());
        cli.print_info("Parent directory: " + current.parent_path().string());
        
        try {
            cli.print_info("Available directories in parent folder:");
            for (const auto& entry : fs::directory_iterator(current.parent_path())) {
                if (entry.is_directory()) {
                    std::cout << "  - " << entry.path().filename().string() << "\n";
                }
            }
        } catch (const fs::filesystem_error&) {
        }
        
        return 1;
    }
    
    if (!fs::is_directory(root_dir)) {
        cli.print_error("'" + root_dir + "' is not a directory!");
        return 1;
    }
    
    cli.print_info("Scanning directory: " + root_dir);
    
    std::unordered_set<std::string> ignored_dirs_set(ignored_dirs.begin(), ignored_dirs.end());
    std::unordered_set<std::string> valid_ext_set(valid_extensions.begin(), valid_extensions.end());
    
    CLISecretScanner scanner(ignored_dirs_set, valid_ext_set, secret_patterns, &cli);
    
    cli.print_info("Analyzing project structure...");
    cli.count_files(root_dir, ignored_dirs_set, valid_ext_set, scanner);
    
    if (cli.get_total_files() == 0) {
        cli.print_info("No files found to scan in the specified directory.");
        return 0;
    }
    
    ThreadPool pool(std::thread::hardware_concurrency());
    std::vector<std::future<void>> futures;
    
    cli.start_progress_indicator();
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(root_dir)) {
            if (!entry.is_regular_file()) continue;
            
            const auto& path = entry.path();
            if (scanner.is_ignored_dir(path.parent_path())) continue;
            if (!scanner.is_valid_extension(path)) continue;
            if (scanner.is_git_ignored(path.string())) continue;
            
            futures.emplace_back(pool.enqueue([path_str = path.string(), &scanner]() {
                scanner.scan_file_with_callback(path_str);
            }));
        }
    } catch (const fs::filesystem_error& e) {
        cli.set_scanning_complete();
        cli.print_error("Filesystem error: " + std::string(e.what()));
        return 1;
    }
    
    for (auto& f : futures) {
        f.get();
    }
    
    cli.set_scanning_complete();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    cli.print_results();
    
    return (cli.get_secrets_found() > 0) ? 1 : 0;
}