#include <iostream>
#include <filesystem>
#include <vector>
#include <future>
#include <unordered_set>

#include "threadpool.h"
#include "scanner.h"
#include "constants.h"
#include "regexpattern.h"

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    
    std::string root_dir = (argc > 1) ? argv[1] : "src/";

    std::unordered_set<std::string> ignored_dirs_set(ignored_dirs.begin(), ignored_dirs.end());
    std::unordered_set<std::string> valid_ext_set(valid_extensions.begin(), valid_extensions.end());

    SecretScanner scanner(ignored_dirs_set, valid_ext_set, secret_patterns);

    ThreadPool pool(std::thread::hardware_concurrency());

    std::vector<std::future<void>> futures;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(root_dir)) {
            if (!entry.is_regular_file()) continue;

            const auto& path = entry.path();

            if (scanner.is_ignored_dir(path.parent_path())) continue;
            if (!scanner.is_valid_extension(path)) continue;
            if (scanner.is_git_ignored(path.string())) continue;

            // Enqueue file scanning task
            futures.emplace_back(pool.enqueue([path_str = path.string(), &scanner]() {
                scanner.scan_file(path_str);
            }));
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return 1;
    }

    for (auto& f : futures) {
        f.get();
    }

    std::cout << "Scanning completed." << std::endl;
    return 0;
}
