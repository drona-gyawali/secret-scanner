#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include "scanner.h"
#include "regexpattern.h"

namespace fs = std::filesystem;

class SecretScannerTest : public ::testing::Test {
protected:
    std::string test_file_path = "test_secret_file.txt";

    void SetUp() override {
        std::ofstream ofs(test_file_path);
        ofs << "AWS key: AKIAABCDEFGHIJKLMNOP\n";
        ofs << "Private key start: -----BEGIN RSA PRIVATE KEY-----\n";
        ofs.close();
    }

    void TearDown() override {
        fs::remove(test_file_path);
    }
};

TEST_F(SecretScannerTest, DetectsSecretsInFile) {
    std::unordered_set<std::string> ignored_dirs;
    std::unordered_set<std::string> valid_exts = {".txt"};
    SecretScanner scanner(ignored_dirs, valid_exts, secret_patterns);

    testing::internal::CaptureStdout();
    scanner.scan_file(test_file_path);
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("\"type\":\"AWS Access Key\""), std::string::npos);
    EXPECT_NE(output.find("\"type\":\"Private Key\""), std::string::npos);
    EXPECT_NE(output.find(test_file_path), std::string::npos);
}

TEST_F(SecretScannerTest, HandlesEmptyFile) {
    std::string empty_file = "empty.txt";
    std::ofstream ofs(empty_file);
    ofs.close();

    std::unordered_set<std::string> ignored_dirs;
    std::unordered_set<std::string> valid_exts = {".txt"};
    SecretScanner scanner(ignored_dirs, valid_exts, secret_patterns);

    testing::internal::CaptureStdout();
    scanner.scan_file(empty_file);
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_TRUE(output.empty());

    fs::remove(empty_file);
}
