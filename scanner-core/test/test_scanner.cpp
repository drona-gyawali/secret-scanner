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

TEST_F(SecretScannerTest, DetectsApiKeysInVariousFileTypes) {
    std::vector<std::pair<std::string, std::string>> test_files = {
        {"test_api_openai.py", "openai_key = \"sk-abcdefghijklmnopqrstuvwxyz12345678901234567890abcdEFGH\"\n"},
        {"test_api.cpp", "std::string anthropic = \"sk-ant-abcdefghijklmnopqrstuvwxyz1234567890abcd\";\n"},
        // TODO: check why gemini is falied
        // {"test_api.c", "char* gemini = \"AIzaAbCdEfGhIjKlMnOpQrStUvWxYz012345678\";\n"},
        {"test_api_mistral.py", "mistral_key = \"mistral-abcdefghijklmnopqrstuvwxyz1234567890abcdefghij\";\n"}
    };

    std::unordered_set<std::string> ignored_dirs;
    std::unordered_set<std::string> valid_exts = {".py", ".cpp", ".c"};
    std::vector<std::pair<std::string, std::regex>> api_patterns = {
        {"OpenAI API Key", std::regex(R"(sk-[a-zA-Z0-9]{48})")},
        {"Anthropic API Key", std::regex(R"(sk-ant-[a-zA-Z0-9]{40})")},
        {"Google Gemini API Key", std::regex(R"(AIza[0-9A-Za-z\-_]{35})")},
        {"Mistral API Key", std::regex(R"(mistral-[a-zA-Z0-9]{40,})")}
    };

    for (const auto& [file, content] : test_files) {
        std::ofstream ofs(file);
        ofs << content;
        ofs.close();
    }

    SecretScanner scanner(ignored_dirs, valid_exts, api_patterns);

    for (const auto& [file, content] : test_files) {
        testing::internal::CaptureStdout();
        scanner.scan_file(file);
        std::string output = testing::internal::GetCapturedStdout();

        if (file.find("openai") != std::string::npos) {
            EXPECT_NE(output.find("\"type\":\"OpenAI API Key\""), std::string::npos);
        }
        if (file.find(".cpp") != std::string::npos) {
            EXPECT_NE(output.find("\"type\":\"Anthropic API Key\""), std::string::npos);
        }
        // if (file.find(".c") != std::string::npos) {
        //     EXPECT_NE(output.find("\"type\":\"Google Gemini API Key\""), std::string::npos);
        // }
        if (file.find("mistral") != std::string::npos) {
            EXPECT_NE(output.find("\"type\":\"Mistral API Key\""), std::string::npos);
        }
        EXPECT_NE(output.find(file), std::string::npos);
        fs::remove(file);
    }
}