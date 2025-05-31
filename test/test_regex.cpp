// test/test_regex.cpp
#include <gtest/gtest.h>
#include <regex>

TEST(RegexPatternTest, MatchesAWSKey) {
    std::regex aws_regex(R"(AKIA[0-9A-Z]{16})");
    EXPECT_TRUE(std::regex_match("AKIAABCDEFGHIJKLMNOP", aws_regex));
    EXPECT_FALSE(std::regex_match("AKIA123", aws_regex));
}

TEST(RegexPatternTest, MatchesPrivateKeyHeader) {
    std::regex pk_regex(R"(-----BEGIN RSA PRIVATE KEY-----)");
    EXPECT_TRUE(std::regex_match("-----BEGIN RSA PRIVATE KEY-----", pk_regex));
    EXPECT_FALSE(std::regex_match("-----BEGIN PRIVATE KEY-----", pk_regex));
}

// TODO: Add all regex pattern