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

TEST(RegexPatternTest, MatchesJWTToken) {
    std::regex jwt_regex(R"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9_-]+)");
    EXPECT_TRUE(std::regex_match("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.SABVfL08pQ4FwO8uL08pQ4FwO8uL08pQ4FwO8uL08pQ", jwt_regex));
    EXPECT_FALSE(std::regex_match("eyJ0eXAi", jwt_regex));
}

TEST(RegexPatternTest, MatchesGenericSecret) {
    std::regex regex(R"(secret\s*=\s*['\"][\w\-]{8,}['\"])");
    EXPECT_TRUE(std::regex_match("secret = \"abcdEFGH-12\"", regex));
    EXPECT_TRUE(std::regex_match("secret= 'abcdefgh'", regex));
    EXPECT_FALSE(std::regex_match("secret = 1234567", regex));
}

TEST(RegexPatternTest, MatchesDBURI) {
    std::regex regex(R"(mongodb\+srv://[^:]+:[^@]+@[^ \n]+)");
    EXPECT_TRUE(std::regex_match("mongodb+srv://user:pass@cluster.mongodb.net", regex));
    EXPECT_FALSE(std::regex_match("mongodb://user:pass@host", regex));
}

TEST(RegexPatternTest, MatchesSlackToken) {
    std::regex regex(R"(xox[baprs]-[0-9a-zA-Z]{10,48})");
    EXPECT_TRUE(std::regex_match("xoxb-1234567890abcdefABCDEF", regex));
    EXPECT_FALSE(std::regex_match("xoxb-123", regex));
}

TEST(RegexPatternTest, MatchesHerokuAPIKey) {
    std::regex regex(R"(heroku_[0-9a-fA-F]{32})");
    EXPECT_TRUE(std::regex_match("heroku_0123456789abcdef0123456789abcdef", regex));
    EXPECT_FALSE(std::regex_match("heroku_01234567", regex));
}

TEST(RegexPatternTest, MatchesFacebookAccessToken) {
    std::regex regex(R"(EAACEdEose0cBA[0-9A-Za-z]+)");
    EXPECT_TRUE(std::regex_match("EAACEdEose0cBA1234567890abcdef", regex));
    EXPECT_FALSE(std::regex_match("EAACEdEose0cB", regex));
}

TEST(RegexPatternTest, MatchesTwitterAccessToken) {
    std::regex regex(R"(AAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z]{27,44})");
    EXPECT_TRUE(std::regex_match("AAAAAAAAAAAAAAAAAAAAA1234567890abcdefABCDEFabcdef12345", regex));
    EXPECT_FALSE(std::regex_match("AAAAAAAAAAAAAAAAAAAAA123", regex));
}

TEST(RegexPatternTest, MatchesGitHubToken) {
    std::regex regex(R"(ghp_[0-9A-Za-z]{36,})");
    EXPECT_TRUE(std::regex_match("ghp_1234567890abcdefABCDEFabcdef1234567890", regex));
    EXPECT_FALSE(std::regex_match("ghp_123", regex));
}

TEST(RegexPatternTest, MatchesMailgunAPIKey) {
    std::regex regex(R"(key-[0-9a-zA-Z]{32})");
    EXPECT_TRUE(std::regex_match("key-1234567890abcdefABCDEFabcdef1234", regex));
    EXPECT_FALSE(std::regex_match("key-123", regex));
}

TEST(RegexPatternTest, MatchesPasswordInEnv) {
    std::regex regex(R"(password\s*=\s*['\"][^'\"]{8,}['\"])");
    EXPECT_TRUE(std::regex_match("password = \"supersecret\"", regex));
    EXPECT_TRUE(std::regex_match("password= 'anotherpass'", regex));
    EXPECT_FALSE(std::regex_match("password = 1234567", regex));
}

TEST(RegexPatternTest, MatchesRSAPrivateKey) {
    std::regex regex(R"(-----BEGIN RSA PRIVATE KEY-----)");
    EXPECT_TRUE(std::regex_match("-----BEGIN RSA PRIVATE KEY-----", regex));
    EXPECT_FALSE(std::regex_match("-----BEGIN PRIVATE KEY-----", regex));
}

TEST(RegexPatternTest, MatchesSSHPrivateKey) {
    std::regex regex(R"(-----BEGIN OPENSSH PRIVATE KEY-----)");
    EXPECT_TRUE(std::regex_match("-----BEGIN OPENSSH PRIVATE KEY-----", regex));
    EXPECT_FALSE(std::regex_match("-----BEGIN RSA PRIVATE KEY-----", regex));
}

TEST(RegexPatternTest, MatchesGoogleOAuthAccessToken) {
    std::regex regex(R"(ya29\.[0-9A-Za-z\-_]+)");
    EXPECT_TRUE(std::regex_match("ya29.A0ARrdaM-abc123_XYZ", regex));
    EXPECT_FALSE(std::regex_match("ya28.A0ARrdaM-abc123_XYZ", regex));
}

TEST(RegexPatternTest, MatchesAzureStorageKey) {
    std::regex regex(R"(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net)");
    EXPECT_TRUE(std::regex_match("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net", regex));
    EXPECT_FALSE(std::regex_match("DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;", regex));
}

TEST(RegexPatternTest, MatchesRabbitMQUri) {
    std::regex regex(R"(amqps?:\/\/[^:]+:[^@]+@[^\/\s:]+(:\d+)?(\/[^\s]*)?)");
    EXPECT_TRUE(std::regex_match("amqp://user:pass@host:5672/vhost", regex));
    EXPECT_TRUE(std::regex_match("amqps://user:pass@host/vhost", regex));
    EXPECT_FALSE(std::regex_match("http://user:pass@host", regex));
}

TEST(RegexPatternTest, MatchesCeleryBrokerURLRedis) {
    std::regex regex(R"(redis:\/\/:(.+)@[^\/\s:]+(:\d+)?(\/\d+)?)");
    EXPECT_TRUE(std::regex_match("redis://:password@localhost:6379/0", regex));
    EXPECT_FALSE(std::regex_match("redis://localhost:6379/0", regex));
}

TEST(RegexPatternTest, MatchesGenericPrivateKey) {
    std::regex regex(R"(-----BEGIN PRIVATE KEY-----)");
    EXPECT_TRUE(std::regex_match("-----BEGIN PRIVATE KEY-----", regex));
    EXPECT_FALSE(std::regex_match("-----BEGIN RSA PRIVATE KEY-----", regex));
}