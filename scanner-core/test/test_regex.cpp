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

TEST(RegexPatternTest, MatchesOpenWeather) {
    std::regex regex(R"([a-fA-F0-9]{32})");
    EXPECT_TRUE(std::regex_match("6501d1d4d63c1e017c3eff5bc5b74844", regex));
    EXPECT_FALSE(std::regex_match("63c1e017c3ef", regex));
}

// TEST(RegexPatternTest, MatchesCloudinaryAPIKey) {
//     std::regex regex(R"([0-9a-zA-Z]{15})");
//     EXPECT_TRUE(std::regex_match("AbCdEfGhIjKlMno", regex));
//     EXPECT_FALSE(std::regex_match("AbCdEfGhIjKlMn", regex));
// }

TEST(RegexPatternTest, MatchesMistralAPIKey) {
    std::regex regex(R"(mistral-[a-zA-Z0-9]{40,})");
    EXPECT_TRUE(std::regex_match("mistral-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN1234567890", regex));
    EXPECT_FALSE(std::regex_match("mistral-abc123", regex));
}

TEST(RegexPatternTest, MatchesCohereAPIKey_Unique) {
    std::regex regex(R"(Cohere-[a-zA-Z0-9]{30,50})");
    EXPECT_TRUE(std::regex_match("Cohere-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN", regex));
    EXPECT_FALSE(std::regex_match("Cohere-abc123", regex));
}

TEST(RegexPatternTest, MatchesHuggingFaceAPIToken) {
    std::regex regex(R"(hf_[a-zA-Z0-9]{64})");
    EXPECT_TRUE(std::regex_match("hf_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789012", regex));
    EXPECT_FALSE(std::regex_match("hf_abc123", regex));
}

TEST(RegexPatternTest, MatchesOpenAIAPIKey) {
    std::regex regex(R"(sk-[a-zA-Z0-9]{48})");
    std::string valid = "sk-abcdefghijklmnopqrstuvwxyzABCD1234567890abcdEFGH";
    std::string invalid = "sk-abc123";
    EXPECT_TRUE(std::regex_match(valid, regex));
    EXPECT_FALSE(std::regex_match(invalid, regex));
}
TEST(RegexPatternTest, MatchesAnthropicAPIKey) {
    std::regex regex(R"(sk-ant-[a-zA-Z0-9]{40})");
    std::string valid = "sk-ant-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCD";
    std::string invalid = "sk-ant-abc123";
    EXPECT_TRUE(std::regex_match(valid, regex));
    EXPECT_FALSE(std::regex_match(invalid, regex));
}

TEST(RegexPatternTest, MatchesGoogleGeminiAPIKey) {
    std::regex regex(R"(AIza[0-9A-Za-z\-_]{35})");
    std::string valid = "AIzaabcdefghijklmnopqrstuvwxyzABCDE1234";
    std::string invalid = "AIzaSyA-abc";
    EXPECT_TRUE(std::regex_match(valid, regex));
    EXPECT_FALSE(std::regex_match(invalid, regex));
}

TEST(RegexPatternTest, MatchesFirebaseAPIKey) {
    std::regex regex(R"(AIza[0-9A-Za-z\-_]{35})");
    std::string valid = "AIzaabcdefghijklmnopqrstuvwxyzABCDE1234";
    std::string invalid = "AIzaSyA-abc";
    EXPECT_TRUE(std::regex_match(valid, regex));
    EXPECT_FALSE(std::regex_match(invalid, regex));
}


TEST(RegexPatternTest, MatchesClerkPublishableKey) {
    std::regex regex(R"(pk_live_[a-zA-Z0-9]{20,})");
    EXPECT_TRUE(std::regex_match("pk_live_abcdefghijklmnopqrstuvwxyz123456", regex));
    EXPECT_FALSE(std::regex_match("pk_live_abc123", regex));
}

TEST(RegexPatternTest, MatchesClerkSecretKey) {
    std::regex regex(R"(sk_live_[a-zA-Z0-9]{20,})");
    EXPECT_TRUE(std::regex_match("sk_live_abcdefghijklmnopqrstuvwxyz123456", regex));
    EXPECT_FALSE(std::regex_match("sk_live_abc123", regex));
}

// TEST(RegexPatternTest, MatchesSupabaseAPIKey) {
//     std::regex regex(R"([A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)");
//     EXPECT_TRUE(std::regex_match("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", regex));
//     EXPECT_FALSE(std::regex_match("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", regex));
// }



TEST(RegexPatternTest, MatchesVercelToken) {
    std::regex pattern(R"(vercel_[a-zA-Z0-9]{40})");
    
    // Valid tokens
    EXPECT_TRUE(std::regex_match("vercel_abcdefghijklmnopqrstuvwxyz1234567890ABCD", pattern));
    EXPECT_TRUE(std::regex_match("vercel_1234567890abcdefghijklmnopqrstuvwxyzABCD", pattern));
    
    // Invalid tokens
    EXPECT_FALSE(std::regex_match("vercel_abc123", pattern));
    EXPECT_FALSE(std::regex_match("vercel_abcdefghijklmnopqrstuvwxyz1234567890ABCDE", pattern)); // too long
    EXPECT_FALSE(std::regex_match("vercel_", pattern));
    EXPECT_FALSE(std::regex_match("vercel_abc@123", pattern)); // invalid char
}

TEST(RegexPatternTest, MatchesNetlifyAccessToken) {
    std::regex pattern(R"(netlify_[a-zA-Z0-9]{40})");
    
    // Valid tokens
    EXPECT_TRUE(std::regex_match("netlify_abcdefghijklmnopqrstuvwxyz1234567890ABCD", pattern));
    EXPECT_TRUE(std::regex_match("netlify_1234567890abcdefghijklmnopqrstuvwxyzABCD", pattern));
    
    // Invalid tokens
    EXPECT_FALSE(std::regex_match("netlify_abc123", pattern));
    EXPECT_FALSE(std::regex_match("netlify_abcdefghijklmnopqrstuvwxyz1234567890ABCDE", pattern));
    EXPECT_FALSE(std::regex_match("netlify_", pattern));
}

TEST(RegexPatternTest, MatchesDigitalOceanAPIToken) {
    std::regex pattern(R"(do_[a-zA-Z0-9]{64})");
    
    // Valid tokens (exactly 64 characters after "do_")
    EXPECT_TRUE(std::regex_match("do_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12", pattern));
    EXPECT_TRUE(std::regex_match("do_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12", pattern));
    
    // Invalid tokens
    EXPECT_FALSE(std::regex_match("do_abc123", pattern));
    EXPECT_FALSE(std::regex_match("do_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ123", pattern)); // too long
    EXPECT_FALSE(std::regex_match("do_", pattern));
}

TEST(RegexPatternTest, MatchesAutodeskForgeClientID) {
    std::regex pattern(R"(forge_client_id\s*[:=]\s*['\"]?[a-zA-Z0-9]{32}['\"]?)", std::regex_constants::icase);
    
    // Valid patterns
    EXPECT_TRUE(std::regex_match("forge_client_id = abcdefghijklmnopqrstuvwxyz123456", pattern));
    EXPECT_TRUE(std::regex_match("forge_client_id: \"abcdefghijklmnopqrstuvwxyz123456\"", pattern));
    EXPECT_TRUE(std::regex_match("forge_client_id='abcdefghijklmnopqrstuvwxyz123456'", pattern));
    EXPECT_TRUE(std::regex_match("FORGE_CLIENT_ID = abcdefghijklmnopqrstuvwxyz123456", pattern));
    
    // Invalid patterns
    EXPECT_FALSE(std::regex_match("forge_client_id = abc123", pattern));
    EXPECT_FALSE(std::regex_match("forge_client_id = abcdefghijklmnopqrstuvwxyz1234567", pattern)); // too long
}

TEST(RegexPatternTest, MatchesAutodeskForgeClientSecret) {
    std::regex pattern(R"(forge_client_secret\s*[:=]\s*['\"]?[a-zA-Z0-9]{32}['\"]?)", std::regex_constants::icase);
    
    // Valid patterns
    EXPECT_TRUE(std::regex_match("forge_client_secret = abcdefghijklmnopqrstuvwxyz123456", pattern));
    EXPECT_TRUE(std::regex_match("forge_client_secret: \"abcdefghijklmnopqrstuvwxyz123456\"", pattern));
    EXPECT_TRUE(std::regex_match("FORGE_CLIENT_SECRET='abcdefghijklmnopqrstuvwxyz123456'", pattern));
    
    // Invalid patterns
    EXPECT_FALSE(std::regex_match("forge_client_secret = abc123", pattern));
    EXPECT_FALSE(std::regex_match("forge_client_secret = abcdefghijklmnopqrstuvwxyz1234567", pattern));
}


TEST(RegexPatternTest, MatchesGitLabPersonalAccessToken) {
    std::regex pattern(R"(glpat-[0-9a-zA-Z_-]{20})");
    
    // Valid tokens
    EXPECT_TRUE(std::regex_match("glpat-abcdefghijklmnopqrst", pattern));
    EXPECT_TRUE(std::regex_match("glpat-1234567890abcdefghij", pattern));
    EXPECT_TRUE(std::regex_match("glpat-abc_def-123456789012", pattern));
    
    // Invalid tokens
    EXPECT_FALSE(std::regex_match("glpat-abc123", pattern));
    EXPECT_FALSE(std::regex_match("glpat-abcdefghijklmnopqrstu", pattern)); // too long
    EXPECT_FALSE(std::regex_match("glpat-", pattern));
}

TEST(RegexPatternTest, MatchesAsanaPersonalAccessToken) {
    std::regex pattern(R"(0\/[0-9a-f]{32})");
    
    // Valid tokens (exactly 32 hex characters after "0/")
    EXPECT_TRUE(std::regex_match("0/abcdef1234567890abcdef1234567890", pattern));
    EXPECT_TRUE(std::regex_match("0/1234567890abcdef1234567890abcdef", pattern));
    
    // Invalid tokens
    EXPECT_FALSE(std::regex_match("0/abc123", pattern));
    EXPECT_FALSE(std::regex_match("0/abcdef1234567890abcdef12345678901", pattern)); // too long
    EXPECT_FALSE(std::regex_match("0/", pattern));
    EXPECT_FALSE(std::regex_match("0/ABCDEF1234567890abcdef1234567890", pattern)); // uppercase not allowed
}

TEST(RegexPatternTest, MatchesSendGridAPIKey) {
    std::regex pattern(R"(SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,})");
    
    EXPECT_TRUE(std::regex_match("SG.abcdefghijklmnopqrstuvwxyz.1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", pattern));
    EXPECT_TRUE(std::regex_match("SG.abc_def-123456789012345.xyz_ABC-789012345678901", pattern));
    
    EXPECT_FALSE(std::regex_match("SG.short.short", pattern));
    EXPECT_FALSE(std::regex_match("SG.abcdefghijklmnopqrstuvwxyz.", pattern));
    EXPECT_FALSE(std::regex_match("SG..1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", pattern));
}

TEST(RegexPatternTest, MatchesTrelloAPIKey) {
    std::regex pattern(R"([a-f0-9]{64})");
    
    EXPECT_TRUE(std::regex_match("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", pattern));
    EXPECT_TRUE(std::regex_match("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", pattern));
    
    EXPECT_FALSE(std::regex_match("abc123", pattern));
    EXPECT_FALSE(std::regex_match("abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678901", pattern)); // too long
    EXPECT_FALSE(std::regex_match("ABCDEF1234567890abcdef1234567890abcdef1234567890abcdef1234567890", pattern)); // uppercase not allowed
}

TEST(RegexPatternTest, MatchesLinearAPIKey) {
    std::regex pattern(R"(lin_api_[a-zA-Z0-9]{40})");
    
    EXPECT_TRUE(std::regex_match("lin_api_abcdefghijklmnopqrstuvwxyz1234567890ABCD", pattern));
    EXPECT_TRUE(std::regex_match("lin_api_1234567890abcdefghijklmnopqrstuvwxyzABCD", pattern));
    
    EXPECT_FALSE(std::regex_match("lin_api_abc123", pattern));
    EXPECT_FALSE(std::regex_match("lin_api_abcdefghijklmnopqrstuvwxyz1234567890ABCDE", pattern)); // too long
    EXPECT_FALSE(std::regex_match("lin_api_", pattern));
}

TEST(RegexPatternTest, MatchesNotionIntegrationToken) {
    std::regex pattern(R"(secret_[a-zA-Z0-9]{43})");
    
    EXPECT_TRUE(std::regex_match("secret_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG", pattern));
    EXPECT_TRUE(std::regex_match("secret_1234567890abcdefghijklmnopqrstuvwxyzABCDEFG", pattern));
    
    EXPECT_FALSE(std::regex_match("secret_abc123", pattern));
    EXPECT_FALSE(std::regex_match("secret_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH", pattern)); // too long
    EXPECT_FALSE(std::regex_match("secret_", pattern));
}

TEST(RegexPatternTest, MatchesClickUpAPIToken) {
    std::regex pattern(R"(pk_[a-zA-Z0-9]{32})");
    
    EXPECT_TRUE(std::regex_match("pk_abcdefghijklmnopqrstuvwxyz123456", pattern));
    EXPECT_TRUE(std::regex_match("pk_1234567890abcdefghijklmnopqrstuv", pattern));
    
    EXPECT_FALSE(std::regex_match("pk_abc123", pattern));
    EXPECT_FALSE(std::regex_match("pk_abcdefghijklmnopqrstuvwxyz1234567", pattern)); // too long
    EXPECT_FALSE(std::regex_match("pk_", pattern));
}

TEST(RegexPatternTest, MatchesShopifySecretKey) {
    std::regex pattern(R"(shpss_[a-fA-F0-9]{32,})");
    
    EXPECT_TRUE(std::regex_match("shpss_abcdef1234567890ABCDEF1234567890", pattern));
    EXPECT_TRUE(std::regex_match("shpss_ABCDEF1234567890abcdef1234567890", pattern));
    EXPECT_TRUE(std::regex_match("shpss_1234567890abcdef1234567890ABCDEFabcd", pattern)); // longer than 32
    
    EXPECT_FALSE(std::regex_match("shpss_abc123", pattern)); // too short
    EXPECT_FALSE(std::regex_match("shpss_", pattern));
    EXPECT_FALSE(std::regex_match("shpss_ghijklmnopqrstuvwxyz12345678", pattern)); // contains invalid chars
}

TEST(RegexPatternTest, MatchesPlausibleAPIKey) {
    std::regex pattern(R"(plausible_[a-zA-Z0-9]{40,})");
    
    EXPECT_TRUE(std::regex_match("plausible_abcdefghijklmnopqrstuvwxyz1234567890ABCD", pattern));
    EXPECT_TRUE(std::regex_match("plausible_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP", pattern)); // longer than 40
    
    EXPECT_FALSE(std::regex_match("plausible_abc123", pattern)); // too short
    EXPECT_FALSE(std::regex_match("plausible_", pattern));
}

TEST(RegexPatternTest, MatchesDatadogAPIKey) {
    std::regex pattern(R"(dd[a-zA-Z0-9]{32})");
    
    EXPECT_TRUE(std::regex_match("ddabcdefghijklmnopqrstuvwxyz123456", pattern));
    EXPECT_TRUE(std::regex_match("dd1234567890abcdefghijklmnopqrstuv", pattern));
    
    EXPECT_FALSE(std::regex_match("ddabc123", pattern));
    EXPECT_FALSE(std::regex_match("ddabcdefghijklmnopqrstuvwxyz1234567", pattern)); // too long
    EXPECT_FALSE(std::regex_match("dd", pattern));
}

TEST(RegexPatternTest, MatchesDropboxAccessToken) {
    std::regex pattern(R"(sl\.[A-Za-z0-9_-]{135})");
    
    std::string validToken = "sl." + std::string(135, 'a');
    std::string validTokenMixed = "sl.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" + std::string(71, 'x'); // 64+71=135
    
    EXPECT_TRUE(std::regex_match(validToken, pattern));
    EXPECT_TRUE(std::regex_match(validTokenMixed, pattern));
    
    EXPECT_FALSE(std::regex_match("sl.abc123", pattern)); // too short
    EXPECT_FALSE(std::regex_match("sl." + std::string(136, 'a'), pattern)); // too long
    EXPECT_FALSE(std::regex_match("sl.", pattern));
}

TEST(RegexPatternTest, DetectTokensInText) {
    std::string text = "Here are some tokens: vercel_abcdefghijklmnopqrstuvwxyz1234567890ABCD and pk.test.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcd";
    
    std::regex vercelPattern(R"(vercel_[a-zA-Z0-9]{40})");
    EXPECT_TRUE(std::regex_search(text, vercelPattern));
    
    std::regex mapboxPattern(R"(pk\.[a-zA-Z0-9]+\.[a-zA-Z0-9]{60,64})");
    EXPECT_TRUE(std::regex_search(text, mapboxPattern));
}
// TODO: WTF error need to investiagate more

// TEST(RegexPatternTest, MatchesMapboxPublicToken) {
//     std::regex pattern(R"(pk\.[a-zA-Z0-9]+\.[a-zA-Z0-9]{60,64})");
    
//     // Valid tokens (60+ characters in the final part)
//     EXPECT_TRUE(std::regex_match("pk.abc123.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZab", pattern));
//     EXPECT_TRUE(std::regex_match("pk.test.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcd", pattern));
    
//     // Invalid tokens
//     EXPECT_FALSE(std::regex_match("pk.abc123.short", pattern));
//     EXPECT_FALSE(std::regex_match("pk..abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcd", pattern));
// }

// TEST(RegexPatternTest, MatchesMapboxSecretToken) {
//     std::regex pattern(R"(sk\.[a-zA-Z0-9]+\.[a-zA-Z0-9]{60,64})");
    
//     // Valid tokens (60+ characters in the final part)
//     EXPECT_TRUE(std::regex_match("sk.abc123.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZab", pattern));
//     EXPECT_TRUE(std::regex_match("sk.test.abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcd", pattern));
    
//     // Invalid tokens
//     EXPECT_FALSE(std::regex_match("sk.abc123.short", pattern));
//     EXPECT_FALSE(std::regex_match("sk..abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcd", pattern));
// }

