/**
 * @file regexpattern.cpp
 * @brief Regular expressions for detecting secrets in source code.
 *
 * Defines a constant vector of pairs, each containing a descriptive string and a corresponding
 * std::regex object. These patterns are crafted to match various types of sensitive information,
 * such as API keys, tokens, private keys, database URIs, and passwords, commonly found in source
 * code or configuration files. Intended for use in secret scanning tools to help prevent accidental
 * exposure of confidential credentials.
 *
 * @author Dorna Raj Gyawali <dronarajgyawali@gmail.com>
 * @date 2025
 */

#include "regexpattern.h"

const std::vector<std::pair<std::string, std::regex>> secret_patterns = {
    {"AWS Access Key", std::regex(R"(AKIA[0-9A-Z]{16})")},
    {"Stripe Secret Key", std::regex(R"(sk_live_[0-9a-zA-Z]{24})")},
    {"Google API Key", std::regex(R"(AIza[0-9A-Za-z\-_]{35})")},
    {"JWT", std::regex(R"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9_-]+)")},
    {"Private Key", std::regex(R"(-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----)")},
    {"Generic Secret", std::regex(R"(secret\s*=\s*['\"][\w\-]{8,}['\"])")},
    {"DB URI", std::regex(R"(mongodb\+srv://[^:]+:[^@]+@[^ \n]+)")},
    {"Slack Token", std::regex(R"(xox[baprs]-[0-9a-zA-Z]{10,48})")},
    {"Heroku API Key", std::regex(R"(heroku_[0-9a-fA-F]{32})")},
    {"Facebook Access Token", std::regex(R"(EAACEdEose0cBA[0-9A-Za-z]+)")},
    {"Twitter Access Token", std::regex(R"(AAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z]{35,44})")},
    {"GitHub Token", std::regex(R"(ghp_[0-9A-Za-z]{36})")},
    {"Mailgun API Key", std::regex(R"(key-[0-9a-zA-Z]{32})")},
    {"Password in Env", std::regex(R"(password\s*=\s*['\"][^'\"]{8,}['\"])")},
    {"RSA Private Key", std::regex(R"(-----BEGIN RSA PRIVATE KEY-----)")},
    {"SSH Private Key", std::regex(R"(-----BEGIN OPENSSH PRIVATE KEY-----)")},
    {"Google OAuth Access Token", std::regex(R"(ya29\.[0-9A-Za-z\-_]+)")},
    {"Azure Storage Key", std::regex(R"(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net)")},
    {"RabbitMQ URI", std::regex(R"(amqps?:\/\/[^:]+:[^@]+@[^\/\s:]+(:\d+)?(\/[^\s]*)?)")},
    {"Celery Broker URL (Redis)", std::regex(R"(redis:\/\/:(.+)@[^\/\s:]+(:\d+)?(\/\d+)?)")},
    {"Generic Private Key", std::regex(R"(-----BEGIN PRIVATE KEY-----)")},
    {"OpenWeather API Key", std::regex(R"([a-fA-F0-9]{32})")},
};
