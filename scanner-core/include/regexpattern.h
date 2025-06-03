// regex.h
#ifndef REGEXPATTERN_H
#define REGEXPATTERN_H

#include <vector>
#include <regex>
#include <string>

/**
 * @brief Contains patterns used for detecting secrets in source code.
 */
extern const std::vector<std::pair<std::string, std::regex>> secret_patterns;

#endif // REGEX_H