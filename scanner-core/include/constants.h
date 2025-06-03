#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <unordered_set>
#include <string>

/**
  @brief Contains constants for file extensions and ignored directories used in secret scanning.
*/
extern const std::unordered_set<std::string> valid_extensions;
extern const std::unordered_set<std::string> ignored_dirs;

#endif // CONSTANTS_H
