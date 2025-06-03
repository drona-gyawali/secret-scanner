# scanner-core/CMakeLists.txt

cmake_minimum_required(VERSION 3.14)
project(scanner_core)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include headers
include_directories(include)

# Source files
set(SRC_FILES
    src/scanner.cpp
    src/constants.cpp
    src/regexpattern.cpp
    src/threadpool.cpp
)

# Build executable
add_executable(secret_scanner src/main.cpp ${SRC_FILES})
target_link_libraries(secret_scanner pthread)

# Testing setup
enable_testing()
include(FetchContent)

FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.13.0.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(googletest)

# Unit test: regex
add_executable(test_regex test/test_regex.cpp)
target_link_libraries(test_regex gtest gtest_main pthread)

# Unit test: scanner
add_executable(test_scanner test/test_scanner.cpp ${SRC_FILES})
target_link_libraries(test_scanner gtest gtest_main pthread)

# Register tests
add_test(NAME RegexTests COMMAND test_regex)
add_test(NAME ScannerTests COMMAND test_scanner)
