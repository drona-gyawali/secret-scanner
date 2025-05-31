cmake_minimum_required(VERSION 3.14)
project(secret_scanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

set(SRC_FILES
    src/scanner.cpp
    src/constants.cpp
    src/regexpattern.cpp
    src/threadpool.cpp
)

add_executable(secret_scanner src/main.cpp ${SRC_FILES})
target_link_libraries(secret_scanner pthread)

enable_testing()

include(FetchContent)

FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.13.0.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(googletest)

# add test executables
add_executable(test_regex test/test_regex.cpp)
target_link_libraries(test_regex gtest gtest_main pthread)

add_executable(test_scanner test/test_scanner.cpp src/scanner.cpp src/regexpattern.cpp src/constants.cpp src/threadpool.cpp)
target_link_libraries(test_scanner gtest gtest_main pthread)

enable_testing()
add_test(NAME RegexTests COMMAND test_regex)
add_test(NAME ScannerTests COMMAND test_scanner)
