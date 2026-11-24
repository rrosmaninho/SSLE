cmake_minimum_required(VERSION 3.20)
project(ssle_services CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# Shared dependencies, resolved once and inherited by every module.
find_package(Threads REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(OpenSSL REQUIRED)

# Debian ships cpp-httplib as a compiled library, not header-only.
find_path(HTTPLIB_INCLUDE_DIR httplib.h REQUIRED)
find_library(HTTPLIB_LIBRARY NAMES cpp-httplib REQUIRED)
find_library(SQLITE3_LIBRARY NAMES sqlite3 REQUIRED)
find_path(SQLITE3_INCLUDE_DIR sqlite3.h REQUIRED)

add_subdirectory(modules/common)
add_subdirectory(modules/registry)
add_subdirectory(modules/ingestion)
add_subdirectory(modules/storage)
add_subdirectory(modules/analytics)
add_subdirectory(modules/sensor)
