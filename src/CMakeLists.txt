cmake_minimum_required(VERSION 3.28..4.1)
project(pkeyencrypt VERSION 0.1.0 LANGUAGES CXX)
set(EXE pkeyencrypt)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Suppress warnings about deprecated is_trivial_v in C++26
if(CMAKE_CXX_STANDARD GREATER_EQUAL 26)
    add_compile_options(-Wno-deprecated)
endif()

add_compile_options(-Wunused -Wnrvo)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

if(CMAKE_GENERATOR MATCHES "Ninja Multi-Config")
  set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "" FORCE)
  set(CMAKE_DEFAULT_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

option(ENABLE_ASAN "Enable AddressSanitizer in Debug" OFF)

# Suppress warnings about deprecated is_trivial_v in C++26
if(CMAKE_CXX_STANDARD GREATER_EQUAL 26)
    add_compile_options(-Wno-deprecated)
endif()

add_executable(${EXE}
    main.cpp
    pkeyencrypt.cpp
)

target_include_directories(${EXE} PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(${EXE} OpenSSL::Crypto)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${EXE} PRIVATE -Wall -Wextra -Wpedantic)
endif()