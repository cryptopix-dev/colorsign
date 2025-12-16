cmake_minimum_required(VERSION 3.16)
project(ColorSign VERSION 1.0.0 LANGUAGES C CXX)

# Toolchain will be set via external toolchain file

# Compiler settings
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags will be set via toolchain file

# Static linking settings will be set via toolchain file

# Windows-specific settings
if(WIN32)
    add_definitions(-D_MINGW -DWIN32 -D_WIN32)
endif()

# SIMD optimization flags will be set via toolchain file

# Dependencies - Use MinGW's built-in OpenSSL
set(OPENSSL_ROOT_DIR "C:/ProgramData/mingw64/mingw64/opt")
set(OPENSSL_USE_STATIC_LIBS TRUE)

# Find OpenSSL - should work with MinGW's built-in version
find_package(OpenSSL REQUIRED)

# Find WebP manually
find_path(WEBP_INCLUDE_DIR webp/types.h PATHS C:/ProgramData/mingw64/mingw64/include C:/msys64/mingw64/include)
find_library(WEBP_LIBRARY webp PATHS C:/ProgramData/mingw64/mingw64/lib C:/msys64/mingw64/lib)
find_library(WEBPDEMUX_LIBRARY webpdemux PATHS C:/ProgramData/mingw64/mingw64/lib C:/msys64/mingw64/lib)
find_library(WEBPMUX_LIBRARY webpmux PATHS C:/ProgramData/mingw64/mingw64/lib C:/msys64/mingw64/lib)

if(WEBP_INCLUDE_DIR AND WEBP_LIBRARY)
    set(WEBP_FOUND TRUE)
    set(WEBP_LIBRARIES ${WEBP_LIBRARY} ${WEBPDEMUX_LIBRARY} ${WEBPMUX_LIBRARY})
else()
    set(WEBP_FOUND FALSE)
endif()

# Add OpenSSL include directories explicitly for Windows
if(WIN32)
    include_directories(${OPENSSL_INCLUDE_DIR})
    if(WEBP_FOUND)
        include_directories(${WEBP_INCLUDE_DIR})
    endif()
endif()

# Google Test - Use system MinGW version if available, otherwise download
find_package(GTest QUIET)
if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    # For Windows: Prevent overriding the parent project's compiler/linker on Windows
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

    # Set compiler for subproject before making it available
    set(CMAKE_C_COMPILER "C:/ProgramData/mingw64/mingw64/bin/gcc.exe" CACHE FILEPATH "C compiler" FORCE)
    set(CMAKE_CXX_COMPILER "C:/ProgramData/mingw64/mingw64/bin/g++.exe" CACHE FILEPATH "C++ compiler" FORCE)

    # Suppress CMake deprecation warnings from googletest
    set(CMAKE_POLICY_VERSION_MINIMUM 3.16)
    FetchContent_MakeAvailable(googletest)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/core)

# Library target
add_library(colorsign STATIC
    src/core/parameters.cpp
    src/core/keygen.cpp
    src/core/sign.cpp
    src/core/verify.cpp
    src/core/cose.cpp
    src/core/color_integration.cpp
    src/core/utils.cpp
    src/core/security_utils.cpp
    src/core/kat.cpp
    src/core/cpu_features.cpp
    src/core/ntt_engine.cpp
    src/core/version.cpp
)

target_link_libraries(colorsign PRIVATE OpenSSL::Crypto)
if(WEBP_FOUND)
    target_link_libraries(colorsign PRIVATE ${WEBP_LIBRARIES})
endif()

# Windows Cryptography API for secure random
if(WIN32)
    target_link_libraries(colorsign PRIVATE crypt32 bcrypt)
endif()

# Main executable
add_executable(colorsign_test src/main.cpp)
target_link_libraries(colorsign_test PRIVATE colorsign)

# Benchmark executable
add_executable(benchmark_color_sign_timing benchmark_color_sign_timing.cpp)
target_link_libraries(benchmark_color_sign_timing PRIVATE colorsign)

# SIMD benchmark executable
add_executable(ntt_simd_benchmark src/core/ntt_simd_benchmark.cpp)
target_link_libraries(ntt_simd_benchmark PRIVATE colorsign)

# KAT vector generator executable
add_executable(generate_kat_vectors generate_kat_vectors.cpp)
target_link_libraries(generate_kat_vectors PRIVATE colorsign)

# All KAT vectors generator executable
add_executable(generate_all_kat_vectors generate_all_kat_vectors.cpp)
target_link_libraries(generate_all_kat_vectors PRIVATE colorsign)

if(WEBP_FOUND)
    # Key image generator executable
    add_executable(generate_key_images generate_key_images.cpp)
    target_link_libraries(generate_key_images PRIVATE colorsign)

    # Key image test executable
    add_executable(test_key_images test_key_images.cpp)
    target_link_libraries(test_key_images PRIVATE colorsign)
endif()

# Tests
enable_testing()

# Add tests subdirectory
add_subdirectory(tests)

# Add comprehensive test target - run all tests including unit tests
add_custom_target(run_all_tests
    COMMAND ${CMAKE_COMMAND} -E echo "Running basic verification test..."
    COMMAND ./colorsign_test
    COMMAND ${CMAKE_COMMAND} -E echo "Running unit tests..."
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running ColorSign verification and unit tests"
)

# Add benchmark as a test
add_test(NAME BenchmarkTest COMMAND benchmark_color_sign_timing)

# Installation
install(TARGETS colorsign
    EXPORT ColorSignTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    INCLUDES DESTINATION include
)

install(DIRECTORY src/include/clwe/
    DESTINATION include/clwe
    FILES_MATCHING PATTERN "*.hpp"
)

# Export targets
install(EXPORT ColorSignTargets
    FILE ColorSignTargets.cmake
    NAMESPACE ColorSign::
    DESTINATION lib/cmake/ColorSign
)