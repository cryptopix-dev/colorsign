# Tests CMakeLists.txt

# Include directories for tests
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src/include/clwe)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src/core)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# Google Test
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Library target
add_library(clwe_test STATIC
    ../src/core/parameters.cpp
    ../src/core/keygen.cpp
    ../src/core/sign.cpp
    ../src/core/verify.cpp
    ../src/core/cose.cpp
    ../src/core/color_integration.cpp
    ../src/core/utils.cpp
    ../src/core/security_utils.cpp
    ../src/core/kat.cpp
    ../src/core/cpu_features.cpp
    ../src/core/ntt_engine.cpp
    ../src/core/color_ntt_engine.cpp
    ../src/core/performance_metrics.cpp
    ../src/core/sampling.cpp
    ../src/core/shake_sampler.cpp
    ../src/core/color_value.cpp
    ../src/core/ntt_scalar.cpp
    ../src/core/tiny_sha3.c
    ../src/core/version.cpp
)

target_link_libraries(clwe_test PRIVATE OpenSSL::Crypto CURL::libcurl)

# macOS Security framework for secure random
if(APPLE)
    target_link_libraries(clwe_test PRIVATE "-framework Security")
    add_compile_definitions(IRAM_ATTR=)
endif()

# Test executables
add_executable(test_color_value test_color_value.cpp)
target_link_libraries(test_color_value PRIVATE clwe_test gtest_main)

add_executable(test_clwe_parameters test_clwe_parameters.cpp)
target_link_libraries(test_clwe_parameters PRIVATE clwe_test gtest_main)

add_executable(test_utils test_utils.cpp)
target_link_libraries(test_utils PRIVATE clwe_test gtest_main)

add_executable(test_ntt_engine test_ntt_engine.cpp)
target_link_libraries(test_ntt_engine PRIVATE clwe_test gtest_main)

add_executable(test_sampling test_sampling.cpp)
target_link_libraries(test_sampling PRIVATE clwe_test gtest_main)

add_executable(test_performance_metrics test_performance_metrics.cpp)
target_link_libraries(test_performance_metrics PRIVATE clwe_test gtest_main)

add_executable(test_known_answer_tests test_known_answer_tests.cpp nist_kat_parser.cpp)
target_link_libraries(test_known_answer_tests PRIVATE clwe_test gtest_main CURL::libcurl)

# Register tests
add_test(NAME ColorValueTests COMMAND test_color_value)
add_test(NAME CLWEParametersTests COMMAND test_clwe_parameters)
add_test(NAME KnownAnswerTests COMMAND test_known_answer_tests)

# Fuzzing targets (only if fuzzing is enabled)
if(ENABLE_FUZZING)
    add_executable(fuzz_edge_cases fuzz/fuzz_edge_cases.cpp)
    target_link_libraries(fuzz_edge_cases PRIVATE clwe_macos)
endif()