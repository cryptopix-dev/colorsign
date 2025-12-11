# Tests CMakeLists.txt for ColorSign

# Include directories for tests
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src/include/clwe)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src/core)

# Test executables
add_executable(test_parameters test_parameters.cpp)
target_link_libraries(test_parameters PRIVATE colorsign_macos gtest_main)

add_executable(test_keygen test_keygen.cpp)
target_link_libraries(test_keygen PRIVATE colorsign_macos gtest_main)

add_executable(test_sign test_sign.cpp)
target_link_libraries(test_sign PRIVATE colorsign_macos gtest_main)

add_executable(test_verify test_verify.cpp)
target_link_libraries(test_verify PRIVATE colorsign_macos gtest_main)

add_executable(test_color_integration test_color_integration.cpp)
target_link_libraries(test_color_integration PRIVATE colorsign_macos gtest_main)

add_executable(test_utils test_utils.cpp)
target_link_libraries(test_utils PRIVATE colorsign_macos gtest_main)

add_executable(test_integration test_integration.cpp)
target_link_libraries(test_integration PRIVATE colorsign_macos gtest_main)

add_executable(test_kat test_kat.cpp)
target_link_libraries(test_kat PRIVATE colorsign_macos gtest_main)

add_executable(test_stress test_stress.cpp)
target_link_libraries(test_stress PRIVATE colorsign_macos gtest_main)

add_executable(test_security_utils test_security_utils.cpp)
target_link_libraries(test_security_utils PRIVATE colorsign_macos gtest_main)
add_executable(test_compression test_compression.cpp)
target_link_libraries(test_compression PRIVATE colorsign_macos gtest_main)

add_executable(test_final_validation test_final_validation.cpp)
target_link_libraries(test_final_validation PRIVATE colorsign_macos gtest_main)



# Register tests
add_test(NAME ParametersTests COMMAND test_parameters)
add_test(NAME KeygenTests COMMAND test_keygen)
add_test(NAME SignTests COMMAND test_sign)
add_test(NAME VerifyTests COMMAND test_verify)
add_test(NAME ColorIntegrationTests COMMAND test_color_integration)
add_test(NAME UtilsTests COMMAND test_utils)
add_test(NAME IntegrationTests COMMAND test_integration)
add_test(NAME KATTests COMMAND test_kat)
add_test(NAME StressTests COMMAND test_stress)
add_test(NAME SecurityUtilsTests COMMAND test_security_utils)

add_test(NAME CompressionTests COMMAND test_compression)

add_test(NAME FinalValidationTests COMMAND test_final_validation)