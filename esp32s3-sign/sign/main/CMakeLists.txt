idf_component_register(SRCS "main.cpp"
                              "../src/core/color_integration.cpp"
                              "../src/core/color_ntt_engine.cpp"
                              "../src/core/color_value.cpp"
                              "../src/core/cose.cpp"
                              "../src/core/cpu_features.cpp"
                              "../src/core/kat.cpp"
                              "../src/core/kat_complete.cpp"
                              "../src/core/keygen.cpp"
                              "../src/core/ntt_engine.cpp"
                              "../src/core/ntt_scalar.cpp"
                              "../src/core/parameters.cpp"
                              "../src/core/sampling.cpp"
                              "../src/core/security_utils.cpp"
                              "../src/core/shake_sampler.cpp"
                              "../src/core/sign.cpp"
                              "../src/core/tiny_sha3.c"
                              "../src/core/utils.cpp"
                              "../src/core/verify.cpp"
                              "../src/core/version.cpp"
                         INCLUDE_DIRS "." "../src/include")

# Enable testing if configured
if(CONFIG_ENABLE_TESTS)
    idf_component_register(
        TEST_SRC
            "../tests/test_clwe_parameters.cpp"
            "../tests/test_color_value.cpp"
            "../tests/test_known_answer_tests.cpp"
            "../tests/test_ntt_engine.cpp"
            "../tests/test_performance_metrics.cpp"
            "../tests/test_sampling.cpp"
            "../tests/test_serialization.cpp"
            "../tests/test_utils.cpp"
        REQUIRES
            unity
    )
endif()
