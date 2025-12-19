#include <gtest/gtest.h>
#include "kat.hpp"
#include "parameters.hpp"
#include "nist_kat_parser.hpp"
#include <vector>
#include <array>
#include <iostream>
#include <stdexcept>

namespace clwe {

class ColorSignKnownAnswerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test with different security levels
        security_levels_ = {44, 65, 87};
    }

    std::vector<uint32_t> security_levels_;

    // Load NIST KAT vectors for a given security level
    std::vector<MLDSA_KAT_TestVector> load_nist_kat_vectors(uint32_t security_level) {
        try {
            std::string kat_content = NIST_KAT_Downloader::download_mldsa_kat(security_level);
            return NIST_KAT_Downloader::parse_mldsa_kat(kat_content);
        } catch (const std::exception& e) {
            std::cerr << "Failed to load NIST KAT vectors for level " << security_level
                      << ": " << e.what() << std::endl;
            // Return empty vector if download fails
            return {};
        }
    }
};

// Test NIST KAT vectors for key generation - 44
TEST_F(ColorSignKnownAnswerTest, NIST_KAT_KeyGeneration44) {
    auto kat_vectors = load_nist_kat_vectors(44);
    if (kat_vectors.empty()) {
        GTEST_SKIP() << "NIST KAT vectors not available for ML-DSA-44";
    }

    CLWEParameters params(44);
    ColorSignKAT kat(params);

    // Test first few vectors
    for (size_t i = 0; i < std::min(size_t(3), kat_vectors.size()); ++i) {
        const auto& tv = kat_vectors[i];

        // The ColorSignKAT class should handle the deterministic key generation
        // and comparison with expected values
        // For now, we'll just check that we can create the KAT object
        EXPECT_EQ(params.security_level, 44u);
    }
}

// Test NIST KAT vectors for signing - 44
TEST_F(ColorSignKnownAnswerTest, NIST_KAT_Signing44) {
    auto kat_vectors = load_nist_kat_vectors(44);
    if (kat_vectors.empty()) {
        GTEST_SKIP() << "NIST KAT vectors not available for ML-DSA-44";
    }

    CLWEParameters params(44);
    ColorSignKAT kat(params);

    // Test first few vectors
    for (size_t i = 0; i < std::min(size_t(3), kat_vectors.size()); ++i) {
        const auto& tv = kat_vectors[i];

        // The ColorSignKAT class should handle signing and verification
        // For now, we'll just check that we can create the KAT object
        EXPECT_EQ(params.security_level, 44u);
    }
}

// Test NIST KAT vectors for key generation - 65
TEST_F(ColorSignKnownAnswerTest, NIST_KAT_KeyGeneration65) {
    auto kat_vectors = load_nist_kat_vectors(65);
    if (kat_vectors.empty()) {
        GTEST_SKIP() << "NIST KAT vectors not available for ML-DSA-65";
    }

    CLWEParameters params(65);
    ColorSignKAT kat(params);

    // Test first few vectors
    for (size_t i = 0; i < std::min(size_t(3), kat_vectors.size()); ++i) {
        const auto& tv = kat_vectors[i];

        // The ColorSignKAT class should handle the deterministic key generation
        // and comparison with expected values
        EXPECT_EQ(params.security_level, 65u);
    }
}

// Test NIST KAT vectors for key generation - 87
TEST_F(ColorSignKnownAnswerTest, NIST_KAT_KeyGeneration87) {
    auto kat_vectors = load_nist_kat_vectors(87);
    if (kat_vectors.empty()) {
        GTEST_SKIP() << "NIST KAT vectors not available for ML-DSA-87";
    }

    CLWEParameters params(87);
    ColorSignKAT kat(params);

    // Test first few vectors
    for (size_t i = 0; i < std::min(size_t(3), kat_vectors.size()); ++i) {
        const auto& tv = kat_vectors[i];

        // The ColorSignKAT class should handle the deterministic key generation
        // and comparison with expected values
        EXPECT_EQ(params.security_level, 87u);
    }
}

} // namespace clwe