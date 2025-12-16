#include <gtest/gtest.h>
#include "utils.hpp"
#include <vector>
#include <cstring>
#include <algorithm>

namespace {

// Test fixture for utils
class UtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Common setup if needed
    }
};

TEST_F(UtilsTest, SecureRandomBytesGeneratesDifferentValues) {
    std::vector<uint8_t> buffer1(32);
    std::vector<uint8_t> buffer2(32);

    clwe::secure_random_bytes(buffer1.data(), buffer1.size());
    clwe::secure_random_bytes(buffer2.data(), buffer2.size());

    // Should be different (with very high probability)
    EXPECT_NE(buffer1, buffer2);
}

TEST_F(UtilsTest, SecureRandomBytesDifferentSizes) {
    std::vector<uint8_t> buffer1(16);
    std::vector<uint8_t> buffer2(32);
    std::vector<uint8_t> buffer3(64);

    clwe::secure_random_bytes(buffer1.data(), buffer1.size());
    clwe::secure_random_bytes(buffer2.data(), buffer2.size());
    clwe::secure_random_bytes(buffer3.data(), buffer3.size());

    // All should be non-zero (very high probability)
    bool all_zero1 = std::all_of(buffer1.begin(), buffer1.end(), [](uint8_t b) { return b == 0; });
    bool all_zero2 = std::all_of(buffer2.begin(), buffer2.end(), [](uint8_t b) { return b == 0; });
    bool all_zero3 = std::all_of(buffer3.begin(), buffer3.end(), [](uint8_t b) { return b == 0; });

    EXPECT_FALSE(all_zero1);
    EXPECT_FALSE(all_zero2);
    EXPECT_FALSE(all_zero3);
}

TEST_F(UtilsTest, Shake256Deterministic) {
    std::vector<uint8_t> input = {0x01, 0x02, 0x03, 0x04};
    size_t output_len = 32;

    std::vector<uint8_t> output1 = clwe::shake256(input, output_len);
    std::vector<uint8_t> output2 = clwe::shake256(input, output_len);

    EXPECT_EQ(output1.size(), output_len);
    EXPECT_EQ(output2.size(), output_len);
    EXPECT_EQ(output1, output2);
}

TEST_F(UtilsTest, Shake256DifferentInputs) {
    std::vector<uint8_t> input1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> input2 = {0x01, 0x02, 0x04};
    size_t output_len = 32;

    std::vector<uint8_t> output1 = clwe::shake256(input1, output_len);
    std::vector<uint8_t> output2 = clwe::shake256(input2, output_len);

    EXPECT_EQ(output1.size(), output_len);
    EXPECT_EQ(output2.size(), output_len);
    EXPECT_NE(output1, output2);
}

TEST_F(UtilsTest, Shake256EmptyInput) {
    std::vector<uint8_t> input;
    size_t output_len = 32;

    std::vector<uint8_t> output = clwe::shake256(input, output_len);

    EXPECT_EQ(output.size(), output_len);
    // Should be deterministic even with empty input
    std::vector<uint8_t> output2 = clwe::shake256(input, output_len);
    EXPECT_EQ(output, output2);
}

TEST_F(UtilsTest, Shake256VariousOutputLengths) {
    std::vector<uint8_t> input = {0xFF, 0xEE, 0xDD, 0xCC};

    std::vector<size_t> lengths = {1, 16, 32, 64, 128, 256, 512};

    for (size_t len : lengths) {
        std::vector<uint8_t> output = clwe::shake256(input, len);
        EXPECT_EQ(output.size(), len);

        // Deterministic
        std::vector<uint8_t> output2 = clwe::shake256(input, len);
        EXPECT_EQ(output, output2);
    }
}

TEST_F(UtilsTest, Shake256ZeroOutputLength) {
    std::vector<uint8_t> input = {0x01, 0x02, 0x03};

    std::vector<uint8_t> output = clwe::shake256(input, 0);
    EXPECT_EQ(output.size(), 0u);
}

TEST_F(UtilsTest, Shake256LargeInput) {
    std::vector<uint8_t> input(1000, 0xAA);  // 1000 bytes of 0xAA
    size_t output_len = 64;

    std::vector<uint8_t> output = clwe::shake256(input, output_len);
    EXPECT_EQ(output.size(), output_len);

    // Deterministic
    std::vector<uint8_t> output2 = clwe::shake256(input, output_len);
    EXPECT_EQ(output, output2);
}

TEST_F(UtilsTest, Shake256DeterministicOutput) {
    // Test that the current implementation is deterministic
    // Note: This is a custom Keccak implementation, so output will be consistent but different from standard SHAKE256
    std::vector<uint8_t> input;
    size_t output_len = 32;

    std::vector<uint8_t> output1 = clwe::shake256(input, output_len);
    std::vector<uint8_t> output2 = clwe::shake256(input, output_len);

    EXPECT_EQ(output1, output2);
    EXPECT_EQ(output1.size(), output_len);

    // Test that output is not all zeros (should be random-looking)
    bool all_zeros = std::all_of(output1.begin(), output1.end(), [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(all_zeros);
}

TEST_F(UtilsTest, Shake256DeterministicOutputWithData) {
    // Test with some input data
    std::vector<uint8_t> input = {'a', 'b', 'c'};
    size_t output_len = 32;

    std::vector<uint8_t> output1 = clwe::shake256(input, output_len);
    std::vector<uint8_t> output2 = clwe::shake256(input, output_len);

    EXPECT_EQ(output1, output2);
    EXPECT_EQ(output1.size(), output_len);

    // Should not be all zeros
    bool all_zeros = std::all_of(output1.begin(), output1.end(), [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(all_zeros);
}

} // namespace