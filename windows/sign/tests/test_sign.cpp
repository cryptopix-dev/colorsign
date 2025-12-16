#include <gtest/gtest.h>
#include "sign.hpp"
#include "keygen.hpp"
#include <stdexcept>

namespace {

// Test fixture for sign
class SignTest : public ::testing::Test {
protected:
    void SetUp() override {
        params = clwe::CLWEParameters(44);
        keygen = std::make_unique<clwe::ColorSignKeyGen>(params);
        std::array<uint8_t, 32> seed = {0};
        auto [pub, priv] = keygen->generate_keypair_deterministic(seed);
        public_key = pub;
        private_key = priv;
        signer = std::make_unique<clwe::ColorSign>(params);
    }

    clwe::CLWEParameters params;
    std::unique_ptr<clwe::ColorSignKeyGen> keygen;
    clwe::ColorSignPublicKey public_key;
    clwe::ColorSignPrivateKey private_key;
    std::unique_ptr<clwe::ColorSign> signer;
};

TEST_F(SignTest, ConstructorValidParameters) {
    EXPECT_NO_THROW(clwe::ColorSign signer(params));
}

TEST_F(SignTest, ConstructorInvalidParameters) {
    EXPECT_THROW({
        clwe::CLWEParameters invalid_params(44, 0, 2, 4, 3329, 2, 39, 78, 1 << 17, (3329 - 1) / 88, 80, 128);
        clwe::ColorSign signer(invalid_params);
    }, std::invalid_argument);
}

TEST_F(SignTest, SignValidMessage) {
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};

    EXPECT_NO_THROW({
        clwe::ColorSignature signature = signer->sign_message(message, private_key, public_key);
        EXPECT_FALSE(signature.z_data.empty());
        EXPECT_FALSE(signature.h_data.empty());
        EXPECT_FALSE(signature.c_data.empty());
        EXPECT_EQ(signature.params.security_level, 44u);
    });
}

TEST_F(SignTest, SignEmptyMessage) {
    std::vector<uint8_t> empty_message;

    EXPECT_THROW(signer->sign_message(empty_message, private_key, public_key), std::invalid_argument);
}

TEST_F(SignTest, SignWithInvalidPrivateKey) {
    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    clwe::ColorSignPrivateKey invalid_private_key{{}, {}, {}, {}, params};

    EXPECT_THROW(signer->sign_message(message, invalid_private_key, public_key), std::invalid_argument);
}

TEST_F(SignTest, SignWithInvalidPublicKey) {
    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    clwe::ColorSignPublicKey invalid_public_key{{0}, {}, {}, {}, params};

    EXPECT_THROW(signer->sign_message(message, private_key, invalid_public_key), std::invalid_argument);
}

TEST_F(SignTest, SignDifferentMessages) {
    std::vector<uint8_t> message1 = {'m', 'e', 's', 's', 'a', 'g', 'e', '1'};
    std::vector<uint8_t> message2 = {'m', 'e', 's', 's', 'a', 'g', 'e', '2'};

    clwe::ColorSignature sig1 = signer->sign_message(message1, private_key, public_key);
    clwe::ColorSignature sig2 = signer->sign_message(message2, private_key, public_key);

    // Signatures should be different for different messages
    EXPECT_NE(sig1.z_data, sig2.z_data);
    EXPECT_NE(sig1.c_data, sig2.c_data);
}

TEST_F(SignTest, SignSameMessageMultipleTimes) {
    std::vector<uint8_t> message = {'s', 'a', 'm', 'e', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};

    clwe::ColorSignature sig1 = signer->sign_message(message, private_key, public_key);
    clwe::ColorSignature sig2 = signer->sign_message(message, private_key, public_key);

    // Signatures might be different due to randomness in y sampling
    // But they should have the same structure
    EXPECT_EQ(sig1.z_data.size(), sig2.z_data.size());
    EXPECT_EQ(sig1.c_data.size(), sig2.c_data.size());
    EXPECT_EQ(sig1.params.security_level, sig2.params.security_level);
}

TEST_F(SignTest, SignatureSerializationRoundTrip) {
    std::vector<uint8_t> message = {'s', 'e', 'r', 'i', 'a', 'l', 'i', 'z', 'e'};

    clwe::ColorSignature original = signer->sign_message(message, private_key, public_key);

    auto serialized = original.serialize();
    auto deserialized = clwe::ColorSignature::deserialize(serialized, params);

    EXPECT_EQ(original.z_data, deserialized.z_data);
    EXPECT_EQ(original.h_data, deserialized.h_data);
    EXPECT_EQ(original.c_data, deserialized.c_data);
    EXPECT_EQ(original.params.security_level, deserialized.params.security_level);
}

TEST_F(SignTest, SignatureDeserializeInvalidData) {
    // Too small data
    std::vector<uint8_t> small_data = {1, 2, 3};
    EXPECT_THROW(clwe::ColorSignature::deserialize(small_data, params), std::invalid_argument);

    // Empty data
    std::vector<uint8_t> empty_data;
    EXPECT_THROW(clwe::ColorSignature::deserialize(empty_data, params), std::invalid_argument);
}

TEST_F(SignTest, SignLargeMessage) {
    std::vector<uint8_t> large_message(1000, 'A');  // 1000 bytes

    EXPECT_NO_THROW({
        clwe::ColorSignature signature = signer->sign_message(large_message, private_key, public_key);
        EXPECT_FALSE(signature.z_data.empty());
        EXPECT_FALSE(signature.h_data.empty());
        EXPECT_FALSE(signature.c_data.empty());
    });
}

TEST_F(SignTest, SignMessageTooLarge) {
    std::vector<uint8_t> too_large_message(1024 * 1024 + 1, 'A');  // >1MB

    EXPECT_THROW(signer->sign_message(too_large_message, private_key, public_key), std::invalid_argument);
}


TEST_F(SignTest, ErrorMessageUtility) {
    EXPECT_EQ(clwe::get_colorsign_sign_error_message(clwe::ColorSignSignError::SUCCESS), "Success");
    EXPECT_EQ(clwe::get_colorsign_sign_error_message(clwe::ColorSignSignError::INVALID_PARAMETERS), "Invalid parameters");
    EXPECT_EQ(clwe::get_colorsign_sign_error_message(clwe::ColorSignSignError::INVALID_PRIVATE_KEY), "Invalid private key");
    EXPECT_EQ(clwe::get_colorsign_sign_error_message(clwe::ColorSignSignError::INVALID_PUBLIC_KEY), "Invalid public key");
    EXPECT_EQ(clwe::get_colorsign_sign_error_message(clwe::ColorSignSignError::INVALID_MESSAGE), "Invalid message");
    EXPECT_EQ(clwe::get_colorsign_sign_error_message(clwe::ColorSignSignError::SIGNING_FAILED), "Signing failed");
}

TEST_F(SignTest, SignatureStructureValidation) {
    std::vector<uint8_t> message = {'v', 'a', 'l', 'i', 'd', 'a', 't', 'e'};

    clwe::ColorSignature signature = signer->sign_message(message, private_key, public_key);

    // Check signature structure - using 32-bit uncompressed packing
    // For ML-DSA-44: k=4, n=256, each coefficient packed as 4 bytes
    uint32_t expected_z_size = params.module_rank * params.degree * 4; // 4 bytes per coefficient
    EXPECT_EQ(signature.z_data.size(), expected_z_size);

    // h_data should have omega bytes
    EXPECT_EQ(signature.h_data.size(), params.omega);

    // c_data should have correct size (packed challenge: 2 bits per coefficient)
    uint32_t expected_c_size = (params.degree + 3) / 4;
    EXPECT_EQ(signature.c_data.size(), expected_c_size);
}

} // namespace