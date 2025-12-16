#include <gtest/gtest.h>
#include "keygen.hpp"
#include <stdexcept>
#include <array>

namespace {

// Test fixture for keygen
class KeyGenTest : public ::testing::Test {
protected:
    void SetUp() override {
        params44 = clwe::CLWEParameters(44);
        params65 = clwe::CLWEParameters(65);
        params87 = clwe::CLWEParameters(87);
    }

    clwe::CLWEParameters params44;
    clwe::CLWEParameters params65;
    clwe::CLWEParameters params87;
};

TEST_F(KeyGenTest, ConstructorValidParameters) {
    EXPECT_NO_THROW(clwe::ColorSignKeyGen keygen(params44));
    EXPECT_NO_THROW(clwe::ColorSignKeyGen keygen(params65));
    EXPECT_NO_THROW(clwe::ColorSignKeyGen keygen(params87));
}

TEST_F(KeyGenTest, ConstructorInvalidParameters) {
    EXPECT_THROW({
        clwe::CLWEParameters invalid_params(44, 0, 2, 4, 3329, 2, 39, 78, 1 << 17, (3329 - 1) / 88, 80, 128);  // degree = 0
        clwe::ColorSignKeyGen keygen(invalid_params);
    }, std::invalid_argument);

    EXPECT_THROW({
        clwe::CLWEParameters invalid_params2(44, 256, 0, 4, 3329, 2, 39, 78, 1 << 17, (3329 - 1) / 88, 80, 128);  // module_rank = 0
        clwe::ColorSignKeyGen keygen(invalid_params2);
    }, std::invalid_argument);
}

TEST_F(KeyGenTest, GenerateKeypairSecurityLevel44) {
    clwe::ColorSignKeyGen keygen(params44);
    auto [public_key, private_key] = keygen.generate_keypair();

    EXPECT_EQ(public_key.params.security_level, 44u);
    EXPECT_EQ(private_key.params.security_level, 44u);
    EXPECT_EQ(public_key.seed_rho.size(), 32u);
    EXPECT_EQ(public_key.seed_K.size(), 32u);
    EXPECT_EQ(public_key.hash_tr.size(), 64u);
    EXPECT_FALSE(public_key.public_data.empty());
    EXPECT_FALSE(private_key.secret_data.empty());
}

TEST_F(KeyGenTest, GenerateKeypairSecurityLevel65) {
    clwe::ColorSignKeyGen keygen(params65);
    auto [public_key, private_key] = keygen.generate_keypair();

    EXPECT_EQ(public_key.params.security_level, 65u);
    EXPECT_EQ(private_key.params.security_level, 65u);
    EXPECT_EQ(public_key.seed_rho.size(), 32u);
    EXPECT_EQ(public_key.seed_K.size(), 32u);
    EXPECT_EQ(public_key.hash_tr.size(), 64u);
    EXPECT_FALSE(public_key.public_data.empty());
    EXPECT_FALSE(private_key.secret_data.empty());
}

TEST_F(KeyGenTest, GenerateKeypairSecurityLevel87) {
    clwe::ColorSignKeyGen keygen(params87);
    auto [public_key, private_key] = keygen.generate_keypair();

    EXPECT_EQ(public_key.params.security_level, 87u);
    EXPECT_EQ(private_key.params.security_level, 87u);
    EXPECT_EQ(public_key.seed_rho.size(), 32u);
    EXPECT_EQ(public_key.seed_K.size(), 32u);
    EXPECT_EQ(public_key.hash_tr.size(), 64u);
    EXPECT_FALSE(public_key.public_data.empty());
    EXPECT_FALSE(private_key.secret_data.empty());
}

TEST_F(KeyGenTest, GenerateKeypairDeterministic) {
    clwe::ColorSignKeyGen keygen(params44);
    std::array<uint8_t, 32> seed = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                   17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

    auto [public_key1, private_key1] = keygen.generate_keypair_deterministic(seed);
    auto [public_key2, private_key2] = keygen.generate_keypair_deterministic(seed);

    EXPECT_EQ(public_key1.seed_rho, public_key2.seed_rho);
    EXPECT_EQ(public_key1.seed_K, public_key2.seed_K);
    EXPECT_EQ(public_key1.hash_tr, public_key2.hash_tr);
    EXPECT_EQ(public_key1.public_data, public_key2.public_data);
    EXPECT_EQ(private_key1.secret_data, private_key2.secret_data);
}

TEST_F(KeyGenTest, GenerateKeypairDifferentSeeds) {
    clwe::ColorSignKeyGen keygen(params44);
    std::array<uint8_t, 32> seed1 = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::array<uint8_t, 32> seed2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    auto [public_key1, private_key1] = keygen.generate_keypair_deterministic(seed1);
    auto [public_key2, private_key2] = keygen.generate_keypair_deterministic(seed2);

    EXPECT_NE(public_key1.public_data, public_key2.public_data);
    EXPECT_NE(private_key1.secret_data, private_key2.secret_data);
}

TEST_F(KeyGenTest, PublicKeySerializationRoundTrip) {
    clwe::ColorSignKeyGen keygen(params44);
    auto [original_public, original_private] = keygen.generate_keypair();

    auto serialized = original_public.serialize();
    auto deserialized = clwe::ColorSignPublicKey::deserialize(serialized, params44);

    EXPECT_EQ(original_public.seed_rho, deserialized.seed_rho);
    EXPECT_EQ(original_public.public_data, deserialized.public_data);
    EXPECT_EQ(original_public.params.security_level, deserialized.params.security_level);
}

TEST_F(KeyGenTest, PrivateKeySerializationRoundTrip) {
    clwe::ColorSignKeyGen keygen(params44);
    auto [original_public, original_private] = keygen.generate_keypair();

    auto serialized = original_private.serialize();
    auto deserialized = clwe::ColorSignPrivateKey::deserialize(serialized, params44);

    EXPECT_EQ(original_private.secret_data, deserialized.secret_data);
    EXPECT_EQ(original_private.params.security_level, deserialized.params.security_level);
}

TEST_F(KeyGenTest, PublicKeyDeserializeInvalidData) {
    clwe::CLWEParameters params(44);

    // Too small data
    std::vector<uint8_t> small_data = {1, 2, 3};
    EXPECT_THROW(clwe::ColorSignPublicKey::deserialize(small_data, params), std::invalid_argument);

    // Empty data
    std::vector<uint8_t> empty_data;
    EXPECT_THROW(clwe::ColorSignPublicKey::deserialize(empty_data, params), std::invalid_argument);
}

TEST_F(KeyGenTest, KeyGenerationConsistency) {
    // Test that generated keys have correct sizes based on parameters
    clwe::ColorSignKeyGen keygen(params44);
    auto [public_key, private_key] = keygen.generate_keypair();

    // Use computed values from parameters instead of hardcoded magic numbers
    size_t expected_public_size = params44.get_expected_public_data_size();
    size_t expected_private_size = params44.get_expected_private_secret_data_size();
    EXPECT_EQ(public_key.public_data.size(), expected_public_size);
    EXPECT_EQ(private_key.secret_data.size(), expected_private_size);
}

TEST_F(KeyGenTest, KeyGenerationConsistency65) {
    clwe::ColorSignKeyGen keygen(params65);
    auto [public_key, private_key] = keygen.generate_keypair();

    // Use computed values from parameters instead of hardcoded magic numbers
    size_t expected_public_size = params65.get_expected_public_data_size();
    size_t expected_private_size = params65.get_expected_private_secret_data_size();
    EXPECT_EQ(public_key.public_data.size(), expected_public_size);
    EXPECT_EQ(private_key.secret_data.size(), expected_private_size);
}

TEST_F(KeyGenTest, KeyGenerationConsistency87) {
    clwe::ColorSignKeyGen keygen(params87);
    auto [public_key, private_key] = keygen.generate_keypair();

    // Use computed values from parameters instead of hardcoded magic numbers
    size_t expected_public_size = params87.get_expected_public_data_size();
    size_t expected_private_size = params87.get_expected_private_secret_data_size();
    EXPECT_EQ(public_key.public_data.size(), expected_public_size);
    EXPECT_EQ(private_key.secret_data.size(), expected_private_size);
}

TEST_F(KeyGenTest, ErrorMessageUtility) {
    EXPECT_EQ(clwe::get_colorsign_error_message(clwe::ColorSignError::SUCCESS), "Success");
    EXPECT_EQ(clwe::get_colorsign_error_message(clwe::ColorSignError::INVALID_PARAMETERS), "Invalid parameters");
    EXPECT_EQ(clwe::get_colorsign_error_message(clwe::ColorSignError::MALFORMED_KEY), "Malformed key");
    EXPECT_EQ(clwe::get_colorsign_error_message(clwe::ColorSignError::MEMORY_ERROR), "Memory allocation failed");
}

TEST_F(KeyGenTest, MultipleKeyGeneration) {
    clwe::ColorSignKeyGen keygen(params44);

    // Generate multiple keypairs and ensure they're different
    auto [pub1, priv1] = keygen.generate_keypair();
    auto [pub2, priv2] = keygen.generate_keypair();

    EXPECT_NE(pub1.public_data, pub2.public_data);
    EXPECT_NE(priv1.secret_data, priv2.secret_data);
}

} // namespace