#include <gtest/gtest.h>
#include "verify.hpp"
#include "sign.hpp"
#include "keygen.hpp"
#include <stdexcept>

namespace {

// Test fixture for verify
class VerifyTest : public ::testing::Test {
protected:
    void SetUp() override {
        params = clwe::CLWEParameters(44);
        keygen = std::make_unique<clwe::ColorSignKeyGen>(params);
        auto [pub, priv] = keygen->generate_keypair();
        public_key = pub;
        private_key = priv;
        signer = std::make_unique<clwe::ColorSign>(params);
        verifier = std::make_unique<clwe::ColorSignVerify>(params);
    }

    clwe::CLWEParameters params;
    std::unique_ptr<clwe::ColorSignKeyGen> keygen;
    clwe::ColorSignPublicKey public_key;
    clwe::ColorSignPrivateKey private_key;
    std::unique_ptr<clwe::ColorSign> signer;
    std::unique_ptr<clwe::ColorSignVerify> verifier;
};

TEST_F(VerifyTest, ConstructorValidParameters) {
    EXPECT_NO_THROW(clwe::ColorSignVerify verifier(params));
}

TEST_F(VerifyTest, ConstructorInvalidParameters) {
    EXPECT_THROW({
        clwe::CLWEParameters invalid_params(44, 0, 2, 4, 3329, 2, 39, 78, 1 << 17, (3329 - 1) / 88, 80, 128);
        clwe::ColorSignVerify verifier(invalid_params);
    }, std::invalid_argument);
}

TEST_F(VerifyTest, VerifyValidSignature) {
    std::vector<uint8_t> message = {'V', 'a', 'l', 'i', 'd', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};

    clwe::ColorSignature signature = signer->sign_message(message, private_key, public_key);

    EXPECT_TRUE(verifier->verify_signature(public_key, signature, message));
}

TEST_F(VerifyTest, VerifyTamperedSignature) {
    std::vector<uint8_t> message = {'t', 'e', 's', 't'};

    clwe::ColorSignature signature = signer->sign_message(message, private_key, public_key);

    // Tamper with signature
    if (!signature.c_data.empty()) {
        signature.c_data[0] ^= 0xFF;
    }

    EXPECT_FALSE(verifier->verify_signature(public_key, signature, message));
}

TEST_F(VerifyTest, VerifyWrongMessage) {
    std::vector<uint8_t> message1 = {'m', 'e', 's', 's', 'a', 'g', 'e', '1'};
    std::vector<uint8_t> message2 = {'m', 'e', 's', 's', 'a', 'g', 'e', '2'};

    clwe::ColorSignature signature = signer->sign_message(message1, private_key, public_key);

    EXPECT_FALSE(verifier->verify_signature(public_key, signature, message2));
}

TEST_F(VerifyTest, VerifyWithWrongPublicKey) {
    std::vector<uint8_t> message = {'w', 'r', 'o', 'n', 'g', ' ', 'k', 'e', 'y'};

    clwe::ColorSignature signature = signer->sign_message(message, private_key, public_key);

    // Generate different key
    auto [wrong_pub, wrong_priv] = keygen->generate_keypair();

    EXPECT_FALSE(verifier->verify_signature(wrong_pub, signature, message));
}

TEST_F(VerifyTest, VerifyEmptyMessage) {
    std::vector<uint8_t> empty_message;
    std::vector<uint8_t> empty_c((params.degree + 3) / 4, 0);
    clwe::ColorSignature dummy_signature{{}, {}, empty_c, params};

    EXPECT_THROW(verifier->verify_signature(public_key, dummy_signature, empty_message), std::invalid_argument);
}

TEST_F(VerifyTest, VerifyInvalidPublicKey) {
    std::vector<uint8_t> message = {'i', 'n', 'v', 'a', 'l', 'i', 'd'};
    clwe::ColorSignPublicKey invalid_public_key{{0}, {}, {}, {}, params};
    std::vector<uint8_t> empty_c((params.degree + 3) / 4, 0);
    clwe::ColorSignature dummy_signature{{}, {}, empty_c, params};

    EXPECT_THROW(verifier->verify_signature(invalid_public_key, dummy_signature, message), std::invalid_argument);
}

TEST_F(VerifyTest, VerifyInvalidSignature) {
    std::vector<uint8_t> message = {'i', 'n', 'v', 'a', 'l', 'i', 'd'};
    clwe::ColorSignature invalid_signature{{}, {}, {1, 2, 3}, params};  // c_data too short

    EXPECT_THROW(verifier->verify_signature(public_key, invalid_signature, message), std::invalid_argument);
}

TEST_F(VerifyTest, VerifyLargeMessage) {
    std::vector<uint8_t> large_message(1000, 'X');

    clwe::ColorSignature signature = signer->sign_message(large_message, private_key, public_key);

    EXPECT_TRUE(verifier->verify_signature(public_key, signature, large_message));
}

TEST_F(VerifyTest, VerifyMessageTooLarge) {
    std::vector<uint8_t> too_large_message(1024 * 1024 + 1, 'X');
    std::vector<uint8_t> empty_c((params.degree + 3) / 4, 0);
    clwe::ColorSignature dummy_signature{{}, {}, empty_c, params};

    EXPECT_THROW(verifier->verify_signature(public_key, dummy_signature, too_large_message), std::invalid_argument);
}

TEST_F(VerifyTest, VerifyWithDifferentSecurityLevels) {
    std::vector<uint8_t> message = {'s', 'e', 'c', 'u', 'r', 'i', 't', 'y'};

    std::vector<uint32_t> levels = {44, 65, 87};
    for (uint32_t level : levels) {
        clwe::CLWEParameters test_params(level);
        clwe::ColorSignKeyGen test_keygen(test_params);
        auto [test_pub, test_priv] = test_keygen.generate_keypair();
        clwe::ColorSign test_signer(test_params);
        clwe::ColorSignVerify test_verifier(test_params);

        clwe::ColorSignature signature = test_signer.sign_message(message, test_priv, test_pub);

        EXPECT_TRUE(test_verifier.verify_signature(test_pub, signature, message));
    }
}

TEST_F(VerifyTest, VerifySignatureTamperedZ) {
    std::vector<uint8_t> message = {'t', 'a', 'm', 'p', 'e', 'r', 'e', 'd'};

    clwe::ColorSignature signature = signer->sign_message(message, private_key, public_key);

    // Tamper with z_data
    if (!signature.z_data.empty()) {
        signature.z_data[0] ^= 0xFF;
    }

    EXPECT_FALSE(verifier->verify_signature(public_key, signature, message));
}

TEST_F(VerifyTest, VerifySignatureTamperedCHash) {
    std::vector<uint8_t> message = {'t', 'a', 'm', 'p', 'e', 'r', 'e', 'd'};

    clwe::ColorSignature signature = signer->sign_message(message, private_key, public_key);

    // Tamper with c_data
    if (signature.c_data.size() >= 16) {
        signature.c_data[15] ^= 0xFF;
    }

    EXPECT_FALSE(verifier->verify_signature(public_key, signature, message));
}

TEST_F(VerifyTest, ErrorMessageUtility) {
    EXPECT_EQ(clwe::get_colorsign_verify_error_message(clwe::ColorSignVerifyError::SUCCESS), "Success");
    EXPECT_EQ(clwe::get_colorsign_verify_error_message(clwe::ColorSignVerifyError::INVALID_PARAMETERS), "Invalid parameters");
    EXPECT_EQ(clwe::get_colorsign_verify_error_message(clwe::ColorSignVerifyError::INVALID_PUBLIC_KEY), "Invalid public key");
    EXPECT_EQ(clwe::get_colorsign_verify_error_message(clwe::ColorSignVerifyError::INVALID_SIGNATURE), "Invalid signature");
    EXPECT_EQ(clwe::get_colorsign_verify_error_message(clwe::ColorSignVerifyError::VERIFICATION_FAILED), "Verification failed");
    EXPECT_EQ(clwe::get_colorsign_verify_error_message(clwe::ColorSignVerifyError::MALFORMED_SIGNATURE), "Malformed signature");
    EXPECT_EQ(clwe::get_colorsign_verify_error_message(clwe::ColorSignVerifyError::Z_OUT_OF_BOUNDS), "Signature z values out of bounds");
}

TEST_F(VerifyTest, MultipleSignaturesVerification) {
    std::vector<uint8_t> message1 = {'f', 'i', 'r', 's', 't'};
    std::vector<uint8_t> message2 = {'s', 'e', 'c', 'o', 'n', 'd'};

    clwe::ColorSignature sig1 = signer->sign_message(message1, private_key, public_key);
    clwe::ColorSignature sig2 = signer->sign_message(message2, private_key, public_key);

    EXPECT_TRUE(verifier->verify_signature(public_key, sig1, message1));
    EXPECT_TRUE(verifier->verify_signature(public_key, sig2, message2));

    // Cross verification should fail
    EXPECT_FALSE(verifier->verify_signature(public_key, sig1, message2));
    EXPECT_FALSE(verifier->verify_signature(public_key, sig2, message1));
}

TEST_F(VerifyTest, VerifyDeterministicKeys) {
    std::array<uint8_t, 32> seed = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                   17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

    clwe::ColorSignKeyGen det_keygen(params);
    auto [det_pub, det_priv] = det_keygen.generate_keypair_deterministic(seed);

    clwe::ColorSign det_signer(params);
    clwe::ColorSignVerify det_verifier(params);

    std::vector<uint8_t> message = {'d', 'e', 't', 'e', 'r', 'm', 'i', 'n', 'i', 's', 't', 'i', 'c'};

    clwe::ColorSignature signature = det_signer.sign_message(message, det_priv, det_pub);

    EXPECT_TRUE(det_verifier.verify_signature(det_pub, signature, message));
}

} // namespace