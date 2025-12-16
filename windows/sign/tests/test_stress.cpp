#include <gtest/gtest.h>
#include "keygen.hpp"
#include "sign.hpp"
#include "verify.hpp"
#include "color_integration.hpp"
#include "parameters.hpp"
#include "utils.hpp"
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <random>
#include <limits>

namespace {

// Test fixture for stress tests
class StressTest : public ::testing::Test {
protected:
    void SetUp() override {
        params44 = clwe::CLWEParameters(44);
        params65 = clwe::CLWEParameters(65);
        params87 = clwe::CLWEParameters(87);
    }

    clwe::CLWEParameters params44, params65, params87;
};

// Edge cases and invalid inputs for key generation
TEST_F(StressTest, KeyGenEdgeCases) {
    // Test with maximum possible seed values
    std::array<uint8_t, 32> max_seed;
    std::fill(max_seed.begin(), max_seed.end(), 0xFF);

    clwe::ColorSignKeyGen keygen(params44);
    auto [pub_max, priv_max] = keygen.generate_keypair_deterministic(max_seed);
    EXPECT_FALSE(pub_max.public_data.empty());
    EXPECT_FALSE(priv_max.secret_data.empty());

    // Test with minimum seed values (all zeros)
    std::array<uint8_t, 32> min_seed = {0};
    auto [pub_min, priv_min] = keygen.generate_keypair_deterministic(min_seed);
    EXPECT_FALSE(pub_min.public_data.empty());
    EXPECT_FALSE(priv_min.secret_data.empty());
}

// Bounds checking for parameters
TEST_F(StressTest, ParameterBoundsChecking) {
    // Test modulus bounds
    EXPECT_THROW(clwe::CLWEParameters(44, 256, 4, 4, 0, 2, 39, 78, 1 << 17, (1 - 1) / 88, 80, 128), std::invalid_argument); // modulus = 0
    EXPECT_THROW(clwe::CLWEParameters(44, 256, 4, 4, 1, 2, 39, 78, 1 << 17, (1 - 1) / 88, 80, 128), std::invalid_argument); // modulus = 1

    // Test degree bounds
    EXPECT_THROW(clwe::CLWEParameters(44, 0, 4, 4, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 128), std::invalid_argument); // degree = 0

    // Test module_rank bounds
    EXPECT_THROW(clwe::CLWEParameters(44, 256, 0, 4, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 128), std::invalid_argument); // module_rank = 0

    // Test repetitions bounds
    EXPECT_THROW(clwe::CLWEParameters(44, 256, 4, 0, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 128), std::invalid_argument); // repetitions = 0

    // Test eta bounds
    EXPECT_THROW(clwe::CLWEParameters(44, 256, 4, 4, 8380417, 0, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 128), std::invalid_argument); // eta = 0

    // Test tau bounds
    EXPECT_THROW(clwe::CLWEParameters(44, 256, 4, 4, 8380417, 2, 0, 78, 1 << 17, (8380417 - 1) / 88, 80, 128), std::invalid_argument); // tau = 0

    // Test beta bounds
    EXPECT_THROW(clwe::CLWEParameters(44, 256, 4, 4, 8380417, 2, 39, 0, 1 << 17, (8380417 - 1) / 88, 80, 128), std::invalid_argument); // beta = 0

    // Test gamma1 bounds
    EXPECT_THROW(clwe::CLWEParameters(44, 256, 4, 4, 8380417, 2, 39, 78, 0, (8380417 - 1) / 88, 80, 128), std::invalid_argument); // gamma1 = 0

    // Test omega bounds
    EXPECT_THROW(clwe::CLWEParameters(44, 256, 4, 4, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 0, 128), std::invalid_argument); // omega = 0

    // Test lambda bounds
    EXPECT_THROW(clwe::CLWEParameters(44, 256, 4, 4, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 0), std::invalid_argument); // lambda = 0
}

// Large key generation stress test
TEST_F(StressTest, LargeKeyGenerationStressTest) {
    // Test generating many keys rapidly
    for (int i = 0; i < 100; ++i) {
        clwe::ColorSignKeyGen keygen(params44);
        auto [public_key, private_key] = keygen.generate_keypair();

        EXPECT_FALSE(public_key.public_data.empty());
        EXPECT_FALSE(private_key.secret_data.empty());
        EXPECT_EQ(public_key.params.security_level, 44u);
        EXPECT_EQ(private_key.params.security_level, 44u);
    }
}

// High iteration key generation stress test
TEST_F(StressTest, HighIterationKeyGenerationStressTest) {
    // Test key generation with different seeds
    for (int i = 0; i < 100; ++i) {
        std::array<uint8_t, 32> seed;
        for (size_t j = 0; j < seed.size(); ++j) {
            seed[j] = static_cast<uint8_t>((i + j) % 256);
        }

        clwe::ColorSignKeyGen keygen(params44);
        auto [public_key, private_key] = keygen.generate_keypair_deterministic(seed);

        EXPECT_FALSE(public_key.public_data.empty());
        EXPECT_FALSE(private_key.secret_data.empty());
        EXPECT_EQ(public_key.seed_rho.size(), 32u);
        EXPECT_EQ(public_key.seed_K.size(), 32u);
    }
}

// Concurrent key generation stress test
TEST_F(StressTest, ConcurrentKeyGenerationStressTest) {
    const int num_threads = 4;
    const int keys_per_thread = 25;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    std::mutex mutex;

    auto thread_func = [&](int thread_id) {
        try {
            for (int i = 0; i < keys_per_thread; ++i) {
                clwe::ColorSignKeyGen keygen(params44);
                auto [public_key, private_key] = keygen.generate_keypair();

                if (!public_key.public_data.empty() && !private_key.secret_data.empty()) {
                    success_count++;
                }
            }
        } catch (...) {
            // Thread failed
        }
    };

    // Launch threads
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(thread_func, i);
    }

    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }

    EXPECT_EQ(success_count, num_threads * keys_per_thread);
}

// Fuzzing-like randomized seed test
TEST_F(StressTest, RandomizedSeedFuzzTest) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> byte_dist(0, 255);

    // Test 50 random seeds
    for (int i = 0; i < 50; ++i) {
        std::array<uint8_t, 32> seed;
        for (size_t j = 0; j < seed.size(); ++j) {
            seed[j] = static_cast<uint8_t>(byte_dist(gen));
        }

        clwe::ColorSignKeyGen keygen(params44);
        auto [public_key, private_key] = keygen.generate_keypair_deterministic(seed);

        EXPECT_FALSE(public_key.public_data.empty());
        EXPECT_FALSE(private_key.secret_data.empty());
        EXPECT_EQ(public_key.seed_rho.size(), 32u);
        EXPECT_EQ(public_key.seed_K.size(), 32u);
        EXPECT_EQ(public_key.hash_tr.size(), 64u);
    }
}

// Memory stress test with large polynomial operations
TEST_F(StressTest, MemoryStressPolynomialOperations) {
    // Test color encoding/decoding with maximum size polynomials
    uint32_t modulus = 8380417;
    size_t max_poly_size = 8192; // Much larger than typical

    std::vector<uint32_t> large_poly(max_poly_size);
    for (size_t i = 0; i < max_poly_size; ++i) {
        large_poly[i] = i % modulus;
    }

    EXPECT_NO_THROW({
        auto encoded = clwe::encode_polynomial_as_colors(large_poly, modulus);
        auto decoded = clwe::decode_colors_to_polynomial(encoded, modulus);

        // Verify round-trip correctness (8-bit truncation)
        ASSERT_EQ(large_poly.size(), decoded.size());
        for (size_t i = 0; i < large_poly.size(); ++i) {
            EXPECT_EQ((large_poly[i] % modulus) & 0xFF, decoded[i]);
        }
    });
}

// Key generation performance regression test
TEST_F(StressTest, KeyGenerationPerformanceRegressionTest) {
    // Measure baseline performance for key generation
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 10; ++i) {
        clwe::ColorSignKeyGen keygen(params44);
        auto [public_key, private_key] = keygen.generate_keypair();
        EXPECT_FALSE(public_key.public_data.empty());
        EXPECT_FALSE(private_key.secret_data.empty());
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete 10 key generations in less than 1 second (reasonable baseline)
    EXPECT_LT(duration.count(), 1000);
}

// Parameter validation stress test
TEST_F(StressTest, ParameterValidationStressTest) {
    // Test various invalid parameter combinations
    std::vector<std::tuple<uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t>> invalid_params = {
        {0, 256, 4, 4, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 128}, // degree = 0
        {44, 0, 4, 4, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 128}, // degree = 0
        {44, 256, 0, 4, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 128}, // module_rank = 0
        {44, 256, 4, 0, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 128}, // repetitions = 0
        {44, 256, 4, 4, 0, 2, 39, 78, 1 << 17, (1 - 1) / 88, 80, 128}, // modulus = 0
        {44, 256, 4, 4, 8380417, 0, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 128}, // eta = 0
        {44, 256, 4, 4, 8380417, 2, 0, 78, 1 << 17, (8380417 - 1) / 88, 80, 128}, // tau = 0
        {44, 256, 4, 4, 8380417, 2, 39, 0, 1 << 17, (8380417 - 1) / 88, 80, 128}, // beta = 0
        {44, 256, 4, 4, 8380417, 2, 39, 78, 0, (8380417 - 1) / 88, 80, 128}, // gamma1 = 0
        {44, 256, 4, 4, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 0, 128}, // omega = 0
        {44, 256, 4, 4, 8380417, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 0}, // lambda = 0
    };

    for (const auto& [sec, deg, rank, rep, mod, eta, tau, beta, gamma1, gamma2, omega, lambda] : invalid_params) {
        EXPECT_THROW(clwe::CLWEParameters(sec, deg, rank, rep, mod, eta, tau, beta, gamma1, gamma2, omega, lambda), std::invalid_argument);
    }
}

// Key serialization stress test
TEST_F(StressTest, KeySerializationStressTest) {
    // Test serialization/deserialization with many different keys
    for (int i = 0; i < 50; ++i) {
        clwe::ColorSignKeyGen keygen(params44);
        auto [original_public, original_private] = keygen.generate_keypair();

        // Serialize and deserialize public key
        auto serialized_public = original_public.serialize();
        auto deserialized_public = clwe::ColorSignPublicKey::deserialize(serialized_public, params44);

        EXPECT_EQ(original_public.seed_rho, deserialized_public.seed_rho);
        EXPECT_EQ(original_public.seed_K, deserialized_public.seed_K);
        EXPECT_EQ(original_public.hash_tr, deserialized_public.hash_tr);
        EXPECT_EQ(original_public.public_data, deserialized_public.public_data);

        // Serialize and deserialize private key
        auto serialized_private = original_private.serialize();
        auto deserialized_private = clwe::ColorSignPrivateKey::deserialize(serialized_private, params44);

        EXPECT_EQ(original_private.secret_data, deserialized_private.secret_data);
        EXPECT_EQ(original_private.params.security_level, deserialized_private.params.security_level);
    }
}

// Boundary condition test for signature serialization
TEST_F(StressTest, SignatureSerializationBoundaryTest) {
    clwe::ColorSignKeyGen keygen(params44);
    auto [public_key, private_key] = keygen.generate_keypair();

    clwe::ColorSign signer(params44);
    std::vector<uint8_t> message = {'B', 'o', 'u', 'n', 'd', 'a', 'r', 'y'};

    clwe::ColorSignature signature = signer.sign_message(message, private_key, public_key);

    // Test serialization/deserialization
    auto serialized = signature.serialize();
    auto deserialized = clwe::ColorSignature::deserialize(serialized, params44);

    EXPECT_EQ(signature.z_data, deserialized.z_data);
    EXPECT_EQ(signature.h_data, deserialized.h_data);
    EXPECT_EQ(signature.c_data, deserialized.c_data);

    // Test with invalid deserialization data
    std::vector<uint8_t> invalid_data = {1, 2, 3};
    EXPECT_THROW(clwe::ColorSignature::deserialize(invalid_data, params44), std::invalid_argument);
}

} // namespace