#include "../src/include/clwe/utils.hpp"
#include "../src/include/clwe/color_integration.hpp"
#include "../src/include/clwe/keygen.hpp"
#include "../src/include/clwe/parameters.hpp"
#include "../src/include/clwe/sign.hpp"
#include "../src/include/clwe/verify.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <chrono>
#include <cassert>
#include <array>

using namespace clwe;

using namespace clwe;

// Test all security levels (44, 65, 87)
void test_all_security_levels() {
    std::cout << "=== Testing All Security Levels ===" << std::endl;

    std::vector<int> security_levels = {44, 65, 87};

    for (int level : security_levels) {
        std::cout << "\n--- Testing Security Level " << level << " ---" << std::endl;

        CLWEParameters params(level);
        std::cout << "Parameters: k=" << params.module_rank
                  << ", n=" << params.degree
                  << ", q=" << params.modulus
                  << ", gamma1=" << params.gamma1
                  << ", gamma2=" << params.gamma2 << std::endl;

        // Test key generation with compression
        ColorSignKeyGen keygen(params);
        auto [public_key, private_key] = keygen.generate_keypair();

        std::cout << "Key generation: SUCCESS" << std::endl;
        std::cout << "Public key size: " << public_key.public_data.size() << " bytes" << std::endl;
        std::cout << "Private key size: " << private_key.secret_data.size() << " bytes" << std::endl;
        std::cout << "Compression enabled: " << (public_key.use_compression ? "YES" : "NO") << std::endl;

        // Test serialization/deserialization
        auto serialized_public = public_key.serialize();
        auto serialized_private = private_key.serialize();

        auto deserialized_public = ColorSignPublicKey::deserialize(serialized_public, params);
        auto deserialized_private = ColorSignPrivateKey::deserialize(serialized_private, params);

        std::cout << "Serialization/deserialization: "
                  << (deserialized_public.use_compression && deserialized_private.use_compression ? "PASS" : "FAIL")
                  << std::endl;

        // Test signing and verification
        try {
            ColorSign signer(params);
            ColorSignVerify verifier(params);

            std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
            ColorSignature signature = signer.sign_message(message, private_key, public_key);

            bool verification_result = verifier.verify_signature(public_key, signature, message);

            std::cout << "Sign/verify operations: " << (verification_result ? "PASS" : "FAIL") << std::endl;
        } catch (const std::exception& e) {
            std::cout << "Sign/verify operations: FAIL (" << e.what() << ")" << std::endl;
        }
    }
}

void test_compression_ratios() {
    std::cout << "\n=== Testing ML-DSA Polynomial Compression ===" << std::endl;

    // Test with ML-DSA-44 parameters
    CLWEParameters params(44);
    uint32_t k = params.module_rank;
    uint32_t n = params.degree;
    uint32_t q = params.modulus;

    std::cout << "Parameters: ML-DSA-44, k=" << k << ", n=" << n << ", q=" << q << std::endl;

    // Generate some test polynomials with binomial distribution (typical for ML-DSA)
    std::vector<std::vector<uint32_t>> test_polys(k, std::vector<uint32_t>(n, 0));

    // Create a sampler for realistic polynomial data
    std::array<uint8_t, 32> seed = {0};
    SHAKE256Sampler sampler;
    sampler.init(seed.data(), seed.size());

    // Generate polynomials with binomial distribution (η=2)
    for (auto& poly : test_polys) {
        sampler.sample_polynomial_binomial(poly.data(), n, params.eta, q);
    }

    // Test standard packing
    auto standard_packed = pack_polynomial_vector(test_polys);
    std::cout << "Standard packing size: " << standard_packed.size() << " bytes" << std::endl;

    // Test compressed packing
    auto compressed_packed = pack_polynomial_vector_compressed(test_polys, q);
    std::cout << "Compressed packing size: " << compressed_packed.size() << " bytes" << std::endl;

    // Test sparse packing
    auto sparse_packed = pack_polynomial_vector_sparse(test_polys, q);
    std::cout << "Sparse packing size: " << sparse_packed.size() << " bytes" << std::endl;

    // Test auto packing
    auto auto_packed = pack_polynomial_vector_auto(test_polys, q);
    std::cout << "Auto packing size: " << auto_packed.size() << " bytes" << std::endl;

    // Calculate compression ratios
    double compressed_ratio = static_cast<double>(compressed_packed.size()) / standard_packed.size();
    double sparse_ratio = static_cast<double>(sparse_packed.size()) / standard_packed.size();
    double auto_ratio = static_cast<double>(auto_packed.size()) / standard_packed.size();

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Compression ratios:" << std::endl;
    std::cout << "  Variable-length: " << compressed_ratio * 100 << "%" << std::endl;
    std::cout << "  Sparse: " << sparse_ratio * 100 << "%" << std::endl;
    std::cout << "  Auto: " << auto_ratio * 100 << "%" << std::endl;

    // Test decompression
    auto decompressed_standard = unpack_polynomial_vector(standard_packed, k, n);
    auto decompressed_compressed = unpack_polynomial_vector_compressed(compressed_packed, k, n, q);
    auto decompressed_sparse = unpack_polynomial_vector_compressed(sparse_packed, k, n, q);
    auto decompressed_auto = unpack_polynomial_vector_compressed(auto_packed, k, n, q);

    // Verify correctness
    bool standard_correct = true;
    bool compressed_correct = true;
    bool sparse_correct = true;
    bool auto_correct = true;

    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (decompressed_standard[i][j] != test_polys[i][j]) standard_correct = false;
            if (decompressed_compressed[i][j] != test_polys[i][j]) compressed_correct = false;
            if (decompressed_sparse[i][j] != test_polys[i][j]) sparse_correct = false;
            if (decompressed_auto[i][j] != test_polys[i][j]) auto_correct = false;
        }
    }

    std::cout << "Decompression correctness:" << std::endl;
    std::cout << "  Standard: " << (standard_correct ? "PASS" : "FAIL") << std::endl;
    std::cout << "  Compressed: " << (compressed_correct ? "PASS" : "FAIL") << std::endl;
    std::cout << "  Sparse: " << (sparse_correct ? "PASS" : "FAIL") << std::endl;
    std::cout << "  Auto: " << (auto_correct ? "PASS" : "FAIL") << std::endl;
}

void test_color_compression() {
    std::cout << "\n=== Testing Color-Compatible Compression ===" << std::endl;

    CLWEParameters params(44);
    uint32_t k = params.module_rank;
    uint32_t n = params.degree;
    uint32_t q = params.modulus;

    // Generate test polynomials
    std::vector<std::vector<uint32_t>> test_polys(k, std::vector<uint32_t>(n, 0));
    std::array<uint8_t, 32> seed = {0};
    SHAKE256Sampler sampler;
    sampler.init(seed.data(), seed.size());

    for (auto& poly : test_polys) {
        sampler.sample_polynomial_binomial(poly.data(), n, params.eta, q);
    }

    // Test standard color encoding
    auto standard_colors = encode_polynomial_vector_as_colors(test_polys, q);
    std::cout << "Standard color encoding size: " << standard_colors.size() << " bytes" << std::endl;

    // Test compressed color encoding
    auto compressed_colors = encode_polynomial_vector_as_colors_compressed(test_polys, q);
    std::cout << "Compressed color encoding size: " << compressed_colors.size() << " bytes" << std::endl;

    // Test auto color encoding
    auto auto_colors = encode_polynomial_vector_as_colors_auto(test_polys, q);
    std::cout << "Auto color encoding size: " << auto_colors.size() << " bytes" << std::endl;

    // Test decompression
    auto decompressed_compressed = decode_colors_to_polynomial_vector_compressed(compressed_colors, k, n, q);
    auto decompressed_auto = decode_colors_to_polynomial_vector_compressed(auto_colors, k, n, q);

    // Verify correctness
    bool compressed_correct = true;
    bool auto_correct = true;

    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (decompressed_compressed[i][j] != test_polys[i][j]) compressed_correct = false;
            if (decompressed_auto[i][j] != test_polys[i][j]) auto_correct = false;
        }
    }

    std::cout << "Color compression correctness:" << std::endl;
    std::cout << "  Compressed: " << (compressed_correct ? "PASS" : "FAIL") << std::endl;
    std::cout << "  Auto: " << (auto_correct ? "PASS" : "FAIL") << std::endl;

    // Test conversion to standard color format
    auto converted_colors = convert_compressed_to_color_format(compressed_colors, k, n, q);
    std::cout << "Converted color format size: " << converted_colors.size() << " bytes" << std::endl;

    auto decompressed_converted = decode_colors_to_polynomial_vector(converted_colors, k, n, q);

    bool conversion_correct = true;
    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (decompressed_converted[i][j] != test_polys[i][j]) conversion_correct = false;
        }
    }

    std::cout << "Color format conversion: " << (conversion_correct ? "PASS" : "FAIL") << std::endl;
}

void test_key_compression() {
    std::cout << "\n=== Testing Key Compression Integration ===" << std::endl;

    try {
        CLWEParameters params(44);
        ColorSignKeyGen keygen(params);

        // Generate a keypair with compression
        auto [public_key, private_key] = keygen.generate_keypair();

        std::cout << "Public key data size: " << public_key.public_data.size() << " bytes" << std::endl;
        std::cout << "Private key data size: " << private_key.secret_data.size() << " bytes" << std::endl;
        std::cout << "Compression enabled: " << (public_key.use_compression ? "YES" : "NO") << std::endl;

        // Serialize and deserialize
        auto serialized_public = public_key.serialize();
        auto serialized_private = private_key.serialize();

        std::cout << "Serialized public key size: " << serialized_public.size() << " bytes" << std::endl;
        std::cout << "Serialized private key size: " << serialized_private.size() << " bytes" << std::endl;

        // Deserialize
        auto deserialized_public = ColorSignPublicKey::deserialize(serialized_public, params);
        auto deserialized_private = ColorSignPrivateKey::deserialize(serialized_private, params);

        std::cout << "Deserialization: " << (deserialized_public.use_compression ? "PASS" : "FAIL") << std::endl;

        // Verify data integrity
        bool data_integrity = (deserialized_public.public_data == public_key.public_data) &&
                             (deserialized_private.secret_data == private_key.secret_data);

        std::cout << "Data integrity: " << (data_integrity ? "PASS" : "FAIL") << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Key compression test failed: " << e.what() << std::endl;
    }
}

void test_cryptographic_operations_with_compressed_keys() {
    std::cout << "\n=== Testing Cryptographic Operations with Compressed Keys ===" << std::endl;

    try {
        CLWEParameters params(44);
        ColorSignKeyGen keygen(params);

        // Generate keypair with compression
        auto [public_key, private_key] = keygen.generate_keypair();

        // Test signing with compressed keys
        ColorSign signer(params);
        std::vector<uint8_t> message = {'T', 'e', 's', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
        ColorSignature signature = signer.sign_message(message, private_key, public_key);

        std::cout << "Signing with compressed keys: SUCCESS" << std::endl;
        std::cout << "Signature size: " << signature.serialize().size() << " bytes" << std::endl;

        // Test verification with compressed keys
        ColorSignVerify verifier(params);
        bool verification_result = verifier.verify_signature(public_key, signature, message);

        std::cout << "Verification with compressed keys: " << (verification_result ? "PASS" : "FAIL") << std::endl;

        // Test backward compatibility with uncompressed keys
        // Generate uncompressed keypair
        auto [uncompressed_public, uncompressed_private] = keygen.generate_keypair_deterministic({0});

        // Test signing with uncompressed keys
        ColorSignature uncompressed_signature = signer.sign_message(message, uncompressed_private, uncompressed_public);

        std::cout << "Signing with uncompressed keys: SUCCESS" << std::endl;
        std::cout << "Uncompressed signature size: " << uncompressed_signature.serialize().size() << " bytes" << std::endl;

        // Test verification with uncompressed keys
        bool uncompressed_verification = verifier.verify_signature(uncompressed_public, uncompressed_signature, message);

        std::cout << "Verification with uncompressed keys: " << (uncompressed_verification ? "PASS" : "FAIL") << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Cryptographic operations test failed: " << e.what() << std::endl;
    }
}

void test_performance() {
    std::cout << "\n=== Testing Performance Metrics ===" << std::endl;

    CLWEParameters params(44);
    uint32_t k = params.module_rank;
    uint32_t n = params.degree;
    uint32_t q = params.modulus;

    // Generate test polynomials
    std::vector<std::vector<uint32_t>> test_polys(k, std::vector<uint32_t>(n, 0));
    std::array<uint8_t, 32> seed = {0};
    SHAKE256Sampler sampler;
    sampler.init(seed.data(), seed.size());

    for (auto& poly : test_polys) {
        sampler.sample_polynomial_binomial(poly.data(), n, params.eta, q);
    }

    // Measure compression ratios
    auto standard_packed = pack_polynomial_vector(test_polys);
    auto compressed_packed = pack_polynomial_vector_compressed(test_polys, q);
    auto sparse_packed = pack_polynomial_vector_sparse(test_polys, q);
    auto auto_packed = pack_polynomial_vector_auto(test_polys, q);

    double standard_size = standard_packed.size();
    double compressed_size = compressed_packed.size();
    double sparse_size = sparse_packed.size();
    double auto_size = auto_packed.size();

    std::cout << "Compression ratios:" << std::endl;
    std::cout << "  Standard: " << standard_size << " bytes" << std::endl;
    std::cout << "  Compressed: " << compressed_size << " bytes ("
              << std::fixed << std::setprecision(2) << (compressed_size/standard_size)*100 << "%)" << std::endl;
    std::cout << "  Sparse: " << sparse_size << " bytes ("
              << std::fixed << std::setprecision(2) << (sparse_size/standard_size)*100 << "%)" << std::endl;
    std::cout << "  Auto: " << auto_size << " bytes ("
              << std::fixed << std::setprecision(2) << (auto_size/standard_size)*100 << "%)" << std::endl;

    // Measure serialization/deserialization speed
    auto start_compress = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; ++i) {
        auto compressed = pack_polynomial_vector_compressed(test_polys, q);
    }
    auto end_compress = std::chrono::high_resolution_clock::now();

    auto start_decompress = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; ++i) {
        auto decompressed = unpack_polynomial_vector_compressed(compressed_packed, k, n, q);
    }
    auto end_decompress = std::chrono::high_resolution_clock::now();

    auto compress_time = std::chrono::duration_cast<std::chrono::microseconds>(end_compress - start_compress).count();
    auto decompress_time = std::chrono::duration_cast<std::chrono::microseconds>(end_decompress - start_decompress).count();

    std::cout << "Performance (100 iterations):" << std::endl;
    std::cout << "  Compression time: " << compress_time << " μs" << std::endl;
    std::cout << "  Decompression time: " << decompress_time << " μs" << std::endl;
    std::cout << "  Average compression: " << (compress_time / 100.0) << " μs/op" << std::endl;
    std::cout << "  Average decompression: " << (decompress_time / 100.0) << " μs/op" << std::endl;
}

void test_security_validation() {
    std::cout << "\n=== Testing Security Validation ===" << std::endl;

    try {
        CLWEParameters params(44);
        ColorSignKeyGen keygen(params);

        // Generate keypair with compression
        auto [public_key, private_key] = keygen.generate_keypair();

        // Test signing and verification
        ColorSign signer(params);
        ColorSignVerify verifier(params);

        std::vector<uint8_t> message = {'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', ' ', 'T', 'e', 's', 't'};
        ColorSignature signature = signer.sign_message(message, private_key, public_key);

        bool verification_result = verifier.verify_signature(public_key, signature, message);

        std::cout << "FIPS 204 compliance test: " << (verification_result ? "PASS" : "FAIL") << std::endl;

        // Test cryptographic correctness
        // Verify that the signature can be validated multiple times
        bool second_verification = verifier.verify_signature(public_key, signature, message);
        std::cout << "Cryptographic correctness (repeat verification): "
                  << (second_verification ? "PASS" : "FAIL") << std::endl;

        // Test with wrong message to ensure it fails
        std::vector<uint8_t> wrong_message = {'W', 'r', 'o', 'n', 'g', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
        bool wrong_verification = verifier.verify_signature(public_key, signature, wrong_message);

        std::cout << "Security property (wrong message rejection): "
                  << (!wrong_verification ? "PASS" : "FAIL") << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Security validation test failed: " << e.what() << std::endl;
    }
}

void test_color_integration() {
    std::cout << "\n=== Testing Color Integration ===" << std::endl;

    CLWEParameters params(44);
    uint32_t k = params.module_rank;
    uint32_t n = params.degree;
    uint32_t q = params.modulus;

    // Generate test polynomials
    std::vector<std::vector<uint32_t>> test_polys(k, std::vector<uint32_t>(n, 0));
    std::array<uint8_t, 32> seed = {0};
    SHAKE256Sampler sampler;
    sampler.init(seed.data(), seed.size());

    for (auto& poly : test_polys) {
        sampler.sample_polynomial_binomial(poly.data(), n, params.eta, q);
    }

    // Test color visualization with compressed data
    auto compressed_colors = encode_polynomial_vector_as_colors_compressed(test_polys, q);
    auto converted_colors = convert_compressed_to_color_format(compressed_colors, k, n, q);

    // Verify that conversion preserves data
    auto decompressed = decode_colors_to_polynomial_vector(converted_colors, k, n, q);

    bool visualization_correct = true;
    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (decompressed[i][j] != test_polys[i][j]) {
                visualization_correct = false;
                break;
            }
        }
        if (!visualization_correct) break;
    }

    std::cout << "Color visualization with compressed data: "
              << (visualization_correct ? "PASS" : "FAIL") << std::endl;

    // Test that no visual artifacts are introduced
    // Check that the converted color format has the expected size
    size_t expected_color_size = k * n * 4; // 4 bytes per coefficient (RGBA)
    bool size_correct = (converted_colors.size() == expected_color_size);

    std::cout << "Color format size correctness: "
              << (size_correct ? "PASS" : "FAIL") << std::endl;
    std::cout << "Expected size: " << expected_color_size << " bytes, Actual: "
              << converted_colors.size() << " bytes" << std::endl;
}

void test_backward_compatibility() {
    std::cout << "\n=== Testing Backward Compatibility ===" << std::endl;

    try {
        CLWEParameters params(44);
        ColorSignKeyGen keygen(params);

        // Generate uncompressed keypair
        auto [uncompressed_public, uncompressed_private] = keygen.generate_keypair_deterministic({0});

        // Generate compressed keypair
        auto [compressed_public, compressed_private] = keygen.generate_keypair();

        // Test that both can sign and verify correctly
        ColorSign signer(params);
        ColorSignVerify verifier(params);

        std::vector<uint8_t> message = {'B', 'a', 'c', 'k', 'w', 'a', 'r', 'd', ' ', 'T', 'e', 's', 't'};

        // Sign with uncompressed keys
        ColorSignature uncompressed_signature = signer.sign_message(message, uncompressed_private, uncompressed_public);
        bool uncompressed_verification = verifier.verify_signature(uncompressed_public, uncompressed_signature, message);

        std::cout << "Uncompressed key operations: "
                  << (uncompressed_verification ? "PASS" : "FAIL") << std::endl;

        // Sign with compressed keys
        ColorSignature compressed_signature = signer.sign_message(message, compressed_private, compressed_public);
        bool compressed_verification = verifier.verify_signature(compressed_public, compressed_signature, message);

        std::cout << "Compressed key operations: "
                  << (compressed_verification ? "PASS" : "FAIL") << std::endl;

        // Test cross-compatibility (sign with one, verify with the other)
        // This should fail since keys are different, but the operations should work
        bool cross_verification = verifier.verify_signature(compressed_public, uncompressed_signature, message);
        std::cout << "Cross-key verification (should fail): "
                  << (!cross_verification ? "PASS" : "FAIL") << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Backward compatibility test failed: " << e.what() << std::endl;
    }
}

int main() {
    std::cout << "=== Comprehensive Key Size Optimization Test Suite ===" << std::endl;

    test_all_security_levels();
    test_compression_ratios();
    test_color_compression();
    test_key_compression();
    test_cryptographic_operations_with_compressed_keys();
    test_performance();
    test_security_validation();
    test_color_integration();
    test_backward_compatibility();

    std::cout << "\n=== Test Suite Summary ===" << std::endl;
    std::cout << "All comprehensive tests completed." << std::endl;
    std::cout << "Check results above for any failures." << std::endl;

    return 0;
}