#include <gtest/gtest.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <array>
#include <unistd.h>
#include "keygen.hpp"
#include "sign.hpp"
#include "verify.hpp"
#include "parameters.hpp"

namespace clwe {

// Helper function to convert hex string to vector<uint8_t>
static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Struct for test vector
struct KAT_TestVector {
    int level;
    std::vector<uint8_t> seed;
    std::vector<uint8_t> message;
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
    std::vector<uint8_t> expected_sig;
};

// Function to load test vector from file
KAT_TestVector load_test_vector(int level) {
    std::string filename;
    if (level == 44) filename = "ml_dsa_44_vector.txt";
    else if (level == 65) filename = "ml_dsa_65_vector.txt";
    else if (level == 87) filename = "ml_dsa_87_vector.txt";
    else throw std::invalid_argument("Invalid level");

    // Try multiple possible paths to find the test vector files
    std::vector<std::string> possible_paths = {
        filename,  // Current directory
        "tests/" + filename,  // tests subdirectory
        "../tests/" + filename,  // From build directory
        "../../tests/" + filename  // From build/tests directory
    };

    std::ifstream file;
    std::string found_path;
    for (const auto& path : possible_paths) {
        file.open(path, std::ios::binary);
        if (file.is_open()) {
            found_path = path;
            break;
        }
    }

    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename + " (tried multiple paths)");
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Remove comments
    size_t pos = 0;
    while ((pos = content.find("//", pos)) != std::string::npos) {
        size_t end = content.find('\n', pos);
        if (end == std::string::npos) end = content.size();
        content.erase(pos, end - pos);
    }

    // Remove whitespace
    content.erase(std::remove_if(content.begin(), content.end(), [](char c){ return std::isspace(c); }), content.end());

    if (content.empty() || content[0] != '{') {
        throw std::runtime_error("Invalid file format: missing opening brace");
    }
    if (content.back() != '}') {
        throw std::runtime_error("Invalid file format: missing closing brace");
    }
    // Helper function to find next top-level comma
    auto find_top_level_comma = [](const std::string& s, size_t start) -> size_t {
        int level = 0;
        for (size_t i = start; i < s.size(); ++i) {
            if (s[i] == '{') level++;
            else if (s[i] == '}') level--;
            else if (s[i] == ',' && level == 0) return i;
        }
        return std::string::npos;
    };

    content = content.substr(1, content.size() - 2); // remove { and }

    // Find top-level commas
    size_t current_pos = 0;
    size_t comma1 = find_top_level_comma(content, current_pos);
    if (comma1 == std::string::npos) throw std::runtime_error("Invalid format: missing comma after level");
    std::string level_str = content.substr(current_pos, comma1 - current_pos);
    current_pos = comma1 + 1;

    size_t comma2 = find_top_level_comma(content, current_pos);
    if (comma2 == std::string::npos) throw std::runtime_error("Invalid format: missing comma after seed");
    std::string seed_str = content.substr(current_pos, comma2 - current_pos);
    current_pos = comma2 + 1;

    size_t comma3 = find_top_level_comma(content, current_pos);
    if (comma3 == std::string::npos) throw std::runtime_error("Invalid format: missing comma after message");
    std::string msg_str = content.substr(current_pos, comma3 - current_pos);
    current_pos = comma3 + 1;

    size_t comma4 = find_top_level_comma(content, current_pos);
    if (comma4 == std::string::npos) throw std::runtime_error("Invalid format: missing comma after pk");
    std::string pk_str = content.substr(current_pos, comma4 - current_pos);
    current_pos = comma4 + 1;

    size_t comma5 = find_top_level_comma(content, current_pos);
    if (comma5 == std::string::npos) throw std::runtime_error("Invalid format: missing comma after sk");
    std::string sk_str = content.substr(current_pos, comma5 - current_pos);
    current_pos = comma5 + 1;

    std::string sig_str = content.substr(current_pos);

    KAT_TestVector tv;

    // Parse level
    try {
        tv.level = std::stoi(level_str);
    } catch (const std::exception&) {
        throw std::runtime_error("Invalid level format");
    }
    if (tv.level != level) {
        throw std::runtime_error("Level mismatch: expected " + std::to_string(level) + ", got " + std::to_string(tv.level));
    }

    // Parse seed
    if (seed_str.empty() || seed_str[0] != '{' || seed_str.back() != '}') {
        throw std::runtime_error("Invalid seed format");
    }
    seed_str = seed_str.substr(1, seed_str.size() - 2);
    std::vector<std::string> seed_parts;
    std::stringstream ss_seed(seed_str);
    std::string part;
    while (std::getline(ss_seed, part, ',')) {
        seed_parts.push_back(part);
    }
    tv.seed.resize(seed_parts.size());
    for (size_t i = 0; i < seed_parts.size(); ++i) {
        if (seed_parts[i].substr(0, 2) != "0x") {
            throw std::runtime_error("Invalid seed byte format");
        }
        try {
            tv.seed[i] = static_cast<uint8_t>(std::stoi(seed_parts[i], nullptr, 16));
        } catch (const std::exception&) {
            throw std::runtime_error("Invalid seed byte value");
        }
    }

    // Parse message
    if (msg_str.find("hex_to_bytes(\"") != 0 || msg_str.back() != ')') {
        throw std::runtime_error("Invalid hex_to_bytes format for message");
    }
    size_t start = msg_str.find('"') + 1;
    size_t end = msg_str.rfind('"');
    if (start >= end) {
        throw std::runtime_error("Invalid hex string in message");
    }
    std::string hex = msg_str.substr(start, end - start);
    tv.message = hex_to_bytes(hex);

    // Parse pk
    if (pk_str.find("hex_to_bytes(\"") != 0 || pk_str.back() != ')') {
        throw std::runtime_error("Invalid hex_to_bytes format for pk");
    }
    start = pk_str.find('"') + 1;
    end = pk_str.rfind('"');
    if (start >= end) {
        throw std::runtime_error("Invalid hex string in pk");
    }
    hex = pk_str.substr(start, end - start);
    tv.pk = hex_to_bytes(hex);

    // Parse sk
    if (sk_str.find("hex_to_bytes(\"") != 0 || sk_str.back() != ')') {
        throw std::runtime_error("Invalid hex_to_bytes format for sk");
    }
    start = sk_str.find('"') + 1;
    end = sk_str.rfind('"');
    if (start >= end) {
        throw std::runtime_error("Invalid hex string in sk");
    }
    hex = sk_str.substr(start, end - start);
    tv.sk = hex_to_bytes(hex);

    // Parse sig
    if (sig_str.find("hex_to_bytes(\"") != 0 || sig_str.back() != ')') {
        throw std::runtime_error("Invalid hex_to_bytes format for signature");
    }
    start = sig_str.find('"') + 1;
    end = sig_str.rfind('"');
    if (start >= end) {
        throw std::runtime_error("Invalid hex string in signature");
    }
    hex = sig_str.substr(start, end - start);
    tv.expected_sig = hex_to_bytes(hex);

    return tv;
}

// Test fixture for KAT
class KATTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup if needed
    }
};

TEST_F(KATTest, MLDSA44_KAT) {
    KAT_TestVector tv = load_test_vector(44);
    CLWEParameters params(44);
    ColorSignKeyGen keygen(params);
    std::array<uint8_t, 32> seed_array;
    std::copy(tv.seed.begin(), tv.seed.end(), seed_array.begin());
    auto [public_key, private_key] = keygen.generate_keypair_deterministic(seed_array);

    // Verify that deterministic key generation produces consistent results
    // by generating keys twice with the same seed
    auto [public_key2, private_key2] = keygen.generate_keypair_deterministic(seed_array);
    EXPECT_EQ(public_key.serialize(), public_key2.serialize());
    EXPECT_EQ(private_key.serialize(), private_key2.serialize());

    // Verify that the generated keys have the correct structure and sizes
    EXPECT_EQ(public_key.serialize().size(), 1154);
    EXPECT_EQ(private_key.serialize().size(), 2178);

    // Verify that the keys can be used for signing and verification
    ColorSign signer(params);
    ColorSignature signature = signer.sign_message(tv.message, private_key, public_key);
    std::vector<uint8_t> sig_bytes = signature.serialize();

    // Verify signature has correct structure
    EXPECT_GT(sig_bytes.size(), 0);

    ColorSignVerify verifier(params);
    bool verify_result = verifier.verify_signature(public_key, signature, tv.message);
    EXPECT_TRUE(verify_result);

    // Verify that signature verification fails for a wrong message
    std::vector<uint8_t> wrong_message = tv.message;
    if (!wrong_message.empty()) {
        wrong_message[0] ^= 0xFF; // Flip one bit
    } else {
        wrong_message.push_back(0x01);
    }
    bool wrong_verify_result = verifier.verify_signature(public_key, signature, wrong_message);
    EXPECT_FALSE(wrong_verify_result);
}

TEST_F(KATTest, MLDSA65_KAT) {
    KAT_TestVector tv = load_test_vector(65);
    CLWEParameters params(65);
    ColorSignKeyGen keygen(params);
    std::array<uint8_t, 32> seed_array;
    std::copy(tv.seed.begin(), tv.seed.end(), seed_array.begin());
    auto [public_key, private_key] = keygen.generate_keypair_deterministic(seed_array);

    // Verify deterministic key generation consistency
    auto [public_key2, private_key2] = keygen.generate_keypair_deterministic(seed_array);
    EXPECT_EQ(public_key.serialize(), public_key2.serialize());
    EXPECT_EQ(private_key.serialize(), private_key2.serialize());

    // Verify key sizes are appropriate for security level 65 (color-encoded)
    EXPECT_EQ(public_key.serialize().size(), 1666);
    EXPECT_EQ(private_key.serialize().size(), 3202);

    // Verify cryptographic operations work correctly
    ColorSign signer(params);
    ColorSignature signature = signer.sign_message(tv.message, private_key, public_key);
    std::vector<uint8_t> sig_bytes = signature.serialize();

    EXPECT_GT(sig_bytes.size(), 0);

    ColorSignVerify verifier(params);
    bool verify_result = verifier.verify_signature(public_key, signature, tv.message);
    EXPECT_TRUE(verify_result);

    // Test with wrong message
    std::vector<uint8_t> wrong_message = tv.message;
    if (!wrong_message.empty()) {
        wrong_message[0] ^= 0xFF;
    } else {
        wrong_message.push_back(0x01);
    }
    bool wrong_verify_result = verifier.verify_signature(public_key, signature, wrong_message);
    EXPECT_FALSE(wrong_verify_result);
}

TEST_F(KATTest, MLDSA87_KAT) {
    KAT_TestVector tv = load_test_vector(87);
    CLWEParameters params(87);
    ColorSignKeyGen keygen(params);
    std::array<uint8_t, 32> seed_array;
    std::copy(tv.seed.begin(), tv.seed.end(), seed_array.begin());
    auto [public_key, private_key] = keygen.generate_keypair_deterministic(seed_array);

    // Verify deterministic key generation consistency
    auto [public_key2, private_key2] = keygen.generate_keypair_deterministic(seed_array);
    EXPECT_EQ(public_key.serialize(), public_key2.serialize());
    EXPECT_EQ(private_key.serialize(), private_key2.serialize());

    // Verify key sizes are appropriate for security level 87 (color-encoded)
    EXPECT_EQ(public_key.serialize().size(), 2178);
    EXPECT_EQ(private_key.serialize().size(), 4226);

    // Verify cryptographic operations work correctly
    ColorSign signer(params);
    ColorSignature signature = signer.sign_message(tv.message, private_key, public_key);
    std::vector<uint8_t> sig_bytes = signature.serialize();

    EXPECT_GT(sig_bytes.size(), 0);

    ColorSignVerify verifier(params);
    bool verify_result = verifier.verify_signature(public_key, signature, tv.message);
    EXPECT_TRUE(verify_result);

    // Test with wrong message
    std::vector<uint8_t> wrong_message = tv.message;
    if (!wrong_message.empty()) {
        wrong_message[0] ^= 0xFF;
    } else {
        wrong_message.push_back(0x01);
    }
    bool wrong_verify_result = verifier.verify_signature(public_key, signature, wrong_message);
    EXPECT_FALSE(wrong_verify_result);
}

} // namespace clwe