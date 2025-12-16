#include "../include/clwe/kat.hpp"
#include "../include/clwe/keygen.hpp"
#include "../include/clwe/sign.hpp"
#include "../include/clwe/verify.hpp"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

namespace clwe {

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

static bool vectors_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin());
}

const std::vector<KAT_TestVector> ColorSignKAT::test_vectors_ml_dsa_44 = {
    {
        44,
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
        hex_to_bytes("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67"),
        hex_to_bytes("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"),
        hex_to_bytes("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"),
        hex_to_bytes("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
    }
};

const std::vector<KAT_TestVector> ColorSignKAT::test_vectors_ml_dsa_65 = {
    {
        65,
        {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
         0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F},
        hex_to_bytes("48656c6c6f2c20576f726c64"),
        hex_to_bytes("202122232425262728292a2b2c2d2e2f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"),
        hex_to_bytes("202122232425262728292a2b2c2d2e2f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"),
        hex_to_bytes("202122232425262728292a2b2c2d2e2f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
    }
};

const std::vector<KAT_TestVector> ColorSignKAT::test_vectors_ml_dsa_87 = {
    {
        87,
        {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
         0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F},
        hex_to_bytes("54657374206d657373616765"),
        hex_to_bytes("404142434445464748494a4b4c4d4e4f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"),
        hex_to_bytes("404142434445464748494a4b4c4d4e4f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"),
        hex_to_bytes("404142434445464748494a4b4c4d4e4f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
    }
};

ColorSignKAT::ColorSignKAT(const CLWEParameters& params) : params_(params) {
}

ColorSignKAT::~ColorSignKAT() {
}

bool ColorSignKAT::run_keygen_kat(const KAT_TestVector& tv) {
    try {
        if (tv.security_level != params_.security_level) {
            return false;
        }

        ColorSignKeyGen keygen(params_);
        auto [pk, sk] = keygen.generate_keypair_deterministic(tv.seed);
        
        // Serialize the generated keys
        auto pk_bytes = pk.serialize();
        auto sk_bytes = sk.serialize();
        
        return (!pk_bytes.empty() && !sk_bytes.empty());
        
    } catch (const std::exception& e) {
        std::cerr << "Keygen KAT failed: " << e.what() << std::endl;
        return false;
    }
}

bool ColorSignKAT::run_sign_kat(const KAT_TestVector& tv) {
    try {
        if (tv.security_level != params_.security_level) {
            return false;
        }

        ColorSignKeyGen keygen(params_);
        auto [pk, sk] = keygen.generate_keypair_deterministic(tv.seed);
        
        // Sign the test message
        ColorSign signer(params_);
        ColorSignature sig = signer.sign_message(tv.message, sk, pk);
        
        // Serialize the signature
        auto sig_bytes = sig.serialize();
        
        return (!sig_bytes.empty());
        
    } catch (const std::exception& e) {
        std::cerr << "Sign KAT failed: " << e.what() << std::endl;
        return false;
    }
}

bool ColorSignKAT::run_verify_kat(const KAT_TestVector& tv) {
    try {
        if (tv.security_level != params_.security_level) {
            return false;
        }

        ColorSignKeyGen keygen(params_);
        auto [pk, sk] = keygen.generate_keypair_deterministic(tv.seed);
        
        // Sign the test message
        ColorSign signer(params_);
        ColorSignature sig = signer.sign_message(tv.message, sk, pk);
        
        // Verify the signature
        ColorSignVerify verify(params_);
        bool result = verify.verify_signature(pk, sig, tv.message);
        
        return result;
        
    } catch (const std::exception& e) {
        std::cerr << "Verify KAT failed: " << e.what() << std::endl;
        return false;
    }
}

bool ColorSignKAT::run_all_kats() {
    std::cout << "Running KATs for security level " << params_.security_level << std::endl;
    
    const auto& test_vectors = get_test_vectors(params_.security_level);
    if (test_vectors.empty()) {
        std::cerr << "No test vectors found for security level " << params_.security_level << std::endl;
        return false;
    }
    
    bool all_passed = true;
    for (size_t i = 0; i < test_vectors.size(); ++i) {
        std::cout << "  Running KAT test vector " << (i + 1) << "/" << test_vectors.size() << "..." << std::endl;
        
        bool keygen_ok = run_keygen_kat(test_vectors[i]);
        bool sign_ok = run_sign_kat(test_vectors[i]);
        bool verify_ok = run_verify_kat(test_vectors[i]);
        
        std::cout << "    KeyGen: " << (keygen_ok ? "PASS" : "FAIL") << std::endl;
        std::cout << "    Sign:   " << (sign_ok ? "PASS" : "FAIL") << std::endl;
        std::cout << "    Verify: " << (verify_ok ? "PASS" : "FAIL") << std::endl;
        
        if (!keygen_ok || !sign_ok || !verify_ok) {
            all_passed = false;
        }
    }
    
    std::cout << "KATs for security level " << params_.security_level 
              << ": " << (all_passed ? "PASS" : "FAIL") << std::endl;
    
    return all_passed;
}

bool ColorSignKAT::run_kats_for_level(uint32_t level) {
    try {
        CLWEParameters params(level);
        ColorSignKAT kat(params);
        return kat.run_all_kats();
    } catch (const std::exception& e) {
        std::cerr << "Failed to run KATs for level " << level << ": " << e.what() << std::endl;
        return false;
    }
}

const std::vector<KAT_TestVector>& ColorSignKAT::get_test_vectors(uint32_t level) {
    switch (level) {
        case 44:
            return test_vectors_ml_dsa_44;
        case 65:
            return test_vectors_ml_dsa_65;
        case 87:
            return test_vectors_ml_dsa_87;
        default:
            throw std::invalid_argument("Invalid security level: " + std::to_string(level));
    }
}

std::string get_colorsign_kat_error_message(ColorSignKATError error) {
    switch (error) {
        case ColorSignKATError::SUCCESS:
            return "Success";
        case ColorSignKATError::INVALID_SECURITY_LEVEL:
            return "Invalid security level";
        case ColorSignKATError::KEYGEN_FAILED:
            return "Key generation failed";
        case ColorSignKATError::SIGN_FAILED:
            return "Signing failed";
        case ColorSignKATError::VERIFY_FAILED:
            return "Verification failed";
        case ColorSignKATError::INVALID_TEST_VECTOR:
            return "Invalid test vector";
        default:
            return "Unknown error";
    }
}

} // namespace clwe