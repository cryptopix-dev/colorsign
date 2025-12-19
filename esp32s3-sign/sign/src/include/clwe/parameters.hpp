#ifndef CLWE_PARAMETERS_HPP
#define CLWE_PARAMETERS_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

// Main CLWE namespace for ColorSign
namespace clwe {

// Parameter structure for CLWE operations in ColorSign
struct CLWEParameters {
    uint32_t security_level;  // Security level (44, 65, 87 for ML-DSA)
    uint32_t degree;          // Ring degree n (256 for ML-DSA)
    uint32_t module_rank;     // Module rank k
    uint32_t repetitions;     // Number of repetitions l
    uint32_t modulus;         // Prime modulus q (8380417 for ML-DSA)
    uint32_t eta;             // Binomial distribution parameter η for key generation
    uint32_t tau;             // Challenge non-zero coefficient count τ
    uint32_t beta;            // Signature coefficient bound β
    uint32_t gamma1;          // Uniform distribution bound γ1 for signing
    uint32_t gamma2;          // Verification bound γ2 = (q-1)/{32,88}
    uint32_t omega;           // Hint weight bound ω
    uint32_t lambda;          // Security strength λ in bits

    // Domain separation constants for Keccak-based hash functions
    static const uint8_t DOMAIN_SEP_H = 0x00;      // For H function in key generation
    static const uint8_t DOMAIN_SEP_G = 0x01;      // For G function
    static const uint8_t DOMAIN_SEP_H_SIG = 0x02;  // For H function in signing
    static const uint8_t DOMAIN_SEP_PRF = 0x03;    // For PRF function

    // Constructor with defaults - ML-DSA/ML-KEM standard parameters
    CLWEParameters(uint32_t sec_level = 44)
        : security_level(sec_level), degree(256), modulus(8380417) {  // Default ML-DSA modulus
        // Set parameters based on security level (ML-DSA or ML-KEM)
        switch (sec_level) {
            case 44:  // ML-DSA-44
                module_rank = 4;
                repetitions = 4;
                eta = 2;
                tau = 39;
                beta = 78;
                gamma1 = 1 << 17;  // 2^17
                gamma2 = (modulus - 1) / 88;
                omega = 80;
                lambda = 128;
                break;
            case 65:  // ML-DSA-65
                module_rank = 6;
                repetitions = 5;
                eta = 4;
                tau = 49;
                beta = 196;
                gamma1 = 1 << 19;  // 2^19
                gamma2 = (modulus - 1) / 32;
                omega = 55;
                lambda = 192;
                break;
            case 87:  // ML-DSA-87
                module_rank = 8;
                repetitions = 7;
                eta = 2;
                tau = 60;
                beta = 120;
                gamma1 = 1 << 19;  // 2^19
                gamma2 = (modulus - 1) / 32;
                omega = 75;
                lambda = 256;
                break;
            case 512:  // ML-KEM-512
                module_rank = 2;
                repetitions = 0;  // Not used in KEM
                modulus = 3329;
                eta = 2;
                tau = 0;  // Not used in KEM
                beta = 0;  // Not used in KEM
                gamma1 = 0;  // Not used in KEM
                gamma2 = 0;  // Not used in KEM
                omega = 0;  // Not used in KEM
                lambda = 128;
                break;
            case 768:  // ML-KEM-768
                module_rank = 3;
                repetitions = 0;  // Not used in KEM
                modulus = 3329;
                eta = 2;
                tau = 0;  // Not used in KEM
                beta = 0;  // Not used in KEM
                gamma1 = 0;  // Not used in KEM
                gamma2 = 0;  // Not used in KEM
                omega = 0;  // Not used in KEM
                lambda = 192;
                break;
            case 1024:  // ML-KEM-1024
                module_rank = 4;
                repetitions = 0;  // Not used in KEM
                modulus = 3329;
                eta = 2;
                tau = 0;  // Not used in KEM
                beta = 0;  // Not used in KEM
                gamma1 = 0;  // Not used in KEM
                gamma2 = 0;  // Not used in KEM
                omega = 0;  // Not used in KEM
                lambda = 256;
                break;
            default:
                throw std::invalid_argument("Invalid security level: must be 44, 65, 87 (ML-DSA) or 512, 768, 1024 (ML-KEM)");
        }
        validate();
    }

    // Constructor with custom parameters
    CLWEParameters(uint32_t sec_level, uint32_t deg, uint32_t rank, uint32_t reps, uint32_t mod, uint32_t e, uint32_t t, uint32_t b, uint32_t g1, uint32_t g2, uint32_t o, uint32_t l)
        : security_level(sec_level), degree(deg), module_rank(rank), repetitions(reps),
          modulus(mod), eta(e), tau(t), beta(b), gamma1(g1), gamma2(g2), omega(o), lambda(l) {
        validate();
    }

    // Validation function
    void validate() const;

    // Helper function to check if a number is prime
    static bool is_prime(uint32_t n) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;
        for (uint32_t i = 5; i * i <= n; i += 6) {
            if (n % i == 0 || n % (i + 2) == 0) return false;
        }
        return true;
    }

    // Helper functions to compute expected key sizes from parameters
    // Color encoding uses RGB format (3 bytes per coefficient)
    size_t get_expected_public_key_size() const {
        // public: rho(32) + K(32) + tr(64) + color_data(k*n*3)
        return 32 + 32 + 64 + (module_rank * degree * 3);
    }

    size_t get_expected_private_key_size() const {
        // private: rho(32) + K(32) + tr(64) + color_data(2*k*n*3)
        return 32 + 32 + 64 + (2 * module_rank * degree * 3);
    }

    size_t get_expected_public_data_size() const {
        // 8-bit grayscale color encoding: k*n*1 byte per coefficient
        return module_rank * degree;
    }

    size_t get_expected_private_secret_data_size() const {
        // Private key secret_data: s1 + s2, each k*n bytes
        return 2 * module_rank * degree;
    }

    std::pair<size_t, size_t> get_valid_public_key_size_range() const {
        auto expected = get_expected_public_key_size();
        // Allow 10% variance for different encoding schemes
        return {expected * 9 / 10, expected * 11 / 10};
    }

    std::pair<size_t, size_t> get_valid_private_key_size_range() const {
        auto expected = get_expected_private_key_size();
        // Allow 10% variance for different encoding schemes
        return {expected * 9 / 10, expected * 11 / 10};
    }

private:
};

} // namespace clwe

#endif // CLWE_PARAMETERS_HPP