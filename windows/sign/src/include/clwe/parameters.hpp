#ifndef CLWE_PARAMETERS_HPP
#define CLWE_PARAMETERS_HPP

#include <cstdint>
#include <stdexcept>
#include <string>

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

    // Constructor with defaults - ML-DSA standard parameters
    CLWEParameters(uint32_t sec_level = 44)
        : security_level(sec_level), degree(256), modulus(8380417) {  // ML-DSA modulus
        // Set parameters based on security level (ML-DSA)
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
            default:
                throw std::invalid_argument("Invalid security level: must be 44, 65, or 87");
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
    void validate() const {
        // Validate security level
        if (security_level != 44 && security_level != 65 && security_level != 87) {
            throw std::invalid_argument("Invalid security level: must be 44, 65, or 87");
        }

        // Validate degree: must be power of 2 and reasonable
        if (degree == 0 || (degree & (degree - 1)) != 0 || degree > 8192) {
            throw std::invalid_argument("Invalid degree: must be a power of 2 between 1 and 8192");
        }

        // Validate module rank: positive and reasonable
        if (module_rank == 0 || module_rank > 16) {
            throw std::invalid_argument("Invalid module rank: must be between 1 and 16");
        }

        // Validate repetitions: positive and reasonable
        if (repetitions == 0 || repetitions > 16) {
            throw std::invalid_argument("Invalid repetitions: must be between 1 and 16");
        }

        // Validate modulus: must be prime and appropriate size
        if (!is_prime(modulus) || modulus < 256 || modulus > 16777216) {  // Allow up to 2^24
            throw std::invalid_argument("Invalid modulus: must be a prime between 256 and 16777216");
        }

        // Validate eta: positive and reasonable
        if (eta == 0 || eta > 16) {
            throw std::invalid_argument("Invalid eta: must be between 1 and 16");
        }

        // Validate tau: positive and reasonable
        if (tau == 0 || tau > degree) {
            throw std::invalid_argument("Invalid tau: must be between 1 and degree");
        }

        // Validate beta: positive
        if (beta == 0) {
            throw std::invalid_argument("Invalid beta: must be positive");
        }

        // Validate gamma1: positive and reasonable
        if (gamma1 == 0 || gamma1 > (1 << 20)) {
            throw std::invalid_argument("Invalid gamma1: must be between 1 and 2^20");
        }

        // Validate gamma2: positive
        if (gamma2 == 0) {
            throw std::invalid_argument("Invalid gamma2: must be positive");
        }

        // Validate omega: positive
        if (omega == 0) {
            throw std::invalid_argument("Invalid omega: must be positive");
        }

        // Validate lambda: valid security strength
        if (lambda != 128 && lambda != 192 && lambda != 256) {
            throw std::invalid_argument("Invalid lambda: must be 128, 192, or 256");
        }
        }
    
        // Get expected sizes for key data
        size_t get_expected_public_data_size() const {
            switch (security_level) {
                case 44: return 1024;
                case 65: return 1536;
                case 87: return 2048;
                default: return 0;
            }
        }
    
        size_t get_expected_private_secret_data_size() const {
            switch (security_level) {
                case 44: return 2048;
                case 65: return 3072;
                case 87: return 4096;
                default: return 0;
            }
        }
    
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

private:
};

} // namespace clwe

#endif // CLWE_PARAMETERS_HPP