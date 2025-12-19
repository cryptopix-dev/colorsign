#include "../include/clwe/parameters.hpp"

namespace clwe {

// Validation function implementation
void CLWEParameters::validate() const {
    // Validate security level
    if (security_level != 44 && security_level != 65 && security_level != 87 &&
        security_level != 512 && security_level != 768 && security_level != 1024) {
        throw std::invalid_argument("Invalid security level: must be 44, 65, 87 (ML-DSA) or 512, 768, 1024 (ML-KEM)");
    }

    // Validate degree: must be power of 2 and reasonable
    if (degree == 0 || (degree & (degree - 1)) != 0 || degree > 8192) {
        throw std::invalid_argument("Invalid degree: must be a power of 2 between 1 and 8192");
    }

    // Validate module rank: positive and reasonable
    if (module_rank == 0 || module_rank > 16) {
        throw std::invalid_argument("Invalid module rank: must be between 1 and 16");
    }

    // Validate repetitions: positive and reasonable (skip for KEM)
    if ((security_level == 44 || security_level == 65 || security_level == 87) &&
        (repetitions == 0 || repetitions > 16)) {
        throw std::invalid_argument("Invalid repetitions: must be between 1 and 16 for ML-DSA");
    }

    // Validate modulus: must be prime and appropriate size
    if (!is_prime(modulus) || modulus < 256 || modulus > 16777216) {  // Allow up to 2^24
        throw std::invalid_argument("Invalid modulus: must be a prime between 256 and 16777216");
    }

    // Validate eta: positive and reasonable
    if (eta == 0 || eta > 16) {
        throw std::invalid_argument("Invalid eta: must be between 1 and 16");
    }

    // Validate tau: positive and reasonable (skip for KEM)
    if ((security_level == 44 || security_level == 65 || security_level == 87) &&
        (tau == 0 || tau > degree)) {
        throw std::invalid_argument("Invalid tau: must be between 1 and degree for ML-DSA");
    }

    // Validate beta: positive (skip for KEM)
    if ((security_level == 44 || security_level == 65 || security_level == 87) &&
        beta == 0) {
        throw std::invalid_argument("Invalid beta: must be positive for ML-DSA");
    }

    // Validate gamma1: positive and reasonable (skip for KEM)
    if ((security_level == 44 || security_level == 65 || security_level == 87) &&
        (gamma1 == 0 || gamma1 > (1 << 20))) {
        throw std::invalid_argument("Invalid gamma1: must be between 1 and 2^20 for ML-DSA");
    }

    // Validate gamma2: positive (skip for KEM)
    if ((security_level == 44 || security_level == 65 || security_level == 87) &&
        gamma2 == 0) {
        throw std::invalid_argument("Invalid gamma2: must be positive for ML-DSA");
    }

    // Validate omega: positive (skip for KEM)
    if ((security_level == 44 || security_level == 65 || security_level == 87) &&
        omega == 0) {
        throw std::invalid_argument("Invalid omega: must be positive for ML-DSA");
    }

    // Validate lambda: valid security strength
    if (lambda != 128 && lambda != 192 && lambda != 256) {
        throw std::invalid_argument("Invalid lambda: must be 128, 192, or 256");
    }
}

} // namespace clwe