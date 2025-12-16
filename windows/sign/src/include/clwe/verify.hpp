#ifndef CLWE_VERIFY_HPP
#define CLWE_VERIFY_HPP

#include "parameters.hpp"
#include "keygen.hpp"
#include "sign.hpp"
#include <vector>
#include <array>

namespace clwe {

// Forward declarations
class ColorSignVerify;
struct COSE_Sign1;

// ColorSign verification class
class ColorSignVerify {
private:
    CLWEParameters params_;

    // Helper methods
    std::vector<std::vector<uint32_t>> generate_matrix_A(const std::array<uint8_t, 32>& seed) const;
    std::vector<std::vector<uint32_t>> extract_t_from_public_key(const ColorSignPublicKey& public_key) const;
    std::vector<std::vector<uint32_t>> compute_w_prime_fixed(const std::vector<std::vector<uint32_t>>& matrix_A,
                                                             const std::vector<std::vector<uint32_t>>& z,
                                                             const std::vector<uint8_t>& c_hash,
                                                             const std::vector<std::vector<uint32_t>>& t) const;
    std::vector<uint32_t> unpack_challenge(const std::vector<uint8_t>& c_hash) const;
    std::vector<uint8_t> hash_message(const std::vector<uint8_t>& message, const std::vector<uint8_t>& context = {}) const;
    std::vector<uint32_t> compute_challenge(const std::vector<uint8_t>& mu,
                                           const std::vector<uint8_t>& w_encoded) const;
    bool check_z_bounds(const std::vector<std::vector<uint32_t>>& z) const;
    bool check_w_bounds(const std::vector<std::vector<uint32_t>>& w) const;
    std::vector<std::vector<uint32_t>> use_hint(const std::vector<uint8_t>& h,
                                               const std::vector<std::vector<uint32_t>>& z,
                                               uint32_t gamma2) const;
    std::vector<std::vector<uint32_t>> hint_decompress(const std::vector<std::vector<uint32_t>>& compressed,
                                                       const std::vector<uint8_t>& h,
                                                       uint32_t gamma2) const;

    // Enhanced security validation methods
    bool verify_signature_basic(const ColorSignPublicKey& public_key,
                                const ColorSignature& signature,
                                const std::vector<uint8_t>& message,
                                const std::vector<uint8_t>& context = {}) const;
    bool run_comprehensive_security_checks(const ColorSignPublicKey& public_key,
                                           const ColorSignature& signature,
                                           const std::vector<uint8_t>& message,
                                           const std::vector<uint8_t>& context) const;

    // Security validation helper methods
    bool check_z_bounds_enhanced(const std::vector<std::vector<uint32_t>>& z) const;
    bool validate_encoding_consistency(const ColorSignPublicKey& public_key,
                                       const ColorSignature& signature) const;
    bool validate_cryptographic_integrity_final(const ColorSignPublicKey& public_key,
                                                const ColorSignature& signature,
                                                const std::vector<uint8_t>& message,
                                                const std::vector<std::vector<uint32_t>>& w_prime) const;
    bool validate_mathematical_consistency(const ColorSignPublicKey& public_key,
                                           const ColorSignature& signature,
                                           const std::vector<std::vector<uint32_t>>& w_prime) const;
    bool validate_challenge_match(const std::vector<std::vector<uint32_t>>& w,
                                  const ColorSignature& signature,
                                  const std::vector<uint8_t>& message,
                                  const std::vector<uint8_t>& context) const;
    std::vector<uint8_t> encode_w_for_challenge(const std::vector<std::vector<uint32_t>>& w) const;
    std::vector<uint8_t> pack_challenge(const std::vector<uint32_t>& c) const;

public:
    ColorSignVerify(const CLWEParameters& params);
    ~ColorSignVerify();

    // Disable copy and assignment
    ColorSignVerify(const ColorSignVerify&) = delete;
    ColorSignVerify& operator=(const ColorSignVerify&) = delete;

    // Verification function
    bool verify_signature(const ColorSignPublicKey& public_key,
                          const ColorSignature& signature,
                          const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& context = {});

    // COSE verification function
    bool verify_signature_cose(const ColorSignPublicKey& public_key,
                               const COSE_Sign1& cose_signature);

    // Getters
    const CLWEParameters& params() const { return params_; }
};

// Error codes for verification operations
enum class ColorSignVerifyError {
    SUCCESS = 0,
    INVALID_PARAMETERS,
    INVALID_PUBLIC_KEY,
    INVALID_SIGNATURE,
    VERIFICATION_FAILED,
    MALFORMED_SIGNATURE,
    Z_OUT_OF_BOUNDS
};

// Utility function to get error message
std::string get_colorsign_verify_error_message(ColorSignVerifyError error);

} // namespace clwe

#endif // CLWE_VERIFY_HPP
