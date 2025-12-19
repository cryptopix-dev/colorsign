#ifndef CLWE_SIGN_HPP
#define CLWE_SIGN_HPP

#include "parameters.hpp"
#include "keygen.hpp"
#include "security_utils.hpp"
#include "utils.hpp"
#include "shake_sampler.hpp"
#include <vector>
#include <array>
#include <memory>

namespace clwe {

// Forward declarations
struct ColorSignature;
class ColorSign;
struct COSE_Sign1;

// COSE Algorithm Identifiers for ML-DSA
constexpr int COSE_ALG_ML_DSA_44 = -8;
constexpr int COSE_ALG_ML_DSA_65 = -9;
constexpr int COSE_ALG_ML_DSA_87 = -10;

// Enhanced error codes for signing operations with security validation
enum class ColorSignSignError {
    SUCCESS = 0,
    INVALID_PARAMETERS,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
    INVALID_MESSAGE,
    SIGNING_FAILED,
    // Security-related errors
    INPUT_VALIDATION_FAILED,
    KEY_SIZE_INVALID,
    MESSAGE_SIZE_INVALID,
    CONTEXT_INVALID,
    POLYNOMIAL_BOUNDS_VIOLATION,
    MEMORY_ALLOCATION_FAILED,
    TIMING_ATTACK_DETECTED,
    BUFFER_OVERFLOW_DETECTED,
    CRYPTOGRAPHIC_FAILURE,
    PARAMETER_MISMATCH,
    INSUFFICIENT_ENTROPY,
    SIDE_CHANNEL_DETECTED
};

// Signature structure for ColorSign (ML-DSA format: z, h, c)
struct ColorSignature {
    std::vector<uint8_t> z_data;         // Signature polynomial z (standard ML-DSA packing)
    std::vector<uint8_t> h_data;         // Hint vector h (compressed)
    std::vector<uint8_t> c_data;         // Challenge polynomial c (packed)
    CLWEParameters params;               // Cryptographic parameters

    ColorSignature() = default;
    ColorSignature(const std::vector<uint8_t>& z, const std::vector<uint8_t>& h, const std::vector<uint8_t>& c, const CLWEParameters& p);

    std::vector<uint8_t> serialize() const;
    static ColorSignature deserialize(const std::vector<uint8_t>& data, const CLWEParameters& params);
};

// ColorSign signing class with enhanced security
class ColorSign {
private:
    CLWEParameters params_;
    std::unique_ptr<SecurityMonitor> security_monitor_;
    std::unique_ptr<TimingProtection> timing_protection_;

    // Helper methods
    std::vector<uint8_t> hash_message(const std::vector<uint8_t>& message, const std::vector<uint8_t>& context = {}) const;
    std::vector<std::vector<uint32_t>> sample_y(SHAKE256Sampler& sampler) const;
    std::vector<std::vector<uint32_t>> compute_w(const std::vector<std::vector<uint32_t>>& matrix_A,
                                                  const std::vector<std::vector<uint32_t>>& y) const;
    std::vector<uint32_t> compute_challenge(const std::vector<uint8_t>& mu,
                                            const std::vector<uint8_t>& w_encoded) const;
    std::vector<std::vector<uint32_t>> compute_z(const std::vector<std::vector<uint32_t>>& y,
                                                  const std::vector<uint32_t>& c,
                                                  const std::vector<std::vector<uint32_t>>& s1,
                                                  const std::vector<std::vector<uint32_t>>& s2) const;
    bool check_y_bounds(const std::vector<std::vector<uint32_t>>& y) const;
    bool check_z_bounds(const std::vector<std::vector<uint32_t>>& z) const;
    bool check_w_bounds(const std::vector<std::vector<uint32_t>>& w) const;
    std::vector<uint8_t> make_hint(const std::vector<std::vector<uint32_t>>& w,
                                   const std::vector<std::vector<uint32_t>>& w_prime,
                                   uint32_t gamma2) const;
    std::vector<uint8_t> pack_challenge(const std::vector<uint32_t>& c) const;
    std::vector<std::vector<uint32_t>> generate_matrix_A(const std::array<uint8_t, 32>& seed) const;
    std::vector<std::vector<uint32_t>> extract_s1_from_private_key(const ColorSignPrivateKey& private_key) const;
    std::vector<std::vector<uint32_t>> compute_w_prime_for_hint(const std::vector<std::vector<uint32_t>>& w,
                                                                const std::vector<uint32_t>& c,
                                                                const std::vector<std::vector<uint32_t>>& s2) const;
    std::vector<std::vector<uint32_t>> extract_s2_from_private_key(const ColorSignPrivateKey& private_key) const;

public:
    ColorSign(const CLWEParameters& params, std::unique_ptr<SecurityMonitor> monitor = nullptr);
    ~ColorSign();

    // Disable copy and assignment
    ColorSign(const ColorSign&) = delete;
    ColorSign& operator=(const ColorSign&) = delete;

    // Security configuration
    void set_security_monitor(std::unique_ptr<SecurityMonitor> monitor);
    const SecurityMonitor* get_security_monitor() const { return security_monitor_.get(); }

    // Comprehensive input validation
    ColorSignSignError validate_signing_inputs(const std::vector<uint8_t>& message,
                                              const ColorSignPrivateKey& private_key,
                                              const ColorSignPublicKey& public_key,
                                              const std::vector<uint8_t>& context = {}) const;

    // Signing function
    ColorSignature sign_message(const std::vector<uint8_t>& message,
                                const ColorSignPrivateKey& private_key,
                                const ColorSignPublicKey& public_key,
                                const std::vector<uint8_t>& context = {});

    // COSE signing function
    COSE_Sign1 sign_message_cose(const std::vector<uint8_t>& message,
                                 const ColorSignPrivateKey& private_key,
                                 const ColorSignPublicKey& public_key,
                                 int alg = COSE_ALG_ML_DSA_44);

    // Getters
    const CLWEParameters& params() const { return params_; }
};

// Utility function to get error message
std::string get_colorsign_sign_error_message(ColorSignSignError error);

} // namespace clwe

#endif // CLWE_SIGN_HPP