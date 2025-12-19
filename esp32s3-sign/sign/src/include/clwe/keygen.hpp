#ifndef CLWE_KEYGEN_HPP
#define CLWE_KEYGEN_HPP

#include "parameters.hpp"
#include "shake_sampler.hpp"
#include <vector>
#include <array>
#include <memory>
#include <random>

namespace clwe {

// Forward declarations
struct ColorSignPublicKey;
struct ColorSignPrivateKey;
class ColorSignKeyGen;

// Key structures for ColorSign (ML-DSA compliant)
struct ColorSignPublicKey {
    std::array<uint8_t, 32> seed_rho;    // Seed for matrix A generation (ρ)
    std::array<uint8_t, 32> seed_K;     // Seed for secret key generation (K)
    std::array<uint8_t, 64> hash_tr;    // Hash of public key (tr)
    std::vector<uint8_t> public_data;   // Serialized public key polynomial t (as colors)
    CLWEParameters params;               // Cryptographic parameters
    uint8_t format_version = 0x01;       // Format version (1 = original, 2 = compressed)
    bool use_compression = false;        // Flag indicating if compression is used

    ColorSignPublicKey() = default;
    ColorSignPublicKey(const std::array<uint8_t, 32>& rho, const std::array<uint8_t, 32>& K,
                       const std::array<uint8_t, 64>& tr, const std::vector<uint8_t>& pd, const CLWEParameters& p,
                       bool compressed = false)
        : seed_rho(rho), seed_K(K), hash_tr(tr), public_data(pd), params(p), use_compression(compressed) {}

    std::vector<uint8_t> serialize() const;
    static ColorSignPublicKey deserialize(const std::vector<uint8_t>& data, const CLWEParameters& params);
};

struct ColorSignPrivateKey {
    std::array<uint8_t, 32> seed_rho;    // Seed for matrix A generation (ρ)
    std::array<uint8_t, 32> seed_K;     // Seed for secret key generation (K)
    std::array<uint8_t, 64> hash_tr;    // Hash of public key (tr)
    std::vector<uint8_t> secret_data;   // Serialized secret polynomials s1, s2, t0 (as colors)
    CLWEParameters params;               // Cryptographic parameters
    uint8_t format_version = 0x01;       // Format version (1 = original, 2 = compressed)
    bool use_compression = false;        // Flag indicating if compression is used

    ColorSignPrivateKey() = default;
    ColorSignPrivateKey(const std::array<uint8_t, 32>& rho, const std::array<uint8_t, 32>& K,
                       const std::array<uint8_t, 64>& tr, const std::vector<uint8_t>& sd, const CLWEParameters& p,
                       bool compressed = false)
        : seed_rho(rho), seed_K(K), hash_tr(tr), secret_data(sd), params(p), use_compression(compressed) {}

    std::vector<uint8_t> serialize() const;
    static ColorSignPrivateKey deserialize(const std::vector<uint8_t>& data, const CLWEParameters& params);
};

// ColorSign key generation class
class ColorSignKeyGen {
private:
    CLWEParameters params_;

    // Helper methods for key generation
    std::vector<std::vector<uint32_t>> generate_matrix_A(const std::array<uint8_t, 32>& rho) const;
    std::vector<std::vector<uint32_t>> sample_s1(const std::array<uint8_t, 32>& K) const;
    std::vector<std::vector<uint32_t>> sample_s2(const std::array<uint8_t, 32>& K) const;
    std::vector<std::vector<uint32_t>> compute_t(const std::vector<std::vector<uint32_t>>& matrix_A,
                                                 const std::vector<std::vector<uint32_t>>& s1,
                                                 const std::vector<std::vector<uint32_t>>& s2) const;
    std::array<uint8_t, 64> compute_tr(const std::vector<std::vector<uint32_t>>& t,
                                       const std::array<uint8_t, 32>& rho,
                                       const std::array<uint8_t, 32>& K) const;
    std::vector<uint8_t> encode_polynomial_vector_as_colors(const std::vector<std::vector<uint32_t>>& poly_vector) const;
    std::vector<std::vector<uint32_t>> decode_colors_to_polynomial_vector(const std::vector<uint8_t>& color_data) const;
    // Compression helper methods
    std::vector<std::vector<uint32_t>> unpack_polynomial_data(const std::vector<uint8_t>& data, uint32_t k, uint32_t n) const;
    std::vector<uint8_t> pack_polynomial_data(const std::vector<std::vector<uint32_t>>& poly_vector) const;


public:
    ColorSignKeyGen(const CLWEParameters& params);
    ~ColorSignKeyGen();

    // Disable copy and assignment
    ColorSignKeyGen(const ColorSignKeyGen&) = delete;
    ColorSignKeyGen& operator=(const ColorSignKeyGen&) = delete;

    // Key generation
    std::pair<ColorSignPublicKey, ColorSignPrivateKey> generate_keypair();

    // Deterministic key generation (for testing)
    std::pair<ColorSignPublicKey, ColorSignPrivateKey> generate_keypair_deterministic(const std::array<uint8_t, 32>& seed);

    // Optimized key generation with advanced compression
    std::pair<ColorSignPublicKey, ColorSignPrivateKey> generate_keypair_optimized();

    // Getters
    const CLWEParameters& params() const { return params_; }
};

// Error codes for ColorSign operations
enum class ColorSignError {
    SUCCESS = 0,
    INVALID_PARAMETERS,
    MALFORMED_KEY,
    MEMORY_ERROR
};

// Utility function to get error message
std::string get_colorsign_error_message(ColorSignError error);

} // namespace clwe

#endif // CLWE_KEYGEN_HPP