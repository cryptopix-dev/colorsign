#include "../include/clwe/keygen.hpp"
#include "../include/clwe/color_integration.hpp"
#include "../include/clwe/utils.hpp"
#include "../include/clwe/ntt_engine.hpp"
#include <random>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <array>
#include <iostream>
#include <iomanip>

namespace clwe {

ColorSignKeyGen::ColorSignKeyGen(const CLWEParameters& params)
    : params_(params) {
    // Validate parameters
    if (params_.degree == 0 || params_.module_rank == 0) {
        throw std::invalid_argument("Invalid parameters: degree and module_rank must be positive");
    }
}

ColorSignKeyGen::~ColorSignKeyGen() = default;

// Generate matrix A from rho using SHAKE128 with domain separation
std::vector<std::vector<uint32_t>> ColorSignKeyGen::generate_matrix_A(const std::array<uint8_t, 32>& rho) const {
    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;
    uint32_t q = params_.modulus;

    std::vector<std::vector<uint32_t>> matrix(k * k, std::vector<uint32_t>(n));

    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < k; ++j) {
            // Domain separation: rho || i || j || 0
            std::vector<uint8_t> domain_sep = std::vector<uint8_t>(rho.begin(), rho.end());
            domain_sep.push_back(static_cast<uint8_t>(i));
            domain_sep.push_back(static_cast<uint8_t>(j));
            domain_sep.push_back(0);

            SHAKE128Sampler sampler;
            sampler.init(domain_sep.data(), domain_sep.size());

            // Sample coefficients uniformly from [0, q)
            uint32_t* coeffs = matrix[i * k + j].data();
            for (uint32_t l = 0; l < n; ++l) {
                coeffs[l] = sampler.sample_uniform(q);
            }
        }
    }

    return matrix;
}

// Sample s1 using SHAKE256 with K || 0
std::vector<std::vector<uint32_t>> ColorSignKeyGen::sample_s1(const std::array<uint8_t, 32>& K) const {
    std::vector<uint8_t> seed = std::vector<uint8_t>(K.begin(), K.end());
    seed.push_back(0);  // Domain separation for s1

    SHAKE256Sampler sampler;
    sampler.init(seed.data(), seed.size());

    std::vector<std::vector<uint32_t>> s1(params_.module_rank, std::vector<uint32_t>(params_.degree));
    for (auto& poly : s1) {
        sampler.sample_polynomial_binomial(poly.data(), params_.degree, params_.eta, params_.modulus);
    }

    return s1;
}

// Sample s2 using SHAKE256 with K || 1
std::vector<std::vector<uint32_t>> ColorSignKeyGen::sample_s2(const std::array<uint8_t, 32>& K) const {
    std::vector<uint8_t> seed = std::vector<uint8_t>(K.begin(), K.end());
    seed.push_back(1);  // Domain separation for s2

    SHAKE256Sampler sampler;
    sampler.init(seed.data(), seed.size());

    std::vector<std::vector<uint32_t>> s2(params_.module_rank, std::vector<uint32_t>(params_.degree));
    for (auto& poly : s2) {
        sampler.sample_polynomial_binomial(poly.data(), params_.degree, params_.eta, params_.modulus);
    }

    return s2;
}



// Compute t = A * s1 + s2 mod q
std::vector<std::vector<uint32_t>> ColorSignKeyGen::compute_t(
    const std::vector<std::vector<uint32_t>>& matrix_A,
    const std::vector<std::vector<uint32_t>>& s1,
    const std::vector<std::vector<uint32_t>>& s2) const {

    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;
    uint32_t q = params_.modulus;

    // Create NTT engine
    auto ntt_engine = create_optimal_ntt_engine(q, n);

    std::vector<std::vector<uint32_t>> public_key(k, std::vector<uint32_t>(n, 0));

    // First compute A * s1 using NTT
    for (uint32_t i = 0; i < k; ++i) {
        std::vector<uint32_t> temp(n, 0);
        for (uint32_t m = 0; m < k; ++m) {
            std::vector<uint32_t> product(n);
            ntt_engine->multiply(matrix_A[i * k + m].data(), s1[m].data(), product.data());
            for (uint32_t j = 0; j < n; ++j) {
                temp[j] = (static_cast<uint64_t>(temp[j]) + product[j]) % q;
            }
        }
        public_key[i] = temp;
    }

    // Add s2: t = (A * s1) + s2 mod q
    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            public_key[i][j] = (public_key[i][j] + s2[i][j]) % q;
        }
    }

    return public_key;
}

// Compute tr = SHAKE256(pk) where pk = rho || pack(t)
std::array<uint8_t, 64> ColorSignKeyGen::compute_tr(const std::vector<std::vector<uint32_t>>& t,
                                                    const std::array<uint8_t, 32>& rho,
                                                    const std::array<uint8_t, 32>&) const {
    std::vector<uint8_t> packed_t = pack_polynomial_vector(t);
    std::vector<uint8_t> pk(rho.begin(), rho.end());
    pk.insert(pk.end(), packed_t.begin(), packed_t.end());

    std::vector<uint8_t> hash = shake256(pk, 64);
    std::array<uint8_t, 64> tr;
    std::copy(hash.begin(), hash.end(), tr.begin());
    return tr;
}

// Basic color encoding: use centralized color integration
std::vector<uint8_t> ColorSignKeyGen::encode_polynomial_vector_as_colors(const std::vector<std::vector<uint32_t>>& poly_vector) const {
    return clwe::encode_polynomial_vector_as_colors(poly_vector, params_.modulus);
}

// Basic color decoding: use centralized color integration
std::vector<std::vector<uint32_t>> ColorSignKeyGen::decode_colors_to_polynomial_vector(const std::vector<uint8_t>& color_data) const {
    return clwe::decode_colors_to_polynomial_vector(color_data, params_.module_rank, params_.degree, params_.modulus);
}

// Helper method to unpack polynomial data (supports color, compressed, and standard formats)
std::vector<std::vector<uint32_t>> ColorSignKeyGen::unpack_polynomial_data(const std::vector<uint8_t>& data, uint32_t k, uint32_t n) const {
    if (data.empty()) return {};

    // Check if this is 8-bit grayscale color data
    if (data.size() == params_.module_rank * params_.degree * 1) {
        // Color format - decode 8-bit grayscale pixels to polynomials
        return decode_colors_to_polynomial_vector(data);
    }
    // Check if this is compressed data
    else if (data.size() >= 5 && data[0] == 0x01 && (data[1] == 0x01 || data[1] == 0x02 || data[1] == 0x03)) {
        // Compressed format - use compressed unpacking
        return unpack_polynomial_vector_compressed(data, k, n, params_.modulus);
    } else {
        // Standard ML-DSA format - use regular unpacking
        return unpack_polynomial_vector(data, k, n);
    }
}

// Helper method to pack polynomial data with auto-compression
std::vector<uint8_t> ColorSignKeyGen::pack_polynomial_data(const std::vector<std::vector<uint32_t>>& poly_vector) const {
    return encode_polynomial_vector_as_colors(poly_vector);
}

// Generate keypair
std::pair<ColorSignPublicKey, ColorSignPrivateKey> ColorSignKeyGen::generate_keypair() {
    // Generate random rho and K
    std::array<uint8_t, 32> rho;
    secure_random_bytes(rho.data(), rho.size());
    std::array<uint8_t, 32> K;
    secure_random_bytes(K.data(), K.size());

    // Generate matrix A
    auto matrix_A = generate_matrix_A(rho);

    // Sample secret keys s1 and s2
    auto s1 = sample_s1(K);
    auto s2 = sample_s2(K);

    // Compute t = A * s1 + s2
    auto t = compute_t(matrix_A, s1, s2);

    // Compute tr
    auto tr = compute_tr(t, rho, K);

    // Use color encoding for internal storage
    auto public_data = pack_polynomial_data(t);
    std::vector<std::vector<uint32_t>> secret_polys = s1;
    secret_polys.insert(secret_polys.end(), s2.begin(), s2.end());
    std::vector<uint8_t> secret_data = encode_polynomial_vector_as_colors(secret_polys);

    // Create keys with color encoding
    ColorSignPublicKey public_key_struct{rho, K, tr, public_data, params_, false};
    ColorSignPrivateKey private_key_struct{rho, K, tr, secret_data, params_, false};

    return {public_key_struct, private_key_struct};
}

// Deterministic key generation for testing (FIPS 204 Algorithm 5)
std::pair<ColorSignPublicKey, ColorSignPrivateKey> ColorSignKeyGen::generate_keypair_deterministic(const std::array<uint8_t, 32>& zeta) {
    // Compute rho = SHAKE256(zeta || 0)
    std::vector<uint8_t> rho_input(zeta.begin(), zeta.end());
    rho_input.push_back(0);
    std::vector<uint8_t> rho_vec = shake256(rho_input, 32);
    std::array<uint8_t, 32> rho;
    std::copy(rho_vec.begin(), rho_vec.end(), rho.begin());

    // Compute K = SHAKE256(zeta || 1)
    std::vector<uint8_t> K_input(zeta.begin(), zeta.end());
    K_input.push_back(1);
    std::vector<uint8_t> K_vec = shake256(K_input, 32);
    std::array<uint8_t, 32> K;
    std::copy(K_vec.begin(), K_vec.end(), K.begin());

    auto matrix_A = generate_matrix_A(rho);

    // Sample s1 and s2 deterministically from K
    auto s1 = sample_s1(K);
    auto s2 = sample_s2(K);

    auto t = compute_t(matrix_A, s1, s2);

    auto tr = compute_tr(t, rho, K);

    auto public_data = pack_polynomial_data(t);
    std::vector<std::vector<uint32_t>> secret_polys = s1;
    secret_polys.insert(secret_polys.end(), s2.begin(), s2.end());
    std::vector<uint8_t> secret_data = encode_polynomial_vector_as_colors(secret_polys);

    // Create keys with color encoding
    ColorSignPublicKey public_key_struct{rho, K, tr, public_data, params_, false};
    ColorSignPrivateKey private_key_struct{rho, K, tr, secret_data, params_, false};

    return {public_key_struct, private_key_struct};
}

// Optimized key generation with advanced compression and color integration
std::pair<ColorSignPublicKey, ColorSignPrivateKey> ColorSignKeyGen::generate_keypair_optimized() {
    // Generate random rho and K
    std::array<uint8_t, 32> rho;
    secure_random_bytes(rho.data(), rho.size());
    std::array<uint8_t, 32> K;
    secure_random_bytes(K.data(), K.size());

    // Generate matrix A
    auto matrix_A = generate_matrix_A(rho);

    // Sample secret keys s1 and s2
    auto s1 = sample_s1(K);
    auto s2 = sample_s2(K);

    // Compute t = A * s1 + s2
    auto t = compute_t(matrix_A, s1, s2);

    // Compute tr
    auto tr = compute_tr(t, rho, K);

    // Use color encoding for internal storage
    auto public_data = pack_polynomial_data(t);
    std::vector<std::vector<uint32_t>> secret_polys = s1;
    secret_polys.insert(secret_polys.end(), s2.begin(), s2.end());
    std::vector<uint8_t> secret_data = encode_polynomial_vector_as_colors(secret_polys);

    // Create keys with color encoding
    ColorSignPublicKey public_key_struct{rho, K, tr, public_data, params_, false};
    ColorSignPrivateKey private_key_struct{rho, K, tr, secret_data, params_, false};

    return {public_key_struct, private_key_struct};
}

// Serialization implementations
std::vector<uint8_t> ColorSignPublicKey::serialize() const {
    std::vector<uint8_t> data;

    // Add format version and compression flag
    data.push_back(format_version);
    data.push_back(use_compression ? 0x01 : 0x00);

    data.insert(data.end(), seed_rho.begin(), seed_rho.end());
    data.insert(data.end(), seed_K.begin(), seed_K.end());
    data.insert(data.end(), hash_tr.begin(), hash_tr.end());
    data.insert(data.end(), public_data.begin(), public_data.end());
    return data;
}

ColorSignPublicKey ColorSignPublicKey::deserialize(const std::vector<uint8_t>& data, const CLWEParameters& params) {
    if (data.size() < 32 + 32 + 64 + 2) { // +2 for version and compression flags
        throw std::invalid_argument("Public key data too small");
    }

    ColorSignPublicKey key;
    size_t offset = 0;

    // Read format version and compression flag
    key.format_version = data[offset++];
    bool compressed = data[offset++] == 0x01;

    std::copy(data.begin() + offset, data.begin() + offset + 32, key.seed_rho.begin());
    offset += 32;
    std::copy(data.begin() + offset, data.begin() + offset + 32, key.seed_K.begin());
    offset += 32;
    std::copy(data.begin() + offset, data.begin() + offset + 64, key.hash_tr.begin());
    offset += 64;
    key.public_data.assign(data.begin() + offset, data.end());
    key.params = params;
    key.use_compression = compressed;

    return key;
}

std::vector<uint8_t> ColorSignPrivateKey::serialize() const {
    std::vector<uint8_t> data;

    // Add format version and compression flag
    data.push_back(format_version);
    data.push_back(use_compression ? 0x01 : 0x00);

    data.insert(data.end(), seed_rho.begin(), seed_rho.end());
    data.insert(data.end(), seed_K.begin(), seed_K.end());
    data.insert(data.end(), hash_tr.begin(), hash_tr.end());
    data.insert(data.end(), secret_data.begin(), secret_data.end());
    return data;
}

ColorSignPrivateKey ColorSignPrivateKey::deserialize(const std::vector<uint8_t>& data, const CLWEParameters& params) {
    if (data.size() < 32 + 32 + 64 + 2) { // +2 for version and compression flags
        throw std::invalid_argument("Private key data too small");
    }

    ColorSignPrivateKey key;
    size_t offset = 0;

    // Read format version and compression flag
    key.format_version = data[offset++];
    bool compressed = data[offset++] == 0x01;

    std::copy(data.begin() + offset, data.begin() + offset + 32, key.seed_rho.begin());
    offset += 32;
    std::copy(data.begin() + offset, data.begin() + offset + 32, key.seed_K.begin());
    offset += 32;
    std::copy(data.begin() + offset, data.begin() + offset + 64, key.hash_tr.begin());
    offset += 64;
    key.secret_data.assign(data.begin() + offset, data.end());
    key.params = params;
    key.use_compression = compressed;

    return key;
}

// Error message utility
std::string get_colorsign_error_message(ColorSignError error) {
    switch (error) {
        case ColorSignError::SUCCESS:
            return "Success";
        case ColorSignError::INVALID_PARAMETERS:
            return "Invalid parameters";
        case ColorSignError::MALFORMED_KEY:
            return "Malformed key";
        case ColorSignError::MEMORY_ERROR:
            return "Memory allocation failed";
        default:
            return "Unknown error";
    }
}

} // namespace clwe