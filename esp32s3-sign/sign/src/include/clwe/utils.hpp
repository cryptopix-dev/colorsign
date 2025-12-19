#ifndef CLWE_UTILS_HPP
#define CLWE_UTILS_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>

namespace clwe {

// Secure random bytes generation
void secure_random_bytes(uint8_t* buffer, size_t len);
// SHAKE256 hash function (XOF)
std::vector<uint8_t> shake256(const std::vector<uint8_t>& input, size_t output_len);

// Modular arithmetic utilities
uint32_t mod_inverse(uint32_t a, uint32_t m);
uint32_t mod_pow(uint32_t base, uint32_t exp, uint32_t mod);
bool is_power_of_two(uint32_t x);

// ML-DSA specific utilities
// Compute high bits of polynomial coefficients (w1 = floor((w + 2^{d-1}) / 2^d))
void compute_high_bits(const std::vector<uint32_t>& w, std::vector<uint32_t>& w1, uint32_t d, uint32_t q);

// Sample challenge polynomial with exactly tau non-zero coefficients in {-1, 0, 1}
void sample_challenge(std::vector<uint32_t>& c, const std::vector<uint8_t>& seed, uint32_t tau, uint32_t n, uint32_t q);

// Pack polynomial vector into bytes (little-endian 32-bit per coefficient)
std::vector<uint8_t> pack_polynomial_vector(const std::vector<std::vector<uint32_t>>& poly_vector);

// Unpack bytes into polynomial vector (little-endian 32-bit per coefficient)
std::vector<std::vector<uint32_t>> unpack_polynomial_vector(const std::vector<uint8_t>& data, uint32_t k, uint32_t n);

// Compression functions for ML-DSA polynomials
std::vector<uint8_t> pack_polynomial_vector_compressed(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);
std::vector<uint8_t> pack_polynomial_vector_sparse(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);
std::vector<uint8_t> pack_polynomial_vector_sparse_enhanced(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);
std::vector<uint8_t> pack_polynomial_vector_huffman(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);
std::vector<uint8_t> pack_polynomial_vector_adaptive_huffman(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);
std::vector<uint8_t> pack_polynomial_vector_arithmetic(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);
std::vector<uint8_t> pack_polynomial_vector_context_aware(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus, uint32_t eta = 2, uint32_t gamma1 = 0, uint32_t gamma2 = 0);
std::vector<uint8_t> pack_polynomial_vector_ml_dsa(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus, uint32_t d);
std::vector<std::vector<uint32_t>> unpack_polynomial_vector_compressed(const std::vector<uint8_t>& data, uint32_t k, uint32_t n, uint32_t modulus);
std::vector<std::vector<uint32_t>> unpack_polynomial_vector_sparse_enhanced(const std::vector<uint8_t>& data, uint32_t k, uint32_t n, uint32_t modulus);
std::vector<std::vector<uint32_t>> unpack_polynomial_vector_ml_dsa(const std::vector<uint8_t>& data, uint32_t k, uint32_t n, uint32_t modulus, uint32_t d);
std::vector<uint8_t> pack_polynomial_vector_auto(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);
std::vector<uint8_t> pack_polynomial_vector_auto_advanced(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus, uint32_t eta = 2, uint32_t gamma1 = 0, uint32_t gamma2 = 0);

// Huffman coding functions
std::vector<uint8_t> build_huffman_table(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);
std::vector<uint8_t> huffman_encode_polynomial_vector(const std::vector<std::vector<uint32_t>>& poly_vector, const std::vector<uint8_t>& huffman_table, uint32_t modulus);
std::vector<std::vector<uint32_t>> huffman_decode_polynomial_vector(const std::vector<uint8_t>& data, uint32_t k, uint32_t n, uint32_t modulus);

} // namespace clwe

#endif // CLWE_UTILS_HPP