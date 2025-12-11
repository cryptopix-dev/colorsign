#ifndef CLWE_COLOR_INTEGRATION_HPP
#define CLWE_COLOR_INTEGRATION_HPP

#include <vector>
#include <cstdint>

namespace clwe {

/**
 * @brief Color integration module for ColorSign
 *
 * Provides functions to encode polynomials and vectors into RGBA pixel arrays
 * for visualization, and decode back. Coefficients are packed into RGBA pixels
 * where each pixel represents one coefficient.
 */

/**
 * @brief Encode a single polynomial into RGBA color data
 *
 * Each coefficient is packed into 4 bytes (RGBA) as:
 * - R: (coeff >> 24) & 0xFF
 * - G: (coeff >> 16) & 0xFF
 * - B: (coeff >> 8) & 0xFF
 * - A: coeff & 0xFF
 *
 * @param poly The polynomial coefficients
 * @param modulus The modulus for coefficient reduction (typically q)
 * @return RGBA color data as byte array
 */
std::vector<uint8_t> encode_polynomial_as_colors(const std::vector<uint32_t>& poly, uint32_t modulus);

/**
 * @brief Decode RGBA color data into a single polynomial
 *
 * Unpacks RGBA bytes back into coefficients and reduces modulo modulus.
 *
 * @param color_data RGBA color data
 * @param modulus The modulus for coefficient reduction
 * @return Polynomial coefficients
 */
std::vector<uint32_t> decode_colors_to_polynomial(const std::vector<uint8_t>& color_data, uint32_t modulus);

/**
 * @brief Encode a vector of polynomials into RGBA color data
 *
 * Each polynomial in the vector is encoded sequentially.
 *
 * @param poly_vector Vector of polynomials
 * @param modulus The modulus for coefficient reduction
 * @return RGBA color data as byte array
 */
std::vector<uint8_t> encode_polynomial_vector_as_colors(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);

/**
 * @brief Decode RGBA color data into a vector of polynomials
 *
 * @param color_data RGBA color data
 * @param k Number of polynomials in the vector
 * @param n Degree of each polynomial
 * @param modulus The modulus for coefficient reduction
 * @return Vector of polynomials
 */
std::vector<std::vector<uint32_t>> decode_colors_to_polynomial_vector(const std::vector<uint8_t>& color_data, uint32_t k, uint32_t n, uint32_t modulus);

// Compression functions for color integration
std::vector<uint8_t> encode_polynomial_vector_as_colors_compressed(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);
std::vector<uint8_t> encode_polynomial_vector_as_colors_huffman(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);
std::vector<std::vector<uint32_t>> decode_colors_to_polynomial_vector_compressed(const std::vector<uint8_t>& color_data, uint32_t k, uint32_t n, uint32_t modulus);
std::vector<uint8_t> convert_compressed_to_color_format(const std::vector<uint8_t>& compressed_data, uint32_t k, uint32_t n, uint32_t modulus);
std::vector<uint8_t> encode_polynomial_vector_as_colors_auto(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus);

// Advanced color integration functions
std::vector<uint8_t> generate_color_representation_from_compressed(const std::vector<uint8_t>& compressed_data, uint32_t k, uint32_t n, uint32_t modulus);
std::vector<uint8_t> compress_with_color_support(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus, bool enable_color_metadata = true);
std::vector<std::vector<uint32_t>> decompress_with_color_support(const std::vector<uint8_t>& dual_format_data, uint32_t& out_k, uint32_t& out_n, uint32_t& out_modulus);
std::vector<uint8_t> generate_color_from_dual_format(const std::vector<uint8_t>& dual_format_data);
std::vector<uint8_t> encode_polynomial_vector_with_color_integration(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus, bool enable_on_demand_color = true);
std::vector<std::vector<uint32_t>> decode_polynomial_vector_with_color_integration(const std::vector<uint8_t>& color_integrated_data, uint32_t modulus);

} // namespace clwe

#endif // CLWE_COLOR_INTEGRATION_HPP