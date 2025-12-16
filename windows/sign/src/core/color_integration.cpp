#include "../include/clwe/color_integration.hpp"
#include "../include/clwe/utils.hpp"
#include <stdexcept>

using namespace clwe;

namespace clwe {

std::vector<uint8_t> encode_polynomial_as_colors(const std::vector<uint32_t>& poly, uint32_t modulus) {
    std::vector<uint8_t> color_data;

    for (uint32_t coeff : poly) {
        coeff %= modulus;
        // Pack coefficient into RGB format (take lower 8 bits)
        color_data.push_back(coeff & 0xFF);
    }

    return color_data;
}

std::vector<uint32_t> decode_colors_to_polynomial(const std::vector<uint8_t>& color_data, uint32_t modulus) {
    std::vector<uint32_t> poly;
    poly.reserve(color_data.size());

    // Unpack from RGB format where each pixel contains up to 3 coefficients
    for (size_t pixel_start = 0; pixel_start < color_data.size(); pixel_start += 3) {
        size_t end = std::min(pixel_start + 3, color_data.size());
        for (size_t b = pixel_start; b < end; ++b) {
            uint32_t coeff = color_data[b];
            poly.push_back(coeff % modulus);
        }
    }

    return poly;
}

std::vector<uint8_t> encode_polynomial_vector_as_colors(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    std::vector<uint8_t> color_data;

    for (const auto& poly : poly_vector) {
        auto poly_colors = encode_polynomial_as_colors(poly, modulus);
        color_data.insert(color_data.end(), poly_colors.begin(), poly_colors.end());
    }

    return color_data;
}

std::vector<std::vector<uint32_t>> decode_colors_to_polynomial_vector(const std::vector<uint8_t>& color_data, uint32_t k, uint32_t n, uint32_t modulus) {
    size_t total_coeffs = k * n;
    if (color_data.size() != total_coeffs) {
        throw std::invalid_argument("Color data size does not match expected dimensions");
    }

    std::vector<std::vector<uint32_t>> poly_vector(k, std::vector<uint32_t>(n));

    size_t coeff_idx = 0;
    // Unpack from RGB format where each pixel contains up to 3 coefficients
    for (size_t pixel_start = 0; pixel_start < color_data.size() && coeff_idx < total_coeffs; pixel_start += 3) {
        size_t end = std::min(pixel_start + 3, color_data.size());
        for (size_t b = pixel_start; b < end && coeff_idx < total_coeffs; ++b) {
            size_t i = coeff_idx / n;
            size_t j = coeff_idx % n;
            poly_vector[i][j] = static_cast<uint32_t>(color_data[b]) % modulus;
            ++coeff_idx;
        }
    }

    return poly_vector;
}

// Compressed color encoding with variable-length encoding
std::vector<uint8_t> encode_polynomial_vector_as_colors_compressed(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    // Use the compressed packing format but maintain color compatibility
    // The compressed format is still compatible with color visualization since we can decode it back

    std::vector<uint8_t> compressed;
    compressed.reserve(1024);

    // Add format version and compression flag for color-compatible compression
    compressed.push_back(0x01); // Version 1
    compressed.push_back(0x03); // Compression flag (3 = color-compatible compressed)

    // Store number of polynomials and degree
    uint32_t k = poly_vector.size();
    uint32_t n = k > 0 ? poly_vector[0].size() : 0;

    compressed.push_back(static_cast<uint8_t>(k));
    compressed.push_back(static_cast<uint8_t>(n >> 8));
    compressed.push_back(static_cast<uint8_t>(n & 0xFF));

    // Color-compatible variable-length encoding
    // This maintains the ability to reconstruct the original color representation
    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            coeff %= modulus;

            // Color-compatible variable-length encoding
            if (coeff == 0) {
                compressed.push_back(0x00); // Single byte for zero
            } else if (coeff < 0x80) {
                compressed.push_back(static_cast<uint8_t>(coeff | 0x80)); // 1 byte
            } else if (coeff < 0x4000) {
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) | 0xC0));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF)); // 2 bytes
            } else if (coeff < 0x200000) {
                compressed.push_back(static_cast<uint8_t>((coeff >> 16) | 0xE0));
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) & 0xFF));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF)); // 3 bytes
            } else {
                // For larger values, use 4 bytes (standard color format)
                compressed.push_back(0xF0);
                compressed.push_back(static_cast<uint8_t>((coeff >> 16) & 0xFF));
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) & 0xFF));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF));
            }
        }
    }

    return compressed;
}

// Decode color-compatible compressed data back to polynomial vector
std::vector<std::vector<uint32_t>> decode_colors_to_polynomial_vector_compressed(const std::vector<uint8_t>& color_data, uint32_t k, uint32_t n, uint32_t modulus) {
    if (color_data.size() < 5) {
        throw std::invalid_argument("Compressed color data too small");
    }

    size_t offset = 0;
    uint8_t version = color_data[offset++];
    uint8_t compression_flag = color_data[offset++];

    // Validate version and compression flag
    if (version != 0x01 || compression_flag != 0x03) {
        throw std::invalid_argument("Unsupported color-compatible compression format");
    }

    // Read dimensions
    uint32_t data_k = color_data[offset++];
    uint32_t data_n = (static_cast<uint32_t>(color_data[offset]) << 8) | color_data[offset + 1];
    offset += 2;

    // Validate dimensions
    if (data_k != k || data_n != n) {
        throw std::invalid_argument("Dimension mismatch in compressed color data");
    }

    std::vector<std::vector<uint32_t>> poly_vector(k, std::vector<uint32_t>(n, 0));

    // Decode color-compatible compressed data
    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            if (offset >= color_data.size()) {
                throw std::invalid_argument("Truncated compressed color data");
            }

            uint8_t first_byte = color_data[offset++];
            uint32_t coeff = 0;

            if (first_byte == 0x00) {
                coeff = 0;
            } else if ((first_byte & 0xC0) == 0x80) {
                coeff = first_byte & 0x7F;
            } else if ((first_byte & 0xE0) == 0xC0) {
                if (offset >= color_data.size()) throw std::invalid_argument("Truncated compressed color data");
                coeff = ((first_byte & 0x3F) << 8) | color_data[offset++];
            } else if ((first_byte & 0xF0) == 0xE0) {
                if (offset + 1 >= color_data.size()) throw std::invalid_argument("Truncated compressed color data");
                coeff = ((first_byte & 0x0F) << 16) | (color_data[offset] << 8) | color_data[offset + 1];
                offset += 2;
            } else if (first_byte == 0xF0) {
                if (offset + 2 >= color_data.size()) throw std::invalid_argument("Truncated compressed color data");
                coeff = (color_data[offset] << 16) | (color_data[offset + 1] << 8) | color_data[offset + 2];
                offset += 3;
            } else {
                throw std::invalid_argument("Invalid color-compatible compression encoding");
            }

            poly_vector[i][j] = coeff % modulus;
        }
    }

    return poly_vector;
}

// Convert compressed polynomial data to standard color format for visualization
std::vector<uint8_t> convert_compressed_to_color_format(const std::vector<uint8_t>& compressed_data, uint32_t k, uint32_t n, uint32_t modulus) {
    // First decode the compressed data
    auto poly_vector = decode_colors_to_polynomial_vector_compressed(compressed_data, k, n, modulus);

    // Then encode as standard color format
    return encode_polynomial_vector_as_colors(poly_vector, modulus);
}

// Auto-select best compression method for color integration
std::vector<uint8_t> encode_polynomial_vector_as_colors_auto(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    // Count non-zero coefficients to determine sparsity
    size_t total_coeffs = 0;
    size_t non_zero_coeffs = 0;

    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            total_coeffs++;
            if ((coeff % modulus) != 0) {
                non_zero_coeffs++;
            }
        }
    }

    // If the data is sparse enough, use color-compatible compression
    // Otherwise use standard color format (which is already somewhat compressed for small values)
    if (non_zero_coeffs < total_coeffs * 0.7) { // 70% threshold for color-compatible compression
        return encode_polynomial_vector_as_colors_compressed(poly_vector, modulus);
    } else {
        return encode_polynomial_vector_as_colors(poly_vector, modulus);
    }
}

// Huffman-based color encoding with adaptive compression
std::vector<uint8_t> encode_polynomial_vector_as_colors_huffman(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    // Use the Huffman packing format but maintain color compatibility
    // The Huffman format is still compatible with color visualization since we can decode it back

    std::vector<uint8_t> compressed;
    compressed.reserve(1024);

    // Add format version and compression flag for color-compatible Huffman compression
    compressed.push_back(0x01); // Version 1
    compressed.push_back(0x05); // Compression flag (5 = color-compatible Huffman)

    // Store number of polynomials and degree
    uint32_t k = poly_vector.size();
    uint32_t n = k > 0 ? poly_vector[0].size() : 0;

    compressed.push_back(static_cast<uint8_t>(k));
    compressed.push_back(static_cast<uint8_t>(n >> 8));
    compressed.push_back(static_cast<uint8_t>(n & 0xFF));

    // Build Huffman table for this data
    auto huffman_table = build_huffman_table(poly_vector, modulus);

    // Encode using Huffman codes
    auto encoded_data = huffman_encode_polynomial_vector(poly_vector, huffman_table, modulus);

    // Combine table and encoded data
    // Add table size (4 bytes)
    uint32_t table_size = huffman_table.size();
    compressed.push_back(static_cast<uint8_t>(table_size >> 24));
    compressed.push_back(static_cast<uint8_t>(table_size >> 16));
    compressed.push_back(static_cast<uint8_t>(table_size >> 8));
    compressed.push_back(static_cast<uint8_t>(table_size & 0xFF));

    // Add Huffman table
    compressed.insert(compressed.end(), huffman_table.begin(), huffman_table.end());

    // Add encoded data
    compressed.insert(compressed.end(), encoded_data.begin(), encoded_data.end());

    return compressed;
}

// On-demand color generation from compressed data
std::vector<uint8_t> generate_color_representation_from_compressed(const std::vector<uint8_t>& compressed_data, uint32_t k, uint32_t n, uint32_t modulus) {
    // First decode the compressed data to polynomial vector
    auto poly_vector = unpack_polynomial_vector_compressed(compressed_data, k, n, modulus);

    // Then convert to standard color format for visualization
    return encode_polynomial_vector_as_colors(poly_vector, modulus);
}

// Dual-format compression with color metadata integration
std::vector<uint8_t> compress_with_color_support(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus, bool enable_color_metadata) {
    // First compress the polynomial data using auto-advanced compression
    auto compressed_data = pack_polynomial_vector_auto_advanced(poly_vector, modulus);

    // If color metadata is enabled, add color generation capabilities
    if (enable_color_metadata) {
        std::vector<uint8_t> dual_format_data;

        // Add dual-format header
        dual_format_data.push_back(0x02); // Version 2
        dual_format_data.push_back(0x01); // Dual-format flag

        // Store dimensions
        uint32_t k = poly_vector.size();
        uint32_t n = k > 0 ? poly_vector[0].size() : 0;

        dual_format_data.push_back(static_cast<uint8_t>(k));
        dual_format_data.push_back(static_cast<uint8_t>(n >> 8));
        dual_format_data.push_back(static_cast<uint8_t>(n & 0xFF));

        // Add modulus information
        dual_format_data.push_back(static_cast<uint8_t>(modulus >> 24));
        dual_format_data.push_back(static_cast<uint8_t>(modulus >> 16));
        dual_format_data.push_back(static_cast<uint8_t>(modulus >> 8));
        dual_format_data.push_back(static_cast<uint8_t>(modulus & 0xFF));

        // Add compressed cryptographic data
        dual_format_data.insert(dual_format_data.end(), compressed_data.begin(), compressed_data.end());

        // Add color metadata (optional, can be used for visualization hints)
        // For now, we'll add a simple color generation flag
        dual_format_data.push_back(0x01); // Color generation enabled

        return dual_format_data;
    }

    return compressed_data;
}

// Decompress dual-format data with color support
std::vector<std::vector<uint32_t>> decompress_with_color_support(const std::vector<uint8_t>& dual_format_data, uint32_t& out_k, uint32_t& out_n, uint32_t& out_modulus) {
    if (dual_format_data.size() < 8) {
        throw std::invalid_argument("Dual-format data too small");
    }

    size_t offset = 0;
    uint8_t version = dual_format_data[offset++];
    uint8_t format_flag = dual_format_data[offset++];

    // Read dimensions
    uint32_t k = dual_format_data[offset++];
    uint32_t n = (static_cast<uint32_t>(dual_format_data[offset]) << 8) | dual_format_data[offset + 1];
    offset += 2;

    // Read modulus
    uint32_t modulus = (static_cast<uint32_t>(dual_format_data[offset]) << 24) |
                      (static_cast<uint32_t>(dual_format_data[offset + 1]) << 16) |
                      (static_cast<uint32_t>(dual_format_data[offset + 2]) << 8) |
                      dual_format_data[offset + 3];
    offset += 4;

    // Set output parameters
    out_k = k;
    out_n = n;
    out_modulus = modulus;

    // Extract the compressed cryptographic data (skip color metadata for now)
    std::vector<uint8_t> compressed_crypto_data(dual_format_data.begin() + offset, dual_format_data.end());

    // Decompress the cryptographic data
    return unpack_polynomial_vector_compressed(compressed_crypto_data, k, n, modulus);
}

// Generate color representation from dual-format data
std::vector<uint8_t> generate_color_from_dual_format(const std::vector<uint8_t>& dual_format_data) {
    uint32_t k, n, modulus;

    // First decompress to get the polynomial data
    auto poly_vector = decompress_with_color_support(dual_format_data, k, n, modulus);

    // Then generate color representation
    return encode_polynomial_vector_as_colors(poly_vector, modulus);
}

// Advanced color integration with on-demand generation
std::vector<uint8_t> encode_polynomial_vector_with_color_integration(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus, bool enable_on_demand_color) {
    if (enable_on_demand_color) {
        // Use dual-format architecture for on-demand color generation
        return compress_with_color_support(poly_vector, modulus, true);
    } else {
        // Use standard color encoding
        return encode_polynomial_vector_as_colors_auto(poly_vector, modulus);
    }
}

// Decode color-integrated data with on-demand support
std::vector<std::vector<uint32_t>> decode_polynomial_vector_with_color_integration(const std::vector<uint8_t>& color_integrated_data, uint32_t modulus) {
    // Check if this is dual-format data
    if (color_integrated_data.size() >= 8 &&
        color_integrated_data[0] == 0x02 &&
        color_integrated_data[1] == 0x01) {
        // Dual-format data - extract cryptographic data
        uint32_t k, n, actual_modulus;
        return decompress_with_color_support(color_integrated_data, k, n, actual_modulus);
    } else {
        // Standard color format - decode normally
        uint32_t k = 1; // Default, will be adjusted
        uint32_t n = 1; // Default, will be adjusted

        // Try to determine dimensions from data size
        // Standard color format: 1 byte per coefficient
        n = color_integrated_data.size();
        return decode_colors_to_polynomial_vector(color_integrated_data, 1, n, modulus);
    }
}

} // namespace clwe