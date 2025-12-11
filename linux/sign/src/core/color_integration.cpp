#include "../include/clwe/color_integration.hpp"
#include <stdexcept>

namespace clwe {

std::vector<uint8_t> encode_polynomial_as_colors(const std::vector<uint32_t>& poly, uint32_t modulus) {
    std::vector<uint8_t> color_data;

    for (uint32_t coeff : poly) {
        coeff %= modulus;
        color_data.push_back((coeff >> 24) & 0xFF);
        color_data.push_back((coeff >> 16) & 0xFF);
        color_data.push_back((coeff >> 8) & 0xFF);
        color_data.push_back(coeff & 0xFF);
    }

    return color_data;
}

std::vector<uint32_t> decode_colors_to_polynomial(const std::vector<uint8_t>& color_data, uint32_t modulus) {
    if (color_data.size() % 4 != 0) {
        throw std::invalid_argument("Color data size must be multiple of 4");
    }

    std::vector<uint32_t> poly;
    poly.reserve(color_data.size() / 4);

    for (size_t i = 0; i < color_data.size(); i += 4) {
        uint32_t coeff = ((uint32_t)color_data[i] << 24) |
                         ((uint32_t)color_data[i + 1] << 16) |
                         ((uint32_t)color_data[i + 2] << 8) |
                         (uint32_t)color_data[i + 3];
        poly.push_back(coeff % modulus);
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
    if (color_data.size() != k * n * 4) {
        throw std::invalid_argument("Color data size does not match expected dimensions");
    }

    std::vector<std::vector<uint32_t>> poly_vector(k, std::vector<uint32_t>(n));

    size_t idx = 0;
    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            uint32_t coeff = ((uint32_t)color_data[idx] << 24) |
                             ((uint32_t)color_data[idx + 1] << 16) |
                             ((uint32_t)color_data[idx + 2] << 8) |
                             (uint32_t)color_data[idx + 3];
            poly_vector[i][j] = coeff % modulus;
            idx += 4;
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

}