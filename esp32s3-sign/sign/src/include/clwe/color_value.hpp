/**
 * @file color_value.hpp
 * @brief Color value representation for ColorKEM cryptographic operations
 *
 * This header defines the ColorValue structure, which represents RGBA color
 * values used as coefficients in lattice-based cryptographic operations.
 * The color representation enables visual interpretation of mathematical
 * computations while maintaining cryptographic security.
 *
 * @author ColorKEM Development Team
 * @version 1.0.0
 * @date 2024
 */

#ifndef COLOR_VALUE_HPP
#define COLOR_VALUE_HPP

#include <cstdint>
#include <iostream>

namespace clwe {

/**
 * @brief Represents an RGBA color value used in Color-CLWE cryptographic operations.
 *
 * In the Color-CLWE scheme, colors serve as coefficients in ring elements (polynomials)
 * over the ring R_q = Z_q[X]/(X^n + 1), where q is a prime modulus and n is the ring dimension.
 *
 * Mapping from RGBA to Ring Elements:
 * - Each ColorValue (r, g, b, a) is packed into a single 32-bit unsigned integer via to_math_value():
 *   value = (r << 24) | (g << 16) | (b << 8) | a
 * - This packed value is treated as a coefficient in Z_q, i.e., coefficient ≡ value mod q
 * - For polynomial operations, each coefficient is a ColorValue, allowing visual interpretation
 *   of cryptographic computations while maintaining mathematical equivalence to standard LWE/CLWE.
 *
 * Mathematical Equivalence:
 * - Arithmetic operations (addition, subtraction, multiplication) are performed modulo q
 *   on the packed uint32_t representation, preserving the algebraic structure of the ring.
 * - The color channels (r,g,b,a) provide a visual representation but do not affect the
 *   underlying mathematical operations, which operate on the full 32-bit packed value.
 * - This allows cryptographic schemes to be "colored" for visualization while maintaining
 *   the security properties of the underlying lattice-based cryptography.
 */
struct ColorValue {
    uint8_t r, g, b, a;  /**< RGBA color components (0-255 each) */

    /**
     * @brief Default constructor - creates opaque black color
     *
     * Initializes color to (0, 0, 0, 255) representing opaque black.
     */
    ColorValue() : r(0), g(0), b(0), a(255) {}

    /**
     * @brief Construct color with specified RGBA values
     *
     * @param red Red component (0-255)
     * @param green Green component (0-255)
     * @param blue Blue component (0-255)
     * @param alpha Alpha component (0-255), defaults to 255 (opaque)
     */
    ColorValue(uint8_t red, uint8_t green, uint8_t blue, uint8_t alpha = 255)
        : r(red), g(green), b(blue), a(alpha) {}

    /**
     * @brief Convert color to mathematical value for cryptographic operations
     *
     * Packs the RGBA components into a single 32-bit unsigned integer:
     * value = (r << 24) | (g << 16) | (b << 8) | a
     *
     * This packed value is used as a coefficient in polynomial arithmetic.
     *
     * @return uint32_t Packed 32-bit mathematical representation
     */
    uint32_t to_math_value() const {
        return (static_cast<uint32_t>(r) << 24) |
               (static_cast<uint32_t>(g) << 16) |
               (static_cast<uint32_t>(b) << 8) |
               static_cast<uint32_t>(a);
    }

    /**
     * @brief Create color from mathematical value
     *
     * Unpacks a 32-bit mathematical value back into RGBA components:
     * r = (value >> 24) & 0xFF
     * g = (value >> 16) & 0xFF
     * b = (value >> 8) & 0xFF
     * a = value & 0xFF
     *
     * @param value 32-bit mathematical value to unpack
     * @return ColorValue Color representation of the mathematical value
     */
    static ColorValue from_math_value(uint32_t value) {
        return ColorValue(
            (value >> 24) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF
        );
    }

    /**
     * @brief Convert to precise 64-bit representation
     *
     * Creates a higher-precision representation using RGB channels only:
     * value = (r << 32) | (g << 16) | b
     *
     * Used for operations requiring more precision than 32 bits.
     *
     * @return uint64_t 64-bit precise representation
     */
    uint64_t to_precise_value() const {
        return (static_cast<uint64_t>(r) << 32) |
               (static_cast<uint64_t>(g) << 16) |
               static_cast<uint64_t>(b);
    }

    /**
     * @brief Create color from precise 64-bit value
     *
     * @param value 64-bit precise value to convert
     * @return ColorValue Color with alpha set to 255 (opaque)
     */
    static ColorValue from_precise_value(uint64_t value) {
        return ColorValue(
            (value >> 32) & 0xFF,
            (value >> 16) & 0xFF,
            value & 0xFF,
            255
        );
    }

    /**
     * @brief Modular addition of color values
     *
     * Performs (this + other) mod modulus on the mathematical representations.
     *
     * @param other Color value to add
     * @param modulus Prime modulus for the operation
     * @return ColorValue Result of modular addition
     */
    ColorValue mod_add(const ColorValue& other, uint32_t modulus) const;

    /**
     * @brief Modular subtraction of color values
     *
     * Performs (this - other) mod modulus on the mathematical representations.
     *
     * @param other Color value to subtract
     * @param modulus Prime modulus for the operation
     * @return ColorValue Result of modular subtraction
     */
    ColorValue mod_subtract(const ColorValue& other, uint32_t modulus) const;

    /**
     * @brief Modular multiplication of color values
     *
     * Performs (this * other) mod modulus on the mathematical representations.
     *
     * @param other Color value to multiply by
     * @param modulus Prime modulus for the operation
     * @return ColorValue Result of modular multiplication
     */
    ColorValue mod_multiply(const ColorValue& other, uint32_t modulus) const;

    /**
     * @brief Convert RGB color to HSV representation
     *
     * @return ColorValue HSV representation (H in r, S in g, V in b, a unchanged)
     */
    ColorValue to_hsv() const;

    /**
     * @brief Convert HSV color back to RGB representation
     *
     * @return ColorValue RGB representation
     */
    ColorValue from_hsv() const;

    /**
     * @brief Equality comparison operator
     *
     * Compares all RGBA components for exact equality.
     *
     * @param other Color value to compare against
     * @return bool True if all components are equal
     */
    bool operator==(const ColorValue& other) const {
        return r == other.r && g == other.g && b == other.b && a == other.a;
    }

    /**
     * @brief Inequality comparison operator
     *
     * @param other Color value to compare against
     * @return bool True if any component differs
     */
    bool operator!=(const ColorValue& other) const {
        return !(*this == other);
    }

    /**
     * @brief Convert color to human-readable string
     *
     * @return std::string String representation in format "(r,g,b,a)"
     */
    std::string to_string() const;

    /**
     * @brief Print color to standard output
     *
     * Outputs the color's string representation followed by a newline.
     */
};

/**
 * @brief Color arithmetic operations namespace
 *
 * Provides optimized functions for performing arithmetic operations on ColorValue
 * objects. Includes both scalar implementations and SIMD-accelerated versions
 * for different CPU architectures.
 */
namespace color_ops {

    /**
     * @brief Add two color values
     *
     * Performs component-wise addition of RGBA values, clamping to 255.
     *
     * @param a First color value
     * @param b Second color value
     * @return ColorValue Sum of the two colors
     */
    ColorValue add_colors(const ColorValue& a, const ColorValue& b);

    /**
     * @brief Multiply two color values
     *
     * Performs component-wise multiplication of RGBA values, scaling by 255.
     *
     * @param a First color value
     * @param b Second color value
     * @return ColorValue Product of the two colors
     */
    ColorValue multiply_colors(const ColorValue& a, const ColorValue& b);

    /**
     * @brief Reduce color value modulo a prime
     *
     * Applies modular reduction to the mathematical representation of the color.
     *
     * @param c Color value to reduce
     * @param modulus Prime modulus for reduction
     * @return ColorValue Color representing the reduced value
     */
    ColorValue mod_reduce_color(const ColorValue& c, uint32_t modulus);

    /** @brief AVX-512 SIMD operations (available when HAVE_AVX512 is defined) */
    #ifdef HAVE_AVX512
    /**
     * @brief AVX-512 vectorized color addition
     * @param a AVX-512 vector of color values
     * @param b AVX-512 vector of color values
     * @return __m512i Vector sum
     */
    __m512i add_colors_avx512(__m512i a, __m512i b);

    /**
     * @brief AVX-512 vectorized color multiplication
     * @param a AVX-512 vector of color values
     * @param b AVX-512 vector of color values
     * @return __m512i Vector product
     */
    __m512i multiply_colors_avx512(__m512i a, __m512i b);

    /**
     * @brief AVX-512 vectorized modular reduction
     * @param c AVX-512 vector of color values
     * @param modulus Prime modulus
     * @return __m512i Vector of reduced values
     */
    __m512i mod_reduce_colors_avx512(__m512i c, uint32_t modulus);
    #endif

    /** @brief ARM NEON SIMD operations (available when __ARM_NEON is defined) */
    #ifdef __ARM_NEON
    #include <arm_neon.h>

    /**
     * @brief NEON vectorized color addition
     * @param a NEON vector of color values
     * @param b NEON vector of color values
     * @return uint32x4_t Vector sum
     */
    uint32x4_t add_colors_neon(uint32x4_t a, uint32x4_t b);

    /**
     * @brief NEON vectorized color multiplication
     * @param a NEON vector of color values
     * @param b NEON vector of color values
     * @return uint32x4_t Vector product
     */
    uint32x4_t multiply_colors_neon(uint32x4_t a, uint32x4_t b);

    /**
     * @brief NEON vectorized modular reduction
     * @param c NEON vector of color values
     * @param modulus Prime modulus
     * @return uint32x4_t Vector of reduced values
     */
    uint32x4_t mod_reduce_colors_neon(uint32x4_t c, uint32_t modulus);
    #endif

    /**
     * @brief SIMD-accelerated color addition (auto-dispatches to available SIMD)
     *
     * Automatically selects the best available SIMD implementation based on
     * CPU capabilities (AVX-512, AVX2, NEON, or scalar fallback).
     *
     * @param a First color value
     * @param b Second color value
     * @return ColorValue SIMD-accelerated sum
     */
    ColorValue add_colors_simd(const ColorValue& a, const ColorValue& b);

    /**
     * @brief SIMD-accelerated color multiplication
     *
     * @param a First color value
     * @param b Second color value
     * @return ColorValue SIMD-accelerated product
     */
    ColorValue multiply_colors_simd(const ColorValue& a, const ColorValue& b);

    /**
     * @brief SIMD-accelerated modular reduction
     *
     * @param c Color value to reduce
     * @param modulus Prime modulus
     * @return ColorValue SIMD-accelerated reduction result
     */
    ColorValue mod_reduce_color_simd(const ColorValue& c, uint32_t modulus);

};

} // namespace clwe

#endif // COLOR_VALUE_HPP