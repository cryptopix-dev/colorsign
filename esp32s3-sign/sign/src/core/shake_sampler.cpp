#include "clwe/shake_sampler.hpp"
#include "clwe/utils.hpp"
#include "clwe/tiny_sha3.h"
#include <cstring>
#include <algorithm>
#include <random>
#include <stdexcept>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace clwe {

SHAKE256Sampler::SHAKE256Sampler() {
    // ctx_ is sha3_ctx_t, no allocation needed
}

SHAKE256Sampler::~SHAKE256Sampler() {
    // No cleanup needed for sha3_ctx_t
}

void SHAKE256Sampler::reset() {
    // Reset by reinitializing
    shake256_init(&ctx_);
}

void SHAKE256Sampler::init(const uint8_t* seed, size_t seed_len) {
    reset();
    shake_update(&ctx_, seed, seed_len);
    shake_xof(&ctx_);
}

void IRAM_ATTR SHAKE256Sampler::squeeze(uint8_t* out, size_t len) {
    shake_out(&ctx_, out, len);
}

void IRAM_ATTR SHAKE256Sampler::random_bytes(uint8_t* out, size_t len) {
    squeeze(out, len);
}

int32_t SHAKE256Sampler::sample_binomial_coefficient(uint32_t eta) {
    // Sample from centered binomial distribution B(2η, 0.5) - η
    // Count the number of 1s in 2η random bits, then subtract η
    uint32_t count_ones = 0;
    size_t num_bytes = (2 * eta + 7) / 8; // Enough bytes for 2η bits
    std::vector<uint8_t> bytes(num_bytes);
    random_bytes(bytes.data(), num_bytes);

    for (uint32_t i = 0; i < 2 * eta; ++i) {
        uint8_t byte = bytes[i / 8];
        uint8_t bit = (byte >> (i % 8)) & 1;
        count_ones += bit;
    }

    return static_cast<int32_t>(count_ones) - static_cast<int32_t>(eta);
}

void SHAKE256Sampler::sample_polynomial_binomial(uint32_t* coeffs, size_t degree,
                                                uint32_t eta, uint32_t modulus) {
    for (size_t i = 0; i < degree; ++i) {
        int32_t sample = sample_binomial_coefficient(eta);
        // Map to positive range: (sample mod modulus + modulus) mod modulus
        coeffs[i] = (sample % static_cast<int32_t>(modulus) + modulus) % modulus;
    }
}

void SHAKE256Sampler::sample_polynomial_binomial_batch(uint32_t** coeffs_batch, size_t count,
                                                     size_t degree, uint32_t eta, uint32_t modulus) {
    for (size_t poly = 0; poly < count; ++poly) {
        sample_polynomial_binomial(coeffs_batch[poly], degree, eta, modulus);
    }
}

void SHAKE256Sampler::sample_polynomial_binomial_batch_avx512(uint32_t** coeffs_batch, size_t count,
                                                             size_t degree, uint32_t eta, uint32_t modulus) {
    // For now, fall back to scalar implementation
    // In production, this would use AVX-512 instructions for parallel sampling
    sample_polynomial_binomial_batch(coeffs_batch, count, degree, eta, modulus);
}

uint32_t SHAKE256Sampler::sample_uniform(uint32_t modulus) {
    // Sample uniformly from [0, modulus)
    // Use rejection sampling for uniform distribution
#ifdef _MSC_VER
    unsigned long index;
    _BitScanReverse(&index, modulus - 1);
    uint32_t mask = (1U << (index + 1)) - 1;
#else
    uint32_t mask = (1U << (32 - __builtin_clz(modulus - 1))) - 1;
#endif

    while (true) {
        uint8_t bytes[4];
        random_bytes(bytes, 4);

        uint32_t sample = (bytes[0] << 24) | (bytes[1] << 16) |
                         (bytes[2] << 8) | bytes[3];
        sample &= mask;

        if (sample < modulus) {
            return sample;
        }
    }
}

void SHAKE256Sampler::sample_polynomial_uniform(uint32_t* coeffs, size_t degree, uint32_t modulus) {
    for (size_t i = 0; i < degree; ++i) {
        coeffs[i] = sample_uniform(modulus);
    }
}

// SHAKE128Sampler implementation for Kyber matrix generation
SHAKE128Sampler::SHAKE128Sampler() {
    // ctx_ is sha3_ctx_t, no allocation needed
}

SHAKE128Sampler::~SHAKE128Sampler() {
    // No cleanup needed for sha3_ctx_t
}

void SHAKE128Sampler::reset() {
    // Reset by reinitializing
    shake128_init(&ctx_);
}

void SHAKE128Sampler::init(const uint8_t* seed, size_t seed_len) {
    reset();
    shake_update(&ctx_, seed, seed_len);
    shake_xof(&ctx_);
}

void IRAM_ATTR SHAKE128Sampler::squeeze(uint8_t* out, size_t len) {
    shake_out(&ctx_, out, len);
}

uint32_t SHAKE128Sampler::sample_uniform(uint32_t modulus) {
    // Sample uniformly from [0, modulus)
    // Use rejection sampling for uniform distribution
#ifdef _MSC_VER
    unsigned long index;
    _BitScanReverse(&index, modulus - 1);
    uint32_t mask = (1U << (index + 1)) - 1;
#else
    uint32_t mask = (1U << (32 - __builtin_clz(modulus - 1))) - 1;
#endif

    while (true) {
        uint8_t bytes[4];
        squeeze(bytes, 4);

        uint32_t sample = (bytes[0] << 24) | (bytes[1] << 16) |
                          (bytes[2] << 8) | bytes[3];
        sample &= mask;

        if (sample < modulus) {
            return sample;
        }
    }
}

} // namespace clwe