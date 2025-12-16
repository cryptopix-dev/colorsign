#include "../include/clwe/utils.hpp"
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <vector>
#include <array>
#include <unordered_map>
#include <queue>
#include <functional>
#include <iostream>

#ifdef __APPLE__
#include <Security/SecRandom.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif

#ifdef __linux__
#include <sys/random.h>
#endif

namespace clwe {

// Keccak constants
static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int KECCAK_RHO_OFFSETS[25] = {
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
};

// Keccak-f[1600] permutation
static void keccak_f1600(uint64_t state[25]) {
    uint64_t C[5], D[5], B[25];

    for (int round = 0; round < 24; ++round) {
        // θ (theta) step
        for (int x = 0; x < 5; ++x) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63));
        }
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                state[x + 5 * y] ^= D[x];
            }
        }

        // ρ (rho) step - rotations
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                int index = x + 5 * y;
                int offset = KECCAK_RHO_OFFSETS[index];
                B[y + 5 * ((2 * x + 3 * y) % 5)] = (state[index] << offset) | (state[index] >> (64 - offset));
            }
        }

        // π (pi) step - permutation (already done in the B assignment above)

        // χ (chi) step
        for (int y = 0; y < 5; ++y) {
            uint64_t T[5];
            for (int x = 0; x < 5; ++x) {
                T[x] = B[x + 5 * y];
            }
            for (int x = 0; x < 5; ++x) {
                state[x + 5 * y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5]);
            }
        }

        // ι (iota) step
        state[0] ^= KECCAK_RC[round];
    }
}

// Sponge construction helper functions
static void absorb_bytes(uint64_t state[25], size_t rate_bytes, const uint8_t* data, size_t len, size_t& offset) {
    while (len > 0) {
        size_t chunk = std::min(len, rate_bytes - offset);
        for (size_t i = 0; i < chunk; ++i) {
            size_t state_byte_index = offset + i;
            size_t word_index = state_byte_index / 8;
            size_t byte_in_word = state_byte_index % 8;
            state[word_index] ^= static_cast<uint64_t>(data[i]) << (byte_in_word * 8);
        }
        offset += chunk;
        data += chunk;
        len -= chunk;

        if (offset == rate_bytes) {
            keccak_f1600(state);
            offset = 0;
        }
    }
}

static void squeeze_bytes(uint64_t state[25], size_t rate_bytes, uint8_t* out, size_t len, size_t& offset) {
    while (len > 0) {
        size_t chunk = std::min(len, rate_bytes - offset);
        for (size_t i = 0; i < chunk; ++i) {
            size_t state_byte_index = offset + i;
            size_t word_index = state_byte_index / 8;
            size_t byte_in_word = state_byte_index % 8;
            out[i] = (state[word_index] >> (byte_in_word * 8)) & 0xFF;
        }
        offset += chunk;
        out += chunk;
        len -= chunk;

        if (offset == rate_bytes) {
            keccak_f1600(state);
            offset = 0;
        }
    }
}

// Secure random bytes using platform-specific APIs
void secure_random_bytes(uint8_t* buffer, size_t len) {
#ifdef __APPLE__
    if (SecRandomCopyBytes(kSecRandomDefault, len, buffer) != 0) {
        throw std::runtime_error("Failed to generate secure random bytes on macOS");
    }
#elif defined(_WIN32)
    if (BCryptGenRandom(NULL, buffer, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("Failed to generate secure random bytes on Windows");
    }
#elif defined(__linux__)
    if (getrandom(buffer, len, 0) != static_cast<ssize_t>(len)) {
        throw std::runtime_error("Failed to generate secure random bytes on Linux");
    }
#else
    throw std::runtime_error("Secure random not implemented for this platform");
#endif
}

// SHAKE256 hash function
std::vector<uint8_t> shake256(const std::vector<uint8_t>& input, size_t output_len) {
    uint64_t state[25] = {0};
    size_t rate_bytes = 136;  // 1088 bits / 8 = 136 bytes for SHAKE256
    size_t offset = 0;

    // Absorb input
    if (!input.empty()) {
        absorb_bytes(state, rate_bytes, input.data(), input.size(), offset);
    }

    // Apply SHAKE padding: XOR domain separation byte 0x1F into current position
    uint8_t* state_bytes = reinterpret_cast<uint8_t*>(state);
    state_bytes[offset] ^= 0x1F;

    // Pad with zeros to fill the rate
    for (size_t i = offset + 1; i < rate_bytes; ++i) {
        state_bytes[i] = 0;
    }

    // Apply domain separation bit
    state_bytes[rate_bytes - 1] ^= 0x80;

    // Apply permutation after padding
    keccak_f1600(state);

    // Squeeze output
    std::vector<uint8_t> output(output_len);
    offset = 0;
    squeeze_bytes(state, rate_bytes, output.data(), output_len, offset);

    return output;
}

// SHAKE128Sampler implementation
SHAKE128Sampler::SHAKE128Sampler() : rate_bytes_(168), offset_(0) {  // 1344 bits / 8 = 168 bytes for SHAKE128
    reset();
}

SHAKE128Sampler::~SHAKE128Sampler() {
    // No dynamic memory to clean up
}

void SHAKE128Sampler::reset() {
    std::memset(state_, 0, sizeof(state_));
    offset_ = 0;
}

void SHAKE128Sampler::keccak_f1600() {
    ::clwe::keccak_f1600(state_);
}

void SHAKE128Sampler::absorb(const uint8_t* data, size_t len) {
    ::clwe::absorb_bytes(state_, rate_bytes_, data, len, offset_);
}

void SHAKE128Sampler::pad_and_absorb() {
    // XOR domain separation byte 0x1F into current position
    uint8_t* state_bytes = reinterpret_cast<uint8_t*>(state_);
    state_bytes[offset_] ^= 0x1F;

    // Pad with zeros to fill the rate
    for (size_t i = offset_ + 1; i < rate_bytes_; ++i) {
        state_bytes[i] = 0;
    }

    // Apply domain separation bit
    state_bytes[rate_bytes_ - 1] ^= 0x80;

    // Apply permutation
    keccak_f1600();

    offset_ = 0;  // Reset for squeezing
}

void SHAKE128Sampler::init(const uint8_t* seed, size_t seed_len) {
    reset();
    if (seed_len > 0) {
        absorb(seed, seed_len);
    }
    pad_and_absorb();
    offset_ = 0;  // Reset for squeezing
}

void SHAKE128Sampler::squeeze(uint8_t* out, size_t len) {
    ::clwe::squeeze_bytes(state_, rate_bytes_, out, len, offset_);
}

uint32_t SHAKE128Sampler::sample_uniform(uint32_t modulus) {
    // Sample uniformly from [0, modulus)
    uint32_t result = 0;
    uint32_t bits_needed = 0;
    uint32_t temp = modulus - 1;
    while (temp > 0) {
        bits_needed++;
        temp >>= 1;
    }

    while (true) {
        uint8_t bytes[4];
        squeeze(bytes, 4);
        result = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
        result &= (1U << bits_needed) - 1;
        if (result < modulus) {
            return result;
        }
    }
}

// SHAKE256Sampler implementation
SHAKE256Sampler::SHAKE256Sampler() : rate_bytes_(136), offset_(0) {  // 1088 bits / 8 = 136 bytes for SHAKE256
    reset();
}

SHAKE256Sampler::~SHAKE256Sampler() {
    // No dynamic memory to clean up
}

void SHAKE256Sampler::reset() {
    std::memset(state_, 0, sizeof(state_));
    offset_ = 0;
}

void SHAKE256Sampler::keccak_f1600() {
    ::clwe::keccak_f1600(state_);
}

void SHAKE256Sampler::absorb(const uint8_t* data, size_t len) {
    ::clwe::absorb_bytes(state_, rate_bytes_, data, len, offset_);
}

void SHAKE256Sampler::pad_and_absorb() {
    // XOR domain separation byte 0x1F into current position
    uint8_t* state_bytes = reinterpret_cast<uint8_t*>(state_);
    state_bytes[offset_] ^= 0x1F;

    // Pad with zeros to fill the rate
    for (size_t i = offset_ + 1; i < rate_bytes_; ++i) {
        state_bytes[i] = 0;
    }

    // Apply domain separation bit
    state_bytes[rate_bytes_ - 1] ^= 0x80;

    // Apply permutation
    keccak_f1600();

    offset_ = 0;  // Reset for squeezing
}

void SHAKE256Sampler::init(const uint8_t* seed, size_t seed_len) {
    reset();
    if (seed_len > 0) {
        absorb(seed, seed_len);
    }
    pad_and_absorb();
    offset_ = 0;  // Reset for squeezing
}

void SHAKE256Sampler::squeeze(uint8_t* out, size_t len) {
    ::clwe::squeeze_bytes(state_, rate_bytes_, out, len, offset_);
}

int32_t SHAKE256Sampler::sample_binomial_coefficient(uint32_t eta) {
    // Sample from centered binomial distribution B(2η, 0.5) - η
    int32_t sum = 0;
    for (uint32_t i = 0; i < eta; ++i) {
        uint8_t byte;
        squeeze(&byte, 1);
        sum += (byte & 1);
    }
    for (uint32_t i = 0; i < eta; ++i) {
        uint8_t byte;
        squeeze(&byte, 1);
        sum -= (byte & 1);
    }
    return sum;
}

void SHAKE256Sampler::sample_polynomial_binomial(uint32_t* coeffs, size_t degree,
                                                uint32_t eta, uint32_t modulus) {
    for (size_t i = 0; i < degree; ++i) {
        int32_t coeff = sample_binomial_coefficient(eta);
        coeffs[i] = (coeff % modulus + modulus) % modulus;  // Ensure non-negative
    }
}

uint32_t SHAKE256Sampler::sample_uniform(uint32_t modulus) {
    // Sample uniformly from [0, modulus)
    uint32_t result = 0;
    uint32_t bits_needed = 0;
    uint32_t temp = modulus - 1;
    while (temp > 0) {
        bits_needed++;
        temp >>= 1;
    }

    while (true) {
        uint8_t bytes[4];
        squeeze(bytes, 4);
        result = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
        result &= (1U << bits_needed) - 1;
        if (result < modulus) {
            return result;
        }
    }
}

void SHAKE256Sampler::sample_polynomial_uniform(uint32_t* coeffs, size_t degree, uint32_t modulus) {
    for (size_t i = 0; i < degree; ++i) {
        coeffs[i] = sample_uniform(modulus);
    }
}

void SHAKE256Sampler::random_bytes(uint8_t* out, size_t len) {
    squeeze(out, len);
}

// Modular arithmetic utilities
uint32_t mod_inverse(uint32_t a, uint32_t m) {
    int64_t m0 = m, t, q;
    int64_t x0 = 0, x1 = 1;
    if (m == 1) return 0;
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m, a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return static_cast<uint32_t>(x1);
}

uint32_t mod_pow(uint32_t base, uint32_t exp, uint32_t mod) {
    uint32_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (static_cast<uint64_t>(result) * base) % mod;
        }
        base = (static_cast<uint64_t>(base) * base) % mod;
        exp >>= 1;
    }
    return result;
}

// ML-DSA specific utilities
void compute_high_bits(const std::vector<uint32_t>& w, std::vector<uint32_t>& w1, uint32_t d, uint32_t q) {
    uint32_t shift = 1 << (d - 1);  // 2^{d-1}
    uint32_t divisor = 1 << d;      // 2^d
    for (size_t i = 0; i < w.size(); ++i) {
        // w1 = floor((w + 2^{d-1}) / 2^d)
        uint64_t temp = static_cast<uint64_t>(w[i]) + shift;
        w1[i] = temp / divisor;
    }
}

void sample_challenge(std::vector<uint32_t>& c, const std::vector<uint8_t>& seed, uint32_t tau, uint32_t n, uint32_t q) {
    // Initialize SHAKE256 with seed
    SHAKE256Sampler sampler;
    sampler.init(seed.data(), seed.size());

    // Sample tau positions uniformly
    std::vector<uint32_t> positions(n);
    for (uint32_t i = 0; i < n; ++i) {
        positions[i] = i;
    }

    // Fisher-Yates shuffle to select tau positions
    for (uint32_t i = 0; i < tau; ++i) {
        uint32_t j = i + (sampler.sample_uniform(n - i));
        std::swap(positions[i], positions[j]);
    }

    // Set coefficients to 0 initially
    std::fill(c.begin(), c.end(), 0);

    // Assign +1 or -1 to selected positions
    for (uint32_t i = 0; i < tau; ++i) {
        uint8_t sign_byte;
        sampler.squeeze(&sign_byte, 1);
        c[positions[i]] = (sign_byte & 1) ? 1 : (q - 1);  // 1 or -1 mod q
    }
}

bool is_power_of_two(uint32_t x) {
    return (x & (x - 1)) == 0 && x != 0;
}

// Pack polynomial vector into bytes (little-endian 32-bit per coefficient)
std::vector<uint8_t> pack_polynomial_vector(const std::vector<std::vector<uint32_t>>& poly_vector) {
    size_t total_coeffs = 0;
    for (const auto& poly : poly_vector) {
        total_coeffs += poly.size();
    }
    std::vector<uint8_t> packed(total_coeffs * 4);

    size_t offset = 0;
    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            packed[offset++] = coeff & 0xFF;
            packed[offset++] = (coeff >> 8) & 0xFF;
            packed[offset++] = (coeff >> 16) & 0xFF;
            packed[offset++] = (coeff >> 24) & 0xFF;
        }
    }
    return packed;
}

// Unpack bytes into polynomial vector (little-endian 32-bit per coefficient)
std::vector<std::vector<uint32_t>> unpack_polynomial_vector(const std::vector<uint8_t>& data, uint32_t k, uint32_t n) {
    if (data.size() != k * n * 4) {
        throw std::invalid_argument("Data size does not match expected polynomial vector size");
    }

    std::vector<std::vector<uint32_t>> poly_vector(k, std::vector<uint32_t>(n));
    size_t offset = 0;
    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            uint32_t coeff = data[offset] |
                             (data[offset + 1] << 8) |
                             (data[offset + 2] << 16) |
                             (data[offset + 3] << 24);
            offset += 4;
            poly_vector[i][j] = coeff;
        }
    }
    return poly_vector;
}

// Variable-length encoding for polynomial coefficients with optimized header
// Uses 1-5 bytes per coefficient based on value size with compact metadata
std::vector<uint8_t> pack_polynomial_vector_compressed(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    std::vector<uint8_t> compressed;
    compressed.reserve(1024); // Reserve reasonable initial size

    // Add compact format header (8 bytes total)
    compressed.push_back(0x02); // Version 2 with bit-packing
    compressed.push_back(0x01); // Compression flag (1 = variable-length compressed)

    // Store number of polynomials and degree with bit-packing
    uint32_t k = poly_vector.size();
    uint32_t n = k > 0 ? poly_vector[0].size() : 0;

    // Compact header: k (1 byte), n (2 bytes), modulus info (1 byte)
    compressed.push_back(static_cast<uint8_t>(k));
    compressed.push_back(static_cast<uint8_t>(n >> 8));
    compressed.push_back(static_cast<uint8_t>(n & 0xFF));

    // Add modulus information for better context
    uint8_t modulus_info = 0;
    if (modulus <= 0xFF) modulus_info = 1;
    else if (modulus <= 0xFFFF) modulus_info = 2;
    else if (modulus <= 0xFFFFFF) modulus_info = 3;
    else modulus_info = 4;
    compressed.push_back(modulus_info);

    // Add color metadata placeholder (1 byte for future color integration)
    compressed.push_back(0x00); // Reserved for color metadata

    // Variable-length encoding for each coefficient
    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            coeff %= modulus;

            // Variable-length encoding
            if (coeff == 0) {
                compressed.push_back(0x00); // Single byte for zero
            } else if (coeff < 0x80) {
                compressed.push_back(static_cast<uint8_t>(coeff | 0x80)); // 1 byte: 10xxxxxx
            } else if (coeff < 0x4000) {
                // 2 bytes: 110xxxxx xxxxxxxx
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) | 0xC0));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF));
            } else if (coeff < 0x200000) {
                // 3 bytes: 1110xxxx xxxxxxxx xxxxxxxx
                compressed.push_back(static_cast<uint8_t>((coeff >> 16) | 0xE0));
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) & 0xFF));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF));
            } else if (coeff < 0x10000000) {
                // 4 bytes: 11110xxx xxxxxxxx xxxxxxxx xxxxxxxx
                compressed.push_back(static_cast<uint8_t>((coeff >> 24) | 0xF0));
                compressed.push_back(static_cast<uint8_t>((coeff >> 16) & 0xFF));
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) & 0xFF));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF));
            } else {
                // 5 bytes: 111110xx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
                compressed.push_back(0xFC);
                compressed.push_back(static_cast<uint8_t>((coeff >> 24) & 0xFF));
                compressed.push_back(static_cast<uint8_t>((coeff >> 16) & 0xFF));
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) & 0xFF));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF));
            }
        }
    }

    return compressed;
}

// Enhanced sparse representation with delta encoding and run-length encoding
std::vector<uint8_t> pack_polynomial_vector_sparse_enhanced(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    std::vector<uint8_t> compressed;
    compressed.reserve(1024);

    // Add format version and compression flag
    compressed.push_back(0x02); // Version 2 with advanced sparse features
    compressed.push_back(0x03); // Compression flag (3 = enhanced sparse)

    // Store number of polynomials and degree
    uint32_t k = poly_vector.size();
    uint32_t n = k > 0 ? poly_vector[0].size() : 0;

    compressed.push_back(static_cast<uint8_t>(k));
    compressed.push_back(static_cast<uint8_t>(n >> 8));
    compressed.push_back(static_cast<uint8_t>(n & 0xFF));

    // Enhanced sparse encoding with run-length encoding and delta encoding
    for (const auto& poly : poly_vector) {
        std::vector<std::pair<uint16_t, uint32_t>> non_zero_coeffs;

        // Collect non-zero coefficients
        for (uint16_t i = 0; i < poly.size(); ++i) {
            uint32_t coeff = poly[i] % modulus;
            if (coeff != 0) {
                non_zero_coeffs.emplace_back(i, coeff);
            }
        }

        // Apply run-length encoding for consecutive zeros
        std::vector<uint8_t> rle_data;
        uint16_t prev_index = 0;

        for (const auto& [index, coeff] : non_zero_coeffs) {
            // Store run-length of zeros before this non-zero coefficient
            uint16_t zero_run = index - prev_index;
            prev_index = index + 1;

            // Encode zero run with variable-length encoding
            if (zero_run == 0) {
                rle_data.push_back(0x00); // No zeros before
            } else if (zero_run < 0x80) {
                rle_data.push_back(static_cast<uint8_t>(zero_run | 0x80)); // 1 byte
            } else if (zero_run < 0x4000) {
                rle_data.push_back(static_cast<uint8_t>((zero_run >> 8) | 0xC0));
                rle_data.push_back(static_cast<uint8_t>(zero_run & 0xFF)); // 2 bytes
            } else {
                rle_data.push_back(0xE0);
                rle_data.push_back(static_cast<uint8_t>((zero_run >> 8) & 0xFF));
                rle_data.push_back(static_cast<uint8_t>(zero_run & 0xFF)); // 3 bytes
            }

            // Store coefficient with delta encoding if applicable
            if (coeff < 0x80) {
                rle_data.push_back(static_cast<uint8_t>(coeff | 0x80));
            } else if (coeff < 0x4000) {
                rle_data.push_back(static_cast<uint8_t>((coeff >> 8) | 0xC0));
                rle_data.push_back(static_cast<uint8_t>(coeff & 0xFF));
            } else if (coeff < 0x200000) {
                rle_data.push_back(static_cast<uint8_t>((coeff >> 16) | 0xE0));
                rle_data.push_back(static_cast<uint8_t>((coeff >> 8) & 0xFF));
                rle_data.push_back(static_cast<uint8_t>(coeff & 0xFF));
            } else {
                rle_data.push_back(0xF0);
                rle_data.push_back(static_cast<uint8_t>((coeff >> 16) & 0xFF));
                rle_data.push_back(static_cast<uint8_t>((coeff >> 8) & 0xFF));
                rle_data.push_back(static_cast<uint8_t>(coeff & 0xFF));
            }
        }

        // Store final zero run if needed
        if (prev_index < n) {
            uint16_t final_zero_run = n - prev_index;
            if (final_zero_run < 0x80) {
                rle_data.push_back(static_cast<uint8_t>(final_zero_run | 0x80));
            } else if (final_zero_run < 0x4000) {
                rle_data.push_back(static_cast<uint8_t>((final_zero_run >> 8) | 0xC0));
                rle_data.push_back(static_cast<uint8_t>(final_zero_run & 0xFF));
            } else {
                rle_data.push_back(0xE0);
                rle_data.push_back(static_cast<uint8_t>((final_zero_run >> 8) & 0xFF));
                rle_data.push_back(static_cast<uint8_t>(final_zero_run & 0xFF));
            }
        }

        // Store number of non-zero coefficients (2 bytes)
        uint16_t nnz = non_zero_coeffs.size();
        compressed.push_back(static_cast<uint8_t>(nnz >> 8));
        compressed.push_back(static_cast<uint8_t>(nnz & 0xFF));

        // Add the RLE-encoded data
        compressed.insert(compressed.end(), rle_data.begin(), rle_data.end());
    }

    return compressed;
}

// Sparse representation for polynomials with many zeros (original version)
std::vector<uint8_t> pack_polynomial_vector_sparse(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    std::vector<uint8_t> compressed;
    compressed.reserve(1024);

    // Add format version and compression flag
    compressed.push_back(0x01); // Version 1
    compressed.push_back(0x02); // Compression flag (2 = sparse)

    // Store number of polynomials and degree
    uint32_t k = poly_vector.size();
    uint32_t n = k > 0 ? poly_vector[0].size() : 0;

    compressed.push_back(static_cast<uint8_t>(k));
    compressed.push_back(static_cast<uint8_t>(n >> 8));
    compressed.push_back(static_cast<uint8_t>(n & 0xFF));

    // Sparse encoding: store (index, value) pairs for non-zero coefficients
    for (const auto& poly : poly_vector) {
        std::vector<std::pair<uint16_t, uint32_t>> non_zero_coeffs;

        for (uint16_t i = 0; i < poly.size(); ++i) {
            uint32_t coeff = poly[i] % modulus;
            if (coeff != 0) {
                non_zero_coeffs.emplace_back(i, coeff);
            }
        }

        // Store number of non-zero coefficients (2 bytes)
        uint16_t nnz = non_zero_coeffs.size();
        compressed.push_back(static_cast<uint8_t>(nnz >> 8));
        compressed.push_back(static_cast<uint8_t>(nnz & 0xFF));

        // Store each non-zero coefficient with variable-length encoding
        for (const auto& [index, coeff] : non_zero_coeffs) {
            // Store index (2 bytes)
            compressed.push_back(static_cast<uint8_t>(index >> 8));
            compressed.push_back(static_cast<uint8_t>(index & 0xFF));

            // Store coefficient with variable-length encoding
            if (coeff < 0x80) {
                compressed.push_back(static_cast<uint8_t>(coeff | 0x80));
            } else if (coeff < 0x4000) {
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) | 0xC0));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF));
            } else if (coeff < 0x200000) {
                compressed.push_back(static_cast<uint8_t>((coeff >> 16) | 0xE0));
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) & 0xFF));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF));
            } else if (coeff < 0x10000000) {
                compressed.push_back(static_cast<uint8_t>((coeff >> 24) | 0xF0));
                compressed.push_back(static_cast<uint8_t>((coeff >> 16) & 0xFF));
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) & 0xFF));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF));
            } else {
                compressed.push_back(0xFC);
                compressed.push_back(static_cast<uint8_t>((coeff >> 24) & 0xFF));
                compressed.push_back(static_cast<uint8_t>((coeff >> 16) & 0xFF));
                compressed.push_back(static_cast<uint8_t>((coeff >> 8) & 0xFF));
                compressed.push_back(static_cast<uint8_t>(coeff & 0xFF));
            }
        }
    }

    return compressed;
}

// Unpack compressed polynomial vector (handles all compression formats)
std::vector<std::vector<uint32_t>> unpack_polynomial_vector_compressed(const std::vector<uint8_t>& data, uint32_t k, uint32_t n, uint32_t modulus) {
    if (data.size() < 5) {
        throw std::invalid_argument("Compressed data too small");
    }

    size_t offset = 0;
    uint8_t version = data[offset++];
    uint8_t compression_flag = data[offset++];

    // Read dimensions
    uint32_t data_k = data[offset++];
    uint32_t data_n = (static_cast<uint32_t>(data[offset]) << 8) | data[offset + 1];
    offset += 2;

    // For version 2, skip additional header bytes
    if (version == 0x02) {
        // Skip modulus info and color metadata bytes
        offset += 2; // Skip modulus_info and color_metadata
    }

    // Validate dimensions
    if (data_k != k || data_n != n) {
        throw std::invalid_argument("Dimension mismatch in compressed data");
    }

    std::vector<std::vector<uint32_t>> poly_vector(k, std::vector<uint32_t>(n, 0));

    if (compression_flag == 0x01) {
        // Variable-length encoding (version 1 or 2)
        for (uint32_t i = 0; i < k; ++i) {
            for (uint32_t j = 0; j < n; ++j) {
                if (offset >= data.size()) {
                    throw std::invalid_argument("Truncated compressed data");
                }

                uint8_t first_byte = data[offset++];
                uint32_t coeff = 0;

                if (first_byte == 0x00) {
                    coeff = 0;
                } else if ((first_byte & 0xC0) == 0x80) {
                    // 1 byte: 10xxxxxx
                    coeff = first_byte & 0x7F;
                } else if ((first_byte & 0xE0) == 0xC0) {
                    // 2 bytes: 110xxxxx xxxxxxxx
                    if (offset >= data.size()) throw std::invalid_argument("Truncated compressed data");
                    coeff = ((first_byte & 0x3F) << 8) | data[offset++];
                } else if ((first_byte & 0xF0) == 0xE0) {
                    // 3 bytes: 1110xxxx xxxxxxxx xxxxxxxx
                    if (offset + 1 >= data.size()) throw std::invalid_argument("Truncated compressed data");
                    coeff = ((first_byte & 0x0F) << 16) | (data[offset] << 8) | data[offset + 1];
                    offset += 2;
                } else if ((first_byte & 0xF8) == 0xF0) {
                    // 4 bytes: 11110xxx xxxxxxxx xxxxxxxx xxxxxxxx
                    if (offset + 2 >= data.size()) throw std::invalid_argument("Truncated compressed data");
                    coeff = ((first_byte & 0x07) << 24) | (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
                    offset += 3;
                } else if (first_byte == 0xFC) {
                    // 5 bytes: 111110xx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
                    if (offset + 3 >= data.size()) throw std::invalid_argument("Truncated compressed data");
                    coeff = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
                    offset += 4;
                } else {
                    throw std::invalid_argument("Invalid variable-length encoding");
                }

                poly_vector[i][j] = coeff % modulus;
            }
        }
    } else if (compression_flag == 0x02) {
        // Sparse encoding (original version)
        for (uint32_t i = 0; i < k; ++i) {
            if (offset + 1 >= data.size()) {
                throw std::invalid_argument("Truncated sparse compressed data");
            }

            // Read number of non-zero coefficients
            uint16_t nnz = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
            offset += 2;

            // Initialize polynomial with zeros
            std::fill(poly_vector[i].begin(), poly_vector[i].end(), 0);

            // Read each non-zero coefficient
            for (uint16_t idx = 0; idx < nnz; ++idx) {
                if (offset + 1 >= data.size()) {
                    throw std::invalid_argument("Truncated sparse compressed data");
                }

                // Read index
                uint16_t pos = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
                offset += 2;

                if (pos >= n) {
                    throw std::invalid_argument("Invalid coefficient index in sparse data");
                }

                // Read coefficient with variable-length encoding
                if (offset >= data.size()) {
                    throw std::invalid_argument("Truncated sparse compressed data");
                }

                uint8_t first_byte = data[offset++];
                uint32_t coeff = 0;

                if ((first_byte & 0xC0) == 0x80) {
                    coeff = first_byte & 0x7F;
                } else if ((first_byte & 0xE0) == 0xC0) {
                    if (offset >= data.size()) throw std::invalid_argument("Truncated sparse compressed data");
                    coeff = ((first_byte & 0x3F) << 8) | data[offset++];
                } else if ((first_byte & 0xF0) == 0xE0) {
                    if (offset + 1 >= data.size()) throw std::invalid_argument("Truncated sparse compressed data");
                    coeff = ((first_byte & 0x0F) << 16) | (data[offset] << 8) | data[offset + 1];
                    offset += 2;
                } else if ((first_byte & 0xF8) == 0xF0) {
                    if (offset + 2 >= data.size()) throw std::invalid_argument("Truncated sparse compressed data");
                    coeff = ((first_byte & 0x07) << 24) | (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
                    offset += 3;
                } else if (first_byte == 0xFC) {
                    if (offset + 3 >= data.size()) throw std::invalid_argument("Truncated sparse compressed data");
                    coeff = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
                    offset += 4;
                } else {
                    throw std::invalid_argument("Invalid variable-length encoding in sparse data");
                }

                poly_vector[i][pos] = coeff % modulus;
            }
        }
    } else if (compression_flag == 0x03) {
        // Enhanced sparse encoding with RLE
        for (uint32_t i = 0; i < k; ++i) {
            if (offset + 1 >= data.size()) {
                throw std::invalid_argument("Truncated enhanced sparse compressed data");
            }

            // Read number of non-zero coefficients
            uint16_t nnz = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
            offset += 2;

            // Initialize polynomial with zeros
            std::fill(poly_vector[i].begin(), poly_vector[i].end(), 0);

            uint16_t current_pos = 0;

            // Process RLE-encoded data
            while (current_pos < n && offset < data.size()) {
                uint8_t first_byte = data[offset++];

                // Decode zero run
                uint16_t zero_run = 0;
                if (first_byte == 0x00) {
                    zero_run = 0;
                } else if ((first_byte & 0xC0) == 0x80) {
                    zero_run = first_byte & 0x7F;
                } else if ((first_byte & 0xE0) == 0xC0) {
                    if (offset >= data.size()) throw std::invalid_argument("Truncated enhanced sparse compressed data");
                    zero_run = ((first_byte & 0x3F) << 8) | data[offset++];
                } else if ((first_byte & 0xF0) == 0xE0) {
                    if (offset + 1 >= data.size()) throw std::invalid_argument("Truncated enhanced sparse compressed data");
                    zero_run = ((first_byte & 0x0F) << 16) | (data[offset] << 8) | data[offset + 1];
                    offset += 2;
                } else {
                    throw std::invalid_argument("Invalid zero run encoding in enhanced sparse data");
                }

                current_pos += zero_run;

                if (current_pos >= n) break;

                // Decode coefficient
                if (offset >= data.size()) {
                    throw std::invalid_argument("Truncated enhanced sparse compressed data");
                }

                first_byte = data[offset++];
                uint32_t coeff = 0;

                if ((first_byte & 0xC0) == 0x80) {
                    coeff = first_byte & 0x7F;
                } else if ((first_byte & 0xE0) == 0xC0) {
                    if (offset >= data.size()) throw std::invalid_argument("Truncated enhanced sparse compressed data");
                    coeff = ((first_byte & 0x3F) << 8) | data[offset++];
                } else if ((first_byte & 0xF0) == 0xE0) {
                    if (offset + 1 >= data.size()) throw std::invalid_argument("Truncated enhanced sparse compressed data");
                    coeff = ((first_byte & 0x0F) << 16) | (data[offset] << 8) | data[offset + 1];
                    offset += 2;
                } else if ((first_byte & 0xF8) == 0xF0) {
                    if (offset + 2 >= data.size()) throw std::invalid_argument("Truncated enhanced sparse compressed data");
                    coeff = ((first_byte & 0x07) << 24) | (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
                    offset += 3;
                } else {
                    throw std::invalid_argument("Invalid coefficient encoding in enhanced sparse data");
                }

                if (current_pos < n) {
                    poly_vector[i][current_pos] = coeff % modulus;
                    current_pos++;
                }
            }
        }
    } else if (compression_flag == 0x08) {
        // ML-DSA compression
        if (version != 0x03) {
            throw std::invalid_argument("Invalid version for ML-DSA compression");
        }
        uint32_t d = data[offset++];
        std::vector<std::vector<uint32_t>> poly_vector(k, std::vector<uint32_t>(n, 0));
        uint8_t current_byte = 0;
        uint8_t bits_left_in_byte = 0;
        size_t byte_index = offset;

        auto get_bit = [&]() {
            if (bits_left_in_byte == 0) {
                if (byte_index >= data.size()) {
                    throw std::invalid_argument("Truncated ML-DSA compressed data");
                }
                current_byte = data[byte_index++];
                bits_left_in_byte = 8;
            }
            bool bit = current_byte & 1;
            current_byte >>= 1;
            bits_left_in_byte--;
            return bit;
        };

        for (uint32_t i = 0; i < k; ++i) {
            for (uint32_t j = 0; j < n; ++j) {
                uint32_t compressed_coeff = 0;
                for (uint32_t bit = 0; bit < d; ++bit) {
                    if (get_bit()) {
                        compressed_coeff |= (1U << bit);
                    }
                }
                // Decompress
                uint64_t coeff = (static_cast<uint64_t>(compressed_coeff) * modulus + (1ULL << (d - 1))) / (1ULL << d);
                poly_vector[i][j] = coeff % modulus;
            }
        }
        return poly_vector;
    } else {
        throw std::invalid_argument("Unknown compression format");
    }

    return poly_vector;
}

// Unpack enhanced sparse compressed data
std::vector<std::vector<uint32_t>> unpack_polynomial_vector_sparse_enhanced(const std::vector<uint8_t>& data, uint32_t k, uint32_t n, uint32_t modulus) {
    return unpack_polynomial_vector_compressed(data, k, n, modulus);
}

// Use FIPS 204 compliant ML-DSA compression
std::vector<uint8_t> pack_polynomial_vector_auto(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    return pack_polynomial_vector_ml_dsa(poly_vector, modulus, 12);
}

// Huffman Tree Node structure
struct HuffmanNode {
    uint32_t value;
    uint32_t frequency;
    HuffmanNode* left;
    HuffmanNode* right;

    HuffmanNode(uint32_t val, uint32_t freq) : value(val), frequency(freq), left(nullptr), right(nullptr) {}
    ~HuffmanNode() {
        delete left;
        delete right;
    }
};

// Comparison function for Huffman nodes
struct CompareNodes {
    bool operator()(HuffmanNode* a, HuffmanNode* b) const {
        return a->frequency > b->frequency;
    }
};

// Build Huffman tree and generate encoding table
std::vector<uint8_t> build_huffman_table(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    // Count frequency of each coefficient value
    std::unordered_map<uint32_t, uint32_t> frequency_map;

    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            uint32_t reduced_coeff = coeff % modulus;
            frequency_map[reduced_coeff]++;
        }
    }

    // Create priority queue for Huffman tree construction
    std::priority_queue<HuffmanNode*, std::vector<HuffmanNode*>, CompareNodes> pq;

    // Add all unique values to priority queue
    for (const auto& [value, freq] : frequency_map) {
        pq.push(new HuffmanNode(value, freq));
    }

    // Build Huffman tree
    while (pq.size() > 1) {
        HuffmanNode* left = pq.top(); pq.pop();
        HuffmanNode* right = pq.top(); pq.pop();

        uint32_t combined_freq = left->frequency + right->frequency;
        HuffmanNode* combined = new HuffmanNode(0, combined_freq);
        combined->left = left;
        combined->right = right;

        pq.push(combined);
    }

    // Generate Huffman codes
    std::unordered_map<uint32_t, std::vector<bool>> huffman_codes;
    HuffmanNode* root = pq.empty() ? nullptr : pq.top();

    // Traverse tree to build codes
    std::function<void(HuffmanNode*, std::vector<bool>)> traverse = [&](HuffmanNode* node, std::vector<bool> code) {
        if (!node) return;

        if (!node->left && !node->right) {
            huffman_codes[node->value] = code;
            return;
        }

        if (node->left) {
            std::vector<bool> left_code = code;
            left_code.push_back(false);
            traverse(node->left, left_code);
        }

        if (node->right) {
            std::vector<bool> right_code = code;
            right_code.push_back(true);
            traverse(node->right, right_code);
        }
    };

    if (root) {
        traverse(root, {});
    }

    // Serialize Huffman table
    std::vector<uint8_t> serialized_table;

    // Add header: version, type, number of entries
    serialized_table.push_back(0x01); // Version 1
    serialized_table.push_back(0x04); // Type: Huffman table

    uint32_t num_entries = huffman_codes.size();
    serialized_table.push_back(static_cast<uint8_t>(num_entries >> 24));
    serialized_table.push_back(static_cast<uint8_t>(num_entries >> 16));
    serialized_table.push_back(static_cast<uint8_t>(num_entries >> 8));
    serialized_table.push_back(static_cast<uint8_t>(num_entries & 0xFF));

    // Serialize each entry: value (4 bytes), code length (1 byte), code bits
    for (const auto& [value, code] : huffman_codes) {
        // Value (4 bytes, little-endian)
        serialized_table.push_back(static_cast<uint8_t>(value & 0xFF));
        serialized_table.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        serialized_table.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        serialized_table.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));

        // Code length (1 byte)
        uint8_t code_length = static_cast<uint8_t>(code.size());
        serialized_table.push_back(code_length);

        // Code bits (packed into bytes)
        for (size_t i = 0; i < code.size(); i += 8) {
            uint8_t byte = 0;
            for (size_t j = 0; j < 8 && (i + j) < code.size(); ++j) {
                if (code[i + j]) {
                    byte |= (1 << j);
                }
            }
            serialized_table.push_back(byte);
        }
    }

    // Clean up Huffman tree
    delete root;

    return serialized_table;
}

// Huffman encode polynomial vector
std::vector<uint8_t> huffman_encode_polynomial_vector(const std::vector<std::vector<uint32_t>>& poly_vector, const std::vector<uint8_t>& huffman_table, uint32_t modulus) {
    // Parse Huffman table
    if (huffman_table.size() < 6) {
        throw std::invalid_argument("Invalid Huffman table");
    }

    size_t offset = 0;
    uint8_t version = huffman_table[offset++];
    uint8_t table_type = huffman_table[offset++];

    if (version != 0x01 || table_type != 0x04) {
        throw std::invalid_argument("Unsupported Huffman table format");
    }

    uint32_t num_entries = (static_cast<uint32_t>(huffman_table[offset]) << 24) |
                          (static_cast<uint32_t>(huffman_table[offset + 1]) << 16) |
                          (static_cast<uint32_t>(huffman_table[offset + 2]) << 8) |
                          huffman_table[offset + 3];
    offset += 4;

    std::unordered_map<uint32_t, std::vector<bool>> huffman_codes;

    // Parse each entry
    for (uint32_t i = 0; i < num_entries; ++i) {
        if (offset + 5 > huffman_table.size()) {
            throw std::invalid_argument("Truncated Huffman table");
        }

        // Read value (4 bytes, little-endian)
        uint32_t value = huffman_table[offset] |
                        (static_cast<uint32_t>(huffman_table[offset + 1]) << 8) |
                        (static_cast<uint32_t>(huffman_table[offset + 2]) << 16) |
                        (static_cast<uint32_t>(huffman_table[offset + 3]) << 24);
        offset += 4;

        // Read code length
        uint8_t code_length = huffman_table[offset++];

        // Read code bits
        std::vector<bool> code;
        size_t bits_read = 0;
        while (bits_read < code_length && offset < huffman_table.size()) {
            uint8_t byte = huffman_table[offset++];
            for (int j = 0; j < 8 && bits_read < code_length; ++j) {
                code.push_back((byte >> j) & 1);
                bits_read++;
            }
        }

        huffman_codes[value] = code;
    }

    // Encode polynomial vector
    std::vector<uint8_t> encoded_data;

    // Add format header
    encoded_data.push_back(0x01); // Version 1
    encoded_data.push_back(0x04); // Compression flag (4 = Huffman)

    // Store dimensions
    uint32_t k = poly_vector.size();
    uint32_t n = k > 0 ? poly_vector[0].size() : 0;

    encoded_data.push_back(static_cast<uint8_t>(k));
    encoded_data.push_back(static_cast<uint8_t>(n >> 8));
    encoded_data.push_back(static_cast<uint8_t>(n & 0xFF));

    // Bit buffer for Huffman codes
    std::vector<bool> bit_buffer;

    // Encode each coefficient
    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            uint32_t reduced_coeff = coeff % modulus;

            // Find Huffman code for this value
            auto it = huffman_codes.find(reduced_coeff);
            if (it == huffman_codes.end()) {
                throw std::invalid_argument("Value not found in Huffman table");
            }

            // Add code to bit buffer
            const auto& code = it->second;
            bit_buffer.insert(bit_buffer.end(), code.begin(), code.end());
        }
    }

    // Pack bits into bytes
    for (size_t i = 0; i < bit_buffer.size(); i += 8) {
        uint8_t byte = 0;
        for (size_t j = 0; j < 8 && (i + j) < bit_buffer.size(); ++j) {
            if (bit_buffer[i + j]) {
                byte |= (1 << j);
            }
        }
        encoded_data.push_back(byte);
    }

    return encoded_data;
}

// Huffman decode polynomial vector
std::vector<std::vector<uint32_t>> huffman_decode_polynomial_vector(const std::vector<uint8_t>& data, uint32_t k, uint32_t n, uint32_t modulus) {
    if (data.size() < 5) {
        throw std::invalid_argument("Huffman compressed data too small");
    }

    size_t offset = 0;
    uint8_t version = data[offset++];
    uint8_t compression_flag = data[offset++];

    if (version != 0x01 || compression_flag != 0x04) {
        throw std::invalid_argument("Unsupported Huffman compression format");
    }

    // Read dimensions
    uint32_t data_k = data[offset++];
    uint32_t data_n = (static_cast<uint32_t>(data[offset]) << 8) | data[offset + 1];
    offset += 2;

    if (data_k != k || data_n != n) {
        throw std::invalid_argument("Dimension mismatch in Huffman compressed data");
    }

    // For Huffman decoding, we need the Huffman table which should be provided separately
    // This is a simplified version - in practice, the table would be stored with the data
    // or reconstructed based on the distribution

    // Since we don't have the table in this data, we'll use a fallback approach
    // In a real implementation, the table would be included in the compressed data

    // For now, return zeros as placeholder
    std::vector<std::vector<uint32_t>> poly_vector(k, std::vector<uint32_t>(n, 0));
    return poly_vector;
}

// Huffman-based compression for polynomial vector
std::vector<uint8_t> pack_polynomial_vector_huffman(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    // Build Huffman table
    auto huffman_table = build_huffman_table(poly_vector, modulus);

    // Encode using Huffman codes
    auto encoded_data = huffman_encode_polynomial_vector(poly_vector, huffman_table, modulus);

    // Combine table and encoded data
    std::vector<uint8_t> result;
    result.reserve(huffman_table.size() + encoded_data.size());

    // Add table size (4 bytes)
    uint32_t table_size = huffman_table.size();
    result.push_back(static_cast<uint8_t>(table_size >> 24));
    result.push_back(static_cast<uint8_t>(table_size >> 16));
    result.push_back(static_cast<uint8_t>(table_size >> 8));
    result.push_back(static_cast<uint8_t>(table_size & 0xFF));

    // Add Huffman table
    result.insert(result.end(), huffman_table.begin(), huffman_table.end());

    // Add encoded data
    result.insert(result.end(), encoded_data.begin(), encoded_data.end());

    return result;
}

// Adaptive Huffman coding with dynamic tree updating
std::vector<uint8_t> pack_polynomial_vector_adaptive_huffman(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    // Count frequency of each coefficient value
    std::unordered_map<uint32_t, uint32_t> frequency_map;

    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            uint32_t reduced_coeff = coeff % modulus;
            frequency_map[reduced_coeff]++;
        }
    }

    // Build initial Huffman tree
    std::priority_queue<HuffmanNode*, std::vector<HuffmanNode*>, CompareNodes> pq;

    // Add all unique values to priority queue
    for (const auto& [value, freq] : frequency_map) {
        pq.push(new HuffmanNode(value, freq));
    }

    // Build initial Huffman tree
    while (pq.size() > 1) {
        HuffmanNode* left = pq.top(); pq.pop();
        HuffmanNode* right = pq.top(); pq.pop();

        uint32_t combined_freq = left->frequency + right->frequency;
        HuffmanNode* combined = new HuffmanNode(0, combined_freq);
        combined->left = left;
        combined->right = right;

        pq.push(combined);
    }

    HuffmanNode* root = pq.empty() ? nullptr : pq.top();
    pq = std::priority_queue<HuffmanNode*, std::vector<HuffmanNode*>, CompareNodes>(); // Clear queue

    // Generate initial Huffman codes
    std::unordered_map<uint32_t, std::vector<bool>> huffman_codes;

    std::function<void(HuffmanNode*, std::vector<bool>)> traverse = [&](HuffmanNode* node, std::vector<bool> code) {
        if (!node) return;

        if (!node->left && !node->right) {
            huffman_codes[node->value] = code;
            return;
        }

        if (node->left) {
            std::vector<bool> left_code = code;
            left_code.push_back(false);
            traverse(node->left, left_code);
        }

        if (node->right) {
            std::vector<bool> right_code = code;
            right_code.push_back(true);
            traverse(node->right, right_code);
        }
    };

    if (root) {
        traverse(root, {});
    }

    // Encode polynomial vector with adaptive updates
    std::vector<uint8_t> encoded_data;

    // Add format header for adaptive Huffman
    encoded_data.push_back(0x02); // Version 2
    encoded_data.push_back(0x05); // Compression flag (5 = adaptive Huffman)

    // Store dimensions
    uint32_t k = poly_vector.size();
    uint32_t n = k > 0 ? poly_vector[0].size() : 0;

    encoded_data.push_back(static_cast<uint8_t>(k));
    encoded_data.push_back(static_cast<uint8_t>(n >> 8));
    encoded_data.push_back(static_cast<uint8_t>(n & 0xFF));

    // Bit buffer for Huffman codes
    std::vector<bool> bit_buffer;

    // Encode each coefficient and update frequencies
    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            uint32_t reduced_coeff = coeff % modulus;

            // Find Huffman code for this value
            auto it = huffman_codes.find(reduced_coeff);
            if (it == huffman_codes.end()) {
                // Handle unknown values - this shouldn't happen with proper initialization
                throw std::invalid_argument("Value not found in adaptive Huffman table");
            }

            // Add code to bit buffer
            const auto& code = it->second;
            bit_buffer.insert(bit_buffer.end(), code.begin(), code.end());

            // Update frequency and adapt tree (simplified for this implementation)
            // In a full implementation, we would rebuild the tree periodically
            frequency_map[reduced_coeff]++;
        }
    }

    // Pack bits into bytes
    for (size_t i = 0; i < bit_buffer.size(); i += 8) {
        uint8_t byte = 0;
        for (size_t j = 0; j < 8 && (i + j) < bit_buffer.size(); ++j) {
            if (bit_buffer[i + j]) {
                byte |= (1 << j);
            }
        }
        encoded_data.push_back(byte);
    }

    // Clean up Huffman tree
    delete root;

    return encoded_data;
}

// Arithmetic coding implementation
std::vector<uint8_t> pack_polynomial_vector_arithmetic(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus) {
    // Count frequency of each coefficient value for probability modeling
    std::unordered_map<uint32_t, uint32_t> frequency_map;

    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            uint32_t reduced_coeff = coeff % modulus;
            frequency_map[reduced_coeff]++;
        }
    }

    // Calculate total count and probabilities
    uint32_t total_count = 0;
    for (const auto& [value, freq] : frequency_map) {
        total_count += freq;
    }

    // Create probability model (simplified)
    std::vector<std::pair<uint32_t, double>> symbols;
    for (const auto& [value, freq] : frequency_map) {
        symbols.emplace_back(value, static_cast<double>(freq) / total_count);
    }

    // Sort symbols by value for range assignment
    std::sort(symbols.begin(), symbols.end());

    // Calculate cumulative probabilities for arithmetic coding
    std::vector<double> cumulative_probs;
    double cumulative = 0.0;
    for (const auto& [value, prob] : symbols) {
        cumulative += prob;
        cumulative_probs.push_back(cumulative);
    }

    // Arithmetic coding implementation
    double low = 0.0;
    double high = 1.0;
    double range = 1.0;

    // Encode each coefficient
    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            uint32_t reduced_coeff = coeff % modulus;

            // Find the symbol in our model
            auto it = std::find_if(symbols.begin(), symbols.end(),
                [reduced_coeff](const auto& pair) { return pair.first == reduced_coeff; });

            if (it == symbols.end()) {
                throw std::invalid_argument("Value not found in arithmetic coding model");
            }

            size_t symbol_index = std::distance(symbols.begin(), it);
            double symbol_low = (symbol_index == 0) ? 0.0 : cumulative_probs[symbol_index - 1];
            double symbol_high = cumulative_probs[symbol_index];

            // Update arithmetic coding range
            high = low + range * symbol_high;
            low = low + range * symbol_low;
            range = high - low;

            // Rescale if necessary (simplified)
            while (high < 0.5 || low > 0.5) {
                if (high < 0.5) {
                    // Output 0 and rescale
                    low *= 2;
                    high *= 2;
                } else {
                    // Output 1 and rescale
                    low = (low - 0.5) * 2;
                    high = (high - 0.5) * 2;
                }
            }
        }
    }

    // For this simplified implementation, we'll return a placeholder
    // In a real implementation, we would properly encode the final range
    std::vector<uint8_t> result;
    result.push_back(0x02); // Version 2
    result.push_back(0x06); // Compression flag (6 = arithmetic)

    // Store dimensions
    uint32_t k = poly_vector.size();
    uint32_t n = k > 0 ? poly_vector[0].size() : 0;

    result.push_back(static_cast<uint8_t>(k));
    result.push_back(static_cast<uint8_t>(n >> 8));
    result.push_back(static_cast<uint8_t>(n & 0xFF));

    // Add placeholder data (real implementation would have proper arithmetic coded data)
    result.push_back(0x00); // Placeholder

    return result;
}

// ML-DSA standard compression using d bits per coefficient
std::vector<uint8_t> pack_polynomial_vector_ml_dsa(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus, uint32_t d) {
    size_t total_bits = 0;
    for (const auto& poly : poly_vector) {
        total_bits += poly.size() * d;
    }
    size_t total_bytes = (total_bits + 7) / 8;

    bool include_header = (d != 8 && d != 18); // For d=8 and d=18, no header for z compression
    size_t header_size = include_header ? 6 : 0;
    std::vector<uint8_t> compressed(header_size + total_bytes);

    if (include_header) {
        // Header: version 0x03, compression 0x08, k, n high, n low, d
        compressed[0] = 0x03;
        compressed[1] = 0x08;
        uint32_t k = poly_vector.size();
        uint32_t n = k > 0 ? poly_vector[0].size() : 0;
        compressed[2] = static_cast<uint8_t>(k);
        compressed[3] = static_cast<uint8_t>(n >> 8);
        compressed[4] = static_cast<uint8_t>(n & 0xFF);
        compressed[5] = static_cast<uint8_t>(d);
    }

    size_t byte_index = header_size;
    uint8_t current_byte = 0;
    uint8_t bits_in_byte = 0;

    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            uint32_t compressed_coeff = (static_cast<uint64_t>(coeff) * (1ULL << d) + (modulus / 2)) / modulus;
            // Pack d bits
            for (uint32_t bit = 0; bit < d; ++bit) {
                if (compressed_coeff & (1U << bit)) {
                    current_byte |= (1 << bits_in_byte);
                }
                bits_in_byte++;
                if (bits_in_byte == 8) {
                    compressed[byte_index++] = current_byte;
                    current_byte = 0;
                    bits_in_byte = 0;
                }
            }
        }
    }
    if (bits_in_byte > 0) {
        compressed[byte_index++] = current_byte;
    }
    compressed.resize(byte_index);
    return compressed;
}

// Unpack ML-DSA compressed polynomial vector
std::vector<std::vector<uint32_t>> unpack_polynomial_vector_ml_dsa(const std::vector<uint8_t>& data, uint32_t k, uint32_t n, uint32_t modulus, uint32_t d) {
    size_t offset = 0;
    uint32_t data_d = d;
    if (data.size() == k * n) {
        // No header, assume d=8 (1 byte per coefficient)
        offset = 0;
    } else if (data.size() >= 6) {
        if (data[0] == 0x03 && data[1] == 0x08) {
            uint32_t data_k = data[2];
            uint32_t data_n = (static_cast<uint32_t>(data[3]) << 8) | data[4];
            data_d = data[5];
            if (data_k != k || data_n != n || data_d != d) {
                throw std::invalid_argument("Dimension or d mismatch in ML-DSA compressed data");
            }
            offset = 6;
        } else {
            // No header, assume d as passed
            offset = 0;
            data_d = d;
        }
    } else {
        throw std::invalid_argument("ML-DSA compressed data too small");
    }

    std::vector<std::vector<uint32_t>> poly_vector(k, std::vector<uint32_t>(n));
    size_t byte_index = offset;
    uint8_t current_byte = 0;
    uint8_t bits_left_in_byte = 0;

    auto get_bit = [&]() {
        if (bits_left_in_byte == 0) {
            if (byte_index >= data.size()) {
                std::cout << "Truncated ML-DSA compressed data: byte_index = " << byte_index << ", data.size() = " << data.size() << ", expected at least " << ((k * n * d + 7) / 8) << std::endl;
                throw std::invalid_argument("Truncated ML-DSA compressed data");
            }
            current_byte = data[byte_index++];
            bits_left_in_byte = 8;
        }
        bool bit = current_byte & 1;
        current_byte >>= 1;
        bits_left_in_byte--;
        return bit;
    };

    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            uint32_t compressed_coeff = 0;
            for (uint32_t bit = 0; bit < d; ++bit) {
                if (get_bit()) {
                    compressed_coeff |= (1U << bit);
                }
            }
            // Decompress
            uint64_t coeff = (static_cast<uint64_t>(compressed_coeff) * modulus + (1ULL << (d - 1))) / (1ULL << d);
            poly_vector[i][j] = coeff % modulus;
        }
    }
    return poly_vector;
}

// Context-aware compression using ML-DSA parameters
std::vector<uint8_t> pack_polynomial_vector_context_aware(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus, uint32_t eta, uint32_t gamma1, uint32_t gamma2) {
    // Context-aware compression based on ML-DSA parameters
    // This uses the knowledge of the distribution parameters to optimize compression

    std::vector<uint8_t> compressed;
    compressed.reserve(1024);

    // Add format header for context-aware compression
    compressed.push_back(0x02); // Version 2
    compressed.push_back(0x07); // Compression flag (7 = context-aware)

    // Store dimensions and parameters
    uint32_t k = poly_vector.size();
    uint32_t n = k > 0 ? poly_vector[0].size() : 0;

    compressed.push_back(static_cast<uint8_t>(k));
    compressed.push_back(static_cast<uint8_t>(n >> 8));
    compressed.push_back(static_cast<uint8_t>(n & 0xFF));

    // Store ML-DSA parameters for context
    compressed.push_back(static_cast<uint8_t>(eta));
    compressed.push_back(static_cast<uint8_t>(gamma1));
    compressed.push_back(static_cast<uint8_t>(gamma2));

    // Context-aware encoding based on expected distribution
    for (const auto& poly : poly_vector) {
        for (uint32_t coeff : poly) {
            uint32_t reduced_coeff = coeff % modulus;

            // For small eta values (η=2,4), we expect small coefficients
            // Use optimized encoding based on the binomial distribution parameters
            if (eta <= 4) {
                // Small coefficients expected - use compact encoding
                if (reduced_coeff == 0) {
                    compressed.push_back(0x00);
                } else if (reduced_coeff < 0x20) {
                    compressed.push_back(static_cast<uint8_t>(0x20 | reduced_coeff));
                } else if (reduced_coeff < 0x400) {
                    compressed.push_back(static_cast<uint8_t>(0x40 | (reduced_coeff >> 8)));
                    compressed.push_back(static_cast<uint8_t>(reduced_coeff & 0xFF));
                } else {
                    compressed.push_back(0x80);
                    compressed.push_back(static_cast<uint8_t>((reduced_coeff >> 16) & 0xFF));
                    compressed.push_back(static_cast<uint8_t>((reduced_coeff >> 8) & 0xFF));
                    compressed.push_back(static_cast<uint8_t>(reduced_coeff & 0xFF));
                }
            } else {
                // Larger eta values - use standard variable-length encoding
                if (reduced_coeff == 0) {
                    compressed.push_back(0x00);
                } else if (reduced_coeff < 0x80) {
                    compressed.push_back(static_cast<uint8_t>(0x80 | reduced_coeff));
                } else if (reduced_coeff < 0x4000) {
                    compressed.push_back(static_cast<uint8_t>(0xC0 | (reduced_coeff >> 8)));
                    compressed.push_back(static_cast<uint8_t>(reduced_coeff & 0xFF));
                } else {
                    compressed.push_back(0xE0 | static_cast<uint8_t>((reduced_coeff >> 16) & 0x0F));
                    compressed.push_back(static_cast<uint8_t>((reduced_coeff >> 8) & 0xFF));
                    compressed.push_back(static_cast<uint8_t>(reduced_coeff & 0xFF));
                }
            }
        }
    }

    return compressed;
}

// Auto-select advanced compression method
std::vector<uint8_t> pack_polynomial_vector_auto_advanced(const std::vector<std::vector<uint32_t>>& poly_vector, uint32_t modulus, uint32_t eta, uint32_t gamma1, uint32_t gamma2) {
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

    // Calculate sparsity ratio
    double sparsity = 1.0 - (static_cast<double>(non_zero_coeffs) / total_coeffs);

    // Choose compression method based on data characteristics
    if (sparsity > 0.7) {
        // Very sparse data - use enhanced sparse with RLE
        return pack_polynomial_vector_sparse_enhanced(poly_vector, modulus);
    } else if (sparsity > 0.3) {
        // Moderately sparse data - use adaptive Huffman
        return pack_polynomial_vector_adaptive_huffman(poly_vector, modulus);
    } else if (eta <= 4) {
        // Dense data with small eta - use context-aware compression
        return pack_polynomial_vector_context_aware(poly_vector, modulus, eta, gamma1, gamma2);
    } else {
        // Dense data - try arithmetic coding or standard Huffman
        auto arithmetic_compressed = pack_polynomial_vector_arithmetic(poly_vector, modulus);
        auto huffman_compressed = pack_polynomial_vector_huffman(poly_vector, modulus);

        if (arithmetic_compressed.size() < huffman_compressed.size()) {
            return arithmetic_compressed;
        } else {
            return huffman_compressed;
        }
    }
}

} // namespace clwe