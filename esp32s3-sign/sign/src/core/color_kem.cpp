#include "clwe/color_kem.hpp"
#include "clwe/shake_sampler.hpp"
#include "clwe/utils.hpp"
#include "clwe/color_integration.hpp"
#include <random>
#include <cstring>
#include <algorithm>
#include <iomanip>
#include <stdexcept>

namespace clwe {

ColorKEM::ColorKEM(const CLWEParameters& params)
    : params_(params) {
    color_ntt_engine_ = std::unique_ptr<ColorNTTEngine>(new ColorNTTEngine(params_.modulus, params_.degree));
}

ColorKEM::~ColorKEM() = default;

std::vector<std::vector<std::vector<ColorValue>>> ColorKEM::generate_matrix_A(const std::array<uint8_t, 32>& seed) const {
    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;
    uint32_t q = params_.modulus;

    std::vector<std::vector<std::vector<ColorValue>>> matrix(k, std::vector<std::vector<ColorValue>>(k, std::vector<ColorValue>(n)));

    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < k; ++j) {

            std::vector<uint8_t> shake_input;
            shake_input.reserve(seed.size() + 2);
            shake_input.insert(shake_input.end(), seed.begin(), seed.end());
            shake_input.push_back(static_cast<uint8_t>(i));
            shake_input.push_back(static_cast<uint8_t>(j));


            SHAKE128Sampler shake128;
            shake128.init(shake_input.data(), shake_input.size());


            size_t coeff_idx = 0;
            while (coeff_idx < n) {
                std::array<uint8_t, 3> bytes;
                shake128.squeeze(bytes.data(), bytes.size());

                uint16_t coeff1 = ((bytes[0] << 4) | (bytes[1] >> 4)) & 0xFFF;
                uint16_t coeff2 = ((bytes[1] << 8) | bytes[2]) & 0xFFF;

                if (coeff1 < q && coeff_idx < n) {
                    matrix[i][j][coeff_idx++] = ColorValue::from_math_value(coeff1);
                }
                if (coeff2 < q && coeff_idx < n) {
                    matrix[i][j][coeff_idx++] = ColorValue::from_math_value(coeff2);
                }
            }
        }
    }

    return matrix;
}
std::vector<std::vector<ColorValue>> ColorKEM::generate_error_vector(uint32_t eta) const {
    std::vector<std::vector<ColorValue>> error_vector(params_.module_rank, std::vector<ColorValue>(params_.degree));

    for (auto& poly : error_vector) {
        SHAKE256Sampler sampler;
        std::array<uint8_t, 32> seed;
        secure_random_bytes(seed.data(), seed.size());
        sampler.init(seed.data(), seed.size());

        sampler.sample_polynomial_binomial(reinterpret_cast<uint32_t*>(poly.data()), params_.degree, eta, params_.modulus);

        for (auto& coeff : poly) {
            coeff = ColorValue::from_math_value(coeff.to_math_value());
        }
    }

    return error_vector;
}

std::vector<std::vector<ColorValue>> ColorKEM::generate_error_vector_deterministic(uint32_t eta, const std::array<uint8_t, 32>& seed) const {
    std::vector<std::vector<ColorValue>> error_vector(params_.module_rank, std::vector<ColorValue>(params_.degree));

    for (size_t i = 0; i < error_vector.size(); ++i) {
        SHAKE256Sampler sampler;
        std::array<uint8_t, 32> indexed_seed = seed;
        indexed_seed[0] ^= static_cast<uint8_t>(i);  // Make seed unique per element
        sampler.init(indexed_seed.data(), indexed_seed.size());

        sampler.sample_polynomial_binomial(reinterpret_cast<uint32_t*>(error_vector[i].data()), params_.degree, eta, params_.modulus);

        for (auto& coeff : error_vector[i]) {
            coeff = ColorValue::from_math_value(coeff.to_math_value());
        }
    }

    return error_vector;
}


std::vector<std::vector<ColorValue>> ColorKEM::generate_secret_key(uint32_t eta) const {
    std::vector<std::vector<ColorValue>> secret_key(params_.module_rank, std::vector<ColorValue>(params_.degree));

    for (auto& poly : secret_key) {
        SHAKE256Sampler sampler;
        std::array<uint8_t, 32> seed;
        secure_random_bytes(seed.data(), seed.size());
        sampler.init(seed.data(), seed.size());

        sampler.sample_polynomial_binomial(reinterpret_cast<uint32_t*>(poly.data()), params_.degree, eta, params_.modulus);

        for (auto& coeff : poly) {
            coeff = ColorValue::from_math_value(coeff.to_math_value());
        }
    }

    return secret_key;
}

std::vector<std::vector<ColorValue>> ColorKEM::generate_secret_key_deterministic(uint32_t eta, const std::array<uint8_t, 32>& seed) const {
    std::vector<std::vector<ColorValue>> secret_key(params_.module_rank, std::vector<ColorValue>(params_.degree));

    for (size_t i = 0; i < secret_key.size(); ++i) {
        SHAKE256Sampler sampler;
        std::array<uint8_t, 32> indexed_seed = seed;
        indexed_seed[0] ^= static_cast<uint8_t>(i);  // Make seed unique per element
        sampler.init(indexed_seed.data(), indexed_seed.size());

        sampler.sample_polynomial_binomial(reinterpret_cast<uint32_t*>(secret_key[i].data()), params_.degree, eta, params_.modulus);

        for (auto& coeff : secret_key[i]) {
            coeff = ColorValue::from_math_value(coeff.to_math_value());
        }
    }

    return secret_key;
}


std::vector<std::vector<ColorValue>> ColorKEM::generate_public_key(const std::vector<std::vector<ColorValue>>& secret_key,
                                                     const std::vector<std::vector<std::vector<ColorValue>>>& matrix_A,
                                                     const std::vector<std::vector<ColorValue>>& error_vector) const {

    auto As = this->matrix_vector_mul(matrix_A, secret_key);
    std::vector<std::vector<ColorValue>> public_key(params_.module_rank, std::vector<ColorValue>(params_.degree));

    for (uint32_t i = 0; i < params_.module_rank; ++i) {
        for (uint32_t d = 0; d < params_.degree; ++d) {
            uint64_t as_val = As[i][d].to_math_value();
            uint64_t e_val = error_vector[i][d].to_math_value();
            uint64_t pk_val = (as_val + e_val) % params_.modulus;
            public_key[i][d] = ColorValue::from_math_value(pk_val);
        }
    }

    return public_key;
}


std::vector<std::vector<ColorValue>> ColorKEM::matrix_vector_mul(const std::vector<std::vector<std::vector<ColorValue>>>& matrix,
                                                    const std::vector<std::vector<ColorValue>>& vector) const {
    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;

    // Validate matrix dimensions
    if (matrix.size() != k) {
        throw std::invalid_argument("Invalid matrix rows: expected " + std::to_string(k) + ", got " + std::to_string(matrix.size()));
    }
    for (const auto& row : matrix) {
        if (row.size() != k) {
            throw std::invalid_argument("Invalid matrix columns: expected " + std::to_string(k) + " per row");
        }
        for (const auto& poly : row) {
            if (poly.size() != n) {
                throw std::invalid_argument("Invalid polynomial size: expected " + std::to_string(n));
            }
        }
    }

    // Validate vector size
    if (vector.size() != k) {
        throw std::invalid_argument("Invalid vector size: expected " + std::to_string(k) + ", got " + std::to_string(vector.size()));
    }
    for (const auto& poly : vector) {
        if (poly.size() != n) {
            throw std::invalid_argument("Invalid polynomial size: expected " + std::to_string(n));
        }
    }

    std::vector<std::vector<ColorValue>> result(k, std::vector<ColorValue>(n));

    for (uint32_t i = 0; i < k; ++i) {
        std::vector<ColorValue> sum(n, ColorValue(0, 0, 0, 0)); // Zero polynomial
        for (uint32_t j = 0; j < k; ++j) {
            std::vector<ColorValue> product(n);
            color_ntt_engine_->multiply_colors(matrix[i][j].data(), vector[j].data(), product.data());
            // Add product to sum
            for (uint32_t d = 0; d < n; ++d) {
                uint64_t s_val = sum[d].to_math_value();
                uint64_t p_val = product[d].to_math_value();
                uint64_t new_val = (s_val + p_val) % params_.modulus;
                sum[d] = ColorValue::from_math_value(new_val);
            }
        }
        result[i] = sum;
    }

    return result;
}


std::vector<std::vector<ColorValue>> ColorKEM::matrix_transpose_vector_mul(const std::vector<std::vector<std::vector<ColorValue>>>& matrix,
                                                              const std::vector<std::vector<ColorValue>>& vector) const {
    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;

    // Validate matrix dimensions
    if (matrix.size() != k) {
        throw std::invalid_argument("Invalid matrix rows: expected " + std::to_string(k) + ", got " + std::to_string(matrix.size()));
    }
    for (const auto& row : matrix) {
        if (row.size() != k) {
            throw std::invalid_argument("Invalid matrix columns: expected " + std::to_string(k) + " per row");
        }
        for (const auto& poly : row) {
            if (poly.size() != n) {
                throw std::invalid_argument("Invalid polynomial size: expected " + std::to_string(n));
            }
        }
    }

    // Validate vector size
    if (vector.size() != k) {
        throw std::invalid_argument("Invalid vector size: expected " + std::to_string(k) + ", got " + std::to_string(vector.size()));
    }
    for (const auto& poly : vector) {
        if (poly.size() != n) {
            throw std::invalid_argument("Invalid polynomial size: expected " + std::to_string(n));
        }
    }

    std::vector<std::vector<ColorValue>> result(k, std::vector<ColorValue>(n));

    for (uint32_t i = 0; i < k; ++i) {
        std::vector<ColorValue> sum(n, ColorValue(0, 0, 0, 0)); // Zero polynomial
        for (uint32_t j = 0; j < k; ++j) {
            std::vector<ColorValue> product(n);
            color_ntt_engine_->multiply_colors(matrix[j][i].data(), vector[j].data(), product.data());
            // Add product to sum
            for (uint32_t d = 0; d < n; ++d) {
                uint64_t s_val = sum[d].to_math_value();
                uint64_t p_val = product[d].to_math_value();
                uint64_t new_val = (s_val + p_val) % params_.modulus;
                sum[d] = ColorValue::from_math_value(new_val);
            }
        }
        result[i] = sum;
    }

    return result;
}



ColorValue ColorKEM::decrypt_message(const std::vector<std::vector<ColorValue>>& secret_key,
                                     const std::vector<std::vector<ColorValue>>& ciphertext) const {

    uint32_t k = params_.module_rank;
    uint32_t q = params_.modulus;

    if (ciphertext.size() != k + 1) {
        throw std::invalid_argument("Invalid ciphertext size: expected " + std::to_string(k + 1) + " polynomials");
    }

    if (secret_key.size() != k) {
        throw std::invalid_argument("Invalid secret key size: expected " + std::to_string(k) + " polynomials");
    }

    std::vector<std::vector<ColorValue>> c1(ciphertext.begin(), ciphertext.begin() + k);
    std::vector<ColorValue> c2 = ciphertext[k];

    std::vector<ColorValue> s_dot_c1_poly(params_.degree, ColorValue(0, 0, 0, 0));
    for (uint32_t i = 0; i < k; ++i) {
        std::vector<ColorValue> product(params_.degree);
        color_ntt_engine_->multiply_colors(secret_key[i].data(), c1[i].data(), product.data());
        for (uint32_t d = 0; d < params_.degree; ++d) {
            uint64_t sdc_val = s_dot_c1_poly[d].to_math_value();
            uint64_t p_val = product[d].to_math_value();
            s_dot_c1_poly[d] = ColorValue::from_math_value((sdc_val + p_val) % q);
        }
    }

    uint64_t s_dot_c1 = s_dot_c1_poly[0].to_math_value(); // Constant term

    uint64_t c2_val = c2[0].to_math_value(); // Constant term
    // Constant-time modular subtraction: v = (c2_val - s_dot_c1) mod q
    uint64_t diff_v = c2_val - s_dot_c1;
    uint64_t mask_v = -static_cast<uint64_t>(static_cast<int64_t>(diff_v) >> 63);
    uint64_t v = diff_v + (mask_v & q);
    v %= q;

    // Constant-time min for dist = min(v, q - v)
    uint64_t q_half = q / 2;
    uint64_t a_dist = v;
    uint64_t b_dist = q - v;
    int64_t signed_diff_dist = static_cast<int64_t>(a_dist) - static_cast<int64_t>(b_dist);
    uint64_t mask_dist = -static_cast<uint64_t>(signed_diff_dist >> 63);
    uint64_t dist = b_dist + (mask_dist & (a_dist - b_dist));

    // Constant-time comparison: m = 1 if dist > q/4, 0 otherwise
    uint32_t q_fourth = q / 4;
    uint64_t diff_m = dist - q_fourth - 1;
    uint64_t mask_m = -static_cast<uint64_t>(static_cast<int64_t>(diff_m) >> 63);
    uint32_t m = 1 - static_cast<uint32_t>(mask_m & 1);

    return ColorValue::from_math_value(m);
}


ColorValue ColorKEM::generate_shared_secret() const {
    uint8_t bytes[4];
    secure_random_bytes(bytes, 4);
    uint32_t value = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    value %= params_.modulus;

    return ColorValue::from_precise_value(value);
}


std::vector<uint8_t> ColorKEM::encode_color_secret(const ColorValue& secret) const {
    uint32_t value = secret.to_math_value();
    return {
        static_cast<uint8_t>((value >> 24) & 0xFF),
        static_cast<uint8_t>((value >> 16) & 0xFF),
        static_cast<uint8_t>((value >> 8) & 0xFF),
        static_cast<uint8_t>(value & 0xFF)
    };
}


ColorValue ColorKEM::decode_color_secret(const std::vector<uint8_t>& encoded) const {
    if (encoded.size() < 4) return ColorValue::from_math_value(0);

    uint32_t value = (static_cast<uint32_t>(encoded[0]) << 24) |
                    (static_cast<uint32_t>(encoded[1]) << 16) |
                    (static_cast<uint32_t>(encoded[2]) << 8) |
                    static_cast<uint32_t>(encoded[3]);

    return ColorValue::from_math_value(value);
}


std::pair<ColorPublicKey, ColorPrivateKey> ColorKEM::keygen() {

    std::array<uint8_t, 32> matrix_seed;
    secure_random_bytes(matrix_seed.data(), matrix_seed.size());

    // std::cout << "DEBUG: Matrix seed: ";
    // for (uint8_t b : matrix_seed) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    // std::cout << std::dec << std::endl;

    auto matrix_A = generate_matrix_A(matrix_seed);
    // std::cout << "DEBUG: Matrix A generated (" << matrix_A.size() << "x" << matrix_A[0].size() << ")" << std::endl;

    auto secret_key_colors = generate_secret_key(params_.eta1);
    // std::cout << "DEBUG: Secret key generated (" << secret_key_colors.size() << " elements)" << std::endl;
    // for (size_t i = 0; i < secret_key_colors.size(); ++i) {
    //     std::cout << "  s[" << i << "] = " << secret_key_colors[i].to_math_value() << std::endl;
    // }

    auto error_vector = generate_error_vector(params_.eta1);
    // std::cout << "DEBUG: Error vector generated (" << error_vector.size() << " elements)" << std::endl;
    // for (size_t i = 0; i < error_vector.size(); ++i) {
    //     std::cout << "  e[" << i << "] = " << error_vector[i].to_math_value() << std::endl;
    // }

    auto public_key_colors = generate_public_key(secret_key_colors, matrix_A, error_vector);
    // std::cout << "DEBUG: Public key generated (" << public_key_colors.size() << " elements)" << std::endl;
    // for (size_t i = 0; i < public_key_colors.size(); ++i) {
    //     std::cout << "  t[" << i << "] = " << public_key_colors[i].to_math_value() << std::endl;
    // }


    std::vector<uint8_t> secret_data;
    for (const auto& poly : secret_key_colors) {
        for (const auto& coeff : poly) {
            auto bytes = color_secret_to_bytes(coeff);
            secret_data.insert(secret_data.end(), bytes.begin(), bytes.end());
        }
    }

    std::vector<uint8_t> public_data;
    for (const auto& poly : public_key_colors) {
        for (const auto& coeff : poly) {
            auto bytes = color_secret_to_bytes(coeff);
            public_data.insert(public_data.end(), bytes.begin(), bytes.end());
        }
    }

    ColorPublicKey public_key{matrix_seed, public_data, params_};
    ColorPrivateKey private_key{secret_data, params_};

    return {public_key, private_key};
}

std::pair<ColorPublicKey, ColorPrivateKey> ColorKEM::keygen_deterministic(const std::array<uint8_t, 32>& matrix_seed,
                                                                       const std::array<uint8_t, 32>& secret_seed,
                                                                       const std::array<uint8_t, 32>& error_seed) {

    auto matrix_A = generate_matrix_A(matrix_seed);

    auto secret_key_colors = generate_secret_key_deterministic(params_.eta1, secret_seed);

    auto error_vector = generate_error_vector_deterministic(params_.eta1, error_seed);

    auto public_key_colors = generate_public_key(secret_key_colors, matrix_A, error_vector);


    std::vector<uint8_t> secret_data = pack_polynomial_vector_ml_dsa(secret_key_colors, params_.modulus, 4);

    std::vector<uint8_t> public_data;
    for (const auto& poly : public_key_colors) {
        for (const auto& coeff : poly) {
            auto bytes = color_secret_to_bytes(coeff);
            public_data.insert(public_data.end(), bytes.begin(), bytes.end());
        }
    }

    ColorPublicKey public_key{matrix_seed, public_data, params_};
    ColorPrivateKey private_key{secret_data, params_};

    return {public_key, private_key};
}


std::pair<ColorCiphertext, ColorValue> ColorKEM::encapsulate(const ColorPublicKey& public_key) {

    // Validate public key parameters match instance parameters
    if (public_key.params.security_level != params_.security_level ||
        public_key.params.modulus != params_.modulus ||
        public_key.params.degree != params_.degree ||
        public_key.params.module_rank != params_.module_rank) {
        throw std::invalid_argument("Public key parameters do not match KEM instance parameters");
    }

    // Validate public key data size
    if (public_key.public_data.size() != params_.module_rank * params_.degree * 4) {
        throw std::invalid_argument("Invalid public key data size: expected " + std::to_string(params_.module_rank * params_.degree * 4) + " bytes, got " + std::to_string(public_key.public_data.size()));
    }

    // Validate public key data is not empty and properly sized
    if (public_key.public_data.empty()) {
        throw std::invalid_argument("Public key data cannot be empty");
    }

    uint8_t byte;
    secure_random_bytes(&byte, 1);
    ColorValue shared_secret = ColorValue::from_math_value(byte & 1);
    // std::cout << "DEBUG ENCAP: Shared secret = " << shared_secret.to_precise_value() << std::endl;

    auto matrix_A = generate_matrix_A(public_key.seed);
    // std::cout << "DEBUG ENCAP: Regenerated matrix A from seed" << std::endl;

    std::vector<std::vector<ColorValue>> public_key_colors(params_.module_rank, std::vector<ColorValue>(params_.degree));
    size_t idx = 0;
    for (size_t i = 0; i < params_.module_rank; ++i) {
        for (size_t d = 0; d < params_.degree; ++d) {
            std::vector<uint8_t> bytes(public_key.public_data.begin() + idx,
                                       public_key.public_data.begin() + idx + 4);
            public_key_colors[i][d] = bytes_to_color_secret(bytes);
            idx += 4;
        }
    }
    // std::cout << "DEBUG ENCAP: Public key colors (" << public_key_colors.size() << " elements):" << std::endl;
    // for (size_t i = 0; i < public_key_colors.size(); ++i) {
    //     std::cout << "  t[" << i << "] = " << public_key_colors[i].to_math_value() << std::endl;
    // }

    auto ciphertext_colors = encrypt_message(matrix_A, public_key_colors, shared_secret);
    // std::cout << "DEBUG ENCAP: Ciphertext colors (" << ciphertext_colors.size() << " elements):" << std::endl;
    // for (size_t i = 0; i < ciphertext_colors.size(); ++i) {
    //     std::cout << "  c[" << i << "] = " << ciphertext_colors[i].to_math_value() << std::endl;
    // }


    std::vector<uint8_t> ciphertext_data;
    for (const auto& poly : ciphertext_colors) {
        for (const auto& coeff : poly) {
            auto bytes = color_secret_to_bytes(coeff);
            ciphertext_data.insert(ciphertext_data.end(), bytes.begin(), bytes.end());
        }
    }


    auto shared_secret_hint = encode_color_secret(shared_secret);

    ColorCiphertext ciphertext{ciphertext_data, shared_secret_hint, params_};

    return {ciphertext, shared_secret};
}

std::pair<ColorCiphertext, ColorValue> ColorKEM::encapsulate_deterministic(const ColorPublicKey& public_key,
                                                                        const std::array<uint8_t, 32>& r_seed,
                                                                        const std::array<uint8_t, 32>& e1_seed,
                                                                        const std::array<uint8_t, 32>& e2_seed,
                                                                        const ColorValue& shared_secret) {

    // Validate public key parameters match instance parameters
    if (public_key.params.security_level != params_.security_level ||
        public_key.params.modulus != params_.modulus ||
        public_key.params.degree != params_.degree ||
        public_key.params.module_rank != params_.module_rank) {
        throw std::invalid_argument("Public key parameters do not match KEM instance parameters");
    }

    // Validate public key data size
    if (public_key.public_data.size() != params_.module_rank * params_.degree * 4) {
        throw std::invalid_argument("Invalid public key data size: expected " + std::to_string(params_.module_rank * params_.degree * 4) + " bytes, got " + std::to_string(public_key.public_data.size()));
    }

    // Validate public key data is not empty and properly sized
    if (public_key.public_data.empty()) {
        throw std::invalid_argument("Public key data cannot be empty");
    }

    auto matrix_A = generate_matrix_A(public_key.seed);

    std::vector<std::vector<ColorValue>> public_key_colors(params_.module_rank, std::vector<ColorValue>(params_.degree));
    size_t idx = 0;
    for (size_t i = 0; i < params_.module_rank; ++i) {
        for (size_t d = 0; d < params_.degree; ++d) {
            std::vector<uint8_t> bytes(public_key.public_data.begin() + idx,
                                       public_key.public_data.begin() + idx + 4);
            public_key_colors[i][d] = bytes_to_color_secret(bytes);
            idx += 4;
        }
    }

    auto ciphertext_colors = encrypt_message_deterministic(matrix_A, public_key_colors, shared_secret, r_seed, e1_seed, e2_seed);


    std::vector<uint8_t> ciphertext_data;
    for (const auto& poly : ciphertext_colors) {
        for (const auto& coeff : poly) {
            auto bytes = color_secret_to_bytes(coeff);
            ciphertext_data.insert(ciphertext_data.end(), bytes.begin(), bytes.end());
        }
    }


    auto shared_secret_hint = encode_color_secret(shared_secret);

    ColorCiphertext ciphertext{ciphertext_data, shared_secret_hint, params_};

    return {ciphertext, shared_secret};
}


ColorValue ColorKEM::decapsulate(const ColorPublicKey& public_key,
                                const ColorPrivateKey& private_key,
                                const ColorCiphertext& ciphertext) {

    // Validate public key parameters match instance parameters
    if (public_key.params.security_level != params_.security_level ||
        public_key.params.modulus != params_.modulus ||
        public_key.params.degree != params_.degree ||
        public_key.params.module_rank != params_.module_rank) {
        throw std::invalid_argument("Public key parameters do not match KEM instance parameters");
    }

    // Validate private key parameters match instance parameters
    if (private_key.params.security_level != params_.security_level ||
        private_key.params.modulus != params_.modulus ||
        private_key.params.degree != params_.degree ||
        private_key.params.module_rank != params_.module_rank) {
        throw std::invalid_argument("Private key parameters do not match KEM instance parameters");
    }

    // Validate ciphertext parameters match instance parameters
    if (ciphertext.params.security_level != params_.security_level ||
        ciphertext.params.modulus != params_.modulus ||
        ciphertext.params.degree != params_.degree ||
        ciphertext.params.module_rank != params_.module_rank) {
        throw std::invalid_argument("Ciphertext parameters do not match KEM instance parameters");
    }

    // Validate private key data is not empty
    if (private_key.secret_data.empty()) {
        throw std::invalid_argument("Private key data cannot be empty");
    }

    // Unpack private key using ML-DSA format
    std::vector<std::vector<uint32_t>> secret_key_polys = unpack_polynomial_vector_ml_dsa(private_key.secret_data, params_.module_rank, params_.degree, params_.modulus, 4);

    // Convert to ColorValue
    std::vector<std::vector<ColorValue>> secret_key_colors(params_.module_rank, std::vector<ColorValue>(params_.degree));
    for (size_t i = 0; i < params_.module_rank; ++i) {
        for (size_t d = 0; d < params_.degree; ++d) {
            secret_key_colors[i][d] = ColorValue::from_math_value(secret_key_polys[i][d]);
        }
    }
    // std::cout << "DEBUG DECAP: Secret key colors (" << secret_key_colors.size() << " elements):" << std::endl;
    // for (size_t i = 0; i < secret_key_colors.size(); ++i) {
    //     std::cout << "  s[" << i << "] = " << secret_key_colors[i].to_math_value() << std::endl;
    // }

    // Validate ciphertext data size
    if (ciphertext.ciphertext_data.size() != (params_.module_rank + 1) * params_.degree * 4) {
        throw std::invalid_argument("Invalid ciphertext data size: expected " + std::to_string((params_.module_rank + 1) * params_.degree * 4) + " bytes, got " + std::to_string(ciphertext.ciphertext_data.size()));
    }

    // Validate ciphertext data is not empty
    if (ciphertext.ciphertext_data.empty()) {
        throw std::invalid_argument("Ciphertext data cannot be empty");
    }

    // Validate shared secret hint size
    if (ciphertext.shared_secret_hint.size() != 4) {
        throw std::invalid_argument("Invalid shared secret hint size: expected 4 bytes, got " + std::to_string(ciphertext.shared_secret_hint.size()));
    }

    std::vector<std::vector<ColorValue>> ciphertext_colors(params_.module_rank + 1, std::vector<ColorValue>(params_.degree));
    size_t idx = 0;
    for (size_t i = 0; i < params_.module_rank + 1; ++i) {
        for (size_t d = 0; d < params_.degree; ++d) {
            std::vector<uint8_t> bytes(ciphertext.ciphertext_data.begin() + idx,
                                       ciphertext.ciphertext_data.begin() + idx + 4);
            ciphertext_colors[i][d] = bytes_to_color_secret(bytes);
            idx += 4;
        }
    }
    // std::cout << "DEBUG DECAP: Ciphertext colors (" << ciphertext_colors.size() << " elements):" << std::endl;
    // for (size_t i = 0; i < ciphertext_colors.size(); ++i) {
    //     std::cout << "  c[" << i << "] = " << ciphertext_colors[i].to_math_value() << std::endl;
    // }

    ColorValue recovered_secret = decrypt_message(secret_key_colors, ciphertext_colors);
    // std::cout << "DEBUG DECAP: Recovered secret = " << recovered_secret.to_precise_value() << std::endl;

    // Fujisaki-Okamoto transform for IND-CCA2 security
    ColorValue hinted_secret = decode_color_secret(ciphertext.shared_secret_hint);
    if (recovered_secret == hinted_secret) {
        return recovered_secret;
    } else {
        return hash_ciphertext(ciphertext);
    }
}

ColorValue ColorKEM::hash_ciphertext(const ColorCiphertext& ciphertext) const {
    auto ct_serial = ciphertext.serialize();
    SHAKE256Sampler shake;
    shake.init(ct_serial.data(), ct_serial.size());

    std::array<uint8_t, 4> hash_bytes;
    shake.squeeze(hash_bytes.data(), 4);

    uint32_t hash_value = (static_cast<uint32_t>(hash_bytes[0]) << 24) |
                          (static_cast<uint32_t>(hash_bytes[1]) << 16) |
                          (static_cast<uint32_t>(hash_bytes[2]) << 8) |
                          static_cast<uint32_t>(hash_bytes[3]);

    return ColorValue::from_math_value(hash_value % params_.modulus);
}


bool ColorKEM::verify_keypair(const ColorPublicKey& public_key, const ColorPrivateKey& private_key) const {
    
    return public_key.params.security_level == private_key.params.security_level &&
           public_key.params.modulus == private_key.params.modulus;
}


std::vector<uint8_t> ColorKEM::color_secret_to_bytes(const ColorValue& secret) {
    uint32_t value = secret.to_math_value();
    // Validate value is within reasonable bounds (though ColorValue should ensure this)
    if (value > 0xFFFFFFFF) {
        throw std::invalid_argument("Color value too large for serialization: " + std::to_string(value));
    }
    return {
        static_cast<uint8_t>((value >> 24) & 0xFF),
        static_cast<uint8_t>((value >> 16) & 0xFF),
        static_cast<uint8_t>((value >> 8) & 0xFF),
        static_cast<uint8_t>(value & 0xFF)
    };
}

ColorValue ColorKEM::bytes_to_color_secret(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 4) {
        throw std::invalid_argument("Insufficient bytes for color secret: need 4 bytes, got " + std::to_string(bytes.size()));
    }

    if (bytes.size() > 4) {
        throw std::invalid_argument("Too many bytes for color secret: expected 4 bytes, got " + std::to_string(bytes.size()));
    }

    uint32_t value = (static_cast<uint32_t>(bytes[0]) << 24) |
                    (static_cast<uint32_t>(bytes[1]) << 16) |
                    (static_cast<uint32_t>(bytes[2]) << 8) |
                    static_cast<uint32_t>(bytes[3]);

    return ColorValue::from_math_value(value);
}


std::vector<uint8_t> ColorPublicKey::serialize() const {
    // Validate seed size
    if (seed.size() != 32) {
        throw std::invalid_argument("Invalid seed size: expected 32 bytes, got " + std::to_string(seed.size()));
    }

    // Validate public data size (should be multiple of 4 for ColorValue serialization)
    if (public_data.size() % 4 != 0 || public_data.empty()) {
        throw std::invalid_argument("Invalid public data size: must be non-empty and multiple of 4 bytes, got " + std::to_string(public_data.size()));
    }

    std::vector<uint8_t> data;

    // Add compression header
    data.push_back(0x01); // Version 1
    data.push_back(0x01); // Format flag (1 = compressed public key)

    // Store original public data size
    uint32_t original_size = public_data.size();
    data.push_back(static_cast<uint8_t>(original_size >> 24));
    data.push_back(static_cast<uint8_t>(original_size >> 16));
    data.push_back(static_cast<uint8_t>(original_size >> 8));
    data.push_back(static_cast<uint8_t>(original_size & 0xFF));

    data.insert(data.end(), seed.begin(), seed.end());

    // Use compressed encoding for public data
    auto compressed_data = encode_polynomial_vector_as_colors_compressed(public_data, params.modulus);
    data.insert(data.end(), compressed_data.begin(), compressed_data.end());

    return data;
}

ColorPublicKey ColorPublicKey::deserialize(const std::vector<uint8_t>& data, const CLWEParameters& params) {
    if (data.size() < 40) { // Minimum: header(8) + seed(32)
        throw std::invalid_argument("Public key data too small: minimum 40 bytes required, got " + std::to_string(data.size()));
    }

    if (data.empty()) {
        throw std::invalid_argument("Public key data cannot be empty");
    }

    size_t offset = 0;
    uint8_t version = data[offset++];
    uint8_t format_flag = data[offset++];

    // Check if this is compressed format
    if (version == 0x01 && format_flag == 0x01) {
        // Compressed format
        uint32_t original_size = (static_cast<uint32_t>(data[offset]) << 24) |
                                (static_cast<uint32_t>(data[offset + 1]) << 16) |
                                (static_cast<uint32_t>(data[offset + 2]) << 8) |
                                data[offset + 3];
        offset += 4;

        if (offset + 32 > data.size()) {
            throw std::invalid_argument("Public key data too small for seed");
        }

        ColorPublicKey key;
        std::copy(data.begin() + offset, data.begin() + offset + 32, key.seed.begin());
        offset += 32;

        // Decompress the public data
        std::vector<uint8_t> compressed_data(data.begin() + offset, data.end());
        key.public_data = decode_colors_to_polynomial_vector_compressed(compressed_data, params.module_rank, params.degree, params.modulus);
        key.params = params;

        // Validate public data size (should be multiple of 4 for ColorValue serialization and non-empty)
        if (key.public_data.size() % 4 != 0 || key.public_data.empty()) {
            throw std::invalid_argument("Invalid public key data size: must be non-empty and multiple of 4 bytes, got " + std::to_string(key.public_data.size()));
        }
        return key;
    } else {
        // Legacy uncompressed format (for backward compatibility)
        ColorPublicKey key;
        std::copy(data.begin(), data.begin() + 32, key.seed.begin());
        key.public_data.assign(data.begin() + 32, data.end());
        key.params = params;

        // Validate public data size (should be multiple of 4 for ColorValue serialization and non-empty)
        if (key.public_data.size() % 4 != 0 || key.public_data.empty()) {
            throw std::invalid_argument("Invalid public key data size: must be non-empty and multiple of 4 bytes, got " + std::to_string(key.public_data.size()));
        }
        return key;
    }
}

std::vector<uint8_t> ColorPrivateKey::serialize() const {
    // Validate secret data size (should be multiple of 4 for ColorValue serialization)
    if (secret_data.size() % 4 != 0 || secret_data.empty()) {
        throw std::invalid_argument("Invalid secret data size: must be non-empty and multiple of 4 bytes, got " + std::to_string(secret_data.size()));
    }

    std::vector<uint8_t> data;

    // Add compression header
    data.push_back(0x01); // Version 1
    data.push_back(0x02); // Format flag (2 = compressed private key)

    // Store original secret data size
    uint32_t original_size = secret_data.size();
    data.push_back(static_cast<uint8_t>(original_size >> 24));
    data.push_back(static_cast<uint8_t>(original_size >> 16));
    data.push_back(static_cast<uint8_t>(original_size >> 8));
    data.push_back(static_cast<uint8_t>(original_size & 0xFF));

    // Use compressed encoding for secret data
    auto compressed_data = encode_polynomial_vector_as_colors_compressed(secret_data, params.modulus);
    data.insert(data.end(), compressed_data.begin(), compressed_data.end());

    return data;
}

ColorPrivateKey ColorPrivateKey::deserialize(const std::vector<uint8_t>& data, const CLWEParameters& params) {
    if (data.empty()) {
        throw std::invalid_argument("Private key data cannot be empty");
    }

    // Check if this is ML-DSA format
    if (data.size() >= 6 && data[0] == 0x03 && data[1] == 0x08) {
        // ML-DSA format
        ColorPrivateKey key;
        key.secret_data = data;  // Keep the packed data
        key.params = params;
        return key;
    } else if (data.size() < 8) { // Minimum: header(8)
        throw std::invalid_argument("Private key data too small: minimum 8 bytes required, got " + std::to_string(data.size()));
    } else {
        size_t offset = 0;
        uint8_t version = data[offset++];
        uint8_t format_flag = data[offset++];

        // Check if this is compressed format
        if (version == 0x01 && format_flag == 0x02) {
            // Compressed format
            uint32_t original_size = (static_cast<uint32_t>(data[offset]) << 24) |
                                    (static_cast<uint32_t>(data[offset + 1]) << 16) |
                                    (static_cast<uint32_t>(data[offset + 2]) << 8) |
                                    data[offset + 3];
            offset += 4;

            ColorPrivateKey key;

            // Decompress the secret data
            std::vector<uint8_t> compressed_data(data.begin() + offset, data.end());
            key.secret_data = decode_colors_to_polynomial_vector_compressed(compressed_data, params.module_rank, params.degree, params.modulus);
            key.params = params;

            // Validate secret data size (should be multiple of 4 for ColorValue serialization and non-empty)
            if (key.secret_data.size() % 4 != 0 || key.secret_data.empty()) {
                throw std::invalid_argument("Invalid private key data size: must be non-empty and multiple of 4 bytes, got " + std::to_string(key.secret_data.size()));
            }
            return key;
        } else {
            // Legacy uncompressed format (for backward compatibility)
            ColorPrivateKey key;
            key.secret_data = data;
            key.params = params;

            // Validate secret data size (should be multiple of 4 for ColorValue serialization and non-empty)
            if (key.secret_data.size() % 4 != 0 || key.secret_data.empty()) {
                throw std::invalid_argument("Invalid private key data size: must be non-empty and multiple of 4 bytes, got " + std::to_string(key.secret_data.size()));
            }
            return key;
        }
    }
}

std::vector<uint8_t> ColorCiphertext::serialize() const {
    // Validate ciphertext data size (should be multiple of 4 for ColorValue serialization)
    if (ciphertext_data.size() % 4 != 0 || ciphertext_data.empty()) {
        throw std::invalid_argument("Invalid ciphertext data size: must be non-empty and multiple of 4 bytes, got " + std::to_string(ciphertext_data.size()));
    }

    // Validate shared secret hint size
    if (shared_secret_hint.size() != 4) {
        throw std::invalid_argument("Invalid shared secret hint size: expected 4 bytes, got " + std::to_string(shared_secret_hint.size()));
    }

    std::vector<uint8_t> data;
    data.insert(data.end(), ciphertext_data.begin(), ciphertext_data.end());
    data.insert(data.end(), shared_secret_hint.begin(), shared_secret_hint.end());
    return data;
}

ColorCiphertext ColorCiphertext::deserialize(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        throw std::invalid_argument("Ciphertext data cannot be empty");
    }

    if (data.size() < 8 || data.size() % 4 != 0) {
        throw std::invalid_argument("Invalid ciphertext data: size must be at least 8 bytes and multiple of 4, got " + std::to_string(data.size()));
    }

    ColorCiphertext ct;

    // shared_secret_hint is always 4 bytes
    size_t hint_size = 4;
    size_t ciphertext_size = data.size() - hint_size;

    // Ensure ciphertext data is not empty
    if (ciphertext_size == 0) {
        throw std::invalid_argument("Ciphertext data portion cannot be empty");
    }

    ct.ciphertext_data.assign(data.begin(), data.begin() + ciphertext_size);
    ct.shared_secret_hint.assign(data.begin() + ciphertext_size, data.end());

    // Validate shared secret hint size
    if (ct.shared_secret_hint.size() != 4) {
        throw std::invalid_argument("Invalid shared secret hint size: expected 4 bytes, got " + std::to_string(ct.shared_secret_hint.size()));
    }

    return ct;
}

ColorCiphertext ColorCiphertext::deserialize(const std::vector<uint8_t>& data, const CLWEParameters& params) {
    ColorCiphertext ct = deserialize(data);
    ct.params = params;
    return ct;
}


std::vector<std::vector<ColorValue>> ColorKEM::encrypt_message(const std::vector<std::vector<std::vector<ColorValue>>>& matrix_A,
                                                   const std::vector<std::vector<ColorValue>>& public_key,
                                                   const ColorValue& message) const {

    // Validate matrix_A dimensions
    if (matrix_A.size() != params_.module_rank) {
        throw std::invalid_argument("Invalid matrix_A rows: expected " + std::to_string(params_.module_rank) + ", got " + std::to_string(matrix_A.size()));
    }
    for (const auto& row : matrix_A) {
        if (row.size() != params_.module_rank) {
            throw std::invalid_argument("Invalid matrix_A columns: expected " + std::to_string(params_.module_rank) + " per row");
        }
    }

    // Validate public_key size
    if (public_key.size() != params_.module_rank) {
        throw std::invalid_argument("Invalid public_key size: expected " + std::to_string(params_.module_rank) + ", got " + std::to_string(public_key.size()));
    }

    // Validate message value is within modulus
    if (message.to_math_value() >= params_.modulus) {
        throw std::invalid_argument("Invalid message value: must be less than modulus " + std::to_string(params_.modulus));
    }

    std::vector<std::vector<ColorValue>> ciphertext(params_.module_rank + 1, std::vector<ColorValue>(params_.degree));

    auto r_vector = generate_secret_key(params_.eta2);

    auto e1_vector = generate_error_vector(params_.eta2);
    auto e2_vector = generate_error_vector(params_.eta2);
    auto e2 = e2_vector[0];

    auto A_trans_r = matrix_transpose_vector_mul(matrix_A, r_vector);
    for (uint32_t i = 0; i < params_.module_rank; ++i) {
        for (uint32_t d = 0; d < params_.degree; ++d) {
            uint64_t atr_val = A_trans_r[i][d].to_math_value();
            uint64_t e1_val = e1_vector[i][d].to_math_value();
            uint64_t c1_val = (atr_val + e1_val) % params_.modulus;
            ciphertext[i][d] = ColorValue::from_math_value(c1_val);
        }
    }

    std::vector<ColorValue> inner_product_poly(params_.degree, ColorValue(0, 0, 0, 0));
    for (uint32_t i = 0; i < params_.module_rank; ++i) {
        std::vector<ColorValue> product(params_.degree);
        color_ntt_engine_->multiply_colors(public_key[i].data(), r_vector[i].data(), product.data());
        for (uint32_t d = 0; d < params_.degree; ++d) {
            uint64_t ip_val = inner_product_poly[d].to_math_value();
            uint64_t p_val = product[d].to_math_value();
            inner_product_poly[d] = ColorValue::from_math_value((ip_val + p_val) % params_.modulus);
        }
    }

    uint64_t inner_product = inner_product_poly[0].to_math_value(); // Constant term

    uint64_t e2_val = e2[0].to_math_value(); // Constant term
    uint64_t m_val = message.to_math_value();

    uint64_t q_half = params_.modulus / 2;
    uint64_t encoded_m = m_val * q_half;
    uint64_t c2_val = (inner_product + e2_val + encoded_m) % params_.modulus;

    ciphertext[params_.module_rank][0] = ColorValue::from_math_value(c2_val);
    for (uint32_t d = 1; d < params_.degree; ++d) {
        ciphertext[params_.module_rank][d] = ColorValue(0, 0, 0, 0); // Zero elsewhere
    }

    return ciphertext;
}

std::vector<std::vector<ColorValue>> ColorKEM::encrypt_message_deterministic(const std::vector<std::vector<std::vector<ColorValue>>>& matrix_A,
                                                                const std::vector<std::vector<ColorValue>>& public_key,
                                                                const ColorValue& message,
                                                                const std::array<uint8_t, 32>& r_seed,
                                                                const std::array<uint8_t, 32>& e1_seed,
                                                                const std::array<uint8_t, 32>& e2_seed) const {

    // Validate matrix_A dimensions
    if (matrix_A.size() != params_.module_rank) {
        throw std::invalid_argument("Invalid matrix_A rows: expected " + std::to_string(params_.module_rank) + ", got " + std::to_string(matrix_A.size()));
    }
    for (const auto& row : matrix_A) {
        if (row.size() != params_.module_rank) {
            throw std::invalid_argument("Invalid matrix_A columns: expected " + std::to_string(params_.module_rank) + " per row");
        }
    }

    // Validate public_key size
    if (public_key.size() != params_.module_rank) {
        throw std::invalid_argument("Invalid public_key size: expected " + std::to_string(params_.module_rank) + ", got " + std::to_string(public_key.size()));
    }

    // Validate message value is within modulus
    if (message.to_math_value() >= params_.modulus) {
        throw std::invalid_argument("Invalid message value: must be less than modulus " + std::to_string(params_.modulus));
    }

    std::vector<std::vector<ColorValue>> ciphertext(params_.module_rank + 1, std::vector<ColorValue>(params_.degree));

    auto r_vector = generate_secret_key_deterministic(params_.eta2, r_seed);

    auto e1_vector = generate_error_vector_deterministic(params_.eta2, e1_seed);
    auto e2_vector = generate_error_vector_deterministic(params_.eta2, e2_seed);
    auto e2 = e2_vector[0];

    auto A_trans_r = matrix_transpose_vector_mul(matrix_A, r_vector);
    for (uint32_t i = 0; i < params_.module_rank; ++i) {
        for (uint32_t d = 0; d < params_.degree; ++d) {
            uint64_t atr_val = A_trans_r[i][d].to_math_value();
            uint64_t e1_val = e1_vector[i][d].to_math_value();
            uint64_t c1_val = (atr_val + e1_val) % params_.modulus;
            ciphertext[i][d] = ColorValue::from_math_value(c1_val);
        }
    }

    std::vector<ColorValue> inner_product_poly(params_.degree, ColorValue(0, 0, 0, 0));
    for (uint32_t i = 0; i < params_.module_rank; ++i) {
        std::vector<ColorValue> product(params_.degree);
        color_ntt_engine_->multiply_colors(public_key[i].data(), r_vector[i].data(), product.data());
        for (uint32_t d = 0; d < params_.degree; ++d) {
            uint64_t ip_val = inner_product_poly[d].to_math_value();
            uint64_t p_val = product[d].to_math_value();
            inner_product_poly[d] = ColorValue::from_math_value((ip_val + p_val) % params_.modulus);
        }
    }

    uint64_t inner_product = inner_product_poly[0].to_math_value(); // Constant term

    uint64_t e2_val = e2[0].to_math_value(); // Constant term
    uint64_t m_val = message.to_math_value();

    uint64_t q_half = params_.modulus / 2;
    uint64_t encoded_m = m_val * q_half;
    uint64_t c2_val = (inner_product + e2_val + encoded_m) % params_.modulus;

    ciphertext[params_.module_rank][0] = ColorValue::from_math_value(c2_val);
    for (uint32_t d = 1; d < params_.degree; ++d) {
        ciphertext[params_.module_rank][d] = ColorValue(0, 0, 0, 0); // Zero elsewhere
    }

    return ciphertext;
}

} 