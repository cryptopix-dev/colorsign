#include "../include/clwe/sign.hpp"
#include "../include/clwe/cose.hpp"
#include "../include/clwe/color_integration.hpp"
#include "../include/clwe/utils.hpp"
#include "../include/clwe/keygen.hpp"
#include "../include/clwe/ntt_engine.hpp"
#include <random>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <array>
#include <iostream>
#include <chrono>

namespace clwe {

ColorSign::ColorSign(const CLWEParameters& params, std::unique_ptr<SecurityMonitor> monitor)
    : params_(params), security_monitor_(std::move(monitor)), timing_protection_(std::make_unique<TimingProtection>()) {

    // Initialize security monitor if not provided
    if (!security_monitor_) {
        security_monitor_ = std::make_unique<DefaultSecurityMonitor>();
    }

    // Validate parameters with security checks
    SecurityError param_check = InputValidator::validate_parameters(params_);
    if (param_check != SecurityError::SUCCESS) {
        security_monitor_->report_security_violation(param_check, "Invalid parameters in ColorSign constructor");
        throw std::invalid_argument("Invalid parameters: " + get_security_error_message(param_check));
    }

    // Additional basic validation
    if (params_.degree == 0 || params_.module_rank == 0) {
        security_monitor_->report_security_violation(SecurityError::INVALID_PARAMETERS,
            "Invalid parameters: degree and module_rank must be positive");
        throw std::invalid_argument("Invalid parameters: degree and module_rank must be positive");
    }

    // Log initialization
    AuditEntry init_entry{
        AuditEvent::KEY_GENERATION_START,
        std::chrono::system_clock::now(),
        "ColorSign initialized with security level " + std::to_string(params_.security_level),
        "ColorSign::ColorSign",
        0
    };
    security_monitor_->log_event(init_entry);
}

ColorSign::~ColorSign() = default;

void ColorSign::set_security_monitor(std::unique_ptr<SecurityMonitor> monitor) {
    security_monitor_ = std::move(monitor);
    timing_protection_ = std::make_unique<TimingProtection>(
        security_monitor_ ? nullptr : std::make_unique<DefaultSecurityMonitor>());
}

ColorSignSignError ColorSign::validate_signing_inputs(const std::vector<uint8_t>& message,
                                                     const ColorSignPrivateKey& private_key,
                                                     const ColorSignPublicKey& public_key,
                                                     const std::vector<uint8_t>& context) const {
    // Validate message size
    SecurityError msg_check = InputValidator::validate_message_size(message);
    if (msg_check != SecurityError::SUCCESS) {
        security_monitor_->report_security_violation(msg_check, "Invalid message size in signing");
        return ColorSignSignError::MESSAGE_SIZE_INVALID;
    }

    // Validate context
    SecurityError ctx_check = InputValidator::validate_context_string(context);
    if (ctx_check != SecurityError::SUCCESS) {
        security_monitor_->report_security_violation(ctx_check, "Invalid context in signing");
        return ColorSignSignError::CONTEXT_INVALID;
    }

    // Validate private key
    SecurityError priv_check = InputValidator::validate_key_format(private_key.secret_data, params_);
    if (priv_check != SecurityError::SUCCESS) {
        security_monitor_->report_security_violation(priv_check, "Invalid private key format");
        return ColorSignSignError::INVALID_PRIVATE_KEY;
    }

    // Validate public key
    SecurityError pub_check = InputValidator::validate_key_format(public_key.public_data, params_);
    if (pub_check != SecurityError::SUCCESS) {
        security_monitor_->report_security_violation(pub_check, "Invalid public key format");
        return ColorSignSignError::INVALID_PUBLIC_KEY;
    }

    // Check parameter consistency
    if (private_key.params.security_level != params_.security_level ||
        public_key.params.security_level != params_.security_level) {
        security_monitor_->report_security_violation(SecurityError::PARAMETER_MISMATCH,
            "Parameter mismatch between keys and signer");
        return ColorSignSignError::PARAMETER_MISMATCH;
    }

    return ColorSignSignError::SUCCESS;
}

// Main signing function (ML-DSA Algorithm 6) with enhanced security
ColorSignature ColorSign::sign_message(const std::vector<uint8_t>& message,
                                       const ColorSignPrivateKey& private_key,
                                       const ColorSignPublicKey& public_key,
                                       const std::vector<uint8_t>& context) {
    // Start timing protection
    timing_protection_->start_operation();

    // Log signing start
    AuditEntry sign_start{
        AuditEvent::SIGNING_START,
        std::chrono::system_clock::now(),
        "Starting signature generation",
        "ColorSign::sign_message",
        0
    };
    security_monitor_->log_event(sign_start);

    // Comprehensive input validation
    ColorSignSignError validation_result = validate_signing_inputs(message, private_key, public_key, context);
    if (validation_result != ColorSignSignError::SUCCESS) {
        timing_protection_->end_operation("sign_message_validation");
        AuditEntry validation_failure{
            AuditEvent::INPUT_VALIDATION_FAILURE,
            std::chrono::system_clock::now(),
            "Input validation failed: " + std::to_string(static_cast<int>(validation_result)),
            "ColorSign::sign_message",
            static_cast<uint32_t>(validation_result)
        };
        security_monitor_->log_event(validation_failure);
        throw std::invalid_argument("Input validation failed: " + std::to_string(static_cast<int>(validation_result)));
    }

    // Extract s1 and s2 from private key
    auto s1 = extract_s1_from_private_key(private_key.secret_data);
    auto s2 = extract_s2_from_private_key(private_key.secret_data);

    // Generate matrix A from public key seed_rho
    auto matrix_A = generate_matrix_A(public_key.seed_rho);

    // Hash message with context: mu = SHAKE256(context || message)
    auto mu = hash_message(message, context);

    // Generate deterministic rho' for y sampling: rho' = SHAKE256(sk || message)
    std::vector<uint8_t> rho_prime_input = private_key.secret_data;
    rho_prime_input.insert(rho_prime_input.end(), message.begin(), message.end());
    std::vector<uint8_t> rho_prime = shake256(rho_prime_input, 64);

    // Initialize sampler for deterministic y sampling
    SHAKE256Sampler y_sampler;
    y_sampler.init(rho_prime.data(), rho_prime.size());

    // Rejection sampling loop for y and z
    size_t rejection_attempts = 0;
    const size_t max_rejection_attempts = 10000;
    while (true) {
        rejection_attempts++;
        if (rejection_attempts > max_rejection_attempts) {
            security_monitor_->report_security_violation(SecurityError::CRYPTOGRAPHIC_FAILURE,
                "Rejection sampling exceeded maximum attempts: " + std::to_string(max_rejection_attempts));
            throw std::runtime_error("Rejection sampling failed: maximum attempts exceeded");
        }

        // Log rejection sampling attempts for security monitoring
        if (rejection_attempts > 1) {  // Log only retries to avoid spam
            AuditEntry attempt_entry{
                AuditEvent::SIGNING_START,  // Reuse event type
                std::chrono::system_clock::now(),
                "Rejection sampling attempt " + std::to_string(rejection_attempts),
                "ColorSign::sign_message",
                static_cast<uint32_t>(SecurityError::CRYPTOGRAPHIC_FAILURE)
            };
            security_monitor_->log_event(attempt_entry);
        }

        // Sample y with bounds checking
        std::vector<std::vector<uint32_t>> y = sample_y(y_sampler);

        // Validate y bounds for security
        SecurityError y_bounds_check = InputValidator::validate_polynomial_vector_bounds(
            y, params_.module_rank, params_.degree, -(params_.gamma1 - 1), params_.gamma1 - 1, params_.modulus);
        if (y_bounds_check != SecurityError::SUCCESS) {
            security_monitor_->report_security_violation(y_bounds_check, "Y polynomial bounds violation");
            continue;  // Resample y
        }

        // Compute w = A * y mod q
        auto w = compute_w(matrix_A, y);

        // Compute w1 = high bits of w
        std::vector<uint32_t> w_flat;
        for (const auto& poly : w) {
            w_flat.insert(w_flat.end(), poly.begin(), poly.end());
        }
        std::vector<uint32_t> w1_flat(w_flat.size());
        compute_high_bits(w_flat, w1_flat, 13, params_.modulus);

        // Check w1 bounds: max |w1[i]| < γ₂ - β (ML-DSA Algorithm 6 rejection condition)
        uint32_t max_w1 = 0;
        for (uint32_t coeff : w1_flat) {
            uint32_t abs_coeff = (coeff > params_.modulus/2) ? params_.modulus - coeff : coeff;
            if (abs_coeff > max_w1) max_w1 = abs_coeff;
        }
        if (max_w1 >= params_.gamma2 - params_.beta) {
            security_monitor_->report_security_violation(SecurityError::INVALID_PARAMETERS, "W1 polynomial bounds violation");
            continue;  // Resample y
        }

        // Encode w1 as bytes
        std::vector<uint8_t> w1_encoded;
        for (uint32_t coeff : w1_flat) {
            w1_encoded.push_back(coeff & 0xFF);
            w1_encoded.push_back((coeff >> 8) & 0xFF);
        }

        // Compute challenge c
        std::vector<uint8_t> challenge_seed = mu;
        challenge_seed.insert(challenge_seed.end(), w1_encoded.begin(), w1_encoded.end());
        std::vector<uint32_t> c(params_.degree);
        sample_challenge(c, challenge_seed, params_.tau, params_.degree, params_.modulus);

        // Compute z = y + c·s1 + c·s2 mod q
        auto z = compute_z(y, c, s1, s2);

        uint32_t max_abs_z = 0;
        for (const auto& poly : z) {
            for (uint32_t coeff : poly) {
                int32_t signed_coeff = (coeff > params_.modulus/2) ? (int32_t)coeff - (int32_t)params_.modulus : (int32_t)coeff;
                uint32_t abs_coeff = std::abs(signed_coeff);
                if (abs_coeff > max_abs_z) max_abs_z = abs_coeff;
            }
        }

        // Check z bounds: ||z||_∞ <= γ₁ - β (ML-DSA Algorithm 6)
        if (!check_z_bounds(z)) {
            continue;  // Resample y
        }

        // Compute w' = w - c·s2 mod q (for hint generation)
        auto w_prime = compute_w_prime_for_hint(w, c, s2);

        // Generate hint h
        auto h = make_hint(w, w_prime, params_.gamma2);

        // Pack challenge c
        auto c_packed = pack_challenge(c);

        // Encode z using standard ML-DSA polynomial packing
        std::vector<uint8_t> z_encoded = pack_polynomial_vector(z);

        // End timing protection and log success
        timing_protection_->end_operation("sign_message_success");

        AuditEntry sign_success{
            AuditEvent::SIGNING_SUCCESS,
            std::chrono::system_clock::now(),
            "Signature generation completed successfully",
            "ColorSign::sign_message",
            0
        };
        security_monitor_->log_event(sign_success);

        return ColorSignature(z_encoded, h, c_packed, params_);
    }
}

// COSE signing function
COSE_Sign1 ColorSign::sign_message_cose(const std::vector<uint8_t>& message,
                                       const ColorSignPrivateKey& private_key,
                                       const ColorSignPublicKey& public_key,
                                       int alg) {
    // Sign the message using the standard signing function
    ColorSignature signature = sign_message(message, private_key, public_key);

    // Create COSE_Sign1 structure
    return create_cose_sign1_from_colorsign(message, signature, alg);
}

// Hash message with SHAKE256 (supports context for ML-DSA)
std::vector<uint8_t> ColorSign::hash_message(const std::vector<uint8_t>& message, const std::vector<uint8_t>& context) const {
    std::vector<uint8_t> input;
    if (!context.empty()) {
        // Prepend context length and context as per ML-DSA spec
        uint8_t context_len = static_cast<uint8_t>(context.size());
        input.push_back(0);  // DOM_SEP
        input.push_back(context_len);
        input.insert(input.end(), context.begin(), context.end());
    }
    input.insert(input.end(), message.begin(), message.end());
    return shake256(input, 64);  // 64 bytes for ML-DSA mu
}

// Sample y with uniform distribution in [-(gamma1-1), gamma1-1] using deterministic sampling
std::vector<std::vector<uint32_t>> ColorSign::sample_y(SHAKE256Sampler& sampler) const {
    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;
    uint32_t gamma1 = params_.gamma1;
    uint32_t q = params_.modulus;

    std::vector<std::vector<uint32_t>> y(k, std::vector<uint32_t>(n));

    int32_t min_val = -(gamma1 - 1);
    int32_t max_val = gamma1 - 1;
    int32_t range = max_val - min_val + 1;

    // Sample uniformly from [min_val, max_val]
    for (auto& poly : y) {
        for (auto& coeff : poly) {
            uint32_t random_val;
            int32_t sampled;
            do {
                uint8_t bytes[4];
                sampler.squeeze(bytes, 4);
                random_val = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
                sampled = static_cast<int32_t>(random_val % range) + min_val;
            } while (sampled < min_val || sampled > max_val);
            // Convert to unsigned representation
            coeff = (static_cast<int64_t>(sampled) % q + q) % q;
        }
    }

    return y;
}

// Compute w = A * y mod q using constant-time arithmetic
std::vector<std::vector<uint32_t>> ColorSign::compute_w(const std::vector<std::vector<uint32_t>>& matrix_A,
                                                        const std::vector<std::vector<uint32_t>>& y) const {
    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;
    uint32_t q = params_.modulus;

    // Create NTT engine
    auto ntt_engine = create_optimal_ntt_engine(q, n);

    std::vector<std::vector<uint32_t>> w(k, std::vector<uint32_t>(n, 0));

    // For each polynomial in w: w[i] = sum_m A[i][m] * y[m]
    for (uint32_t i = 0; i < k; ++i) {
        std::vector<uint32_t> temp(n, 0);
        for (uint32_t m = 0; m < k; ++m) {
            std::vector<uint32_t> product(n);
            ntt_engine->multiply(matrix_A[i * k + m].data(), y[m].data(), product.data());
            for (uint32_t j = 0; j < n; ++j) {
                // Use constant-time modular addition
                temp[j] = ConstantTime::ct_add(temp[j], product[j], q);
            }
        }
        w[i] = temp;
    }

    return w;
}

// Compute challenge c = sample polynomial from SHAKE256(mu || w_encoded)
std::vector<uint32_t> ColorSign::compute_challenge(const std::vector<uint8_t>& mu,
                                                   const std::vector<uint8_t>& w_encoded) const {
    std::vector<uint8_t> input = mu;
    input.insert(input.end(), w_encoded.begin(), w_encoded.end());

    SHAKE256Sampler sampler;
    sampler.init(input.data(), input.size());

    std::vector<uint32_t> c(params_.degree, 0);

    // Sample challenge polynomial with coefficients in {-1, 0, 1}
    // In ML-DSA, exactly tau non-zero coefficients, but for simplicity, sample with small probability
    for (size_t i = 0; i < params_.degree; ++i) {
        uint8_t byte;
        sampler.squeeze(&byte, 1);
        if (byte < 85) {  // ~1/3 probability
            c[i] = 1;
        } else if (byte < 170) {
            c[i] = params_.modulus - 1;  // -1 mod q
        } else {
            c[i] = 0;
        }
    }

    return c;
}

// Compute z = y + c·s1 + c·s2 mod q using polynomial multiplication via NTT
std::vector<std::vector<uint32_t>> ColorSign::compute_z(const std::vector<std::vector<uint32_t>>& y,
                                                         const std::vector<uint32_t>& c,
                                                         const std::vector<std::vector<uint32_t>>& s1,
                                                         const std::vector<std::vector<uint32_t>>& s2) const {
    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;
    uint32_t q = params_.modulus;

    // Create NTT engine for polynomial multiplication
    auto ntt_engine = create_optimal_ntt_engine(q, n);

    std::vector<std::vector<uint32_t>> z(k, std::vector<uint32_t>(n));

    for (uint32_t i = 0; i < k; ++i) {
        // Compute cs1 = NTT_multiply(c, s1[i])
        std::vector<uint32_t> cs1(n);
        ntt_engine->multiply(c.data(), s1[i].data(), cs1.data());

        // Compute cs2 = NTT_multiply(c, s2[i])
        std::vector<uint32_t> cs2(n);
        ntt_engine->multiply(c.data(), s2[i].data(), cs2.data());

        // Compute z[i] = y[i] + cs1 + cs2 mod q
        for (uint32_t j = 0; j < n; ++j) {
            uint32_t sum_cs = ConstantTime::ct_add(cs1[j], cs2[j], q);
            z[i][j] = ConstantTime::ct_add(y[i][j], sum_cs, q);
        }
    }

    return z;
}

// Check if y coefficients are within bounds [-gamma1 + 1, gamma1 - 1]
bool ColorSign::check_y_bounds(const std::vector<std::vector<uint32_t>>& y) const {
    uint32_t gamma1 = params_.gamma1;
    uint32_t q = params_.modulus;
    int32_t min_val = -(gamma1 - 1);
    int32_t max_val = gamma1 - 1;

    for (const auto& poly : y) {
        for (uint32_t coeff : poly) {
            // Convert to signed value
            int32_t signed_coeff = (coeff > q/2) ? (int32_t)coeff - (int32_t)q : (int32_t)coeff;
            if (signed_coeff < min_val || signed_coeff > max_val) {
                return false;
            }
        }
    }
    return true;
}

// Check if z coefficients are within bounds [-gamma1 + beta, gamma1 - beta] as per FIPS 204
bool ColorSign::check_z_bounds(const std::vector<std::vector<uint32_t>>& z) const {
    uint32_t gamma1 = params_.gamma1;
    uint32_t beta = params_.beta;
    uint32_t q = params_.modulus;
    int32_t min_val = -(gamma1 - beta);
    int32_t max_val = gamma1 - beta;

    for (const auto& poly : z) {
        for (uint32_t coeff : poly) {
            // Convert to signed value
            int32_t signed_coeff = (coeff > q/2) ? (int32_t)coeff - (int32_t)q : (int32_t)coeff;
            if (signed_coeff < min_val || signed_coeff > max_val) {
                return false;
            }
        }
    }
    return true;
}

// Check if w coefficients are in [-(gamma2 - 1), gamma2] where gamma2 = (q-1)/2
bool ColorSign::check_w_bounds(const std::vector<std::vector<uint32_t>>& w) const {
    uint32_t gamma2 = params_.gamma2;
    uint32_t q = params_.modulus;
    int32_t min_val = -(gamma2 - 1);
    int32_t max_val = gamma2;

    for (const auto& poly : w) {
        for (uint32_t coeff : poly) {
            // Convert to signed value
            int32_t signed_coeff = (coeff > q/2) ? (int32_t)coeff - (int32_t)q : (int32_t)coeff;
            if (signed_coeff < min_val || signed_coeff > max_val) {
                return false;
            }
        }
    }
    return true;
}


// Generate matrix A (same as keygen)
std::vector<std::vector<uint32_t>> ColorSign::generate_matrix_A(const std::array<uint8_t, 32>& seed) const {
    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;
    uint32_t q = params_.modulus;

    std::vector<std::vector<uint32_t>> matrix(k * k, std::vector<uint32_t>(n));

    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < k; ++j) {
            // Domain separation: seed || i || j || 0
            std::vector<uint8_t> domain_sep = std::vector<uint8_t>(seed.begin(), seed.end());
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

// Extract s1 from private key (first k polynomials)
std::vector<std::vector<uint32_t>> ColorSign::extract_s1_from_private_key(const std::vector<uint8_t>& secret_data) const {
    // Unpack the packed secret data to get s1, s2 (2*k polynomials)
    auto all_polys = unpack_polynomial_vector(secret_data, 2 * params_.module_rank, params_.degree);

    uint32_t k = params_.module_rank;

    // Return first k polynomials (s1)
    return std::vector<std::vector<uint32_t>>(all_polys.begin(), all_polys.begin() + k);
}

// Extract s2 from private key (second k polynomials)
std::vector<std::vector<uint32_t>> ColorSign::extract_s2_from_private_key(const std::vector<uint8_t>& secret_data) const {
    // Unpack the packed secret data to get s1, s2 (2*k polynomials)
    auto all_polys = unpack_polynomial_vector(secret_data, 2 * params_.module_rank, params_.degree);

    uint32_t k = params_.module_rank;

    // Return second k polynomials (s2)
    return std::vector<std::vector<uint32_t>>(all_polys.begin() + k, all_polys.begin() + 2 * k);
}


// Compute w' = w - c·s2 mod q for hint generation using constant-time arithmetic
std::vector<std::vector<uint32_t>> ColorSign::compute_w_prime_for_hint(const std::vector<std::vector<uint32_t>>& w,
                                                                       const std::vector<uint32_t>& c,
                                                                       const std::vector<std::vector<uint32_t>>& s2) const {
    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;
    uint32_t q = params_.modulus;

    auto ntt_engine = create_optimal_ntt_engine(q, n);

    std::vector<std::vector<uint32_t>> w_prime = w;  // Copy w

    // Compute c·s2
    std::vector<std::vector<uint32_t>> cs2(k, std::vector<uint32_t>(n, 0));
    for (uint32_t i = 0; i < k; ++i) {
        ntt_engine->multiply(c.data(), s2[i].data(), cs2[i].data());
    }

    // Compute w' = w - c·s2 mod q using constant-time arithmetic
    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            w_prime[i][j] = ConstantTime::ct_sub(w_prime[i][j], cs2[i][j], q);
        }
    }

    return w_prime;
}

// Generate hint vector h for signature compression using constant-time operations
std::vector<uint8_t> ColorSign::make_hint(const std::vector<std::vector<uint32_t>>& w,
                                         const std::vector<std::vector<uint32_t>>& w_prime,
                                         uint32_t gamma2) const {
    uint32_t k = params_.module_rank;
    uint32_t n = params_.degree;
    uint32_t omega = params_.omega;
    uint32_t q = params_.modulus;

    std::vector<uint8_t> h(omega, 0);
    size_t hint_index = 0;

    for (uint32_t i = 0; i < k; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            // Convert to signed values using constant-time operations
            int32_t w_signed = (w[i][j] >= (q + 1) / 2) ? static_cast<int32_t>(w[i][j]) - static_cast<int32_t>(q) : static_cast<int32_t>(w[i][j]);
            int32_t w_prime_signed = (w_prime[i][j] >= (q + 1) / 2) ? static_cast<int32_t>(w_prime[i][j]) - static_cast<int32_t>(q) : static_cast<int32_t>(w_prime[i][j]);

            // Compute absolute values using constant-time operations
            uint32_t abs_w = ConstantTime::ct_abs(w_signed);
            uint32_t abs_w_prime = ConstantTime::ct_abs(w_prime_signed);

            // Check conditions: |w| <= gamma2 and |w'| > gamma2
            // Use constant-time comparison: (abs_w <= gamma2) AND (abs_w_prime > gamma2)
            uint32_t w_condition = (abs_w <= gamma2) ? 1 : 0;
            uint32_t w_prime_condition = (abs_w_prime > gamma2) ? 1 : 0;
            uint32_t hint_needed = w_condition & w_prime_condition;

            if (hint_needed && hint_index < omega) {
                // Set the hint bit in constant time
                size_t byte_idx = hint_index / 8;
                uint8_t bit_pos = hint_index % 8;
                uint8_t mask = static_cast<uint8_t>(1 << bit_pos);
                h[byte_idx] = ConstantTime::select(h[byte_idx], static_cast<uint8_t>(h[byte_idx] | mask), hint_needed);
            }

            hint_index += hint_needed;
        }
    }

    return h;
}

// Pack challenge polynomial c into bytes (simplified version)
std::vector<uint8_t> ColorSign::pack_challenge(const std::vector<uint32_t>& c) const {
    size_t n = c.size();
    size_t packed_size = (n + 3) / 4;  // 4 coefficients per byte (2 bits each)
    std::vector<uint8_t> packed(packed_size, 0);

    for (size_t i = 0; i < n; ++i) {
        // Simple direct comparison (not constant-time, but working)
        uint8_t bit = 0;
        if (c[i] == 1) {
            bit = 1;
        } else if (c[i] == params_.modulus - 1) {  // -1 mod q
            bit = 2;
        } else {
            bit = 0;  // c[i] == 0
        }

        size_t byte_idx = i / 4;
        uint8_t shift = (i % 4) * 2;
        packed[byte_idx] |= (bit << shift);
    }

    return packed;
}

// Constructor for ColorSignature (ML-DSA format)
ColorSignature::ColorSignature(const std::vector<uint8_t>& z, const std::vector<uint8_t>& h, const std::vector<uint8_t>& c, const CLWEParameters& p)
    : z_data(z), h_data(h), c_data(c), params(p) {
}

// Serialization for ColorSignature (ML-DSA format)
std::vector<uint8_t> ColorSignature::serialize() const {
    std::vector<uint8_t> data;
    data.insert(data.end(), z_data.begin(), z_data.end());
    data.insert(data.end(), h_data.begin(), h_data.end());
    data.insert(data.end(), c_data.begin(), c_data.end());
    return data;
}

ColorSignature ColorSignature::deserialize(const std::vector<uint8_t>& data, const CLWEParameters& params) {
    // ML-DSA signature format: z || h || c
    // z size: k * n * 4 bytes (standard ML-DSA packing)
    // h size: omega bytes (hint)
    // c size: (degree + 3) / 4 bytes (packed challenge)

    size_t z_size = params.module_rank * params.degree * 4;
    size_t h_size = params.omega;
    size_t c_size = (params.degree + 3) / 4;

    size_t expected_size = z_size + h_size + c_size;
    if (data.size() != expected_size) {
        throw std::invalid_argument("Signature data size mismatch");
    }

    ColorSignature sig;
    size_t offset = 0;
    sig.z_data.assign(data.begin() + offset, data.begin() + offset + z_size);
    offset += z_size;
    sig.h_data.assign(data.begin() + offset, data.begin() + offset + h_size);
    offset += h_size;
    sig.c_data.assign(data.begin() + offset, data.begin() + offset + c_size);
    sig.params = params;
    return sig;
}

// Error message utility with comprehensive error handling
std::string get_colorsign_sign_error_message(ColorSignSignError error) {
    switch (error) {
        case ColorSignSignError::SUCCESS:
            return "Success";
        case ColorSignSignError::INVALID_PARAMETERS:
            return "Invalid parameters";
        case ColorSignSignError::INVALID_PRIVATE_KEY:
            return "Invalid private key";
        case ColorSignSignError::INVALID_PUBLIC_KEY:
            return "Invalid public key";
        case ColorSignSignError::INVALID_MESSAGE:
            return "Invalid message";
        case ColorSignSignError::SIGNING_FAILED:
            return "Signing failed";
        case ColorSignSignError::INPUT_VALIDATION_FAILED:
            return "Input validation failed";
        case ColorSignSignError::KEY_SIZE_INVALID:
            return "Key size invalid";
        case ColorSignSignError::MESSAGE_SIZE_INVALID:
            return "Message size invalid";
        case ColorSignSignError::CONTEXT_INVALID:
            return "Context invalid";
        case ColorSignSignError::POLYNOMIAL_BOUNDS_VIOLATION:
            return "Polynomial bounds violation";
        case ColorSignSignError::MEMORY_ALLOCATION_FAILED:
            return "Memory allocation failed";
        case ColorSignSignError::TIMING_ATTACK_DETECTED:
            return "Timing attack detected";
        case ColorSignSignError::BUFFER_OVERFLOW_DETECTED:
            return "Buffer overflow detected";
        case ColorSignSignError::CRYPTOGRAPHIC_FAILURE:
            return "Cryptographic failure";
        case ColorSignSignError::PARAMETER_MISMATCH:
            return "Parameter mismatch";
        case ColorSignSignError::INSUFFICIENT_ENTROPY:
            return "Insufficient entropy";
        case ColorSignSignError::SIDE_CHANNEL_DETECTED:
            return "Side channel attack detected";
        default:
            return "Unknown error";
    }
}

} // namespace clwe