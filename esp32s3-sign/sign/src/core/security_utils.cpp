#include "../include/clwe/security_utils.hpp"
#include "../include/clwe/parameters.hpp"
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <chrono>
#include <memory>
#include <map>
#include <cmath>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace clwe {

std::unique_ptr<SecurityMonitor> global_security_monitor;

void initialize_security_monitor(std::unique_ptr<SecurityMonitor> monitor) {
    if (!monitor) {
        global_security_monitor = std::unique_ptr<SecurityMonitor>(new DefaultSecurityMonitor());
    } else {
        global_security_monitor = std::move(monitor);
    }
}

SecurityMonitor* get_security_monitor() {
    if (!global_security_monitor) {
        initialize_security_monitor();
    }
    return global_security_monitor.get();
}

void DefaultSecurityMonitor::log_event(const AuditEntry& entry) {
    audit_log_.push_back(entry);

    if (audit_log_.size() > max_log_size_) {
        audit_log_.erase(audit_log_.begin());
    }
}

void DefaultSecurityMonitor::report_security_violation(SecurityError error, const std::string& details) {
    AuditEntry entry{
        AuditEvent::SECURITY_VIOLATION,
        std::chrono::system_clock::now(),
        details,
        "DefaultSecurityMonitor",
        static_cast<uint32_t>(error)
    };
    log_event(entry);
}

bool DefaultSecurityMonitor::detect_timing_anomaly(const std::string& operation_name, uint64_t operation_time_ns) {
    auto& history = operation_histories_[operation_name];
    history.push_back(operation_time_ns);

    if (history.size() > max_history_size_) {
        history.erase(history.begin());
    }

    if (history.size() < min_samples_for_stats_) {
        return false;
    }

    double k = operation_k_values_[operation_name];
    if (k == 0.0) {
        k = 3.0;
    }

    double sum = 0.0;
    for (auto time : history) {
        sum += static_cast<double>(time);
    }
    double mean = sum / history.size();

    double variance = 0.0;
    for (auto time : history) {
        double diff = static_cast<double>(time) - mean;
        variance += diff * diff;
    }
    variance /= history.size();
    double std_dev = std::sqrt(variance);

    double threshold = mean + k * std_dev;

    bool is_anomaly = static_cast<double>(operation_time_ns) > threshold;

    if (is_anomaly) {
        consecutive_anomalies_[operation_name]++;
        if (consecutive_anomalies_[operation_name] >= 3) {
            report_security_violation(SecurityError::TIMING_ATTACK_DETECTED,
                "Statistical timing anomaly detected in " + operation_name +
                ": " + std::to_string(operation_time_ns) + " ns (mean: " +
                std::to_string(mean) + ", std_dev: " + std::to_string(std_dev) +
                ", threshold: " + std::to_string(threshold) + ")");
            return true;
        }
    } else {
        consecutive_anomalies_[operation_name] = 0;
    }

    return false;
}

SecurityError InputValidator::validate_message_size(const std::vector<uint8_t>& message) {
    if (message.size() > MAX_MESSAGE_SIZE) {
        return SecurityError::INVALID_INPUT_SIZE;
    }
    if (message.empty()) {
        return SecurityError::INVALID_INPUT_SIZE;
    }
    return SecurityError::SUCCESS;
}

SecurityError InputValidator::validate_key_size(const std::vector<uint8_t>& key_data) {
    if (key_data.size() > MAX_KEY_SIZE) {
        return SecurityError::INVALID_KEY_FORMAT;
    }
    if (key_data.empty()) {
        return SecurityError::INVALID_KEY_FORMAT;
    }
    return SecurityError::SUCCESS;
}

SecurityError InputValidator::validate_signature_size(const std::vector<uint8_t>& signature) {
    if (signature.size() > MAX_SIGNATURE_SIZE) {
        return SecurityError::INVALID_SIGNATURE_FORMAT;
    }
    if (signature.empty()) {
        return SecurityError::INVALID_SIGNATURE_FORMAT;
    }
    return SecurityError::SUCCESS;
}

SecurityError InputValidator::validate_parameters(const CLWEParameters& params) {
    try {
        params.validate();
        return SecurityError::SUCCESS;
    } catch (const std::invalid_argument&) {
        return SecurityError::INVALID_PARAMETERS;
    }
}

SecurityError InputValidator::validate_key_format(const std::vector<uint8_t>& key_data, const CLWEParameters& params, bool is_private_key) {
    SecurityError size_check = validate_key_size(key_data);
    if (size_check != SecurityError::SUCCESS) {
        return size_check;
    }

    // Check if this is 8-bit grayscale color-encoded key
    size_t eight_bit_size = params.module_rank * params.degree * 1;
    if (key_data.size() == eight_bit_size) {
        return SecurityError::SUCCESS;
    }

    // Check if this is RGB565 color-encoded key
    size_t color_size = params.module_rank * params.degree * 2;
    if (key_data.size() == color_size) {
        return SecurityError::SUCCESS;
    }

    // Check if this is a compressed key (starts with 0x03 0x08)
    bool is_compressed = (key_data.size() >= 2 && key_data[0] == 0x03 && key_data[1] == 0x08);

    size_t expected_min_size;
    if (is_compressed) {
        // For compressed keys, minimum size is header + some data
        expected_min_size = 10;  // Header + minimal data
    } else {
        // For uncompressed keys
        expected_min_size = params.module_rank * params.degree * 4;
    }


    if (key_data.size() < expected_min_size) {
        return SecurityError::INVALID_KEY_FORMAT;
    }

    return SecurityError::SUCCESS;
}

SecurityError InputValidator::validate_context_string(const std::vector<uint8_t>& context) {
    if (context.size() > 255) {
        return SecurityError::INVALID_CONTEXT;
    }
    return SecurityError::SUCCESS;
}

SecurityError InputValidator::validate_polynomial_vector_bounds(const std::vector<std::vector<uint32_t>>& poly_vec,
                                                                uint32_t expected_k, uint32_t expected_n,
                                                                int32_t min_val, int32_t max_val, uint32_t q) {
    if (poly_vec.size() != expected_k) {
        return SecurityError::BOUNDS_CHECK_FAILURE;
    }

    for (const auto& poly : poly_vec) {
        if (poly.size() != expected_n) {
            return SecurityError::BOUNDS_CHECK_FAILURE;
        }

        for (uint32_t coeff : poly) {
            uint32_t q_half = q / 2;
            int32_t signed_coeff;
            if (coeff >= q_half) {
                signed_coeff = static_cast<int32_t>(coeff) - static_cast<int32_t>(q);
            } else {
                signed_coeff = static_cast<int32_t>(coeff);
            }

            if (signed_coeff < min_val || signed_coeff > max_val) {
                return SecurityError::BOUNDS_CHECK_FAILURE;
            }
        }
    }

    return SecurityError::SUCCESS;
}

void* SecureMemory::secure_malloc(size_t size) {
    if (size == 0) {
        return nullptr;
    }

    void* ptr = nullptr;
#ifdef _WIN32
    ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ptr) {
        VirtualLock(ptr, size);
    }
#else
    ptr = malloc(size);
#endif

    if (!ptr) {
        get_security_monitor()->report_security_violation(SecurityError::MEMORY_ALLOCATION_FAILED,
            "Failed to allocate secure memory of size " + std::to_string(size));
        return nullptr;
    }

    return ptr;
}

void SecureMemory::secure_free(void* ptr) {
    if (!ptr) return;

#ifdef _WIN32
    VirtualUnlock(ptr, 0);  // Unlock first
    VirtualFree(ptr, 0, MEM_RELEASE);
#else
    free(ptr);
#endif
}

void SecureMemory::secure_wipe(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

    if (size > 1024 * 1024 * 1024) {
        get_security_monitor()->report_security_violation(SecurityError::INVALID_MEMORY_ACCESS,
            "Attempt to wipe excessively large memory block: " + std::to_string(size) + " bytes");
        return;
    }

    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    size_t original_size = size;
    while (size--) {
        *p++ = 0;
    }

    std::memset(ptr, 0xFF, original_size);
    std::memset(ptr, 0x00, original_size);
    std::memset(ptr, 0xAA, original_size);
    std::memset(ptr, 0x00, original_size);
}

SecurityError SecureMemory::validate_buffer_bounds(const void* buffer, size_t buffer_size,
                                                  size_t access_offset, size_t access_size) {
    if (!buffer) {
        return SecurityError::INVALID_MEMORY_ACCESS;
    }

    if (access_offset > buffer_size || access_size > buffer_size - access_offset) {
        get_security_monitor()->report_security_violation(SecurityError::BUFFER_OVERFLOW_DETECTED,
            "Buffer overflow attempt: offset=" + std::to_string(access_offset) +
            ", size=" + std::to_string(access_size) + ", buffer_size=" + std::to_string(buffer_size));
        return SecurityError::BUFFER_OVERFLOW_DETECTED;
    }

    return SecurityError::SUCCESS;
}

bool ConstantTime::compare(const void* a, const void* b, size_t len) {
    if (!a || !b) return false;

    volatile uint8_t result = 0;
    const volatile uint8_t* pa = static_cast<const volatile uint8_t*>(a);
    const volatile uint8_t* pb = static_cast<const volatile uint8_t*>(b);

    for (size_t i = 0; i < len; ++i) {
        result |= (pa[i] ^ pb[i]);
    }

    return result == 0;
}

uint32_t ConstantTime::select(uint32_t a, uint32_t b, uint32_t condition) {
    uint32_t mask = -static_cast<int32_t>(condition != 0);
    return (a & mask) | (b & ~mask);
}

uint64_t ConstantTime::select(uint64_t a, uint64_t b, uint64_t condition) {
    uint64_t mask = -static_cast<int64_t>(condition != 0);
    return (a & mask) | (b & ~mask);
}

uint32_t ConstantTime::ct_min(uint32_t a, uint32_t b) {
    uint32_t diff = a - b;
    uint32_t mask = -static_cast<int32_t>(diff >> 31);
    return (a & mask) | (b & ~mask);
}

uint32_t ConstantTime::ct_max(uint32_t a, uint32_t b) {
    uint32_t diff = a - b;
    uint32_t mask = -static_cast<int32_t>(diff >> 31);
    return (b & mask) | (a & ~mask);
}

uint32_t ConstantTime::ct_abs(int32_t x) {
    int32_t mask = x >> 31;
    return (x ^ mask) - mask;
}

uint32_t ConstantTime::ct_mod(uint32_t a, uint32_t m) {
    if (m == 0) return 0;
    uint32_t result = a % m;
    if (result > m - 1) result -= m;
    return result;
}

uint32_t ConstantTime::ct_add(uint32_t a, uint32_t b, uint32_t m) {
    uint64_t sum = static_cast<uint64_t>(a) + b;
    return ct_mod(static_cast<uint32_t>(sum), m);
}

uint32_t ConstantTime::ct_sub(uint32_t a, uint32_t b, uint32_t m) {
    uint64_t diff = static_cast<uint64_t>(a) + m - b;
    return ct_mod(static_cast<uint32_t>(diff), m);
}

uint32_t ConstantTime::ct_mul(uint32_t a, uint32_t b, uint32_t m) {
    uint64_t product = static_cast<uint64_t>(a) * b;
    return ct_mod(static_cast<uint32_t>(product), m);
}

uint32_t ConstantTime::ct_array_access(const uint32_t* array, size_t size, size_t index) {
    if (!array || index >= size) {
        return 0;
    }

    uint32_t result = 0;
    for (size_t i = 0; i < size; ++i) {
        uint32_t mask = -static_cast<int32_t>(i == index);
        result |= (array[i] & mask);
    }
    return result;
}

TimingProtection::TimingProtection(std::unique_ptr<SecurityMonitor> monitor)
    : monitor_(std::move(monitor)) {
    if (!monitor_) {
        monitor_ = std::unique_ptr<SecurityMonitor>(new DefaultSecurityMonitor());
    }
}

TimingProtection::~TimingProtection() = default;

void TimingProtection::start_operation() {
    operation_start_time_ = std::chrono::high_resolution_clock::now().time_since_epoch().count();
}

void TimingProtection::end_operation(const std::string& operation_name) {
    auto end_time = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    uint64_t duration_ns = end_time - operation_start_time_;

    if (monitor_->detect_timing_anomaly(operation_name, duration_ns)) {
        AuditEntry entry{
            AuditEvent::TIMING_ANOMALY,
            std::chrono::system_clock::now(),
            "Timing anomaly in " + operation_name + ": " + std::to_string(duration_ns) + " ns",
            operation_name,
            static_cast<uint32_t>(SecurityError::TIMING_ATTACK_DETECTED)
        };
        monitor_->log_event(entry);
    }
}

uint64_t TimingProtection::get_operation_time_ns() const {
    auto current_time = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    return current_time - operation_start_time_;
}

std::string get_security_error_message(SecurityError error) {
    switch (error) {
        case SecurityError::SUCCESS:
            return "Success";
        case SecurityError::INVALID_INPUT_SIZE:
            return "Invalid input size";
        case SecurityError::INVALID_KEY_FORMAT:
            return "Invalid key format";
        case SecurityError::INVALID_SIGNATURE_FORMAT:
            return "Invalid signature format";
        case SecurityError::INVALID_PARAMETERS:
            return "Invalid parameters";
        case SecurityError::TIMING_ATTACK_DETECTED:
            return "Timing attack detected";
        case SecurityError::MEMORY_ALLOCATION_FAILED:
            return "Memory allocation failed";
        case SecurityError::BUFFER_OVERFLOW_DETECTED:
            return "Buffer overflow detected";
        case SecurityError::INVALID_MEMORY_ACCESS:
            return "Invalid memory access";
        case SecurityError::CRYPTOGRAPHIC_FAILURE:
            return "Cryptographic failure";
        case SecurityError::SIDE_CHANNEL_DETECTED:
            return "Side channel attack detected";
        case SecurityError::INSUFFICIENT_ENTROPY:
            return "Insufficient entropy";
        case SecurityError::INVALID_CONTEXT:
            return "Invalid context";
        case SecurityError::PARAMETER_MISMATCH:
            return "Parameter mismatch";
        case SecurityError::BOUNDS_CHECK_FAILURE:
            return "Bounds check failure";
        default:
            return "Unknown security error";
    }
}

} // namespace clwe