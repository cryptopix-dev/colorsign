#ifndef CLWE_SECURITY_UTILS_HPP
#define CLWE_SECURITY_UTILS_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <chrono>
#include <memory>
#include <map>

namespace clwe {

// Security configuration constants
constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024;  // 1MB max message size
constexpr size_t MAX_KEY_SIZE = 64 * 1024;       // 64KB max key size
constexpr size_t MAX_SIGNATURE_SIZE = 32 * 1024; // 32KB max signature size
constexpr uint32_t TIMING_ATTACK_MITIGATION_ROUNDS = 1000;

// Security error codes
enum class SecurityError {
    SUCCESS = 0,
    INVALID_INPUT_SIZE,
    INVALID_KEY_FORMAT,
    INVALID_SIGNATURE_FORMAT,
    INVALID_PARAMETERS,
    TIMING_ATTACK_DETECTED,
    MEMORY_ALLOCATION_FAILED,
    BUFFER_OVERFLOW_DETECTED,
    INVALID_MEMORY_ACCESS,
    CRYPTOGRAPHIC_FAILURE,
    SIDE_CHANNEL_DETECTED,
    INSUFFICIENT_ENTROPY,
    INVALID_CONTEXT,
    PARAMETER_MISMATCH,
    BOUNDS_CHECK_FAILURE
};

// Security audit event types
enum class AuditEvent {
    KEY_GENERATION_START,
    KEY_GENERATION_SUCCESS,
    KEY_GENERATION_FAILURE,
    SIGNING_START,
    SIGNING_SUCCESS,
    SIGNING_FAILURE,
    VERIFICATION_START,
    VERIFICATION_SUCCESS,
    VERIFICATION_FAILURE,
    SECURITY_VIOLATION,
    TIMING_ANOMALY,
    MEMORY_VIOLATION,
    INPUT_VALIDATION_FAILURE
};

// Audit log entry structure
struct AuditEntry {
    AuditEvent event_type;
    std::chrono::system_clock::time_point timestamp;
    std::string details;
    std::string source_function;
    uint32_t error_code;
};

// Security monitoring interface
class SecurityMonitor {
public:
    virtual ~SecurityMonitor() = default;
    virtual void log_event(const AuditEntry& entry) = 0;
    virtual void report_security_violation(SecurityError error, const std::string& details) = 0;
    virtual bool detect_timing_anomaly(const std::string& operation_name, uint64_t operation_time_ns) = 0;
};

// Default security monitor implementation
class DefaultSecurityMonitor : public SecurityMonitor {
private:
    std::vector<AuditEntry> audit_log_;
    std::map<std::string, std::vector<uint64_t>> operation_histories_;
    std::map<std::string, double> operation_k_values_;
    std::map<std::string, int> consecutive_anomalies_;
    size_t max_history_size_ = 100;
    size_t min_samples_for_stats_ = 10;
    size_t max_log_size_ = 1000;

public:
    void log_event(const AuditEntry& entry) override;
    void report_security_violation(SecurityError error, const std::string& details) override;
    bool detect_timing_anomaly(const std::string& operation_name, uint64_t operation_time_ns) override;
    const std::vector<AuditEntry>& get_audit_log() const { return audit_log_; }
    void clear_audit_log() { audit_log_.clear(); }

    // Configure threshold multiplier for operation type (default k=3.0)
    void set_operation_threshold(const std::string& operation_name, double k_value) {
        operation_k_values_[operation_name] = k_value;
    }

    // Set maximum history size for statistical calculations
    void set_max_history_size(size_t size) { max_history_size_ = size; }

    // Set maximum audit log size
    void set_max_log_size(size_t size) { max_log_size_ = size; }
};

// Input validation utilities
class InputValidator {
public:
    static SecurityError validate_message_size(const std::vector<uint8_t>& message);
    static SecurityError validate_key_size(const std::vector<uint8_t>& key_data);
    static SecurityError validate_signature_size(const std::vector<uint8_t>& signature);
    static SecurityError validate_parameters(const struct CLWEParameters& params);
    static SecurityError validate_key_format(const std::vector<uint8_t>& key_data, const CLWEParameters& params, bool is_private_key = false);
    static SecurityError validate_context_string(const std::vector<uint8_t>& context);
    static SecurityError validate_polynomial_vector_bounds(const std::vector<std::vector<uint32_t>>& poly_vec,
                                                           uint32_t expected_k, uint32_t expected_n,
                                                           int32_t min_val, int32_t max_val, uint32_t q);
};

// Memory safety utilities
class SecureMemory {
public:
    static void* secure_malloc(size_t size);
    static void secure_free(void* ptr);
    static void secure_wipe(void* ptr, size_t size);
    static SecurityError validate_buffer_bounds(const void* buffer, size_t buffer_size,
                                               size_t access_offset, size_t access_size);

    // RAII wrapper for secure memory
    template<typename T>
    class SecureBuffer {
    private:
        T* data_;
        size_t size_;
        bool wiped_;

    public:
        SecureBuffer(size_t size) : data_(nullptr), size_(size), wiped_(false) {
            data_ = static_cast<T*>(secure_malloc(size * sizeof(T)));
            if (!data_) throw std::bad_alloc();
        }

        ~SecureBuffer() {
            if (data_ && !wiped_) {
                secure_wipe(data_, size_ * sizeof(T));
            }
            secure_free(data_);
        }

        T* data() { return data_; }
        const T* data() const { return data_; }
        size_t size() const { return size_; }

        T& operator[](size_t index) {
            if (index >= size_) throw std::out_of_range("SecureBuffer index out of bounds");
            return data_[index];
        }

        const T& operator[](size_t index) const {
            if (index >= size_) throw std::out_of_range("SecureBuffer index out of bounds");
            return data_[index];
        }

        void wipe() {
            if (data_ && !wiped_) {
                secure_wipe(data_, size_ * sizeof(T));
                wiped_ = true;
            }
        }
    };
};

// Constant-time utilities
class ConstantTime {
public:
    // Constant-time comparison
    static bool compare(const void* a, const void* b, size_t len);

    // Constant-time selection
    static uint32_t select(uint32_t a, uint32_t b, uint32_t condition);
    static uint64_t select(uint64_t a, uint64_t b, uint64_t condition);

    // Constant-time min/max
    static uint32_t ct_min(uint32_t a, uint32_t b);
    static uint32_t ct_max(uint32_t a, uint32_t b);

    // Constant-time absolute value
    static uint32_t ct_abs(int32_t x);

    // Constant-time modular arithmetic
    static uint32_t ct_mod(uint32_t a, uint32_t m);
    static uint32_t ct_add(uint32_t a, uint32_t b, uint32_t m);
    static uint32_t ct_sub(uint32_t a, uint32_t b, uint32_t m);
    static uint32_t ct_mul(uint32_t a, uint32_t b, uint32_t m);

    // Constant-time array access
    static uint32_t ct_array_access(const uint32_t* array, size_t size, size_t index);
};

// Timing attack mitigation
class TimingProtection {
private:
    uint64_t operation_start_time_;
    std::unique_ptr<SecurityMonitor> monitor_;

public:
    TimingProtection(std::unique_ptr<SecurityMonitor> monitor = nullptr);
    ~TimingProtection();

    void start_operation();
    void end_operation(const std::string& operation_name);
    uint64_t get_operation_time_ns() const;
};

// Error handling utilities
std::string get_security_error_message(SecurityError error);

// Global security monitor instance
extern std::unique_ptr<SecurityMonitor> global_security_monitor;

// Initialize global security monitor
void initialize_security_monitor(std::unique_ptr<SecurityMonitor> monitor = nullptr);

// Get current security monitor
SecurityMonitor* get_security_monitor();

} // namespace clwe

#endif // CLWE_SECURITY_UTILS_HPP