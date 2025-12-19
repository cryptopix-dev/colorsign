# ColorSign for ESP32-S3

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-4.4+-blue.svg)](https://docs.espressif.com/projects/esp-idf/en/latest/)
[![Post-Quantum](https://img.shields.io/badge/Post--Quantum-ML--DSA-blue.svg)](https://doi.org/10.6028/NIST.FIPS.204)

**Platform**: ESP32-S3
**Version**: 1.0.0
**Authors**: CRYPTOPIX (OPC) PVT LTD Development team
**Cryptographic Basis**: ML-DSA (NIST FIPS 204)

This is the ESP32-S3-specific implementation of ColorSign, a post-quantum digital signature scheme optimized for embedded IoT applications using the ESP-IDF framework. ColorSign provides mathematically equivalent security to ML-DSA while incorporating enhanced security monitoring and timing protection for embedded systems.

## 📋 Table of Contents

- [Overview](#overview)
- [Build Instructions](#-build-instructions)
- [API Usage](#-api-usage)
- [Security Features](#-security-features)
- [Testing Procedures](#-testing-procedures)
- [Platform-Specific Details](#-platform-specific-details)
- [Performance Benchmarks](#-performance-benchmarks)
- [COSE Integration](#-cose-integration)
- [Troubleshooting](#-troubleshooting)
- [Support](#-support)

## Overview

ColorSign implements the ML-DSA digital signature scheme with the following key features:

- **Post-Quantum Security**: Based on the Learning With Errors (LWE) problem
- **EUF-CMA Security**: Existentially unforgeable under chosen message attacks
- **Enhanced Security**: Built-in security monitoring and timing protection
- **ESP32-S3 Optimized**: Scalar operations for embedded deployment
- **Memory Efficient**: Designed for constrained IoT environments
- **COSE Compatible**: Supports CBOR Object Signing and Encryption

### Supported Security Levels

| Parameter Set | NIST Level | Public Key Size | Private Key Size | Signature Size |
|---------------|------------|-----------------|------------------|----------------|
| ML-DSA-44     | 2          | 1,312 bytes    | 2,560 bytes     | 2,420 bytes    |
| ML-DSA-65     | 3          | 1,952 bytes    | 4,000 bytes     | 3,328 bytes    |
| ML-DSA-87     | 5          | 2,592 bytes    | 4,864 bytes     | 4,620 bytes    |

## 🚀 Build Instructions

### Prerequisites

- **ESP-IDF**: Version 4.4 or higher
- **ESP32-S3 Development Board**: With at least 512KB RAM and 4MB flash
- **CMake**: Version 3.16 or higher (included with ESP-IDF)
- **Python**: Version 3.7 or higher

### Setup ESP-IDF

1. Follow the [ESP-IDF Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/get-started/index.html)
2. Install ESP-IDF and set up the environment variables
3. Verify installation:

```bash
idf.py --version
```

### Build Process

1. Navigate to the project directory:

```bash
cd esp32s3/sign
```

2. Set the target to ESP32-S3:

```bash
idf.py set-target esp32s3
```

3. Configure the project (optional, uses default sdkconfig):

```bash
idf.py menuconfig
```

4. Build the project:

```bash
idf.py build
```

### Flash and Monitor

```bash
# Flash to device
idf.py flash

# Monitor serial output
idf.py monitor

# Combined flash and monitor
idf.py flash monitor
```

### Clean Build

```bash
idf.py clean
idf.py build
```

## 💡 API Usage

### ESP-IDF Component Integration

Add this directory to your ESP-IDF project's `components/` folder or set `EXTRA_COMPONENT_DIRS` in your project CMakeLists.txt.

### Basic Digital Signature Example

```cpp
#include "clwe/keygen.hpp"
#include "clwe/sign.hpp"
#include "clwe/verify.hpp"
#include "esp_log.h"

static const char* TAG = "ColorSign_Example";

extern "C" void app_main() {
    ESP_LOGI(TAG, "Starting ColorSign example");

    // Initialize cryptographic parameters (ML-DSA-44)
    clwe::CLWEParameters params(44);

    // Generate keypair
    clwe::ColorSignKeyGen keygen(params);
    auto [public_key, private_key] = keygen.generate_keypair();
    ESP_LOGI(TAG, "Keypair generated successfully");

    // Create signer instance
    clwe::ColorSign signer(params);

    // Prepare message
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'};

    // Sign message
    clwe::ColorSignature signature = signer.sign_message(message, private_key, public_key);
    ESP_LOGI(TAG, "Message signed successfully");

    // Create verifier instance
    clwe::ColorSignVerify verifier(params);

    // Verify signature
    bool is_valid = verifier.verify_signature(public_key, signature, message);

    if (is_valid) {
        ESP_LOGI(TAG, "✅ Signature verification successful!");
    } else {
        ESP_LOGE(TAG, "❌ Signature verification failed!");
    }
}
```

### Advanced Usage with Context and Error Handling

```cpp
#include "clwe/sign.hpp"
#include "clwe/verify.hpp"
#include <esp_system.h>

extern "C" void sign_example_with_context() {
    try {
        clwe::CLWEParameters params(65);
        clwe::ColorSign signer(params);
        clwe::ColorSignVerify verifier(params);

        // Generate keys
        clwe::ColorSignKeyGen keygen(params);
        auto [pk, sk] = keygen.generate_keypair();

        // Message and context
        std::vector<uint8_t> message = {'I', 'o', 'T', ' ', 'D', 'a', 't', 'a'};
        std::vector<uint8_t> context = {'A', 'p', 'p', ' ', 'C', 'o', 'n', 't', 'e', 'x', 't'};

        // Sign with context
        auto signature = signer.sign_message(message, sk, pk, context);

        // Verify with context
        bool valid = verifier.verify_signature(pk, signature, message, context);

        if (valid) {
            ESP_LOGI("SIGN", "Context-aware signature verified");
        }

        // Test context mismatch (should fail)
        std::vector<uint8_t> wrong_context = {'W', 'r', 'o', 'n', 'g'};
        bool invalid = verifier.verify_signature(pk, signature, message, wrong_context);

        if (!invalid) {
            ESP_LOGI("SIGN", "Context validation working correctly");
        }

    } catch (const std::exception& e) {
        ESP_LOGE("SIGN", "Error: %s", e.what());
    }
}
```

### COSE Integration Example

```cpp
#include "clwe/cose.hpp"
#include "clwe/sign.hpp"

extern "C" void cose_signing_example() {
    clwe::CLWEParameters params(44);
    clwe::ColorSign signer(params);

    // Generate keys
    clwe::ColorSignKeyGen keygen(params);
    auto [pk, sk] = keygen.generate_keypair();

    // Message to sign
    std::vector<uint8_t> message = {'C', 'O', 'S', 'E', ' ', 'P', 'a', 'y', 'l', 'o', 'a', 'd'};

    // Create COSE_Sign1 signature
    clwe::COSE_Sign1 cose_sig = signer.sign_message_cose(message, sk, pk, clwe::COSE_ALG_ML_DSA_44);

    // Serialize COSE object
    std::vector<uint8_t> cose_bytes = cose_sig.serialize();

    // Verify COSE signature
    clwe::ColorSignVerify verifier(params);
    bool cose_valid = verifier.verify_cose_signature(cose_sig);

    ESP_LOGI("COSE", "COSE signature %s", cose_valid ? "valid" : "invalid");
}
```

### Memory Management

ColorSign is optimized for embedded systems:

- **Heap Allocation**: Large structures allocated on heap
- **Secure Cleanup**: Automatic zeroization of private keys
- **Memory Pools**: Compatible with ESP-IDF memory management
- **Stack Optimization**: Minimal stack usage

## 🔒 Security Features

### Cryptographic Security

- **EUF-CMA Security**: Strongest notion of digital signature security
- **Post-Quantum**: Secure against quantum computing attacks
- **NIST Standardized**: Implements ML-DSA as specified in FIPS 204

### Implementation Security

- **Constant-Time Operations**: All operations run in constant time
- **Side-Channel Protection**: Built-in timing attack countermeasures
- **Input Validation**: Comprehensive validation with security monitoring
- **Secure Random Generation**: Uses ESP32 hardware RNG

### ESP32-S3 Specific Security

- **Secure Boot**: Compatible with ESP32-S3 secure boot
- **Flash Encryption**: Works with encrypted flash
- **Memory Protection**: Utilizes MPU for secure memory regions
- **Hardware Security**: Leverages ESP32 security features

### Enhanced Security Features

- **Security Monitoring**: Runtime security checks and anomaly detection
- **Timing Protection**: Active protection against timing attacks
- **Key Management**: Secure key generation and storage guidelines
- **Audit Logging**: Optional security event logging

## 🧪 Testing Procedures

### Unit Tests

Run the comprehensive test suite:

```bash
# Build and run tests
idf.py test

# Run specific test component
idf.py test --test-name=color_sign_tests
```

### Known Answer Tests (KAT)

ColorSign includes NIST KAT vectors:

```bash
# Run KAT tests
cd tests
./test_known_answer_tests
```

### Security Testing

```cpp
// Example security validation
#include "clwe/security_utils.hpp"

void test_security_features() {
    clwe::CLWEParameters params(44);
    clwe::ColorSign signer(params);

    // Test input validation
    std::vector<uint8_t> invalid_message; // Empty message
    clwe::ColorSignPrivateKey dummy_sk;
    clwe::ColorSignPublicKey dummy_pk;

    auto error = signer.validate_signing_inputs(invalid_message, dummy_sk, dummy_pk);
    if (error != clwe::ColorSignSignError::SUCCESS) {
        ESP_LOGI("SECURITY", "Input validation working: %s", get_colorsign_sign_error_message(error));
    }

    // Test timing protection
    // (Implementation includes automatic timing checks)
}
```

### Host Testing

For development testing on macOS/Linux:

```bash
cd tests
mkdir build && cd build
cmake ..
make
./test_color_sign
```

### Test Coverage

- **Algorithm Correctness**: ML-DSA operations verified against KAT vectors
- **Security Validation**: Input validation and error handling
- **Performance**: Timing analysis and optimization
- **Memory Safety**: Leak detection and buffer overflow tests
- **COSE Compatibility**: CBOR encoding/decoding verification

## 🏗️ Platform-Specific Details

### ESP32-S3 Requirements

- **RAM**: Minimum 320KB free heap for ML-DSA-44, 480KB for ML-DSA-87
- **Flash**: 4MB minimum for code and key storage
- **CPU**: Xtensa LX7 dual-core processor
- **Power**: Compatible with ESP32-S3 power management

### Optimizations

- **Scalar Implementation**: No SIMD requirements
- **NTT Operations**: Optimized for ESP32-S3
- **Memory Layout**: Cache-friendly data structures
- **Sampling**: Efficient SHAKE-based random sampling

### ESP-IDF Integration

- **FreeRTOS**: Thread-safe cryptographic operations
- **WiFi/Bluetooth**: Secure communication protocol support
- **OTA Updates**: Secure firmware signing capabilities
- **TLS Integration**: Compatible with ESP-TLS stack

## 📊 Performance Benchmarks

Approximate performance on ESP32-S3 (160MHz):

| Operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|-----------|
| Key Generation | 850ms | 1,400ms | 2,100ms |
| Signing | 450ms | 750ms | 1,100ms |
| Verification | 280ms | 460ms | 680ms |
| Memory Usage | 180KB | 280KB | 400KB |

*Note: Performance varies with ESP-IDF version and optimization settings.*

## 🔐 COSE Integration

ColorSign supports COSE (CBOR Object Signing and Encryption) for IoT applications:

### COSE Algorithm Identifiers

- `COSE_ALG_ML_DSA_44` (-8)
- `COSE_ALG_ML_DSA_65` (-9)
- `COSE_ALG_ML_DSA_87` (-10)

### COSE Usage Example

```cpp
// Create COSE_Sign1 with ML-DSA
clwe::COSE_Sign1 cose_sig = signer.sign_message_cose(
    payload, private_key, public_key, clwe::COSE_ALG_ML_DSA_44
);

// Serialize for transmission
std::vector<uint8_t> cose_bytes = cose_sig.serialize();

// Deserialize and verify
clwe::COSE_Sign1 received_cose = clwe::COSE_Sign1::deserialize(cose_bytes);
bool valid = verifier.verify_cose_signature(received_cose);
```

## 🔧 Troubleshooting

### Common Issues

1. **Build Failures**
   - Verify ESP-IDF installation and environment setup
   - Check CMake version compatibility
   - Ensure correct ESP32-S3 target

2. **Memory Constraints**
   - Use smaller parameter sets (44 instead of 87)
   - Increase heap size in sdkconfig
   - Monitor memory usage with ESP-IDF tools

3. **Performance Issues**
   - Enable compiler optimizations
   - Consider ESP32-S3 overclocking options
   - Profile with ESP-IDF performance tools

4. **Security Validation Errors**
   - Check entropy source configuration
   - Verify timing protection settings
   - Ensure input validation is active

### Debug Configuration

Enable detailed logging:

```
CONFIG_LOG_DEFAULT_LEVEL_DEBUG=y
CONFIG_LOG_DEFAULT_LEVEL=4
CONFIG_COMPILER_OPTIMIZATION_LEVEL_DEBUG=y
```

## 📞 Support

### Documentation

- [ML-DSA Specification](https://doi.org/10.6028/NIST.FIPS.204)
- [COSE Specification](https://tools.ietf.org/html/rfc8152)
- [ESP-IDF Documentation](https://docs.espressif.com/projects/esp-idf/)
- [ColorSign Repository](https://github.com/cryptopix-dev/ColorSign)

### Issue Reporting

For ESP32-S3-specific issues:
- **GitHub Issues**: [Report bugs](https://github.com/cryptopix-dev/ColorSign/issues)
- **Email**: support@cryptopix.in
- **Forum**: ESP32 Community Forums

### Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Ensure security validation passes
5. Submit a pull request

---

**ColorSign ESP32-S3**: Enabling post-quantum digital signatures for the Internet of Things with lattice-based cryptography.