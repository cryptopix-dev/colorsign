# ColorSign: Post-Quantum Digital Signature Library (Windows)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![CMake](https://img.shields.io/badge/CMake-3.16+-blue.svg)](https://cmake.org/)
[![FIPS 204](https://img.shields.io/badge/FIPS-204-green.svg)](https://csrc.nist.gov/pubs/fips/204/final)

ColorSign is a high-performance, production-ready implementation of the Module-Lattice-based Digital Signature Algorithm (ML-DSA) as specified in NIST FIPS 204. This library provides quantum-resistant digital signatures with innovative color-based polynomial encoding for enhanced security and efficiency.

## 🚀 Key Features

- **FIPS 204 Compliant**: Full implementation of ML-DSA (formerly CRYSTALS-Dilithium)
- **Multiple Security Levels**: Support for ML-DSA-44, ML-DSA-65, and ML-DSA-87
- **Color Integration**: Novel polynomial encoding using color representations for improved security
- **High Performance**: SIMD optimizations (AVX2, AVX512, NEON) for accelerated computations
- **Enterprise Ready**: Comprehensive key management, audit logging, and security features
- **COSE Support**: Native CBOR Object Signing and Encryption (COSE) integration
- **Windows Native**: Optimized for Windows with MinGW/GCC support
- **Comprehensive Testing**: Full test suite with Known Answer Tests (KAT) vectors

## 🎨 Pixel-Based Key Functionality

ColorSign introduces an innovative **pixel-based key encoding system** that transforms cryptographic polynomials into visual RGB pixel representations. This feature provides enhanced security through novel encoding techniques while enabling unique visualization and storage capabilities.

### How It Works

The pixel-based system encodes polynomial coefficients into RGB color data where each pixel represents up to three coefficients:

- **Encoding Process**: Polynomial coefficients are reduced modulo the cryptographic modulus and packed into RGB channels (R, G, B)
- **Pixel Structure**: Each 8-bit color channel stores one coefficient value (0-255)
- **Visualization**: Keys can be rendered as images for debugging, education, or steganographic purposes

### Key Benefits

- **Enhanced Security**: Novel encoding provides additional obfuscation layer
- **Visual Debugging**: Keys can be visualized as images for cryptographic analysis
- **Compact Storage**: Efficient representation of large polynomial vectors
- **Steganography**: Potential for hiding cryptographic data in images
- **Cross-Platform Compatibility**: Works across all supported platforms (macOS, Windows, Linux)

### Technical Details

#### Basic Encoding
```cpp
// Encode a polynomial into RGB color data
std::vector<uint8_t> color_data = encode_polynomial_as_colors(polynomial, modulus);

// Each coefficient becomes a pixel channel value
// coefficient % modulus -> 8-bit color value (0-255)
```

#### Vector Encoding
```cpp
// Encode multiple polynomials (key components)
std::vector<uint8_t> color_key = encode_polynomial_vector_as_colors(poly_vector, modulus);

// Supports automatic compression for sparse polynomials
std::vector<uint8_t> compressed = encode_polynomial_vector_as_colors_auto(poly_vector, modulus);
```

#### Decoding Back to Polynomials
```cpp
// Decode RGB data back to polynomial coefficients
std::vector<uint32_t> polynomial = decode_colors_to_polynomial(color_data, modulus);

// Decode multiple polynomials from color data
std::vector<std::vector<uint32_t>> poly_vector =
    decode_colors_to_polynomial_vector(color_data, k, n, modulus);
```

### Advanced Features

#### Compression Integration
- **Variable-Length Encoding**: Efficient storage for sparse polynomials
- **Huffman Coding**: Adaptive compression for optimal space usage
- **Dual-Format Support**: Simultaneous cryptographic and visual representations

#### On-Demand Color Generation
```cpp
// Enable on-demand color generation for compressed keys
std::vector<uint8_t> dual_format = encode_polynomial_vector_with_color_integration(
    poly_vector, modulus, true /* enable_on_demand_color */
);

// Generate color representation from compressed data
std::vector<uint8_t> color_image = generate_color_from_dual_format(dual_format);
```

### Usage in Key Generation

The pixel-based encoding is integrated into ColorSign's key generation process:

```cpp
// Keys are stored using color encoding internally
auto [public_key, private_key] = keygen.generate_keypair();

// Public and private key data contains color-encoded polynomials
std::vector<uint8_t> public_color_data = public_key.public_data;
std::vector<uint8_t> private_color_data = private_key.secret_data;
```

### Visualization Example

Keys can be visualized as images where:
- **Dark pixels**: Represent low coefficient values (near zero)
- **Bright pixels**: Represent high coefficient values
- **Color patterns**: Reflect the mathematical structure of the polynomials
- **Image dimensions**: Depend on polynomial degree and vector size

### Security Considerations

- **Information Preservation**: Encoding/decoding is lossless for cryptographic operations
- **No Security Degradation**: Color representation doesn't weaken the underlying cryptography
- **Additional Obfuscation**: Visual encoding provides secondary protection layer
- **Format Detection**: Multiple encoding formats supported with automatic detection

### Performance Characteristics

- **Encoding Speed**: Fast conversion with minimal computational overhead
- **Storage Efficiency**: Variable compression ratios based on polynomial sparsity
- **Memory Usage**: Compact representation suitable for resource-constrained environments
- **Platform Optimization**: SIMD-accelerated operations on supported architectures

This pixel-based functionality makes ColorSign unique among post-quantum signature schemes, combining mathematical rigor with innovative visual cryptography techniques.

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Documentation](#api-documentation)
- [Usage Examples](#usage-examples)
- [Testing](#testing)
- [Windows-Specific Features](#windows-specific-features)
- [Build Requirements](#build-requirements)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## 🔧 Installation

### Prerequisites

- **C++ Compiler**: MinGW/GCC 9+, Clang 10+, or MSVC 2019+
- **CMake**: Version 3.16 or higher
- **OpenSSL**: Version 1.1.1 or higher
- **Git**: For cloning dependencies

### MinGW Installation

ColorSign for Windows requires MinGW/GCC toolchain. Here are the installation options:

#### Option 1: MSYS2 (Recommended)

```powershell
# Install MSYS2 from https://www.msys2.org/
# Open MSYS2 MinGW 64-bit terminal and run:

pacman -Syu
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
```

#### Option 2: Chocolatey

```powershell
# Install Chocolatey first: https://chocolatey.org/install
choco install cmake mingw
```

#### Option 3: Manual Installation

1. Download MinGW from https://sourceforge.net/projects/mingw-w64/
2. Install with the following components:
   - mingw32-base
   - mingw32-gcc-g++
   - mingw32-cmake
   - mingw32-openssl
3. Add MinGW to your PATH environment variable

### Required Dependencies

ColorSign requires the following dependencies:

- **CMake 3.16+**: Build system configuration
- **MinGW/GCC 9+**: C++17 compiler toolchain
- **OpenSSL 1.1.1+**: Cryptographic primitives
- **GoogleTest**: Automatically downloaded via FetchContent

### Environment Setup

After installing MinGW, ensure the following environment variables are set:

```powershell
# Set MinGW paths (adjust paths as needed for your installation)
set PATH=C:\ProgramData\mingw64\mingw64\bin;%PATH%
set OPENSSL_ROOT_DIR=C:\ProgramData\mingw64\mingw64\opt
```

## 📦 Build Script Documentation

ColorSign for Windows uses batch scripts for build automation and testing. These scripts provide a streamlined, Windows-native build experience.

### `build_windows.bat` - Windows Build Script

The `build_windows.bat` script provides a comprehensive, automated build process for ColorSign on Windows systems using batch commands.

#### Location
```
windows/sign/build_windows.bat
```

#### Features
- **Batch Automation**: Uses Windows batch commands for native scripting
- **Automated Tool Detection**: Checks for required tools (CMake, GCC, OpenSSL)
- **Environment Configuration**: Sets up MinGW toolchain automatically
- **Error Handling**: Stops on errors for reliable build process
- **Directory Management**: Automatically creates build directory
- **Verification Testing**: Runs quick verification test after build

#### Usage Instructions

```powershell
# Navigate to the Windows sign directory
cd windows/sign

# Run the build script
.\build_windows.bat
```

#### What the Script Does

1. **Tool Verification**: Checks for required tools (cmake, gcc, openssl)
2. **Environment Setup**: Configures MinGW compiler paths and OpenSSL
3. **Build Directory Setup**: Creates a `build/` directory if it doesn't exist
4. **CMake Configuration**: Configures the project with MinGW toolchain
5. **Project Building**: Uses CMake to build the configured project
6. **Build Verification**: Runs the main test executable to validate the build
7. **Status Reporting**: Provides clear output about build completion

#### Expected Output

```
========================================
ColorSign Windows Build Script
========================================

Checking for required build tools...
[OK] cmake found
[OK] gcc found
[OK] openssl found
All required tools are available.

Configuring project with CMake...
Building project...
Build completed successfully!
Executables are available in the build/ directory:
  - colorsign_test: Main ColorSign test executable
  - ntt_simd_benchmark: NTT SIMD benchmark tool

Running quick verification test...
Verification test passed!
```

#### Troubleshooting

- **Missing Tools**: If you get "Required tool not found" errors, ensure MinGW, CMake, and OpenSSL are installed and in your PATH
- **CMake Configuration Issues**: Verify the MinGW toolchain file paths in `mingw-toolchain.cmake`
- **Build Failures**: Check that all dependencies are properly installed and accessible

### `run_tests.bat` - Comprehensive Test Runner

The `run_tests.bat` script provides automated test execution with detailed reporting for ColorSign on Windows.

#### Location
```
windows/sign/run_tests.bat
```

#### Features
- **Comprehensive Testing**: Runs all test suites automatically
- **Detailed Reporting**: Provides clear pass/fail summary with statistics
- **Error Handling**: Graceful error handling with detailed output
- **Test Aggregation**: Runs multiple test executables sequentially

#### Usage Instructions

```powershell
# Navigate to the Windows sign directory
cd windows/sign

# Run tests (requires build directory to exist)
.\run_tests.bat
```

#### What the Script Does

1. **Build Verification**: Ensures build directory exists
2. **Test Execution**: Runs all individual test suites
3. **Result Aggregation**: Provides comprehensive summary
4. **Status Reporting**: Clear pass/fail indication with exit codes

#### Expected Output

```
========================================
ColorSign Comprehensive Test Suite
========================================

Running test suites...
----------------------
Running Parameters Tests...
PASSED
Running Key Generation Tests...
PASSED
Running Sign Tests...
PASSED
Running Verify Tests...
PASSED
Running Color Integration Tests...
PASSED
Running Utils Tests...
PASSED
Running Security Utils Tests...
PASSED
Running Integration Tests...
PASSED
Running KAT Tests...
PASSED
Running Stress Tests...
PASSED

========================================
Test Summary
========================================
Total Tests: 10
Passed: 10
Failed: 0
All tests passed!
```

## 🚀 Quick Start

```cpp
#include "clwe/keygen.hpp"
#include "clwe/sign.hpp"
#include "clwe/verify.hpp"

int main() {
    // Initialize parameters (ML-DSA-44)
    clwe::CLWEParameters params(44);

    // Generate keypair
    clwe::ColorSignKeyGen keygen(params);
    auto [public_key, private_key] = keygen.generate_keypair();

    // Sign a message
    clwe::ColorSign signer(params);
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    auto signature = signer.sign_message(message, private_key, public_key);

    // Verify signature
    clwe::ColorSignVerify verifier(params);
    bool is_valid = verifier.verify_signature(public_key, signature, message);

    return is_valid ? 0 : 1;
}
```

## 📚 API Documentation

### Core Classes

#### `CLWEParameters`
Cryptographic parameter configuration for ML-DSA variants.

```cpp
// Constructor with security level (44, 65, or 87)
clwe::CLWEParameters params(44);

// Custom parameters
clwe::CLWEParameters params(44, 256, 4, 4, 8380417, 2, 39, 78, 524288, 88, 80, 128);
```

#### `ColorSignKeyGen`
Key pair generation functionality.

```cpp
clwe::ColorSignKeyGen keygen(params);
auto [public_key, private_key] = keygen.generate_keypair();

// Deterministic generation (for testing)
auto [pub_key, priv_key] = keygen.generate_keypair_deterministic(seed);
```

#### `ColorSign`
Digital signature creation with enhanced security features.

```cpp
clwe::ColorSign signer(params);

// Basic signing
auto signature = signer.sign_message(message, private_key, public_key);

// COSE signing
auto cose_signature = signer.sign_message_cose(message, private_key, public_key, COSE_ALG_ML_DSA_44);
```

#### `ColorSignVerify`
Signature verification with comprehensive security checks.

```cpp
clwe::ColorSignVerify verifier(params);

// Basic verification
bool is_valid = verifier.verify_signature(public_key, signature, message);

// COSE verification
bool cose_valid = verifier.verify_signature_cose(public_key, cose_signature);
```

### Key Structures

#### `ColorSignPublicKey`
```cpp
struct ColorSignPublicKey {
    std::array<uint8_t, 32> seed_rho;    // Matrix generation seed
    std::array<uint8_t, 32> seed_K;     // Secret key generation seed
    std::array<uint8_t, 64> hash_tr;    // Public key hash
    std::vector<uint8_t> public_data;   // Color-encoded public polynomial
    CLWEParameters params;              // Cryptographic parameters
};
```

#### `ColorSignPrivateKey`
```cpp
struct ColorSignPrivateKey {
    std::array<uint8_t, 32> seed_rho;    // Matrix generation seed
    std::array<uint8_t, 32> seed_K;     // Secret key generation seed
    std::array<uint8_t, 64> hash_tr;    // Public key hash
    std::vector<uint8_t> secret_data;   // Color-encoded secret polynomials
    CLWEParameters params;              // Cryptographic parameters
};
```

## 💡 Usage Examples

### Basic Key Generation and Signing

```cpp
#include "clwe/colorsign.hpp"

int main() {
    // Initialize with ML-DSA-65 for higher security
    clwe::CLWEParameters params(65);

    // Generate keys
    clwe::ColorSignKeyGen keygen(params);
    auto [pub_key, priv_key] = keygen.generate_keypair();

    // Prepare message
    std::string msg = "Quantum-resistant message";
    std::vector<uint8_t> message(msg.begin(), msg.end());

    // Sign message
    clwe::ColorSign signer(params);
    clwe::ColorSignature signature = signer.sign_message(message, priv_key, pub_key);

    // Serialize signature for storage/transmission
    std::vector<uint8_t> sig_bytes = signature.serialize();

    // Verify signature
    clwe::ColorSignVerify verifier(params);
    bool valid = verifier.verify_signature(pub_key, signature, message);

    std::cout << "Signature valid: " << (valid ? "Yes" : "No") << std::endl;
    return 0;
}
```

### COSE Integration

```cpp
#include "clwe/cose.hpp"

// Create COSE Sign1 signature
clwe::COSE_Sign1 cose_sig = signer.sign_message_cose(
    message, private_key, public_key, clwe::COSE_ALG_ML_DSA_44
);

// Serialize to CBOR
std::vector<uint8_t> cose_bytes = cose_sig.serialize();

// Verify COSE signature
bool cose_valid = verifier.verify_signature_cose(public_key, cose_sig);
```

### Enterprise Key Management

```cpp
#include "clwe/enterprise_key_manager.hpp"

// Initialize enterprise key manager
clwe::EnterpriseKeyManager key_manager(config);

// Generate enterprise keypair with lifecycle management
auto key_id = key_manager.generate_enterprise_keypair(
    "production-key-001",
    clwe::KeyType::SIGNING,
    clwe::SecurityLevel::HIGH
);

// Sign with enterprise key
auto signature = key_manager.sign_with_enterprise_key(key_id, message);
```

## 🧪 Testing

### Comprehensive Test Suite

ColorSign for Windows includes a comprehensive test suite with **121 individual tests** across 11 categories, ensuring robust validation of all cryptographic functionality.

### Running All Tests

```powershell
# Navigate to Windows sign directory
cd windows/sign

# Run comprehensive test suite (auto-builds if needed)
.\run_all_tests.bat
```

The test runner automatically:
- Executes all 121 tests across 11 categories
- Provides detailed output with pass/fail statistics
- Returns appropriate exit codes for CI/CD integration
- Validates build integrity before testing

### Test Categories

| Category | Test Count | Description |
|----------|------------|-------------|
| **Parameters** | 6 | Parameter validation and construction |
| **Key Generation** | 15 | Key generation and serialization |
| **Sign** | 13 | Signature creation and validation |
| **Verify** | 16 | Signature verification scenarios |
| **Color Integration** | 13 | Color encoding/decoding |
| **Utils** | 10 | Utility functions and helpers |
| **Security Utils** | 16 | Security-related utilities |
| **Integration** | 11 | End-to-end workflow testing |
| **KAT** | 3 | Known Answer Tests for FIPS compliance |
| **Stress** | 11 | Stress and edge case testing |
| **Main Verification** | 1 | Overall system verification |

**Total: 121 tests providing comprehensive coverage**

### Running Individual Tests

```powershell
# After building, run specific test executables
.\build\tests\test_parameters
.\build\tests\test_keygen
.\build\tests\test_sign
.\build\tests\test_verify
.\build\tests\test_color_integration
.\build\tests\test_utils
.\build\tests\test_security_utils
.\build\tests\test_integration
.\build\tests\test_kat
.\build\tests\test_stress
```

### Known Answer Tests (KAT)

```powershell
# Generate KAT vectors for compliance testing
.\build\generate_kat_vectors

# Generate all KAT vectors for all security levels
.\build\generate_all_kat_vectors

# Run comprehensive KAT validation
.\build\tests\test_kat
```

### Benchmarking

```powershell
# Run performance benchmarks
.\build\benchmark_color_sign_timing

# SIMD performance test (AVX2/AVX512)
.\build\ntt_simd_benchmark
```

### Test Output Example

```
========================================
ColorSign Comprehensive Test Suite
========================================

Running test suites...
----------------------
Running Parameters Tests... ✓ PASSED
Running Key Generation Tests... ✓ PASSED
Running Sign Tests... ✓ PASSED
Running Verify Tests... ✓ PASSED
Running Color Integration Tests... ✓ PASSED
Running Utils Tests... ✓ PASSED
Running Security Utils Tests... ✓ PASSED
Running Integration Tests... ✓ PASSED
Running KAT Tests... ✓ PASSED
Running Stress Tests... ✓ PASSED
Running Main Verification Test... ✓ PASSED

========================================
Test Summary
========================================
Total Tests: 11
Passed: 11
Failed: 0
All tests passed! ✓
```

### Cross-Platform Testing

The Windows test suite serves as the reference implementation for the cross-platform testing framework, providing:
- **Comprehensive test coverage** that macOS and Linux implementations match
- **Identical test results** for the same cryptographic operations
- **Platform-specific optimizations** while maintaining functional equivalence
- **Automated CI/CD integration** with clear pass/fail indicators

For more details on cross-platform testing, see [CROSS_PLATFORM_TESTING.md](../CROSS_PLATFORM_TESTING.md).

## 🪟 Windows-Specific Features

### Supported Platforms
- **Windows**: Windows 10+, Windows Server 2019+
- **Architectures**: x86, x86_64, ARM64

### Platform Features
- **MinGW/GCC Integration**: Full MinGW/GCC toolchain support
- **Windows Security**: Windows Certificate Store integration
- **COM Support**: COM interface for enterprise integration
- **Windows Services**: Support for running as Windows Service

### Build System
- **CMake**: Windows build configuration with MinGW Makefiles generator
- **SIMD Support**: Automatic detection of AVX2, AVX512 instructions
- **Package Management**: MSI installer generation

### Windows Performance Optimization

```powershell
# Build with maximum optimization
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-O3 -march=native -mtune=native" ..

# Enable AVX512 support (if available)
cmake -DCMAKE_CXX_FLAGS="-mavx512f -mavx512vl -mavx512bw -mavx512dq" ..

# Build for ARM64 (MinGW)
cmake -DCMAKE_SYSTEM_PROCESSOR=ARM64 ..
```

## 🏗️ Build Requirements

### Minimum Requirements
- **OS**: Windows 10+, Windows Server 2019+
- **Compiler**: MinGW/GCC 9+ (via MSYS2 recommended)
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 500MB for source and build artifacts

### Dependencies
- **OpenSSL**: 1.1.1+ (for cryptographic primitives)
- **CMake**: 3.16+ (build system)
- **GoogleTest**: Automatically downloaded via FetchContent

### SIMD Support
- **x86-64**: AVX2, AVX512F/VL/BW/DQ (automatic detection)
- **ARM64**: NEON (automatic detection)

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### Build Tool Not Found
**Error**: "Required tool 'cmake' is not installed or not in PATH"

**Solution**:
1. Install CMake from https://cmake.org/download/
2. Add CMake to your PATH environment variable
3. Restart your command prompt

#### MinGW/GCC Not Found
**Error**: "Required tool 'gcc' is not installed or not in PATH"

**Solution**:
1. Install MSYS2 from https://www.msys2.org/
2. Run: `pacman -S mingw-w64-x86_64-gcc`
3. Add MinGW to PATH: `set PATH=C:\ProgramData\mingw64\mingw64\bin;%PATH%`

#### OpenSSL Not Found
**Error**: "Could NOT find OpenSSL"

**Solution**:
1. Install OpenSSL via MSYS2: `pacman -S mingw-w64-x86_64-openssl`
2. Set environment variable: `set OPENSSL_ROOT_DIR=C:\ProgramData\mingw64\mingw64\opt`

#### CMake Configuration Errors
**Error**: "CMake configuration failed"

**Solution**:
1. Verify all paths in `mingw-toolchain.cmake` are correct
2. Ensure MinGW binaries are in your PATH
3. Try cleaning build directory and re-running: `rmdir /s /q build && .\build_windows.bat`

#### Build Failures
**Error**: "Build failed"

**Solution**:
1. Check build output for specific errors
2. Ensure all dependencies are installed
3. Try building with verbose output: `cmake --build . --verbose`

#### Test Execution Issues
**Error**: "Build directory not found"

**Solution**:
1. Run build script first: `.\build_windows.bat`
2. Verify build directory exists
3. Check that all executables were built successfully

### Debugging Tips

- **Enable Verbose Output**: Add `--verbose` flag to cmake build commands
- **Check Environment**: Run `set` to verify all environment variables are set correctly
- **Clean Build**: Remove build directory and start fresh: `rmdir /s /q build`
- **Check Logs**: Review CMake configuration output for warnings or errors

### Getting Help

If you encounter issues not covered here:
1. Check the [GitHub Issues](https://github.com/cryptopix-dev/colorsign/issues)
2. Review the [Discussions](https://github.com/cryptopix-dev/colorsign/discussions)
3. Contact support: support@cryptopix.in

## 🤝 Contributing

We welcome contributions to ColorSign! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```powershell
# Fork and clone
git clone https://github.com/your-org/colorsign.git
cd colorsign

# Create feature branch
git checkout -b feature/your-feature

# Build with tests
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
cmake --build . --config Debug

# Run tests
ctest --output-on-failure
```

### Code Style

- Follow C++17 best practices
- Use RAII principles
- Comprehensive error handling
- Clear documentation comments
- Security-first approach

## 📄 License

ColorSign is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

```
Copyright 2024 ColorSign Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## 📞 Contact

- **Project Homepage**: https://github.com/cryptopix-dev/colorsign
- **Issues**: https://github.com/cryptopix-dev/colorsign/issues
- **Discussions**: https://github.com/cryptopix-dev/colorsign/discussions
- **Email**: support@cryptopix.in

### Security

For security-related issues, please email support@cryptopix.in instead of creating public issues.

## 🙏 Acknowledgments

- NIST for the FIPS 204 standard
- The CRYSTALS team for the Dilithium algorithm
- OpenSSL project for cryptographic primitives
- GoogleTest framework for testing infrastructure

---

**ColorSign**: Securing the quantum future, one signature at a time.