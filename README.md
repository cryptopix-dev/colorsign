# ColorSign: Post-Quantum Digital Signature Library

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![CMake](https://img.shields.io/badge/CMake-3.16+-blue.svg)](https://cmake.org/)
[![FIPS 204](https://img.shields.io/badge/FIPS-204-green.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![Version](https://img.shields.io/badge/Version-1.0.0-green.svg)](https://github.com/cryptopix-dev/ColorSign)

**Project Name**: ColorSign
**Version**: 1.0.0
**Authors**: CRYPTOPIX (OPC) PVT LTD Development team
**Email**: support@cryptopix.in
**Copyright**: ©2025 CRYPTOPIX (OPC) PVT LTD
**GitHub Repository**: https://github.com/cryptopix-dev/ColorSign

ColorSign is a high-performance, production-ready implementation of the Module-Lattice-based Digital Signature Algorithm (ML-DSA) as specified in NIST FIPS 204. This library provides quantum-resistant digital signatures with innovative color-based polynomial encoding for enhanced security and efficiency.

## 🚀 Key Features

- **FIPS 204 Compliant**: Full implementation of ML-DSA (formerly CRYSTALS-Dilithium)
- **Multiple Security Levels**: Support for ML-DSA-44, ML-DSA-65, and ML-DSA-87
- **Color Integration**: Novel polynomial encoding using color representations for improved security
- **High Performance**: SIMD optimizations (AVX2, AVX512, NEON) for accelerated computations
- **Enterprise Ready**: Comprehensive key management, audit logging, and security features
- **COSE Support**: Native CBOR Object Signing and Encryption (COSE) integration
- **Cross-Platform**: Linux, macOS, and Windows support
- **Comprehensive Testing**: Full test suite with Known Answer Tests (KAT) vectors

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Usage Examples](#usage-examples)
- [Testing](#testing)
- [Build Requirements](#build-requirements)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## 🔧 Installation

### Prerequisites

- **C++ Compiler**: GCC 9+, Clang 10+, or MSVC 2019+
- **CMake**: Version 3.16 or higher
- **OpenSSL**: Version 1.1.1 or higher
- **Git**: For cloning dependencies

### Platform-Specific Installation

#### Linux
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install cmake g++ libssl-dev build-essential

# For Fedora/RHEL/CentOS
sudo dnf install cmake gcc-c++ openssl-devel

# Clone and build
git clone https://github.com/cryptopix-dev/ColorSign.git
cd ColorSign
./linux/sign/build_linux.sh
```

#### macOS
```bash
# Install dependencies
brew install cmake openssl

# Clone and build
git clone https://github.com/cryptopix-dev/ColorSign.git
cd ColorSign
./macos/sign/build_macos.sh
```

#### Windows
```bash
# Install dependencies (using vcpkg)
git clone https://github.com/cryptopix-dev/ColorSign.git
cd ColorSign
./windows/sign/build_windows.bat
```

## 📁 Project Structure

```
ColorSign/
├── linux/                  # Linux-specific implementation
│   ├── sign/               # Core signing functionality
│   │   ├── build/          # Build artifacts (excluded from Git)
│   │   ├── src/            # Source code
│   │   ├── include/        # Header files
│   │   ├── tests/          # Test suite
│   │   ├── build_linux.sh  # Linux build script
│   │   └── README.md       # Linux-specific documentation
├── macos/                  # macOS-specific implementation
│   └── sign/               # macOS signing functionality
├── windows/                # Windows-specific implementation
│   └── sign/               # Windows signing functionality
├── *.md                    # Security analysis reports
└── README.md               # This file
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

## 🧪 Testing

### Running Tests

```bash
# Linux
cd linux/sign
./run_all_tests.sh

# macOS
cd macos/sign
./run_all_tests.sh

# Windows
cd windows/sign
run_all_tests.bat
```

### Test Coverage

- **121+ individual tests** across 11 categories
- **Known Answer Tests (KAT)** for FIPS compliance
- **Performance benchmarks** for all security levels
- **Cross-platform validation** ensuring consistency

## 🏗️ Build Requirements

### Minimum Requirements

- **OS**: Ubuntu 18.04+, macOS 10.15+, Windows 10+
- **Compiler**: C++17 compliant compiler (GCC 7.0+, Clang 10+, MSVC 2019+)
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 500MB for source and build artifacts

### Dependencies

- **OpenSSL**: 1.1.1+ (for cryptographic primitives)
- **CMake**: 3.16+ (build system)
- **GoogleTest**: Automatically downloaded via FetchContent

### SIMD Support

- **x86-64**: AVX2, AVX512F/VL/BW/DQ (automatic detection)
- **ARM64**: NEON (automatic detection)
- **ARMv7**: NEON (automatic detection)

## 🤝 Contributing

We welcome contributions to ColorSign! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Fork and clone
git clone https://github.com/cryptopix-dev/ColorSign.git
cd ColorSign

# Create feature branch
git checkout -b feature/your-feature

# Build with tests
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)

# Run tests
ctest --output-on-failure
```

## 📄 License

ColorSign is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

```
Copyright 2025 CRYPTOPIX (OPC) PVT LTD

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

- **Project Homepage**: https://github.com/cryptopix-dev/ColorSign
- **Issues**: https://github.com/cryptopix-dev/ColorSign/issues
- **Discussions**: https://github.com/cryptopix-dev/ColorSign/discussions
- **Email**: support@cryptopix.in

### Security

For security-related issues, please email support@cryptopix.in instead of creating public issues.

## 🔐 Cryptographic Implementation Notes

- **FIPS 204 Compliance**: Full implementation of ML-DSA (Module-Lattice-based Digital Signature Algorithm)
- **Quantum Resistance**: Designed to resist attacks from both classical and quantum computers
- **Color-Based Encoding**: Innovative polynomial representation using color spaces for enhanced security
- **Deterministic Signatures**: Optional deterministic signature generation for reproducible results
- **Side-Channel Resistance**: Constant-time implementations to prevent timing attacks

## 🙏 Acknowledgments

- NIST for the FIPS 204 standard
- OpenSSL project for cryptographic primitives
- GoogleTest framework for testing infrastructure

---

**ColorSign**: Securing the quantum future, one signature at a time.
