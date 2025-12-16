#include "src/include/clwe/keygen.hpp"
#include "src/include/clwe/parameters.hpp"
#include "src/include/clwe/sign.hpp"
#include "src/include/clwe/verify.hpp"
#include <iostream>
#include <vector>
#include <fstream>
#include <webp/decode.h>

std::vector<uint8_t> load_webp_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + filename);
    }

    // Decode WebP to RGB
    int width, height;
    uint8_t* rgb_data = WebPDecodeRGB(buffer.data(), buffer.size(), &width, &height);
    if (!rgb_data) {
        throw std::runtime_error("Failed to decode WebP: " + filename);
    }

    size_t num_pixels = static_cast<size_t>(width) * height;
    std::vector<uint8_t> full_data(rgb_data, rgb_data + num_pixels * 3);

    WebPFree(rgb_data);

    // Extract the original data size from the first 4 bytes
    if (full_data.size() < 4) {
        throw std::runtime_error("Invalid WebP data: too small");
    }
    uint32_t data_size = (static_cast<uint32_t>(full_data[0]) << 24) |
                         (static_cast<uint32_t>(full_data[1]) << 16) |
                         (static_cast<uint32_t>(full_data[2]) << 8) |
                         static_cast<uint32_t>(full_data[3]);

    if (full_data.size() < 4 + data_size) {
        throw std::runtime_error("Invalid WebP data: size mismatch");
    }

    std::vector<uint8_t> result(full_data.begin() + 4, full_data.begin() + 4 + data_size);
    return result;
}

std::vector<uint8_t> load_bin_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + filename);
    }
    return buffer;
}

int main() {
    try {
        clwe::CLWEParameters params(44);

        std::cout << "Loading public key from public_key.bin..." << std::endl;
        auto public_bin = load_bin_file("public_key.bin");
        auto public_key_bin = clwe::ColorSignPublicKey::deserialize(public_bin, params);
        std::cout << "Public key from bin loaded and deserialized successfully!" << std::endl;

        std::cout << "Loading private key from private_key.bin..." << std::endl;
        auto private_bin = load_bin_file("private_key.bin");
        auto private_key_bin = clwe::ColorSignPrivateKey::deserialize(private_bin, params);
        std::cout << "Private key from bin loaded and deserialized successfully!" << std::endl;

        std::cout << "Loading public key from public_key.webp..." << std::endl;
        auto public_rgb = load_webp_file("public_key.webp");
        std::cout << "WebP data size: " << public_rgb.size() << ", bin size: " << public_bin.size() << std::endl;
        if (public_rgb == public_bin) {
            std::cout << "WebP data matches bin data!" << std::endl;
        } else {
            std::cout << "WebP data does not match bin data!" << std::endl;
            return 1;
        }
        auto public_key = clwe::ColorSignPublicKey::deserialize(public_rgb, params);
        std::cout << "Public key loaded and deserialized successfully!" << std::endl;

        std::cout << "Loading private key from private_key.webp..." << std::endl;
        auto private_rgb = load_webp_file("private_key.webp");
        std::cout << "WebP data size: " << private_rgb.size() << ", bin size: " << private_bin.size() << std::endl;
        if (private_rgb == private_bin) {
            std::cout << "WebP data matches bin data!" << std::endl;
        } else {
            std::cout << "WebP data does not match bin data!" << std::endl;
            return 1;
        }
        auto private_key = clwe::ColorSignPrivateKey::deserialize(private_rgb, params);
        std::cout << "Private key loaded and deserialized successfully!" << std::endl;

        clwe::ColorSign signer(params);
        std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};

        std::cout << "Signing message..." << std::endl;
        auto signature = signer.sign_message(message, private_key, public_key);

        std::cout << "Signing successful!" << std::endl;

        clwe::ColorSignVerify verifier(params);
        std::cout << "Verifying signature..." << std::endl;
        bool is_valid = verifier.verify_signature(public_key, signature, message);

        if (is_valid) {
            std::cout << "Signature verification successful!" << std::endl;
            std::cout << "Key images can be used for signing operations!" << std::endl;
        } else {
            std::cout << "Signature verification failed!" << std::endl;
            return 1;
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}