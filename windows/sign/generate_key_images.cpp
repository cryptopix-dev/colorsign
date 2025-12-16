#include "src/include/clwe/keygen.hpp"
#include "src/include/clwe/parameters.hpp"
#include "src/include/clwe/color_integration.hpp"
#include "src/include/clwe/utils.hpp"
#include <iostream>
#include <vector>
#include <iomanip>
#include <cmath>
#include <webp/encode.h>
#include <fstream>

bool save_webp_file(const std::vector<uint8_t>& data, const std::string& filename) {
    if (data.empty()) return false;

    // Prepend the data size as 4 bytes (big-endian)
    std::vector<uint8_t> rgb_data;
    uint32_t size = data.size();
    rgb_data.push_back((size >> 24) & 0xFF);
    rgb_data.push_back((size >> 16) & 0xFF);
    rgb_data.push_back((size >> 8) & 0xFF);
    rgb_data.push_back(size & 0xFF);
    rgb_data.insert(rgb_data.end(), data.begin(), data.end());

    size_t total_size = rgb_data.size();
    size_t num_pixels = (total_size + 2) / 3; // Ensure at least enough for the data
    size_t width = static_cast<size_t>(std::ceil(std::sqrt(static_cast<double>(num_pixels))));
    size_t height = (num_pixels + width - 1) / width;

    // Create image buffer, pad with black pixels if necessary
    std::vector<uint8_t> image(width * height * 3, 0);
    for (size_t i = 0; i < total_size; ++i) {
        image[i] = rgb_data[i];
    }

    uint8_t* webp_data = nullptr;
    size_t webp_size = WebPEncodeLosslessRGB(image.data(), width, height, static_cast<int>(width * 3), &webp_data);
    if (webp_size == 0) {
        return false;
    }

    // Write to file
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        WebPFree(webp_data);
        return false;
    }
    file.write(reinterpret_cast<char*>(webp_data), webp_size);
    file.close();

    WebPFree(webp_data);
    return true;
}

int main() {
    try {
        clwe::CLWEParameters params(44);
        clwe::ColorSignKeyGen keygen(params);

        std::cout << "Generating ColorSign keypair..." << std::endl;
        auto [public_key, private_key] = keygen.generate_keypair();

        std::cout << "Key generation successful!" << std::endl;

        // Serialize full keys
        auto public_serialized = public_key.serialize();
        auto private_serialized = private_key.serialize();

        // Save as bin for comparison
        {
            std::ofstream file("public_key.bin", std::ios::binary);
            file.write(reinterpret_cast<const char*>(public_serialized.data()), public_serialized.size());
        }
        {
            std::ofstream file("private_key.bin", std::ios::binary);
            file.write(reinterpret_cast<const char*>(private_serialized.data()), private_serialized.size());
        }

        std::cout << "Saving public key as public_key.webp..." << std::endl;
        if (save_webp_file(public_serialized, "public_key.webp")) {
            std::cout << "Public key saved successfully!" << std::endl;
        } else {
            std::cout << "Failed to save public key!" << std::endl;
            return 1;
        }

        std::cout << "Saving private key as private_key.webp..." << std::endl;
        if (save_webp_file(private_serialized, "private_key.webp")) {
            std::cout << "Private key saved successfully!" << std::endl;
        } else {
            std::cout << "Failed to save private key!" << std::endl;
            return 1;
        }

        std::cout << "All keys saved as WebP images!" << std::endl;
        std::cout << "Public key image: public_key.webp" << std::endl;
        std::cout << "Private key image: private_key.webp" << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}