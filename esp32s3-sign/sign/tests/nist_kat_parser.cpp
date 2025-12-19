#include "nist_kat_parser.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <curl/curl.h>

// Helper function to convert hex string to bytes
static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper function to trim whitespace
static std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, last - first + 1);
}

// Helper function to convert string to array
template<size_t N>
static std::array<uint8_t, N> string_to_array(const std::string& hex) {
    auto bytes = hex_to_bytes(hex);
    if (bytes.size() != N) {
        throw std::runtime_error("Invalid array size");
    }
    std::array<uint8_t, N> arr;
    std::copy(bytes.begin(), bytes.end(), arr.begin());
    return arr;
}

// CURL write callback
static size_t write_callback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

namespace clwe {

// Download ML-DSA KAT file
std::string NIST_KAT_Downloader::download_mldsa_kat(uint32_t security_level) {
    std::string url;
    if (security_level == 44) {
        url = "https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/example-files/PQCsignKAT_1706.rsp";
    } else if (security_level == 65) {
        url = "https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/example-files/PQCsignKAT_2527.rsp";
    } else if (security_level == 87) {
        url = "https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/example-files/PQCsignKAT_3309.rsp";
    } else {
        throw std::runtime_error("Invalid security level for ML-DSA KAT");
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error("Failed to download KAT file: " + std::string(curl_easy_strerror(res)));
    }

    return response;
}

// Parse ML-DSA KAT file
std::vector<MLDSA_KAT_TestVector> NIST_KAT_Downloader::parse_mldsa_kat(const std::string& content) {
    std::vector<MLDSA_KAT_TestVector> vectors;
    std::istringstream iss(content);
    std::string line;

    MLDSA_KAT_TestVector current_vector;
    bool in_vector = false;

    while (std::getline(iss, line)) {
        line = trim(line);
        if (line.empty()) continue;

        if (line.find("count = ") == 0) {
            if (in_vector) {
                vectors.push_back(current_vector);
            }
            current_vector = MLDSA_KAT_TestVector();
            current_vector.count = std::stoi(line.substr(8));
            in_vector = true;
        } else if (line.find("seed = ") == 0) {
            current_vector.seed = string_to_array<32>(line.substr(7));
        } else if (line.find("pk = ") == 0) {
            current_vector.pk = hex_to_bytes(line.substr(5));
        } else if (line.find("sk = ") == 0) {
            current_vector.sk = hex_to_bytes(line.substr(5));
        } else if (line.find("msg = ") == 0) {
            current_vector.message = hex_to_bytes(line.substr(6));
        } else if (line.find("sm = ") == 0) {
            current_vector.sig = hex_to_bytes(line.substr(5));
        }
    }

    if (in_vector) {
        vectors.push_back(current_vector);
    }

    return vectors;
}

} // namespace clwe