#ifndef NIST_KAT_PARSER_HPP
#define NIST_KAT_PARSER_HPP

#include <vector>
#include <string>
#include <array>
#include <cstdint>

namespace clwe {

// Structure for ML-DSA KAT test vector
struct MLDSA_KAT_TestVector {
    uint32_t count;
    std::array<uint8_t, 32> seed;
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
    std::vector<uint8_t> message;
    std::vector<uint8_t> sig;
};

// Class to download and parse NIST KAT files
class NIST_KAT_Downloader {
public:
    // Download ML-DSA KAT file for given parameter set
    static std::string download_mldsa_kat(uint32_t security_level);

    // Parse ML-DSA .rsp file content
    static std::vector<MLDSA_KAT_TestVector> parse_mldsa_kat(const std::string& content);
};

} // namespace clwe

#endif // NIST_KAT_PARSER_HPP