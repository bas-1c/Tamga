#include "util/Base64.h"

#include <array>
#include <cctype>

namespace tamga::util {

namespace {
constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline std::uint8_t DecodeChar(const char c) {
    if (c >= 'A' && c <= 'Z') return static_cast<std::uint8_t>(c - 'A');
    if (c >= 'a' && c <= 'z') return static_cast<std::uint8_t>(c - 'a' + 26);
    if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 255;
}
} // namespace

std::string Base64Encode(const std::vector<std::uint8_t>& input) {
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);

    for (std::size_t i = 0; i < input.size(); i += 3) {
        const std::uint32_t b0 = input[i];
        const std::uint32_t b1 = (i + 1 < input.size()) ? input[i + 1] : 0;
        const std::uint32_t b2 = (i + 2 < input.size()) ? input[i + 2] : 0;
        const std::uint32_t triple = (b0 << 16) | (b1 << 8) | b2;

        out.push_back(kAlphabet[(triple >> 18) & 0x3F]);
        out.push_back(kAlphabet[(triple >> 12) & 0x3F]);
        out.push_back(i + 1 < input.size() ? kAlphabet[(triple >> 6) & 0x3F] : '=');
        out.push_back(i + 2 < input.size() ? kAlphabet[triple & 0x3F] : '=');
    }

    return out;
}

bool Base64Decode(const std::string& input, std::vector<std::uint8_t>& out) {
    std::string normalized;
    normalized.reserve(input.size());
    for (const unsigned char ch : input) {
        if (std::isspace(ch) != 0) {
            continue;
        }
        normalized.push_back(static_cast<char>(ch));
    }

    if (normalized.size() % 4 != 0) {
        return false;
    }

    out.clear();
    out.reserve((normalized.size() / 4) * 3);

    for (std::size_t i = 0; i < normalized.size(); i += 4) {
        const char c0 = normalized[i];
        const char c1 = normalized[i + 1];
        const char c2 = normalized[i + 2];
        const char c3 = normalized[i + 3];

        const std::uint8_t d0 = DecodeChar(c0);
        const std::uint8_t d1 = DecodeChar(c1);
        const std::uint8_t d2 = (c2 == '=') ? 0 : DecodeChar(c2);
        const std::uint8_t d3 = (c3 == '=') ? 0 : DecodeChar(c3);

        if (d0 == 255 || d1 == 255 || (c2 != '=' && d2 == 255) || (c3 != '=' && d3 == 255)) {
            return false;
        }

        const std::uint32_t triple = (static_cast<std::uint32_t>(d0) << 18) |
                                     (static_cast<std::uint32_t>(d1) << 12) |
                                     (static_cast<std::uint32_t>(d2) << 6) |
                                     static_cast<std::uint32_t>(d3);

        out.push_back(static_cast<std::uint8_t>((triple >> 16) & 0xFF));
        if (c2 != '=') out.push_back(static_cast<std::uint8_t>((triple >> 8) & 0xFF));
        if (c3 != '=') out.push_back(static_cast<std::uint8_t>(triple & 0xFF));
    }

    return true;
}

} // namespace tamga::util
