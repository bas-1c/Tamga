#include "util/Hex.h"

#include <iomanip>
#include <sstream>

namespace tamga::util {

std::string HexEncode(const std::uint8_t* data, const std::size_t size) {
    if (data == nullptr || size == 0) {
        return {};
    }
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i) {
        stream << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return stream.str();
}

std::string HexEncode(const std::vector<std::uint8_t>& data) {
    return HexEncode(data.data(), data.size());
}

std::string HexFromUInt64(std::uint64_t value) {
    constexpr char kHex[] = "0123456789abcdef";
    std::string out(16U, '0');
    for (std::size_t i = 0; i < out.size(); ++i) {
        const std::size_t shift = (out.size() - 1U - i) * 4U;
        out[i] = kHex[(value >> shift) & 0x0FU];
    }
    return out;
}

std::string StableDerHash(const std::vector<std::uint8_t>& data) {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const std::uint8_t byte : data) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return HexFromUInt64(hash);
}

} // namespace tamga::util
