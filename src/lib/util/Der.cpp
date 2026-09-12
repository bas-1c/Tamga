#include "util/Der.h"

#include <limits>

namespace tamga::util {
namespace {

// Еквівалент `start + len <= limit` без переповнення. Саме наївна форма
// `start + len <= limit` була суттю С-06: при `len`, близькому до SIZE_MAX,
// сума переповнюється по модулю 2^N і перевірка мовчки проходить.
bool InBounds(const std::size_t start, const std::size_t len, const std::size_t limit) {
    return start <= limit && len <= limit - start;
}

}  // namespace

bool ParseDerLength(const std::uint8_t* data,
                    const std::size_t limit,
                    std::size_t& offset,
                    std::size_t& length) {
    if (data == nullptr || offset >= limit) {
        return false;
    }

    const std::uint8_t first = data[offset++];
    if ((first & 0x80U) == 0) {
        length = first;
        return InBounds(offset, length, limit);
    }

    const std::size_t count = first & 0x7FU;
    if (count == 0 || count > sizeof(std::size_t) || !InBounds(offset, count, limit)) {
        return false;
    }

    length = 0;
    for (std::size_t i = 0; i < count; ++i) {
        // Зупиняємось до того, як зсув утратить старші біти: інакше
        // «завелика» довжина мовчки перетворилася б на маленьку.
        if (length > (std::numeric_limits<std::size_t>::max() >> 8U)) {
            return false;
        }
        length = (length << 8U) | data[offset++];
    }

    return InBounds(offset, length, limit);
}

bool ParseTlvAt(const std::uint8_t* data,
                const std::size_t offset,
                const std::size_t limit,
                TlvView& out) {
    if (data == nullptr || offset >= limit) {
        return false;
    }

    out.tag = data[offset];
    out.value_offset = offset + 1;
    std::size_t value_length = 0;
    if (!ParseDerLength(data, limit, out.value_offset, value_length)) {
        return false;
    }

    out.value_length = value_length;
    out.next_offset = out.value_offset + out.value_length;
    return true;
}

bool ParseDerLength(const std::vector<std::uint8_t>& data,
                    const std::size_t limit,
                    std::size_t& offset,
                    std::size_t& length) {
    // Межа не може виходити за фактичний буфер, навіть якщо викликач помилився.
    const std::size_t effective = limit < data.size() ? limit : data.size();
    return ParseDerLength(data.data(), effective, offset, length);
}

bool ParseTlvAt(const std::vector<std::uint8_t>& data,
                const std::size_t offset,
                const std::size_t limit,
                TlvView& out) {
    const std::size_t effective = limit < data.size() ? limit : data.size();
    return ParseTlvAt(data.data(), offset, effective, out);
}

bool ParseTlvAt(const std::vector<std::uint8_t>& data, const std::size_t offset, TlvView& out) {
    return ParseTlvAt(data.data(), offset, data.size(), out);
}

}  // namespace tamga::util
