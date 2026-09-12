#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "pades/PdfTypes.h"

namespace tamga::pades {

// Обчислення ByteRange та вилучення підписаних байтів PDF-документа (байтовий
// рівень — над сирими байтами PDF, незалежно від PDF-рушія).
class PdfByteRange {
public:
    // ByteRange для PDF-підпису: range1 = [0, lt), range2 = [gt+1, end).
    // Виключено весь рядок /Contents разом із роздільниками '<' і '>'.
    // lt — зсув '<', gt — зсув '>'.
    static ByteRange Compute(std::size_t lt, std::size_t gt, std::size_t file_size);

    // Конкатенує підписані байти за ByteRange.
    static std::vector<std::uint8_t> ExtractSignedBytes(const std::vector<std::uint8_t>& pdf,
                                                        const ByteRange& br);
};

}  // namespace tamga::pades
