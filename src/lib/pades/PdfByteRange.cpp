#include "pades/PdfByteRange.h"

namespace tamga::pades {

ByteRange PdfByteRange::Compute(std::size_t lt, std::size_t gt, std::size_t file_size) {
    ByteRange br;
    br.offset1 = 0;
    br.length1 = static_cast<std::uint64_t>(lt);              // До '<', не включаючи його.
    br.offset2 = static_cast<std::uint64_t>(gt + 1);          // Після '>'.
    br.length2 = static_cast<std::uint64_t>(file_size - gt - 1);
    return br;
}

std::vector<std::uint8_t> PdfByteRange::ExtractSignedBytes(const std::vector<std::uint8_t>& pdf,
                                                           const ByteRange& br) {
    std::vector<std::uint8_t> out;
    const std::size_t size = pdf.size();
    const bool first_in_bounds = br.offset1 <= size && br.length1 <= size - br.offset1;
    const bool second_in_bounds = br.offset2 <= size && br.length2 <= size - br.offset2;
    if (first_in_bounds) {
        const std::size_t o1 = static_cast<std::size_t>(br.offset1);
        const std::size_t l1 = static_cast<std::size_t>(br.length1);
        out.insert(out.end(), pdf.begin() + o1, pdf.begin() + o1 + l1);
    }
    if (second_in_bounds) {
        const std::size_t o2 = static_cast<std::size_t>(br.offset2);
        const std::size_t l2 = static_cast<std::size_t>(br.length2);
        out.insert(out.end(), pdf.begin() + o2, pdf.begin() + o2 + l2);
    }
    return out;
}

}  // namespace tamga::pades
