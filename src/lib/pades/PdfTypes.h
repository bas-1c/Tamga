#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::pades {

// Спільні PDF/PAdES типи: профілі, ByteRange та модель словника підпису.

// Рівень PAdES-профілю згідно ETSI EN 319 142-1.
enum class PadesProfile {
    B,
    T,
    LT,
    LTA,
};

// ByteRange PDF-підпису: два діапазони байтів навколо вмісту /Contents.
struct ByteRange {
    std::uint64_t offset1{0};
    std::uint64_t length1{0};
    std::uint64_t offset2{0};
    std::uint64_t length2{0};
};

// Модель словника підпису PDF (/Sig) із форматно-специфічними полями PAdES.
struct PdfSignatureDictionary {
    PadesProfile profile{PadesProfile::B};
    ByteRange byte_range;
    std::vector<std::uint8_t> signature;  // DER CMS/CAdES залежно від SubFilter
    std::string sub_filter;               // adbe.pkcs7.detached, ETSI.CAdES.detached, ETSI.RFC3161
    std::string reason;
    std::string location;
    std::string contact_info;
    std::string signing_time;
    std::vector<std::uint8_t> cert;  // опційне вбудовування сертифіката
};

}  // namespace tamga::pades
