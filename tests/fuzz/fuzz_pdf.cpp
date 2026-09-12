// Fuzz-ціль: PDF (PAdES).
//
// Поверхня: qpdf плюс власний розбір /ByteRange, /Contents і /DSS. Цікаві саме
// ці три: перші два визначають, ЩО саме покрито підписом, а /DSS — джерело
// сертифікатів TSA (див. ADR 018 і виправлення резолвінгу TSA з /DSS).

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "pades/PdfParser.h"

namespace {

constexpr std::size_t kMaxInput = 8u * 1024u * 1024u;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > kMaxInput) {
        return 0;
    }
    const std::vector<std::uint8_t> pdf(data, data + size);

    {
        std::string error;
        (void)tamga::pades::PdfParser::IsValidPdf(pdf, error);
    }

    // Обидва наступні шляхи навмисно викликаються НЕЗАЛЕЖНО від результату
    // IsValidPdf: у реальному обігу трапляються документи, які qpdf вважає
    // пошкодженими, але з яких верифікатор усе одно намагається щось дістати.
    {
        const auto fields = tamga::pades::PdfParser::ExtractSignatureFields(pdf);
        (void)fields.size();
    }

    {
        std::vector<std::vector<std::uint8_t>> certificates;
        std::vector<std::vector<std::uint8_t>> ocsp_responses;
        std::vector<std::vector<std::uint8_t>> crls;
        (void)tamga::pades::PdfParser::ParseDss(pdf, certificates, ocsp_responses, crls);
    }

    return 0;
}
