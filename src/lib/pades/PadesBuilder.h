#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "core/SignatureRequest.h"
#include "pades/PdfTypes.h"

// Форвард-оголошення крипто-бекендів core, щоб PDF-рушій не протікав у заголовки.
namespace tamga::core {
class CryptoniteAdapter;
class TspClient;
}  // namespace tamga::core

namespace tamga::pades {

// Постачальник RFC 3161 timestamp-токена для PAdES-T/LTA: отримує октети для
// штампування і повертає DER-токен. У продакшні обгортає TspClient; у тестах —
// мок-TSA.
using TimestampProvider = std::function<bool(const std::vector<std::uint8_t>& tbs,
                                             std::vector<std::uint8_t>& token,
                                             std::string& error)>;

// Докази збираються після отримання токена: TSA відповіді може відрізнятися
// від очікуваного сервера. Збір доказів не є рішенням про довіру.
struct PadesValidationEvidence {
    std::vector<std::vector<std::uint8_t>> certificate_chain;
    std::vector<std::vector<std::uint8_t>> crls;
    std::vector<std::vector<std::uint8_t>> ocsp_responses;
};
using TimestampEvidenceProvider = std::function<bool(
    const std::vector<std::uint8_t>& token, const std::vector<std::uint8_t>& tbs,
    PadesValidationEvidence& evidence, std::string& error)>;

// Параметри побудови PAdES-підпису поверх PDF-документа.
struct PadesParameters {
    PadesProfile profile{PadesProfile::B};
    std::string field_name{"Signature1"};
    std::string reason;
    std::string location;
    tamga::core::SignatureRequest request;
    // Для T/LTA — мітки часу; обовʼязковий для profile >= T.
    TimestampProvider timestamp_provider;
    TimestampEvidenceProvider timestamp_evidence_provider;
    // Для LT/LTA — DSS (Document Security Store): сертифікати ланцюга та
    // revocation-дані (інʼєктуються; у продакшні — з chain/revocation сервісів).
    std::vector<std::vector<std::uint8_t>> certificate_chain;
    std::vector<std::vector<std::uint8_t>> crls;
    std::vector<std::vector<std::uint8_t>> ocsp_responses;
};

// Будівник PAdES-підписів: формує детачд CMS над ByteRange і вбудовує його у PDF.
// Реалізація доступна лише у збірці з TAMGA_ENABLE_PDF_SIGNATURES.
class PadesBuilder {
public:
    PadesBuilder(tamga::core::CryptoniteAdapter& crypto, tamga::core::TspClient& tsp);

    // Додає PAdES-підпис до вже існуючого PDF як incremental update. Вхідні
    // bytes і попередні revisions/підписи зберігаються; не-PDF input
    // відхиляється. Повертає false + error_message при помилці.
    bool SignPdf(const PadesParameters& params,
                 const std::vector<std::uint8_t>& document_content,
                 const tamga::core::SigningKey& signing_key,
                 std::vector<std::uint8_t>& signed_pdf_out,
                 std::string& error_message);

private:
    tamga::core::CryptoniteAdapter& crypto_;
    tamga::core::TspClient& tsp_;
};

}  // namespace tamga::pades
