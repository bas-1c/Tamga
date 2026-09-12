#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/policy/PolicyTypes.h"

namespace tamga::core::policy {

// Хвиля 8, п.3: тут більше немає класу `TimestampValidator` і його
// `TimestampValidationInput`/`TimestampValidatorResult`.
//
// Політика довіри до TSA живе рівно в одному місці — `validation::TimestampEngine`.
// Видалений клас був другою, РОЗБІЖНОЮ політикою direct-match і мав нуль
// викликів у продакшні; його тримали живим лише тести. Розбіжності були
// предметні, а не косметичні:
//   * він робив direct-match ще й проти `trust_anchors_der` (CA-якорі QTSP),
//     коли `tsa_trust_anchors_der` порожній, тобто ширший набір збігів;
//   * історичний direct-match гейтився `trust_mode == "compatibility"`,
//     а не `policy.allow_historical_trust`;
//   * і головне — при direct-match він НЕ перевіряв строк дії сертифіката TSA.
//     Саме це виправив С-19, але лише в `TimestampEngine`; тут дефект лишався.
//
// Нижче лишається криптографічний шар — його використовують `TimestampEngine`,
// `PadesVerifier` і `XadesVerifier`.

struct TimestampExtractionResult {
    bool success{false};
    std::string failure_code;
    std::vector<std::uint8_t> token_der; // The extracted DER token bytes (id-aa-signatureTimeStampToken)
    std::string gen_time; // GeneralizedTime converted to string (e.g. ISO-8601 or similar)
    std::string message;
};

struct TimestampValidationResult {
    bool valid{false};
    std::string failure_code;
    std::string gen_time;
    std::vector<std::uint8_t> tsa_certificate_der; // The signer certificate of the TSA
    std::vector<std::vector<std::uint8_t>> embedded_certificates_der; // Other certificates embedded in the token SignedData
    // true, якщо сертифікат TSA знайдено НЕ в самому токені, а у зовнішньому
    // пулі кандидатів (для PAdES-LT/LTA — у /DSS документа).
    bool tsa_certificate_external{false};
    std::string message;
};

// Extracts the raw token and generation time from CMS SignedData
TimestampExtractionResult ExtractTimestampToken(const std::vector<std::uint8_t>& cms_der);

// Cryptographically validates the timestamp token (imprint match, TSA signature, etc.)
//
// additional_certificates_der — необовʼязковий зовнішній пул сертифікатів, у
// якому шукається сертифікат підписанта TSA, якщо його немає в самому токені.
// Для PAdES-LT/LTA це вміст /DSS/Certs: за ETSI EN 319 142-1 докази валідації
// (у т.ч. сертифікати TSA) виносяться у Document Security Store документа, а
// SignedData.certificates токена може бути порожнім. Пул використовується лише
// як джерело кандидатів — звірка з SignerIdentifier токена (issuerAndSerial або
// SKI) і перевірка підпису лишаються обовʼязковими, тож зайві сертифікати в
// пулі не можуть зробити невалідну мітку валідною.
TimestampValidationResult ValidateTimestampToken(
    const std::vector<std::uint8_t>& token_der,
    const std::vector<std::uint8_t>& cms_signature_value,
    const std::vector<std::vector<std::uint8_t>>& additional_certificates_der = {});

} // namespace tamga::core::policy
