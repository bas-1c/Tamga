#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/policy/PolicyTypes.h"
#include "core/validation/ValidationTypes.h"

namespace tamga::core::validation {

struct TimestampEngineInput {
    std::vector<std::uint8_t> cms_der;
    std::vector<std::uint8_t> explicit_timestamp_token_der;
    std::vector<std::uint8_t> explicit_timestamp_imprint_source;
    std::string validation_time; // ISO-8601
    ValidationPolicy policy;
    ValidationPlan plan;
    std::vector<std::vector<std::uint8_t>> current_trust_anchors_der;
    std::vector<std::vector<std::uint8_t>> tsa_trust_anchors_der;          // TSA endpoint certs від tsa-store (TL direct-match)
    std::vector<std::vector<std::uint8_t>> historical_trust_anchors_der;
    std::vector<std::vector<std::uint8_t>> historical_tsa_trust_anchors_der; // historical-tsa-store
    std::vector<std::vector<std::uint8_t>> custom_trust_anchors_der;
    std::vector<std::vector<std::uint8_t>> pinned_trust_anchors_der;
    std::vector<std::vector<std::uint8_t>> intermediate_store_certificates_der;
    // ПД-01: зовнішній пул кандидатів на сертифікат підписанта TSA, коли самого
    // сертифіката в токені немає. Для PAdES-LT/LTA це /DSS/Certs документа (за
    // ETSI EN 319 142-1 докази валідації виносяться саме туди, а
    // SignedData.certificates токена може бути порожнім); для CMS/CAdES — просто
    // вбудовані сертифікати. Пул є ДЖЕРЕЛОМ КАНДИДАТІВ, а не довіри: звірка з
    // SignerIdentifier токена і перевірка підпису лишаються обов'язковими
    // (див. контракт policy::ValidateTimestampToken), тож зайвий сертифікат у
    // пулі не може зробити невалідну мітку валідною.
    std::vector<std::vector<std::uint8_t>> additional_tsa_candidate_certificates_der;
    // Вбудовані докази відкликання перевіряються щодо TSA та її видавця;
    // жоден сертифікат із контейнера не перетворюється на якір довіри.
    std::vector<std::vector<std::uint8_t>> embedded_crls_der;
    std::vector<std::vector<std::uint8_t>> embedded_ocsp_responses_der;
    ValidationProfile profile{ValidationProfile::Strict};
    ValidationLevel level{ValidationLevel::Basic};
};

struct TimestampEngineResult {
    // valid — повна перевірка; policy_acceptable може бути true за soft-fail,
    // але такого результату недостатньо для довіреного часу підпису.
    bool valid{false};
    bool policy_acceptable{false};
    bool crypto_valid{false};
    bool gen_time_valid{false};
    bool certificate_time_valid{false};
    bool eku_valid{false};
    bool trust_valid{false};
    bool historical_trust_used{false};
    bool revocation_checked{false};
    bool ocsp_attempted{false};
    bool crl_attempted{false};
    policy::TimestampStatus status{policy::TimestampStatus::NotChecked};
    policy::RevocationStatus revocation_status{policy::RevocationStatus::NotChecked};
    std::string reason_code;
    std::string trust_source;
    std::string gen_time;
    std::string validation_time;
    std::vector<std::uint8_t> tsa_certificate_der;
    std::vector<std::uint8_t> tsa_issuer_certificate_der;
    std::vector<std::string> because;
    std::vector<std::string> warnings;
    std::vector<std::string> limitations;
    std::vector<std::string> evidence_ids;
};

class TimestampEngine final {
public:
    TimestampEngineResult Validate(const TimestampEngineInput& input) const;
};

// Строгий UTC GeneralizedTime → ISO-8601; не підставляє поточний час.
bool NormalizeTimestampTime(const std::string& raw, std::string& iso);

// Пошук лише зв'язку видавець → сертифікат (імена та підпис), не довіри.
std::vector<std::uint8_t> FindVerifiedTsaIssuer(
    const std::vector<std::uint8_t>& tsa_der,
    const std::vector<std::vector<std::uint8_t>>& candidates);

// AIA TSA або локальний реєстр за підтвердженим видавцем; без мережі.
std::string ResolveTsaOcspUrl(const std::vector<std::uint8_t>& tsa_der,
                              const std::vector<std::uint8_t>& issuer_der,
                              const std::string& work_dir);

} // namespace tamga::core::validation
