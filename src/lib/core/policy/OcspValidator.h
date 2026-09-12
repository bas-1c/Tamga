#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/policy/PolicyTypes.h"

namespace tamga::core::policy {

struct OcspValidationInput {
    std::string url;
    bool use_nonce{true};
    std::int32_t timeout_ms{10000};
    std::vector<std::uint8_t> signer_certificate_der;
    std::vector<std::uint8_t> issuer_certificate_der;
    std::string validation_time;
    std::vector<std::uint8_t> response_der;
};

struct OcspValidationResult {
    bool checked{false};
    // Чи респондер узагалі ВІДПОВІВ. Без цього поля два принципово різні
    // випадки нерозрізненні ззовні: HTTP-запит не вдався (респондер мовчить)
    // і респондер відповів, але відмовою по суті (`unauthorized`, `tryLater`)
    // — обидва дають `RevocationStatus::ResponderUnavailable`. Для живої
    // сюїти ця різниця визначальна: перший випадок — пропуск тесту (чужа
    // недоступність), другий — відповідь, яку ми зобовʼязані розібрати.
    bool responder_answered{false};
    bool revoked{false};
    RevocationStatus status{RevocationStatus::NotChecked};
    std::string message;
    std::string request_evidence_id;
    std::string response_evidence_id;
    // Лише відповідь із підтвердженим підписом і прив'язкою до CertID;
    // придатна для пакування у DSS, але не є самостійним рішенням про довіру.
    std::vector<std::uint8_t> response_der;
    time_t revocation_time{0};
};

class OcspValidator final {
public:
    OcspValidationResult Validate(const OcspValidationInput& input) const;
};

namespace detail {

struct OcspCertIdFields {
    std::vector<std::uint8_t> issuer_name_hash;
    std::vector<std::uint8_t> issuer_key_hash;
    std::vector<std::uint8_t> serial_number;
};

struct OcspMappedCertificateStatus {
    OcspCertIdFields cert_id;
    std::string status;
    time_t revocation_time{0};
};

RevocationStatus MapOcspStatusForRequestedCertId(
    const OcspCertIdFields& requested,
    const std::vector<OcspMappedCertificateStatus>& statuses,
    bool& revoked,
    time_t& revocation_time,
    std::string& message);

inline RevocationStatus MapOcspStatusForRequestedCertId(
    const OcspCertIdFields& requested,
    const std::vector<OcspMappedCertificateStatus>& statuses,
    bool& revoked,
    std::string& message) {
    time_t dummy_revocation_time = 0;
    return MapOcspStatusForRequestedCertId(requested, statuses, revoked, dummy_revocation_time, message);
}

std::vector<OcspMappedCertificateStatus> MergeOcspStatusesByResponseOrder(
    std::vector<OcspMappedCertificateStatus> cert_ids,
    const std::vector<OcspMappedCertificateStatus>& api_statuses);

} // namespace detail

} // namespace tamga::core::policy
