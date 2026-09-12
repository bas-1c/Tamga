#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/policy/PolicyTypes.h"
#include "core/validation/ValidationTypes.h"

namespace tamga::core::validation {

/**
 * Роль сертифіката у процесі валідації.
 */
enum class CertificateRole {
    Signer,
    IntermediateCa,
    Tsa,
    OcspResponder,
    CrlIssuer,
};

/**
 * Вхідні параметри для перевірки статусу відкликання сертифіката.
 */
struct RevocationEngineInput {
    std::vector<std::uint8_t> certificate_der;
    std::vector<std::uint8_t> issuer_certificate_der;
    CertificateRole role{CertificateRole::Signer};
    std::string validation_time; // Момент валідації у форматі ISO-8601

    bool network_allowed{false};
    bool revocation_hard_fail{false};
    std::vector<std::vector<std::uint8_t>> crls_der; // Локальні/вбудовані CRL
    std::vector<std::uint8_t> embedded_ocsp_response; // Вбудована OCSP відповідь
    // WP-5: кілька кандидатів вбудованої OCSP-відповіді (XAdES RevocationValues
    // може містити відповіді і для signer, і для intermediate/OCSP-responder
    // сертифікатів). Кожен кандидат перевіряється на CertID-відповідність
    // certificate_der/issuer_certificate_der; перший, що дає визначений
    // good/revoked статус, використовується.
    std::vector<std::vector<std::uint8_t>> embedded_ocsp_responses_der;
    std::string ocsp_url; // URL точки доступу OCSP
};

/**
 * Результат перевірки статусу відкликання сертифіката.
 */
struct RevocationEngineResult {
    OverallStatus overall_status{OverallStatus::Indeterminate};
    policy::RevocationStatus revocation_status{policy::RevocationStatus::NotChecked};
    std::vector<std::string> because;
    std::vector<std::string> warnings;
    std::vector<std::string> limitations;
    std::vector<std::string> evidence_ids; // request_evidence_id, response_evidence_id, crl_evidence_id
    time_t revocation_time{0};
    // WP-11: чи справді робилась спроба OCSP (embedded або мережевий запит),
    // окремо від CRL — потрібно для канонічного `ocspChecked`/`crlChecked` у
    // VerifyReport без здогадок за текстом `because`.
    bool ocsp_attempted{false};
    bool crl_attempted{false};
};

/**
 * Двигун перевірки статусу відкликання сертифікатів.
 */
class RevocationEngine final {
public:
    RevocationEngineResult Validate(const RevocationEngineInput& input) const;
};

} // namespace tamga::core::validation
