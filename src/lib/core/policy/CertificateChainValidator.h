#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/policy/PolicyTypes.h"

namespace tamga::core::policy {

struct CertificateChainInput {
    std::vector<std::uint8_t> signer_certificate_der;
    std::vector<std::vector<std::uint8_t>> embedded_certificates_der;
    std::vector<std::vector<std::uint8_t>> intermediate_certificates_der;
    std::vector<std::vector<std::uint8_t>> aia_certificates_der;
    std::vector<std::vector<std::uint8_t>> trust_anchors_der;
    std::string trust_anchor_source{"trust-store"};
    std::string validation_time;
};

bool ParseIso8601Time(const std::string& text, time_t& out_time);

// С-19: чи дійсний сертифікат (DER) на заданий момент. Винесено з
// анонімного namespace, бо та сама перевірка потрібна TimestampEngine для
// гілки TL direct-match, де ланцюжок узагалі не будується.
// Порожній/нерозбірний час -> перевірка проти поточного часу.
bool IsCertificateValidAt(const std::vector<std::uint8_t>& certificate_der,
                          const std::string& validation_time);

struct CertificateChainResult {
    bool checked{false};
    bool trusted{false};
    bool chain_valid{false};
    ChainStatus status{ChainStatus::NotChecked};
    // WP-3 (canonical certificateTimeValid, CR-02): чи власна валідність
    // (notBefore/notAfter) сертифіката підписанта підтверджена на
    // `validation_time` — незалежно від того, чи ланцюг дійшов до довіреного
    // якоря. Лишається false (невизначено), якщо перевірку взагалі не
    // виконано (сертифікат відсутній/недекодовний).
    bool signer_certificate_time_valid{false};
    std::vector<std::uint8_t> issuer_certificate_der;
    std::vector<std::uint8_t> signer_issuer_certificate_der;
    std::string message;
    std::string chain_debug;
};

class CertificateChainValidator final {
public:
    CertificateChainResult Validate(const CertificateChainInput& input) const;
};

} // namespace tamga::core::policy
