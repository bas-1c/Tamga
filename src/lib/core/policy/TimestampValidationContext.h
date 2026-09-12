#pragma once

#include <cstdint>
#include <string>
#include <vector>

// WP-0 (заморожений контракт) — для WP-6.
//
// Контекст валідації RFC 3161 TimeStampToken. На відміну від поточної
// поведінки (приймається будь-який із трьох digest, HI-04),
// hash_algorithm_oid є ОБОВʼЯЗКОВИМ: imprint обчислюється САМЕ за цим OID, а
// EKU id-kp-timeStamping перевіряється через ASN.1, не byte-pattern (HI-05).
// Реалізація + єдиний TSA-trust для XAdES VerifyXml — WP-6.

namespace tamga::core::policy {

struct TimestampValidationContext {
    // messageImprint.hashAlgorithm OID (обовʼязковий; порожній -> помилка).
    std::string hash_algorithm_oid;

    // Очікуваний imprint (digest даних, які покриває мітка часу).
    std::vector<std::uint8_t> message_imprint;

    // RFC 3161 TimeStampToken (DER).
    std::vector<std::uint8_t> token_der;

    // Вимагати повний TSA-trust: ланцюг до довіреного TSA + EKU + chain.
    bool require_trusted_tsa{true};

    // Вимагати EKU id-kp-timeStamping (через ASN.1 ExtKeyUsageSyntax).
    bool require_timestamping_eku{true};
};

}  // namespace tamga::core::policy
