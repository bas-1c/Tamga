#pragma once

// WP-6 (HI-05): спільна ASN.1-коректна перевірка extendedKeyUsage (RFC 5280
// §4.2.1.12), що замінює byte-pattern пошук OID у сирих байтах розширення,
// який раніше дублювався в TimestampValidator.cpp, TimestampEngine.cpp і
// OcspValidator.cpp. Байт-патерн некоректний за конструкцією: він знаходить
// потрібну послідовність байтів будь-де у значенні розширення (включно за
// межами самого KeyPurposeId), не перевіряючи фактичну ASN.1-структуру
// ExtendedKeyUsage, тож підроблене/сфабриковане розширення з тим самим
// байтовим патерном, вставленим як "шум" поза межами дійсного OID, могло б
// хибно пройти перевірку.

#include <cstddef>

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "cert.h"
#include "byte_array.h"
#include "oids.h"
#include "pkix_utils.h"
#include "ExtendedKeyUsage.h"
}
#endif

namespace tamga::core::policy {

#if TAMGA_CRYPTONITE_ENABLED

// Розбирає extendedKeyUsage через ExtendedKeyUsage_desc і перевіряє, чи хоча
// б один KeyPurposeId дорівнює заданому OID (порівняння номерів arc, а не
// сирих байтів).
inline bool CertificateHasExtendedKeyUsage(const Certificate_t* cert, const long* oid_numbers,
                                           std::size_t oid_numbers_len) {
    if (cert == nullptr || oid_numbers == nullptr || oid_numbers_len == 0) {
        return false;
    }
    const OidNumbers* eku_ext_oid = oids_get_oid_numbers_by_id(OID_EXT_KEY_USAGE_EXTENSION_ID);
    if (eku_ext_oid == nullptr) {
        return false;
    }
    ByteArray* ext_value = nullptr;
    if (cert_get_ext_value(cert, eku_ext_oid, &ext_value) != RET_OK || ext_value == nullptr) {
        ba_free(ext_value);
        return false;
    }
    auto* eku = static_cast<ExtendedKeyUsage_t*>(
        asn_decode_with_alloc(get_ExtendedKeyUsage_desc(), ba_get_buf(ext_value), ba_get_len(ext_value)));
    ba_free(ext_value);
    if (eku == nullptr) {
        return false;
    }
    OidNumbers target{const_cast<long*>(oid_numbers), oid_numbers_len};
    bool found = false;
    if (eku->list.array != nullptr) {
        for (int i = 0; i < eku->list.count && !found; ++i) {
            const KeyPurposeId_t* purpose = eku->list.array[i];
            if (purpose != nullptr && pkix_check_oid_equal(purpose, &target)) {
                found = true;
            }
        }
    }
    ASN_FREE(get_ExtendedKeyUsage_desc(), eku);
    return found;
}

// id-kp-timeStamping: 1.3.6.1.5.5.7.3.8 (RFC 3161 §2.3).
inline bool HasTimestampingEku(const Certificate_t* cert) {
    static const long kOid[] = {1, 3, 6, 1, 5, 5, 7, 3, 8};
    return CertificateHasExtendedKeyUsage(cert, kOid, sizeof(kOid) / sizeof(kOid[0]));
}

// id-kp-OCSPSigning: 1.3.6.1.5.5.7.3.9 (RFC 6960 §4.2.2.2).
inline bool HasOcspSigningEku(const Certificate_t* cert) {
    static const long kOid[] = {1, 3, 6, 1, 5, 5, 7, 3, 9};
    return CertificateHasExtendedKeyUsage(cert, kOid, sizeof(kOid) / sizeof(kOid[0]));
}

#endif  // TAMGA_CRYPTONITE_ENABLED

}  // namespace tamga::core::policy
