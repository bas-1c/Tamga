// Перевірка відкликання за CRL.
//
// Виділено з CryptoniteAdapter.cpp (O-01): CheckCertificateRevocation /
// GetCrlNextUpdate.

#include "core/cryptonite/Internal.h"

namespace tamga::core {

// Внутрішні помічники реалізації видимі без кваліфікації: код перенесено з
// CryptoniteAdapter.cpp без єдиної правки тіл функцій, тому директива тут
// свідома — вона обмежена цим TU і не впливає на публічний контракт.
using namespace cryptonite_detail;

namespace {
#if TAMGA_CRYPTONITE_ENABLED

time_t PkixTimeToTimeT(const PKIXTime_t& asn_time) {
    if (asn_time.present == PKIXTime_PR_utcTime) {
        return asn_UT2time(&asn_time.choice.utcTime, nullptr, false);
    } else if (asn_time.present == PKIXTime_PR_generalTime) {
        return asn_GT2time(&asn_time.choice.generalTime, nullptr, false);
    }
    return (time_t)-1;
}

#endif  // TAMGA_CRYPTONITE_ENABLED
}  // namespace

CryptoniteAdapter::CrlCheckResult CryptoniteAdapter::CheckCertificateRevocation(
    const std::vector<std::uint8_t>& certificate_der,
    const std::vector<std::uint8_t>& crl_der,
    const std::vector<std::uint8_t>& issuer_certificate_der) {
    CrlCheckResult result;

#if TAMGA_CRYPTONITE_ENABLED
    if (certificate_der.empty() || crl_der.empty()) {
        result.message = "Certificate or CRL data is empty";
        return result;
    }

    ScopedByteArray cert_ba(MakeByteArray(certificate_der), ba_free);
    ScopedByteArray crl_ba(MakeByteArray(crl_der), ba_free);
    ScopedCert cert(cert_alloc(), cert_free);
    ScopedCrl crl(crl_alloc(), crl_free);

    if (cert_ba == nullptr || crl_ba == nullptr || cert == nullptr || crl == nullptr) {
        result.message = "Memory allocation failed";
        return result;
    }

    if (cert_decode(cert.get(), cert_ba.get()) != RET_OK) {
        result.message = "Certificate decode failed";
        return result;
    }

    if (crl_decode(crl.get(), crl_ba.get()) != RET_OK) {
        result.message = "CRL decode failed";
        return result;
    }

    // Verify CRL signature if issuer certificate is provided
    if (!issuer_certificate_der.empty()) {
        ScopedByteArray issuer_ba(MakeByteArray(issuer_certificate_der), ba_free);
        ScopedCert issuer_cert(cert_alloc(), cert_free);
        if (issuer_ba != nullptr && issuer_cert != nullptr &&
            cert_decode(issuer_cert.get(), issuer_ba.get()) == RET_OK) {
            // Адаптер переходить під ScopedVerifyAdapter НЕЗАЛЕЖНО від rc: старий
            // код звільняв його теж безумовно, і init міг залишити ненульовий
            // вказівник навіть при помилці.
            VerifyAdapter* verify_adapter_raw = nullptr;
            const int va_rc = verify_adapter_init_by_cert(issuer_cert.get(), &verify_adapter_raw);
            ScopedVerifyAdapter verify_adapter(verify_adapter_raw, verify_adapter_free);
            if (va_rc == RET_OK && verify_adapter != nullptr) {
                result.crl_valid = crl_verify(crl.get(), verify_adapter.get()) == RET_OK;
            }
        }
    }

    {
        bool is_revoked = false;
        const int rc = crl_check_cert(crl.get(), cert.get(), &is_revoked);
        if (rc == RET_OK) {
            result.checked = true;
            result.revoked = is_revoked;
            result.message = is_revoked ? "Certificate is revoked" : "Certificate is not revoked";
            if (is_revoked) {
                RevokedCertificate_t* rev_cert_raw = nullptr;
                if (crl_get_cert_info(crl.get(), cert.get(), &rev_cert_raw) == RET_OK &&
                    rev_cert_raw != nullptr) {
                    ScopedRevokedCertificate rev_cert(rev_cert_raw, FreeRevokedCertificate);
                    result.revocation_time = PkixTimeToTimeT(rev_cert->revocationDate);
                }
            }
        } else {
            result.message = BuildRcError("CRL certificate check", rc);
        }
    }
#else
    (void)certificate_der;
    (void)crl_der;
    (void)issuer_certificate_der;
    result.message = "Vendored cryptonite support is disabled at build time";
#endif

    return result;
}

bool CryptoniteAdapter::GetCrlValidityWindow(const std::vector<std::uint8_t>& crl_der,
                                             std::time_t& this_update,
                                             std::time_t& next_update) {
    this_update = 0;
    next_update = 0;
#if TAMGA_CRYPTONITE_ENABLED
    if (crl_der.empty()) {
        return false;
    }
    ScopedByteArray crl_ba(MakeByteArray(crl_der), ba_free);
    ScopedCrl crl(crl_alloc(), crl_free);
    if (crl_ba == nullptr || crl == nullptr) {
        return false;
    }
    if (crl_decode(crl.get(), crl_ba.get()) != RET_OK) {
        return false;
    }
    TBSCertList_t* tbs_raw = nullptr;
    if (crl_get_tbs(crl.get(), &tbs_raw) != RET_OK || tbs_raw == nullptr) {
        return false;
    }
    ScopedTbsCertList tbs(tbs_raw, FreeTbsCertList);

    const std::time_t parsed_this = PkixTimeToTimeT(tbs->thisUpdate);
    if (parsed_this == static_cast<std::time_t>(-1)) {
        return false;
    }
    this_update = parsed_this;

    // nextUpdate за RFC 5280 необовʼязковий: його відсутність означає
    // «без заявленої межі свіжості», а не «протерміновано».
    const std::time_t parsed_next = PkixTimeToTimeT(tbs->nextUpdate);
    if (parsed_next != static_cast<std::time_t>(-1)) {
        next_update = parsed_next;
    }
    return true;
#else
    (void)crl_der;
    return false;
#endif
}

bool CryptoniteAdapter::GetCrlNextUpdate(const std::vector<std::uint8_t>& crl_der,
                                         std::time_t& next_update) {
    next_update = 0;
#if TAMGA_CRYPTONITE_ENABLED
    if (crl_der.empty()) {
        return false;
    }
    ScopedByteArray crl_ba(MakeByteArray(crl_der), ba_free);
    ScopedCrl crl(crl_alloc(), crl_free);
    if (crl_ba == nullptr || crl == nullptr) {
        return false;
    }

    bool ok = false;
    if (crl_decode(crl.get(), crl_ba.get()) == RET_OK) {
        TBSCertList_t* tbs_raw = nullptr;
        if (crl_get_tbs(crl.get(), &tbs_raw) == RET_OK && tbs_raw != nullptr) {
            ScopedTbsCertList tbs(tbs_raw, FreeTbsCertList);
            const std::time_t parsed = PkixTimeToTimeT(tbs->nextUpdate);
            if (parsed != static_cast<std::time_t>(-1)) {
                next_update = parsed;
                ok = true;
            }
        }
    }
    return ok;
#else
    (void)crl_der;
    return false;
#endif
}

}  // namespace tamga::core
