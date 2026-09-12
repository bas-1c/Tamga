// WP-6 (HI-05) regression suite — extendedKeyUsage через ASN.1, не byte-pattern.
//
// tamga::core::policy::HasTimestampingEku / HasOcspSigningEku (EkuUtils.h)
// раніше в TimestampValidator.cpp, TimestampEngine.cpp і OcspValidator.cpp
// шукали DER-послідовність байтів OID у сирому значенні розширення
// extendedKeyUsage. Такий пошук коректно розпізнає легітимні сертифікати,
// але не перевіряє фактичну ASN.1-структуру ExtendedKeyUsage: довільні
// байти, що випадково або навмисно опинилися в тому самому extnValue ПІСЛЯ
// справжнього SET OF KeyPurposeId, теж "знаходяться" підрядковим пошуком,
// хоча жодним KeyPurposeId насправді не є.
//
// Цей тест перевіряє чотири випадки на реально згенерованих
// самопідписаних DSTU4145-сертифікатах:
//   1) валідний EKU id-kp-timeStamping -> HasTimestampingEku == true;
//   2) відсутній EKU -> обидві функції == false;
//   3) інший EKU (id-kp-OCSPSigning) -> HasTimestampingEku == false,
//      HasOcspSigningEku == true (і навпаки для дзеркального випадку);
//      4) підроблений byte-pattern: єдиний легітимний KeyPurposeId —
//      id-kp-OCSPSigning, але одразу ПІСЛЯ коректного DER-encoding
//      ExtendedKeyUsage у той самий extnValue дописано сирі байти
//      OID id-kp-timeStamping. Старий підхід (пошук підрядка) хибно
//      визнав би це за наявність timeStamping EKU; ASN.1-парсер — ні,
//      бо єдиний елемент SET OF залишається OCSPSigning.
//
// Повертає: 0 = усі перевірки пройшли; 1 = регресія; 77 = збірка без
// TAMGA_ENABLE_VENDOR_CRYPTONITE (тест недоступний).

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

#include "core/policy/EkuUtils.h"

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "aid.h"
#include "byte_array.h"
#include "cert.h"
#include "cert_engine.h"
#include "certificate_request_engine.h"
#include "cryptonite_manager.h"
#include "digest_adapter.h"
#include "dstu4145.h"
#include "ext.h"
#include "gost28147.h"
#include "oids.h"
#include "pkcs12.h"
#include "pkix_utils.h"
#include "sign_adapter.h"
#include "spki.h"
#include "verify_adapter.h"
}
#endif

namespace {

constexpr int kSkip = 77;

bool Require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        return false;
    }
    return true;
}

#if TAMGA_CRYPTONITE_ENABLED

// id-kp-timeStamping: 1.3.6.1.5.5.7.3.8, DER: 06 08 2B 06 01 05 05 07 03 08.
const std::vector<std::uint8_t> kTimeStampingOidDer = {
    0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08};

// Генерує мінімальний самопідписаний DSTU4145-сертифікат. Якщо
// eku_oid_numbers непорожній, додає розширення extendedKeyUsage з єдиним
// KeyPurposeId, побудованим з цих номерів arc; append_forged_suffix (якщо
// непорожній) дописується у сирі байти extnValue ПІСЛЯ коректного
// DER-encoding, імітуючи атаку на byte-pattern пошук.
bool GenerateCertWithEku(const std::vector<long>& eku_oid_numbers,
                        const std::vector<std::uint8_t>& append_forged_suffix,
                        std::vector<std::uint8_t>& cert_der_out) {
    cert_der_out.clear();

    Dstu4145Ctx* ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    Gost28147Ctx* cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    if (ec_params == nullptr || cipher_params == nullptr) {
        dstu4145_free(ec_params);
        gost28147_free(cipher_params);
        return false;
    }

    AlgorithmIdentifier_t* aid = nullptr;
    ByteArray* aid_ba = nullptr;
    Pkcs12Ctx* storage = nullptr;
    SignAdapter* sa = nullptr;
    DigestAdapter* da = nullptr;
    VerifyAdapter* va = nullptr;
    CertificateRequestEngine* creq_eng = nullptr;
    CertificationRequest_t* cert_req = nullptr;
    CertificateEngine* cert_eng = nullptr;
    Certificate_t* cert = nullptr;
    ByteArray* cert_encoded = nullptr;
    Extension_t* eku_ext = nullptr;
    OBJECT_IDENTIFIER_t* eku_oid = nullptr;
    Extensions_t* extensions = nullptr;
    SubjectPublicKeyInfo_t* spki = nullptr;
    int rc = 0;
    bool ok = false;

    rc = aid_create_dstu4145(ec_params, cipher_params, true, &aid);
    if (rc != 0) goto cleanup;
    rc = aid_encode(aid, &aid_ba);
    if (rc != 0) goto cleanup;
    rc = pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, "test", 1024, &storage);
    if (rc != 0) goto cleanup;
    rc = pkcs12_generate_key(storage, aid_ba);
    if (rc != 0) goto cleanup;
    rc = pkcs12_store_key(storage, "signer", "test", 1024);
    if (rc != 0) goto cleanup;
    rc = pkcs12_select_key(storage, "signer", "test");
    if (rc != 0) goto cleanup;
    rc = pkcs12_get_sign_adapter(storage, &sa);
    if (rc != 0) goto cleanup;
    rc = pkcs12_get_verify_adapter(storage, &va);
    if (rc != 0) goto cleanup;
    rc = va->get_pub_key(va, &spki);
    if (rc != 0) goto cleanup;
    rc = digest_adapter_init_by_aid(&spki->algorithm, &da);
    if (rc != 0) goto cleanup;
    rc = ecert_request_alloc(sa, &creq_eng);
    if (rc != 0) goto cleanup;
    rc = ecert_request_set_subj_name(creq_eng, "{CN=Tamga EKU Test}{O=Tamga}{C=UA}");
    if (rc != 0) goto cleanup;
    rc = ecert_request_generate(creq_eng, &cert_req);
    if (rc != 0) goto cleanup;

    if (!eku_oid_numbers.empty()) {
        OidNumbers numbers{const_cast<long*>(eku_oid_numbers.data()), eku_oid_numbers.size()};
        rc = pkix_create_oid(&numbers, &eku_oid);
        if (rc != 0) goto cleanup;

        OBJECT_IDENTIFIER_t* oids[1] = {eku_oid};
        rc = ext_create_ext_key_usage(false, oids, 1, &eku_ext);
        if (rc != 0) goto cleanup;

        if (!append_forged_suffix.empty()) {
            std::vector<std::uint8_t> combined(eku_ext->extnValue.buf,
                                               eku_ext->extnValue.buf + eku_ext->extnValue.size);
            combined.insert(combined.end(), append_forged_suffix.begin(), append_forged_suffix.end());
            rc = OCTET_STRING_fromBuf(&eku_ext->extnValue,
                                      reinterpret_cast<const char*>(combined.data()),
                                      static_cast<int>(combined.size()));
            if (rc != 0) goto cleanup;
        }

        extensions = static_cast<Extensions_t*>(calloc(1, sizeof(Extensions_t)));
        if (extensions == nullptr) goto cleanup;
        rc = ASN_SEQUENCE_ADD(&extensions->list, eku_ext);
        if (rc != 0) goto cleanup;
        eku_ext = nullptr;  // ownership transferred to extensions
    }

    rc = ecert_alloc(sa, da, true, &cert_eng);
    if (rc != 0) goto cleanup;

    {
        const unsigned char serial_bytes[] = {
            0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33
        };
        ByteArray* serial_ba = ba_alloc_from_uint8(serial_bytes, sizeof(serial_bytes));
        time_t not_before = std::time(nullptr) - 86400;
        time_t not_after = not_before + 365 * 86400;
        rc = ecert_generate(cert_eng, cert_req, 2, serial_ba, &not_before, &not_after, extensions, &cert);
        ba_free(serial_ba);
    }
    if (rc != 0) goto cleanup;

    rc = cert_encode(cert, &cert_encoded);
    if (rc != 0) goto cleanup;

    cert_der_out.assign(ba_get_buf(cert_encoded), ba_get_buf(cert_encoded) + ba_get_len(cert_encoded));
    ok = true;

cleanup:
    ba_free(cert_encoded);
    cert_free(cert);
    ecert_free(cert_eng);
    if (extensions != nullptr) {
        ASN_FREE_CONTENT_STATIC(get_Extensions_desc(), extensions);
        free(extensions);
    }
    if (eku_ext != nullptr) {
        ASN_FREE(get_Extension_desc(), eku_ext);
    }
    if (eku_oid != nullptr) {
        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), eku_oid);
    }
    ecert_request_free(creq_eng);
    if (cert_req != nullptr) {
        ASN_FREE(get_CertificationRequest_desc(), cert_req);
    }
    spki_free(spki);
    digest_adapter_free(da);
    verify_adapter_free(va);
    sign_adapter_free(sa);
    pkcs12_free(storage);
    ba_free(aid_ba);
    aid_free(aid);
    gost28147_free(cipher_params);
    dstu4145_free(ec_params);
    return ok;
}

bool CheckEkuOnDer(const std::vector<std::uint8_t>& cert_der, bool& has_timestamping, bool& has_ocsp_signing) {
    ByteArray* ba = ba_alloc_from_uint8(cert_der.data(), cert_der.size());
    if (ba == nullptr) {
        return false;
    }
    Certificate_t* cert = cert_alloc();
    if (cert == nullptr) {
        ba_free(ba);
        return false;
    }
    const bool decoded = cert_decode(cert, ba) == RET_OK;
    ba_free(ba);
    if (!decoded) {
        cert_free(cert);
        return false;
    }
    has_timestamping = tamga::core::policy::HasTimestampingEku(cert);
    has_ocsp_signing = tamga::core::policy::HasOcspSigningEku(cert);
    cert_free(cert);
    return true;
}

bool RunValidTimestampingEkuCase() {
    std::vector<std::uint8_t> cert_der;
    if (!Require(GenerateCertWithEku({1, 3, 6, 1, 5, 5, 7, 3, 8}, {}, cert_der),
                 "Failed to generate cert with id-kp-timeStamping EKU")) {
        return false;
    }
    bool has_timestamping = false;
    bool has_ocsp_signing = false;
    if (!Require(CheckEkuOnDer(cert_der, has_timestamping, has_ocsp_signing), "Failed to decode generated cert")) {
        return false;
    }
    return Require(has_timestamping, "Valid id-kp-timeStamping EKU must be recognized") &&
           Require(!has_ocsp_signing, "Cert with only timeStamping EKU must not report OCSPSigning");
}

bool RunNoEkuCase() {
    std::vector<std::uint8_t> cert_der;
    if (!Require(GenerateCertWithEku({}, {}, cert_der), "Failed to generate cert without EKU extension")) {
        return false;
    }
    bool has_timestamping = false;
    bool has_ocsp_signing = false;
    if (!Require(CheckEkuOnDer(cert_der, has_timestamping, has_ocsp_signing), "Failed to decode generated cert")) {
        return false;
    }
    return Require(!has_timestamping, "Cert without EKU extension must not report timeStamping") &&
           Require(!has_ocsp_signing, "Cert without EKU extension must not report OCSPSigning");
}

bool RunDifferentEkuCase() {
    std::vector<std::uint8_t> cert_der;
    if (!Require(GenerateCertWithEku({1, 3, 6, 1, 5, 5, 7, 3, 9}, {}, cert_der),
                 "Failed to generate cert with id-kp-OCSPSigning EKU")) {
        return false;
    }
    bool has_timestamping = false;
    bool has_ocsp_signing = false;
    if (!Require(CheckEkuOnDer(cert_der, has_timestamping, has_ocsp_signing), "Failed to decode generated cert")) {
        return false;
    }
    return Require(!has_timestamping, "Cert with only OCSPSigning EKU must not report timeStamping") &&
           Require(has_ocsp_signing, "Valid id-kp-OCSPSigning EKU must be recognized");
}

bool RunForgedBytePatternCase() {
    // Єдиний легітимний KeyPurposeId -- OCSPSigning. Одразу після коректного
    // DER-encoding ExtendedKeyUsage дописано сирі байти OID id-kp-timeStamping
    // -- рядок, який стара реалізація (memcmp по всьому extnValue) знайшла б
    // і хибно повернула HasTimestampingEku == true.
    std::vector<std::uint8_t> cert_der;
    if (!Require(GenerateCertWithEku({1, 3, 6, 1, 5, 5, 7, 3, 9}, kTimeStampingOidDer, cert_der),
                 "Failed to generate cert with forged trailing OID pattern")) {
        return false;
    }
    bool has_timestamping = false;
    bool has_ocsp_signing = false;
    if (!Require(CheckEkuOnDer(cert_der, has_timestamping, has_ocsp_signing), "Failed to decode generated cert")) {
        return false;
    }
    return Require(!has_timestamping,
                   "ASN.1-correct EKU parsing must NOT be fooled by a forged timeStamping OID "
                   "pattern appended after the real (OCSPSigning-only) ExtendedKeyUsage DER "
                   "content -- a byte-substring scan would have wrongly matched here") &&
           Require(has_ocsp_signing, "The only real KeyPurposeId (OCSPSigning) must still be recognized");
}

#endif  // TAMGA_CRYPTONITE_ENABLED

}  // namespace

int main() {
#if !TAMGA_CRYPTONITE_ENABLED
    std::cerr << "Skipping HI-05 EKU regression: built without TAMGA_ENABLE_VENDOR_CRYPTONITE\n";
    return kSkip;
#else
    bool ok = true;
    ok = RunValidTimestampingEkuCase() && ok;
    ok = RunNoEkuCase() && ok;
    ok = RunDifferentEkuCase() && ok;
    ok = RunForgedBytePatternCase() && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
#endif
}
