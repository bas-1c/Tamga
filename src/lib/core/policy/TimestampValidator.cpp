#include "core/policy/TimestampValidator.h"
#include "util/Der.h"
#include "util/Iso8601.h"
#include "core/cryptonite/Internal.h"
#include "core/cryptonite/Names.h"
#include "core/policy/CertificateChainValidator.h"

#include "core/CryptoniteAdapter.h"
#include "core/policy/EkuUtils.h"
#include "core/policy/ImprintDigest.h"
#include "core/policy/Sha256Helper.h"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "TSTInfo.h"
#include "byte_array.h"
#include "content_info.h"
#include "dstu7564.h"
#include "gost34_311.h"
#include "pkix_errors.h"
#include "signed_data.h"
#include "CertificateSet.h"
#include "SignerIdentifier.h"
#include "cert.h"
#include "signer_info.h"
#include "signed_data_engine.h"
#include "signer_info_engine.h"
#include "asn1_utils.h"
#include "oids.h"
#include "pkix_utils.h"
#include "cryptonite_manager.h"
#include "ext.h"
#include "Attribute.h"
#include "OCTET_STRING.h"
#include "OBJECT_IDENTIFIER.h"
}
#endif

namespace tamga::core::policy {

namespace {

#if TAMGA_CRYPTONITE_ENABLED
// ADR-027: локальна копія прибрана — спільні обгортки живуть у
// `core/cryptonite/Internal.h`.
// Семантика збігалася з Internal.h (порожній вхід -> порожній ByteArray).
using cryptonite_detail::MakeByteArray;

std::string GeneralizedTimeToString(const GeneralizedTime_t& time) {
    if (time.buf == nullptr || time.size <= 0) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(time.buf),
                       reinterpret_cast<const char*>(time.buf) + time.size);
}

// WP-6 (HI-04): dotted-рядок OID для messageImprint.hashAlgorithm.
// ADR-027: власна копія прибрана — OidFromAsn1(OBJECT_IDENTIFIER_t) один,
// у `cryptonite/Names`.
using tamga::core::cryptonite_detail::OidFromAsn1;

// Примітка (O-06 аудиту): локальна копія ComputeKupyna256, що раніше була
// тут, прибрана — використовується спільна tamga::core::ComputeKupyna256 із
// ImprintDigest.h/.cpp. ComputeGost34311Local навмисно ЛИШАЄТЬСЯ локальною
// (окреме питання дублювання з іншими місцями поки не вирішувалось).
//
// ГОСТ 34.311 imprint (українські TSA можуть використовувати його у
// messageImprint). Доповнює перевірку imprint у ValidateTimestampToken.
bool ComputeGost34311Local(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& out_hash) {
    ByteArray* sync = ba_alloc_by_len(32);
    if (sync == nullptr) {
        return false;
    }
    ba_set(sync, 0);
    Gost34311Ctx* ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);
    if (ctx == nullptr) {
        ba_free(sync);
        return false;
    }
    ByteArray* data_ba = MakeByteArray(data);
    ByteArray* hash_ba = nullptr;
    bool ok = data_ba != nullptr && gost34_311_update(ctx, data_ba) == 0 &&
              gost34_311_final(ctx, &hash_ba) == 0 && hash_ba != nullptr;
    if (ok) {
        out_hash.assign(ba_get_buf(hash_ba), ba_get_buf(hash_ba) + ba_get_len(hash_ba));
    }
    ba_free(hash_ba);
    ba_free(data_ba);
    gost34_311_free(ctx);
    ba_free(sync);
    return ok;
}

// Повертає точне кодування SignerInfo.signedAttrs із вхідного CMS, не
// перекодовуючи SET OF. Окремі українські TSA видають BER-сумісний порядок
// атрибутів, який ASN.1-кодер при повторному DER-кодуванні переставляє; підпис
// треба перевіряти над фактично переданими байтами з нормативною заміною тегу
// IMPLICIT [0] на SET OF (RFC 5652 §5.4).
bool ExtractRawSignedAttrs(const std::vector<std::uint8_t>& cms_der,
                           std::vector<std::uint8_t>& encoded_attrs) {
    using tamga::util::ParseTlvAt;
    using tamga::util::TlvView;

    encoded_attrs.clear();
    TlvView content_info{};
    TlvView content_type{};
    TlvView explicit_content{};
    TlvView signed_data{};
    if (!ParseTlvAt(cms_der, 0U, content_info) || content_info.tag != 0x30U ||
        !ParseTlvAt(cms_der, content_info.value_offset, content_info.next_offset, content_type) ||
        content_type.tag != 0x06U ||
        !ParseTlvAt(cms_der, content_type.next_offset, content_info.next_offset, explicit_content) ||
        explicit_content.tag != 0xA0U ||
        !ParseTlvAt(cms_der, explicit_content.value_offset, explicit_content.next_offset,
                    signed_data) ||
        signed_data.tag != 0x30U) {
        return false;
    }

    std::size_t cursor = signed_data.value_offset;
    TlvView node{};
    // version, digestAlgorithms, encapContentInfo
    for (int index = 0; index < 3; ++index) {
        if (!ParseTlvAt(cms_der, cursor, signed_data.next_offset, node)) {
            return false;
        }
        cursor = node.next_offset;
    }
    // certificates [0] і CRLs [1] є необов'язковими.
    while (cursor < signed_data.next_offset &&
           ParseTlvAt(cms_der, cursor, signed_data.next_offset, node) &&
           (node.tag == 0xA0U || node.tag == 0xA1U)) {
        cursor = node.next_offset;
    }
    TlvView signer_infos{};
    TlvView signer_info{};
    if (!ParseTlvAt(cms_der, cursor, signed_data.next_offset, signer_infos) ||
        signer_infos.tag != 0x31U ||
        !ParseTlvAt(cms_der, signer_infos.value_offset, signer_infos.next_offset, signer_info) ||
        signer_info.tag != 0x30U) {
        return false;
    }

    cursor = signer_info.value_offset;
    // version, sid, digestAlgorithm
    for (int index = 0; index < 3; ++index) {
        if (!ParseTlvAt(cms_der, cursor, signer_info.next_offset, node)) {
            return false;
        }
        cursor = node.next_offset;
    }
    TlvView signed_attrs{};
    if (!ParseTlvAt(cms_der, cursor, signer_info.next_offset, signed_attrs) ||
        signed_attrs.tag != 0xA0U) {
        return false;
    }
    encoded_attrs.assign(cms_der.begin() + static_cast<std::ptrdiff_t>(cursor),
                         cms_der.begin() + static_cast<std::ptrdiff_t>(signed_attrs.next_offset));
    return !encoded_attrs.empty();
}

// Звірка кандидатів у наборі із SignerIdentifier: спершу вимагаємо
// digitalSignature у KeyUsage, потім (як і раніше) допускаємо сертифікат без
// цього обмеження — сертифікати TSA подекуди не несуть KeyUsage взагалі.
int LocalResolveSignerFromSet(const SignerIdentifier_t* signer_id,
                              const CertificateSet_t* certs,
                              Certificate_t** certificate) {
    if (certs == nullptr) {
        return RET_PKIX_NO_CERTIFICATE;
    }
    int rc = get_cert_by_sid_and_usage(signer_id, KEY_USAGE_DIGITAL_SIGNATURE, certs, certificate);
    if (rc != RET_OK || *certificate == nullptr) {
        cert_free(*certificate);
        *certificate = nullptr;
        rc = get_cert_by_sid_and_usage(signer_id, 0, certs, certificate);
    }
    return rc;
}

// Складає CertificateSet із набору DER-сертифікатів (для PAdES — з /DSS/Certs).
// Непридатні до розбору записи мовчки пропускаються: /DSS — це контейнер
// доказів, у якому сторонній запис не має ламати резолвінг решти. Порожній
// або цілком нерозбірливий набір дає RET_PKIX_NO_CERTIFICATE.
int LocalBuildCertificateSet(const std::vector<std::vector<std::uint8_t>>& ders,
                             CertificateSet_t** out) {
    *out = nullptr;

    std::vector<ByteArray*> owned;
    std::vector<const ByteArray*> pool;
    owned.reserve(ders.size());
    pool.reserve(ders.size() + 1);

    for (const auto& der : ders) {
        if (der.empty()) {
            continue;
        }
        ByteArray* ba = ba_alloc_from_uint8(der.data(), der.size());
        if (ba == nullptr) {
            continue;
        }
        // Попередній розбір: get_cert_set_from_cert_array перериває побудову
        // всього набору на першому ж збійному записі, тож відсіюємо їх тут.
        Certificate_t* probe = cert_alloc();
        const bool decodable = probe != nullptr && cert_decode(probe, ba) == RET_OK;
        cert_free(probe);
        if (!decodable) {
            ba_free(ba);
            continue;
        }
        owned.push_back(ba);
        pool.push_back(ba);
    }
    pool.push_back(nullptr);

    int rc = RET_PKIX_NO_CERTIFICATE;
    if (!owned.empty()) {
        rc = get_cert_set_from_cert_array(pool.data(), out);
    }

    for (ByteArray* ba : owned) {
        ba_free(ba);
    }
    if (rc != RET_OK) {
        ASN_FREE(&CertificateSet_desc, *out);
        *out = nullptr;
    }
    return rc;
}

// additional_certificates_der — зовнішній пул кандидатів (для PAdES-LT/LTA це
// /DSS/Certs документа). Використовується лише тоді, коли сертифікат підписанта
// відсутній у самому SignedData.
int LocalExtractSignerCertificate(const SignedData_t* signed_data,
                                  Certificate_t** certificate,
                                  const std::vector<std::vector<std::uint8_t>>& additional_certificates_der = {},
                                  bool* resolved_externally = nullptr,
                                  int* embedded_certificate_count = nullptr) {
    SignerInfo_t* signer_info = nullptr;
    SignerIdentifier_t* signer_id = nullptr;
    CertificateSet_t* certs = nullptr;
    CertificateSet_t* external_certs = nullptr;
    int rc = RET_OK;

    *certificate = nullptr;
    if (resolved_externally != nullptr) {
        *resolved_externally = false;
    }
    if (embedded_certificate_count != nullptr) {
        *embedded_certificate_count = 0;
    }

    rc = sdata_get_signer_info_by_idx(signed_data, 0, &signer_info);
    if (rc != RET_OK) {
        goto cleanup;
    }

    rc = sinfo_get_signer_id(signer_info, &signer_id);
    if (rc != RET_OK) {
        goto cleanup;
    }

    rc = sdata_get_certs(signed_data, &certs);
    if (rc == RET_OK && certs != nullptr) {
        if (embedded_certificate_count != nullptr) {
            *embedded_certificate_count = certs->list.count;
        }
        rc = LocalResolveSignerFromSet(signer_id, certs, certificate);
    } else {
        rc = (rc == RET_OK) ? RET_PKIX_NO_CERTIFICATE : rc;
    }

    // PAdES-LT/LTA: у токені мітки часу сертифікат TSA може бути відсутній —
    // за ETSI EN 319 142-1 докази валідації виносяться у /DSS документа.
    // Шукаємо там за тим самим SignerIdentifier; сама перевірка підпису далі
    // не змінюється, тож зовнішній пул не послаблює вердикт.
    if ((rc != RET_OK || *certificate == nullptr) && !additional_certificates_der.empty()) {
        cert_free(*certificate);
        *certificate = nullptr;
        if (LocalBuildCertificateSet(additional_certificates_der, &external_certs) == RET_OK) {
            rc = LocalResolveSignerFromSet(signer_id, external_certs, certificate);
            if (rc == RET_OK && *certificate != nullptr && resolved_externally != nullptr) {
                *resolved_externally = true;
            }
        }
    }

cleanup:
    sinfo_free(signer_info);
    ASN_FREE(&SignerIdentifier_desc, signer_id);
    ASN_FREE(&CertificateSet_desc, certs);
    ASN_FREE(&CertificateSet_desc, external_certs);
    return rc;
}

bool LocalEncodeCertificateDer(const Certificate_t* certificate, std::vector<std::uint8_t>& out_der) {
    if (certificate == nullptr) {
        out_der.clear();
        return false;
    }
    ByteArray* encoded = nullptr;
    const int rc = cert_encode(const_cast<Certificate_t*>(certificate), &encoded);
    if (rc != RET_OK || encoded == nullptr) {
        ba_free(encoded);
        out_der.clear();
        return false;
    }
    const std::uint8_t* buf = ba_get_buf(encoded);
    const size_t len = ba_get_len(encoded);
    if (buf != nullptr && len > 0) {
        out_der.assign(buf, buf + len);
    } else {
        out_der.clear();
    }
    ba_free(encoded);
    return !out_der.empty();
}
#endif

// ADR-027: копія прибрана — спільна реалізація в `util/Iso8601.h`.
using tamga::util::FormatAsIso8601;

[[maybe_unused]] bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

} // namespace

TimestampExtractionResult ExtractTimestampToken(const std::vector<std::uint8_t>& cms_der) {
    TimestampExtractionResult result;
    result.failure_code = "TIMESTAMP_FORMAT_INVALID";
    if (cms_der.empty()) {
        result.message = "CMS input is empty.";
        return result;
    }

    std::string error_message;
    bool timestamp_present = false;
    if (tamga::core::CryptoniteAdapter::HasSignatureTimestampToken(cms_der, timestamp_present, error_message) &&
        !timestamp_present) {
        result.failure_code = "TIMESTAMP_MISSING";
        result.message = "CMS signature timestamp is missing.";
        return result;
    }
    if (!tamga::core::CryptoniteAdapter::ExtractSignatureTimestampToken(cms_der, result.token_der, error_message)) {
        result.message = error_message.empty()
            ? "CMS signature does not contain id-aa-signatureTimeStampToken."
            : error_message;
        return result;
    }

#if TAMGA_CRYPTONITE_ENABLED
    ByteArray* token_ba = MakeByteArray(result.token_der);
    if (token_ba == nullptr) {
        result.message = "Unable to allocate timestamp token buffer.";
        return result;
    }

    ContentInfo_t* token_cinfo = cinfo_alloc();
    if (token_cinfo == nullptr) {
        ba_free(token_ba);
        result.message = "Unable to allocate timestamp token ContentInfo.";
        return result;
    }

    int rc = cinfo_decode(token_cinfo, token_ba);
    if (rc != RET_OK) {
        cinfo_free(token_cinfo);
        ba_free(token_ba);
        result.message = "Timestamp token ContentInfo decode failed.";
        return result;
    }

    SignedData_t* token_sdata = nullptr;
    rc = cinfo_get_signed_data(token_cinfo, &token_sdata);
    if (rc != RET_OK || token_sdata == nullptr) {
        cinfo_free(token_cinfo);
        ba_free(token_ba);
        result.message = "Timestamp token is not CMS SignedData.";
        return result;
    }

    TSTInfo_t* tst_info = nullptr;
    rc = sdata_get_tst_info(token_sdata, &tst_info);
    if (rc != RET_OK || tst_info == nullptr) {
        sdata_free(token_sdata);
        cinfo_free(token_cinfo);
        ba_free(token_ba);
        result.message = "Timestamp token does not contain TSTInfo.";
        return result;
    }

    result.gen_time = GeneralizedTimeToString(tst_info->genTime);
    result.success = true;
    result.failure_code.clear();

    ASN_FREE(&TSTInfo_desc, tst_info);
    sdata_free(token_sdata);
    cinfo_free(token_cinfo);
    ba_free(token_ba);
    return result;
#else
    result.failure_code = "TIMESTAMP_UNSUPPORTED";
    result.message = "Timestamp validation requires TAMGA_ENABLE_VENDOR_CRYPTONITE=ON.";
    return result;
#endif
}

TimestampValidationResult ValidateTimestampToken(
    const std::vector<std::uint8_t>& token_der,
    const std::vector<std::uint8_t>& cms_signature_value,
    const std::vector<std::vector<std::uint8_t>>& additional_certificates_der) {
    TimestampValidationResult result;
    result.failure_code = "TIMESTAMP_FORMAT_INVALID";
    if (token_der.empty()) {
        result.message = "Token DER is empty.";
        return result;
    }

#if TAMGA_CRYPTONITE_ENABLED
    ByteArray* token_ba = MakeByteArray(token_der);
    ContentInfo_t* token_cinfo = nullptr;
    SignedData_t* token_sdata = nullptr;
    TSTInfo_t* tst_info = nullptr;
    Certificate_t* tsa_cert = nullptr;

    if (token_ba == nullptr) {
        result.message = "Unable to allocate timestamp token buffer.";
        return result;
    }

    token_cinfo = cinfo_alloc();
    if (token_cinfo == nullptr) {
        ba_free(token_ba);
        result.message = "Unable to allocate timestamp token ContentInfo.";
        return result;
    }

    int rc = cinfo_decode(token_cinfo, token_ba);
    if (rc != RET_OK) {
        cinfo_free(token_cinfo);
        ba_free(token_ba);
        result.message = "Timestamp token ContentInfo decode failed.";
        return result;
    }

    rc = cinfo_get_signed_data(token_cinfo, &token_sdata);
    if (rc != RET_OK || token_sdata == nullptr) {
        cinfo_free(token_cinfo);
        ba_free(token_ba);
        result.message = "Timestamp token is not CMS SignedData.";
        return result;
    }

    rc = sdata_get_tst_info(token_sdata, &tst_info);
    if (rc != RET_OK || tst_info == nullptr) {
        sdata_free(token_sdata);
        cinfo_free(token_cinfo);
        ba_free(token_ba);
        result.message = "Timestamp token does not contain TSTInfo.";
        return result;
    }

    result.gen_time = GeneralizedTimeToString(tst_info->genTime);

    // 1. Verify message imprint (WP-6 / HI-04): обчислюємо САМЕ той алгоритм,
    // що заявлено у messageImprint.hashAlgorithm, а не приймаємо будь-який із
    // трьох digest. Це усуває маскування підміненого algorithm-identifier.
    const auto* actual_imprint = tst_info->messageImprint.hashedMessage.buf;
    const auto actual_imprint_size = tst_info->messageImprint.hashedMessage.size;

    auto imprint_equals = [&](const std::vector<std::uint8_t>& expected) {
        return actual_imprint != nullptr && actual_imprint_size > 0 &&
               expected.size() == static_cast<std::size_t>(actual_imprint_size) &&
               std::equal(expected.begin(), expected.end(), actual_imprint);
    };

    const std::string imprint_oid = OidFromAsn1(tst_info->messageImprint.hashAlgorithm.algorithm);
    const auto declared_alg = tamga::core::ImprintFromDigestOid(imprint_oid);

    bool imprint_match = false;
    bool imprint_computed = false;
    if (declared_alg) {
        std::vector<std::uint8_t> expected;
        bool computed = false;
        switch (*declared_alg) {
            case tamga::core::ImprintDigest::Kupyna256:
                computed = tamga::core::ComputeKupyna256(cms_signature_value, expected);
                break;
            case tamga::core::ImprintDigest::Gost34311:
                computed = ComputeGost34311Local(cms_signature_value, expected);
                break;
            case tamga::core::ImprintDigest::Sha256: {
                auto sha = Sha256(cms_signature_value);
                expected.assign(sha.begin(), sha.end());
                computed = true;
                break;
            }
            default:
                computed = false;  // SHA-384/512 у RFC3161-імпринті UA TSA не вживаються
                break;
        }
        // Заявлений, але незбіжний алгоритм -> imprint НЕ валідний (без fallback).
        imprint_match = computed && imprint_equals(expected);
        imprint_computed = computed;
    }
    // ME-05: раніше тут був "compatibility" fallback, що для нерозпізнаного
    // messageImprint.hashAlgorithm OID приймав збіг ІМПРИНТУ проти БУДЬ-ЯКОГО
    // з трьох відомих digest (Kupyna-256/GOST34311/SHA-256) — RFC 3161 вимагає
    // трактувати нерозпізнаний algorithm identifier як unsupported, а не
    // шукати збіг серед відомих digest (інакше токен із помилковим/чужим OID,
    // чий hashedMessage випадково чи навмисно дорівнює одному з трьох
    // digest-варіантів, приймався б як валідний). Профіль-залежна поблажка
    // (forensic-mode leniency з warning, як пропонує аудит) НЕ реалізована —
    // ValidateTimestampToken не отримує ValidationProfile на вхід (жоден з 8
    // викликачів у XadesVerifier/PadesVerifier/TimestampEngine наразі не
    // прокидає профіль на цей рівень); запровадження цього — окрема,
    // архітектурно ширша зміна, аналогічна за масштабом HI-01/HI-02.
    // imprint_match лишається false для нерозпізнаного OID — той самий
    // fail-closed принцип, що вже діє для розпізнаного, але незбіжного OID.

    if (!imprint_match) {
        result.failure_code = imprint_computed ? "TIMESTAMP_IMPRINT_MISMATCH" : "TIMESTAMP_IMPRINT_UNSUPPORTED";
        // Звільняємо ресурси і повертаємо помилку
        cert_free(tsa_cert);
        ASN_FREE(&TSTInfo_desc, tst_info);
        sdata_free(token_sdata);
        cinfo_free(token_cinfo);
        ba_free(token_ba);
        result.message = declared_alg
            ? "Timestamp token message imprint does not match CMS signature value."
            : "Timestamp token message imprint hashAlgorithm OID (" + imprint_oid + ") is not recognized.";
        return result;
    }

    // 2. Extract TSA certificate and embedded certs before freeing ASN.1 objects.
    // Для PAdES-LT/LTA сертифікат TSA часто відсутній у самому токені й лежить
    // у /DSS документа — тоді його беремо з additional_certificates_der.
    bool tsa_cert_external = false;
    int token_embedded_cert_count = 0;
    rc = LocalExtractSignerCertificate(token_sdata, &tsa_cert, additional_certificates_der,
                                       &tsa_cert_external, &token_embedded_cert_count);
    if (rc != RET_OK || tsa_cert == nullptr) {
        result.failure_code = "TSA_CERTIFICATE_MISSING";
        ASN_FREE(&TSTInfo_desc, tst_info);
        sdata_free(token_sdata);
        cinfo_free(token_cinfo);
        ba_free(token_ba);
        result.message = "TSA signer certificate resolution failed (rc = " + std::to_string(rc) +
                         ", tokenCerts = " + std::to_string(token_embedded_cert_count) +
                         ", additionalCerts = " + std::to_string(additional_certificates_der.size()) + ").";
        return result;
    }

    result.tsa_certificate_external = tsa_cert_external;
    LocalEncodeCertificateDer(tsa_cert, result.tsa_certificate_der);

    {
        CertificateSet_t* certs = nullptr;
        rc = sdata_get_certs(token_sdata, &certs);
        if (rc == RET_OK && certs != nullptr) {
            for (int index = 0; index < certs->list.count; ++index) {
                const CertificateChoices_t* choice = certs->list.array[index];
                if (choice == nullptr || choice->present != CertificateChoices_PR_certificate) {
                    continue;
                }
                std::vector<std::uint8_t> der;
                if (LocalEncodeCertificateDer(&choice->choice.certificate, der)) {
                    result.embedded_certificates_der.push_back(std::move(der));
                }
            }
            ASN_FREE(&CertificateSet_desc, certs);
        }
    }

    // 3. Verify TSA signature manually using tsa_cert and token_sdata
    result.failure_code = "TIMESTAMP_SIGNATURE_INVALID";
    bool signature_verified = false;
    std::string sig_err;

    SignerInfo_t* sinfo = nullptr;
    OidNumbers* kupyna_oid = nullptr;
    OBJECT_IDENTIFIER_t* message_digest_oid = nullptr;
    Attribute_t* message_digest_attr = nullptr;
    uint8_t* attr_buffer = nullptr;
    size_t attr_buffer_len = 0;
    OCTET_STRING_t* message_digest_octet = nullptr;
    ByteArray* message_digest_ba = nullptr;
    ByteArray* sign_ba = nullptr;
    VerifyAdapter* verify_adapter = nullptr;
    DigestAdapter* digest_adapter = nullptr;
    bool is_kupyna256 = false;

    // Check we have eContent to verify
    if (token_sdata->encapContentInfo.eContent == nullptr ||
        token_sdata->encapContentInfo.eContent->buf == nullptr ||
        token_sdata->encapContentInfo.eContent->size == 0) {
        sig_err = "TSA token is missing eContent.";
        goto sig_cleanup;
    }

    rc = sdata_get_signer_info_by_idx(token_sdata, 0, &sinfo);
    if (rc != RET_OK || sinfo == nullptr) {
        sig_err = "Failed to resolve TSA SignerInfo (rc = " + std::to_string(rc) + ").";
        goto sig_cleanup;
    }

    // Determine digest algorithm
    kupyna_oid = oids_get_oid_numbers_by_str("1.2.804.2.1.1.1.1.2.2.1");
    if (kupyna_oid != nullptr && pkix_check_oid_equal(&sinfo->digestAlgorithm.algorithm, kupyna_oid)) {
        is_kupyna256 = true;
    }

    // Compute eContent hash
    {
        std::vector<std::uint8_t> computed_digest;

        if (is_kupyna256) {
            const std::uint8_t* econtent_buf = token_sdata->encapContentInfo.eContent->buf;
            const size_t econtent_size = token_sdata->encapContentInfo.eContent->size;
            std::vector<std::uint8_t> econtent_vec(econtent_buf, econtent_buf + econtent_size);

            if (!tamga::core::ComputeKupyna256(econtent_vec, computed_digest)) {
                sig_err = "Kupyna-256 computation failed.";
                goto sig_cleanup;
            }
        } else {
            rc = digest_adapter_init_by_cert(tsa_cert, &digest_adapter);
            if (rc != RET_OK || digest_adapter == nullptr) {
                sig_err = "Failed to initialize digest adapter (rc = " + std::to_string(rc) + ").";
                goto sig_cleanup;
            }

            ByteArray* econtent_ba = nullptr;
            rc = asn_OCTSTRING2ba(token_sdata->encapContentInfo.eContent, &econtent_ba);
            if (rc != RET_OK || econtent_ba == nullptr) {
                ba_free(econtent_ba);
                sig_err = "Failed to convert eContent to ByteArray.";
                goto sig_cleanup;
            }

            ByteArray* digest_ba = nullptr;
            rc = digest_adapter->update(digest_adapter, econtent_ba);
            if (rc == RET_OK) {
                rc = digest_adapter->final(digest_adapter, &digest_ba);
            }
            ba_free(econtent_ba);

            if (rc != RET_OK || digest_ba == nullptr) {
                ba_free(digest_ba);
                sig_err = "Digest computation failed.";
                goto sig_cleanup;
            }

            computed_digest.assign(ba_get_buf(digest_ba), ba_get_buf(digest_ba) + ba_get_len(digest_ba));
            ba_free(digest_ba);
        }

        // Extract message-digest attribute
        rc = pkix_create_oid(oids_get_oid_numbers_by_id(OID_MESSAGE_DIGEST_ID), &message_digest_oid);
        if (rc != RET_OK) {
            sig_err = "Failed to create message-digest OID (rc = " + std::to_string(rc) + ").";
            goto sig_cleanup;
        }

        rc = sinfo_get_signed_attr_by_oid(sinfo, message_digest_oid, &message_digest_attr);
        if (rc != RET_OK ||
            message_digest_attr == nullptr ||
            message_digest_attr->value.list.count != 1 ||
            message_digest_attr->value.list.array == nullptr ||
            message_digest_attr->value.list.array[0] == nullptr) {
            sig_err = "TSA SignerInfo is missing message-digest attribute (rc = " + std::to_string(rc) + ").";
            goto sig_cleanup;
        }

        rc = asn_encode(&AttributeValue_desc, (void*)message_digest_attr->value.list.array[0], &attr_buffer, &attr_buffer_len);
        if (rc != RET_OK || attr_buffer == nullptr) {
            sig_err = "Failed to encode message-digest attribute (rc = " + std::to_string(rc) + ").";
            goto sig_cleanup;
        }

        message_digest_octet = reinterpret_cast<OCTET_STRING_t*>(asn_decode_with_alloc(&OCTET_STRING_desc, attr_buffer, attr_buffer_len));
        if (message_digest_octet == nullptr) {
            sig_err = "Failed to decode message-digest octet string.";
            goto sig_cleanup;
        }

        rc = asn_OCTSTRING2ba(message_digest_octet, &message_digest_ba);
        if (rc != RET_OK || message_digest_ba == nullptr) {
            sig_err = "Failed to convert message-digest octet string to ByteArray.";
            goto sig_cleanup;
        }

        if (ba_get_len(message_digest_ba) != computed_digest.size() ||
            std::memcmp(ba_get_buf(message_digest_ba), computed_digest.data(), computed_digest.size()) != 0) {
            sig_err = "TSA token message imprint does not match CMS signature value.";
            goto sig_cleanup;
        }
    }

    // Підпис потрібен окремо лише для сумісного fallback над точними байтами
    // signedAttrs; основну CMS-перевірку нижче виконує Cryptonite цілком.
    {
        OidNumbers* dstu_kupyna_sign_oid = oids_get_oid_numbers_by_str("1.2.804.2.1.1.1.1.3.6.1.1");
        if (dstu_kupyna_sign_oid != nullptr && pkix_check_oid_equal(&sinfo->signatureAlgorithm.algorithm, dstu_kupyna_sign_oid)) {
            sign_ba = ba_alloc_from_uint8(sinfo->signature.buf, sinfo->signature.size);
            if (sign_ba == nullptr) {
                rc = RET_MEMORY_ALLOC_ERROR;
            } else {
                rc = RET_OK;
            }
        } else {
            rc = sign_os_to_ba(&sinfo->signature, &sinfo->signatureAlgorithm, &sign_ba);
        }
        if (dstu_kupyna_sign_oid != nullptr) {
            oids_oid_numbers_free(dstu_kupyna_sign_oid);
        }
    }
    if (rc != RET_OK || sign_ba == nullptr) {
        sig_err = "Failed to convert signature to ByteArray (rc = " + std::to_string(rc) + ").";
        goto sig_cleanup;
    }

    rc = verify_adapter_init_by_cert(tsa_cert, &verify_adapter);
    if (rc != RET_OK || verify_adapter == nullptr) {
        sig_err = "Failed to initialize verify adapter for TSA certificate (rc = " + std::to_string(rc) + ").";
        goto sig_cleanup;
    }

    // Алгоритм гешування підпису токена задає SignerInfo.digestAlgorithm, а не
    // алгоритм, яким КНЕДП підписав сертифікат TSA. Для дослідженого токена
    // обидва значення збігаються (Купина-256), але явний вибір тут зберігає
    // нормативну поведінку для сертифікатів і токенів різних поколінь.
    if (verify_adapter->set_digest_alg != nullptr) {
        rc = verify_adapter->set_digest_alg(verify_adapter, &sinfo->digestAlgorithm);
        if (rc != RET_OK) {
            sig_err = "Failed to select TSA SignerInfo digest algorithm (rc = " +
                      std::to_string(rc) + ").";
            goto sig_cleanup;
        }
    }

    // Не перевіряємо signedAttrs вручну через verify_hash: для CMS підпис
    // формується над DER SET OF Attributes із правилами заміни контекстного
    // тегу [0], а повторне кодування ASN.1-структури не гарантує тотожних
    // байтів. Канонічний примітив Cryptonite виконує рівно CMS-перевірку,
    // яку Tamga вже застосовує до CAdES, включно з messageDigest і коректним
    // перетворенням ДСТУ-підпису.
    digest_adapter_free(digest_adapter);
    digest_adapter = nullptr;
    rc = digest_adapter_init_by_aid(&sinfo->digestAlgorithm, &digest_adapter);
    if (rc != RET_OK || digest_adapter == nullptr) {
        sig_err = "Failed to initialize TSA SignerInfo digest adapter (rc = " +
                  std::to_string(rc) + ").";
        goto sig_cleanup;
    }

    rc = sdata_verify_internal_data_by_adapter(token_sdata, digest_adapter, verify_adapter, 0);
    if (rc != RET_OK && is_kupyna256) {
        std::vector<std::uint8_t> raw_signed_attrs;
        if (ExtractRawSignedAttrs(token_der, raw_signed_attrs)) {
            // Нормативне представлення для обчислення CMS-підпису: точний
            // вміст із токена, але тег IMPLICIT [0] замінено на SET OF.
            raw_signed_attrs.front() = 0x31U;
            std::vector<std::uint8_t> raw_attrs_digest;
            if (tamga::core::ComputeKupyna256(raw_signed_attrs, raw_attrs_digest)) {
                ByteArray* raw_hash = ba_alloc_from_uint8(raw_attrs_digest.data(),
                                                          raw_attrs_digest.size());
                if (raw_hash != nullptr) {
                    rc = verify_adapter->verify_hash(verify_adapter, raw_hash, sign_ba);
                    ba_free(raw_hash);
                }
            }
        }
    }
    if (rc != RET_OK) {
        sig_err = "TSA signature verification failed (CMS verify rc = " +
                  std::to_string(rc) + ").";
        goto sig_cleanup;
    }

    signature_verified = true;

sig_cleanup:
    if (verify_adapter != nullptr) {
        verify_adapter_free(verify_adapter);
    }
    if (digest_adapter != nullptr) {
        digest_adapter_free(digest_adapter);
    }
    ba_free(sign_ba);
    ba_free(message_digest_ba);
    if (message_digest_octet != nullptr) {
        ASN_FREE(&OCTET_STRING_desc, message_digest_octet);
    }
    if (attr_buffer != nullptr) {
        free(attr_buffer);
    }
    if (message_digest_attr != nullptr) {
        ASN_FREE(&Attribute_desc, message_digest_attr);
    }
    if (message_digest_oid != nullptr) {
        ASN_FREE(&OBJECT_IDENTIFIER_desc, message_digest_oid);
    }
    if (kupyna_oid != nullptr) {
        oids_oid_numbers_free(kupyna_oid);
    }
    if (sinfo != nullptr) {
        sinfo_free(sinfo);
    }

    // Clean up original variables
    cert_free(tsa_cert);
    ASN_FREE(&TSTInfo_desc, tst_info);
    sdata_free(token_sdata);
    cinfo_free(token_cinfo);
    ba_free(token_ba);

    if (!signature_verified) {
        result.message = sig_err.empty() ? "TSA signature verification failed." : sig_err;
        return result;
    }

    result.valid = true;
    result.failure_code.clear();
    return result;
#else
    (void)cms_signature_value;
    (void)additional_certificates_der;
    result.failure_code = "TIMESTAMP_UNSUPPORTED";
    result.message = "Timestamp validation requires TAMGA_ENABLE_VENDOR_CRYPTONITE=ON.";
    return result;
#endif
}

} // namespace tamga::core::policy
