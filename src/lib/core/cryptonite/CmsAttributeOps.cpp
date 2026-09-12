// Доступ до атрибутів CMS SignerInfo: мітка часу (CAdES-T), claimed signingTime,
// значення підпису, OID алгоритму гешування.
//
// Виділено з CryptoniteAdapter.cpp (O-01).

#include "core/cryptonite/Internal.h"
#include "core/cryptonite/Names.h"

namespace tamga::core {

// Внутрішні помічники реалізації видимі без кваліфікації: код перенесено з
// CryptoniteAdapter.cpp без єдиної правки тіл функцій, тому директива тут
// свідома — вона обмежена цим TU і не впливає на публічний контракт.
using namespace cryptonite_detail;

bool CryptoniteAdapter::AppendTspToken(const std::vector<std::uint8_t>& cms_in,
                                        const std::vector<std::uint8_t>& tsp_token_der,
                                        std::vector<std::uint8_t>& cms_out,
                                        std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    if (cms_in.empty() || tsp_token_der.empty()) {
        error_message = "AppendTspToken: empty CMS or TSP token";
        return false;
    }

    ScopedByteArray cms_ba(MakeByteArray(cms_in), ba_free);
    if (cms_ba == nullptr) {
        error_message = "AppendTspToken: unable to allocate ByteArray for CMS input";
        return false;
    }

    ScopedContentInfo cinfo(cinfo_alloc(), cinfo_free);
    if (cinfo == nullptr) {
        error_message = "AppendTspToken: unable to allocate ContentInfo";
        return false;
    }
    int rc = cinfo_decode(cinfo.get(), cms_ba.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("AppendTspToken: ContentInfo decode", rc);
        return false;
    }

    SignedData_t* sdata_raw = nullptr;
    rc = cinfo_get_signed_data(cinfo.get(), &sdata_raw);
    ScopedSignedData sdata(sdata_raw, sdata_free);
    if (rc != RET_OK || sdata == nullptr) {
        error_message = BuildRcError("AppendTspToken: cinfo_get_signed_data", rc);
        return false;
    }

    SignerInfos_t* signer_infos_raw = nullptr;
    rc = sdata_get_signer_infos(sdata.get(), &signer_infos_raw);
    ScopedSignerInfos signer_infos(signer_infos_raw, FreeSignerInfos);
    if (rc != RET_OK || signer_infos == nullptr || signer_infos->list.count < 1 ||
        signer_infos->list.array == nullptr || signer_infos->list.array[0] == nullptr) {
        error_message = BuildRcError("AppendTspToken: sdata_get_signer_infos", rc == RET_OK ? RET_PKIX_SDATA_NO_SIGNERS : rc);
        return false;
    }
    // Позичений вказівник у середину signer_infos — НЕ звільняється окремо.
    SignerInfo_t* sinfo = signer_infos->list.array[0];

    // Побудувати Attribute: тип = id-aa-signatureTimeStampToken, значення = tsp_token_der як ANY
    ScopedAttribute tsp_attr(static_cast<Attribute_t*>(calloc(1, sizeof(Attribute_t))), FreeAttribute);
    if (tsp_attr == nullptr) {
        error_message = "AppendTspToken: unable to allocate Attribute for TSP";
        return false;
    }

    rc = pkix_set_oid(oids_get_oid_numbers_by_id(OID_AA_SIGNATURE_TIME_STAMP_TOKEN_ID),
                      &tsp_attr->type);
    if (rc != RET_OK) {
        error_message = BuildRcError("AppendTspToken: setting TSP OID", rc);
        return false;
    }

    {
        // Обгортаємо DER-байти TSP-токена у ANY. Проміжний ByteArray тут не
        // потрібен: буфер ANY заповнюється копією прямо з `tsp_token_der`.
        ScopedAny any_tsp(static_cast<ANY_t*>(calloc(1, sizeof(ANY_t))), FreeAny);
        if (any_tsp == nullptr) {
            error_message = "AppendTspToken: unable to allocate ANY for TSP token";
            return false;
        }
        any_tsp->buf = static_cast<uint8_t*>(malloc(tsp_token_der.size()));
        if (any_tsp->buf == nullptr) {
            error_message = "AppendTspToken: unable to allocate ANY buffer";
            return false;
        }
        std::memcpy(any_tsp->buf, tsp_token_der.data(), tsp_token_der.size());
        any_tsp->size = static_cast<int>(tsp_token_der.size());

        rc = ASN_SET_ADD(&tsp_attr->value.list, any_tsp.get());
        if (rc != RET_OK) {
            error_message = BuildRcError("AppendTspToken: ASN_SET_ADD for TSP ANY", rc);
            return false;
        }
        // Володіння перейшло до списку значень атрибута.
        (void)any_tsp.release();
    }

    // Атрибут КОПІЮЄТЬСЯ в SignerInfo, тож tsp_attr лишається нашим.
    rc = sinfo_add_unsigned_attr(sinfo, tsp_attr.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("AppendTspToken: sinfo_add_unsigned_attr", rc);
        return false;
    }

    rc = sdata_set_signer_infos(sdata.get(), signer_infos.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("AppendTspToken: sdata_set_signer_infos", rc);
        return false;
    }

    // Перекодуємо з оновленим SignerInfo
    ScopedContentInfo cinfo_out(cinfo_alloc(), cinfo_free);
    if (cinfo_out == nullptr) {
        error_message = "AppendTspToken: unable to allocate output ContentInfo";
        return false;
    }
    rc = cinfo_init_by_signed_data(cinfo_out.get(), sdata.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("AppendTspToken: cinfo_init_by_signed_data", rc);
        return false;
    }

    ByteArray* encoded_raw = nullptr;
    rc = cinfo_encode(cinfo_out.get(), &encoded_raw);
    ScopedByteArray encoded(encoded_raw, ba_free);
    if (rc != RET_OK || encoded == nullptr) {
        error_message = BuildRcError("AppendTspToken: cinfo_encode", rc);
        return false;
    }

    AssignFromByteArray(encoded.get(), cms_out);
    {
        bool has_tsp_token = false;
        std::string check_error;
        if (!HasSignatureTimestampToken(cms_out, has_tsp_token, check_error) || !has_tsp_token) {
            error_message = "AppendTspToken: encoded CMS does not contain id-aa-signatureTimeStampToken";
            if (!check_error.empty()) {
                error_message += ": " + check_error;
            }
            return false;
        }
    }
    error_message.clear();
    return true;
#else
    (void)cms_in;
    (void)tsp_token_der;
    cms_out = cms_in;
    error_message = "Cryptonite not enabled";
    return false;
#endif
}

bool CryptoniteAdapter::HasSignatureTimestampToken(const std::vector<std::uint8_t>& cms_in,
                                                   bool& has_token,
                                                   std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    has_token = false;
    if (cms_in.empty()) {
        error_message = "HasSignatureTimestampToken: empty CMS input";
        return false;
    }

    ScopedByteArray cms_ba(MakeByteArray(cms_in), ba_free);
    if (cms_ba == nullptr) {
        error_message = "HasSignatureTimestampToken: unable to allocate ByteArray for CMS input";
        return false;
    }

    ScopedContentInfo cinfo(cinfo_alloc(), cinfo_free);
    if (cinfo == nullptr) {
        error_message = "HasSignatureTimestampToken: unable to allocate ContentInfo";
        return false;
    }
    int rc = cinfo_decode(cinfo.get(), cms_ba.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("HasSignatureTimestampToken: ContentInfo decode", rc);
        return false;
    }

    SignedData_t* sdata_raw = nullptr;
    rc = cinfo_get_signed_data(cinfo.get(), &sdata_raw);
    ScopedSignedData sdata(sdata_raw, sdata_free);
    if (rc != RET_OK || sdata == nullptr) {
        error_message = BuildRcError("HasSignatureTimestampToken: cinfo_get_signed_data", rc);
        return false;
    }

    SignerInfo_t* sinfo_raw = nullptr;
    rc = sdata_get_signer_info_by_idx(sdata.get(), 0, &sinfo_raw);
    ScopedSignerInfo sinfo(sinfo_raw, sinfo_free);
    if (rc != RET_OK || sinfo == nullptr) {
        error_message = BuildRcError("HasSignatureTimestampToken: sdata_get_signer_info_by_idx", rc);
        return false;
    }

    OBJECT_IDENTIFIER_t* tsp_oid_raw = nullptr;
    rc = pkix_create_oid(oids_get_oid_numbers_by_id(OID_AA_SIGNATURE_TIME_STAMP_TOKEN_ID), &tsp_oid_raw);
    ScopedOid tsp_oid(tsp_oid_raw, FreeOid);
    if (rc != RET_OK || tsp_oid == nullptr) {
        error_message = BuildRcError("HasSignatureTimestampToken: creating TSP OID", rc);
        return false;
    }

    Attribute_t* attr_raw = nullptr;
    rc = sinfo_get_unsigned_attr_by_oid(sinfo.get(), tsp_oid.get(), &attr_raw);
    ScopedAttribute attr(attr_raw, FreeAttribute);
    has_token = (rc == RET_OK && attr != nullptr);
    // Відсутність атрибута — НЕ помилка виклику: has_token=false і успіх.
    error_message.clear();
    return true;
#else
    (void)cms_in;
    has_token = false;
    error_message = "Cryptonite not enabled";
    return false;
#endif
}

bool CryptoniteAdapter::ExtractSignatureTimestampToken(const std::vector<std::uint8_t>& cms_in,
                                                       std::vector<std::uint8_t>& tsp_token_der,
                                                       std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    tsp_token_der.clear();
    if (cms_in.empty()) {
        error_message = "ExtractSignatureTimestampToken: empty CMS input";
        return false;
    }

    ScopedByteArray cms_ba(MakeByteArray(cms_in), ba_free);
    if (cms_ba == nullptr) {
        error_message = "ExtractSignatureTimestampToken: unable to allocate ByteArray for CMS input";
        tsp_token_der.clear();
        return false;
    }

    ScopedContentInfo cinfo(cinfo_alloc(), cinfo_free);
    if (cinfo == nullptr) {
        error_message = "ExtractSignatureTimestampToken: unable to allocate ContentInfo";
        tsp_token_der.clear();
        return false;
    }
    int rc = cinfo_decode(cinfo.get(), cms_ba.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("ExtractSignatureTimestampToken: ContentInfo decode", rc);
        tsp_token_der.clear();
        return false;
    }

    SignedData_t* sdata_raw = nullptr;
    rc = cinfo_get_signed_data(cinfo.get(), &sdata_raw);
    ScopedSignedData sdata(sdata_raw, sdata_free);
    if (rc != RET_OK || sdata == nullptr) {
        error_message = BuildRcError("ExtractSignatureTimestampToken: cinfo_get_signed_data", rc);
        tsp_token_der.clear();
        return false;
    }

    SignerInfo_t* sinfo_raw = nullptr;
    rc = sdata_get_signer_info_by_idx(sdata.get(), 0, &sinfo_raw);
    ScopedSignerInfo sinfo(sinfo_raw, sinfo_free);
    if (rc != RET_OK || sinfo == nullptr) {
        error_message = BuildRcError("ExtractSignatureTimestampToken: sdata_get_signer_info_by_idx", rc);
        tsp_token_der.clear();
        return false;
    }

    OBJECT_IDENTIFIER_t* tsp_oid_raw = nullptr;
    rc = pkix_create_oid(oids_get_oid_numbers_by_id(OID_AA_SIGNATURE_TIME_STAMP_TOKEN_ID), &tsp_oid_raw);
    ScopedOid tsp_oid(tsp_oid_raw, FreeOid);
    if (rc != RET_OK || tsp_oid == nullptr) {
        error_message = BuildRcError("ExtractSignatureTimestampToken: creating TSP OID", rc);
        tsp_token_der.clear();
        return false;
    }

    Attribute_t* attr_raw = nullptr;
    rc = sinfo_get_unsigned_attr_by_oid(sinfo.get(), tsp_oid.get(), &attr_raw);
    ScopedAttribute attr(attr_raw, FreeAttribute);
    if (rc != RET_OK || attr == nullptr || attr->value.list.count < 1 ||
        attr->value.list.array == nullptr || attr->value.list.array[0] == nullptr) {
        error_message = "ExtractSignatureTimestampToken: signature timestamp token is missing";
        tsp_token_der.clear();
        return false;
    }

    const ANY_t* value = attr->value.list.array[0];
    if (value->buf == nullptr || value->size <= 0) {
        error_message = "ExtractSignatureTimestampToken: signature timestamp token value is empty";
        tsp_token_der.clear();
        return false;
    }
    tsp_token_der.assign(value->buf, value->buf + value->size);
    error_message.clear();
    return true;
#else
    (void)cms_in;
    tsp_token_der.clear();
    error_message = "Cryptonite not enabled";
    return false;
#endif
}

bool CryptoniteAdapter::ExtractSigningTime(const std::vector<std::uint8_t>& cms_in,
                                           std::string& out_iso8601) {
    out_iso8601.clear();
#if TAMGA_CRYPTONITE_ENABLED
    if (cms_in.empty()) {
        return false;
    }

    ScopedByteArray cms_ba(MakeByteArray(cms_in), ba_free);
    if (cms_ba == nullptr) {
        return false;
    }
    ScopedContentInfo cinfo(cinfo_alloc(), cinfo_free);
    if (cinfo == nullptr) {
        return false;
    }
    if (cinfo_decode(cinfo.get(), cms_ba.get()) != RET_OK) {
        return false;
    }

    SignedData_t* sdata_raw = nullptr;
    const int sdata_rc = cinfo_get_signed_data(cinfo.get(), &sdata_raw);
    ScopedSignedData sdata(sdata_raw, sdata_free);
    if (sdata_rc != RET_OK || sdata == nullptr) {
        return false;
    }

    time_t signing_time = 0;
    if (sdata_get_signing_time(sdata.get(), 0, &signing_time) != RET_OK || signing_time <= 0) {
        return false;
    }

    struct tm tm_utc;
#ifdef _WIN32
    gmtime_s(&tm_utc, &signing_time);
#else
    gmtime_r(&signing_time, &tm_utc);
#endif
    char time_str[32];
    if (std::strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0) {
        return false;
    }
    out_iso8601 = time_str;
    return true;
#else
    (void)cms_in;
    return false;
#endif
}

bool CryptoniteAdapter::GetSignatureValue(const std::vector<std::uint8_t>& cms_in,
                                         std::vector<std::uint8_t>& signature_value,
                                         std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    if (cms_in.empty()) {
        error_message = "GetSignatureValue: empty CMS input";
        return false;
    }

    ScopedByteArray cms_ba(MakeByteArray(cms_in), ba_free);
    if (cms_ba == nullptr) {
        error_message = "GetSignatureValue: unable to allocate ByteArray for CMS input";
        return false;
    }

    ScopedContentInfo cinfo(cinfo_alloc(), cinfo_free);
    if (cinfo == nullptr) {
        error_message = "GetSignatureValue: unable to allocate ContentInfo";
        return false;
    }
    int rc = cinfo_decode(cinfo.get(), cms_ba.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("GetSignatureValue: ContentInfo decode", rc);
        return false;
    }

    // Раніше ця гілка звільняла лише cinfo: якщо cinfo_get_signed_data повертав
    // помилку, встигнувши віддати sdata, той губився. RAII знімає цей клас витоку.
    SignedData_t* sdata_raw = nullptr;
    rc = cinfo_get_signed_data(cinfo.get(), &sdata_raw);
    ScopedSignedData sdata(sdata_raw, sdata_free);
    if (rc != RET_OK || sdata == nullptr) {
        error_message = BuildRcError("GetSignatureValue: cinfo_get_signed_data", rc);
        return false;
    }

    SignerInfo_t* sinfo_raw = nullptr;
    rc = sdata_get_signer_info_by_idx(sdata.get(), 0, &sinfo_raw);
    ScopedSignerInfo sinfo(sinfo_raw, sinfo_free);
    if (rc != RET_OK || sinfo == nullptr) {
        error_message = BuildRcError("GetSignatureValue: sdata_get_signer_info_by_idx", rc);
        return false;
    }

    if (sinfo->signature.buf == nullptr || sinfo->signature.size <= 0) {
        error_message = "GetSignatureValue: signature field is empty";
        return false;
    }
    signature_value.assign(sinfo->signature.buf, sinfo->signature.buf + sinfo->signature.size);
    // Раніше тут був `return error_message.empty()` без очищення: успішний виклик
    // повертав false, якщо викликач передав рядок із попереднім повідомленням — а
    // саме так його і використовує PadesVerifier (один `e` на ланцюжок викликів).
    // Тепер контракт такий самий, як у решти методів: успіх очищає повідомлення.
    error_message.clear();
    return true;
#else
    (void)cms_in;
    (void)signature_value;
    error_message = "Cryptonite not enabled";
    return false;
#endif
}

bool CryptoniteAdapter::GetSignerDigestAlgorithmOid(const std::vector<std::uint8_t>& cms_in,
                                                    std::string& out_digest_oid,
                                                    std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    if (cms_in.empty()) {
        error_message = "GetSignerDigestAlgorithmOid: empty CMS input";
        return false;
    }

    ScopedByteArray cms_ba(MakeByteArray(cms_in), ba_free);
    if (cms_ba == nullptr) {
        error_message = "GetSignerDigestAlgorithmOid: unable to allocate ByteArray for CMS input";
        return false;
    }

    ScopedContentInfo cinfo(cinfo_alloc(), cinfo_free);
    if (cinfo == nullptr) {
        error_message = "GetSignerDigestAlgorithmOid: unable to allocate ContentInfo";
        return false;
    }
    int rc = cinfo_decode(cinfo.get(), cms_ba.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("GetSignerDigestAlgorithmOid: ContentInfo decode", rc);
        return false;
    }

    // Той самий клас витоку, що і в GetSignatureValue: sdata губився, якщо
    // cinfo_get_signed_data повертав помилку, встигнувши його віддати.
    SignedData_t* sdata_raw = nullptr;
    rc = cinfo_get_signed_data(cinfo.get(), &sdata_raw);
    ScopedSignedData sdata(sdata_raw, sdata_free);
    if (rc != RET_OK || sdata == nullptr) {
        error_message = BuildRcError("GetSignerDigestAlgorithmOid: cinfo_get_signed_data", rc);
        return false;
    }

    SignerInfo_t* sinfo_raw = nullptr;
    rc = sdata_get_signer_info_by_idx(sdata.get(), 0, &sinfo_raw);
    ScopedSignerInfo sinfo(sinfo_raw, sinfo_free);
    if (rc != RET_OK || sinfo == nullptr) {
        error_message = BuildRcError("GetSignerDigestAlgorithmOid: sdata_get_signer_info_by_idx", rc);
        return false;
    }

    out_digest_oid = OidFromAsn1(sinfo->digestAlgorithm.algorithm);
    if (out_digest_oid.empty()) {
        error_message = "GetSignerDigestAlgorithmOid: sinfo digestAlgorithm OID is empty";
        return false;
    }
    // Як і в GetSignatureValue: успіх очищає повідомлення, а не покладається на те,
    // що викликач передав порожній рядок.
    error_message.clear();
    return true;
#else
    (void)cms_in;
    (void)out_digest_oid;
    error_message = "Cryptonite not enabled";
    return false;
#endif
}

}  // namespace tamga::core
