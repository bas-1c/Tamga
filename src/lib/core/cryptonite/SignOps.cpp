// Створення CMS/CAdES-підпису та все, що для цього треба від контейнера ключа.
//
// Виділено з CryptoniteAdapter.cpp (O-01): SignDetached / SignAttached /
// SignHash / ExtractSignerCertificate.

#include "core/cryptonite/CertUtil.h"
#include "core/cryptonite/Internal.h"
#include "core/cryptonite/Signer.h"

namespace tamga::core {

// Внутрішні помічники реалізації видимі без кваліфікації: код перенесено з
// CryptoniteAdapter.cpp без єдиної правки тіл функцій, тому директива тут
// свідома — вона обмежена цим TU і не впливає на публічний контракт.
using namespace cryptonite_detail;

namespace {
#if TAMGA_CRYPTONITE_ENABLED

bool SignCms(bool use_pkcs12,
             const std::vector<std::uint8_t>& key_material,
             const std::vector<std::uint8_t>& certificate_der,
             const std::string& password,
             const std::vector<std::uint8_t>& data,
             const bool internal_data,
             const bool include_signing_time,
             std::vector<std::uint8_t>& out,
             std::string& error_message) {
    ScopedByteArray data_ba(MakeByteArray(data), ba_free);
    if (data_ba == nullptr) {
        error_message = "Unable to allocate cryptonite ByteArray for input data";
        return false;
    }

    SignAdapter* sign_adapter_raw = nullptr;
    Certificate_t* signer_certificate_raw = nullptr;
    int rc = use_pkcs12
                 ? PreparePkcs12Signer(key_material, password, certificate_der, &sign_adapter_raw, &signer_certificate_raw)
                 : PreparePkcs8Signer(key_material, certificate_der, &sign_adapter_raw, &signer_certificate_raw);

    // Порядок ОГОЛОШЕННЯ визначає зворотний порядок звільнення. Тут він свідомо
    // повторює той, що був у ручному cleanup: sign_adapter -> digest_adapter ->
    // signer_certificate -> data_ba. Адаптери будуються з сертифіката, тож
    // переставляти їх місцями наосліп не можна.
    ScopedCert signer_certificate(signer_certificate_raw, cert_free);
    ScopedDigestAdapter digest_adapter(nullptr, digest_adapter_free);
    ScopedSignAdapter sign_adapter(sign_adapter_raw, sign_adapter_free);
    if (rc != RET_OK) {
        error_message = BuildSignerPreparationError(use_pkcs12, rc);
        return false;
    }

    {
        DigestAdapter* digest_adapter_raw = nullptr;
        rc = digest_adapter_init_by_cert(signer_certificate.get(), &digest_adapter_raw);
        digest_adapter.reset(digest_adapter_raw);
        if (rc != RET_OK) {
            // reset() звільняє часткову алокацію першої спроби: старий код просто
            // передавав той самий вказівник у init_default і губив її.
            digest_adapter.reset();
            digest_adapter_raw = nullptr;
            rc = digest_adapter_init_default(&digest_adapter_raw);
            digest_adapter.reset(digest_adapter_raw);
        }
    }
    if (rc != RET_OK) {
        error_message = BuildRcError("digest adapter initialization", rc);
        return false;
    }

    SignerInfoEngine* signer_engine_raw = nullptr;
    rc = esigner_info_alloc(sign_adapter.get(), digest_adapter.get(), digest_adapter.get(),
                            &signer_engine_raw);
    ScopedSignerInfoEngine signer_engine(signer_engine_raw, esigner_info_free);
    if (rc != RET_OK) {
        error_message = BuildRcError("signer info engine initialization", rc);
        return false;
    }

    // ETSI EN 319 142-1: у PAdES час задається PDF /M, а не CMS signingTime.
    if (include_signing_time) {
        ScopedAttribute signing_time_attr(static_cast<Attribute_t*>(calloc(1, sizeof(Attribute_t))),
                                          FreeAttribute);
        if (signing_time_attr == nullptr) {
            error_message = "Unable to allocate Attribute for signingTime";
            return false;
        }

        rc = pkix_set_oid(oids_get_oid_numbers_by_id(OID_SIGNING_TIME_ID), &signing_time_attr->type);
        if (rc != RET_OK) {
            error_message = BuildRcError("setting signingTime OID", rc);
            return false;
        }

        ScopedUtcTime utc_time(static_cast<UTCTime_t*>(calloc(1, sizeof(UTCTime_t))), FreeUtcTime);
        if (utc_time == nullptr) {
            error_message = "Unable to allocate UTCTime struct";
            return false;
        }

        time_t cur_time = std::time(nullptr);
        struct tm tm_utc;
#ifdef _WIN32
        gmtime_s(&tm_utc, &cur_time);
#else
        gmtime_r(&cur_time, &tm_utc);
#endif

        char time_str[32];
        std::strftime(time_str, sizeof(time_str), "%y%m%d%H%M%SZ", &tm_utc);

        utc_time->size = static_cast<int>(std::strlen(time_str));
        utc_time->buf = static_cast<uint8_t*>(malloc(utc_time->size + 1));
        if (utc_time->buf == nullptr) {
            error_message = "Unable to allocate UTCTime buffer";
            return false;
        }
        std::memcpy(utc_time->buf, time_str, utc_time->size);
        utc_time->buf[utc_time->size] = '\0';

        ScopedAny any_utc_time(ANY_new_fromType(&UTCTime_desc, utc_time.get()), FreeAny);
        utc_time.reset();
        if (any_utc_time == nullptr) {
            error_message = "Unable to wrap UTCTime into ANY";
            return false;
        }

        rc = ASN_SET_ADD(&signing_time_attr->value.list, any_utc_time.get());
        if (rc != RET_OK) {
            error_message = BuildRcError("adding signingTime value to Attribute", rc);
            return false;
        }
        // Володіння ANY перейшло до списку значень атрибута — знімаємо його з
        // scoped-обгортки, інакше буде double-free разом із самим атрибутом.
        (void)any_utc_time.release();

        // Атрибут КОПІЮЄТЬСЯ в рушій, тож звільняється тут у будь-якому разі.
        rc = esigner_info_add_signed_attr(signer_engine.get(), signing_time_attr.get());
        if (rc != RET_OK) {
            error_message = BuildRcError("adding signingTime signed attribute to engine", rc);
            return false;
        }
    }

    SignedDataEngine* signed_data_engine_raw = nullptr;
    rc = esigned_data_alloc(signer_engine.get(), &signed_data_engine_raw);
    ScopedSignedDataEngine signed_data_engine(signed_data_engine_raw, esigned_data_free);
    // esigned_data_alloc перебирає володіння signer_engine. Умова та сама, що була
    // в ручному cleanup: якщо signed_data_engine з'явився — звільняти треба ЙОГО,
    // а signer_engine більше не наш.
    if (signed_data_engine != nullptr) {
        (void)signer_engine.release();
    }
    if (rc != RET_OK) {
        error_message = BuildRcError("signed data engine initialization", rc);
        return false;
    }

    const OidNumbers* data_oid = oids_get_oid_numbers_by_id(OID_DATA_ID);
    if (data_oid == nullptr) {
        error_message = "Unable to resolve CMS data OID";
        return false;
    }

    rc = esigned_data_set_data(signed_data_engine.get(), data_oid, data_ba.get(), internal_data);
    if (rc != RET_OK) {
        error_message = BuildRcError("signed data payload setup", rc);
        return false;
    }

    rc = esigned_data_add_cert(signed_data_engine.get(), signer_certificate.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("signer certificate attachment", rc);
        return false;
    }

    SignedData_t* signed_data_raw = nullptr;
    rc = esigned_data_generate(signed_data_engine.get(), &signed_data_raw);
    ScopedSignedData signed_data(signed_data_raw, sdata_free);
    if (rc != RET_OK) {
        error_message = BuildRcError("signed data generation", rc);
        return false;
    }

    ScopedContentInfo content_info(cinfo_alloc(), cinfo_free);
    if (content_info == nullptr) {
        error_message = "Unable to allocate ContentInfo";
        return false;
    }

    rc = cinfo_init_by_signed_data(content_info.get(), signed_data.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("ContentInfo initialization", rc);
        return false;
    }

    ByteArray* encoded_raw = nullptr;
    rc = cinfo_encode(content_info.get(), &encoded_raw);
    ScopedByteArray encoded(encoded_raw, ba_free);
    if (rc != RET_OK || encoded == nullptr) {
        error_message = BuildRcError("ContentInfo encoding", rc == RET_OK ? RET_PKIX_GENERAL_ERROR : rc);
        return false;
    }

    AssignFromByteArray(encoded.get(), out);
    error_message.clear();
    return true;
}

#endif  // TAMGA_CRYPTONITE_ENABLED
}  // namespace

bool CryptoniteAdapter::SignDetached(bool use_pkcs12,
                                     const std::vector<std::uint8_t>& key_material,
                                     const std::vector<std::uint8_t>& certificate_der,
                                     const std::string& password,
                                     const std::vector<std::uint8_t>& data,
                                     std::vector<std::uint8_t>& signature,
                                     std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    return SignCms(use_pkcs12, key_material, certificate_der, password, data, false, true,
                   signature, error_message);
#else
    (void)use_pkcs12;
    (void)key_material;
    (void)certificate_der;
    (void)password;
    (void)data;
    (void)signature;
    error_message = BuildDisabledError();
    return false;
#endif
}

bool CryptoniteAdapter::SignPadesDetached(bool use_pkcs12,
                                         const std::vector<std::uint8_t>& key_material,
                                         const std::vector<std::uint8_t>& certificate_der,
                                         const std::string& password,
                                         const std::vector<std::uint8_t>& data,
                                         std::vector<std::uint8_t>& signature,
                                         std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    return SignCms(use_pkcs12, key_material, certificate_der, password, data, false, false,
                   signature, error_message);
#else
    (void)use_pkcs12;
    (void)key_material;
    (void)certificate_der;
    (void)password;
    (void)data;
    (void)signature;
    error_message = BuildDisabledError();
    return false;
#endif
}

bool CryptoniteAdapter::SignAttached(bool use_pkcs12,
                                     const std::vector<std::uint8_t>& key_material,
                                     const std::vector<std::uint8_t>& certificate_der,
                                     const std::string& password,
                                     const std::vector<std::uint8_t>& data,
                                     std::vector<std::uint8_t>& signed_data,
                                     std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    return SignCms(use_pkcs12, key_material, certificate_der, password, data, true, true,
                   signed_data, error_message);
#else
    (void)use_pkcs12;
    (void)key_material;
    (void)certificate_der;
    (void)password;
    (void)data;
    (void)signed_data;
    error_message = BuildDisabledError();
    return false;
#endif
}

bool CryptoniteAdapter::SignHash(bool use_pkcs12,
                                 const std::vector<std::uint8_t>& key_material,
                                 const std::vector<std::uint8_t>& certificate_der,
                                 const std::string& password,
                                 const std::vector<std::uint8_t>& hash,
                                 std::vector<std::uint8_t>& signature,
                                 std::string& error_message) {
    signature.clear();
#if TAMGA_CRYPTONITE_ENABLED
    SignAdapter* sign_adapter_raw = nullptr;
    Certificate_t* signer_certificate_raw = nullptr;
    int rc = use_pkcs12
                 ? PreparePkcs12Signer(key_material, password, certificate_der, &sign_adapter_raw, &signer_certificate_raw)
                 : PreparePkcs8Signer(key_material, certificate_der, &sign_adapter_raw, &signer_certificate_raw);
    ScopedCert signer_certificate(signer_certificate_raw, cert_free);
    ScopedSignAdapter sign_adapter(sign_adapter_raw, sign_adapter_free);
    if (rc != RET_OK || sign_adapter == nullptr) {
        error_message = BuildSignerPreparationError(use_pkcs12, rc);
        return false;
    }

    if (sign_adapter->sign_hash == nullptr) {
        error_message = "Підписант не підтримує sign_hash";
        return false;
    }

    ScopedByteArray hash_ba(MakeByteArray(hash), ba_free);
    if (hash_ba == nullptr) {
        error_message = BuildRcError("hash byte array", RET_MEMORY_ALLOC_ERROR);
        return false;
    }

    ByteArray* sign_ba_raw = nullptr;
    rc = sign_adapter->sign_hash(sign_adapter.get(), hash_ba.get(), &sign_ba_raw);
    ScopedByteArray sign_ba(sign_ba_raw, ba_free);
    if (rc != RET_OK || sign_ba == nullptr) {
        error_message = BuildRcError("sign_hash", rc);
        return false;
    }

    AssignFromByteArray(sign_ba.get(), signature);
    return !signature.empty();
#else
    (void)use_pkcs12;
    (void)key_material;
    (void)certificate_der;
    (void)password;
    (void)hash;
    error_message = BuildDisabledError();
    return false;
#endif
}

bool CryptoniteAdapter::ExtractSignerCertificate(bool use_pkcs12,
                                                 const std::vector<std::uint8_t>& key_material,
                                                 const std::vector<std::uint8_t>& certificate_der,
                                                 const std::string& password,
                                                 std::vector<std::uint8_t>& certificate_out,
                                                 std::string& error_message) {
    certificate_out.clear();
#if TAMGA_CRYPTONITE_ENABLED
    SignAdapter* sign_adapter_raw = nullptr;
    Certificate_t* signer_certificate_raw = nullptr;
    const int rc = use_pkcs12
                       ? PreparePkcs12Signer(key_material, password, certificate_der, &sign_adapter_raw, &signer_certificate_raw)
                       : PreparePkcs8Signer(key_material, certificate_der, &sign_adapter_raw, &signer_certificate_raw);
    ScopedCert signer_certificate(signer_certificate_raw, cert_free);
    ScopedSignAdapter sign_adapter(sign_adapter_raw, sign_adapter_free);
    if (rc != RET_OK || signer_certificate == nullptr) {
        error_message = BuildSignerPreparationError(use_pkcs12, rc);
        return false;
    }

    const bool ok = EncodeCertificateDer(signer_certificate.get(), certificate_out);
    if (!ok || certificate_out.empty()) {
        error_message = "Не вдалося закодувати сертифікат підписувача";
        return false;
    }
    return true;
#else
    (void)use_pkcs12;
    (void)key_material;
    (void)certificate_der;
    (void)password;
    error_message = BuildDisabledError();
    return false;
#endif
}

}  // namespace tamga::core
