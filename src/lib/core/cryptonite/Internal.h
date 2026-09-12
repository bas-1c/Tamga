#pragma once

// Спільний внутрішній «фундамент» для реалізації CryptoniteAdapter.
//
// O-01: CryptoniteAdapter.cpp розрісся до 2352 рядків і змішував у собі підпис,
// перевірку, розбір сертифікатів, CRL і CMS-атрибути. Реалізацію розділено на
// кілька TU у цьому каталозі; публічний контракт (`core/CryptoniteAdapter.h`)
// НЕ змінився — жоден зовнішній модуль не потребує правок.
//
// Тут лежить лише те, що потрібно БІЛЬШ НІЖ ОДНОМУ модулю реалізації:
// підключення vendored cryptonite, RAII-обгортки над його C-типами, побудова
// повідомлень про помилки та конвертація ByteArray <-> std::vector.
//
// Заголовок внутрішній: він НЕ встановлюється і не входить у публічний SDK.

#include "core/CryptoniteAdapter.h"
#include "util/Hex.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "AttributeTypeAndValue.h"
#include "CertificateSet.h"
#include "OBJECT_IDENTIFIER.h"
#include "SignerIdentifier.h"
#include "TBSCertificate.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "content_info.h"
#include "crl.h"
#include "cryptonite_errors.h"
#include "cryptonite_manager.h"
#include "ext.h"
#include "oids.h"
#include "pkcs12.h"
#include "pkcs8.h"
#include "pkix_errors.h"
#include "pkix_utils.h"
#include "signed_data.h"
#include "signed_data_engine.h"
#include "signer_info.h"
#include "signer_info_engine.h"
#include "Attribute.h"
#include "UTCTime.h"
#include "ANY.h"
#include "PKIXTime.h"
#include "RevokedCertificate.h"
#include "TBSCertList.h"
}
#endif

namespace tamga::core::cryptonite_detail {

// ADR-027: HexEncode більше не визначається тут — одна реалізація в
// `util/Hex`. Коротке ім'я лишається, бо на нього спираються модулі
// cryptonite (CertificateInfo, CmsAttributeOps тощо).
using tamga::util::HexEncode;

inline void ResetPolicyInfo(VerifyPolicyInfo& policy_info) {
    policy_info = {};
}

#if !TAMGA_CRYPTONITE_ENABLED
inline std::string BuildDisabledError() {
    return "Vendored cryptonite support is disabled at build time";
}
#endif

#if TAMGA_CRYPTONITE_ENABLED

// Integrity-failure rc codes returned by cryptonite's CMS verify family when the
// signature simply does not match the data / signer certificate. The Session layer
// surfaces these as a clean is_valid=false result, whereas anything else is reported
// as an execution error with a descriptive message.
//
// Keep in sync with:
//   vendor/cryptonite/src/pkix/c/api/pkix_errors.h — RET_PKIX_VERIFY_FAILED, RET_PKIX_SDATA_*
//   vendor/cryptonite/src/asn1/c/api/asn1_errors.h — RET_VERIFY_FAILED
// New upstream codes default to the "execution error" branch (safe default), and can
// be promoted into integrity failures by adding them to this single set.
inline const std::unordered_set<int>& IntegrityFailureRcCodes() {
    static const std::unordered_set<int> kSet = {
        RET_VERIFY_FAILED,
        RET_PKIX_VERIFY_FAILED,
        RET_PKIX_SDATA_WRONG_CONTENT_DATA,
        RET_PKIX_SDATA_WRONG_EXT_DATA,
        RET_PKIX_SDATA_VERIFY_CERT_V2_FAILED,
    };
    return kSet;
}

inline bool IsIntegrityFailureRc(const int code) {
    const auto& set = IntegrityFailureRcCodes();
    return set.find(code) != set.end();
}

inline std::string BuildRcError(const char* stage, const int rc) {
    std::ostringstream stream;
    stream << stage << " failed (cryptonite rc=" << rc << ")";
    return stream.str();
}

// ADR-027: два ЯВНО названі контракти замість чотирьох копій із мовчазно
// різною поведінкою. Копії в `policy/AiaIssuerFetcher`, `policy/OcspValidator`
// і `policy/TimestampValidator` розходилися саме на порожньому вході: дві
// повертали nullptr, дві — валідний порожній ByteArray. Через це той самий
// порожній вхід в одному модулі відхилявся одразу, а в іншому потрапляв
// у крипто-шар. Обирати «переможця» тут не можна — обидві поведінки
// комусь потрібні, тому вони просто мають різні імена.

// Порожній вхід -> валідний ByteArray нульової довжини.
inline ByteArray* MakeByteArray(const std::vector<std::uint8_t>& data) {
    if (data.empty()) {
        return ba_alloc_by_len(0);
    }
    return ba_alloc_from_uint8(data.data(), data.size());
}

// Порожній вхід -> nullptr. Для місць, де порожні дані є помилкою і мають
// бути відхилені ДО того, як дійдуть до розбору (напр. порожнє тіло
// OCSP-відповіді).
inline ByteArray* MakeByteArrayOrNull(const std::vector<std::uint8_t>& data) {
    if (data.empty()) {
        return nullptr;
    }
    return ba_alloc_from_uint8(data.data(), data.size());
}

inline void AssignFromByteArray(const ByteArray* data, std::vector<std::uint8_t>& out) {
    out.assign(ba_get_buf(data), ba_get_buf(data) + ba_get_len(data));
}


template <typename T, void (*FreeFn)(T*)>
using ScopedPtr = std::unique_ptr<T, decltype(FreeFn)>;

using ScopedByteArray = ScopedPtr<ByteArray, ba_free>;
using ScopedPkcs12Ctx = ScopedPtr<Pkcs12Ctx, pkcs12_free>;
using ScopedCert = ScopedPtr<Certificate_t, cert_free>;
using ScopedPkcs8 = ScopedPtr<PrivateKeyInfo_t, pkcs8_free>;
using ScopedSignAdapter = ScopedPtr<SignAdapter, sign_adapter_free>;
using ScopedCrl = ScopedPtr<CertificateList_t, crl_free>;
using ScopedContentInfo = ScopedPtr<ContentInfo_t, cinfo_free>;
using ScopedSignedData = ScopedPtr<SignedData_t, sdata_free>;
using ScopedSignerInfo = ScopedPtr<SignerInfo_t, sinfo_free>;
using ScopedDigestAdapter = ScopedPtr<DigestAdapter, digest_adapter_free>;
using ScopedVerifyAdapter = ScopedPtr<VerifyAdapter, verify_adapter_free>;
using ScopedSignerInfoEngine = ScopedPtr<SignerInfoEngine, esigner_info_free>;
using ScopedSignedDataEngine = ScopedPtr<SignedDataEngine, esigned_data_free>;

// Типи, згенеровані asn1c, звільняються макросом ASN_FREE із дескриптором типу,
// а не окремою функцією. Обгортки нижче дають цим типам той самий вигляд, що й
// решті: одна вільна функція `void(T*)`, придатна для ScopedPtr.
//
// Додаткова властивість, важлива саме тут: unique_ptr НЕ викликає deleter для
// nullptr, тож ручні перевірки `if (ptr) { ASN_FREE(...); }` (які в старому
// коді стояли нерівномірно — десь були, десь ні) стають непотрібними.
inline void FreeCertificateSet(CertificateSet_t* certs) {
    ASN_FREE(get_CertificateSet_desc(), certs);
}

inline void FreeSignerInfos(SignerInfos_t* signer_infos) {
    ASN_FREE(&SignerInfos_desc, signer_infos);
}

inline void FreeSignerIdentifier(SignerIdentifier_t* signer_id) {
    ASN_FREE(&SignerIdentifier_desc, signer_id);
}

inline void FreeAttribute(Attribute_t* attribute) {
    ASN_FREE(&Attribute_desc, attribute);
}

inline void FreeOid(OBJECT_IDENTIFIER_t* oid) {
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
}

inline void FreeSpki(SubjectPublicKeyInfo_t* spki) {
    ASN_FREE(&SubjectPublicKeyInfo_desc, spki);
}

inline void FreeUtcTime(UTCTime_t* utc_time) {
    ASN_FREE(&UTCTime_desc, utc_time);
}

inline void FreeAny(ANY_t* any) {
    ASN_FREE(&ANY_desc, any);
}

inline void FreeRevokedCertificate(RevokedCertificate_t* revoked) {
    ASN_FREE(get_RevokedCertificate_desc(), revoked);
}

inline void FreeTbsCertList(TBSCertList_t* tbs) {
    ASN_FREE(get_TBSCertList_desc(), tbs);
}

using ScopedCertificateSet = ScopedPtr<CertificateSet_t, FreeCertificateSet>;
using ScopedSignerInfos = ScopedPtr<SignerInfos_t, FreeSignerInfos>;
using ScopedSignerIdentifier = ScopedPtr<SignerIdentifier_t, FreeSignerIdentifier>;
using ScopedAttribute = ScopedPtr<Attribute_t, FreeAttribute>;
using ScopedOid = ScopedPtr<OBJECT_IDENTIFIER_t, FreeOid>;
using ScopedSpki = ScopedPtr<SubjectPublicKeyInfo_t, FreeSpki>;
using ScopedUtcTime = ScopedPtr<UTCTime_t, FreeUtcTime>;
using ScopedAny = ScopedPtr<ANY_t, FreeAny>;
using ScopedRevokedCertificate = ScopedPtr<RevokedCertificate_t, FreeRevokedCertificate>;
using ScopedTbsCertList = ScopedPtr<TBSCertList_t, FreeTbsCertList>;

#endif  // TAMGA_CRYPTONITE_ENABLED

}  // namespace tamga::core::cryptonite_detail
