#pragma once

// Примітиви над X.509-сертифікатами всередині CMS: кодування в DER, збір
// вбудованого набору, перевірка «видано цим видавцем».
//
// Виділено з CryptoniteAdapter.cpp (O-01). Спільні для VerifyOps.cpp (побудова
// вердикту по ланцюгу), SignOps.cpp (повернення DER сертифіката підписанта) і
// CertificateInfo.cpp (розбір PKCS#7-набору).

#include "core/cryptonite/Internal.h"

#if TAMGA_CRYPTONITE_ENABLED

namespace tamga::core::cryptonite_detail {

// true, якщо підпис `certificate` перевіряється відкритим ключем `issuer`.
bool VerifyCertificateByIssuer(const Certificate_t* certificate, const Certificate_t* issuer);

// ADR-027: канонічне декодування DER -> Certificate_t. Було ЧОТИРИ копії
// (RsaVerifier, AiaIssuerFetcher, CertificateChainValidator, OcspValidator),
// які відрізнялися не поведінкою, а лише способом віддати результат:
// out-параметр за посиланням, за подвійним вказівником, RAII-повернення і
// декодування в уже виділений обʼєкт. Усі чотири однаково fail-closed на
// порожньому вході — розходження, як у С-06, тут НЕ було. Але саме тому
// їх і варто звести: наступна правка мусить мати одне місце.
//
// Дві форми замість чотирьох, бо вони справді різні:
//   * `DecodeCertificateDer` — виділяє і віддає володіння;
//   * `DecodeCertificateDerInto` — декодує у вже виділений обʼєкт виклику.
// Перша реалізована через другу, тож `cert_decode` викликається в одному
// місці на весь проєкт.
bool DecodeCertificateDerInto(const std::vector<std::uint8_t>& der, Certificate_t* certificate);

// Порожній `der` -> порожній вказівник. Порожній вхід тут завжди помилка.
ScopedCert DecodeCertificateDer(const std::vector<std::uint8_t>& der);

bool EncodeCertificateDer(const Certificate_t* certificate, std::vector<std::uint8_t>& out_der);

void CollectEmbeddedCertificatesDer(const CertificateSet_t* certs,
                                    std::vector<std::vector<std::uint8_t>>& out_ders);

bool IsCertificateSelfSigned(const Certificate_t* certificate);

// keyUsage (RFC 5280 §4.2.1.3, OID 2.5.29.15).
//
// ЄДИНЕ місце розбору цього розширення. До 2026-09-02 однаковий фрагмент
// (`cert_get_key_usage` + `asn_BITSTRING_get_bit` + `ASN_FREE`) стояв трьома
// копіями — `policy/CertificateChainValidator.cpp`, `policy/PolicyCache.cpp`,
// `policy/TrustListSync.cpp`, — і саме тому четверту (гейт підпису) сюди й
// зведено, а не дописано поруч.
//
// Спільне для всіх копій правило: ВІДСУТНЄ розширення означає «обмежень немає».
// Це не поблажливість, а RFC 5280: keyUsage не обов'язкове для сертифікатів
// кінцевого користувача, і fail-closed на його відсутності відкинув би цілком
// законні сертифікати.
//
// `key_usage_bit` — константа з `KeyUsage.h` (`KeyUsage_digitalSignature` тощо),
// а НЕ маска `KeyUsageBits` із `ext.h`: `asn_BITSTRING_get_bit` працює з
// номером біта.
bool CertificateAllowsKeyUsage(const Certificate_t* certificate, int key_usage_bit);

// Чи дозволяє сертифікат СТАВИТИ ПІДПИС: `digitalSignature` (біт 0) або
// `nonRepudiation`/`contentCommitment` (біт 1). Сертифікат ключа протоколів
// розподілу ключів (`keyAgreement`) цю перевірку не проходить.
bool CertificateAllowsSigning(const Certificate_t* certificate);

// Шукає у наборі сертифікат, яким підписано `certificate`. `visited` захищає
// від циклів у ланцюгу. nullptr, якщо видавця немає в наборі.
const Certificate_t* FindIssuerCertificate(const Certificate_t* certificate,
                                           const CertificateSet_t* certs,
                                           const std::vector<const Certificate_t*>& visited);

}  // namespace tamga::core::cryptonite_detail

#endif  // TAMGA_CRYPTONITE_ENABLED
