#pragma once

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace tamga::core {

struct CertificateMetadata {
    std::string subject;
    std::string issuer;
    std::string common_name;
    std::string organization;
    std::string country;
    std::string tax_id;
    std::string serial_number_hex;
};

// Мультипідпис CMS: результат перевірки ОДНОГО SignerInfo.
struct CmsSignerResult {
    int index{0};  // 1-based, порядок у SignedData
    bool signature_valid{false};
    std::vector<std::uint8_t> certificate_der;
};

struct VerifyPolicyInfo {
    bool signer_certificate_present{false};
    bool certificate_time_valid{false};
    bool chain_checked{false};
    bool chain_valid{false};
    bool trust_checked{false};
    bool trust_valid{false};
    bool revocation_checked{false};
    std::string policy{"crypto-integrity-only"};
    std::string trust_status{"not-implemented"};
    std::string message;
    std::vector<std::uint8_t> signer_certificate_der;
    std::vector<std::vector<std::uint8_t>> embedded_certificates_der;
    // Скільки SignerInfo реально є в CMS, і скільки з них Tamga перевірила.
    //
    // CMS-шлях валідує ВСІ SignerInfo (повна per-signer перевірка), а
    // signature_valid є AND-агрегацією по них — так само, як HI-01 зробив для
    // XAdES. Мультипідписний контейнер (звична форма українського документообігу:
    // один `.p7s` з підписами кількох сторін — Вчасно, M.E.Doc) більше не може
    // дати загальний ACCEPTED, якщо хоча б один підпис не пройшов.
    // Ці поля лишаються у звіті як явне підтвердження покриття: у нормі
    // verified_signer_count == signer_count.
    int signer_count{0};
    int verified_signer_count{0};
    // Результат КОЖНОГО підписанта. Верхньорівневий вердикт — AND по цьому списку.
    std::vector<CmsSignerResult> signers;
};

class CryptoniteAdapter final {
public:
    static bool SignDetached(bool use_pkcs12,
                             const std::vector<std::uint8_t>& key_material,
                             const std::vector<std::uint8_t>& certificate_der,
                             const std::string& password,
                             const std::vector<std::uint8_t>& data,
                             std::vector<std::uint8_t>& signature,
                             std::string& error_message);

    // PAdES зберігає заявлений час у PDF /M і не включає CMS signingTime.
    static bool SignPadesDetached(bool use_pkcs12,
                                  const std::vector<std::uint8_t>& key_material,
                                  const std::vector<std::uint8_t>& certificate_der,
                                  const std::string& password,
                                  const std::vector<std::uint8_t>& data,
                                  std::vector<std::uint8_t>& signature,
                                  std::string& error_message);

    static bool VerifyDetached(const std::vector<std::uint8_t>& data,
                               const std::vector<std::uint8_t>& signature,
                               bool& is_valid,
                               VerifyPolicyInfo& policy_info,
                               std::string& error_message);

    static bool SignAttached(bool use_pkcs12,
                             const std::vector<std::uint8_t>& key_material,
                             const std::vector<std::uint8_t>& certificate_der,
                             const std::string& password,
                             const std::vector<std::uint8_t>& data,
                             std::vector<std::uint8_t>& signed_data,
                             std::string& error_message);

    // Raw-sign примітив (ADR 013): підписує вже обчислений геш (імпринт) і
    // повертає канонічні октети підпису (для XMLDSIG/XAdES ds:SignatureValue).
    // Геш має відповідати алгоритму ключа (для ДСТУ — ГОСТ 34.311/Купина).
    static bool SignHash(bool use_pkcs12,
                         const std::vector<std::uint8_t>& key_material,
                         const std::vector<std::uint8_t>& certificate_der,
                         const std::string& password,
                         const std::vector<std::uint8_t>& hash,
                         std::vector<std::uint8_t>& signature,
                         std::string& error_message);

    // Витягує DER сертифіката підписувача з контейнера ключа (зокрема з PKCS12,
    // де сертифікат не доступний як окремий blob). Потрібно для вбудовування
    // KeyInfo/X509Certificate у XMLDSIG/XAdES.
    static bool ExtractSignerCertificate(bool use_pkcs12,
                                         const std::vector<std::uint8_t>& key_material,
                                         const std::vector<std::uint8_t>& certificate_der,
                                         const std::string& password,
                                         std::vector<std::uint8_t>& certificate_out,
                                         std::string& error_message);

    // ТЗ Рівень 3: витягує всі сертифікати з PKCS#7-набору (`.p7b` — типова форма,
    // якою КНЕДП і ЦЗО віддають ланцюги та видані сертифікати). Це degenerate
    // SignedData без підписантів, тому розбирається тим самим cinfo/sdata-шляхом.
    // Повертає false, якщо вміст не є PKCS#7 — викликач тоді пробує DER/PEM.
    static bool ExtractCertificatesFromPkcs7(const std::vector<std::uint8_t>& pkcs7_der,
                                             std::vector<std::vector<std::uint8_t>>& certificates_out,
                                             std::string& error_message);

    // true, якщо байти є синтаксично коректним X.509-сертифікатом. Потрібно, щоб
    // виловлювати сертифікати з довільної DER-структури (відповідь CMP), не
    // покладаючись на власний ASN.1-парсер: розбір робить cryptonite.
    static bool IsCertificateDer(const std::vector<std::uint8_t>& candidate_der);

    // Перевіряє raw-підпис над гешем за відкритим ключем із сертифіката.
    // Повертає true, якщо операція виконалась (результат — у is_valid); false
    // лише за помилок підготовки (декодування сертифіката/ключа).
    static bool VerifyHash(const std::vector<std::uint8_t>& certificate_der,
                           const std::vector<std::uint8_t>& hash,
                           const std::vector<std::uint8_t>& signature,
                           bool& is_valid,
                           std::string& error_message);

    static bool VerifyAttached(const std::vector<std::uint8_t>& signed_data,
                               bool& is_valid,
                               std::vector<std::uint8_t>& content,
                               VerifyPolicyInfo& policy_info,
                               std::string& error_message);

    static bool ExtractCertificateMetadata(const std::vector<std::uint8_t>& certificate_der,
                                           CertificateMetadata& metadata,
                                           std::string& error_message);

    struct CrlCheckResult {
        bool checked{false};
        bool revoked{false};
        bool crl_valid{false};
        std::string message;
        time_t revocation_time{0};
    };

    static CrlCheckResult CheckCertificateRevocation(
        const std::vector<std::uint8_t>& certificate_der,
        const std::vector<std::uint8_t>& crl_der,
        const std::vector<std::uint8_t>& issuer_certificate_der);

    // С-01: вікно дійсності CRL [thisUpdate, nextUpdate].
    //
    // `crl_check_cert` у vendored cryptonite звіряє ЛИШЕ серійний номер — ані
    // issuer, ані дати. Тому без цієї пари прострочений CRL давав `Good` для
    // сертифіката, відкликаного вже після його випуску.
    //
    // Повертає false, якщо CRL не декодується або thisUpdate відсутній.
    // `next_update` дорівнює 0, коли поле відсутнє (RFC 5280 дозволяє його
    // опускати) — це «без заявленої межі свіжості», а не «протерміновано».
    static bool GetCrlValidityWindow(const std::vector<std::uint8_t>& crl_der,
                                     std::time_t& this_update,
                                     std::time_t& next_update);

    // Повертає nextUpdate CRL як time_t. false, якщо CRL порожній/не декодується
    // або поле nextUpdate відсутнє. Out-param обнуляється при невдачі.
    static bool GetCrlNextUpdate(const std::vector<std::uint8_t>& crl_der,
                                 std::time_t& next_update);

    static bool FindMatchingCertificate(const std::vector<std::uint8_t>& key_material,
                                        const std::vector<std::vector<std::uint8_t>>& chain,
                                        std::vector<std::uint8_t>& matching_cert);

    // Авто-резолвер сертифікатів, крок 1: витягує SubjectPublicKeyInfo (DER) із
    // приватного ключа. Працює і для PKCS#12/`.dat`-контейнерів без certBag
    // (тоді потрібен password), і для «голого» PKCS#8.
    //
    // SPKI — однозначний ідентифікатор підписанта в усіх реєстрах КНЕДП, тому це
    // база і для локального кешу (`cert-cache/<sha256(spki)>.cer`), і для
    // мережевого пошуку, і для fail-closed перевірки знайденого сертифіката.
    static bool ExtractSubjectPublicKeyInfo(const std::vector<std::uint8_t>& key_material,
                                            const std::string& password,
                                            std::vector<std::uint8_t>& spki_der,
                                            std::string& error_message);

    // Повертає SubjectPublicKeyInfo (DER) із сертифіката X.509.
    static bool ExtractCertificateSubjectPublicKeyInfo(const std::vector<std::uint8_t>& certificate_der,
                                                       std::vector<std::uint8_t>& spki_der,
                                                       std::string& error_message);

    // Fail-closed перевірка: чи справді `certificate_der` належить цьому ключу.
    // Порівнюються SPKI ключа і сертифіката — те саме математичне відношення,
    // яке потім використає підпис. Хибний/чужий сертифікат мусить бути відкинутий
    // ДО того, як його підставлять у signer.
    //
    // У PKCS#12 перевіряються УСІ ключі контейнера: «універсальні» контейнери
    // КНЕДП містять і ключ підпису, і ключ протоколів розподілу ключів, тож
    // сертифікат підписанта може відповідати не першому з них. Який саме ключ
    // збігся, вирішує далі `PreparePkcs12Signer`.
    static bool CertificateMatchesPrivateKey(const std::vector<std::uint8_t>& key_material,
                                             const std::string& password,
                                             const std::vector<std::uint8_t>& certificate_der);

    // Вбудовує TSP-токен як unsigned attribute id-aa-signatureTimeStampToken (CAdES-T)
    // у перший SignerInfo вже готового CMS ContentInfo DER.
    static bool AppendTspToken(const std::vector<std::uint8_t>& cms_in,
                               const std::vector<std::uint8_t>& tsp_token_der,
                               std::vector<std::uint8_t>& cms_out,
                               std::string& error_message);

    static bool HasSignatureTimestampToken(const std::vector<std::uint8_t>& cms_in,
                                           bool& has_token,
                                           std::string& error_message);

    static bool ExtractSignatureTimestampToken(const std::vector<std::uint8_t>& cms_in,
                                               std::vector<std::uint8_t>& tsp_token_der,
                                               std::string& error_message);

    // WP-10: витягує claimed signingTime (signed attribute) першого SignerInfo з
    // CMS SignedData як ISO8601 UTC ("YYYY-MM-DDTHH:MM:SSZ"). Повертає false,
    // якщо атрибут відсутній/непарситься (не помилка — просто немає claimed часу).
    static bool ExtractSigningTime(const std::vector<std::uint8_t>& cms_in,
                                   std::string& out_iso8601);

    // Витягує значення підпису (signature value) з першого SignerInfo у CMS ContentInfo DER.
    static bool GetSignatureValue(const std::vector<std::uint8_t>& cms_in,
                                  std::vector<std::uint8_t>& signature_value,
                                  std::string& error_message);

    // Вилучає OID digestAlgorithm першого SignerInfo з CMS SignedData.
    static bool GetSignerDigestAlgorithmOid(const std::vector<std::uint8_t>& cms_in,
                                            std::string& out_digest_oid,
                                            std::string& error_message);
};

} // namespace tamga::core
