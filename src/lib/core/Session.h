#pragma once

#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "core/CryptoniteAdapter.h"
#include "util/Json.h"
#include "core/Errors.h"
#include "core/policy/TrustListSettings.h"
#include "core/policy/TrustListSync.h"
#include "core/session/VerifyReportOwnership.h"

namespace tamga::core {

enum class TimestampMode { BestEffort = 0, Disabled, Required };

struct Settings {
    bool offline_mode{true};
    std::string work_dir;
    std::string trust_mode{"strict"};
    std::string validation_level{"standard"};
    // AIA URL надходить із недовіреного сертифіката, тому мережеве
    // дозавантаження issuer-ів потребує окремого явного opt-in.
    bool allow_aia_issuer_fetch{false};
};

struct FileStoreSettings { std::string base_path; bool allow_overwrite{true}; };
struct OcspSettings { std::string url; bool use_nonce{true}; std::int32_t timeout_ms{10000}; };
struct TspSettings {
    std::string url;
    std::string policy_oid;
    std::int32_t timeout_ms{10000};
    std::string imprint_digest_oid;
};
struct LdapSettings { std::string url; std::string base_dn; std::int32_t timeout_ms{10000}; };
struct CmpSettings { std::string url; std::string profile; std::int32_t timeout_ms{10000}; };

// WP-12 (Session-звіт): Session-рівневий відповідник tamga::xades::DataObjectFormat
// (SignedDataObjectProperties/DataObjectFormat, ETSI EN 319 132-1 §5.2.2) —
// Session.h навмисно не залежить від xades/XadesTypes.h (не всі збірки мають
// TAMGA_ENABLE_XML_SIGNATURES), тому це окрема, структурно ідентична копія,
// заповнювана в Session*Ops.ipp, а не прямий reuse XAdES-типу.
struct DataObjectFormatEntry {
    std::string object_reference;
    std::string mime_type;
    std::string description;
};

// Канонічний результат однієї мітки; докази TSA не змішуються з відкликанням підписувача.
struct TimestampEntry {
    int signature_index{0};
    std::string kind{"signature"};
    std::uint64_t signed_revision_end{0};
    std::string status{"timestamp-not-validated"};
    bool valid{false};
    bool policy_acceptable{false};
    bool crypto_valid{false};
    bool gen_time_valid{false};
    bool certificate_time_valid{false};
    bool eku_valid{false};
    bool trust_valid{false};
    bool revocation_checked{false};
    bool historical_trust_used{false};
    bool ocsp_attempted{false};
    bool crl_attempted{false};
    std::string gen_time;
    std::string validation_time;
    std::string reason_code;
    std::string trust_source;
    std::string tsa_subject;
    std::string tsa_issuer;
    std::string tsa_serial;
    std::string tsa_fingerprint_sha256;
    std::string revocation_status{"not-checked"};
    std::vector<std::string> because;
    std::vector<std::string> warnings;
    std::vector<std::string> limitations;
    std::vector<std::string> evidence_ids;
};

// WP-2 (Session-інтеграція): один запис per-signature звіту для документів/
// контейнерів із кількома ds:Signature (XadesVerifier::VerifyAll). Несе
// крипто-/структурний стан кожного підпису (signature_valid, профіль,
// timestamp) І (HI-01) повну незалежну trust/revocation/certificate.timeValid
// перевірку САМЕ цього підписанта (окремий X.509 chain + OCSP/CRL на
// кожного співпідписанта, а не лише на один репрезентативний, як було до
// HI-01). Верхньорівневі агреговані VerifyReport::trust_valid/revocation_status
// тощо — тепер AND-агрегація (`all_valid` policy, рішення користувача) по
// ВСІХ signatures[], а не копія одного репрезентативного.
struct SignatureEntry {
    int index{0};  // 1-based, порядок документа/контейнера
    bool signature_valid{false};
    bool signer_certificate_present{false};
    // ME-01: структурна наявність XAdES SignedProperties/QualifyingProperties
    // — НЕ те саме, що signer_certificate_present (наявність KeyInfo/
    // X509Certificate). Підпис може мати SignedProperties без вбудованого
    // сертифіката (і навпаки) — trust-валідація можлива лише за наявності
    // сертифіката, тож signer_certificate_present МАЄ відображати саме його.
    // Для не-XAdES операцій (CMS/CAdES) лишається false — не застосовується.
    bool qualifying_properties_present{false};
    // S-003: чи збігається SigningCertificate/CertDigest з фактичним
    // KeyInfo/X509Certificate (обов'язкова перевірка за ETSI EN 319 132-1
    // §5.2.2). false також впливає на signature_valid (fail-closed).
    bool signing_certificate_digest_valid{false};
    std::string format_profile;
    bool timestamp_checked{false};
    bool timestamp_valid{false};
    std::string timestamp_status{"timestamp-not-validated"};
    std::vector<TimestampEntry> timestamp_details;
    bool ltv_valid{false};
    // HI-02: структурна наявність XAdES-доказів (CertificateValues/
    // RevocationValues), ПРИВ'ЯЗАНИХ до сертифіката САМЕ цього підпису
    // (digest-binding CompleteCertificateRefs/CompleteRevocationRefs, або сама
    // наявність values для baseline B-LT без Complete*Refs). НЕ включає
    // підтвердження trust-ланцюга/відкликання саме по собі — те тепер несе
    // ltv_evidence_validated нижче (HI-01 додав per-signer trust/revocation,
    // що зробило це поле обчислюваним).
    bool ltv_evidence_bound{false};
    // HI-01: докази прив'язані (ltv_evidence_bound) І trust-ланцюг САМЕ
    // цього підписанта довірений (trust_valid нижче) І його відкликання
    // ПІДТВЕРДЖЕНО (revocation_status=="valid"/"good") — per-signer
    // еквівалент VerifyReport::ltv_evidence_validated (HI-02), який раніше
    // не міг бути обчислений для НЕ-репрезентативних підписантів, бо
    // trust/revocation рахувались лише для одного репрезентативного.
    bool ltv_evidence_validated{false};
    // HI-01: повна незалежна trust/revocation/certificate.timeValid-перевірка
    // САМЕ цього підписанта (окремий X.509 chain + OCSP/CRL на кожного, а не
    // лише на репрезентативного, як раніше) — див. VerifyReport для семантики
    // кожного поля; тут — той самий набір, але per-signer.
    bool certificate_time_valid{false};
    std::string validation_time_source{"unknown"};
    bool chain_checked{false};
    bool chain_valid{false};
    std::string chain_debug;
    bool trust_checked{false};
    bool trust_valid{false};
    std::string trust_status{"not-implemented"};
    std::string trust_mode{"strict"};
    std::string trust_reason{"not-evaluated"};
    bool historical_trust_used{false};
    std::string historical_anchor_subject;
    std::string historical_anchor_serial;
    bool revocation_checked{false};
    bool ocsp_checked{false};
    std::string revocation_status{"not-checked"};
    // Gemini review (PR #37): без цих полів агрегація в
    // ApplyPerSignerTrustAggregation могла дати report.trust_valid=false
    // (через untrusted co-signer), лишаючи report.error_code=None і
    // report.message порожнім — неузгоджений звіт (trust_valid каже
    // "проблема", errorCode каже "жодної проблеми"). Ці поля несуть
    // error_code/message САМЕ цього підписанта з ApplyPerSignerTrustValidation.
    ErrorCode error_code{ErrorCode::None};
    std::string message;
    // WP-12: SignaturePolicyIdentifier/SignedDataObjectProperties (ETSI EN 319
    // 132-1 §5.2.1.3/§5.2.2) — структурний парсинг, БЕЗ криптографічної
    // перевірки signature_policy_hash проти реального зовнішнього документа
    // політики (Tamga не має доступу до реєстру політик конкретної CA).
    bool signature_policy_present{false};
    std::string signature_policy_id;
    std::string signature_policy_hash_algo_uri;
    std::vector<DataObjectFormatEntry> data_object_formats;
};

struct VerifyReport {
    bool has_result{false};
    bool execution_succeeded{false};
    bool signature_valid{false};
    bool trust_valid{false};
    bool trust_checked{false};
    bool revocation_checked{false};
    bool ocsp_checked{false};
    // ME-02: структурна наявність XAdES RevocationValues (LTV-доказів
    // відкликання) у підписі — НЕ те саме, що revocation_checked/ocsp_checked
    // (факт, що RevocationEngine ДІЙСНО обробив і підтвердив ці докази).
    // Підпис може мати RevocationValues, які canonical pipeline не зміг
    // прив'язати/розпізнати — раніше це помилково давало ocspChecked=true
    // лише за структурною наявністю (див. bugfix-log). Для не-XAdES операцій
    // лишається false.
    bool revocation_evidence_present{false};
    bool tsp_checked{false};
    bool timestamp_checked{false};
    bool timestamp_valid{false};
    std::string timestamp_status{"timestamp-not-validated"};
    std::vector<TimestampEntry> timestamp_details;
    bool signer_certificate_present{false};
    // ME-01: див. коментар при SignatureEntry::qualifying_properties_present
    // — репрезентативного підпису відповідник того самого diagnostics flag.
    bool qualifying_properties_present{false};
    bool certificate_time_valid{false};
    // WP-3 (canonical certificateTimeValid, CR-02): яке значення часу
    // фактично використано для перевірки notBefore/notAfter сертифіката
    // підписанта — "trustedTimestamp" (доведений RFC3161), "signingTime"
    // (заявлений/недоведений час підпису), "currentTime" (fallback на момент
    // виклику) або "unknown" (сертифікат відсутній). Виставляється разом із
    // `certificate_time_valid` у тому самому місці, де відбувається реальна
    // X.509-перевірка — жодних окремих евристик на рівні report-builder'ів.
    std::string validation_time_source{"unknown"};
    bool chain_checked{false};
    bool chain_valid{false};
    bool trust_list_checked{false};
    // Мультипідпис CMS: скільки SignerInfo у контейнері і скільки перевірено.
    // signer_count > verified_signer_count означає, що вердикт стосується НЕ всіх
    // підписантів — цей розрив мусить бути видимим у звіті.
    int cms_signer_count{0};
    int cms_verified_signer_count{0};
    bool trust_list_update_succeeded{false};
    std::string operation;
    std::string policy{"crypto-integrity-only"};
    std::string container_type{"unknown"};
    std::string signature_format{"CMS"};
    std::string format_profile;
    // WP-5 (ME-04): `format_profile` — структурний хінт (наявність
    // CertificateValues/RevocationValues/SignatureTimeStamp). `validated_profile`
    // виставляється ЛИШЕ коли XAdES-докази прив'язані (ltv_evidence_bound) І
    // ланцюг довіри побудовано саме з цих доказів (trust_valid) І відкликання
    // підтверджено (revocation_status == "valid"). Порожній рядок -> ще не
    // підтверджено (може бути structural-only false positive).
    std::string validated_profile;
    bool ltv_valid{false};
    // HI-02: `ltv_valid` (вище) зберігає ІСНУЮЧУ структурну семантику БЕЗ
    // зміни поведінки (сертифікат/timestamp валідні + CertificateValues/
    // RevocationValues присутні) — інтегратори, що вже читають `ltvValid` як
    // "докази присутні", не отримують breaking change. Два нові поля дають
    // деталізацію, якої бракувало (дослідницький звіт користувача):
    //   ltv_evidence_bound     — докази СТРУКТУРНО прив'язані до підпису
    //                             (те саме, що вирішує validated_profile вище).
    //   ltv_evidence_validated — докази прив'язані І trust-ланцюг ДІЙСНО
    //                             довірений (trust_valid) І відкликання
    //                             ПІДТВЕРДЖЕНО (revocation_status=="valid") —
    //                             те, що мало б означати "LTV valid" у
    //                             юридично значущому сенсі. Обчислюється так
    //                             само, як і validated_profile (той самий
    //                             xades_evidence_confirmed вираз), НЕ залежить
    //                             від ще не реалізованої TSA-chain довіри.
    bool ltv_evidence_bound{false};
    bool ltv_evidence_validated{false};
    // WP-12: SignaturePolicyIdentifier/SignedDataObjectProperties для
    // репрезентативного підпису — той самий принцип, що й timestamp/ltv поля
    // вище (per-signature деталі — у SignatureEntry в signatures[] нижче).
    bool signature_policy_present{false};
    std::string signature_policy_id;
    std::string signature_policy_hash_algo_uri;
    std::vector<DataObjectFormatEntry> data_object_formats;
    // WP-7: чи всі data-obj контейнера покрито підписом (ASiC-E coverage, M3).
    bool container_coverage_complete{true};
    // К-01: ЧОМУ покриття неповне — булевого поля для цього замало.
    // "not-applicable" для форматів без поняття контейнера/ревізій (CMS);
    // ASiC-E: "complete" | "container-object-not-signed";
    // PAdES: "complete" | "extended-by-unsigned-revisions" |
    //        "modified-after-signing" | "unsigned-data-appended" |
    //        "coverage-unverifiable".
    std::string coverage_status{"not-applicable"};
    // ADR-029: контейнер СТРУКТУРНО непридатний до обробки — маніфест
    // посилається на відсутній обʼєкт, імена записів неоднозначні тощо.
    //
    // Це третій стан, окремий від двох наявних, і саме тому він потрібен.
    // «Підпис не зійшовся» (`signature_valid=false`) неправда: до криптографії
    // не дійшло. «Перевірку не вдалося завершити» (`execution_succeeded=false`)
    // теж неправда, і гірша: вона звучить як збій інфраструктури, після якого
    // інтегратор пише повтор спроби — а поламаний контейнер від повтору
    // кращим не стане.
    //
    // `signature_valid` при цьому лишається `false` (fail-closed): жодного
    // підпису ми не підтвердили. Причину несе `summary.code`.
    bool container_malformed{false};
    // WP-2 (Session-інтеграція): по одному запису на кожен ds:Signature в
    // документі/контейнері (кілька META-INF/signatures*.xml теж
    // розгортаються в один плаский список). Порожній для операцій без
    // XAdES-мультипідпису (SignData/VerifyFile тощо).
    std::vector<SignatureEntry> signatures;
    std::string trust_status{"not-implemented"};
    std::string trust_mode{"strict"};
    std::string trust_reason{"not-evaluated"};
    bool historical_trust_used{false};
    std::string historical_anchor_subject;
    std::string historical_anchor_serial;
    std::string revocation_status{"not-checked"};
    std::string trust_list_source{"https://czo.gov.ua/download/tl/TL-UA-EC.xml"};
    std::string trust_list_cache_status{"not-checked"};
    std::string trust_list_last_sync;
    ErrorCode error_code{ErrorCode::None};
    std::string message;
    std::string chain_debug;
};

// WP-17 (ME-06): окремий, від VerifyReport незалежний, стан останнього
// SyncTrustList(). Раніше SyncTrustList писав напряму у VerifyReport::
// trust_list_* — ті самі поля, які Verify*-операції заповнюють через
// ValidationReportProjection під час X.509 chain validation. Через це виклик
// SyncTrustList() між двома Verify*-викликами міг мовчки підмінити діагностику
// trust-list, встановлену останнім Verify*, а наступний Verify* (який
// створює свіжий VerifyReport) так само стирав щойно записаний
// SyncTrustList()-результат. Тепер SyncTrustList() пише лише сюди;
// VerifyReport::trust_list_* лишається виключно проекцією chain validation
// ОДНОГО конкретного verify-виклику.
struct TrustListSyncReport {
    bool checked{false};
    bool update_succeeded{false};
    std::string source{"https://czo.gov.ua/download/tl/TL-UA-EC.xml"};
    std::string cache_status{"not-checked"};
    std::string last_sync;
    // B-3: whether the ds:Signature of the downloaded TL XML was actually verified,
    // and with what strength. See policy::TrustListSyncResult::xml_signature_status.
    // "not-verified-*" means the trust anchor rests on TLS alone.
    // С-22: до першого SyncTrustList() перевірка просто НЕ виконувалась —
    // а "not-verified-disabled" стверджує, що її вимкнено політикою. При
    // типовій політиці PreferAvailable це прямо вводило в оману.
    std::string xml_signature_status{"not-checked"};
};

// ADR-027: копія прибрана — одна реалізація в `util/Json`.
using tamga::util::BoolJson;

class Session {
public:
    // А-04: конструктор наповнює кеш звіту користувача тим самим будівником,
    // що й усі подальші операції. Доти дефолт був літералом у цьому заголовку
    // і застарів на цілу версію схеми.
    Session();

    bool Initialize();
    bool Finalize();
    bool SetSettings(const Settings& settings);
    bool SetFileStoreSettings(const FileStoreSettings& settings);
    bool SetOcspSettings(const OcspSettings& settings);
    bool SetTspSettings(const TspSettings& settings);
    bool SetLdapSettings(const LdapSettings& settings);
    bool SetCmpSettings(const CmpSettings& settings);
    bool SetTrustListSettings(const TrustListSettings& settings);
    bool SyncTrustList();

    bool DescribeSupportedMedia(std::string& out_json) const;
    bool ReadPrivateKey(const std::string& media_descriptor_json, std::string password);
    bool ReadPrivateKeyBinary(const std::vector<std::uint8_t>& key_data, std::string store_password, std::string key_password = {}, std::string jks_alias = {});
    bool ReadPrivateKeyFile(const std::string& path, std::string store_password, std::string key_password = {}, std::string jks_alias = {});
    bool ResetPrivateKey();

    bool Base64Encode(const std::vector<std::uint8_t>& input, std::string& out) const;
    bool Base64Decode(const std::string& input, std::vector<std::uint8_t>& out) const;
    // ME-08: validation_time_iso опційний (ISO 8601, напр. "2026-06-15T12:00:00Z").
    // Порожній -- поводиться як раніше. Непорожній, але нерозпізнаний -> false
    // + InvalidArgument. Див. коментар у SessionCertificateOps.ipp.
    bool GetCertificateInfo(const std::vector<std::uint8_t>& cert_data, std::string& out_json,
                           const std::string& validation_time_iso = "");
    bool CheckCertificateRevocation(const std::vector<std::uint8_t>& cert_data, const std::vector<std::uint8_t>& crl_data, const std::vector<std::uint8_t>& issuer_cert_data, std::string& out_json);
    void RecordVerifyFailure(std::string operation, ErrorCode error_code, std::string message);
    bool GetLastVerifyReport(std::string& out_json) const;
    bool GetUserReport(std::string& out_json) const;

    bool SignData(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& signature);
    bool SignData(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& signature, TimestampMode timestamp_mode);
    bool VerifyData(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& signature, bool& is_valid);
    bool SignDataBase64(const std::vector<std::uint8_t>& data, std::string& signature_base64);
    bool VerifyDataBase64(const std::vector<std::uint8_t>& data, const std::string& signature_base64, bool& is_valid);

    bool SignDataInternal(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& signed_data);
    bool SignDataInternal(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& signed_data, TimestampMode timestamp_mode);
    bool VerifyDataInternal(const std::vector<std::uint8_t>& signed_data, bool& is_valid, std::vector<std::uint8_t>& content);
    bool SignDataInternalBase64(const std::vector<std::uint8_t>& data, std::string& signed_data_base64);
    bool VerifyDataInternalBase64(const std::string& signed_data_base64, bool& is_valid, std::vector<std::uint8_t>& content);
    bool VerifyDataInternalString(const std::vector<std::uint8_t>& signed_data, bool& is_valid, std::string& content_utf8);
    bool VerifyDataInternalBase64String(const std::string& signed_data_base64, bool& is_valid, std::string& content_utf8);

    bool SignFile(const std::string& path, std::vector<std::uint8_t>& signature);
    bool SignFile(const std::string& path, std::vector<std::uint8_t>& signature, TimestampMode timestamp_mode);
    bool VerifyFile(const std::string& path, const std::vector<std::uint8_t>& signature, bool& is_valid);
    bool RawSignFile(const std::string& input_path, const std::string& signature_path);
    bool RawSignFile(const std::string& input_path, const std::string& signature_path, TimestampMode timestamp_mode);
    bool RawVerifyFile(const std::string& input_path, const std::string& signature_path, bool& is_valid);

    bool SignXml(const std::string& xml, std::string& signed_xml_out);
    // profile: "" or "xmldsig" → plain XMLDSIG-enveloped (default);
    // "xades-bes" → XAdES-BES with SignedProperties;
    // "xades-t"   → XAdES-T (BES + SignatureTimeStamp, requires ConfigureTsp + online mode).
    bool SignXml(const std::string& xml, const std::string& xades_profile, std::string& signed_xml_out);
    bool VerifyXml(const std::string& signed_xml, bool& is_valid);
    bool SignPdf(const std::vector<std::uint8_t>& document_content, std::vector<std::uint8_t>& signed_pdf_out);
    // А-07: профіль PAdES задається явно. Доти точка входу жорстко ставила
    // `PadesProfile::B`, хоча `PadesBuilder` реалізує T/LT/LTA — рушій умів
    // більше за контракт, і це був стан «випадково», а не «за рішенням».
    //
    // profile: "" або "pades-b"/"b"   → PAdES-B (типово, як і раніше);
    //          "pades-t"/"t"          → + мітка часу підпису (потребує
    //                                    ConfigureTsp і offline=false);
    //          "pades-lt"/"lt"        → + DSS: ланцюг сертифікатів і CRL;
    //          "pades-lta"/"lta"      → + документна мітка часу.
    //
    // Fail-closed: якщо матеріал для заявленого рівня зібрати не вдалося,
    // документ НЕ створюється. PDF, який заявляє LT і не несе доказів, гірший
    // за відмову — саме тому рівень не понижується мовчки.
    bool SignPdf(const std::vector<std::uint8_t>& document_content,
                 const std::string& pades_profile,
                 std::vector<std::uint8_t>& signed_pdf_out);
    bool VerifyPdf(const std::vector<std::uint8_t>& pdf, bool& is_valid);

    // Типові ASiC-шляхи віддають XAdES-розкладку (META-INF/signatures*.xml).
    // CAdES-розкладка лишається доступною окремими методами під іменами
    // форматів `asic-s-cades` / `asic-e-cades`.
    bool SignFileAsicS(const std::string& input_path, const std::string& output_path);
    bool SignFileAsicSCades(const std::string& input_path, const std::string& output_path);
    bool VerifyFileAsicS(const std::string& asics_path, bool& is_valid);
    bool SignFileAsicE(const std::string& input_path, const std::string& output_path);
    bool SignFileAsicECades(const std::string& input_path, const std::string& output_path);
    // Спільна реалізація обох XAdES-профілів; asic_e перемикає ASiC-S/ASiC-E.
    bool SignFileAsicXades(const std::string& input_path, const std::string& output_path, bool asic_e);
    bool VerifyFileAsicE(const std::string& asice_path, bool& is_valid);
    bool VerifyFileAsicEXades(const std::string& asice_path, bool& is_valid);
    bool AddSignatureToAsicE(const std::string& asice_path, const std::string& output_path);
    std::string ResolveDefaultTspUrl() const;

    bool ShowCertificates();
    bool ShowCRLs();

    [[nodiscard]] bool IsInitialized() const;
    [[nodiscard]] bool IsPrivateKeyLoaded() const;
    [[nodiscard]] bool NeedSetSettings() const;
    [[nodiscard]] bool OfflineMode() const;
    [[nodiscard]] LastError GetLastError() const;

private:
    enum class KeyFormat { Unknown = 0, Pkcs12, Jks, Pem, Der };

    bool NormalizeKeyContainer(const std::vector<std::uint8_t>& key_data, const std::string& store_password, const std::string& key_password, const std::string& jks_alias, bool strict_pem, std::vector<std::uint8_t>& normalized, std::vector<std::uint8_t>& key_material, std::vector<std::uint8_t>& certificate, KeyFormat& format, std::string& error_message) const;
    static bool IsValidDerContainer(const std::vector<std::uint8_t>& der_data, std::string& error_message);
    // Додаткові джерела відкритого сертифіката для контейнерів без certBag
    // (`.dat`, `key-6.dat`, PKCS#12 DER від Вчасно/ІІТ/ДПС/ПриватБанку тощо).
    // Заповнюється з media-дескриптора; порожня структура = поведінка як раніше.
    struct CertificateHints {
        std::string certificate_path;    // "certificatePath" / "certPath"
        std::string certificate_base64;  // "certificateBase64" / "certBase64"
        std::string key_file_path;       // шлях до самого ключа — база для sidecar-пошуку
        std::string ca_hint;             // "ca" / "provider" — пріоритетний КНЕДП
        // ТЗ Рівень 3: "edrpou" / "drfo" / "subject" — звужує вибірку LDAP-каталогу.
        // Не обовʼязковий: відбір усе одно завершує звірка з відкритим ключем.
        std::string subject_identifier;
    };

    bool LoadKeyFromBytes(const std::vector<std::uint8_t>& key_data, std::string store_password, std::string key_password, std::string jks_alias, bool strict_pem, const CertificateHints& cert_hints = {});
    bool LoadPrivateKeyPayload(const std::vector<std::uint8_t>& key_data, std::string store_password, std::string key_password, std::string jks_alias, bool strict_pem, const CertificateHints& cert_hints = {});
    // Авто-резолвер: викликається лише коли після нормалізації сертифікат порожній.
    bool ResolveMissingCertificate(const std::vector<std::uint8_t>& key_material,
                                   const std::string& password,
                                   const CertificateHints& cert_hints,
                                   std::vector<std::uint8_t>& certificate,
                                   std::string& error_message) const;
    void CommitLoadedKey(std::vector<std::uint8_t> normalized, std::vector<std::uint8_t> key_material, std::vector<std::uint8_t> certificate, const std::string& store_password, KeyFormat format);
    void ClearVerifyReport();
    void SetVerifyReport(std::string operation, bool execution_succeeded, bool signature_valid, ErrorCode error_code, std::string message);
    void OverrideVerifyReportOperation(std::string operation);

    // Н-04 (TOCTOU звіту). Verify-операції навмисно НЕ тримають mutex_ під час
    // роботи (WP-17: мережеві OCSP/CRL/TSA-виклики поза критичною секцією).
    // Через це між комітом `last_verify_report_` і подальшим доуточненням
    // окремих полів мутекс відпускається — і паралельний Verify* на ТІЙ САМІЙ
    // сесії встигає закомітити СВІЙ звіт. Доуточнення тоді потрапляло в чужий
    // звіт: операція чи статус мітки часу від одного виклику опинялися у
    // результаті іншого.
    //
    // Тримати mutex_ на всю операцію не можна — це відкотило б WP-17 і
    // повернуло блокування GetReport() на час мережевих викликів. Тому замість
    // розширення критичної секції вводиться ЕПОХА звіту: кожен коміт отримує
    // глобально унікальний номер, а доуточнення застосовується лише тоді, коли
    // поточний звіт — усе ще той, який закомітив ЦЕЙ потік.
    //
    // Викликати лише під mutex_.
    void MarkVerifyReportCommittedLocked();
    bool VerifyReportStillOwnedByThisThreadLocked() const;
    void RefreshUserReport(std::string container_type, std::string signature_format);
    void RefreshUserReportForCurrentOperation();
    void SecureClearLoadedKey();
    static void SecureErase(std::string& value);
    void SetError(ErrorCode code, std::string message);
    void ClearError();

    // Н-04 (ADR-033): облік «чи звіт усе ще мій» винесено у власний тип.
    // Значення епох глобально унікальні, тож збіг із епохою, записаною іншою
    // сесією, неможливий.
    VerifyReportOwnership verify_report_ownership_{};

    mutable std::mutex mutex_;
    bool is_initialized_{false};
    bool is_private_key_loaded_{false};
    bool need_set_settings_{true};

    Settings settings_{};
    FileStoreSettings file_store_settings_{};
    OcspSettings ocsp_settings_{};
    TspSettings tsp_settings_{};
    LdapSettings ldap_settings_{};
    CmpSettings cmp_settings_{};
    TrustListSettings trust_list_settings_{};
    LastError last_error_{};
    std::vector<std::uint8_t> loaded_key_{};
    std::vector<std::uint8_t> loaded_key_material_{};
    std::vector<std::uint8_t> loaded_certificate_{};
    std::string loaded_key_password_{};
    KeyFormat loaded_key_format_{KeyFormat::Unknown};
    VerifyReport last_verify_report_{};
    // WP-17 (ME-06): див. коментар над TrustListSyncReport — навмисно
    // окремий від last_verify_report_ стан.
    TrustListSyncReport last_trust_list_sync_report_{};
    CertificateMetadata last_signer_metadata_{};
    // А-04: тут стояв ЛІТЕРАЛ дефолтного звіту зі `"schemaVersion":"2.0"`,
    // тоді як `UserReportBuilder` уже віддавав `"2.1"`. Друге джерело тієї
    // самої правди, і оновлювали лише перше. Спостерігалося вікном «виклик
    // GetUserReport() до Initialize()»: `GetUserReport` не має передумов і
    // віддавав кеш як є, тож споживач, який читає `schemaVersion` для
    // визначення сумісності, бачив версію, якої вже не існує.
    //
    // Тепер кеш наповнює конструктор через той самий будівник, що й усі
    // подальші операції (див. `Session::Session`).
    std::string last_user_report_json_{};
};

} // namespace tamga::core
