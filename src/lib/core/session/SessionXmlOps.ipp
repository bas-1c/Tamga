// Session-оркестрація XMLDSIG (enveloped) поверх xmldsig-builder/verifier.
// Доступно лише у збірці з TAMGA_ENABLE_XML_SIGNATURES; інакше — NotSupported.

#if defined(TAMGA_XML_SIGNATURES_ENABLED)
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/XmlSignatureBuilder.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xmldsig/XmlTransformEngine.h"
#include "xades/XadesBuilder.h"
#include "xades/XadesVerifier.h"
#endif

namespace tamga::core {

namespace {

[[maybe_unused]] const char* kXmlDsigDisabledMessage =
    "XMLDSIG support requires building with TAMGA_ENABLE_XML_SIGNATURES";

#if defined(TAMGA_XML_SIGNATURES_ENABLED)
// Ідентифікатор не є криптографічним значенням: він лише зв'язує
// ds:Reference з xades:DataObjectFormat усередині одного XML-документа.
// Лічильник гарантує унікальність у процесі, а два часові значення — між
// послідовними запусками з практично однаковою часовою міткою. Формат —
// 32 малі hex-символи без дефісів, як в еталонних контейнерах Дії.
std::string GenerateGuid() {
    static std::atomic<std::uint64_t> sequence{0};
    const auto wall_clock = static_cast<std::uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());
    const auto monotonic_clock = static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const std::uint64_t tail = monotonic_clock ^ sequence.fetch_add(1, std::memory_order_relaxed);

    std::ostringstream out;
    out << std::hex << std::setfill('0')
        << std::setw(8) << static_cast<std::uint32_t>(wall_clock >> 32)
        << std::setw(4) << static_cast<std::uint16_t>(wall_clock >> 16)
        << std::setw(4) << static_cast<std::uint16_t>(wall_clock)
        << std::setw(4) << static_cast<std::uint16_t>(tail >> 48)
        << std::setw(12) << (tail & UINT64_C(0x0000FFFFFFFFFFFF));
    return out.str();
}

// Дефолтні алгоритми XMLDSIG для домену Tamga (ДСТУ 4145 + ГОСТ 34.311),
// конвенція xmldsig-more (поширена в українських реалізаціях). Остаточну
// відповідність офіційному профілю звіряємо cross-validation у Phase 8.
constexpr const char* kXmlDsigSignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
constexpr const char* kXmlDsigDigestMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
constexpr const char* kXmlDsigEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
constexpr const char* kXmlDsigC14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

const char* XadesProfileName(tamga::xades::XadesProfile p) {
    switch (p) {
        case tamga::xades::XadesProfile::BES: return "XAdES-BES";
        case tamga::xades::XadesProfile::T: return "XAdES-T";
        case tamga::xades::XadesProfile::C: return "XAdES-C";
        case tamga::xades::XadesProfile::X: return "XAdES-X";
        case tamga::xades::XadesProfile::X_L: return "XAdES-X-L";
        case tamga::xades::XadesProfile::A: return "XAdES-A";
    }
    return "XAdES";
}

std::string SessionXadesProfileName(const tamga::xades::XadesVerificationResult& result) {
    std::string profile = result.format_profile.empty()
        ? XadesProfileName(result.detected_profile)
        : result.format_profile;

    // Session-generated XML fixtures are legacy XAdES-T objects. Keep the public
    // VerifyXml report stable even if the low-level detector uses the newer
    // ETSI baseline spelling for the same evidence set.
    if (profile == "XAdES-B-T") {
        profile = "XAdES-T";
    }
    return profile;
}
#endif

}  // namespace

bool Session::SignXml(const std::string& xml, std::string& signed_xml_out) {
    signed_xml_out.clear();
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_initialized_) {
        SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
        return false;
    }
    if (!is_private_key_loaded_) {
        SetError(ErrorCode::KeyNotLoaded, ToString(ErrorCode::KeyNotLoaded));
        return false;
    }
#if defined(TAMGA_XML_SIGNATURES_ENABLED)
    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    tamga::xmldsig::XmlSignatureBuilder builder(canonicalizer, transform_engine, digest_engine, crypto);

    tamga::xmldsig::XmlSignatureParameters params;
    params.signature_method_uri = kXmlDsigSignatureMethod;
    params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {kXmlDsigEnveloped, kXmlDsigC14n};
    ref.digest_method = kXmlDsigDigestMethod;
    params.references.push_back(ref);

    tamga::core::SigningKey key;
    key.use_pkcs12 = (loaded_key_format_ == KeyFormat::Pkcs12);
    key.key_material = loaded_key_material_;
    key.certificate_der = loaded_certificate_;
    key.password = loaded_key_password_;

    // Для PKCS12 сертифікат лежить усередині контейнера (loaded_certificate_
    // порожній) — дістаємо його для вбудовування у KeyInfo.
    if (key.certificate_der.empty()) {
        std::string cert_error;
        std::vector<std::uint8_t> signer_cert;
        if (CryptoniteAdapter::ExtractSignerCertificate(key.use_pkcs12, key.key_material,
                                                        key.certificate_der, key.password,
                                                        signer_cert, cert_error)) {
            key.certificate_der = std::move(signer_cert);
        }
    }

    std::string error_message;
    if (!builder.Sign(xml, params, key, signed_xml_out, error_message)) {
        signed_xml_out.clear();
        SetError(ErrorCode::InternalError, std::move(error_message));
        return false;
    }
    ClearError();
    return true;
#else
    (void)xml;
    SetError(ErrorCode::NotSupported, kXmlDsigDisabledMessage);
    return false;
#endif
}

bool Session::SignXml(const std::string& xml, const std::string& xades_profile,
                      std::string& signed_xml_out) {
    signed_xml_out.clear();

    const bool is_xades_bes = (xades_profile == "xades-bes");
    const bool is_xades_t = (xades_profile == "xades-t");

    // "" or "xmldsig" → delegate to the plain XMLDSIG path (existing 2-arg overload)
    if (!is_xades_bes && !is_xades_t) {
        if (xades_profile.empty() || xades_profile == "xmldsig") {
            return SignXml(xml, signed_xml_out);
        }
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::NotSupported,
                 "SignXml: unsupported profile \"" + xades_profile +
                 "\"; expected \"xmldsig\", \"xades-bes\", or \"xades-t\"");
        return false;
    }

#if !defined(TAMGA_XML_SIGNATURES_ENABLED)
    (void)xml;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::NotSupported, kXmlDsigDisabledMessage);
    }
    return false;
#else
    // Lock-narrowing: XAdES-T needs a TSP network call outside the mutex.
    tamga::core::SigningKey key;
    TspSettings tsp_settings;
    bool offline_mode = true;
    std::string work_dir;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        if (!is_private_key_loaded_) {
            SetError(ErrorCode::KeyNotLoaded, ToString(ErrorCode::KeyNotLoaded));
            return false;
        }
        key.use_pkcs12 = (loaded_key_format_ == KeyFormat::Pkcs12);
        key.key_material = loaded_key_material_;
        key.certificate_der = loaded_certificate_;
        key.password = loaded_key_password_;
        tsp_settings = tsp_settings_;
        offline_mode = settings_.offline_mode;
        work_dir = settings_.work_dir;
    }

    // Extract signer certificate from PKCS12 when it was not stored separately.
    if (key.certificate_der.empty()) {
        std::string cert_error;
        std::vector<std::uint8_t> signer_cert;
        if (CryptoniteAdapter::ExtractSignerCertificate(key.use_pkcs12, key.key_material,
                                                        key.certificate_der, key.password,
                                                        signer_cert, cert_error)) {
            key.certificate_der = std::move(signer_cert);
        }
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp_client;
    tamga::xades::XadesBuilder xades_builder(crypto, tsp_client);

    tamga::xades::XadesParameters xparams;
    xparams.profile = is_xades_t ? tamga::xades::XadesProfile::T : tamga::xades::XadesProfile::BES;
    xparams.xml_params.signature_method_uri = kXmlDsigSignatureMethod;
    xparams.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    {
        tamga::xmldsig::XmlReference ref;
        ref.uri = "";
        ref.transforms = {kXmlDsigEnveloped, kXmlDsigC14n};
        ref.digest_method = kXmlDsigDigestMethod;
        xparams.xml_params.references.push_back(ref);
    }

    if (is_xades_t) {
        std::string tsp_url = tsp_settings.url;
        if (tsp_url.empty()) {
            tsp_url = ResolveDefaultTspUrlCombined(key.certificate_der, work_dir);
        }
        if (tsp_url.empty() || offline_mode) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::OnlineServiceUnavailable,
                     "XAdES-T requires a TSP URL and online mode; "
                     "use ConfigureTsp() and set offline=false in Configure()");
            return false;
        }
        const TspSettings captured_tsp = tsp_settings;
        const std::string captured_url = std::move(tsp_url);
        xparams.timestamp_provider = [captured_tsp, captured_url](
            const std::vector<std::uint8_t>& tbs,
            std::vector<std::uint8_t>& token,
            std::string& error) -> bool {
            ImprintResult imprint;
            if (!ResolveTspImprint(captured_tsp, tbs, {}, imprint, error)) return false;
            return TspClient::GetTimestamp(imprint.hash, imprint.digest_oid, captured_url,
                                           captured_tsp.timeout_ms, captured_tsp.policy_oid,
                                           token, error);
        };
    }

    std::string error_message;
    if (!xades_builder.Sign(xml, xparams, key, signed_xml_out, error_message)) {
        signed_xml_out.clear();
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError, std::move(error_message));
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearError();
    }
    return true;
#endif
}

bool Session::VerifyXml(const std::string& signed_xml, bool& is_valid) {
    is_valid = false;

    // WP-17 (звуження critical section): раніше mutex_ трималася на всю
    // тривалість цієї функції, включно з мережевими OCSP/CRL/TSA-викликами
    // всередині RunFormatTrustValidation/ApplyXadesTimestampPolicyValidation
    // — потенційне блокування GetError/GetLastVerifyReport з іншого потоку
    // під час повільної (offline/online) перевірки. Тепер lock тримається
    // лише для (1) початкової перевірки стану + знімка Settings і (2)
    // фінального коміту результату; увесь XML-парсинг, крипто- і
    // trust/TSA-мережевий pipeline працює з ЛОКАЛЬНИМ Settings/VerifyReport,
    // без lock_guard.
    Settings local_settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        local_settings = settings_;
    }
#if defined(TAMGA_XML_SIGNATURES_ENABLED)
    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesVerifier verifier(xml_verifier, crypto, tsp);

    // WP-2 (Session-інтеграція): VerifyAll підтримує кілька ds:Signature в
    // ОДНОМУ XML-документі. Репрезентативним для агрегованих полів звіту
    // (signatureValid/trust/timestamp тощо) обираємо ПЕРШИЙ невалідний
    // підпис, а якщо всі валідні — перший загалом (той самий принцип, що й
    // раніше застосовувався до ASiC-E multi-file co-signing). Крипто-стан
    // КОЖНОГО підпису додатково потрапляє у report.signatures[].
    tamga::xades::XadesSignatureSet result_set;
    std::string error_message;
    if (!verifier.VerifyAll(signed_xml, result_set, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError, std::move(error_message));
        return false;
    }
    is_valid = result_set.all_valid;

    std::size_t representative_index = 0;
    for (std::size_t i = 0; i < result_set.signatures.size(); ++i) {
        if (!result_set.signatures[i].signature_valid) {
            representative_index = i;
            break;
        }
    }
    const tamga::xades::XadesVerificationResult& result = result_set.signatures[representative_index];

    // Phase 7: форматний звіт XAdES. Будується у ЛОКАЛЬНОМУ report — жодних
    // звернень до last_verify_report_ до фінального коміту нижче.
    const std::string xades_profile = SessionXadesProfileName(result);
    VerifyReport report;
    report.has_result = true;
    report.execution_succeeded = true;
    report.signature_valid = result_set.all_valid;
    report.signature_format = "XAdES";
    report.format_profile = xades_profile;
    // ME-01: signer_certificate_present мусить відображати наявність
    // KeyInfo/X509Certificate (те, від чого залежить trust-валідація), а НЕ
    // наявність SignedProperties/QualifyingProperties (то окремий структурний
    // факт, який XAdES-підпис може мати незалежно від вбудованого
    // сертифіката). ASiC-XAdES шлях (VerifyFileAsicEXades) уже використовує
    // цей самий критерій.
    report.signer_certificate_present = !result.signer_certificate_der.empty();
    report.qualifying_properties_present = result.qualifying_properties_present;
    report.timestamp_checked = result.signature_timestamp_checked;
    report.tsp_checked = result.tsp_checked;
    if (report.timestamp_checked) {
        ApplyFormatTimestampVerdict(report, result.signature_timestamp_valid,
                                    /*canonical_full=*/false);
    }
    report.ltv_valid = result.ltv_valid;
    report.ltv_evidence_bound = result.ltv_evidence_bound;
    // ME-02: структурна наявність RevocationValues — НЕ те саме, що
    // report.revocation_checked/ocsp_checked (встановлюються нижче через
    // RunFormatTrustValidationOn і НЕ клонуються тут повторно).
    report.revocation_evidence_present = result.revocation_values_present;
    report.operation = "VerifyXml";
    report.policy = "xades-format";
    for (std::size_t i = 0; i < result_set.signatures.size(); ++i) {
        const auto& one = result_set.signatures[i];
        SignatureEntry entry;
        entry.index = static_cast<int>(i) + 1;
        entry.signature_valid = one.signature_valid;
        // ME-01: той самий критерій, що для report вище.
        entry.signer_certificate_present = !one.signer_certificate_der.empty();
        entry.qualifying_properties_present = one.qualifying_properties_present;
        entry.signing_certificate_digest_valid = one.signing_certificate_digest_valid;
        entry.format_profile = SessionXadesProfileName(one);
        entry.timestamp_checked = one.signature_timestamp_checked;
        if (entry.timestamp_checked) {
            ApplyEntryTimestampVerdict(entry, one.signature_timestamp_valid);
        }
        entry.ltv_valid = one.ltv_valid;
        entry.ltv_evidence_bound = one.ltv_evidence_bound;
        // HI-01: незалежна trust/revocation/certificate.timeValid-перевірка
        // САМЕ цього підписанта (окремий X.509 chain + OCSP/CRL на кожного
        // співпідписанта, WP-5 ME-07 передає embedded evidence так само, як
        // і раніше робилось лише для одного репрезентативного нижче).
        ApplyPerSignerTrustValidation(local_settings, one.signer_certificate_der, one.certificate_values_der,
                                      one.revocation_values_ocsp_der, one.revocation_values_crl_der, entry);
        ApplyPerSignerXadesTimestampValidation(local_settings, one, entry);
        entry.ltv_evidence_validated = entry.ltv_evidence_bound && entry.trust_valid &&
            (entry.revocation_status == "valid" || entry.revocation_status == "good");
        entry.signature_policy_present = one.signature_policy_present;
        entry.signature_policy_id = one.signature_policy_id;
        entry.signature_policy_hash_algo_uri = one.signature_policy_hash_algo_uri;
        entry.data_object_formats = ToSessionDataObjectFormats(one.data_object_formats);
        report.signatures.push_back(std::move(entry));
    }

    // Q-004: окремий RunFormatTrustValidationOn для репрезентативного
    // сертифіката видалений — ApplyPerSignerTrustAggregation нижче
    // заповнює error_code/message/chain_debug з "найгіршого" підписанта
    // (так само як trust_valid/revocation_status/chain_valid тощо), тому
    // попередній мережевий trust-виклик давав N+1 мережевих round-trips
    // при N підписантах без жодного корисного ефекту (HI-01).
    ApplyPerSignerTrustAggregation(report);
    // В-03: див. коментар у SessionPdfOps.ipp — знімок канонічного вердикту
    // мітки часу до відновлення форматних полів.
    const bool canonical_timestamp_full = (report.timestamp_status == "timestamp-valid");
    // WP-5 (ME-04): validated_profile підтверджується ЛИШЕ якщо структурний
    // evidence-binding пройшов (ltv_evidence_bound) І саме ця trust/revocation
    // перевірка (щойно виконана ApplyPerSignerTrustAggregation) визнала
    // ланцюг довіреним і відкликання підтвердженим — тепер ДЛЯ ВСІХ
    // підписантів (HI-01), а не лише для репрезентативного.
    const bool xades_evidence_confirmed = result.ltv_evidence_bound &&
                                          report.trust_valid &&
                                          (report.revocation_status == "valid" || report.revocation_status == "good");
    report.signature_format = "XAdES";
    report.format_profile = xades_profile;
    report.timestamp_checked = result.signature_timestamp_checked;
    report.tsp_checked = result.tsp_checked;
    if (report.timestamp_checked) {
        ApplyFormatTimestampVerdict(report, result.signature_timestamp_valid,
                                    canonical_timestamp_full);
    }
    report.ltv_valid = result.ltv_valid;
    report.ltv_evidence_bound = result.ltv_evidence_bound;
    report.signature_policy_present = result.signature_policy_present;
    report.signature_policy_id = result.signature_policy_id;
    report.signature_policy_hash_algo_uri = result.signature_policy_hash_algo_uri;
    report.data_object_formats = ToSessionDataObjectFormats(result.data_object_formats);

    // WP-6 (H2): раніше лише VerifyFileAsicEXades доводив SignatureTimeStamp
    // до повної довіри TSA (сертифікат/ланцюг/EKU) через
    // ApplyXadesTimestampPolicyValidation (мережевий TSA-виклик, ПОЗА
    // lock_guard); голий VerifyXml (без ASiC-E) зупинявся на самій
    // криптоперевірці токена. Той самий виклик тепер застосовується й тут,
    // щоб timestampValid/ltvValid відображали реальну довіру до TSA, а не
    // лише валідність RFC3161-підпису.
    AggregatePerSignerTimestamps(report);
    report.validated_profile = xades_evidence_confirmed ? xades_profile : std::string();
    // HI-02: ltvEvidenceValidated — той самий вираз, що вже вирішує
    // validated_profile вище (навмисно ДО ApplyXadesTimestampPolicyValidation,
    // яка може окремо скинути trust_valid з причин TSA-довіри, WP-6).
    report.ltv_evidence_validated = xades_evidence_confirmed;

    // Фінальний коміт: єдина ділянка, де це знову торкається спільного
    // стану Session, — короткий lock без жодного мережевого виклику під ним.
    // Q-003: RefreshUserReport оновлює кеш last_user_report_json_ (який читає
    // GetUserReport()) — раніше VerifyXml його НЕ викликав, тож GetUserReport()
    // після VerifyXml повертав звіт попередньої операції.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_verify_report_ = std::move(report);
        // Н-04: фіксуємо епоху цього коміту — доуточнення нижче застосується
        // лише якщо звіт усе ще належить цьому потоку.
        MarkVerifyReportCommittedLocked();
        RefreshUserReport("", "XAdES");
        ClearError();
    }
    return true;
#else
    (void)signed_xml;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::NotSupported, kXmlDsigDisabledMessage);
    }
    return false;
#endif
}

// Підпис файла у ASiC-контейнер із XAdES-підписом — розкладка, яку створює і
// читає українська екосистема (Дія, ІІТ):
//
//   mimetype
//   <документ>
//   META-INF/manifest.xml        (лише ASiC-E; OASIS ODF, не ASiCManifest)
//   META-INF/signatures.xml      (ASiC-S)
//   META-INF/signatures001.xml   (ASiC-E)
//
// Це НЕ те саме, що `SignFileAsicSCades`/`SignFileAsicECades`: там підпис —
// CAdES у `META-INF/signature.p7s`. Обидві розкладки дозволені ETSI EN 319
// 162-1; цей шлях відтворює XAdES-профіль еталонних контейнерів Дії.
bool Session::SignFileAsicXades(const std::string& input_path, const std::string& output_path, bool asic_e) {
#if !defined(TAMGA_XML_SIGNATURES_ENABLED)
    (void)input_path;
    (void)output_path;
    (void)asic_e;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::NotSupported, kXmlDsigDisabledMessage);
    }
    return false;
#else
    const char* const profile_name = asic_e ? "ASiC-E" : "ASiC-S";

    FileStoreSettings settings;
    TspSettings tsp_settings;
    bool offline_mode = true;
    std::string work_dir;
    tamga::core::SigningKey key;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        if (!is_private_key_loaded_) {
            SetError(ErrorCode::KeyNotLoaded, ToString(ErrorCode::KeyNotLoaded));
            return false;
        }
        settings = file_store_settings_;
        tsp_settings = tsp_settings_;
        offline_mode = settings_.offline_mode;
        work_dir = settings_.work_dir;
        key.use_pkcs12 = (loaded_key_format_ == KeyFormat::Pkcs12);
        key.key_material = loaded_key_material_;
        key.certificate_der = loaded_certificate_;
        key.password = loaded_key_password_;
    }

    if (key.certificate_der.empty()) {
        std::string cert_error;
        std::vector<std::uint8_t> signer_cert;
        if (CryptoniteAdapter::ExtractSignerCertificate(key.use_pkcs12, key.key_material,
                                                        key.certificate_der, key.password,
                                                        signer_cert, cert_error)) {
            key.certificate_der = std::move(signer_cert);
        }
    }

    const std::string resolved_input_path = ResolveFilePath(input_path, settings);
    std::vector<std::uint8_t> file_data;
    std::string error_message;
    if (!ReadBinaryFile(resolved_input_path, "input file for ASiC", file_data, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }
    if (file_data.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Input file is empty");
        return false;
    }

    const std::filesystem::path input_fs_path(std::filesystem::u8path(resolved_input_path));
    const std::string entry_name = input_fs_path.filename().u8string();

    // URI посилання має пережити percent-decode, який робить читач
    // (`util::NormalizeAsicEntryUri`). Дія кодує кожен байт UTF-8 поза
    // unreserved-набором RFC 3986, тому відтворюємо саме цю форму.
    const std::string reference_uri = [&entry_name]() {
        static const char kHex[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(entry_name.size());
        for (const char raw : entry_name) {
            const unsigned char ch = static_cast<unsigned char>(raw);
            const bool unreserved =
                (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' ||
                ch == '_' || ch == '~';
            const bool needs_escape = !unreserved;
            if (needs_escape) {
                out.push_back('%');
                out.push_back(kHex[(ch >> 4) & 0x0F]);
                out.push_back(kHex[ch & 0x0F]);
            } else {
                out.push_back(raw);
            }
        }
        return out;
    }();

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp_client;
    tamga::xades::XadesBuilder xades_builder(crypto, tsp_client);

    tamga::xades::XadesParameters xparams;
    // Нові ASiC-S/E XAdES створюємо в одному явному профілі Купини-256.
    // `signatureAlgorithm` X.509 описує підпис ВИДАВЦЯ сертифіката і не
    // визначає алгоритм нового XMLDSIG-підпису. Еталони Дії містять Купина-
    // підписи і з ГОСТ-підписаними сертифікатами, тому вибір за outer OID
    // давав неправильний ГОСТ-профіль для частини чинних сертифікатів.
    constexpr const char* kAsicSignatureMethodUri =
        "http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256";
    constexpr const char* kAsicDigestMethodUri =
        "http://www.w3.org/2001/04/xmlenc#dstu7564-256";

    const std::string signature_guid = GenerateGuid();
    xparams.xml_params.signature_id = "id-" + signature_guid;
    xparams.signed_properties_id = "xades-id-" + signature_guid;
    xparams.xml_params.signature_method_uri = kAsicSignatureMethodUri;
    xparams.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N_Exclusive;
    xparams.cert_digest_uri = kAsicDigestMethodUri;
    xparams.signed_properties_digest_uri = kAsicDigestMethodUri;
    {
        tamga::xmldsig::XmlReference ref;
        ref.id = "id-" + signature_guid + "-1";
        ref.type = "";
        ref.emit_type_attribute = true;
        ref.uri = reference_uri;
        // Детачений об'єкт даних: жодних ds:Transforms, дайджест — із сирих
        // байтів файла, як його бачить розпакувальник контейнера.
        ref.digest_method = kAsicDigestMethodUri;
        xparams.xml_params.references.push_back(ref);
        xparams.xml_params.external_data[reference_uri] = file_data;

        tamga::xades::DataObjectFormat data_format;
        data_format.object_reference = "#" + ref.id;
        data_format.mime_type = tamga::asic::GetMimeTypeFromFilename(entry_name);
        xparams.qualifying_properties.signed_props.data_object_formats.push_back(
            std::move(data_format));
    }

    // Мітку часу додаємо, коли є мережа і TSA: без неї перевіряльники (зокрема
    // Дія) показують підпис як не підтверджений кваліфікованою позначкою часу.
    // Недоступність TSA не зриває підпис — рівень просто лишається BES, а
    // причина осідає в стані помилки (той самий best-effort, що й у CMS-шляху).
    std::string tsp_url = tsp_settings.url;
    if (tsp_url.empty()) {
        tsp_url = ResolveDefaultTspUrlCombined(key.certificate_der, work_dir);
    }
    const bool want_timestamp = !offline_mode && !tsp_url.empty();
    if (want_timestamp) {
        xparams.profile = tamga::xades::XadesProfile::T;
        const TspSettings captured_tsp = tsp_settings;
        const std::string captured_url = tsp_url;
        xparams.timestamp_provider = [captured_tsp, captured_url](
            const std::vector<std::uint8_t>& tbs,
            std::vector<std::uint8_t>& token,
            std::string& error) -> bool {
            ImprintResult imprint;
            if (!ResolveTspImprint(captured_tsp, tbs, {}, imprint, error)) return false;
            return TspClient::GetTimestamp(imprint.hash, imprint.digest_oid, captured_url,
                                           captured_tsp.timeout_ms, captured_tsp.policy_oid,
                                           token, error);
        };
    } else {
        xparams.profile = tamga::xades::XadesProfile::BES;
    }

    const std::string host_xml =
        "<asic:XAdESSignatures"
        " xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\""
        " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""
        " xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\""
        " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"/>";

    std::string signature_xml;
    std::string timestamp_error;
    if (!xades_builder.Sign(host_xml, xparams, key, signature_xml, error_message)) {
        if (!want_timestamp) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::InternalError, std::move(error_message));
            return false;
        }
        // Повтор без мітки часу: причина падіння майже завжди в TSA, і мовчки
        // віддати контейнер без підпису гірше, ніж віддати його рівнем нижче.
        timestamp_error = error_message;
        xparams.profile = tamga::xades::XadesProfile::BES;
        xparams.timestamp_provider = nullptr;
        if (!xades_builder.Sign(host_xml, xparams, key, signature_xml, error_message)) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::InternalError, std::move(error_message));
            return false;
        }
    }

    tamga::asic::AsicXadesContent content;
    content.filename = entry_name;
    content.file_data = std::move(file_data);
    content.signature_documents.push_back(
        "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\" ?>" + signature_xml);

    std::vector<std::uint8_t> container;
    const bool packed = asic_e
        ? tamga::asic::AsicXadesContainer::PackE(content, container, error_message)
        : tamga::asic::AsicXadesContainer::PackS(content, container, error_message);
    if (!packed) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError,
                 std::string("Failed to pack ") + profile_name + ": " + error_message);
        return false;
    }

    const std::string resolved_output_path = ResolveFilePath(output_path, settings);
    const std::filesystem::path fs_out_path(std::filesystem::u8path(resolved_output_path));
    if (!settings.allow_overwrite && std::filesystem::exists(fs_out_path)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Output file already exists");
        return false;
    }
    const auto write_result = util::WriteBytesAtomic(fs_out_path, container.data(), container.size());
    if (!write_result) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (write_result.status == util::AtomicWriteStatus::TargetUnusable) {
            SetError(ErrorCode::InvalidArgument, "Unable to open output file: " + resolved_output_path);
        } else {
            SetError(ErrorCode::InternalError,
                     std::string("Failed writing ") + profile_name + " output file: " + write_result.message);
        }
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (timestamp_error.empty()) {
            ClearError();
        } else {
            // Контейнер створено і записано, але рівнем нижче за замовлений.
            SetError(ErrorCode::OnlineServiceUnavailable,
                     std::string(profile_name) + " container timestamp was not applied: " + timestamp_error);
        }
    }
    return true;
#endif
}

}  // namespace tamga::core
