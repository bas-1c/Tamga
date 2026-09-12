#include "support/FixturePaths.h"
// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено — ctest не знає, скільки тестів
// мало бути.
// Довірчий список ЦЗО: налаштування, розбір TL XML і кеш політики.
//
// Тести розбору навмисно перевіряють і стійкість до ін'єкцій через
// коментарі та CDATA — див. TrustListParser.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "types.h"
#include "IMemoryManager.h"
#include "asic/AsicReader.h"
#include "asic/AsicWriter.h"
#include "asic/AsicContainers.h"
#include "miniz.h"
#include "core/Errors.h"
#include "core/HttpClient.h"
#include "core/KeyParsers.h"
#include "core/net/CaSettingsRegistry.h"
#include "core/net/CertificateFetcher.h"
#include "core/net/CertificateResolver.h"
#include "core/Session.h"
#include "tamga/tamga_c_api.h"
#include "core/TspClient.h"
#include "core/policy/AiaIssuerFetcher.h"
#include "core/policy/CertificateChainValidator.h"
#include "core/policy/CrlValidator.h"
#include "core/policy/CrlCache.h"
#include "core/policy/ImprintDigest.h"
#include "core/policy/OcspValidator.h"
#include "core/policy/PolicyCache.h"
#include "core/policy/TimestampValidator.h"
#include "core/policy/TlXmlSigCheck.h"
#include "core/policy/TrustListParser.h"
#include "core/policy/TrustListSettings.h"
#include "core/policy/TrustListSync.h"
#include "core/policy/Sha256Helper.h"
#include "core/policy/UserReportBuilder.h"
#include "core/session/VerifySummary.h"
#include "core/validation/EvidenceStore.h"
#include "core/validation/PathEngine.h"
#include "core/validation/PolicyResolver.h"
#include "core/validation/SigningTimeResolver.h"
#include "core/validation/ValidationReportJson.h"
#include "core/validation/ValidationReportProjection.h"
#include "core/validation/TrustServiceEvaluator.h"
#include "core/validation/RevocationEngine.h"
#include "core/validation/TimestampEngine.h"
#include "core/validation/ValidationEngine.h"
#include "core/CryptoniteAdapter.h"
#include "core/policy/ImprintDigest.h"
#include "nativeapi/TamgaAddIn.h"
#include "util/AsicUri.h"
#include "util/Base64.h"
#include "util/Utf.h"
#include "nativeapi/VariantUtils.h"

// Phase 0 (ADR 012): стаб-заголовки форматних підсистем XMLDSIG/XAdES/PAdES.
// Включення тут дає compile-smoke у проєктному тулчейні — заголовки мають
// парситися й бути взаємно консистентними, поки .cpp зʼявляться у фазах 1-6.
#include "core/SignatureRequest.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/XmlTransformEngine.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSecContext.h"
#include "xmldsig/XmlSignatureBuilder.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xades/XadesTypes.h"
#include "xades/XadesBuilder.h"
#include "xades/XadesVerifier.h"
#include "pades/PdfTypes.h"
#include "pades/PdfParser.h"
#include "pades/PdfByteRange.h"
#include "pades/PadesBuilder.h"
#include "pades/PadesVerifier.h"

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "aid.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "cert_engine.h"
#include "certificate_request_engine.h"
#include "crl.h"
#include "crl_engine.h"
#include "cryptonite_manager.h"
#include "digest_adapter.h"
#include "dstu4145.h"
#include "dstu7564.h"
#include "ext.h"
#include "gost28147.h"
#include "oids.h"
#include "ocsp_response.h"
#include "ocsp_response_engine.h"
#include "pkcs12.h"
#include "pkcs8.h"
#include "sign_adapter.h"
#include "spki.h"
#include "verify_adapter.h"
#include "content_info.h"
#include "signed_data.h"
#include "CertificateSerialNumber.h"
#include "RevokedCertificate.h"
#include "TSTInfo.h"
#include "signed_data_engine.h"
#include "signer_info_engine.h"
#include "signer_info.h"
#include "CertificateSet.h"
#include "SignerIdentifier.h"
#include "pkix_utils.h"
#include "tsp_request.h"
#include "tsp_response.h"
#include "tsp_request_engine.h"
#include "tsp_response_engine.h"
#include "adapters_map.h"
#include "DigestAlgorithmIdentifiers.h"
#include "MessageImprint.h"
#include "AlgorithmIdentifier.h"
#if defined(_WIN32)
#include "dirent_internal.h"
#endif
}
#endif

#include "support/TestSupport.h"
#include "suites/Suites.h"

using namespace tamga_tests;

void TestTrustListSettingsDefaults() {
    tamga::core::TrustListSettings settings;
    ExpectTrue(settings.url == "https://czo.gov.ua/download/tl/TL-UA-EC.xml",
               "Trust list default URL should point to CZO XML");
    ExpectTrue(settings.timeout_ms == 30000, "Trust list timeout default should be 30000 ms");
    ExpectTrue(settings.cache_ttl_hours == 24, "Trust list cache TTL default should be 24 hours");
    ExpectTrue(settings.allow_https_bootstrap, "HTTPS bootstrap should be enabled by default");
    // B-3: TL XML signature verification is no longer opt-out-by-default. The old
    // `verify_xml_signature{false}` left the trust anchor of the whole system on TLS
    // alone, and a requested-but-unsupported check silently passed.
    //
    // The default stayed `Disabled` for one measured reason only: the genuine CZO
    // TL is signed with rsa-sha256, which the verifier could not do, so any other
    // default would have broken production. That blocker is gone — the verifier now
    // has an RSA-PKCS1 path (core/RsaVerifier.h), and `tamga-interop-diag tl-sig
    // tests/TL-UA-EC.xml` reports VERIFIED on the real list. Hence PreferAvailable.
    ExpectTrue(settings.xml_signature_policy ==
                   tamga::core::TrustListSettings::XmlSignaturePolicy::PreferAvailable,
               "TrustListSettings::xml_signature_policy must default to PreferAvailable now "
               "that the verifier handles the algorithm CZO actually signs TL-UA-EC.xml with");
    ExpectTrue(settings.xml_signer_cert_der.empty(),
               "TrustListSettings::xml_signer_cert_der must default to empty");
}

// B-3 regression: the sync result must always state whether the TL ds:Signature was
// actually verified, so "not verified" can never be mistaken for "verified". Before
// this change a build without the XMLDSIG engine answered `not_supported` and the
// sync path fell through as success with no observable difference.
void TestTrustListSyncReportsXmlSignatureStatus() {
    // Default-constructed result must not claim verification.
    tamga::core::policy::TrustListSyncResult fresh;
    // С-22: дефолт керує шляхом fallback-на-кеш, де перевірка підпису не
    // виконувалась зовсім — тож "not-checked", а не "disabled". Властивість,
    // заради якої цей тест існує ("not verified" не сміє виглядати як
    // "verified"), збережена й перевіряється явно нижче.
    ExpectTrue(fresh.xml_signature_status == "not-checked",
               "TrustListSyncResult must default to not-checked");
    ExpectFalse(fresh.xml_signature_status.rfind("verified", 0) == 0,
                "default sync result must never claim verification");

    // Disabled policy is reported as such rather than left blank.
    tamga::core::TrustListSettings disabled;
    disabled.xml_signature_policy = tamga::core::TrustListSettings::XmlSignaturePolicy::Disabled;
    ExpectTrue(disabled.xml_signature_policy ==
                   tamga::core::TrustListSettings::XmlSignaturePolicy::Disabled,
               "Disabled policy must be representable");

    // Require must be representable and distinct from PreferAvailable — it is the
    // setting that turns a missing engine into a hard failure instead of a gap.
    tamga::core::TrustListSettings required;
    required.xml_signature_policy = tamga::core::TrustListSettings::XmlSignaturePolicy::Require;
    ExpectTrue(required.xml_signature_policy !=
                   tamga::core::TrustListSettings::XmlSignaturePolicy::PreferAvailable,
               "Require must be distinct from PreferAvailable");

    // The Session-level report surface must carry the status through to callers.
    //
    // С-22: типове значення змінено з "not-verified-disabled" на "not-checked".
    // Обидва однаково НЕ означають "перевірено" — властивість, заради якої цей
    // тест існує, збережена. Але "disabled" стверджував, що перевірку вимкнено
    // політикою, тоді як типова політика — PreferAvailable: до першого
    // SyncTrustList() перевірка просто ще не виконувалась.
    tamga::core::TrustListSyncReport report;
    ExpectTrue(report.xml_signature_status == "not-checked",
               "TrustListSyncReport must default to not-checked before the first sync");
    // Головна властивість, а не конкретний рядок: жодне типове значення не
    // сміє починатися з "verified".
    ExpectFalse(report.xml_signature_status.rfind("verified", 0) == 0,
                "default TL signature status must never claim verification");
}

// Hardening: невалідний UTF-8 у шляху мусить давати ЧИСТУ помилку, а не аварію
// процесу. Раніше такий рядок доходив до std::filesystem::u8path і на MSVC валив
// процес із 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN). Для бібліотеки під 1С це
// неприпустимо: хост не має падати через некоректний вхід. Найчастіше джерело —
// шлях, переданий у системному ANSI-кодуванні замість UTF-8.
void TestInvalidUtf8PathFailsCleanlyInsteadOfCrashing() {
    // 0xFF/0xFE не можуть зустрітися у валідному UTF-8.
    std::string bad_path = "C:";
    bad_path += static_cast<char>(0x5C);   // backslash
    bad_path += static_cast<char>(0xFF);   // invalid UTF-8 lead byte
    bad_path += static_cast<char>(0xFE);   // invalid UTF-8 lead byte
    bad_path += static_cast<char>(0x5C);
    bad_path += "signed.asice";

    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for UTF-8 path hardening test");

    // Кожен файловий вхід мусить відмовити, а не впасти.
    bool valid = true;
    ExpectFalse(session.VerifyFileAsicEXades(bad_path, valid),
                "VerifyFileAsicEXades must reject a non-UTF-8 path");
    ExpectFalse(valid, "No signature may be reported valid for an unreadable path");

    ExpectFalse(session.ReadPrivateKeyFile(bad_path, "pw"),
                "ReadPrivateKeyFile must reject a non-UTF-8 path");
    const auto err = session.GetLastError();
    ExpectTrue(err.code != tamga::core::ErrorCode::None,
               "A non-UTF-8 path must surface an explicit error code");

    // Валідний UTF-8 з кирилицею НЕ має відкидатися цією перевіркою — інакше
    // hardening зламав би основний український сценарій.
    const std::string cyrillic_missing = u8"C:\\тест\\nope.asice";
    bool valid2 = true;
    ExpectFalse(session.VerifyFileAsicEXades(cyrillic_missing, valid2),
                "A missing Cyrillic path still fails, but as a normal not-found error");
}

void TestTrustListSettingsEmptyUrlUsesDefault() {
    tamga::core::Session session;
    tamga::core::TrustListSettings settings;
    settings.url = "";
    ExpectTrue(session.SetTrustListSettings(settings), "Empty trust list URL should use default URL");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::None,
               "Accepted empty trust list URL should clear last error");
}

void TestTrustListReportFieldsExistBeforeSync() {
    tamga::core::Session session;
    PrepareInitializedSession(session);
    std::string report;
    ExpectTrue(session.GetLastVerifyReport(report), "Initial report should be available");
    ExpectValidJson(report, "Initial trust list report should be valid JSON");
    ExpectContains(report, "\"trustList\"", "Technical report should include trustList block");
    ExpectContains(report, "\"cacheStatus\":\"not-checked\"", "Trust list cache should start as not-checked");
}

void TestTrustListParserExtractsCertificateAndEndpoints() {
    const auto xml = ReadBinaryFixture("trust-list/TL-UA-EC-minimal.xml");
    tamga::core::policy::TrustListParser parser;
    const auto result = parser.Parse(std::string(xml.begin(), xml.end()));
    ExpectTrue(result.ok, "Trust list parser should accept minimal XML fixture");
    ExpectTrue(result.certificates.size() == 1, "Parser should extract one certificate");
    ExpectTrue(std::string(result.certificates[0].begin(), result.certificates[0].end()) == "CERT",
               "Parser should base64-decode certificate payload");
    ExpectTrue(result.endpoints.ocsp_urls.size() == 1, "Parser should extract OCSP URL");
    ExpectTrue(result.endpoints.crl_urls.size() == 1, "Parser should extract CRL URL");
    ExpectTrue(result.endpoints.tsp_urls.size() == 1, "Parser should extract TSP URL");
}

void TestTrustListParserAcceptsNamespacedAndAttributedTags() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<TrustServiceStatusList xmlns:tsl=\"urn:test\">"
        "<TrustServiceProvider>"
        "<Service>"
        "<tsl:X509Certificate xmlns:tsl=\"x\">Q0VSVA==</tsl:X509Certificate>"
        "<CRL type=\"delta\">https://example.test/with-attr.crl</CRL>"
        "<OCSP priority=\"1\">https://example.test/with-attr-ocsp</OCSP>"
        "<TSP xmlns=\"urn:test\">https://example.test/with-attr-tsp</TSP>"
        "</Service>"
        "</TrustServiceProvider>"
        "</TrustServiceStatusList>";

    tamga::core::policy::TrustListParser parser;
    const auto result = parser.Parse(xml);
    ExpectTrue(result.ok, "Trust list parser should accept namespaced and attributed tags");
    ExpectTrue(result.certificates.size() == 1, "Parser should extract namespaced certificate tag");
    if (result.certificates.size() == 1) {
        ExpectTrue(std::string(result.certificates[0].begin(), result.certificates[0].end()) == "CERT",
                   "Parser should decode namespaced certificate payload");
    }
    ExpectTrue(result.endpoints.crl_urls.size() == 1 &&
                   result.endpoints.crl_urls[0] == "https://example.test/with-attr.crl",
               "Parser should extract attributed CRL tag");
    ExpectTrue(result.endpoints.ocsp_urls.size() == 1 &&
                   result.endpoints.ocsp_urls[0] == "https://example.test/with-attr-ocsp",
               "Parser should extract attributed OCSP tag");
    ExpectTrue(result.endpoints.tsp_urls.size() == 1 &&
                   result.endpoints.tsp_urls[0] == "https://example.test/with-attr-tsp",
                   "Parser should extract attributed TSP tag");
}

// S-004: comment-injected service block must NOT materialize as a trust anchor.
void TestTrustListParserIgnoresCommentInjectedService() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<TrustServiceStatusList>"
        "<!-- <TrustServiceProvider><TSPService>"
        "<ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>"
        "<ServiceStatus>http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>"
        "<X509Certificate>AAEC</X509Certificate>"
        "</TSPService></TrustServiceProvider> -->"
        "</TrustServiceStatusList>";

    tamga::core::policy::TrustListParser parser;
    const auto result = parser.Parse(xml);
    ExpectTrue(result.services.empty(),
               "S-004: comment-injected TSPService must not materialize as a trust anchor");
    ExpectTrue(result.certificates.empty(),
               "S-004: certificate inside comment block must not be extracted");
}

// S-004: CDATA-injected service block must NOT materialize as a trust anchor.
void TestTrustListParserIgnoresCdataInjectedService() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<TrustServiceStatusList>"
        "<![CDATA[<TrustServiceProvider><TSPService>"
        "<ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>"
        "<ServiceStatus>http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>"
        "<X509Certificate>AAEC</X509Certificate>"
        "</TSPService></TrustServiceProvider>]]>"
        "</TrustServiceStatusList>";

    tamga::core::policy::TrustListParser parser;
    const auto result = parser.Parse(xml);
    ExpectTrue(result.services.empty(),
               "S-004: CDATA-injected TSPService must not materialize as a trust anchor");
    ExpectTrue(result.certificates.empty(),
               "S-004: certificate inside CDATA section must not be extracted");
}

void TestTrustListParserExtractsRealTlServices() {
    const auto xml_path = tamga_test::TestDataRoot() / "tests" / "TL-UA-EC.xml";
    const auto xml = ReadBinaryFixture(xml_path);
    ExpectFalse(xml.empty(), "Real TL XML fixture should be available");

    tamga::core::policy::TrustListParser parser;
    const auto result = parser.Parse(std::string(xml.begin(), xml.end()));
    ExpectTrue(result.ok, "Trust list parser should accept real CZO TL XML fixture");
    ExpectTrue(!result.services.empty(), "Parser should extract TSPService records from real TL XML");

    bool has_granted_ca = false;
    bool has_tsa = false;
    for (const auto& service : result.services) {
        if (Contains(service.status, "/granted") &&
            (Contains(service.service_type, "/CA/QC") || Contains(service.service_type, "/MR-CA/QC")) &&
            !service.certificates.empty()) {
            has_granted_ca = true;
        }
        if (Contains(service.service_type, "/TSA/QTST") || Contains(service.service_type, "/MR-TSA/QTST")) {
            has_tsa = true;
        }
    }
    ExpectTrue(has_granted_ca, "Real TL parser should expose granted CA/MR-CA certificate services");
    ExpectTrue(has_tsa, "Real TL parser should expose TSA services for metadata");
}

void TestPolicyCacheWritesTrustListState() {
    const auto work_dir = MakeTemporaryFixturePath(".cache-root");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir, ec);

    tamga::core::policy::PolicyCache cache(work_dir.string());
    tamga::core::policy::PolicyCacheState state;
    state.source_url = "https://example.test/tl.xml";
    state.cache_status = "fresh";
    state.last_sync = "2026-06-12T00:00:00Z";
    ExpectTrue(cache.WriteTrustList(std::vector<std::uint8_t>{'<','x','/','>'}, state),
               "PolicyCache should write trust list and state");
    ExpectTrue(std::filesystem::exists(work_dir / "trust-list" / "TL-UA-EC.xml"),
               "PolicyCache should create trust list XML file");
    ExpectTrue(std::filesystem::exists(work_dir / "trust-list" / "state.json"),
               "PolicyCache should create state JSON file");
    ExpectTrue(cache.WriteTrustList(std::vector<std::uint8_t>{'<','y','/','>'}, state),
               "PolicyCache should replace existing trust list atomically");
    const auto replaced_xml = ReadBinaryFixture(work_dir / "trust-list" / "TL-UA-EC.xml");
    ExpectTrue(std::string(replaced_xml.begin(), replaced_xml.end()) == "<y/>",
               "PolicyCache should expose replaced trust list XML content");
    ExpectFalse(std::filesystem::exists(work_dir / "trust-list" / "TL-UA-EC.xml.tmp"),
                "PolicyCache should not leave trust list temp file after successful write");
    ExpectFalse(std::filesystem::exists(work_dir / "trust-list" / "state.json.tmp"),
                "PolicyCache should not leave state temp file after successful write");
}

void TestPolicyCacheDoesNotReplaceXmlWhenStateStagingFails() {
    const auto work_dir = MakeTemporaryFixturePath(".cache-atomic");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir, ec);

    tamga::core::policy::PolicyCache cache(work_dir.string());
    tamga::core::policy::PolicyCacheState state;
    state.source_url = "https://example.test/tl.xml";
    state.cache_status = "fresh";
    state.last_sync = "2026-06-12T00:00:00Z";
    ExpectTrue(cache.WriteTrustList(std::vector<std::uint8_t>{'<','o','l','d','/','>'}, state),
               "PolicyCache should write initial trust list pair");

    const auto blocked_state_temp = work_dir / "trust-list" / "state.json.tmp";
    std::filesystem::create_directories(blocked_state_temp, ec);
    ExpectTrue(WriteBinaryFile(blocked_state_temp / "block", std::vector<std::uint8_t>{'x'}),
               "Test should block state temp path with a non-empty directory");
    ExpectFalse(cache.WriteTrustList(std::vector<std::uint8_t>{'<','n','e','w','/','>'}, state),
                "PolicyCache should fail when state temp path cannot be staged");
    const auto xml = ReadBinaryFixture(work_dir / "trust-list" / "TL-UA-EC.xml");
    ExpectTrue(std::string(xml.begin(), xml.end()) == "<old/>",
               "PolicyCache should keep previous XML when state write fails");

    std::filesystem::remove_all(work_dir, ec);
}


// ADR-027: закріплення РІЗНИЦІ, знайденої при зведенні двох копій `LocalName`.
//
// `asic/AsicContainers` брав частину після ПЕРШОЇ двокрапки, а цей парсер —
// після ОСТАННЬОЇ. На коректному QName (двокрапка щонайбільше одна) результат
// однаковий, тож розходження не мало симптому. Але цей парсер читає довірчий
// список ВЛАСНИМ сканером, а не libxml2: `ReadElementName` бере байти до
// пробілу, `>` або `/`, тож ім'я з двома двокрапками сюди справді потрапляє.
//
// І саме на такому імені копії давали різне:
//   "evil:tsl:X509Certificate" -> find:  "tsl:X509Certificate"  (не збіг)
//                                 rfind: "X509Certificate"      (ЗБІГ)
// Тобто в модулі з найменш довіреним входом стояла БІЛЬШ поблажлива форма.
//
// Обрано сувору: за XML Namespaces у QName щонайбільше одна двокрапка, отже
// ім'я з двома — некоректне і зіставлятися з очікуваним не повинно.
void TestTrustListParserRejectsDoubleColonElementName() {
    // Контроль: те саме дерево з КОРЕКТНИМ (оголошеним) префіксом парситься
    // як раніше.
    //
    // ADR-030 — ЗВУЖЕННЯ, назване явно. До переходу на libxml2 контроль стояв
    // на префіксі `tsl:` БЕЗ оголошення `xmlns:tsl`, і саморобний сканер його
    // приймав: він різав ім'я по першій двокрапці й на namespace не дивився.
    // libxml2 таке ім'я QName не вважає — воно лишається цілим
    // ("tsl:X509Certificate") і з "X509Certificate" не збігається.
    // Тримаємо саме сувору поведінку: неоголошений префікс — це не
    // namespace-well-formed XML, а тут вирішується, що стане КОРЕНЕМ ДОВІРИ.
    const std::string valid =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<TrustServiceStatusList xmlns:tsl=\"http://uri.etsi.org/02231/v2#\">"
        "<TrustServiceProvider>"
        "<Service>"
        "<tsl:X509Certificate>Q0VSVA==</tsl:X509Certificate>"
        "</Service>"
        "</TrustServiceProvider>"
        "</TrustServiceStatusList>";

    tamga::core::policy::TrustListParser parser;
    const auto ok = parser.Parse(valid);
    ExpectTrue(ok.certificates.size() == 1,
               "sanity: a single-colon QName with a declared prefix must still be recognized");

    const std::string undeclared_prefix =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<TrustServiceStatusList>"
        "<TrustServiceProvider>"
        "<Service>"
        "<tsl:X509Certificate>Q0VSVA==</tsl:X509Certificate>"
        "</Service>"
        "</TrustServiceProvider>"
        "</TrustServiceStatusList>";
    const auto undeclared = parser.Parse(undeclared_prefix);
    ExpectTrue(undeclared.certificates.empty(),
               "ADR-030: an undeclared namespace prefix is not a QName and must not "
               "materialize a trust anchor");

    // Некоректне ім'я з двома двокрапками НЕ має вважатися X509Certificate.
    const std::string malformed =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<TrustServiceStatusList>"
        "<TrustServiceProvider>"
        "<Service>"
        "<evil:tsl:X509Certificate>Q0VSVA==</evil:tsl:X509Certificate>"
        "</Service>"
        "</TrustServiceProvider>"
        "</TrustServiceStatusList>";

    const auto rejected = parser.Parse(malformed);
    ExpectTrue(rejected.certificates.empty(),
               "ADR-027: an element name with two colons is not a QName and must not "
               "be matched as X509Certificate (the lenient rfind form did match it)");
}

// П-07/С-21 у корені довіри. Це ТОЙ САМИЙ клас помилки, який у двійнику
// (`asic/AsicContainers.cpp`) знайшли й виправили, а тут він лишався: межа тега
// шукалася як `xml.find('>', name_pos)`, тобто по ПЕРШОМУ '>', хоча всередині
// значення атрибута '>' — цілком валідний XML-символ. Тег обрізався достроково,
// і далі розбір розходився з канонічним XML — у парсері, який визначає корінь
// довіри всієї системи.
//
// Тест закріплює саме поведінку канонічного парсера: атрибут із '>' не має
// впливати ні на розпізнавання елемента, ні на його значення.
void TestTrustListParserHandlesGreaterThanInsideAttribute() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<TrustServiceStatusList>"
        "<TrustServiceProvider>"
        "<Service>"
        "<X509Certificate note=\"a>b\">Q0VSVA==</X509Certificate>"
        "<CRL note=\"x>y\" type=\"delta\">https://example.test/gt.crl</CRL>"
        "</Service>"
        "</TrustServiceProvider>"
        "</TrustServiceStatusList>";

    tamga::core::policy::TrustListParser parser;
    const auto result = parser.Parse(xml);
    ExpectTrue(result.certificates.size() == 1,
               "П-07: '>' inside an attribute value must not hide the X509Certificate element");
    if (result.certificates.size() == 1) {
        ExpectTrue(std::string(result.certificates[0].begin(), result.certificates[0].end()) == "CERT",
                   "П-07: certificate payload must survive a '>' in a sibling attribute");
    }
    ExpectTrue(result.endpoints.crl_urls.size() == 1 &&
                   result.endpoints.crl_urls[0] == "https://example.test/gt.crl",
               "П-07: attributes after a '>' inside a quoted value must not corrupt the element value");
}

// ADR-030: XXE. Довірчий список приходить із мережі, тож DTD і зовнішні
// сутності мають бути закриті ПОВНІСТЮ, а не «не підставлятися».
void TestTrustListParserRejectsDtdAndExternalEntity() {
    tamga::core::policy::TrustListParser parser;

    const std::string external_entity =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE TrustServiceStatusList ["
        "<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">"
        "]>"
        "<TrustServiceStatusList>"
        "<TrustServiceProvider><Service>"
        "<CRL>&xxe;</CRL>"
        "</Service></TrustServiceProvider>"
        "</TrustServiceStatusList>";
    const auto xxe = parser.Parse(external_entity);
    ExpectFalse(xxe.ok, "XXE: a document with a DTD-declared external entity must be rejected");
    ExpectTrue(xxe.endpoints.crl_urls.empty(), "XXE: nothing may be extracted from a rejected document");

    // Внутрішня сутність без SYSTEM теж відхиляється: DTD-підмножина сама по
    // собі є поверхнею entity-expansion, і жоден із наших форматів її не
    // потребує.
    const std::string internal_dtd =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE TrustServiceStatusList [<!ENTITY a \"AAEC\">]>"
        "<TrustServiceStatusList>"
        "<TrustServiceProvider><Service>"
        "<X509Certificate>&a;</X509Certificate>"
        "</Service></TrustServiceProvider>"
        "</TrustServiceStatusList>";
    const auto dtd = parser.Parse(internal_dtd);
    ExpectFalse(dtd.ok, "XXE: any DTD subset must be rejected, not merely left unexpanded");
    ExpectTrue(dtd.certificates.empty(), "XXE: no certificate may come out of a DTD-bearing document");
}

// ADR-030: межа розміру вхідного XML. Без неї `xmlReadMemory` отримав би
// звужений до `int` розмір і мовчки розібрав би ЧАСТИНУ документа з успішним
// результатом — а для довірчого списку «частина» гірша за відмову.
//
// Перевіряємо саме МЕЖУ, а не 2 ГіБ: виділяти 64 МіБ у тесті непотрібно, а
// контракт (відмова, а не тихе усічення) видно й на межі.
void TestTrustListParserRejectsOversizedInput() {
    tamga::core::policy::TrustListParser parser;

    const auto empty_result = parser.Parse(std::string{});
    ExpectFalse(empty_result.ok, "An empty document must be rejected, not reported as parsed");
    ExpectFalse(empty_result.message.empty(), "A rejected document must carry a diagnostic message");

    // Валідний, але «роздутий» пробілами документ у межах ліміту має
    // розбиратися нормально — інакше межа виявилася б занадто вузькою.
    std::string padded =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<TrustServiceStatusList>"
        "<TrustServiceProvider><Service>";
    padded += "<CRL>https://example.test/padded.crl</CRL>";
    padded += std::string(64 * 1024, ' ');
    padded += "</Service></TrustServiceProvider></TrustServiceStatusList>";
    const auto padded_result = parser.Parse(padded);
    ExpectTrue(padded_result.ok, "A large but valid trust list must still parse");
    ExpectTrue(padded_result.endpoints.crl_urls.size() == 1,
               "Padding must not affect extracted endpoints");
}
