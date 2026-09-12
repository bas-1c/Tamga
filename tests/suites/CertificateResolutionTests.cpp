#include "support/FixturePaths.h"
// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Пошук і резолвінг сертифікатів: sidecar, мережеві джерела, реєстр КНЕДП,
// CMP genMessage. Наскрізна тема — fail-closed: жодне джерело не має
// підвищувати довіру мовчки.

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

// ── Авто-резолвер сертифікатів (ТЗ §6) ────────────────────────────────────────
// Українські КНЕДП видають контейнери без certBag, тож відкритий сертифікат
// доводиться шукати поруч, у кеші або в мережі. Ключова властивість, яку
// перевіряють ці тести, — fail-closed: жоден кандидат не приймається без
// математичної відповідності закритому ключу.
void TestCertificateResolverSpkiAndFailClosedMatching() {
#if TAMGA_CRYPTONITE_ENABLED
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> cert;
    std::string key_password;
    if (!LoadResolverKeyPair(key, cert, key_password)) {
        RecordSkip("PKI PEM fixtures not available");
        return;
    }

    std::vector<std::uint8_t> key_spki;
    std::string err;
    if (!tamga::core::CryptoniteAdapter::ExtractSubjectPublicKeyInfo(key, key_password, key_spki, err)) {
        RecordSkip("SPKI extraction unsupported for this fixture: " + err);
        return;
    }
    ExpectFalse(key_spki.empty(), "SPKI extracted from the private key must not be empty");

    std::vector<std::uint8_t> cert_spki;
    ExpectTrue(tamga::core::CryptoniteAdapter::ExtractCertificateSubjectPublicKeyInfo(cert, cert_spki, err),
               "SPKI must be extractable from the certificate");
    ExpectTrue(key_spki == cert_spki,
               "The matched fixture pair must yield an identical SubjectPublicKeyInfo");

    // Позитив: сертифікат тієї самої пари приймається.
    ExpectTrue(tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(key, key_password, cert),
               "The certificate of the same pair must match the private key");

    // Fail-closed: чужий сертифікат мусить бути відкинутий. Це саме та перевірка,
    // яка не дає підписати дані сертифікатом, що не належить ключу.
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto foreign = ReadBinaryFixture(pki_dir / "root_certificate.cer");
    if (!foreign.empty()) {
        ExpectFalse(tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(key, key_password, foreign),
                    "A foreign certificate must never be accepted for this private key");
    }
#endif
}

// ТЗ Рівень 3: реєстр КНЕДП проти СПРАВЖНЬОГО `CAs.json` ЦЗО.
//
// Фікстура — не синтетика, а реальний файл (33 записи). Це принципово: формат
// має нерівності, які на вигаданому прикладі не зʼявились би — адреси то з
// шляхом (`ca.gp.gov.ua/cmp`), то без (`ca.tax.gov.ua`), порти то 80, то 43222,
// `cmpAddress` подекуди порожній, а `directAccess` присутній не в усіх записах.
void TestCaSettingsRegistryParsesRealCzoFile() {
    const auto path = tamga_test::TestDataRoot() / "tests" / "fixtures" /
                      "ca-registry" / "CAs.json";
    const auto bytes = ReadBinaryFixture(path);
    if (bytes.empty()) {
        RecordSkip("CAs.json fixture not available");
        return;
    }
    const std::string json(bytes.begin(), bytes.end());

    std::vector<tamga::core::net::CaSettingsEntry> entries;
    std::string error;
    ExpectTrue(tamga::core::net::CaSettingsRegistry::ParseJson(json, entries, error),
               "the real CAs.json must parse");
    ExpectTrue(entries.size() >= 30,
               "the CZO registry must yield the full set of CAs, not a truncated prefix");

    // Пошук за ЄДРПОУ — найточніша ознака.
    const auto* tax = tamga::core::net::CaSettingsRegistry::Find(entries, "43005393");
    ExpectTrue(tax != nullptr, "the CA must be findable by its EDRPOU");
    if (tax != nullptr) {
        ExpectTrue(tax->address == "ca.tax.gov.ua", "the EDRPOU lookup must return the right CA");
        // Адреса без шляху -> додається типовий шлях служби; порт 80 не пишемо.
        ExpectTrue(tax->ocsp_url == "http://ca.tax.gov.ua/services/ocsp/",
                   "OCSP URL must be assembled from address+port+path");
        ExpectTrue(tax->cmp_url == "http://ca.tax.gov.ua/services/cmp/",
                   "CMP URL must gain the default path when the address carries none");
        ExpectFalse(tax->issuer_cns.empty(), "issuerCNs must be captured");
    }

    // Пошук за адресою і за підрядком CN.
    ExpectTrue(tamga::core::net::CaSettingsRegistry::Find(entries, "ca.tax.gov.ua") != nullptr,
               "the CA must be findable by address");
    ExpectTrue(tamga::core::net::CaSettingsRegistry::Find(entries, "no-such-ca.example") == nullptr,
               "an unknown hint must not match anything");

    // Адреса, яка ВЖЕ містить шлях, не повинна отримати ще один.
    bool saw_explicit_path = false;
    for (const auto& e : entries) {
        if (e.cmp_url.find("/cmp") != std::string::npos &&
            e.cmp_url.find("/services/cmp/") == std::string::npos) {
            saw_explicit_path = true;
            ExpectTrue(e.cmp_url.find("/cmp/services/cmp/") == std::string::npos,
                       "an address that already carries a path must not get a second one");
        }
    }
    ExpectTrue(saw_explicit_path,
               "the fixture must still contain CAs whose cmpAddress carries an explicit path");

    // Нетиповий порт мусить лишитись у URL, типовий 80 — ні.
    bool saw_custom_port = false;
    for (const auto& e : entries) {
        if (e.ocsp_url.find(":43222") != std::string::npos) {
            saw_custom_port = true;
        }
        ExpectTrue(e.ocsp_url.find(":80/") == std::string::npos,
                   "the default HTTP port must not be written into the URL");
    }
    ExpectTrue(saw_custom_port, "CAs using a non-default OCSP port must keep it in the URL");

    // Сміття не має валити розбір у краш чи нескінченний цикл.
    std::vector<tamga::core::net::CaSettingsEntry> junk;
    std::string junk_error;
    ExpectFalse(tamga::core::net::CaSettingsRegistry::ParseJson("{\"not\":\"an array\"}", junk,
                                                                junk_error),
                "a non-array document must be rejected");
    ExpectFalse(tamga::core::net::CaSettingsRegistry::ParseJson("[{\"address\":\"a\",", junk,
                                                                junk_error),
                "a truncated document must be rejected, not silently accepted");
}

// ТЗ Рівень 3: структура CMP-запиту (RFC 4210 genm / id-it-caCerts).
// Живого КНЕДП у CI немає, тож перевіряється те, що перевірити МОЖНА — що
// повідомлення є коректним DER із потрібним OID і тегом тіла [21].
void TestCmpGenMessageStructure() {
    const auto msg = tamga::core::net::CmpCertificateFetcher::BuildCaCertsGenMessage();
    ExpectFalse(msg.empty(), "the CMP genm message must not be empty");
    ExpectTrue(msg.front() == 0x30, "PKIMessage must be a DER SEQUENCE");

    // Довжина в заголовку мусить відповідати фактичному розміру — інакше
    // приймальна сторона відкинула б запит як биту ASN.1.
    ExpectTrue(msg.size() > 2, "message must carry a length");
    std::size_t declared = 0;
    std::size_t header = 2;
    if ((msg[1] & 0x80) != 0) {
        const int n = msg[1] & 0x7F;
        header = 2 + static_cast<std::size_t>(n);
        for (int i = 0; i < n; ++i) {
            declared = (declared << 8) | msg[2 + static_cast<std::size_t>(i)];
        }
    } else {
        declared = msg[1];
    }
    ExpectTrue(header + declared == msg.size(),
               "the declared DER length must match the encoded message exactly");

    // id-it-caCerts = 1.3.6.1.5.5.7.4.17
    const std::vector<std::uint8_t> oid = {0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x11};
    ExpectTrue(std::search(msg.begin(), msg.end(), oid.begin(), oid.end()) != msg.end(),
               "the genm body must request id-it-caCerts (1.3.6.1.5.5.7.4.17)");
    // PKIBody genm — context-specific constructed [21] = 0xB5.
    ExpectTrue(std::find(msg.begin(), msg.end(), static_cast<std::uint8_t>(0xB5)) != msg.end(),
               "the body must be tagged [21] genm");

    // Виловлювання сертифікатів із довільного DER: у відповіді CMP сертифікат
    // лежить углибині PKIMessage, тож шукати треба структурно, а не за зміщенням.
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> cert;
    std::string key_password;
#if TAMGA_CRYPTONITE_ENABLED
    if (LoadResolverKeyPair(key, cert, key_password) && !cert.empty()) {
        std::vector<std::uint8_t> wrapped = {0x30, 0x82, 0x00, 0x00, 0xA0, 0x03};
        wrapped.insert(wrapped.end(), cert.begin(), cert.end());
        wrapped.push_back(0x00);
        const auto harvested = tamga::core::net::CmpCertificateFetcher::HarvestCertificates(wrapped);
        ExpectTrue(harvested.size() == 1,
                   "exactly the embedded certificate must be harvested from the response");
        if (harvested.size() == 1) {
            ExpectTrue(harvested.front() == cert,
                       "the harvested bytes must be the certificate, byte-for-byte");
        }
        // Сміття без сертифікатів не має давати кандидатів.
        const std::vector<std::uint8_t> noise(512, 0x30);
        ExpectTrue(tamga::core::net::CmpCertificateFetcher::HarvestCertificates(noise).empty(),
                   "noise must not be mistaken for certificates");
    }
#else
    (void)key; (void)cert; (void)key_password;
#endif
}

// ТЗ Рівень 3: мережеві джерела не мають жодних привілеїв.
//
// Ключова властивість: fetcher лише ПРОПОНУЄ кандидатів, а приймає їх той самий
// `CertificateMatchesPrivateKey`, що й для sidecar/кешу. Живої LDAP-служби в CI
// немає, тож транспорт підмінюється — перевіряється саме поведінка резолвера,
// а не мережа. Перевіряти тут треба насамперед НЕГАТИВ: якби мережевий кандидат
// приймався без звірки, підпис створювався б чужим сертифікатом.
void TestCertificateResolverNetworkSourcesFailClosed() {
#if TAMGA_CRYPTONITE_ENABLED
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> cert;
    std::string key_password;
    if (!LoadResolverKeyPair(key, cert, key_password)) {
        RecordSkip("PKI PEM fixtures not available");
        return;
    }
    std::string probe_err;
    std::vector<std::uint8_t> probe_spki;
    if (!tamga::core::CryptoniteAdapter::ExtractSubjectPublicKeyInfo(key, key_password, probe_spki,
                                                                     probe_err)) {
        RecordSkip("SPKI extraction unsupported for this fixture");
        return;
    }

    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto foreign = ReadBinaryFixture(pki_dir / "root_certificate.cer");

    const auto base = std::filesystem::temp_directory_path() /
                      ("tamga-resolver-net-" + std::to_string(std::time(nullptr)));
    std::error_code ec;
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code e;
            std::filesystem::remove_all(path, e);
        }
    } cleanup{base};

    auto make_request = [&](const std::string& work) {
        tamga::core::net::CertificateResolveRequest req;
        req.key_material = key;
        req.password = key_password;
        req.work_dir = work;
        req.offline_mode = false;  // Рівень 3 працює лише онлайн
        req.ldap_url = "ldap://ca.example.ua:389";
        req.ldap_base_dn = "ou=certificates,o=example";
        req.subject_identifier = "1234567890";
        return req;
    };

    // ── 1. Каталог віддає ЧУЖИЙ сертифікат ────────────────────────────────────
    if (!foreign.empty()) {
        const auto work = base / "reject";
        std::filesystem::create_directories(work, ec);
        tamga::core::net::LdapCertificateFetcher::ScopedMockTransport transport(
            [&](const tamga::core::net::CertificateFetchRequest& request) {
                tamga::core::net::CertificateFetchResult r;
                // Підказка мусить долітати до джерела — інакше фільтр каталогу
                // будувався б без неї, і вибірка була б іншою.
                ExpectTrue(request.subject_hint == "1234567890",
                           "the subject hint must reach the LDAP fetcher");
                ExpectTrue(request.base_dn == "ou=certificates,o=example",
                           "the base DN must reach the LDAP fetcher");
                r.executed = true;
                r.candidates.push_back(foreign);
                return r;
            });

        auto res = tamga::core::net::CertificateResolver{}.Resolve(make_request(work.string()));
        ExpectFalse(res.succeeded,
                    "a certificate fetched over the network that does not match the key must be "
                    "REJECTED — the network has no privilege over sidecar or cache");
        ExpectTrue(res.rejected_candidates > 0,
                   "the rejected network candidate must be counted, not silently dropped");
        ExpectTrue(res.certificate_der.empty(),
                   "no certificate may be returned when nothing matched (fail-closed)");
        ExpectTrue(std::filesystem::is_empty(work / "cert-cache", ec) ||
                       !std::filesystem::exists(work / "cert-cache", ec),
                   "a rejected candidate must never reach the cache");
    }

    // ── 2. Каталог віддає ПРАВИЛЬНИЙ сертифікат (серед чужих) ─────────────────
    {
        const auto work = base / "accept";
        std::filesystem::create_directories(work, ec);
        tamga::core::net::LdapCertificateFetcher::ScopedMockTransport transport(
            [&](const tamga::core::net::CertificateFetchRequest&) {
                tamga::core::net::CertificateFetchResult r;
                r.executed = true;
                if (!foreign.empty()) {
                    r.candidates.push_back(foreign);  // шум перед потрібним
                }
                r.candidates.push_back(cert);
                return r;
            });

        auto res = tamga::core::net::CertificateResolver{}.Resolve(make_request(work.string()));
        ExpectTrue(res.succeeded, "the matching certificate must be found among the candidates");
        ExpectTrue(res.source == "ldap", "the resolution source must be reported as ldap");
        ExpectTrue(res.certificate_der == cert, "the resolved certificate must be the matching one");
        // Мережевий результат мусить осісти в кеші — інакше наступний підпис
        // офлайн знову впав би, і Рівень 3 не мав би сенсу.
        const auto cache_file = work / "cert-cache" / (res.spki_sha256 + ".cer");
        ExpectTrue(std::filesystem::exists(cache_file, ec),
                   "a network-resolved certificate must be cached for offline reuse");
    }

    // ── 3. Джерело недоступне ─────────────────────────────────────────────────
    {
        const auto work = base / "down";
        std::filesystem::create_directories(work, ec);
        tamga::core::net::LdapCertificateFetcher::ScopedMockTransport transport(
            [](const tamga::core::net::CertificateFetchRequest&) {
                tamga::core::net::CertificateFetchResult r;
                r.executed = false;  // не змогли запитати
                r.message = "LDAP fetch: connect failed";
                return r;
            });

        auto res = tamga::core::net::CertificateResolver{}.Resolve(make_request(work.string()));
        ExpectFalse(res.succeeded, "an unreachable directory must not produce a certificate");
        ExpectContains(res.message, "connect failed",
                       "the failure must state WHY the network step did not help");
    }

    // ── 4. Онлайн, але жодного джерела не налаштовано ─────────────────────────
    {
        const auto work = base / "unset";
        std::filesystem::create_directories(work, ec);
        tamga::core::net::CertificateResolveRequest req;
        req.key_material = key;
        req.password = key_password;
        req.work_dir = work.string();
        req.offline_mode = false;
        auto res = tamga::core::net::CertificateResolver{}.Resolve(req);
        ExpectFalse(res.succeeded, "without a configured source nothing can be resolved");
        ExpectContains(res.message, "no network source configured",
                       "the message must distinguish 'not configured' from 'not found'");
    }
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

// П-05. Mock-seam трьох мережевих джерел (`LdapTransport` / `HttpTransport` /
// `CmpTransport`) був набором голих глобальних `std::function` без будь-якої
// синхронізації: `ScopedMockTransport` їх писав, `Fetch` читав.
//
// МЕЖА ЦЬОГО ТЕСТУ, названа прямо: він НЕ доводить відсутності гонки даних.
// Під MSVC немає ThreadSanitizer, а ASan гонок не ловить; багатопотоковий
// тест може роками не влучити у вікно. Доказом виправлення є код-рев'ю і
// зіставлення з мутекс-захищеним близнюком у `core/HttpClient.cpp`, а не цей
// прогін.
//
// Що тест справді перевіряє — КОРЕКТНІСТЬ під конкурентним доступом: поки
// один потік ставить і знімає мок, читачі отримують або повний результат
// мока, або повну відмову «джерело не налаштоване», і ніколи — щось третє.
// Стан «між» означав би виклик порожньої `std::function` (стара реалізація
// читала глобал двічі: окремо для перевірки й окремо для виклику).
//
// URL навмисно порожній: без мока шлях завершується до будь-якого
// мережевого виклику, тож тест не залежить від мережі.
//
// Емпірика (записана, щоб не переоцінювати цю пробу): на СТАРОМУ коді вона
// аварійно завершувала бінарник у 5 прогонах із 6 — `0xC0000409`, тобто
// __fastfail від `std::bad_function_call` на другому читанні глобала. Один
// прогін із шести проходив чисто. Тобто проба ловить дефект часто, але
// «зелено» на ній нічого не доводить — саме тому вона названа пробою, а не
// доказом.
void TestCertificateFetcherMockSeamIsConsistentUnderConcurrency() {
    using tamga::core::net::CertificateFetchRequest;
    using tamga::core::net::CertificateFetchResult;
    using tamga::core::net::HttpCertificateFetcher;

    const std::vector<std::uint8_t> mocked_candidate{0x30, 0x03, 0x02, 0x01, 0x00};
    const std::string unmocked_message = "HTTP fetch: no certificate URL configured";

    constexpr int kReaderCount = 4;
    std::atomic<bool> stop{false};
    std::atomic<int> ready{0};
    std::atomic<int> mocked{0};
    std::atomic<int> unmocked{0};
    std::atomic<int> inconsistent{0};

    std::vector<std::thread> readers;
    for (int i = 0; i < kReaderCount; ++i) {
        readers.emplace_back([&]() {
            ready.fetch_add(1, std::memory_order_relaxed);
            while (!stop.load(std::memory_order_relaxed)) {
                CertificateFetchRequest request;
                const CertificateFetchResult result = HttpCertificateFetcher::Fetch(request);
                if (result.executed && result.candidates.size() == 1U &&
                    result.candidates.front() == mocked_candidate) {
                    mocked.fetch_add(1, std::memory_order_relaxed);
                } else if (!result.executed && result.candidates.empty() &&
                           result.message == unmocked_message) {
                    unmocked.fetch_add(1, std::memory_order_relaxed);
                } else {
                    inconsistent.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    // Без цього очікування писар устигав відпрацювати всі цикли ДО того, як
    // читачі стартують, і проба мовчки не перевіряла нічого.
    while (ready.load(std::memory_order_relaxed) < kReaderCount) {
        std::this_thread::yield();
    }

    for (int i = 0; i < 500; ++i) {
        HttpCertificateFetcher::ScopedMockTransport mock(
            [&mocked_candidate](const CertificateFetchRequest&) {
                CertificateFetchResult r;
                r.executed = true;
                r.candidates.push_back(mocked_candidate);
                return r;
            });
        std::this_thread::yield();
    }

    stop.store(true, std::memory_order_relaxed);
    for (auto& reader : readers) {
        reader.join();
    }

    ExpectTrue(inconsistent.load() == 0,
               "concurrent Fetch must never observe a half-installed mock transport");
    ExpectTrue(mocked.load() + unmocked.load() > 0,
               "the concurrency probe must actually have executed Fetch");
}

void TestCertificateResolverSidecarCacheAndFailClosed() {
#if TAMGA_CRYPTONITE_ENABLED
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> cert;
    std::string key_password;
    if (!LoadResolverKeyPair(key, cert, key_password)) {
        RecordSkip("PKI PEM fixtures not available");
        return;
    }
    std::string probe_err;
    std::vector<std::uint8_t> probe_spki;
    if (!tamga::core::CryptoniteAdapter::ExtractSubjectPublicKeyInfo(key, key_password, probe_spki, probe_err)) {
        RecordSkip("SPKI extraction unsupported for this fixture");
        return;
    }

    const auto base = std::filesystem::temp_directory_path() /
                      ("tamga-resolver-" + std::to_string(std::time(nullptr)));
    const auto key_dir = base / "keys";
    const auto work_dir = base / "work";
    std::error_code ec;
    std::filesystem::create_directories(key_dir, ec);
    std::filesystem::create_directories(work_dir, ec);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code e;
            std::filesystem::remove_all(path, e);
        }
    } cleanup{base};

    const auto key_path = key_dir / "signer.dat";
    WriteBinaryFile(key_path, key);

    // ── ТЗ §6.1: sidecar `.cer` поруч із ключем ───────────────────────────────
    WriteBinaryFile(key_dir / "signer.cer", cert);
    tamga::core::net::CertificateResolveRequest req;
    req.key_material = key;
    req.password = key_password;
    req.key_file_path = key_path.string();
    req.work_dir = work_dir.string();
    req.offline_mode = true;

    auto res = tamga::core::net::CertificateResolver{}.Resolve(req);
    ExpectTrue(res.succeeded, "Sidecar .cer next to the key must be discovered");
    ExpectTrue(res.source == "sidecar", "Resolution source must be reported as sidecar");
    ExpectTrue(res.certificate_der == cert, "Resolved certificate must be the sidecar certificate");
    ExpectFalse(res.spki_sha256.empty(), "Resolver must report the SPKI fingerprint");

    // Успішний sidecar-резолв мусить наповнити кеш — інакше офлайн-робота після
    // видалення sidecar була б неможливою.
    const auto cache_file = work_dir / "cert-cache" / (res.spki_sha256 + ".cer");
    ExpectTrue(std::filesystem::exists(cache_file, ec),
               "A locally resolved certificate must be written to cert-cache");

    // ── ТЗ §6.2: читання з кешу, коли sidecar більше немає ────────────────────
    std::filesystem::remove(key_dir / "signer.cer", ec);
    auto cached = tamga::core::net::CertificateResolver{}.Resolve(req);
    ExpectTrue(cached.succeeded, "Certificate must still resolve from cert-cache without a sidecar");
    ExpectTrue(cached.source == "cache", "Resolution source must be reported as cache");

    // ── ТЗ §6.4: fail-closed на невідповідному сертифікаті ────────────────────
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto foreign = ReadBinaryFixture(pki_dir / "root_certificate.cer");
    if (!foreign.empty()) {
        // Чистий work_dir, щоб кеш попереднього кроку не давав хибного успіху.
        const auto empty_work = base / "work2";
        std::filesystem::create_directories(empty_work, ec);
        WriteBinaryFile(key_dir / "signer.cer", foreign);

        tamga::core::net::CertificateResolveRequest bad;
        bad.key_material = key;
        bad.password = key_password;
        bad.key_file_path = key_path.string();
        bad.work_dir = empty_work.string();
        bad.offline_mode = true;
        auto rejected = tamga::core::net::CertificateResolver{}.Resolve(bad);
        ExpectFalse(rejected.succeeded,
                    "A sidecar certificate that does not match the key must be rejected");
        ExpectTrue(rejected.rejected_candidates > 0,
                   "The rejected foreign candidate must be counted, not silently ignored");
        ExpectTrue(rejected.certificate_der.empty(),
                   "No certificate may be returned when nothing matched (fail-closed)");

        // Явно переданий невідповідний сертифікат — помилка конфігурації, і
        // резолвер не має права підмінити його чимось іншим.
        tamga::core::net::CertificateResolveRequest explicit_bad;
        explicit_bad.key_material = key;
        explicit_bad.password = key_password;
        bad.password = key_password;
        explicit_bad.explicit_certificate_der = foreign;
        explicit_bad.work_dir = empty_work.string();
        explicit_bad.offline_mode = true;
        auto explicit_res = tamga::core::net::CertificateResolver{}.Resolve(explicit_bad);
        ExpectFalse(explicit_res.succeeded,
                    "An explicitly supplied mismatched certificate must fail, not fall through");
    }

    // ── Q-02: відносний шлях до ключа БЕЗ каталогу ────────────────────────────
    //
    // Типовий виклик CLI — `--key key.dat` із поточного каталогу. `ResolveFilePath`
    // за порожнього `base_path` лишає такий шлях відносним («key.dat»), тому в
    // резолвер приходить саме гола назва файлу. Раніше порожній `parent_path()`
    // трактувався як «каталогу немає», список кандидатів виходив порожнім, і
    // сертифікат поруч із ключем не знаходився взагалі — навіть коли лежав там.
    //
    // `work_dir` тут щоразу свіжий і порожній: успіх має прийти рівно від
    // sidecar-пошуку, а не від кешу попередніх кроків.
    {
        const auto rel_dir = base / "relative";
        const auto rel_work = base / "work4";
        const auto dot_work = base / "work5";
        std::filesystem::create_directories(rel_dir, ec);
        std::filesystem::create_directories(rel_work, ec);
        std::filesystem::create_directories(dot_work, ec);
        WriteBinaryFile(rel_dir / "signer.dat", key);
        WriteBinaryFile(rel_dir / "signer.cer", cert);

        struct CwdGuard {
            std::filesystem::path previous;
            explicit CwdGuard(const std::filesystem::path& next) {
                std::error_code e;
                previous = std::filesystem::current_path(e);
                std::filesystem::current_path(next, e);
            }
            CwdGuard(const CwdGuard&) = delete;
            CwdGuard& operator=(const CwdGuard&) = delete;
            ~CwdGuard() {
                std::error_code e;
                if (!previous.empty()) {
                    std::filesystem::current_path(previous, e);
                }
            }
        } cwd_guard{rel_dir};

        tamga::core::net::CertificateResolveRequest relative;
        relative.key_material = key;
        relative.password = key_password;
        relative.key_file_path = "signer.dat";  // саме те, що віддає ResolveFilePath
        relative.work_dir = rel_work.string();
        relative.offline_mode = true;
        auto rel_res = tamga::core::net::CertificateResolver{}.Resolve(relative);
        ExpectTrue(rel_res.succeeded,
                   "A sidecar next to a bare relative key path must be discovered");
        ExpectTrue(rel_res.source == "sidecar",
                   "A bare relative key path must resolve via sidecar, not cache or network");
        ExpectTrue(rel_res.certificate_der == cert,
                   "The certificate next to the relative key path must be the sidecar one");

        // `./signer.dat` у явному вигляді дефекту НЕ мав: `parent_path()` тут
        // дорівнює «.», а не порожньому рядку, тому кандидати збиралися й
        // раніше. (Через `ResolveFilePath` така форма взагалі не доходить —
        // `lexically_normal()` перетворює її на «signer.dat», тобто на випадок
        // вище.) Тримаємо як сторожа: після фіксу обидві форми мають лишатися
        // рівноцінними.
        relative.key_file_path = "./signer.dat";
        relative.work_dir = dot_work.string();
        auto dot_res = tamga::core::net::CertificateResolver{}.Resolve(relative);
        ExpectTrue(dot_res.succeeded,
                   "A './key.dat' style relative path must behave identically");
        ExpectTrue(dot_res.source == "sidecar",
                   "A './key.dat' style relative path must also resolve via sidecar");
    }

    // Офлайн-режим не має робити мережевих спроб і мусить чесно про це сказати.
    tamga::core::net::CertificateResolveRequest no_local;
    no_local.key_material = key;
    no_local.password = key_password;
    no_local.work_dir = (base / "work3").string();
    no_local.offline_mode = true;
    auto offline_res = tamga::core::net::CertificateResolver{}.Resolve(no_local);
    ExpectFalse(offline_res.succeeded, "Offline resolution without local material must fail");
    ExpectContains(offline_res.message, "offline",
                   "Offline refusal must state that network lookup was forbidden");
#endif
}

// F-04: ValidationEngine більше не припускає, що криптографія зійшлася.
//
// Раніше в SynthesizeDecision йшла константа `kSignatureCryptoValidAssumed = true`:
// припущення було істинним для тодішніх викликачів, але НЕ перевірялося. Будь-який
// новий шлях, що забув би перевірити підпис, отримав би VALID-вердикт від самого
// лише руху ланцюга й відкликання — тобто хибнопозитив у найгіршому місці.
//
// Тепер це явний вхід ValidationContext із fail-closed типовим значенням.
// Тест навмисно НЕ заповнює його — саме та ситуація «викликач забув».
void TestValidationEngineFailsClosedWithoutCryptoVerdict() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for the fail-closed check");
    if (!fixture.valid) {
        return;
    }

    tamga::core::validation::ValidationContext ctx;
    ctx.profile = tamga::core::validation::ValidationProfile::Compatibility;
    ctx.level = tamga::core::validation::ValidationLevel::Basic;
    ctx.offline = true;
    // signature_crypto_valid свідомо НЕ виставляємо -> має лишитись false.
    ExpectFalse(ctx.signature_crypto_valid,
                "ValidationContext.signature_crypto_valid must default to false (fail-closed)");

    const auto report =
        tamga::core::validation::ValidationEngine{}.Validate(ctx, fixture.cert_der, {});
    ExpectFalse(report.decision.signature_valid,
                "without a crypto verdict the decision must NOT report signature_valid=true");
    ExpectTrue(report.decision.overall_status != tamga::core::validation::OverallStatus::Valid,
               "without a crypto verdict the overall status must not be Valid");

    bool explained = false;
    for (const auto& reason : report.decision.because) {
        if (reason.find("Криптографічна перевірка") != std::string::npos) {
            explained = true;
            break;
        }
    }
    ExpectTrue(explained,
               "the report must SAY that the crypto verdict was missing, otherwise the rejection "
               "looks like a chain or trust failure");

    // Контрольний бік: із підтвердженою криптографією той самий вхід більше не
    // блокується саме цією причиною (довіра може падати з інших підстав — це не
    // предмет цього тесту).
    ctx.signature_crypto_valid = true;
    const auto confirmed =
        tamga::core::validation::ValidationEngine{}.Validate(ctx, fixture.cert_der, {});
    bool still_complaining = false;
    for (const auto& reason : confirmed.decision.because) {
        if (reason.find("Криптографічна перевірка") != std::string::npos) {
            still_complaining = true;
            break;
        }
    }
    ExpectFalse(still_complaining,
                "with signature_crypto_valid=true the missing-crypto reason must disappear");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}
