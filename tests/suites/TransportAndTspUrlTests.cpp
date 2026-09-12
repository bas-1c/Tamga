// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Транспорт (HTTP, TSP) і вибір адреси TSA. Тут закріплено політику
// призначення: приватні адреси, DNS-rebinding і приватний редірект
// блокуються.

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
#include "core/net/HttpAccessPolicy.h"
#include "core/net/HttpMessageSyntax.h"
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

void TestTspClientMocked() {
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestTspClientMocked ---\n";
    std::vector<std::uint8_t> hash = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<std::uint8_t> token;
    std::string err;
    bool ok = TspClient::GetTimestamp(hash, "1.2.804.2.1.1.1.1.2.1.1", "invalid-tsp-url", 500, "", token, err);
    ExpectFalse(ok, "TspClient should fail with syntactically invalid URL");
    ExpectFalse(err.empty(), "Error message should not be empty on failure");
}

void TestHttpClientMockPost() {
    tamga::core::HttpClient::ScopedMockTransport mock(
        [](const tamga::core::HttpRequest& request) {
            tamga::core::HttpResponse response;
            response.succeeded = true;
            response.status_code = 200;
            response.body = std::vector<std::uint8_t>{'<','o','k','/','>'};
            response.message = request.url;
            return response;
        });

    auto result = tamga::core::HttpClient::Post(
        "https://example.test/tl.xml",
        std::vector<std::uint8_t>{},
        "application/xml",
        1000);

    ExpectTrue(result.succeeded, "Mocked HTTP POST should succeed");
    ExpectTrue(result.status_code == 200, "Mocked HTTP POST should preserve status code");
    ExpectTrue(std::string(result.body.begin(), result.body.end()) == "<ok/>",
               "Mocked HTTP POST should return configured body");
}

void TestHttpDestinationPolicyBlocksNonPublicAddresses() {
    const std::vector<std::string> denied = {
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://[::ffff:127.0.0.1]/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://metadata.google.internal/",
    };
    for (const auto& url : denied) {
        const auto result = tamga::core::HttpClient::CheckDestination(url);
        ExpectFalse(result.allowed, ("Destination policy must reject " + url).c_str());
    }
}

void TestHttpDestinationPolicyRejectsDnsRebindingAndPrivateRedirect() {
    std::atomic<int> calls{0};
    std::atomic<int> rebinding_resolutions{0};
    tamga::core::HttpClient::ScopedMockResolver resolver(
        [&rebinding_resolutions](const std::string& host) {
            if (host == "mixed-dns.example") {
                return std::vector<std::string>{"93.184.216.34", "10.20.30.40"};
            }
            if (host == "rebinding.example") {
                return rebinding_resolutions.fetch_add(1) == 0
                    ? std::vector<std::string>{"93.184.216.34"}
                    : std::vector<std::string>{"127.0.0.1"};
            }
            return std::vector<std::string>{"93.184.216.34"};
        });
    tamga::core::HttpClient::ScopedMockTransport transport(
        [&calls](const tamga::core::HttpRequest& request) {
            ++calls;
            tamga::core::HttpResponse response;
            if (request.url == "https://public.example/start") {
                response.status_code = 302;
                response.response_headers = "Location: http://127.0.0.1/private\r\n";
                response.message = "redirect";
                return response;
            }
            response.succeeded = true;
            response.status_code = 200;
            return response;
        });

    const auto mixed_dns = tamga::core::HttpClient::Get(
        "https://mixed-dns.example/certificate.cer", "application/pkix-cert", 1000);
    ExpectFalse(mixed_dns.attempted, "DNS response containing any private address must be rejected before transport");
    ExpectTrue(calls.load() == 0, "Mixed public/private DNS answer must not reach HTTP transport");

    const auto rebinding = tamga::core::HttpClient::Get(
        "https://rebinding.example/certificate.cer", "application/pkix-cert", 1000);
    ExpectFalse(rebinding.attempted, "Destination must be re-resolved and rejected if DNS rebinds to private");
    ExpectTrue(rebinding_resolutions.load() >= 2, "DNS rebinding test must perform repeated policy resolution");
    ExpectTrue(calls.load() == 0, "DNS rebinding candidate must not reach HTTP transport");

    const auto redirected = tamga::core::HttpClient::Get(
        "https://public.example/start", "application/pkix-cert", 1000);
    ExpectFalse(redirected.succeeded, "Public-to-private redirect must be rejected");
    ExpectTrue(calls.load() == 1, "Redirect target must be rejected before a second transport call");
}

// П-08. Класифікатор IP має ТРИ стани, і раніше дві точки його застосування
// розходилися замовчуванням: перевірка призначення вимагала `== Public`, а
// перевірка фактичної peer-адреси зʼєднання питала `!= Blocked`. Через це все,
// що не розпізналося як IP, на другому шляху проходило.
//
// Тест б'є саме по цьому: рядки, які не є IP-адресою, мають бути відхилені.
// На старій логіці (`!= Blocked`) кожен із них повертав `true`.
void TestPeerAddressPolicyIsFailClosedForNonIpText() {
    using tamga::core::detail::IsAllowedPublicAddress;

    // Публічні адреси лишаються дозволеними — інакше «fail-closed» перетворився б
    // на «нічого не працює», і тест не мав би сенсу.
    ExpectTrue(IsAllowedPublicAddress("93.184.216.34"),
               "Public IPv4 peer address must stay allowed");
    ExpectTrue(IsAllowedPublicAddress("2001:4860:4860::8888"),
               "Public IPv6 peer address must stay allowed");

    // Заблоковані діапазони — те, що стара перевірка й так ловила.
    ExpectFalse(IsAllowedPublicAddress("127.0.0.1"), "Loopback peer address must be denied");
    ExpectFalse(IsAllowedPublicAddress("10.0.0.1"), "RFC1918 peer address must be denied");
    ExpectFalse(IsAllowedPublicAddress("169.254.169.254"), "Metadata peer address must be denied");
    ExpectFalse(IsAllowedPublicAddress("::1"), "IPv6 loopback peer address must be denied");

    // Ядро регресії: NotAnIp. Стара перевірка (`!= Blocked`) на кожному з цих
    // рядків казала «публічна».
    ExpectFalse(IsAllowedPublicAddress(""), "Empty peer address text must be denied");
    ExpectFalse(IsAllowedPublicAddress("internal.example"),
                "Hostname instead of a peer address must be denied");
    ExpectFalse(IsAllowedPublicAddress("not-an-ip"), "Unparseable peer address must be denied");
    ExpectFalse(IsAllowedPublicAddress("93.184.216.34 "),
                "Peer address with trailing garbage must be denied");
    ExpectFalse(IsAllowedPublicAddress("fe80::1%eth0"),
                "Scoped IPv6 literal is not parsed as an address and must be denied");
}

// Той самий інваріант на другій точці застосування: якщо резолвер повернув
// щось, що не є IP-адресою, призначення відхиляється до транспортного виклику.
// Ця гілка була правильною й раніше — тест закріплює її як сторожа, щоб
// вирівнювання полярності не «полагодило» її у зворотний бік.
void TestHttpDestinationPolicyRejectsNonIpResolverAnswer() {
    std::atomic<int> calls{0};
    tamga::core::HttpClient::ScopedMockResolver resolver(
        [](const std::string& host) -> std::vector<std::string> {
            if (host == "bogus-dns.example") {
                return {"not-an-ip"};
            }
            if (host == "partly-bogus-dns.example") {
                return {"93.184.216.34", "internal.example"};
            }
            return {"93.184.216.34"};
        });
    tamga::core::HttpClient::ScopedMockTransport transport(
        [&calls](const tamga::core::HttpRequest&) {
            ++calls;
            tamga::core::HttpResponse response;
            response.succeeded = true;
            response.status_code = 200;
            return response;
        });

    const auto bogus = tamga::core::HttpClient::Get(
        "https://bogus-dns.example/certificate.cer", "application/pkix-cert", 1000);
    ExpectFalse(bogus.attempted, "Resolver answer that is not an IP address must be rejected");

    const auto partly = tamga::core::HttpClient::Get(
        "https://partly-bogus-dns.example/certificate.cer", "application/pkix-cert", 1000);
    ExpectFalse(partly.attempted,
                "One unparseable address in the DNS answer must reject the destination");
    ExpectTrue(calls.load() == 0, "Unparseable DNS answers must not reach HTTP transport");
}

void TestResolveDefaultTspUrl() {
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestResolveDefaultTspUrl ---\n";
    Session session;
    ExpectTrue(session.ResolveDefaultTspUrl().empty(), "Should return empty when no key is loaded");

#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    if (fixture.valid) {
        ExpectTrue(PrepareInitializedSession(session), "Session should initialize");
        ExpectSessionTrue(session,
            session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
            "ReadPrivateKeyBinary should load key");
        ExpectTrue(session.ResolveDefaultTspUrl().empty(), "Should return empty for mock CN");
    }
#endif
}

// ME-06 (повний фікс): Session::ResolveDefaultTspUrl (і транзитивно
// SignData/SignDataInternal) МАЄ віддавати перевагу TL-based резолюції над
// хардкод-таблицею issuer DN, коли в workDir є синхронізований TL-кеш із
// granted TSA-сервісом. Мок-сертифікат фікстури не збігається з жодним
// записом хардкод-таблиці (підтверджено вище в TestResolveDefaultTspUrl),
// тож ненульовий результат тут можливий ЛИШЕ через TL-шлях.
void TestSessionResolveDefaultTspUrlPrefersTrustListOverIssuerTable() {
#if TAMGA_CRYPTONITE_ENABLED
    std::cerr << "--- TestSessionResolveDefaultTspUrlPrefersTrustListOverIssuerTable ---\n";
    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    const auto work_dir = MakeTemporaryFixturePath(".session-tsp-resolve");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir, ec);

    const auto xml = BuildTrustListXmlForTest("http://czo.gov.ua/TrstSvc/Svctype/National-TSA/QTST",
                                              "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted");
    tamga::core::policy::TrustListParser parser;
    const auto parsed = parser.Parse(std::string(xml.begin(), xml.end()));
    ExpectTrue(parsed.ok, "Synthetic TSA TL XML should parse (Session ME-06 test)");

    tamga::core::policy::PolicyCache cache(work_dir.string());
    tamga::core::policy::PolicyCacheState state;
    state.source_url = "https://example.test/tl.xml";
    state.cache_status = "fresh";
    state.last_sync = "2026-06-15T00:00:00Z";
    state.update_succeeded = true;
    ExpectTrue(cache.WriteTrustListMaterialized(xml, state, parsed),
               "PolicyCache should materialize TSA metadata (Session ME-06 test)");

    tamga::core::Session session;
    tamga::core::Settings settings;
    settings.offline_mode = true;  // ME-06: локальний TL-кеш дозволено читати й offline
    settings.work_dir = work_dir.string();
    ExpectTrue(session.SetSettings(settings), "SetSettings should succeed (Session ME-06 test)");
    ExpectTrue(session.Initialize(), "Session should initialize (Session ME-06 test)");
    ExpectSessionTrue(session,
        session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
        "ReadPrivateKeyBinary should load key (Session ME-06 test)");

    ExpectTrue(session.ResolveDefaultTspUrl() == "https://example.test/tsp",
              "ME-06: Session::ResolveDefaultTspUrl must prefer the TL-based TSA endpoint "
              "over the hardcoded issuer table");

    std::filesystem::remove_all(work_dir, ec);
#endif
}

// п.18: політика мережевого доступу тепер живе окремо від транспорту
// (`core/net/HttpAccessPolicy`), і саме тому її можна викликати НАПРЯМУ —
// без WinHTTP, без глобальних мок-сем, без мережі. До розділення кожна така
// перевірка мусила йти крізь живий HTTP-клієнт, і саме тому розходження
// полярності П-08 прожило стільки, скільки прожило.
//
// Резолвер передається параметром, тож тут перевіряється рівно те, що
// вирішує політика, і нічого понад те.
void TestHttpAccessPolicyIsCallableWithoutTransport() {
    using tamga::core::net::CheckDestination;
    using tamga::core::net::ClassifyIpAddress;
    using tamga::core::net::IpClassification;
    using tamga::core::net::ParseDestinationUrl;

    // Розбір URL: схема, порт, крапка в кінці імені, IPv6 у дужках.
    ExpectTrue(ParseDestinationUrl("https://ca.example.ua/tsp").valid,
               "Plain HTTPS URL must parse");
    ExpectTrue(ParseDestinationUrl("https://CA.Example.UA./tsp").host == "ca.example.ua",
               "Host must be lowercased and the trailing root dot dropped");
    ExpectFalse(ParseDestinationUrl("ftp://ca.example.ua/tsp").valid,
                "Non-HTTP(S) scheme must be rejected by the policy, not by the transport");
    ExpectFalse(ParseDestinationUrl("https://ca.example.ua:0/tsp").valid,
                "Port 0 must be rejected");
    ExpectFalse(ParseDestinationUrl("https://fe80::1/tsp").valid,
                "Bare IPv6 literal without brackets must be rejected");

    // Три стани класифікатора — саме тритактність і є змістом П-08.
    ExpectTrue(ClassifyIpAddress("93.184.216.34") == IpClassification::Public,
               "Public IPv4 must classify as Public");
    ExpectTrue(ClassifyIpAddress("169.254.169.254") == IpClassification::Blocked,
               "Metadata address must classify as Blocked");
    ExpectTrue(ClassifyIpAddress("ca.example.ua") == IpClassification::NotAnIp,
               "A hostname is neither Public nor Blocked — the third state must survive");

    // Десяткова та восьмерична форми того самого loopback: обхід, який
    // перевірка «за текстом» пропустила б.
    ExpectTrue(ClassifyIpAddress("2130706433") == IpClassification::Blocked,
               "Decimal form of 127.0.0.1 must be blocked");
    ExpectTrue(ClassifyIpAddress("0177.0.0.1") == IpClassification::Blocked,
               "Octal form of 127.0.0.1 must be blocked");

    // IPv6 transition-діапазони. Коментар у класифікаторі обіцяв, що всі вони
    // fail-closed, а код віддавав `Public` усьому в 2000::/3 — зокрема 6to4 і
    // Teredo, у які IPv4 вкладена. Це та сама помилка полярності, що дала
    // П-08, лише по осі «коментар обіцяє більше, ніж робить код».
    ExpectTrue(ClassifyIpAddress("2001:4860:4860::8888") == IpClassification::Public,
               "An ordinary global unicast address must stay Public");
    ExpectTrue(ClassifyIpAddress("2002:7f00:1::") == IpClassification::Blocked,
               "6to4 with 127.0.0.1 embedded must be judged by the embedded IPv4");
    ExpectTrue(ClassifyIpAddress("2002:a00:1::") == IpClassification::Blocked,
               "6to4 with 10.0.0.1 embedded must be blocked as the private IPv4 it carries");
    ExpectTrue(ClassifyIpAddress("2002:a9fe:a9fe::") == IpClassification::Blocked,
               "6to4 with the metadata address embedded must be blocked");
    ExpectTrue(ClassifyIpAddress("2002:5db8:d822::") == IpClassification::Public,
               "6to4 with a public IPv4 embedded stays Public — the range is not blocked wholesale");
    ExpectTrue(ClassifyIpAddress("2001::1") == IpClassification::Blocked,
               "Teredo 2001::/32 is blocked with the whole IETF Protocol Assignments 2001::/23");
    ExpectTrue(ClassifyIpAddress("2001:2::1") == IpClassification::Blocked,
               "Benchmarking 2001:2::/48 falls under the same 2001::/23 rule");
    ExpectTrue(ClassifyIpAddress("2001:db8::1") == IpClassification::Blocked,
               "Documentation 2001:db8::/32 must remain blocked");
    ExpectTrue(ClassifyIpAddress("3fff::1") == IpClassification::Blocked,
               "Documentation 3fff::/20 (RFC 9637) must be blocked");
    ExpectTrue(ClassifyIpAddress("64:ff9b::7f00:1") == IpClassification::Blocked,
               "NAT64 well-known prefix carrying 127.0.0.1 must be judged by the embedded IPv4");
    ExpectTrue(ClassifyIpAddress("64:ff9b::5db8:d822") == IpClassification::Public,
               "NAT64 well-known prefix carrying a public IPv4 stays Public");
    ExpectTrue(ClassifyIpAddress("64:ff9b:1::1") == IpClassification::Blocked,
               "Local-use NAT64 64:ff9b:1::/48 has no fixed embedded-IPv4 position — fail closed");
    ExpectTrue(ClassifyIpAddress("::ffff:127.0.0.1") == IpClassification::Blocked,
               "IPv4-mapped loopback must be blocked");
    ExpectTrue(ClassifyIpAddress("::ffff:93.184.216.34") == IpClassification::Public,
               "IPv4-mapped public address must stay Public");
    ExpectTrue(ClassifyIpAddress("::127.0.0.1") == IpClassification::Blocked,
               "Deprecated IPv4-compatible ::/96 is outside 2000::/3 and stays fail-closed");

    // Повний вердикт із підставним резолвером. Жодного DNS і жодного сокета.
    const auto public_resolver = [](const std::string&) {
        return std::vector<std::string>{"93.184.216.34"};
    };
    const auto private_resolver = [](const std::string&) {
        return std::vector<std::string>{"93.184.216.34", "10.0.0.7"};
    };
    const auto empty_resolver = [](const std::string&) { return std::vector<std::string>{}; };

    ExpectTrue(CheckDestination("https://ca.example.ua/tsp", public_resolver, false).allowed,
               "Destination resolving to a public address must be allowed");
    ExpectFalse(CheckDestination("https://ca.example.ua/tsp", private_resolver, false).allowed,
                "One private address among the answers must deny the whole destination");
    ExpectFalse(CheckDestination("https://ca.example.ua/tsp", empty_resolver, false).allowed,
                "A destination that does not resolve must be denied");
    ExpectFalse(CheckDestination("https://127.0.0.1/tsp", public_resolver, false).allowed,
                "A blocked literal must be denied before the resolver is consulted");

    // Збережена межа: коли викликач дозволив пропустити DNS і резолвера немає,
    // призначення вважається дозволеним. Це поведінка детермінованих
    // мок-тестів, і вона мала пережити рефакторинг без змін.
    ExpectTrue(CheckDestination("https://ca.example.ua/tsp",
                                tamga::core::HttpHostResolver{}, true)
                   .allowed,
               "Without a resolver and with DNS skipping allowed the destination stays allowed");
}

// Побудова URL редиректу — теж політика, а не транспорт: саме тут вирішується,
// КУДИ піде наступний запит. Відносний `Location` є класичним місцем обходу
// перевірки призначення, і після розділення його можна перевірити прямо.
void TestHttpRedirectSyntaxIsCallableWithoutTransport() {
    using tamga::core::net::IsRedirectStatus;
    using tamga::core::net::ResolveHttpRedirectUrl;
    using tamga::core::net::ResponseHeaderValue;

    ExpectTrue(ResponseHeaderValue("HTTP/1.1 302 Found\r\nLocation: /next\r\n", "location") ==
                   "/next",
               "Header lookup must be case-insensitive and trim spaces");
    ExpectTrue(ResponseHeaderValue("HTTP/1.1 200 OK\r\n", "location").empty(),
               "A missing header must yield an empty value, not garbage");

    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a/b?x=1", "/c") ==
                   "https://ca.example.ua/c",
               "Absolute path must be resolved against the origin");
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a/b?x=1", "c") ==
                   "https://ca.example.ua/a/c",
               "Relative path must be resolved against the directory, query dropped");
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a", "http://evil.example/x") ==
                   "http://evil.example/x",
               "An absolute Location is returned as-is — the destination check judges it next");
    ExpectTrue(ResolveHttpRedirectUrl("not-a-url", "/c").empty(),
               "An unparseable base must yield an empty URL, which the caller treats as refusal");

    // B-07: розвʼязання за RFC 3986 §5.3. Форми, яких стара реалізація не
    // знала, вона зводила до «дописати до каталогу бази» — і мовчки будувала
    // адресу, якої на сервері немає. Обходу перевірки призначення тут не було:
    // ціль усе одно проходить `CheckDestination`. Дефект функціональний.
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a/b", "//cdn.example/new") ==
                   "https://cdn.example/new",
               "Protocol-relative Location must inherit only the scheme, not the authority");
    ExpectTrue(ResolveHttpRedirectUrl("http://ca.example.ua/a/b", "//cdn.example/new") ==
                   "http://cdn.example/new",
               "Protocol-relative Location must inherit the base scheme verbatim");
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a/file?x=1", "?new=2") ==
                   "https://ca.example.ua/a/file?new=2",
               "Query-only Location must keep the whole base path, not truncate to its directory");
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a/file?x=1", "#frag") ==
                   "https://ca.example.ua/a/file?x=1#frag",
               "Fragment-only Location must keep both the base path and the base query");
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a/b/c", "../up") ==
                   "https://ca.example.ua/a/up",
               "Dot segments in a relative Location must be removed, not carried into the path");
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a/b", "/x/../y") ==
                   "https://ca.example.ua/y",
               "Dot segments in an absolute-path Location must be removed as well");
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a/b", "c?q=1#f") ==
                   "https://ca.example.ua/a/c?q=1#f",
               "Query and fragment of a relative Location must survive the merge");
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua", "c") ==
                   "https://ca.example.ua/c",
               "A base without a path must merge against the root");
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a/b", "//").empty(),
               "A protocol-relative Location without an authority must be refused");
    ExpectTrue(ResolveHttpRedirectUrl("https://ca.example.ua/a/b", "").empty(),
               "An empty Location is a refusal, not a repeat of the base request");

    ExpectTrue(IsRedirectStatus(301L) && IsRedirectStatus(308L),
               "301 and 308 are redirects");
    ExpectFalse(IsRedirectStatus(200L) || IsRedirectStatus(304L),
                "200 and 304 are not redirects");
}
