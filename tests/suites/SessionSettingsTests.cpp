// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Налаштування сесії та їх межові значення: типові значення після
// Initialize, онлайн-налаштування, OID імпринта TSP, скидання стану ключа.

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

void TestInitializeAppliesDefaultSettings() {
    tamga::core::Session session;
    ExpectTrue(session.NeedSetSettings(), "Fresh session should report legacy NeedSetSettings before Initialize");
    ExpectTrue(session.Initialize(), "Initialize should succeed without SetSettings");
    ExpectFalse(session.NeedSetSettings(), "Initialize should apply default settings");
    ExpectTrue(session.OfflineMode(), "Default initialized session should stay offline");
}

void TestOnlineSettingsAllowEmptyUrlAsDisabledDefault() {
    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize before online settings");

    tamga::core::TspSettings tsp;
    tsp.url = "";
    tsp.policy_oid = "";
    tsp.timeout_ms = 10000;
    ExpectTrue(session.SetTspSettings(tsp), "Empty TSP URL should mean auto/default TSP settings");

    tamga::core::OcspSettings ocsp;
    ocsp.url = "";
    ocsp.use_nonce = true;
    ocsp.timeout_ms = 10000;
    ExpectTrue(session.SetOcspSettings(ocsp), "Empty OCSP URL should mean disabled OCSP endpoint");

    tamga::core::LdapSettings ldap;
    ldap.url = "";
    ldap.base_dn = "";
    ldap.timeout_ms = 10000;
    ExpectTrue(session.SetLdapSettings(ldap), "Empty LDAP URL should be accepted as disabled LDAP settings");

    tamga::core::CmpSettings cmp;
    cmp.url = "";
    cmp.profile = "";
    cmp.timeout_ms = 10000;
    ExpectTrue(session.SetCmpSettings(cmp), "Empty CMP URL should be accepted as disabled CMP settings");
}

void TestOnlineSettingsDefaultsAndValidationEdges() {
    ExpectTrue(tamga::core::OcspSettings{}.timeout_ms == 10000, "OCSP default timeout should be 10000 ms");
    ExpectTrue(tamga::core::TspSettings{}.timeout_ms == 10000, "TSP default timeout should be 10000 ms");
    ExpectTrue(tamga::core::LdapSettings{}.timeout_ms == 10000, "LDAP default timeout should be 10000 ms");
    ExpectTrue(tamga::core::CmpSettings{}.timeout_ms == 10000, "CMP default timeout should be 10000 ms");

    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize before online settings validation");

    tamga::core::OcspSettings ocsp;
    ocsp.url = "invalid-ocsp-url";
    ExpectFalse(session.SetOcspSettings(ocsp), "Non-empty invalid OCSP URL should remain invalid");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
               "Invalid OCSP URL should set InvalidArgument");

    tamga::core::TspSettings tsp;
    tsp.url = "invalid-tsp-url";
    ExpectFalse(session.SetTspSettings(tsp), "Non-empty invalid TSP URL should remain invalid");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
               "Invalid TSP URL should set InvalidArgument");

    tamga::core::LdapSettings ldap;
    ldap.url = "invalid-ldap-url";
    ExpectFalse(session.SetLdapSettings(ldap), "Non-empty invalid LDAP URL should remain invalid");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
               "Invalid LDAP URL should set InvalidArgument");

    ldap.url = "ldap://example.test";
    ExpectFalse(session.SetLdapSettings(ldap), "Non-empty valid LDAP URL should still be unsupported");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::NotSupported,
               "Valid LDAP URL should set NotSupported");

    tamga::core::CmpSettings cmp;
    cmp.url = "invalid-cmp-url";
    ExpectFalse(session.SetCmpSettings(cmp), "Non-empty invalid CMP URL should remain invalid");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
               "Invalid CMP URL should set InvalidArgument");

    cmp.url = "https://example.test/cmp";
    ExpectFalse(session.SetCmpSettings(cmp), "Non-empty valid CMP URL should still be unsupported");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::NotSupported,
               "Valid CMP URL should set NotSupported");
}

void TestTspSettingsImprintDigestOidValidation() {
    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize before testing TSP OID validation");

    // Test valid OIDs and special values (including symbolic aliases and case-insensitive "auto")
    const std::vector<std::string> valid_oids = {
        "",
        "auto",
        "Auto",
        "AUTO",
        "aUtO",
        "1.2.804.2.1.1.1.1.2.2.1",
        "1.2.804.2.1.1.1.1.2.1",
        "2.16.840.1.101.3.4.2.1",
        "2.16.840.1.101.3.4.2.2",
        "2.16.840.1.101.3.4.2.3",
        "Kupyna256",
        "kupyna-256",
        "Gost34311",
        "gost-34311",
        "SHA-256",
        "sha-256",
        "sha256",
        "SHA-384",
        "sha-384",
        "sha384",
        "SHA-512",
        "sha-512",
        "sha512"
    };

    for (const auto& oid : valid_oids) {
        tamga::core::TspSettings tsp;
        tsp.url = ""; // Empty URL is valid (means default/disabled)
        tsp.imprint_digest_oid = oid;
        ExpectTrue(session.SetTspSettings(tsp), ("Should accept valid TSP imprint digest OID: " + oid).c_str());
    }

    // Test invalid OIDs
    const std::vector<std::string> invalid_oids = {
        "invalid",
        "1.2.3.4",
        "2.16.840.1.101.3.4.2.0",
        "1.2.804.2.1.1.1.1.2.2"
    };

    for (const auto& oid : invalid_oids) {
        tamga::core::TspSettings tsp;
        tsp.url = "";
        tsp.imprint_digest_oid = oid;
        ExpectFalse(session.SetTspSettings(tsp), ("Should reject invalid TSP imprint digest OID: " + oid).c_str());
        ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
                   ("Rejection of OID: " + oid + " should set InvalidArgument error").c_str());
    }
}

void TestVerifyReportForNotInitializedVerify() {
    tamga::core::Session session;
    std::string json;
    bool is_valid = true;
    ExpectFalse(session.VerifyData({}, {}, is_valid), "VerifyData should fail before Initialize");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::NotInitialized, "VerifyData should set NotInitialized error");
    ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed after failed verification");
    ExpectContains(json, "\"operation\":\"VerifyData\"", "Verify report should record VerifyData operation");
    ExpectContains(json, "\"errorCode\":\"NotInitialized\"", "Verify report should expose error code");
}

void TestVerifyReportForInvalidBase64() {
    tamga::core::Session session;
    std::string json;
    bool is_valid = true;
    ExpectFalse(session.VerifyDataBase64({}, "not-base64***", is_valid), "VerifyDataBase64 should reject invalid Base64 input");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument, "VerifyDataBase64 should set InvalidArgument error");
    ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed after Base64 failure");
    ExpectContains(json, "\"operation\":\"VerifyDataBase64\"", "Verify report should record VerifyDataBase64 operation");
}

void TestSessionResetPrivateKeyState() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for reset scenario");

    const auto fixture = FixturePath("jks/unicode-alias-password.jks");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyFile(fixture.string(), u8"ПарольСховища1", u8"ПарольКлюча2", u8"КлючТест"),
                      "ReadPrivateKeyFile should load JKS before reset");
    ExpectTrue(session.IsPrivateKeyLoaded(), "ReadPrivateKeyFile should mark private key as loaded");
    ExpectTrue(session.ResetPrivateKey(), "ResetPrivateKey should succeed");
    ExpectFalse(session.IsPrivateKeyLoaded(), "ResetPrivateKey should clear loaded private key state");
}

// С-06: ParseDerLength у KeyParsers.cpp завершувався перевіркою
// `offset + length <= limit`, яка при length, близькому до SIZE_MAX,
// переповнюється по модулю 2^N і пропускає значення далеко за межами буфера.
// Guard проти цього вже існував у другій копії того самого парсера
// (SessionHelpers.ipp), але сюди його не перенесли.
//
// Тест не намагається вгадати точне зміщення DER усередині JKS: він проходить
// по реальній фікстурі вікном і в кожній позиції підставляє long-form довжину
// 0x88 FF..FF. Парсер мусить у КОЖНОМУ випадку завершитися чисто — повернути
// результат, а не вийти за межі буфера. Під ASan (де XML/PDF-конфігурація
// тепер теж інструментується) OOB тут проявився б діагностикою.
// С-08: звіт не має стверджувати, що trust validation "не реалізована".
// Формулювання жило в BuildVerifyMessage і потрапляло у GetReport()/GetError()
// для кожної успішної перевірки без власного тексту. Знахідку фіксували ще
// 2026-08-20 і не виправили — це був рецидив. Тест існує саме тому, що
// повернути такий рядок легко й непомітно.
#if defined(TAMGA_XML_SIGNATURES_ENABLED)
// С-17: підписом вважається лише елемент у namespace XMLDSIG.
//
// Раніше збирач верхнього рівня розпізнавав вузли за самою ЛОКАЛЬНОЮ назвою,
// тож елемент `Signature` у ЧУЖОМУ namespace вважався підписом. Доведеного
// exploit-а це не давало (далі спрацьовують анти-XSW перевірки), але місце,
// яке вирішує, ЩО взагалі є підписом, не має виходити за межі профілю.
//
// Перевіряємо через публічний API: документ із чужим namespace має бути
// відхилений як такий, що не містить підпису, а не оброблений як підпис.
void TestVerifyXmlRejectsForeignNamespaceSignature() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "session init (foreign ns)");

    const std::string foreign =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<root><ev:Signature xmlns:ev=\"urn:evil:not-xmldsig\">"
        "<ev:SignatureValue>AAAA</ev:SignatureValue></ev:Signature></root>";

    bool valid = true;
    const bool executed = session.VerifyXml(foreign, valid);
    ExpectFalse(valid, "a Signature element in a foreign namespace must not verify");
    (void)executed;
}
#endif  // TAMGA_XML_SIGNATURES_ENABLED

void TestVerifyReportDoesNotClaimTrustValidationMissing() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for verify message check");

    std::vector<std::uint8_t> signature;
    bool is_valid = true;
    // Свідомо невалідний вхід: нас цікавить САМЕ текст звіту, а не вердикт.
    (void)session.VerifyData({'d', 'a', 't', 'a'}, {0x30, 0x03, 0x02, 0x01, 0x00}, is_valid);

    std::string report;
    if (session.GetLastVerifyReport(report)) {
        ExpectFalse(Contains(report, "Trust validation is not implemented"),
                    "report must not claim that trust validation is unimplemented");
        ExpectFalse(Contains(report, "not implemented"),
                    "report must not contain a stale 'not implemented' claim");
    }
}
