// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// XMLDSIG і базові профілі XAdES: підписання, перевірка, мультипідпис,
// політика підпису. Саме тут живуть регресії на реальних артефактах Дії.

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

void TestXmlDsigEnvelopedSignVerifyRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    using namespace tamga::xmldsig;
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for XMLDSIG round-trip should generate");
    if (!fixture.valid) {
        return;
    }

    XmlCanonicalizer canonicalizer;
    XmlTransformEngine transform_engine;
    XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    XmlSignatureBuilder builder(canonicalizer, transform_engine, digest_engine, crypto);
    XmlSignatureVerifier verifier(canonicalizer, transform_engine, digest_engine, crypto);

    XmlSignatureParameters params;
    params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.c14n_method = CanonicalizationMethod::C14N;
    XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.references.push_back(ref);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc Id=\"o1\"><Data>hello</Data></Doc>", params, key, signed_xml, error),
               "XMLDSIG enveloped Sign should succeed");
    ExpectTrue(signed_xml.find("SignatureValue") != std::string::npos,
               "signed XML must contain SignatureValue");
    ExpectTrue(signed_xml.find("X509Certificate") != std::string::npos,
               "signed XML must embed signer certificate in KeyInfo");

    XmlSignatureVerificationResult result;
    ExpectTrue(verifier.Verify(signed_xml, result, error), "Verify should run");
    ExpectTrue(result.digest_valid, "reference digests must be valid");
    ExpectTrue(result.signature_valid, "SignedInfo DSTU signature must be valid");

    // Підробка підписаного контенту має ламати дайджест посилання.
    std::string tampered = signed_xml;
    const auto pos = tampered.find(">hello<");
    ExpectTrue(pos != std::string::npos, "locate signed content for tampering");
    if (pos != std::string::npos) {
        tampered.replace(pos, 7, ">HELLO<");
        XmlSignatureVerificationResult tampered_result;
        ExpectTrue(verifier.Verify(tampered, tampered_result, error),
                   "Verify of tampered document should still run");
        ExpectFalse(tampered_result.digest_valid, "tampered content must break the reference digest");
    }
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

void TestXmlDsigDetachedIdReferenceRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    using namespace tamga::xmldsig;
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for detached #id round-trip");
    if (!fixture.valid) {
        return;
    }

    XmlCanonicalizer canonicalizer;
    XmlTransformEngine transform_engine;
    XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    XmlSignatureBuilder builder(canonicalizer, transform_engine, digest_engine, crypto);
    XmlSignatureVerifier verifier(canonicalizer, transform_engine, digest_engine, crypto);

    // Підпис посилається на елемент #o1 (без enveloped-трансформу); ds:Signature
    // додається до кореня як сусід — піддерево #o1 лишається незмінним.
    XmlSignatureParameters params;
    params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.c14n_method = CanonicalizationMethod::C14N;
    XmlReference ref;
    ref.uri = "#o1";
    ref.transforms = {"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.references.push_back(ref);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Item Id=\"o1\"><Data>hello</Data></Item></Doc>", params, key,
                            signed_xml, error),
               "detached #id Sign should succeed");

    XmlSignatureVerificationResult result;
    ExpectTrue(verifier.Verify(signed_xml, result, error), "detached #id Verify should run");
    ExpectTrue(result.digest_valid, "detached #id reference digest must be valid");
    ExpectTrue(result.signature_valid, "detached #id SignedInfo signature must be valid");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

void TestSessionSignVerifyXmlRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for Session XMLDSIG round-trip");
    if (!fixture.valid) {
        return;
    }
    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize");
    ExpectSessionTrue(session, session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test"),
                      "Session should load DSTU pkcs12 key");
    ExpectTrue(session.IsPrivateKeyLoaded(), "private key should be loaded");

    std::string signed_xml;
    ExpectSessionTrue(session, session.SignXml("<Doc Id=\"o1\"><Data>hello</Data></Doc>", signed_xml),
                      "Session::SignXml should succeed");
    ExpectTrue(signed_xml.find("SignatureValue") != std::string::npos,
               "Session-signed XML must contain SignatureValue");

    bool is_valid = false;
    ExpectSessionTrue(session, session.VerifyXml(signed_xml, is_valid), "Session::VerifyXml should run");
    ExpectTrue(is_valid, "Session XMLDSIG round-trip must be valid");

    // Q-003: GetUserReport() має відображати САМЕ щойно виконану VerifyXml-
    // операцію, а не застарілий звіт попередньої операції. Раніше VerifyXml не
    // викликав RefreshUserReport у фінальному lock, тож user-звіт лишався
    // старим.
    std::string user_report;
    ExpectTrue(session.GetUserReport(user_report), "GetUserReport should be readable after VerifyXml");
    ExpectContains(user_report, "\"operation\":\"VerifyXml\"",
                   "GetUserReport must reflect the VerifyXml operation (Q-003)");

    std::string tampered = signed_xml;
    const auto pos = tampered.find(">hello<");
    if (pos != std::string::npos) {
        tampered.replace(pos, 7, ">HELLO<");
        bool tampered_valid = true;
        ExpectSessionTrue(session, session.VerifyXml(tampered, tampered_valid),
                          "Session::VerifyXml of tampered doc should run");
        ExpectFalse(tampered_valid, "tampered Session XMLDSIG must be invalid");
    }
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// Step 3 (XAdES-sign): Session::SignXml(xml, "xades-bes") повинен створювати
// XAdES-BES enveloped-підпис, верифікований Session::VerifyXml із
// formatProfile="XAdES-BES" і qualifyingPropertiesPresent=true.
// Session::SignXml(xml, "xades-t") з offline_mode=true повинен повертати
// false з відповідною помилкою (немає TSP у тестовому середовищі).
void TestSessionSignXmlXadesProfiles() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for XAdES profile round-trip");
    if (!fixture.valid) return;

    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize");
    ExpectSessionTrue(session, session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test"),
                      "Session should load DSTU pkcs12 key");

    // --- XAdES-BES round-trip ---
    std::string signed_xades;
    ExpectSessionTrue(session,
                      session.SignXml("<Doc Id=\"o1\"><Data>xades-bes-test</Data></Doc>",
                                     "xades-bes", signed_xades),
                      "Session::SignXml(xades-bes) should succeed");
    ExpectTrue(signed_xades.find("QualifyingProperties") != std::string::npos,
               "XAdES-BES output must contain QualifyingProperties");
    ExpectTrue(signed_xades.find("SigningTime") != std::string::npos,
               "XAdES-BES output must contain SigningTime");

    bool is_valid = false;
    ExpectSessionTrue(session, session.VerifyXml(signed_xades, is_valid),
                      "Session::VerifyXml of XAdES-BES output should run");
    ExpectTrue(is_valid, "XAdES-BES round-trip must be cryptographically valid");

    std::string report_json;
    ExpectTrue(session.GetLastVerifyReport(report_json),
               "GetLastVerifyReport should succeed after XAdES-BES verify");
    // XadesVerifier uses ETSI EN 319 132 baseline notation "XAdES-B-B" for BES.
    // The schemaVersion:2.0 JSON uses "profile" key inside the "signature" block.
    ExpectTrue(report_json.find("\"profile\":\"XAdES-B-B\"") != std::string::npos ||
               report_json.find("\"profile\":\"XAdES-BES\"") != std::string::npos,
               "VerifyXml report must reflect XAdES-BES/B-B format profile");
    ExpectContains(report_json, "\"qualifyingPropertiesPresent\":true",
                   "VerifyXml report must show qualifyingPropertiesPresent=true for XAdES-BES");

    // --- xmldsig default ("") behaves same as 2-arg overload ---
    std::string signed_xmldsig;
    ExpectSessionTrue(session,
                      session.SignXml("<Doc Id=\"o2\"><Data>xmldsig-test</Data></Doc>",
                                     "", signed_xmldsig),
                      "Session::SignXml(\"\") should succeed (xmldsig default)");
    ExpectTrue(signed_xmldsig.find("QualifyingProperties") == std::string::npos,
               "XMLDSIG default output must NOT contain QualifyingProperties");

    // --- XAdES-T offline → should fail with clear error ---
    std::string signed_t;
    const bool t_result = session.SignXml(
        "<Doc Id=\"o3\"><Data>xades-t-test</Data></Doc>", "xades-t", signed_t);
    ExpectFalse(t_result, "Session::SignXml(xades-t) must fail when offline_mode=true");
    ExpectTrue(signed_t.empty(), "signed_xml_out must remain empty on XAdES-T failure");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::OnlineServiceUnavailable,
               "GetLastError().code must be OnlineServiceUnavailable after XAdES-T offline failure");
    ExpectTrue(!session.GetLastError().message.empty(),
               "GetLastError().message must be non-empty after XAdES-T offline failure");

    // --- unknown profile → NotSupported error ---
    std::string signed_bad;
    ExpectFalse(session.SignXml("<Doc/>", "unknown-profile", signed_bad),
                "Session::SignXml with unknown profile must return false");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// WP-2 (Session-інтеграція): Session::VerifyXml тепер делегує до
// XadesVerifier::VerifyAll і публікує per-signature крипто-стан у
// GetLastVerifyReport()["signatures"]. Перевіряємо на СПРАВЖНЬОМУ документі
// з двома незалежними ds:Signature (два різні DSTU-ключі), а не лише
// одинарний підпис — інакше регресія "signatures[] завжди має 1 елемент"
// лишилась би непоміченою.
void TestSessionVerifyXmlMultiSignatureReport() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture_a = GenerateDstuFixture();
    const auto fixture_b = GenerateDstuFixture();
    ExpectTrue(fixture_a.valid && fixture_b.valid, "DSTU fixtures for Session multi-signature report");
    if (!fixture_a.valid || !fixture_b.valid) {
        return;
    }

    tamga::core::Session session_a;
    ExpectTrue(session_a.Initialize(), "Session A should initialize");
    ExpectSessionTrue(session_a, session_a.ReadPrivateKeyBinary(fixture_a.pkcs12_blob, "test", "test"),
                      "Session A should load DSTU pkcs12 key");
    std::string signed_a;
    ExpectSessionTrue(session_a, session_a.SignXml("<Doc Id=\"o1\"><Data>hello</Data></Doc>", signed_a),
                      "Session A::SignXml should succeed");

    tamga::core::Session session_b;
    ExpectTrue(session_b.Initialize(), "Session B should initialize");
    ExpectSessionTrue(session_b, session_b.ReadPrivateKeyBinary(fixture_b.pkcs12_blob, "test", "test"),
                      "Session B should load DSTU pkcs12 key");
    std::string signed_b;
    ExpectSessionTrue(session_b, session_b.SignXml("<Doc Id=\"o1\"><Data>hello</Data></Doc>", signed_b),
                      "Session B::SignXml should succeed");

    const auto extract_signature = [](const std::string& xml) -> std::string {
        const auto start = xml.find("<Signature");
        const auto end = xml.find("</Signature>");
        if (start == std::string::npos || end == std::string::npos) {
            return {};
        }
        return xml.substr(start, end + std::string("</Signature>").size() - start);
    };
    const std::string second_signature_block = extract_signature(signed_b);
    ExpectTrue(!second_signature_block.empty(), "second session-signed XML must contain a Signature block");

    std::string merged = signed_a;
    const auto close_doc = merged.rfind("</Doc>");
    ExpectTrue(close_doc != std::string::npos, "first session-signed XML must contain closing </Doc>");
    merged.insert(close_doc, second_signature_block);

    tamga::core::Session verifier_session;
    ExpectTrue(verifier_session.Initialize(), "verifier Session should initialize");
    bool is_valid = false;
    ExpectSessionTrue(verifier_session, verifier_session.VerifyXml(merged, is_valid),
                      "Session::VerifyXml of a genuinely dual-signed document should run");
    ExpectTrue(is_valid, "dual-signature document must verify as all_valid");

    std::string report_json;
    ExpectTrue(verifier_session.GetLastVerifyReport(report_json),
               "GetLastVerifyReport should succeed after multi-signature VerifyXml");
    ExpectContains(report_json, "\"signatures\":[{\"index\":1,\"signatureValid\":true",
                  "report must list first signature as valid");
    ExpectContains(report_json, "\"index\":2,\"signatureValid\":true",
                  "report must list second signature as valid");

    // Тампер лише другого підпису -> все ще 2 записи в signatures[], але
    // сукупний is_valid=false, і саме другий запис позначено невалідним.
    std::string tampered = merged;
    const auto value_pos = tampered.rfind("<SignatureValue>");
    ExpectTrue(value_pos != std::string::npos, "merged document must contain a second SignatureValue to tamper");
    const auto value_end = tampered.find("</SignatureValue>", value_pos);
    ExpectTrue(value_end != std::string::npos, "SignatureValue must be well-formed");
    const std::size_t content_start = value_pos + std::string("<SignatureValue>").size();
    ExpectTrue(value_end != std::string::npos && value_end > content_start + 4,
               "SignatureValue content must be long enough to tamper safely");
    if (value_pos != std::string::npos && value_end != std::string::npos && value_end > content_start + 4) {
        char& c = tampered[content_start + 2];
        c = (c == 'A') ? 'B' : 'A';
        bool tampered_valid = true;
        tamga::core::Session tampered_session;
        ExpectTrue(tampered_session.Initialize(), "tampered-check Session should initialize");
        ExpectSessionTrue(tampered_session, tampered_session.VerifyXml(tampered, tampered_valid),
                          "Session::VerifyXml of tampered dual-signature document should run");
        ExpectFalse(tampered_valid, "tampering the second signature must invalidate the whole set");

        std::string tampered_report;
        ExpectTrue(tampered_session.GetLastVerifyReport(tampered_report),
                   "GetLastVerifyReport should succeed after tampered multi-signature VerifyXml");
        ExpectContains(tampered_report, "\"index\":1,\"signatureValid\":true",
                      "first signature must remain valid after tampering only the second");
        ExpectContains(tampered_report, "\"index\":2,\"signatureValid\":false",
                      "second signature must be reported invalid after tampering");
    }
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// HI-01: раніше повна trust-перевірка (X.509 chain) рахувалась ЛИШЕ для
// одного репрезентативного підпису — genuinely dual-signed документ, де
// ОДИН підписант trusted, а ІНШИЙ ні, міг помилково показати верхньорівневий
// trustValid=true, якщо репрезентативним випадково обирався trusted
// підписант. Тест доводить: (1) кожен SignatureEntry отримує ВЛАСний,
// незалежно обчислений trust-результат; (2) верхньорівневий trustValid —
// AND-агрегація (all_valid policy) по ВСІХ підписантах, тож один untrusted
// співпідписант робить УВЕСЬ verdict untrusted, навіть коли крипто-цілісність
// (is_valid) лишається true для обох підписів.
void TestSessionVerifyXmlPerSignerTrustAggregation() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture_a = GenerateDstuFixture();
    const auto fixture_b = GenerateDstuFixture();
    ExpectTrue(fixture_a.valid && fixture_b.valid, "DSTU fixtures for HI-01 per-signer trust test");
    if (!fixture_a.valid || !fixture_b.valid) {
        return;
    }

    // Довірчий сховище містить ЛИШЕ сертифікат fixture_a — fixture_b
    // навмисно НЕ trusted anchor, щоб отримати РІЗНІ trust-результати для
    // двох підписантів одного документа.
    const auto work_dir = MakeTemporaryFixturePath(".hi01-per-signer-trust");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir / "trust-store", ec);
    ExpectTrue(WriteBinaryFile(work_dir / "trust-store" / "signer-a.cer", fixture_a.cert_der),
               "HI-01 test should write signer A trust anchor");

    // XadesBuilder з явним certificate_chain -- на відміну від plain
    // Session::SignXml, це вбудовує KeyInfo/ds:X509Certificate, без якого
    // signer_certificate_present=false і trust-перевірка взагалі не
    // запускається (RunFormatTrustValidationOn early-return на порожньому
    // сертифікаті) — саме те, що потрібне цьому тесту.
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xades::XadesBuilder builder(crypto, tsp);
    const auto sign_bes = [&](const DstuFixture& fixture, const std::string& sig_id) -> std::string {
        tamga::xades::XadesParameters params;
        params.profile = tamga::xades::XadesProfile::BES;
        params.xml_params.signature_id = sig_id;
        params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
        params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
        tamga::xmldsig::XmlReference ref;
        ref.uri = "";
        ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                          "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
        ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        params.xml_params.references.push_back(ref);
        params.certificate_chain.push_back(fixture.cert_der);

        tamga::core::SigningKey key;
        key.use_pkcs12 = true;
        key.key_material = fixture.pkcs12_blob;
        key.certificate_der = fixture.cert_der;
        key.password = "test";

        std::string signed_xml;
        std::string error;
        ExpectTrue(builder.Sign("<Doc Id=\"o1\"><Data>hi01</Data></Doc>", params, key, signed_xml, error),
                  "XAdES-BES sign for HI-01 per-signer trust test");
        return signed_xml;
    };

    const std::string signed_a = sign_bes(fixture_a, "sigHi01SignerA");
    const std::string signed_b = sign_bes(fixture_b, "sigHi01SignerB");

    // XadesBuilder (на відміну від plain Session::SignXml) серіалізує вузол
    // із префіксом "ds:" (xmlns:ds декларація на самому <ds:Signature>).
    const auto extract_signature = [](const std::string& xml) -> std::string {
        const auto start = xml.find("<ds:Signature");
        const auto end = xml.find("</ds:Signature>");
        if (start == std::string::npos || end == std::string::npos) {
            return {};
        }
        return xml.substr(start, end + std::string("</ds:Signature>").size() - start);
    };
    const std::string second_signature_block = extract_signature(signed_b);
    ExpectTrue(!second_signature_block.empty(), "second session-signed XML must contain a Signature block");

    std::string merged = signed_a;
    const auto close_doc = merged.rfind("</Doc>");
    ExpectTrue(close_doc != std::string::npos, "first session-signed XML must contain closing </Doc>");
    merged.insert(close_doc, second_signature_block);

    tamga::core::Session verifier_session;
    tamga::core::Settings settings;
    settings.offline_mode = true;
    settings.work_dir = work_dir.string();
    ExpectTrue(verifier_session.SetSettings(settings), "HI-01 test should accept offline work_dir settings");
    ExpectTrue(verifier_session.Initialize(), "verifier Session should initialize");
    bool is_valid = false;
    ExpectSessionTrue(verifier_session, verifier_session.VerifyXml(merged, is_valid),
                      "Session::VerifyXml of a genuinely dual-signed document should run");
    ExpectTrue(is_valid, "dual-signature document must verify as all_valid (crypto integrity unaffected by trust)");

    std::string report_json;
    ExpectTrue(verifier_session.GetLastVerifyReport(report_json),
               "GetLastVerifyReport should succeed after per-signer trust VerifyXml");

    // Кожен підписант отримав ВЛАСНий, незалежний trust-результат.
    ExpectContains(report_json, "\"index\":1", "report must list first signature entry");
    ExpectContains(report_json, "\"index\":2", "report must list second signature entry");
    ExpectContains(report_json, "\"trust\":{\"checked\":true,\"valid\":true",
                   "HI-01: signer A (trust anchor present) must report trust.valid=true for its own entry");
    ExpectContains(report_json, "\"trust\":{\"checked\":true,\"valid\":false",
                   "HI-01: signer B (no trust anchor) must report trust.valid=false for its own entry");

    // Регресія: верхньорівневий агрегат МАЄ бути untrusted, попри те, що
    // один із двох підписантів (fixture_a) дійсно trusted -- all_valid
    // policy, не "перший репрезентативний".
    ExpectContains(report_json, "\"trustValid\":false",
                   "HI-01: top-level trustValid must be false when ANY co-signer is untrusted (all_valid policy)");
    // Gemini review (PR #37): report.trust_valid=false МАЄ узгоджуватись із
    // report.errorCode -- без прокидання error_code/message від "найгіршого"
    // підписанта в ApplyPerSignerTrustAggregation, errorCode лишався б "None"
    // попри агрегований untrusted-вердикт.
    ExpectContains(report_json, "\"errorCode\":\"TrustValidationFailed\"",
                   "HI-01: errorCode must reflect the untrusted co-signer, not stay None");

    std::filesystem::remove_all(work_dir, ec);
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

void TestXadesBesSignVerifyRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for XAdES-BES round-trip");
    if (!fixture.valid) {
        return;
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesBuilder builder(crypto, tsp);
    tamga::xades::XadesVerifier verifier(xml_verifier, crypto, tsp);

    tamga::xades::XadesParameters params;
    params.profile = tamga::xades::XadesProfile::BES;
    params.xml_params.signature_id = "sig1";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Data>hi</Data></Doc>", params, key, signed_xml, error),
               "XAdES-BES Sign should succeed");
    ExpectTrue(signed_xml.find("QualifyingProperties") != std::string::npos,
               "XAdES output must contain QualifyingProperties");
    ExpectTrue(signed_xml.find("SigningCertificate") != std::string::npos,
               "XAdES output must contain SigningCertificate");
    ExpectTrue(signed_xml.find("SigningTime") != std::string::npos,
               "XAdES output must contain SigningTime");

    tamga::xades::XadesVerificationResult result;
    ExpectTrue(verifier.Verify(signed_xml, result, error), "XAdES Verify should run");
    ExpectTrue(result.signature_valid, "XAdES signature (incl. SignedProperties) must be valid");
    ExpectTrue(result.qualifying_properties_present, "QualifyingProperties must be detected");
    ExpectTrue(result.signing_certificate_digest_valid, "SigningCertificate CertDigest must match");
    ExpectFalse(result.signing_time.empty(), "SigningTime must be extracted");
    ExpectTrue(result.detected_profile == tamga::xades::XadesProfile::BES, "profile must be BES");

    // Підробка даних має ламати підпис (через дайджест посилання на дані).
    std::string tampered = signed_xml;
    const auto pos = tampered.find(">hi<");
    if (pos != std::string::npos) {
        tampered.replace(pos, 4, ">XX<");
        tamga::xades::XadesVerificationResult tampered_result;
        ExpectTrue(verifier.Verify(tampered, tampered_result, error), "verify of tampered XAdES runs");
        ExpectFalse(tampered_result.signature_valid, "tampered XAdES must be invalid");
    }
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// S-003: XAdES SigningCertificate/CertDigest mismatch must produce
// signing_certificate_digest_valid=false AND signature_valid=false (fail-closed).
// Test scenario: sign with cert A, replace ds:KeyInfo/X509Certificate with cert B —
// the CertDigest in SignedProperties still references cert A's hash, so the check
// fails. XMLDSIG VerifyHash also fails (cert B key can't verify cert A's signature)
// but the test confirms that signing_certificate_digest_valid is correctly reflected.
void TestXadesCertDigestMismatchFailsClosed() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture_a = GenerateDstuFixture();
    const auto fixture_b = GenerateDstuFixture();
    ExpectTrue(fixture_a.valid, "DSTU fixture A for S-003 test");
    ExpectTrue(fixture_b.valid, "DSTU fixture B for S-003 test");
    if (!fixture_a.valid || !fixture_b.valid) return;

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesBuilder builder(crypto, tsp);
    tamga::xades::XadesVerifier verifier(xml_verifier, crypto, tsp);

    tamga::xades::XadesParameters params;
    params.profile = tamga::xades::XadesProfile::BES;
    params.xml_params.signature_id = "sig1";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture_a.pkcs12_blob;
    key.certificate_der = fixture_a.cert_der;
    key.password = "test";

    // Sign with cert A — produces X509Certificate=certA, CertDigest=hash(certA).
    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Data>test</Data></Doc>", params, key, signed_xml, error),
               "S-003: XAdES-BES Sign with cert A should succeed");

    // Replace ds:KeyInfo/X509Certificate content with cert B's base64.
    // CertDigest still references cert A → mismatch after substitution.
    // KeyInfo is inside ds:Signature and NOT covered by any ds:Reference, so
    // the data/SignedProperties digests remain valid after this substitution.
    const std::string cert_a_b64 = tamga::util::Base64Encode(fixture_a.cert_der);
    const std::string cert_b_b64 = tamga::util::Base64Encode(fixture_b.cert_der);
    const auto pos = signed_xml.find(cert_a_b64);
    if (pos == std::string::npos) {
        std::cerr << "  S-003: could not locate cert A base64 in signed XML — skipping\n";
        return;
    }
    std::string tampered = signed_xml;
    tampered.replace(pos, cert_a_b64.size(), cert_b_b64);

    tamga::xades::XadesVerificationResult result;
    ExpectTrue(verifier.Verify(tampered, result, error),
               "S-003: Verify on tampered XML must run (structural, not early-exit)");
    ExpectFalse(result.signing_certificate_digest_valid,
                "S-003: signing_certificate_digest_valid must be false on cert mismatch");
    ExpectFalse(result.signature_valid,
                "S-003: signature_valid must be false when CertDigest mismatches (fail-closed)");
    const bool has_mismatch_note = std::any_of(
        result.notes.begin(), result.notes.end(),
        [](const std::string& n) { return n.find("mismatch") != std::string::npos; });
    ExpectTrue(has_mismatch_note,
               "S-003: notes must contain CertDigest mismatch description");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// WP-12: SignaturePolicyIdentifier/SignedDataObjectProperties тепер
// фактично генеруються (XadesBuilder) і структурно парсяться (XadesVerifier)
// — раніше моделі (SignaturePolicy/DataObjectFormat у XadesTypes.h) існували,
// але ніде не читались/не записувались (мертві типи).
void TestXadesSignaturePolicyAndDataObjectFormatRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for XAdES SignaturePolicy/DataObjectFormat round-trip");
    if (!fixture.valid) {
        return;
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesBuilder builder(crypto, tsp);
    tamga::xades::XadesVerifier verifier(xml_verifier, crypto, tsp);

    tamga::xades::XadesParameters params;
    params.profile = tamga::xades::XadesProfile::BES;
    params.xml_params.signature_id = "sigPolicy";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);

    tamga::xades::SignaturePolicy policy;
    policy.policy_id = "urn:tamga:test-policy:v1";
    policy.policy_hash_algo_uri = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    policy.policy_hash_value = {0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD};
    params.qualifying_properties.signed_props.signature_policy = policy;

    tamga::xades::DataObjectFormat dof;
    dof.object_reference = "#" + params.xml_params.signature_id + "-data";
    dof.mime_type = "application/pdf";
    dof.description = "Test document for WP-12";
    params.qualifying_properties.signed_props.data_object_formats.push_back(dof);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Data>hi</Data></Doc>", params, key, signed_xml, error),
               "XAdES Sign with SignaturePolicy/DataObjectFormat should succeed");
    ExpectTrue(signed_xml.find("SignaturePolicyIdentifier") != std::string::npos,
               "signed XML must contain SignaturePolicyIdentifier");
    ExpectTrue(signed_xml.find("SignedDataObjectProperties") != std::string::npos,
               "signed XML must contain SignedDataObjectProperties");
    ExpectTrue(signed_xml.find("DataObjectFormat") != std::string::npos,
               "signed XML must contain DataObjectFormat");

    tamga::xades::XadesVerificationResult result;
    ExpectTrue(verifier.Verify(signed_xml, result, error), "XAdES Verify should run");
    ExpectTrue(result.signature_valid, "signature (incl. new SignedProperties children) must remain valid");
    ExpectTrue(result.signature_policy_present, "signature_policy_present must be true");
    ExpectTrue(result.signature_policy_id == policy.policy_id, "signature_policy_id must round-trip exactly");
    ExpectTrue(result.signature_policy_hash_algo_uri == policy.policy_hash_algo_uri,
               "signature_policy_hash_algo_uri must round-trip exactly");
    ExpectTrue(result.signature_policy_hash_value == policy.policy_hash_value,
               "signature_policy_hash_value must round-trip exactly (byte-for-byte)");

    ExpectTrue(result.data_object_formats.size() == 1, "exactly one DataObjectFormat must be parsed");
    if (result.data_object_formats.size() == 1) {
        ExpectTrue(result.data_object_formats[0].object_reference == dof.object_reference,
                   "DataObjectFormat.object_reference must round-trip exactly");
        ExpectTrue(result.data_object_formats[0].mime_type == dof.mime_type,
                   "DataObjectFormat.mime_type must round-trip exactly");
        ExpectTrue(result.data_object_formats[0].description == dof.description,
                   "DataObjectFormat.description must round-trip exactly");
    }

    // Регресія: підпис БЕЗ політики/DataObjectFormat (типовий шлях, вже
    // покритий іншими тестами) не повинен випадково повідомляти про
    // присутність цих властивостей.
    tamga::xades::XadesParameters plain_params = params;
    plain_params.qualifying_properties.signed_props.signature_policy.reset();
    plain_params.qualifying_properties.signed_props.data_object_formats.clear();
    plain_params.xml_params.signature_id = "sigNoPolicy";
    std::string plain_signed_xml;
    ExpectTrue(builder.Sign("<Doc><Data>hi</Data></Doc>", plain_params, key, plain_signed_xml, error),
               "plain XAdES Sign (no policy/DOF) should still succeed");
    tamga::xades::XadesVerificationResult plain_result;
    ExpectTrue(verifier.Verify(plain_signed_xml, plain_result, error), "plain XAdES Verify should run");
    ExpectFalse(plain_result.signature_policy_present,
                "signature_policy_present must be false when no policy was signed");
    ExpectTrue(plain_result.data_object_formats.empty(),
               "data_object_formats must be empty when none were signed");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// WP-12 (Session-звіт): доводить рушій (XadesBuilder/XadesVerifier, вище)
// до GetLastVerifyReport() -- signature_policy_present/id/hashAlgorithmUri і
// data_object_formats тепер проброшені у Session::VerifyXml, і в
// top-level report, і в per-signature signatures[] (той самий принцип, що
// WP-2 застосував до signatures[] загалом).
void TestSessionVerifyXmlSignaturePolicyReport() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for Session SignaturePolicy report");
    if (!fixture.valid) {
        return;
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xades::XadesBuilder builder(crypto, tsp);

    tamga::xades::XadesParameters params;
    params.profile = tamga::xades::XadesProfile::BES;
    params.xml_params.signature_id = "sigPolicySession";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);

    tamga::xades::SignaturePolicy policy;
    policy.policy_id = "urn:tamga:test-policy:session-v1";
    policy.policy_hash_algo_uri = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    policy.policy_hash_value = {0xDE, 0xAD, 0xBE, 0xEF};
    params.qualifying_properties.signed_props.signature_policy = policy;

    tamga::xades::DataObjectFormat dof;
    dof.object_reference = "#" + params.xml_params.signature_id + "-data";
    dof.mime_type = "application/pdf";
    dof.description = "Session-level WP-12 report test";
    params.qualifying_properties.signed_props.data_object_formats.push_back(dof);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Data>hi</Data></Doc>", params, key, signed_xml, error),
               "XAdES Sign with SignaturePolicy/DataObjectFormat should succeed (Session report test)");

    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "session init (signature policy report)");
    bool valid = false;
    ExpectSessionTrue(session, session.VerifyXml(signed_xml, valid), "Session::VerifyXml should run");
    ExpectTrue(valid, "signature with SignaturePolicy/DataObjectFormat must remain valid via Session");

    std::string json;
    ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed");
    ExpectContains(json, "\"signaturePolicy\":{\"present\":true,\"id\":\"urn:tamga:test-policy:session-v1\"",
                  "top-level report must expose signaturePolicy.present/id");
    ExpectContains(json, "\"hashAlgorithmUri\":\"http://www.w3.org/2001/04/xmldsig-more#gost34311\"",
                  "top-level report must expose signaturePolicy.hashAlgorithmUri");
    ExpectContains(json, "\"dataObjectFormats\":[{\"objectReference\":\"#sigPolicySession-data\"",
                  "top-level report must expose dataObjectFormats[0].objectReference");
    ExpectContains(json, "\"mimeType\":\"application/pdf\"",
                  "top-level report must expose dataObjectFormats[0].mimeType");
    ExpectContains(json, "\"signaturePolicyPresent\":true",
                  "signatures[] entry must expose signaturePolicyPresent");

    // Регресія: звичайний підпис без політики не повинен показувати
    // signaturePolicy.present=true у Session-звіті.
    tamga::xades::XadesParameters plain_params = params;
    plain_params.qualifying_properties.signed_props.signature_policy.reset();
    plain_params.qualifying_properties.signed_props.data_object_formats.clear();
    plain_params.xml_params.signature_id = "sigNoPolicySession";
    std::string plain_signed_xml;
    ExpectTrue(builder.Sign("<Doc><Data>hi</Data></Doc>", plain_params, key, plain_signed_xml, error),
               "plain XAdES Sign (no policy/DOF) should still succeed (Session report test)");
    tamga::core::Session plain_session;
    ExpectTrue(plain_session.Initialize(), "session init (plain, no policy)");
    bool plain_valid = false;
    ExpectSessionTrue(plain_session, plain_session.VerifyXml(plain_signed_xml, plain_valid),
                      "Session::VerifyXml (plain) should run");
    std::string plain_json;
    ExpectTrue(plain_session.GetLastVerifyReport(plain_json), "GetLastVerifyReport (plain) should succeed");
    ExpectContains(plain_json, "\"signaturePolicy\":{\"present\":false,\"id\":\"\"",
                  "plain signature must report signaturePolicy.present=false");
    ExpectContains(plain_json, "\"dataObjectFormats\":[]",
                  "plain signature must report an empty dataObjectFormats array");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// ME-01: signer_certificate_present у VerifyXml мусить відображати наявність
// KeyInfo/X509Certificate, а НЕ наявність xades:SignedProperties
// (qualifying_properties_present) — це два незалежних структурних факти.
void TestSessionVerifyXmlCertificatePresentReflectsX509Certificate() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for ME-01 certificate-present test");
    if (!fixture.valid) {
        return;
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xades::XadesBuilder builder(crypto, tsp);

    tamga::xades::XadesParameters params;
    params.profile = tamga::xades::XadesProfile::BES;
    params.xml_params.signature_id = "sigMe01";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Data>hi</Data></Doc>", params, key, signed_xml, error),
               "XAdES Sign should succeed (ME-01 certificate-present test)");
    ExpectTrue(signed_xml.find("<ds:X509Certificate>") != std::string::npos,
               "sanity: signed XML must embed X509Certificate before stripping");

    // Базовий випадок: сертифікат присутній — certificate.present і
    // qualifyingPropertiesPresent обидва true.
    {
        tamga::core::Session session;
        ExpectTrue(session.Initialize(), "session init (ME-01 baseline)");
        bool valid = false;
        ExpectSessionTrue(session, session.VerifyXml(signed_xml, valid), "Session::VerifyXml should run (baseline)");
        ExpectTrue(valid, "baseline signature with embedded certificate must be valid");
        std::string json;
        ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed (baseline)");
        ExpectContains(json, "\"present\":true", "baseline report must show certificate.present=true");
        ExpectContains(json, "\"qualifyingPropertiesPresent\":true",
                       "baseline report must show qualifyingPropertiesPresent=true");
    }

    // Регресія (ME-01): підпис зі SignedProperties, але БЕЗ вбудованого
    // X509Certificate — signer_certificate_present МАЄ бути false, навіть
    // якщо qualifying_properties_present (SignedProperties) лишається true.
    const std::string stripped_xml = StripX509CertificateForTest(signed_xml);
    ExpectTrue(stripped_xml.find("<ds:X509Certificate>") == std::string::npos,
               "sanity: X509Certificate must be removed from stripped XML");
    ExpectTrue(stripped_xml.find("SignedProperties") != std::string::npos,
               "sanity: SignedProperties must remain present in stripped XML");
    {
        tamga::core::Session session;
        ExpectTrue(session.Initialize(), "session init (ME-01 stripped)");
        bool valid = true;
        ExpectSessionTrue(session, session.VerifyXml(stripped_xml, valid),
                          "Session::VerifyXml of stripped-cert doc should run");
        ExpectFalse(valid, "signature without embedded certificate cannot cryptographically verify");
        std::string json;
        ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed (stripped)");
        ExpectContains(json, "\"present\":false",
                       "ME-01: certificate.present must be false when X509Certificate is absent");
        ExpectContains(json, "\"qualifyingPropertiesPresent\":true",
                       "ME-01: qualifyingPropertiesPresent must stay true (SignedProperties still present)");
        ExpectContains(json, "\"certificatePresent\":false",
                       "ME-01: signatures[] entry must also show certificatePresent=false");
    }
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}
