// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Розширені профілі XAdES: T, X-L, A (archive time-stamp) і поля LTV.
// Тут закріплено HI-02: структурна наявність доказів не дорівнює
// підтвердженій довірі.

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

void TestXadesTSignVerifyRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for XAdES-T round-trip");
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
    params.profile = tamga::xades::XadesProfile::T;
    params.xml_params.signature_id = "sigT";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);
    params.timestamp_provider = [&fixture](const std::vector<std::uint8_t>& tbs,
                                           std::vector<std::uint8_t>& token,
                                           std::string& err) {
        return MockTsaTimestamp(fixture, tbs, token, err);
    };

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Data>ts</Data></Doc>", params, key, signed_xml, error),
               "XAdES-T Sign should succeed");
    ExpectTrue(signed_xml.find("SignatureTimeStamp") != std::string::npos,
               "XAdES-T output must contain SignatureTimeStamp");
    ExpectTrue(signed_xml.find("EncapsulatedTimeStamp") != std::string::npos,
               "XAdES-T output must contain EncapsulatedTimeStamp");

    tamga::xades::XadesVerificationResult result;
    ExpectTrue(verifier.Verify(signed_xml, result, error), "XAdES-T Verify should run");
    ExpectTrue(result.signature_valid, "XAdES-T signature must be valid");
    ExpectTrue(result.detected_profile == tamga::xades::XadesProfile::T, "profile must be T");
    ExpectTrue(result.timestamps_valid, "XAdES-T SignatureTimeStamp must validate");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

void TestXadesXLSignVerifyRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for XAdES-X-L round-trip");
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
    params.profile = tamga::xades::XadesProfile::X_L;
    params.xml_params.signature_id = "sigXL";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);
    params.timestamp_provider = [&fixture](const std::vector<std::uint8_t>& tbs,
                                           std::vector<std::uint8_t>& token, std::string& err) {
        return MockTsaTimestamp(fixture, tbs, token, err);
    };
    // Ланцюг = самопідписаний сертифікат фікстури (для офлайн-тесту агрегації).
    params.certificate_chain.push_back(fixture.cert_der);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Data>xl</Data></Doc>", params, key, signed_xml, error),
               "XAdES-X-L Sign should succeed");
    ExpectTrue(signed_xml.find("CompleteCertificateRefs") != std::string::npos,
               "X-L output must contain CompleteCertificateRefs");
    ExpectTrue(signed_xml.find("CertificateValues") != std::string::npos,
               "X-L output must contain CertificateValues");
    ExpectTrue(signed_xml.find("EncapsulatedX509Certificate") != std::string::npos,
               "X-L output must contain EncapsulatedX509Certificate");

    tamga::xades::XadesVerificationResult result;
    ExpectTrue(verifier.Verify(signed_xml, result, error), "XAdES-X-L Verify should run");
    ExpectTrue(result.signature_valid, "XAdES-X-L signature must be valid");
    ExpectTrue(result.timestamps_valid, "XAdES-X-L SignatureTimeStamp must validate");
    ExpectTrue(result.cert_refs_complete, "XAdES-X-L must expose complete certificate refs");
    ExpectTrue(result.detected_profile == tamga::xades::XadesProfile::X_L, "profile must be X-L");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

void TestXadesArchiveSignVerifyRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for XAdES-A round-trip");
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
    params.profile = tamga::xades::XadesProfile::A;
    params.xml_params.signature_id = "sigA";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);
    params.timestamp_provider = [&fixture](const std::vector<std::uint8_t>& tbs,
                                           std::vector<std::uint8_t>& token, std::string& err) {
        return MockTsaTimestamp(fixture, tbs, token, err);
    };
    params.certificate_chain.push_back(fixture.cert_der);
    // Структурний revocation-блоб (для офлайн-тесту агрегації CRL refs/values).
    params.crls.push_back(fixture.cert_der);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Data>arch</Data></Doc>", params, key, signed_xml, error),
               "XAdES-A Sign should succeed");
    for (const char* tag : {"SignatureTimeStamp", "SigAndRefsTimeStamp", "ArchiveTimeStamp",
                            "CompleteCertificateRefs", "CompleteRevocationRefs",
                            "CertificateValues", "RevocationValues", "EncapsulatedCRLValue"}) {
        ExpectTrue(signed_xml.find(tag) != std::string::npos,
                   "XAdES-A output must contain expected element");
    }

    tamga::xades::XadesVerificationResult result;
    ExpectTrue(verifier.Verify(signed_xml, result, error), "XAdES-A Verify should run");
    ExpectTrue(result.signature_valid, "XAdES-A signature must be valid");
    ExpectTrue(result.timestamps_valid, "all XAdES-A timestamps must validate");
    ExpectTrue(result.archive_timestamps_valid, "ArchiveTimeStamp must validate");
    ExpectTrue(result.cert_refs_complete, "certificate refs must be complete");
    ExpectTrue(result.revocation_refs_complete, "revocation refs must be complete");
    ExpectTrue(result.detected_profile == tamga::xades::XadesProfile::A, "profile must be A");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// WP-13: ArchiveTimeStamp message-imprint тепер покриває ds:Reference-вміст
// (ETSI EN 319 132-1 §5.5.2.3, крок 1) через спільний
// xades::detail::BuildArchiveTimeStampImprintInput. Ця регресія перевіряє,
// що токен, обчислений для ОДНОГО документа, відхиляється при підміні у
// СТРУКТУРНО ідентичний, але змістовно ІНШИЙ документ -- token-swap/wrapping
// клас атак на ArchiveTimeStamp.
void TestXadesArchiveTimeStampRejectsSwappedToken() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for ArchiveTimeStamp token-swap test");
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

    auto sign_document = [&](const std::string& doc_xml, const std::string& sig_id) -> std::string {
        tamga::xades::XadesParameters params;
        params.profile = tamga::xades::XadesProfile::A;
        params.xml_params.signature_id = sig_id;
        params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
        params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
        tamga::xmldsig::XmlReference ref;
        ref.uri = "";
        ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                          "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
        ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        params.xml_params.references.push_back(ref);
        params.timestamp_provider = [&fixture](const std::vector<std::uint8_t>& tbs,
                                               std::vector<std::uint8_t>& token, std::string& err) {
            return MockTsaTimestamp(fixture, tbs, token, err);
        };
        params.certificate_chain.push_back(fixture.cert_der);
        params.crls.push_back(fixture.cert_der);

        tamga::core::SigningKey key;
        key.use_pkcs12 = true;
        key.key_material = fixture.pkcs12_blob;
        key.certificate_der = fixture.cert_der;
        key.password = "test";

        std::string signed_xml;
        std::string error;
        ExpectTrue(builder.Sign(doc_xml, params, key, signed_xml, error), "XAdES-A sign for token-swap test");
        return signed_xml;
    };

    const std::string signed_a = sign_document("<Doc><Data>archive-swap-a</Data></Doc>", "sigSwapA");
    const std::string signed_b = sign_document("<Doc><Data>archive-swap-b</Data></Doc>", "sigSwapB");

    const std::string token_a = ExtractArchiveTimeStampTokenForTest(signed_a);
    ExpectFalse(token_a.empty(), "Must be able to extract ArchiveTimeStamp token from document A");

    const std::string tampered_b = ReplaceArchiveTimeStampTokenForTest(signed_b, token_a);
    ExpectTrue(tampered_b != signed_b, "Token swap must actually change document B");

    tamga::xades::XadesVerificationResult tampered_result;
    std::string error;
    ExpectTrue(verifier.Verify(tampered_b, tampered_result, error), "Verify should run on tampered document B");
    ExpectFalse(tampered_result.archive_timestamps_valid,
               "ArchiveTimeStamp imprint from a different document must be rejected");
    // HI-04: format_profile/detected_profile="XAdES-A" мусить вимагати
    // archive_timestamps_valid, а не лише структурної наявності елемента —
    // підроблений ArchiveTimeStamp НЕ повинен звітувати XAdES-A.
    ExpectTrue(tampered_result.format_profile != "XAdES-A",
              "HI-04: tampered ArchiveTimeStamp must not be reported as format_profile=XAdES-A");
    ExpectTrue(tampered_result.detected_profile != tamga::xades::XadesProfile::A,
              "HI-04: tampered ArchiveTimeStamp must not be reported as detected_profile=A");

    // Санітарна перевірка: НЕ підмінений B і далі валідний -- тест дійсно
    // ловить саме підміну, а не щось стороннє в самому document B.
    tamga::xades::XadesVerificationResult clean_result;
    ExpectTrue(verifier.Verify(signed_b, clean_result, error), "Verify should run on clean document B");
    ExpectTrue(clean_result.archive_timestamps_valid, "Unmodified document B ArchiveTimeStamp must still validate");
    ExpectTrue(clean_result.format_profile == "XAdES-A",
              "sanity: unmodified document B with valid ArchiveTimeStamp must still report XAdES-A");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// HI-04 (Session-рівень): той самий token-swap, що
// TestXadesArchiveTimeStampRejectsSwappedToken, але через Session::VerifyXml
// -> GetLastVerifyReport() JSON -- підтверджує, що фікс поширюється на
// публічний NativeAPI-звіт (profile ТА validatedProfile), а не лише на
// внутрішній XadesVerificationResult.
void TestSessionVerifyXmlArchiveProfileRequiresValidTimestamp() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for HI-04 Session profile test");
    if (!fixture.valid) {
        return;
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xades::XadesBuilder builder(crypto, tsp);

    auto sign_document = [&](const std::string& doc_xml, const std::string& sig_id) -> std::string {
        tamga::xades::XadesParameters params;
        params.profile = tamga::xades::XadesProfile::A;
        params.xml_params.signature_id = sig_id;
        params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
        params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
        tamga::xmldsig::XmlReference ref;
        ref.uri = "";
        ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                          "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
        ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        params.xml_params.references.push_back(ref);
        params.timestamp_provider = [&fixture](const std::vector<std::uint8_t>& tbs,
                                               std::vector<std::uint8_t>& token, std::string& err) {
            return MockTsaTimestamp(fixture, tbs, token, err);
        };
        params.certificate_chain.push_back(fixture.cert_der);
        params.crls.push_back(fixture.cert_der);

        tamga::core::SigningKey key;
        key.use_pkcs12 = true;
        key.key_material = fixture.pkcs12_blob;
        key.certificate_der = fixture.cert_der;
        key.password = "test";

        std::string signed_xml;
        std::string error;
        ExpectTrue(builder.Sign(doc_xml, params, key, signed_xml, error),
                  "XAdES-A sign for HI-04 Session profile test");
        return signed_xml;
    };

    const std::string signed_a = sign_document("<Doc><Data>hi04-session-a</Data></Doc>", "sigHi04A");
    const std::string signed_b = sign_document("<Doc><Data>hi04-session-b</Data></Doc>", "sigHi04B");

    const std::string token_a = ExtractArchiveTimeStampTokenForTest(signed_a);
    ExpectFalse(token_a.empty(), "Must be able to extract ArchiveTimeStamp token from document A");
    const std::string tampered_b = ReplaceArchiveTimeStampTokenForTest(signed_b, token_a);
    ExpectTrue(tampered_b != signed_b, "Token swap must actually change document B");

    // Санітарна перевірка: чистий B і далі звітує XAdES-A через Session-звіт.
    {
        tamga::core::Session session;
        ExpectTrue(session.Initialize(), "session init (HI-04 clean)");
        bool valid = false;
        ExpectSessionTrue(session, session.VerifyXml(signed_b, valid), "Session::VerifyXml should run (clean)");
        ExpectTrue(valid, "clean signature must be cryptographically valid");
        std::string json;
        ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed (clean)");
        ExpectContains(json, "\"profile\":\"XAdES-A\"", "sanity: clean document must report profile=XAdES-A");
    }

    // Регресія (HI-04): підмінений ArchiveTimeStamp НЕ повинен давати
    // profile=XAdES-A ані validatedProfile=XAdES-A у публічному звіті.
    {
        tamga::core::Session session;
        ExpectTrue(session.Initialize(), "session init (HI-04 tampered)");
        bool valid = false;
        ExpectSessionTrue(session, session.VerifyXml(tampered_b, valid),
                          "Session::VerifyXml should run (tampered ArchiveTimeStamp)");
        std::string json;
        ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed (tampered)");
        ExpectFalse(json.find("\"profile\":\"XAdES-A\"") != std::string::npos,
                   "HI-04: tampered ArchiveTimeStamp must not report profile=XAdES-A");
        ExpectFalse(json.find("\"validatedProfile\":\"XAdES-A\"") != std::string::npos,
                   "HI-04: tampered ArchiveTimeStamp must not report validatedProfile=XAdES-A");
    }
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// ME-02: `revocationEvidencePresent` (top-level `certificate`/`revocation`
// JSON у GetLastVerifyReport()) відображає структурну наявність XAdES
// RevocationValues, ОКРЕМО від canonical `checked`/`ocspChecked`, які тепер
// походять виключно з фактичного вердикту ValidationEngine/RevocationEngine
// (раніше — optimistic fallback за самою наявністю B-LT-доказів + валідного
// підпису, прибраний цим фіксом; див. bugfix-log). Підпис БЕЗ RevocationValues
// (plain XAdES-X-L без CRL) звітує `evidencePresent=false`; підпис З
// RevocationValues звітує `evidencePresent=true`, незалежно від того, чи
// canonical revocation-перевірка дала singular визначений вердикт.
void TestSessionVerifyXmlRevocationEvidencePresentField() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for ME-02 revocation evidence test");
    if (!fixture.valid) {
        return;
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xades::XadesBuilder builder(crypto, tsp);

    auto sign_document = [&](bool with_crl, const std::string& sig_id) -> std::string {
        tamga::xades::XadesParameters params;
        params.profile = tamga::xades::XadesProfile::X_L;
        params.xml_params.signature_id = sig_id;
        params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
        params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
        tamga::xmldsig::XmlReference ref;
        ref.uri = "";
        ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                          "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
        ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        params.xml_params.references.push_back(ref);
        params.timestamp_provider = [&fixture](const std::vector<std::uint8_t>& tbs,
                                               std::vector<std::uint8_t>& token, std::string& err) {
            return MockTsaTimestamp(fixture, tbs, token, err);
        };
        params.certificate_chain.push_back(fixture.cert_der);
        if (with_crl) {
            // Структурний revocation-блоб (як у TestXadesArchiveSignVerifyRoundTrip)
            // -- достатньо, щоб RevocationValues/EncapsulatedCRLValue з'явились
            // у виводі; не є справжнім CRL.
            params.crls.push_back(fixture.cert_der);
        }

        tamga::core::SigningKey key;
        key.use_pkcs12 = true;
        key.key_material = fixture.pkcs12_blob;
        key.certificate_der = fixture.cert_der;
        key.password = "test";

        std::string signed_xml;
        std::string error;
        ExpectTrue(builder.Sign("<Doc><Data>me02</Data></Doc>", params, key, signed_xml, error),
                  "XAdES-X-L sign for ME-02 revocation evidence test");
        return signed_xml;
    };

    const std::string signed_with_crl = sign_document(true, "sigMe02WithCrl");
    ExpectTrue(signed_with_crl.find("RevocationValues") != std::string::npos,
              "sanity: signature with CRL must contain RevocationValues");

    const std::string signed_without_crl = sign_document(false, "sigMe02NoCrl");
    ExpectFalse(signed_without_crl.find("RevocationValues") != std::string::npos,
               "sanity: signature without CRL must not contain RevocationValues");

    {
        tamga::core::Session session;
        ExpectTrue(session.Initialize(), "session init (ME-02 with CRL)");
        bool valid = false;
        ExpectSessionTrue(session, session.VerifyXml(signed_with_crl, valid),
                          "Session::VerifyXml should run (with CRL)");
        std::string json;
        ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed (with CRL)");
        ExpectContains(json, "\"evidencePresent\":true",
                       "ME-02: signature with RevocationValues must report evidencePresent=true");
    }
    {
        tamga::core::Session session;
        ExpectTrue(session.Initialize(), "session init (ME-02 without CRL)");
        bool valid = false;
        ExpectSessionTrue(session, session.VerifyXml(signed_without_crl, valid),
                          "Session::VerifyXml should run (without CRL)");
        std::string json;
        ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed (without CRL)");
        ExpectContains(json, "\"evidencePresent\":false",
                       "ME-02: signature without RevocationValues must report evidencePresent=false");
    }
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// HI-02: розділення колишнього єдиного ltv_valid (структурна наявність
// CertificateValues/RevocationValues + валідний timestamp) на три деталізовані
// поля. Тест демонструє САМЕ прогалину, яку HI-02 закриває: XAdES-X-L підпис
// із self-signed тестовим сертифікатом (без реальної CA/trust-anchor
// інфраструктури в work_dir) має структурно ПРИВ'ЯЗАНІ LTV-докази
// (ltvEvidenceBound=true) — але trust-ланцюг НЕ підтверджений (self-signed,
// не trusted anchor), тож ltvEvidenceValidated МАЄ бути false, і публічний
// checks.ltv.code МАЄ НЕ бути "LTV_VALID" — навіть попри те, що старий
// структурний ltvValid (незмінний, зворотно сумісний) лишається true.
void TestSessionVerifyXmlLtvEvidenceSplitFields() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for HI-02 ltv evidence split test");
    if (!fixture.valid) {
        return;
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xades::XadesBuilder builder(crypto, tsp);

    tamga::xades::XadesParameters params;
    params.profile = tamga::xades::XadesProfile::X_L;
    params.xml_params.signature_id = "sigHi02LtvSplit";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);
    params.timestamp_provider = [&fixture](const std::vector<std::uint8_t>& tbs,
                                           std::vector<std::uint8_t>& token, std::string& err) {
        return MockTsaTimestamp(fixture, tbs, token, err);
    };
    params.certificate_chain.push_back(fixture.cert_der);
    // Структурний revocation-блоб (як у TestSessionVerifyXmlRevocationEvidencePresentField)
    // -- достатньо, щоб RevocationValues з'явились у виводі.
    params.crls.push_back(fixture.cert_der);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Data>hi02</Data></Doc>", params, key, signed_xml, error),
              "XAdES-X-L sign for HI-02 ltv evidence split test");
    ExpectTrue(signed_xml.find("RevocationValues") != std::string::npos,
              "sanity: signature must contain RevocationValues");
    ExpectTrue(signed_xml.find("CertificateValues") != std::string::npos,
              "sanity: signature must contain CertificateValues");

    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "session init (HI-02 ltv evidence split)");
    bool valid = false;
    ExpectSessionTrue(session, session.VerifyXml(signed_xml, valid), "Session::VerifyXml should run");
    std::string json;
    ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed");

    // Без trust-anchor інфраструктури (self-signed тестовий сертифікат,
    // порожній work_dir) TSA-сертифікат теж не є довіреним, тож XAdES-шлях
    // (де ApplyXadesTimestampPolicyValidation прив'язує ЗАГАЛЬНИЙ ltv_valid
    // до підтвердженого TSA-довіри timestamp_result.valid) дає legacy
    // ltvValid=false. Але НОВЕ поле evidenceBound лишається true — воно
    // суто структурне (digest-binding CompleteCertificateRefs/
    // CompleteRevocationRefs проти CertificateValues/RevocationValues
    // цього ж підпису) і НЕ залежить від жодної trust-перевірки. Це показує,
    // що evidenceBound — незалежний сигнал, а не просто alias ltvValid.
    // Точна компонована підстрока — щоб уникнути хибних збігів з іншими
    // "evidenceBound":true в звіті.
    ExpectContains(json, "\"ltv\":{",
                   "HI-02: report must contain ltv block");
    ExpectContains(json, ",\"evidenceBound\":true,\"evidenceValidated\":false,\"fullyValidated\":false",
                   "HI-02: ltv block must report evidenceBound=true (structural, trust-independent) "
                   "and NOT claim evidenceValidated for a self-signed untrusted chain");
    // Регресія: публічний checks.ltv.code МАЄ НЕ стверджувати LTV_VALID лише
    // за структурною наявністю доказів -- це й була прогалина, яку HI-02 закрив.
    ExpectFalse(json.find("\"ltv\":{\"status\":\"valid\",\"code\":\"LTV_VALID\"") != std::string::npos,
               "HI-02: checks.ltv must not claim LTV_VALID when trust/revocation are not actually confirmed");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// LO-01: попередні тести (TestSessionVerifyXmlLtvEvidenceSplitFields) доводили
// лише self-signed/untrusted-chain гілку HI-02's evidenceBound/evidenceValidated
// split -- "щасливий шлях" (trust anchor присутній, відкликання СПРАВДІ
// підтверджено через реальний, коректно підписаний CRL) ніде в сюїті не
// спостерігався зеленим. Цей тест закриває саме цю прогалину: генерує
// СПРАВЖНІЙ CRL (GenerateGoodCrlForTest, engine-based, підписаний тим самим
// self-signed ключем фікстури), кладе сертифікат фікстури як trust anchor
// (і tsa anchor, бо MockTsaTimestamp підписує тим самим ключем), і перевіряє,
// що evidenceValidated=true / checks.ltv.code=LTV_VALID дійсно ДОСЯЖНІ, а не
// лише теоретично можливі за визначенням полів.
void TestSessionVerifyXmlLtvEvidenceValidatedTrustedPath() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    const auto tsa = GenerateDstuTsaFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for LO-01 trusted-path LTV test");
    ExpectTrue(tsa.valid, "Окремий TSA з EKU має створитися");
    if (!fixture.valid || !tsa.valid) {
        return;
    }

    std::vector<std::uint8_t> good_crl_der;
    std::string crl_error;
    ExpectTrue(GenerateGoodCrlForTest(fixture, good_crl_der, crl_error),
              ("LO-01 test should generate a genuinely valid, signed CRL: " + crl_error).c_str());
    std::vector<std::uint8_t> tsa_crl;
    ExpectTrue(GenerateGoodCrlForTest(tsa, tsa_crl, crl_error), "Справжній CRL TSA має створитися");

    const auto work_dir = MakeTemporaryFixturePath(".lo01-ltv-trusted-path");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir / "trust-store", ec);
    std::filesystem::create_directories(work_dir / "tsa-store", ec);
    ExpectTrue(WriteBinaryFile(work_dir / "trust-store" / "fixture.cer", fixture.cert_der),
               "LO-01 test should write signer trust anchor");
    ExpectTrue(WriteBinaryFile(work_dir / "tsa-store" / "fixture.cer", tsa.cert_der),
               "Окремий TSA з належним EKU є явно налаштованим якорем");

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xades::XadesBuilder builder(crypto, tsp);

    tamga::xades::XadesParameters params;
    params.profile = tamga::xades::XadesProfile::X_L;
    params.xml_params.signature_id = "sigLo01TrustedLtv";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);
    params.timestamp_provider = [&tsa](const std::vector<std::uint8_t>& tbs,
                                           std::vector<std::uint8_t>& token, std::string& err) {
        return MockTsaTimestamp(tsa, tbs, token, err);
    };
    params.certificate_chain.push_back(fixture.cert_der);
    // Справжній CRL (не placeholder-блоб, як в інших тестах цього файлу) --
    // потрібен саме для того, щоб RevocationEngine/CrlValidator дійсно
    // підтвердили відкликання ("valid"), а не впали на decode-помилці.
    params.crls.push_back(good_crl_der);
    params.certificate_chain.push_back(tsa.cert_der);
    params.crls.push_back(tsa_crl);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string signed_xml;
    std::string error;
    ExpectTrue(builder.Sign("<Doc><Data>lo01</Data></Doc>", params, key, signed_xml, error),
              "XAdES-X-L sign for LO-01 trusted-path LTV test");

    tamga::core::Session session;
    tamga::core::Settings settings;
    settings.offline_mode = true;
    settings.work_dir = work_dir.string();
    ExpectTrue(session.SetSettings(settings), "LO-01 test should accept offline work_dir settings");
    ExpectTrue(session.Initialize(), "session init (LO-01 trusted-path LTV)");
    bool valid = false;
    ExpectSessionTrue(session, session.VerifyXml(signed_xml, valid), "Session::VerifyXml should run");
    std::string json;
    ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed");

    // Санітарна перевірка: справжній CRL дійсно підтвердив відкликання.
    ExpectContains(json, "\"revocationStatus\":\"valid\"",
                   "sanity: genuine CRL must confirm revocation as valid, not invalid/not-checked");

    // Головна ціль тесту: "щасливий шлях" HI-02, ніколи раніше не
    // спостережений зеленим у сюїті.
    ExpectContains(json, ",\"evidenceBound\":true,\"evidenceValidated\":true,\"fullyValidated\":true",
                   "LO-01: trusted anchor + confirmed revocation must yield evidenceValidated=true");
    ExpectContains(json, "\"ltv\":{\"status\":\"valid\",\"code\":\"LTV_VALID\"",
                   "LO-01: checks.ltv must report LTV_VALID when evidence is genuinely bound and validated");

    std::filesystem::remove_all(work_dir, ec);
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}
