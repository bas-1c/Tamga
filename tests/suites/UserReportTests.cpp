// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Метадані сертифіката і користувацький звіт: поля підписувача,
// синхронізація операції, очищення після Finalize.

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

void TestCertificateMetadataExtractionForFixture() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    tamga::core::CertificateMetadata metadata;
    std::string error;
    ExpectTrue(tamga::core::CryptoniteAdapter::ExtractCertificateMetadata(fixture.cert_der, metadata, error),
               "Fixture certificate metadata extraction should succeed");
    ExpectTrue(metadata.subject.find("CN=Tamga Test") != std::string::npos ||
               metadata.common_name == "Tamga Test",
               "Metadata should expose fixture common name");
    ExpectFalse(metadata.serial_number_hex.empty(), "Metadata should expose certificate serial number");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestCertificateMetadataSerialUsesDerOrderForPemFixture() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto cert_pem = ReadBinaryFixture(FixturePath("pki/cert.pem"));
    std::vector<tamga::core::PemDerLoader::PemBlock> blocks;
    std::string error;
    tamga::core::PemDerLoader::LoadOptions options;
    options.strict_mode = true;
    ExpectTrue(tamga::core::PemDerLoader::LoadAll(cert_pem, blocks, error, options),
               "PEM certificate fixture should parse for metadata serial order test");
    const auto cert_it = std::find_if(blocks.begin(), blocks.end(),
                                      [](const auto& block) { return block.type == "CERTIFICATE"; });
    ExpectTrue(cert_it != blocks.end(), "PEM certificate fixture should contain CERTIFICATE block");
    if (cert_it == blocks.end()) {
        return;
    }

    const std::string der_serial_hex = ExtractDerCertificateSerialHexForTest(cert_it->der_payload);
    ExpectFalse(der_serial_hex.empty(), "Test helper should extract DER-order certificate serial");

    tamga::core::CertificateMetadata metadata;
    ExpectTrue(tamga::core::CryptoniteAdapter::ExtractCertificateMetadata(cert_it->der_payload, metadata, error),
               "PEM fixture metadata extraction should succeed");
    ExpectTrue(metadata.serial_number_hex == der_serial_hex,
               "Certificate metadata serial number should preserve DER/TBS INTEGER byte order");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestUserReportAfterDetachedVerifyContainsSignerFields() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    tamga::core::Session session;
    PrepareInitializedSession(session);
    ExpectTrue(session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
               "Fixture key should load");

    const std::vector<std::uint8_t> data{'d','a','t','a'};
    std::vector<std::uint8_t> signature;
    ExpectTrue(session.SignData(data, signature, tamga::core::TimestampMode::Disabled),
               "Signing should succeed");
    bool is_valid = false;
    ExpectTrue(session.VerifyData(data, signature, is_valid), "VerifyData should execute");
    ExpectTrue(is_valid, "Fixture signature should be valid");

    std::string json;
    ExpectTrue(session.GetUserReport(json), "GetUserReport should return JSON after verify");
    ExpectContains(json, "\"subject\":\"Tamga Test\"", "User report should include signer subject field");
    ExpectContains(json, "\"certificate\"", "User report should include certificate block");
    ExpectContains(json, "\"signature\"", "User report should include signature block");
    ExpectContains(json, "\"policy\"", "User report should include policy block");
    ExpectTrue(Contains(json, "\"fullName\":\"Tamga Test\"") ||
               Contains(json, "\"serialNumber\":\"0102030405060708090a0b0c0d0e0f1011121314\""),
               "User report should include signer commonName or certificate serial number from fixture");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestUserReportRefreshesAfterFailedVerifyDataBase64() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    tamga::core::Session session;
    PrepareInitializedSession(session);
    ExpectTrue(session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
               "Fixture key should load for stale user report regression");

    const std::vector<std::uint8_t> data{'s','t','a','l','e'};
    std::vector<std::uint8_t> signature;
    ExpectTrue(session.SignData(data, signature, tamga::core::TimestampMode::Disabled),
               "Signing should succeed before stale report regression");
    bool is_valid = false;
    ExpectTrue(session.VerifyData(data, signature, is_valid),
               "Initial VerifyData should build successful user report");
    ExpectTrue(is_valid, "Initial fixture signature should be valid");

    std::string success_json;
    ExpectTrue(session.GetUserReport(success_json), "Successful user report should be readable");
    ExpectContains(success_json, "\"present\":true",
                   "Successful user report should expose signer before failure regression");

    is_valid = true;
    ExpectFalse(session.VerifyDataBase64(data, "not-base64***", is_valid),
                "Invalid Base64 verify should fail after prior success");
    ExpectFalse(is_valid, "Invalid Base64 verify should reset validity flag");

    std::string failure_json;
    ExpectTrue(session.GetUserReport(failure_json),
               "Failed verify should rebuild user report instead of preserving prior success");
    ExpectContains(failure_json, "\"operation\":\"VerifyDataBase64\"",
                   "Failed Base64 user report should identify VerifyDataBase64");
    ExpectContains(failure_json, "\"errorCode\":\"InvalidArgument\"",
                   "Failed Base64 user report should expose InvalidArgument");
    ExpectContains(failure_json, "\"executionSucceeded\":false",
                   "Failed Base64 user report should mark execution failure");
    ExpectContains(failure_json, "\"present\":false",
                   "Failed Base64 user report should clear previous signer list");
    ExpectFalse(Contains(failure_json, "\"fullName\""),
                "Failed Base64 user report must not keep previous signer fields");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestUserReportVerifyDataBase64OperationSync() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    tamga::core::Session session;
    PrepareInitializedSession(session);
    ExpectTrue(session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
               "Fixture key should load for Base64 operation sync");

    const std::vector<std::uint8_t> data{'b','6','4'};
    std::vector<std::uint8_t> signature;
    ExpectTrue(session.SignData(data, signature, tamga::core::TimestampMode::Disabled),
               "Signing should succeed before Base64 operation sync");
    const std::string signature_base64 = tamga::util::Base64Encode(signature);

    bool is_valid = false;
    ExpectTrue(session.VerifyDataBase64(data, signature_base64, is_valid),
               "VerifyDataBase64 should execute with valid signature");
    ExpectTrue(is_valid, "VerifyDataBase64 should validate fixture signature");

    std::string json;
    ExpectTrue(session.GetUserReport(json), "Base64 user report should be readable");
    ExpectContains(json, "\"operation\":\"VerifyDataBase64\"",
                   "Base64 user report should sync wrapper operation after successful verify");
    ExpectContains(json, "\"format\":\"CMS\"",
                   "Base64 user report should preserve detached CMS signature format");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestUserReportClearsAfterFinalize() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    tamga::core::Session session;
    PrepareInitializedSession(session);
    ExpectTrue(session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
               "Fixture key should load before finalize user report regression");

    const std::vector<std::uint8_t> data{'f','i','n'};
    std::vector<std::uint8_t> signature;
    ExpectTrue(session.SignData(data, signature, tamga::core::TimestampMode::Disabled),
               "Signing should succeed before finalize user report regression");
    bool is_valid = false;
    ExpectTrue(session.VerifyData(data, signature, is_valid),
               "VerifyData should build successful user report before Finalize");
    ExpectTrue(is_valid, "Fixture signature should be valid before Finalize");

    std::string success_json;
    ExpectTrue(session.GetUserReport(success_json), "Successful user report should be readable before Finalize");
    ExpectContains(success_json, "\"present\":true",
                   "Successful user report should expose signer before Finalize");

    ExpectTrue(session.Finalize(), "Finalize should clear verify report state");

    std::string final_json;
    ExpectTrue(session.GetUserReport(final_json), "User report should remain readable after Finalize");
    ExpectContains(final_json, "\"summaryCode\":\"not-executed\"",
                   "User report after Finalize should reset to not-executed");
    ExpectContains(final_json, "\"present\":false",
                   "User report after Finalize should clear previous signer list");
    ExpectFalse(Contains(final_json, "\"fullName\""),
                "User report after Finalize must not keep previous signer fields");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}
