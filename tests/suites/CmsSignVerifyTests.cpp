// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// CMS: підписання й перевірка (attached і detached), реакція на підробку
// підпису та даних, витяг відомостей про сертифікат.

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

void TestSignVerifyRoundTripDstu() {
#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU4145 fixture generation should succeed");
    if (!fixture.valid) {
        return;
    }

    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for DSTU round-trip");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "ReadPrivateKeyBinary should load DSTU4145 PKCS#12 fixture");
    ExpectTrue(session.IsPrivateKeyLoaded(), "DSTU4145 PKCS#12 fixture should mark key as loaded");

    const std::vector<std::uint8_t> payload = {'T', 'a', 'm', 'g', 'a'};

    // Detached sign/verify round-trip
    std::vector<std::uint8_t> detached_sig;
    ExpectSessionTrue(session, session.SignData(payload, detached_sig),
                      "SignData should succeed with DSTU4145 fixture");
    ExpectFalse(detached_sig.empty(), "SignData should produce non-empty signature");

    bool detached_valid = false;
    ExpectSessionTrue(session, session.VerifyData(payload, detached_sig, detached_valid),
                      "VerifyData should succeed for DSTU4145 detached round-trip");
    ExpectTrue(detached_valid, "VerifyData should confirm integrity of DSTU4145 detached signature");

    std::string detached_report;
    ExpectTrue(session.GetLastVerifyReport(detached_report),
               "GetLastVerifyReport should succeed after DSTU detached round-trip");
    ExpectContains(detached_report, "\"schemaVersion\":\"2.2\"", "Detached round-trip report should use v2.2 schema");
    ExpectContains(detached_report, "\"code\":\"SIGNATURE_CRYPTOGRAPHICALLY_VALID\"",
                   "Detached round-trip report should mark crypto integrity valid");
    ExpectContains(detached_report, "\"operation\":\"VerifyData\"",
                   "Detached round-trip report should identify VerifyData operation");

    // Verify that signing time is present in the detached signature
    {
        ContentInfo_t* cinfo = cinfo_alloc();
        ByteArray* sig_ba = ba_alloc_from_uint8(detached_sig.data(), detached_sig.size());
        int parse_rc = cinfo_decode(cinfo, sig_ba);
        ExpectTrue(parse_rc == RET_OK, "Should decode ContentInfo from generated signature");

        SignedData_t* sdata = nullptr;
        parse_rc = cinfo_get_signed_data(cinfo, &sdata);
        ExpectTrue(parse_rc == RET_OK && sdata != nullptr, "Should get SignedData from ContentInfo");

        time_t signing_time = 0;
        parse_rc = sdata_get_signing_time(sdata, 0, &signing_time);
        ExpectTrue(parse_rc == RET_OK, "Should extract signing time from generated signature");

        time_t current_time = std::time(nullptr);
        double diff = std::difftime(current_time, signing_time);
        ExpectTrue(std::abs(diff) < 300, "Signing time should be close to current time");

        ba_free(sig_ba);
        cinfo_free(cinfo);
    }

    // Internal (attached) sign/verify round-trip
    std::vector<std::uint8_t> internal_sig;
    ExpectSessionTrue(session, session.SignDataInternal(payload, internal_sig),
                      "SignDataInternal should succeed with DSTU4145 fixture");
    ExpectFalse(internal_sig.empty(), "SignDataInternal should produce non-empty CMS blob");

    bool internal_valid = false;
    std::vector<std::uint8_t> extracted_content;
    ExpectSessionTrue(session, session.VerifyDataInternal(internal_sig, internal_valid, extracted_content),
                      "VerifyDataInternal should succeed for DSTU4145 attached round-trip");
    ExpectTrue(internal_valid, "VerifyDataInternal should confirm integrity of DSTU4145 attached signature");
    ExpectTrue(extracted_content == payload, "VerifyDataInternal should extract original payload");

    std::string attached_report;
    ExpectTrue(session.GetLastVerifyReport(attached_report),
               "GetLastVerifyReport should succeed after DSTU attached round-trip");
    ExpectContains(attached_report, "\"code\":\"SIGNATURE_CRYPTOGRAPHICALLY_VALID\"",
                   "Attached round-trip report should mark crypto integrity valid");
    ExpectContains(attached_report, "\"operation\":\"VerifyDataInternal\"",
                   "Attached round-trip report should identify VerifyDataInternal operation");

    // GetCertificateInfo on the generated DSTU certificate
    std::string cert_json;
    ExpectSessionTrue(session, session.GetCertificateInfo(fixture.cert_der, cert_json),
                      "GetCertificateInfo should parse DSTU4145 fixture certificate");
    ExpectContains(cert_json, "\"subjectDn\":\"", "DSTU cert info should contain subjectDn");
    ExpectContains(cert_json, "CN=Tamga Test", "DSTU cert subjectDn should contain CN in RFC 4514 format");
    ExpectContains(cert_json, "O=Tamga", "DSTU cert subjectDn should contain O in RFC 4514 format");
    ExpectContains(cert_json, "C=UA", "DSTU cert subjectDn should contain C in RFC 4514 format");
    ExpectContains(cert_json, "\"extKeyUsage\":", "DSTU cert info should contain extKeyUsage field");
    ExpectContains(cert_json, "\"authorityKeyIdentifier\":", "DSTU cert info should contain authorityKeyIdentifier field");
    ExpectContains(cert_json, "\"subjectAltName\":", "DSTU cert info should contain subjectAltName field");
    ExpectContains(cert_json, "\"crlDistributionPoints\":", "DSTU cert info should contain crlDistributionPoints field");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestDetachedCmsVerifyReportFormalization() {
#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU4145 fixture generation should succeed (detached verify report)");
    if (!fixture.valid) {
        return;
    }

    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for detached verify report test");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "ReadPrivateKeyBinary should load DSTU4145 PKCS#12 fixture (detached verify report)");

    const std::vector<std::uint8_t> payload = {'p', 'o', 'l', 'i', 'c', 'y', '-', 'v', '4'};
    std::vector<std::uint8_t> signature;
    ExpectSessionTrue(session, session.SignData(payload, signature),
                      "SignData should succeed for detached verify report test");

    bool is_valid = false;
    ExpectSessionTrue(session, session.VerifyData(payload, signature, is_valid),
                      "VerifyData should succeed for detached verify report test");
    ExpectTrue(is_valid, "VerifyData should confirm crypto integrity of detached DSTU4145 signature");

    std::string report;
    ExpectTrue(session.GetLastVerifyReport(report), "GetLastVerifyReport should succeed after detached verify");
    // Schema and operation identification
    ExpectContains(report, "\"schemaVersion\":\"2.2\"", "Detached verify report should advertise v2.2 schema");
    ExpectContains(report, "\"operation\":\"VerifyData\"", "Detached verify report should identify operation");
    ExpectContains(report, "\"hasResult\":true", "Detached verify report should flag hasResult");
    // Crypto integrity category (the authoritative pass/fail for CMS signature)
    ExpectContains(report, "\"code\":\"SIGNATURE_CRYPTOGRAPHICALLY_VALID\"",
                   "Detached verify report should mark crypto integrity checked and valid");
    // Summary semantic (trust-store empty in fixture dir) — must be one of the integrity-only forms
    ExpectTrue(Contains(report, "\"summaryCode\":\"integrity-without-trust-store\"") ||
                   Contains(report, "\"summaryCode\":\"integrity-only\"") ||
                   Contains(report, "\"summaryCode\":\"integrity-but-chain-incomplete\"") ||
                   Contains(report, "\"summaryCode\":\"integrity-and-trust\""),
               "Detached verify summary should reflect integrity-only (no trust-store) class");
    // Legacy fields preserved for 1C clients that parse v3
    ExpectContains(report, "\"signatureValid\":true", "Legacy signatureValid must remain available for v3 clients");
    ExpectContains(report, "\"executionSucceeded\":true", "Legacy executionSucceeded must remain available for v3 clients");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestAttachedCmsVerifyReportFormalization() {
#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU4145 fixture generation should succeed (attached verify report)");
    if (!fixture.valid) {
        return;
    }

    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for attached verify report test");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "ReadPrivateKeyBinary should load DSTU4145 PKCS#12 fixture (attached verify report)");

    const std::vector<std::uint8_t> payload = {'a', 't', 't', 'a', 'c', 'h', 'e', 'd'};
    std::vector<std::uint8_t> signed_blob;
    ExpectSessionTrue(session, session.SignDataInternal(payload, signed_blob),
                      "SignDataInternal should succeed for attached verify report test");

    bool is_valid = false;
    std::vector<std::uint8_t> extracted;
    ExpectSessionTrue(session, session.VerifyDataInternal(signed_blob, is_valid, extracted),
                      "VerifyDataInternal should succeed for attached verify report test");
    ExpectTrue(is_valid, "VerifyDataInternal should confirm crypto integrity of attached DSTU4145 signature");
    ExpectTrue(extracted == payload, "VerifyDataInternal should return original payload");

    std::string report;
    ExpectTrue(session.GetLastVerifyReport(report),
               "GetLastVerifyReport should succeed after attached verify");
    ExpectContains(report, "\"operation\":\"VerifyDataInternal\"",
                   "Attached verify report should identify VerifyDataInternal operation");
    ExpectContains(report, "\"code\":\"SIGNATURE_CRYPTOGRAPHICALLY_VALID\"",
                   "Attached verify report should mark crypto integrity checked and valid");
    ExpectContains(report, "\"signerCertificatePresent\":true",
                   "Attached CMS should expose signer certificate from embedded certs");
    ExpectContains(report, "\"certificate\":{",
                   "Attached verify report should expose certificate category");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestDetachedCmsVerifyRejectsTamperedSignature() {
#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU4145 fixture generation should succeed (tamper detached)");
    if (!fixture.valid) {
        return;
    }

    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for tamper detached test");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "ReadPrivateKeyBinary should load DSTU4145 fixture (tamper detached)");

    const std::vector<std::uint8_t> payload = {'t', 'a', 'm', 'p', 'e', 'r', '-', 'd'};
    std::vector<std::uint8_t> signature;
    ExpectSessionTrue(session, session.SignData(payload, signature),
                      "SignData should succeed for tamper detached test");
    ExpectFalse(signature.empty(), "SignData must produce non-empty signature before tampering");

    // Tamper the payload: verify against different data → integrity must fail.
    std::vector<std::uint8_t> tampered_payload = payload;
    tampered_payload.back() ^= 0xFF;

    bool is_valid = true;
    const bool call_result = session.VerifyData(tampered_payload, signature, is_valid);
    ExpectFalse(is_valid, "is_valid must be false for a tampered detached payload");

    std::string report;
    ExpectTrue(session.GetLastVerifyReport(report), "GetLastVerifyReport should succeed after tamper detection");
    ExpectContains(report, "\"operation\":\"VerifyData\"",
                   "Tampered detached verify report should identify VerifyData operation");
    ExpectContains(report, "\"signatureValid\":false",
                   "Tampered detached verify must report signatureValid=false");
    // cryptonite's pkix layer may expose tamper either as a clean integrity-failure rc
    // (translated to executionSucceeded=true, is_valid=false) or as an execution error
    // (translated to executionSucceeded=false). Both are acceptable tamper signals.
    if (call_result) {
        ExpectContains(report, "\"executionSucceeded\":true",
                       "Clean integrity failure should keep executionSucceeded=true");
        ExpectContains(report, "\"code\":\"SIGNATURE_CRYPTOGRAPHICALLY_INVALID\"",
                       "Clean integrity failure should report cryptoIntegrity.valid=false");
        ExpectContains(report, "\"summaryCode\":\"integrity-failed\"",
                       "Clean integrity failure should summarize as integrity-failed");
    } else {
        ExpectContains(report, "\"executionSucceeded\":false",
                       "Execution failure should report executionSucceeded=false");
        ExpectContains(report, "\"summaryCode\":\"execution-failed\"",
                       "Execution failure should summarize as execution-failed");
    }
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestAttachedCmsVerifyRejectsTamperedBlob() {
#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU4145 fixture generation should succeed (tamper attached)");
    if (!fixture.valid) {
        return;
    }

    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for tamper attached test");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "ReadPrivateKeyBinary should load DSTU4145 fixture (tamper attached)");

    const std::vector<std::uint8_t> payload = {'t', 'a', 'm', 'p', 'e', 'r', '-', 'a'};
    std::vector<std::uint8_t> signed_blob;
    ExpectSessionTrue(session, session.SignDataInternal(payload, signed_blob),
                      "SignDataInternal should succeed for tamper attached test");
    ExpectFalse(signed_blob.empty(), "SignDataInternal must produce non-empty blob before tampering");

    // Tamper a byte near the end of the blob — for DSTU4145 CMS this lands within the signature
    // value, so sdata_verify_internal_data_by_adapter returns an integrity-failure rc rather than
    // an ASN.1 decoding error.
    ExpectTrue(signed_blob.size() > 32, "CMS blob must be large enough to tamper safely");
    signed_blob[signed_blob.size() - 8] ^= 0x01;

    bool is_valid = true;
    std::vector<std::uint8_t> extracted;
    const bool call_result = session.VerifyDataInternal(signed_blob, is_valid, extracted);
    ExpectFalse(is_valid, "is_valid must be false for a tampered attached CMS blob");

    std::string report;
    ExpectTrue(session.GetLastVerifyReport(report),
               "GetLastVerifyReport should succeed after tamper attached detection");
    ExpectContains(report, "\"operation\":\"VerifyDataInternal\"",
                   "Tampered attached verify report should identify VerifyDataInternal operation");
    ExpectContains(report, "\"signatureValid\":false",
                   "Tampered attached verify must report signatureValid=false");
    // Depending on which byte was tampered, we either get a clean integrity failure
    // (call_result==true, executionSucceeded=true) or an ASN.1/decoding execution failure
    // (call_result==false, executionSucceeded=false). Both must be reflected in the summary.
    if (call_result) {
        ExpectContains(report, "\"executionSucceeded\":true",
                       "Clean integrity failure should keep executionSucceeded=true");
        ExpectContains(report, "\"code\":\"SIGNATURE_CRYPTOGRAPHICALLY_INVALID\"",
                       "Clean integrity failure should report cryptoIntegrity.valid=false");
        ExpectContains(report, "\"summaryCode\":\"integrity-failed\"",
                       "Clean integrity failure should summarize as integrity-failed");
    } else {
        ExpectContains(report, "\"executionSucceeded\":false",
                       "Decoding failure path should report executionSucceeded=false");
        ExpectContains(report, "\"summaryCode\":\"execution-failed\"",
                       "Decoding failure path should summarize as execution-failed");
    }
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestSignVerifyIntegrationCanonicalFixtureBlocker() {
    const auto canonical_fixture = FixturePath("pki/keycert.pem");
    ExpectTrue(std::filesystem::exists(canonical_fixture), "Canonical sign->verify fixture should exist in repository");

    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for canonical sign->verify scenario");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyFile(canonical_fixture.string(), ""),
                      "ReadPrivateKeyFile should load canonical PEM key+cert fixture for sign->verify");

    const std::vector<std::uint8_t> payload = {'T', 'a', 'm', 'g', 'a'};

    std::vector<std::uint8_t> detached_signature;
    ExpectFalse(session.SignData(payload, detached_signature),
                "Canonical fixture currently should expose signer blocker for detached sign");
    #if TAMGA_CRYPTONITE_ENABLED
    ExpectContains(session.GetLastError().message,
                   "signer preparation failed",
                   "Detached sign blocker should report signer preparation failure");
#else
    ExpectContains(session.GetLastError().message,
                   "TAMGA_ENABLE_VENDOR_CRYPTONITE=ON",
                   "Detached sign blocker should report disabled cryptonite build");
#endif

    std::vector<std::uint8_t> internal_signature;
    ExpectFalse(session.SignDataInternal(payload, internal_signature),
                "Canonical fixture currently should expose signer blocker for internal sign");
    #if TAMGA_CRYPTONITE_ENABLED
    ExpectContains(session.GetLastError().message,
                   "signer preparation failed",
                   "Internal sign blocker should report signer preparation failure");
#else
    ExpectContains(session.GetLastError().message,
                   "TAMGA_ENABLE_VENDOR_CRYPTONITE=ON",
                   "Internal sign blocker should report disabled cryptonite build");
#endif
}


void TestGetCertificateInfoWithPemFixture() {
    tamga::core::Session session;
    std::string json;
    const auto cert_pem = ReadBinaryFixture(FixturePath("pki/cert.pem"));
    std::vector<tamga::core::PemDerLoader::PemBlock> blocks;
    std::string error;
    tamga::core::PemDerLoader::LoadOptions options;
    options.strict_mode = true;
    ExpectTrue(tamga::core::PemDerLoader::LoadAll(cert_pem, blocks, error, options), "PEM certificate fixture should parse");
    const auto cert_it = std::find_if(blocks.begin(), blocks.end(), [](const auto& block) { return block.type == "CERTIFICATE"; });
    ExpectTrue(cert_it != blocks.end(), "PEM certificate fixture should contain CERTIFICATE block");
    if (cert_it == blocks.end()) {
        return;
    }
    const auto cert_blob = cert_it->der_payload;
    ExpectTrue(session.GetCertificateInfo(cert_blob, json), "GetCertificateInfo should parse PEM certificate fixture");
    ExpectContains(json, "\"serial\":\"", "GetCertificateInfo should contain serial");
    ExpectContains(json, "\"validity\":{", "GetCertificateInfo should contain validity object");
    ExpectContains(json, "\"subjectDn\":\"", "GetCertificateInfo should contain subjectDn field");

    // Verify RFC 4514 format of the PEM fixture subject.
    ExpectContains(json, "CN=Tamga Test", "subjectDn should contain CN in RFC 4514 format");
    ExpectContains(json, "O=Tamga", "subjectDn should contain O in RFC 4514 format");
    ExpectContains(json, "C=UA", "subjectDn should contain C in RFC 4514 format");

    // Verify new fields are present
    ExpectContains(json, "\"extKeyUsage\":", "GetCertificateInfo should contain extKeyUsage field");
    ExpectContains(json, "\"authorityKeyIdentifier\":", "GetCertificateInfo should contain authorityKeyIdentifier field");
    ExpectContains(json, "\"subjectAltName\":", "GetCertificateInfo should contain subjectAltName field");
    ExpectContains(json, "\"crlDistributionPoints\":", "GetCertificateInfo should contain crlDistributionPoints field");

    // ME-08: validAtCurrentTime — явний, однозначний alias для того самого
    // значення, що validNow (legacy). Без validationTimeIso "validAt.time"
    // лишається порожнім, а "validAt.valid" — false (нічого не запитано).
    ExpectContains(json, "\"validAtCurrentTime\":", "GetCertificateInfo should contain validAtCurrentTime field");
    ExpectContains(json, "\"validAt\":{\"time\":\"\",\"valid\":false}",
                   "GetCertificateInfo without validationTimeIso must report an empty/unrequested validAt block");
}

// ME-08: GetCertificateInfo(certData, validationTimeIso) — перевірка валідності
// сертифіката на ДОВІЛЬНИЙ момент часу, а не лише "зараз" (validNow), і
// відхилення нерозпізнаного значення часу (fail-closed, не мовчазний ignore).
void TestGetCertificateInfoValidAtExplicitTime() {
#if TAMGA_CRYPTONITE_ENABLED
    tamga::core::Session session;
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for ME-08 validAt test");
    if (!fixture.valid) {
        return;
    }

    // Санітарна перевірка: сертифікат фікстури має бути валідним "зараз"
    // (як і інші тести, що покладаються на цю фікстуру для підпису/TSA).
    std::string json_now;
    ExpectTrue(session.GetCertificateInfo(fixture.cert_der, json_now), "GetCertificateInfo should parse fixture certificate");
    ExpectContains(json_now, "\"validNow\":true", "sanity: fixture certificate must be valid right now");

    // Довільний момент часу в межах notBefore..notAfter — valid=true. Фікстура
    // діє (now - 1 день) .. (+364 днів) (див. GenerateDstuFixture), тож
    // "+30 днів від зараз" гарантовано в межах вікна незалежно від часу
    // запуску тесту.
    const time_t in_range_ts = std::time(nullptr) + 30 * 86400;
    std::tm in_range_tm{};
#ifdef _WIN32
    gmtime_s(&in_range_tm, &in_range_ts);
#else
    gmtime_r(&in_range_ts, &in_range_tm);
#endif
    char in_range_buf[32];
    std::strftime(in_range_buf, sizeof(in_range_buf), "%Y-%m-%dT%H:%M:%SZ", &in_range_tm);
    const std::string in_range_iso(in_range_buf);

    std::string json_in_range;
    ExpectTrue(session.GetCertificateInfo(fixture.cert_der, json_in_range, in_range_iso),
               "GetCertificateInfo with an in-range validationTimeIso should succeed");
    ExpectContains(json_in_range, "\"validAt\":{\"time\":\"" + in_range_iso + "\",\"valid\":true}",
                   "ME-08: validAt must report valid=true for a timestamp within the certificate's validity window");

    // Явно далеке майбутнє — після notAfter -- valid=false. Лишаємось нижче
    // межі 2038 року: на 32-бітних цілях (time_t 32-біт) дата після 2038
    // переповнює timegm()/_mkgmtime() у ParseIso8601Time, і виклик впаде
    // (fail-closed), а не поверне очікуваний valid=false.
    std::string json_future;
    ExpectTrue(session.GetCertificateInfo(fixture.cert_der, json_future, "2035-01-01T00:00:00Z"),
               "GetCertificateInfo with a far-future validationTimeIso should still succeed (execution-level)");
    ExpectContains(json_future, "\"validAt\":{\"time\":\"2035-01-01T00:00:00Z\",\"valid\":false}",
                   "ME-08: validAt must report valid=false for a timestamp after notAfter");

    // Явно далеке минуле — до notBefore -- valid=false.
    std::string json_past;
    ExpectTrue(session.GetCertificateInfo(fixture.cert_der, json_past, "1990-01-01T00:00:00Z"),
               "GetCertificateInfo with a far-past validationTimeIso should still succeed (execution-level)");
    ExpectContains(json_past, "\"validAt\":{\"time\":\"1990-01-01T00:00:00Z\",\"valid\":false}",
                   "ME-08: validAt must report valid=false for a timestamp before notBefore");

    // Регресія: нерозпізнаний час МАЄ відхилятись (fail-closed), а не мовчки
    // ігноруватись як "не запитано".
    std::string json_invalid;
    ExpectFalse(session.GetCertificateInfo(fixture.cert_der, json_invalid, "not-a-timestamp"),
               "ME-08: GetCertificateInfo must reject an unparseable validationTimeIso");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
              "ME-08: unparseable validationTimeIso must set InvalidArgument");
#else
    // V-05: у діагностичній збірці vendor=OFF фікстура ДСТУ недоступна за
    // побудовою (GenerateDstuFixture під тим самим guard). Без цієї гілки
    // документована OFF-конфігурація просто не компілювалась.
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}
