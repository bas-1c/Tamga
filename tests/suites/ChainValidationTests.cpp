// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Валідація ланцюга сертифікатів, історичні знімки TL і оцінка
// довірчих сервісів. Разом із `PathBuildingTests` це повний шлях довіри.

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

void TestCertificateChainValidatorRejectsEmptyTrustStore() {
#if TAMGA_CRYPTONITE_ENABLED
    tamga::core::policy::CertificateChainValidator validator;
    tamga::core::policy::CertificateChainInput input;
    input.signer_certificate_der = GenerateDstuFixture().cert_der;
    const auto result = validator.Validate(input);
    ExpectTrue(result.checked, "Chain validator should check non-empty signer certificate");
    ExpectTrue(result.status == tamga::core::policy::ChainStatus::Untrusted,
               "Empty trust store should produce untrusted chain");
#endif
}

void TestCertificateChainValidatorTrustsSelfSignedAnchorFixture() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    tamga::core::policy::CertificateChainValidator validator;
    tamga::core::policy::CertificateChainInput input;
    input.signer_certificate_der = fixture.cert_der;
    input.trust_anchors_der.push_back(fixture.cert_der);
    const auto result = validator.Validate(input);
    ExpectTrue(result.checked, "Chain validator should check signer certificate");
    ExpectTrue(result.trusted, "Self-signed fixture certificate should be trusted when present as anchor");
    ExpectTrue(result.signer_issuer_certificate_der == fixture.cert_der,
               "Direct trust anchor should also be reported as signer immediate issuer");
#endif
}

void TestCertificateChainValidatorRejectsMalformedSignerDer() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    tamga::core::policy::CertificateChainValidator validator;
    tamga::core::policy::CertificateChainInput input;
    input.signer_certificate_der = {0x30, 0x03, 0x02, 0x01, 0xff};
    input.trust_anchors_der.push_back(fixture.cert_der);
    const auto result = validator.Validate(input);
    ExpectTrue(result.checked, "Malformed signer certificate should still be checked");
    ExpectFalse(result.trusted, "Malformed signer certificate must not be trusted");
    ExpectTrue(result.status == tamga::core::policy::ChainStatus::InvalidSignature,
               "Malformed signer DER should produce InvalidSignature chain status");
    ExpectTrue(Contains(result.message, "decode"),
               "Malformed signer DER should preserve a decode failure message");
#endif
}

void TestCertificateChainValidatorRejectsWrongDirectionAnchorVerification() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto root = ReadBinaryFixture(
        pki_dir / "root_certificate.cer");
    const auto user = ReadBinaryFixture(
        pki_dir / "userur_certificate.cer");
    if (root.empty() || user.empty()) {
        RecordSkip("Cryptonite PKI fixtures not available");
        return;
    }

    tamga::core::policy::CertificateChainValidator validator;
    tamga::core::policy::CertificateChainInput input;
    input.signer_certificate_der = root;
    input.trust_anchors_der.push_back(user);
    const auto result = validator.Validate(input);
    ExpectTrue(result.checked, "Wrong-direction chain should be checked");
    ExpectFalse(result.trusted,
                "Signer must not be trusted only because the configured anchor verifies by signer");
#endif
}

// Хвиля 8, п.5: група тестів побудови та вибору шляху сертифіката
// переїхала у `tests/suites/PathBuildingTests.cpp`. Оголошення — в
// `tests/suites/Suites.h`; порядок викликів у main() не змінився, тож
// список `Running ...` лишається побайтово тим самим.

void TestParseIso8601Time() {
    time_t val = 0;
    ExpectTrue(tamga::core::policy::ParseIso8601Time("2026-06-15T18:08:47Z", val),
               "ParseIso8601Time should parse UTC ISO-8601 successfully");
    
    struct tm tm_val{};
#ifdef _WIN32
    const auto* gmt = gmtime(&val);
    if (gmt) tm_val = *gmt;
#else
    gmtime_r(&val, &tm_val);
#endif
    ExpectTrue(tm_val.tm_year == 2026 - 1900, "Year should be 2026");
    ExpectTrue(tm_val.tm_mon == 6 - 1, "Month should be 6");
    ExpectTrue(tm_val.tm_mday == 15, "Day should be 15");
    ExpectTrue(tm_val.tm_hour == 18, "Hour should be 18");
    ExpectTrue(tm_val.tm_min == 8, "Minute should be 8");
    ExpectTrue(tm_val.tm_sec == 47, "Second should be 47");
    
    ExpectFalse(tamga::core::policy::ParseIso8601Time("invalid-date", val),
                "ParseIso8601Time should reject invalid date strings");

#if TAMGA_CRYPTONITE_ENABLED
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto root_der = ReadBinaryFixture(pki_dir / "root_certificate.cer");
    if (!root_der.empty()) {
        ByteArray* ba = ba_alloc_from_uint8(root_der.data(), root_der.size());
        Certificate_t* cert = cert_alloc();
        if (ba != nullptr && cert != nullptr && cert_decode(cert, ba) == RET_OK) {
            ByteArray* ext = nullptr;
            bool is_ca = false;
            if (cert_get_ext_value(cert, oids_get_oid_numbers_by_id(OID_BASIC_CONSTRAINTS_EXTENSION_ID), &ext) == RET_OK && ext != nullptr) {
                BasicConstraints_t* basic_constraints = static_cast<BasicConstraints_t*>(
                    asn_decode_with_alloc(get_BasicConstraints_desc(), ba_get_buf(ext), ba_get_len(ext)));
                is_ca = basic_constraints != nullptr && basic_constraints->cA != nullptr && *basic_constraints->cA != 0;
                ASN_FREE(get_BasicConstraints_desc(), basic_constraints);
            }
            ba_free(ext);

            KeyUsage_t* usage = nullptr;
            int rc = cert_get_key_usage(cert, &usage);
            int bit = 0;
            int bit_rc = -1;
            if (rc == RET_OK && usage != nullptr) {
                bit_rc = asn_BITSTRING_get_bit(usage, KeyUsage_keyCertSign, &bit);
            }
            std::cerr << "!!! DIAGNOSTIC: root cert is_ca=" << is_ca
                      << ", key_usage_rc=" << rc
                      << ", usage_null=" << (usage == nullptr)
                      << ", bit_rc=" << bit_rc
                      << ", bit=" << bit << "\n";
            if (usage != nullptr) {
                ASN_FREE(get_KeyUsage_desc(), usage);
            }
        } else {
            std::cerr << "!!! DIAGNOSTIC: root cert failed to decode\n";
        }
        ba_free(ba);
        cert_free(cert);
    } else {
        std::cerr << "!!! DIAGNOSTIC: root cert empty\n";
    }
#endif
}

void TestCertificateChainValidatorTimeAware() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        return;
    }
    tamga::core::policy::CertificateChainValidator validator;
    tamga::core::policy::CertificateChainInput input;
    input.signer_certificate_der = fixture.cert_der;
    input.trust_anchors_der.push_back(fixture.cert_der);

    // Test 1: empty validation_time => valid (current time)
    {
        const auto result = validator.Validate(input);
        ExpectTrue(result.trusted, "Empty validation_time should fall back to current time (valid)");
    }

    // Test 2: validation_time in the past (before notBefore) => Expired
    {
        input.validation_time = "2000-01-01T00:00:00Z";
        const auto result = validator.Validate(input);
        ExpectFalse(result.trusted, "Past validation_time should be untrusted");
        ExpectTrue(result.status == tamga::core::policy::ChainStatus::Expired,
                   "Past validation_time should fail with ChainStatus::Expired");
    }

    // Test 3: validation_time in the future (after notAfter) => Expired.
    // The fixture cert is valid for 365 days from "now", so any year well past
    // that proves the point. Keep it below the 2038 boundary: on 32-bit targets
    // time_t is 32-bit, and a post-2038 timestamp overflows timegm() in
    // ParseIso8601Time (fails to parse, silently falls back to current-time
    // validation). 2037 is comfortably after notAfter on every supported arch.
    {
        input.validation_time = "2037-01-01T00:00:00Z";
        const auto result = validator.Validate(input);
        ExpectFalse(result.trusted, "Future validation_time should be untrusted");
        ExpectTrue(result.status == tamga::core::policy::ChainStatus::Expired,
                   "Future validation_time should fail with ChainStatus::Expired");
    }
#endif
}

void TestHistoricalTlSnapshotSelection() {
    const auto work_dir = MakeTemporaryFixturePath(".historical-tl-select");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir / "trust-list" / "history", ec);

    auto write_dummy = [](const std::filesystem::path& path) {
        std::ofstream out(path);
        out << "dummy";
    };

    const auto current_path = work_dir / "trust-list" / "TL-UA-EC.xml";
    const auto tl_2024_01 = work_dir / "trust-list" / "history" / "TL-UA-EC-2024-01.xml";
    const auto tl_2024_05 = work_dir / "trust-list" / "history" / "TL-UA-EC-2024-05.xml";
    const auto tl_2024_12 = work_dir / "trust-list" / "history" / "TL-UA-EC-2024-12.xml";

    write_dummy(current_path);
    write_dummy(tl_2024_01);
    write_dummy(tl_2024_05);
    write_dummy(tl_2024_12);

    using tamga::core::validation::TrustServiceEvaluator;

    // Test 1: strict current TL
    auto res = TrustServiceEvaluator::SelectSnapshot(work_dir.string(), "2024-05-15T00:00:00Z", true);
    ExpectTrue(res == current_path, "Strict current TL should always return current TL path");

    // Test 2: empty reference time
    res = TrustServiceEvaluator::SelectSnapshot(work_dir.string(), "", false);
    ExpectTrue(res == current_path, "Empty reference time should return current TL path");

    // Test 3: exact match
    res = TrustServiceEvaluator::SelectSnapshot(work_dir.string(), "2024-05-01T00:00:00Z", false);
    ExpectTrue(res == tl_2024_05, "Exact year-month match should return corresponding snapshot");

    // Test 4: reference time between snapshots (2024-06-15) => should select 2024-05
    res = TrustServiceEvaluator::SelectSnapshot(work_dir.string(), "2024-06-15T00:00:00Z", false);
    ExpectTrue(res == tl_2024_05, "Reference time between snapshots should select nearest past snapshot");

    // Test 5: reference time before all history files (2023-11) => should select earliest (2024-01)
    res = TrustServiceEvaluator::SelectSnapshot(work_dir.string(), "2023-11-01T00:00:00Z", false);
    ExpectTrue(res == tl_2024_01, "Reference time before all history should select earliest snapshot");

    // Clean up
    std::filesystem::remove_all(work_dir, ec);
}

void TestTrustServiceEvaluatorEvaluation() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto cert_pem = ReadBinaryFixture(FixturePath("pki/cert.pem"));
    std::vector<tamga::core::PemDerLoader::PemBlock> blocks;
    std::string error;
    tamga::core::PemDerLoader::LoadOptions options;
    options.strict_mode = true;
    ExpectTrue(tamga::core::PemDerLoader::LoadAll(cert_pem, blocks, error, options),
               "PEM certificate fixture should parse for trust service evaluator test");
    const auto cert_it = std::find_if(blocks.begin(), blocks.end(),
                                      [](const auto& block) { return block.type == "CERTIFICATE"; });
    ExpectTrue(cert_it != blocks.end(), "PEM certificate fixture should contain CERTIFICATE block");
    if (cert_it == blocks.end()) {
        return;
    }
    const auto& cert_der = cert_it->der_payload;

    const auto xml_data = BuildGrantedCaTrustListXmlForTest(cert_der);
    std::string xml(xml_data.begin(), xml_data.end());

    using tamga::core::validation::TrustServiceEvaluator;
    TrustServiceEvaluator evaluator;

    // Test 1: valid certificate found in trust list
    auto res = evaluator.Evaluate(cert_der, xml, "sha256:test");
    ExpectTrue(res.checked, "TrustServiceEvaluator should perform evaluation");
    ExpectTrue(res.service_trusted, "Service should be trusted");
    ExpectTrue(res.service_type == "http://czo.gov.ua/TrstSvc/Svctype/CA/QC", "Service type should match XML");
    ExpectTrue(res.status == "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted", "Status should match XML");
    ExpectTrue(res.snapshot_evidence_id == "sha256:test", "Snapshot evidence ID should match input");
    ExpectTrue(res.limitations.empty(), "There should be no limitations for trusted service");

    // Test 2: non-granted service
    const auto xml_revoked_data = BuildTrustListXmlForTest("http://czo.gov.ua/TrstSvc/Svctype/CA/QC",
                                                           "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/withdrawn",
                                                           cert_der);
    std::string xml_revoked(xml_revoked_data.begin(), xml_revoked_data.end());
    res = evaluator.Evaluate(cert_der, xml_revoked, "sha256:test");
    ExpectTrue(res.checked, "Evaluation should run");
    ExpectFalse(res.service_trusted, "Service should not be trusted");
    ExpectTrue(res.limitations.size() == 1, "There should be 1 limitation");
    ExpectContains(res.limitations[0], "status is not granted", "Limitation should explain non-granted status");

    // Test 3: cert not found
    std::vector<std::uint8_t> dummy_cert = {0x30, 0x03, 0x02, 0x01, 0x01};
    res = evaluator.Evaluate(dummy_cert, xml, "sha256:test");
    ExpectTrue(res.checked, "Evaluation should run");
    ExpectFalse(res.service_trusted, "Service should not be trusted");
    ExpectTrue(res.limitations.size() == 1, "There should be 1 limitation");
    ExpectContains(res.limitations[0], "not found in trust list", "Limitation should explain not found");
#endif
}
