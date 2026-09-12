#include "support/FixturePaths.h"
// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// CAdES-T: додавання й витяг мітки часу, визначення алгоритму дайджесту
// підписувача, режими роботи з TSP.

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

void TestCadesTAppendAndExtract() {
#if TAMGA_CRYPTONITE_ENABLED
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestCadesTAppendAndExtract ---\n";

    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for CAdES-T test");
    ExpectSessionTrue(session,
        session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
        "ReadPrivateKeyBinary should load key for CAdES-T test");

    std::vector<std::uint8_t> data = { 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd' };
    std::vector<std::uint8_t> signature;
    ExpectSessionTrue(session, session.SignData(data, signature), "SignData should succeed");

    std::vector<std::uint8_t> sig_val;
    std::string err;
    ExpectTrue(CryptoniteAdapter::GetSignatureValue(signature, sig_val, err), "GetSignatureValue should succeed");
    ExpectFalse(sig_val.empty(), "Signature value should not be empty");

    bool has_tsp_token = true;
    ExpectTrue(CryptoniteAdapter::HasSignatureTimestampToken(signature, has_tsp_token, err),
               "HasSignatureTimestampToken should inspect BES signature");
    ExpectFalse(has_tsp_token, "Fresh BES signature should not contain id-aa-signatureTimeStampToken");

    std::vector<std::uint8_t> mock_tsp_token = { 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 0x4f, 0x4b };
    std::vector<std::uint8_t> cms_with_tsp;
    ExpectTrue(CryptoniteAdapter::AppendTspToken(signature, mock_tsp_token, cms_with_tsp, err), "AppendTspToken should succeed");
    ExpectFalse(cms_with_tsp.empty(), "CMS with TSP should not be empty");
    ExpectTrue(cms_with_tsp.size() > signature.size(), "CMS with TSP should be larger than BES CMS");
    ExpectTrue(CryptoniteAdapter::HasSignatureTimestampToken(cms_with_tsp, has_tsp_token, err),
               "HasSignatureTimestampToken should inspect CAdES-T signature");
    ExpectTrue(has_tsp_token, "CAdES-T signature should contain id-aa-signatureTimeStampToken");
    std::vector<std::uint8_t> extracted_tsp_token;
    ExpectTrue(CryptoniteAdapter::ExtractSignatureTimestampToken(cms_with_tsp, extracted_tsp_token, err),
               "ExtractSignatureTimestampToken should extract CAdES-T timestamp token");
    ExpectTrue(extracted_tsp_token == mock_tsp_token,
               "ExtractSignatureTimestampToken should preserve timestamp token DER bytes");

    bool is_valid = false;
    ExpectSessionTrue(session, session.VerifyData(data, cms_with_tsp, is_valid), "VerifyData on CAdES-T signature should succeed");
    ExpectTrue(is_valid, "CAdES-T signature should be cryptographically valid");
#endif
}

void TestGetSignerDigestAlgorithmOid() {
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestGetSignerDigestAlgorithmOid ---\n";

    std::string digest_oid;
    std::string error_message;

    // 1. Порожній вхід
    std::vector<std::uint8_t> empty_cms;
    bool ok = CryptoniteAdapter::GetSignerDigestAlgorithmOid(empty_cms, digest_oid, error_message);
#if TAMGA_CRYPTONITE_ENABLED
    ExpectFalse(ok, "GetSignerDigestAlgorithmOid should fail for empty input");
    ExpectTrue(error_message.find("empty CMS input") != std::string::npos, "Error should mention empty CMS input");
#else
    ExpectFalse(ok, "GetSignerDigestAlgorithmOid should fail when Cryptonite is disabled");
    ExpectTrue(error_message == "Cryptonite not enabled", "Error should say Cryptonite not enabled");
#endif

    // 2. Некоректні дані
    std::vector<std::uint8_t> invalid_cms = {0x01, 0x02, 0x03};
    error_message.clear();
    ok = CryptoniteAdapter::GetSignerDigestAlgorithmOid(invalid_cms, digest_oid, error_message);
#if TAMGA_CRYPTONITE_ENABLED
    ExpectFalse(ok, "GetSignerDigestAlgorithmOid should fail for invalid CMS");
    ExpectTrue(error_message.find("ContentInfo decode") != std::string::npos, "Error should mention ContentInfo decode");
#else
    ExpectFalse(ok, "GetSignerDigestAlgorithmOid should fail when Cryptonite is disabled");
    ExpectTrue(error_message == "Cryptonite not enabled", "Error should say Cryptonite not enabled");
#endif

    // 3. Реальний підпис з файлу (ДСТУ 34311 / ГОСТ 34.311)
#if TAMGA_CRYPTONITE_ENABLED
    std::filesystem::path sig_path = tamga_test::TestDataRoot() / "tests" / "rahunok.pdf.sig";
    std::vector<std::uint8_t> cms_data = ReadBinaryFixture(sig_path);
    if (!cms_data.empty()) {
        error_message.clear();
        digest_oid.clear();
        ok = CryptoniteAdapter::GetSignerDigestAlgorithmOid(cms_data, digest_oid, error_message);
        ExpectTrue(ok, "GetSignerDigestAlgorithmOid should succeed on real CMS signature");
        ExpectTrue(error_message.empty(), "Error message should be empty on success");
        ExpectTrue(digest_oid == "1.2.804.2.1.1.1.1.2.1", "Should extract GOST 34.311 OID from rahunok.pdf.sig");
    } else {
        // rahunok.pdf.sig — локальний бінарний fixture, який не зберігається в git.
        // GOST 34.311 OID-екстракцію також покриває крок 4 нижче через
        // згенерований DSTU-fixture, тож за відсутності файлу крок пропускаємо.
        RecordSkip("rahunok.pdf.sig fixture not available");
    }

    // 4. Підпис з ДСТУ 34311 (через генерацію з fixture)
    auto fixture = GenerateDstuFixture();
    if (fixture.valid) {
        Session session;
        ExpectTrue(PrepareInitializedSession(session), "Session should initialize for DSTU test");
        ExpectTrue(session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                   "ReadPrivateKeyBinary should load key for DSTU test");
        
        std::vector<std::uint8_t> data = {'t', 'e', 's', 't'};
        std::vector<std::uint8_t> signature;
        ExpectTrue(session.SignData(data, signature), "SignData should succeed");
        
        error_message.clear();
        digest_oid.clear();
        ok = CryptoniteAdapter::GetSignerDigestAlgorithmOid(signature, digest_oid, error_message);
        ExpectTrue(ok, "GetSignerDigestAlgorithmOid should succeed on generated signature");
        ExpectTrue(digest_oid == "1.2.804.2.1.1.1.1.2.1", "Should extract GOST 34.311 OID");
    } else {
        RecordSkip("DSTU fixture not available for DSTU check");
    }

    // 5. Реальний підпис (Купина-256) з tsa_token.der
    std::filesystem::path tsa_path = tamga_test::TestDataRoot() / "tests" / "tsa_token.der";
    std::vector<std::uint8_t> tsa_data = ReadBinaryFixture(tsa_path);
    if (tsa_data.empty()) {
        RecordSkip("External timestamp corpus is not configured (TAMGA_TEST_DATA_ROOT)");
        return;
    }

    error_message.clear();
    digest_oid.clear();
    ok = CryptoniteAdapter::GetSignerDigestAlgorithmOid(tsa_data, digest_oid, error_message);
    ExpectTrue(ok, "GetSignerDigestAlgorithmOid should succeed on tsa_token.der");
    ExpectTrue(error_message.empty(), "Error message should be empty on success");
    ExpectTrue(digest_oid == "1.2.804.2.1.1.1.1.2.2.1", "Should extract Kupyna-256 OID from tsa_token.der");
#endif
}

void TestImprintFromDigestOidMapping() {
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestImprintFromDigestOidMapping ---\n";

    // Тести регістронезалежності
    auto alg = ImprintFromDigestOid("KUPYNA-256");
    ExpectTrue(alg.has_value() && alg.value() == ImprintDigest::Kupyna256, "KUPYNA-256 case insensitivity");

    alg = ImprintFromDigestOid("sha-256");
    ExpectTrue(alg.has_value() && alg.value() == ImprintDigest::Sha256, "sha-256 case insensitivity");

    alg = ImprintFromDigestOid("SHA-256");
    ExpectTrue(alg.has_value() && alg.value() == ImprintDigest::Sha256, "SHA-256 case insensitivity");

    // RSA/ECDSA OID-и для SHA-384 та SHA-512
    alg = ImprintFromDigestOid("1.2.840.113549.1.1.12"); // sha384WithRSAEncryption
    ExpectTrue(alg.has_value() && alg.value() == ImprintDigest::Sha384, "sha384WithRSAEncryption OID");

    alg = ImprintFromDigestOid("1.2.840.10045.4.3.3"); // ecdsa-with-SHA384
    ExpectTrue(alg.has_value() && alg.value() == ImprintDigest::Sha384, "ecdsa-with-SHA384 OID");

    alg = ImprintFromDigestOid("1.2.840.113549.1.1.13"); // sha512WithRSAEncryption
    ExpectTrue(alg.has_value() && alg.value() == ImprintDigest::Sha512, "sha512WithRSAEncryption OID");

    alg = ImprintFromDigestOid("1.2.840.10045.4.3.4"); // ecdsa-with-SHA512
    ExpectTrue(alg.has_value() && alg.value() == ImprintDigest::Sha512, "ecdsa-with-SHA512 OID");

    // Інші існуючі
    alg = ImprintFromDigestOid("1.2.804.2.1.1.1.1.2.2.1");
    ExpectTrue(alg.has_value() && alg.value() == ImprintDigest::Kupyna256, "Kupyna-256 OID");

    alg = ImprintFromDigestOid("1.2.804.2.1.1.1.1.2.1");
    ExpectTrue(alg.has_value() && alg.value() == ImprintDigest::Gost34311, "Gost34311 OID");

    alg = ImprintFromDigestOid("invalid-oid");
    ExpectFalse(alg.has_value(), "invalid-oid should return nullopt");
}

void TestTimestampModeDisabledDoesNotRequireTsp() {
#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize for timestamp disabled test");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "ReadPrivateKeyBinary should load key for timestamp disabled test");

    std::vector<std::uint8_t> signature;
    const std::vector<std::uint8_t> data = {'n', 'o', '-', 't', 's', 'p'};
    ExpectSessionTrue(session,
                      session.SignData(data, signature, tamga::core::TimestampMode::Disabled),
                      "SignData with TimestampMode::Disabled should succeed without TSP");

    bool has_tsp = true;
    std::string err;
    ExpectTrue(tamga::core::CryptoniteAdapter::HasSignatureTimestampToken(signature, has_tsp, err),
               "Disabled timestamp mode should still produce inspectable CMS");
    ExpectFalse(has_tsp, "TimestampMode::Disabled should not embed TSP token");
#endif
}

void TestTimestampValidatorMissingForBesSignature() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    tamga::core::Session session;
    PrepareInitializedSession(session);
    ExpectTrue(session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
               "Fixture key should load");
    std::vector<std::uint8_t> signature;
    ExpectTrue(session.SignData(std::vector<std::uint8_t>{'d','a','t','a'},
                                signature,
                                tamga::core::TimestampMode::Disabled),
               "BES signing should succeed");

    // Хвиля 8, п.3: перевірка перенесена на канонічний TimestampEngine —
    // мертвий policy::TimestampValidator видалено разом із його розбіжною
    // політикою direct-match.
    tamga::core::validation::TimestampEngineInput input;
    input.cms_der = signature;
    const auto result = tamga::core::validation::TimestampEngine{}.Validate(input);
    ExpectFalse(result.valid, "BES signature has no timestamp, so it cannot be valid");
    ExpectTrue(result.status == tamga::core::policy::TimestampStatus::Missing,
               "BES signature should report missing timestamp token");
#endif
}

void TestImprintDigest() {
    using namespace tamga::core;
    using namespace tamga::asic;

    // 1. Тести для ImprintFromDigestOid
    {
        // Перевірка OID
        ExpectTrue(ImprintFromDigestOid("1.2.804.2.1.1.1.1.2.2.1") == ImprintDigest::Kupyna256, "OID Kupyna-256");
        ExpectTrue(ImprintFromDigestOid("1.2.804.2.1.1.1.1.2.1") == ImprintDigest::Gost34311, "OID Gost34311");
        ExpectTrue(ImprintFromDigestOid("2.16.840.1.101.3.4.2.1") == ImprintDigest::Sha256, "OID SHA-256");
        ExpectTrue(ImprintFromDigestOid("2.16.840.1.101.3.4.2.2") == ImprintDigest::Sha384, "OID SHA-384");
        ExpectTrue(ImprintFromDigestOid("2.16.840.1.101.3.4.2.3") == ImprintDigest::Sha512, "OID SHA-512");

        // Перевірка аліасів
        ExpectTrue(ImprintFromDigestOid("Kupyna256") == ImprintDigest::Kupyna256, "Alias Kupyna256");
        ExpectTrue(ImprintFromDigestOid("kupyna-256") == ImprintDigest::Kupyna256, "Alias kupyna-256");
        ExpectTrue(ImprintFromDigestOid("Gost34311") == ImprintDigest::Gost34311, "Alias Gost34311");
        ExpectTrue(ImprintFromDigestOid("gost-34311") == ImprintDigest::Gost34311, "Alias gost-34311");
        ExpectTrue(ImprintFromDigestOid("SHA-256") == ImprintDigest::Sha256, "Alias SHA-256");
        ExpectTrue(ImprintFromDigestOid("sha-256") == ImprintDigest::Sha256, "Alias sha-256");
        ExpectTrue(ImprintFromDigestOid("sha256") == ImprintDigest::Sha256, "Alias sha256");
        ExpectTrue(ImprintFromDigestOid("SHA-384") == ImprintDigest::Sha384, "Alias SHA-384");
        ExpectTrue(ImprintFromDigestOid("sha-384") == ImprintDigest::Sha384, "Alias sha-384");
        ExpectTrue(ImprintFromDigestOid("sha384") == ImprintDigest::Sha384, "Alias sha384");
        ExpectTrue(ImprintFromDigestOid("SHA-512") == ImprintDigest::Sha512, "Alias SHA-512");
        ExpectTrue(ImprintFromDigestOid("sha-512") == ImprintDigest::Sha512, "Alias sha-512");
        ExpectTrue(ImprintFromDigestOid("sha512") == ImprintDigest::Sha512, "Alias sha512");

        // Перевірка OID підпису (префікс та конкретні)
        ExpectTrue(ImprintFromDigestOid("1.2.804.2.1.1.1.1.3") == ImprintDigest::Kupyna256, "Prefix DSTU 4145 short");
        ExpectTrue(ImprintFromDigestOid("1.2.804.2.1.1.1.1.3.1.1") == ImprintDigest::Kupyna256, "Prefix DSTU 4145 long");
        ExpectTrue(ImprintFromDigestOid("1.2.840.113549.1.1.11") == ImprintDigest::Sha256, "RSA with SHA-256 OID");
        ExpectTrue(ImprintFromDigestOid("1.2.840.10045.4.3.2") == ImprintDigest::Sha256, "ECDSA with SHA-256 OID");

        // Невалідні OID
        ExpectTrue(!ImprintFromDigestOid("1.2.3.4").has_value(), "Invalid OID");
        ExpectTrue(!ImprintFromDigestOid("unknown-alg").has_value(), "Unknown alias");
    }

    // 2. Тести для ComputeImprint (SHA-256 працює завжди)
    {
        std::vector<std::uint8_t> data = { 0x61, 0x62, 0x63 }; // "abc"
        ImprintResult res;
        std::string err;
        ExpectTrue(ComputeImprint(ImprintDigest::Sha256, data, res, err), "ComputeImprint Sha256 success");
        ExpectTrue(res.digest_oid == "2.16.840.1.101.3.4.2.1", "Sha256 OID correct");
        
        std::vector<std::uint8_t> expected_sha256 = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        };
        ExpectTrue(res.hash == expected_sha256, "Sha256 hash matches");
    }

    // 3. Тести для Kupyna-256, Gost34311, Sha384, Sha512 (під TAMGA_CRYPTONITE_ENABLED)
#if TAMGA_CRYPTONITE_ENABLED
    {
        // Kupyna-256
        std::vector<std::uint8_t> data_kupyna;
        for (int i = 0; i < 64; ++i) {
            data_kupyna.push_back(static_cast<std::uint8_t>(i));
        }
        ImprintResult res;
        std::string err;
        ExpectTrue(ComputeImprint(ImprintDigest::Kupyna256, data_kupyna, res, err), "ComputeImprint Kupyna256 success");
        ExpectTrue(res.digest_oid == "1.2.804.2.1.1.1.1.2.2.1", "Kupyna256 OID correct");
        std::vector<std::uint8_t> expected_kupyna = {
            0x08, 0xF4, 0xEE, 0x6F, 0x1B, 0xE6, 0x90, 0x3B, 0x32, 0x4C, 0x4E, 0x27, 0x99, 0x0C, 0xB2, 0x4E,
            0xF6, 0x9D, 0xD5, 0x8D, 0xBE, 0x84, 0x81, 0x3E, 0xE0, 0xA5, 0x2F, 0x66, 0x31, 0x23, 0x98, 0x75
        };
        ExpectTrue(res.hash == expected_kupyna, "Kupyna256 hash matches");
    }
    {
        // Gost34311
        std::vector<std::uint8_t> data_gost = {
            0xad, 0x26, 0xf4, 0x36, 0xf0, 0xb6, 0x27, 0x88, 0x00, 0x38, 0x72, 0x7d, 0x22, 0xe0, 0x2c, 0x97,
            0xd0, 0x81, 0xef, 0x85, 0x26, 0x0f, 0xc9, 0x67, 0x18, 0x39, 0x50, 0x91, 0xce, 0x22, 0x4d, 0xd7
        };
        ImprintResult res;
        std::string err;
        ExpectTrue(ComputeImprint(ImprintDigest::Gost34311, data_gost, res, err), "ComputeImprint Gost34311 success");
        ExpectTrue(res.digest_oid == "1.2.804.2.1.1.1.1.2.1", "Gost34311 OID correct");
        std::vector<std::uint8_t> expected_gost = {
            0x02, 0xd7, 0xe8, 0xa3, 0xc1, 0x11, 0x78, 0x8b, 0xb1, 0xb8, 0xa4, 0x89, 0xc5, 0xe3, 0x30, 0x28,
            0x87, 0x28, 0xf1, 0xc3, 0x08, 0xc2, 0xce, 0xc0, 0x8e, 0x09, 0x26, 0x5b, 0xfa, 0x39, 0x55, 0x99
        };
        ExpectTrue(res.hash == expected_gost, "Gost34311 hash matches");
    }
    {
        // Sha384
        std::vector<std::uint8_t> data = { 0x61, 0x62, 0x63 }; // "abc"
        ImprintResult res;
        std::string err;
        ExpectTrue(ComputeImprint(ImprintDigest::Sha384, data, res, err), "ComputeImprint Sha384 success");
        ExpectTrue(res.digest_oid == "2.16.840.1.101.3.4.2.2", "Sha384 OID correct");
        std::vector<std::uint8_t> expected_sha384 = {
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
            0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
            0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
        };
        ExpectTrue(res.hash == expected_sha384, "Sha384 hash matches");
    }
    {
        // Sha512
        std::vector<std::uint8_t> data = { 0x61, 0x62, 0x63 }; // "abc"
        ImprintResult res;
        std::string err;
        ExpectTrue(ComputeImprint(ImprintDigest::Sha512, data, res, err), "ComputeImprint Sha512 success");
        ExpectTrue(res.digest_oid == "2.16.840.1.101.3.4.2.3", "Sha512 OID correct");
        std::vector<std::uint8_t> expected_sha512 = {
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
        };
        ExpectTrue(res.hash == expected_sha512, "Sha512 hash matches");
    }
#else
    // Перевірка fail-closed у збірці без cryptonite
    {
        std::vector<std::uint8_t> data = { 1, 2, 3 };
        ImprintResult res;
        std::string err;
        ExpectFalse(ComputeImprint(ImprintDigest::Kupyna256, data, res, err), "Kupyna should fail when cryptonite disabled");
        ExpectFalse(ComputeImprint(ImprintDigest::Gost34311, data, res, err), "Gost should fail when cryptonite disabled");
        ExpectFalse(ComputeImprint(ImprintDigest::Sha384, data, res, err), "Sha384 should fail when cryptonite disabled");
        ExpectFalse(ComputeImprint(ImprintDigest::Sha512, data, res, err), "Sha512 should fail when cryptonite disabled");
    }
#endif
}
