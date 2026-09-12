// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Режими роботи з міткою часу (Required / BestEffort / Disabled) і повна
// перевірка токена TSA. Наскрізна тема — невдача TSP мусить ОЧИЩАТИ
// попередній результат, а не лишати його як свіжий.

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
#include "core/session/PadesEvidenceCollection.h"
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
#include "ocsp_request.h"
#include "ocsp_request_engine.h"
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
#include "CertificateLists.h"
#include "BasicOCSPResponse.h"
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

void TestTimestampValidatorFullVerification() {
#if TAMGA_CRYPTONITE_ENABLED
    // 1. Test verification on real invoice signature with TSA timestamp
    {
        std::ifstream f("tests/invoice.pdf.sig", std::ios::binary);
        if (!f) {
            f.open("../../tests/invoice.pdf.sig", std::ios::binary);
        }
        if (f) {
            std::vector<std::uint8_t> real_sig((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            std::vector<std::uint8_t> real_sig_val;
            std::string sig_val_err;
            bool got_sig_val = tamga::core::CryptoniteAdapter::GetSignatureValue(real_sig, real_sig_val, sig_val_err);
            ExpectTrue(got_sig_val, "Should extract signature value from real invoice signature");

            auto ext_res = tamga::core::policy::ExtractTimestampToken(real_sig);
            ExpectTrue(ext_res.success, "Should extract timestamp token from real invoice signature");

            auto val_res = tamga::core::policy::ValidateTimestampToken(ext_res.token_der, real_sig_val);
            ExpectTrue(val_res.valid, "Should cryptographically validate TSA signature on real invoice");
        }
    }

    // 2. Full validation scenario using TimestampValidator
    const auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    tamga::core::Session session;
    PrepareInitializedSession(session);
    ExpectTrue(session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
               "Fixture key should load");

    std::vector<std::uint8_t> data = { 'T', 'e', 's', 't', ' ', 'D', 'a', 't', 'a' };
    std::vector<std::uint8_t> signature;
    ExpectTrue(session.SignData(data, signature), "SignData should succeed");

    std::vector<std::uint8_t> sig_val;
    std::string err;
    ExpectTrue(tamga::core::CryptoniteAdapter::GetSignatureValue(signature, sig_val, err), "GetSignatureValue should succeed");

    std::vector<std::uint8_t> good_imprint;
    Dstu7564Ctx* ctx = dstu7564_alloc(DSTU7564_SBOX_1);
    dstu7564_init(ctx, 32);
    ByteArray* sig_ba = ba_alloc_from_uint8(sig_val.data(), sig_val.size());
    dstu7564_update(ctx, sig_ba);
    ByteArray* hash_ba = nullptr;
    dstu7564_final(ctx, &hash_ba);
    good_imprint.assign(ba_get_buf(hash_ba), ba_get_buf(hash_ba) + ba_get_len(hash_ba));
    ba_free(hash_ba);
    ba_free(sig_ba);
    dstu7564_free(ctx);

    auto good_tst_info = CreateTstInfoDer(good_imprint, "20260615220000Z");
    std::vector<std::uint8_t> mock_tsp_token;
    ExpectTrue(GenerateMockTspToken(fixture.pkcs12_blob, fixture.cert_der, good_tst_info, mock_tsp_token),
               "GenerateMockTspToken should succeed");

    std::vector<std::uint8_t> cms_with_tsp;
    ExpectTrue(tamga::core::CryptoniteAdapter::AppendTspToken(signature, mock_tsp_token, cms_with_tsp, err), "AppendTspToken should succeed");

    // Scenario A: Full validation successful (when anchor is provided)
    {
        tamga::core::validation::TimestampEngineInput input;
        input.cms_der = cms_with_tsp;
        input.current_trust_anchors_der = { fixture.cert_der };

        const auto result = tamga::core::validation::TimestampEngine{}.Validate(input);
        ExpectFalse(result.valid, "Fixture TSA certificate without timestamping policy evidence must fail closed");
        ExpectTrue(result.status == tamga::core::policy::TimestampStatus::UntrustedTsa ||
                   result.status == tamga::core::policy::TimestampStatus::TsaExpired,
                   "Status should show untrusted or time-invalid TSA");
    }

    // Scenario B: Validation fails if no anchor is provided
    {
        tamga::core::validation::TimestampEngineInput input;
        input.cms_der = cms_with_tsp;

        const auto result = tamga::core::validation::TimestampEngine{}.Validate(input);
        ExpectFalse(result.valid, "Should fail without trust anchors");
        ExpectTrue(result.status == tamga::core::policy::TimestampStatus::UntrustedTsa ||
                   result.status == tamga::core::policy::TimestampStatus::TsaExpired,
                   "Status should show untrusted or time-invalid TSA");
    }
#endif
}

// ME-05: раніше нерозпізнаний messageImprint.hashAlgorithm OID приймався за
// збігом ІМПРИНТУ з БУДЬ-яким із трьох відомих digest (compatibility
// fallback у ValidateTimestampToken) -- токен із чужим/помилковим OID, чий
// hashedMessage випадково чи навмисно дорівнює Kupyna-256/GOST34311/SHA-256
// дайджесту, приймався як валідний. Регресія: той самий сценарій тепер має
// відхилятись.
void TestTimestampValidatorRejectsUnknownImprintOid() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    tamga::core::Session session;
    PrepareInitializedSession(session);
    ExpectTrue(session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
               "Fixture key should load (ME-05 test)");

    std::vector<std::uint8_t> data = {'M', 'E', '-', '0', '5'};
    std::vector<std::uint8_t> signature;
    ExpectTrue(session.SignData(data, signature), "SignData should succeed (ME-05 test)");

    std::vector<std::uint8_t> sig_val;
    std::string sig_val_err;
    ExpectTrue(tamga::core::CryptoniteAdapter::GetSignatureValue(signature, sig_val, sig_val_err),
               "GetSignatureValue should succeed (ME-05 test)");

    std::vector<std::uint8_t> real_imprint;
    Dstu7564Ctx* ctx = dstu7564_alloc(DSTU7564_SBOX_1);
    ExpectTrue(ctx != nullptr, "dstu7564_alloc should succeed (ME-05 test)");
    if (ctx != nullptr) {
        dstu7564_init(ctx, 32);
        ByteArray* sig_ba = ba_alloc_from_uint8(sig_val.data(), sig_val.size());
        ExpectTrue(sig_ba != nullptr, "ba_alloc_from_uint8 should succeed (ME-05 test)");
        if (sig_ba != nullptr) {
            dstu7564_update(ctx, sig_ba);
            ByteArray* hash_ba = nullptr;
            dstu7564_final(ctx, &hash_ba);
            ExpectTrue(hash_ba != nullptr, "dstu7564_final should produce a digest (ME-05 test)");
            if (hash_ba != nullptr) {
                real_imprint.assign(ba_get_buf(hash_ba), ba_get_buf(hash_ba) + ba_get_len(hash_ba));
                ba_free(hash_ba);
            }
            ba_free(sig_ba);
        }
        dstu7564_free(ctx);
    }

    // SHA-1 -- реальний, синтаксично коректний, широко зареєстрований OID,
    // якого Tamga НЕ розпізнає (ImprintFromDigestOid його не мапить), але
    // hashedMessage тут -- справжній Kupyna-256 дайджест sig_val.
    auto bogus_tst_info = CreateTstInfoDer(real_imprint, "20260615220000Z", "1.3.14.3.2.26");
    std::vector<std::uint8_t> bogus_token;
    ExpectTrue(GenerateMockTspToken(fixture.pkcs12_blob, fixture.cert_der, bogus_tst_info, bogus_token),
               "GenerateMockTspToken should succeed (ME-05 test)");

    auto val_res = tamga::core::policy::ValidateTimestampToken(bogus_token, sig_val);
    ExpectFalse(val_res.valid,
               "ME-05: unrecognized hashAlgorithm OID with a matching known digest must be rejected");
    ExpectContains(val_res.message, "not recognized",
                  "ME-05: rejection message should mention the unrecognized OID");

    // Санітарна перевірка: той самий imprint під ПРАВИЛЬНИМ (розпізнаним)
    // Kupyna-256 OID -- і далі валідний, тест ловить саме unknown-OID
    // сценарій, а не щось стороннє.
    auto good_tst_info = CreateTstInfoDer(real_imprint, "20260615220000Z");
    std::vector<std::uint8_t> good_token;
    ExpectTrue(GenerateMockTspToken(fixture.pkcs12_blob, fixture.cert_der, good_tst_info, good_token),
               "GenerateMockTspToken should succeed (ME-05 sanity)");
    auto good_val_res = tamga::core::policy::ValidateTimestampToken(good_token, sig_val);
    ExpectTrue(good_val_res.valid, "sanity: recognized Kupyna-256 OID with matching imprint must validate");
#endif
}

void TestTimestampModeRequiredFailsWhenNoTspUrl() {
#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize online for timestamp required test");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "ReadPrivateKeyBinary should load key for timestamp required test");

    std::vector<std::uint8_t> signature = {0xde, 0xad};
    const std::vector<std::uint8_t> data = {'t', 's', 'p', '-', 'r', 'e', 'q'};
    ExpectFalse(session.SignData(data, signature, tamga::core::TimestampMode::Required),
                "TimestampMode::Required should fail when no TSP URL can be resolved");
    ExpectTrue(signature.empty(), "TimestampMode::Required should clear detached output on TSP failure");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::OnlineServiceUnavailable,
               "TimestampMode::Required failure should be OnlineServiceUnavailable");

    std::vector<std::uint8_t> signed_data = {0xbe, 0xef};
    ExpectFalse(session.SignDataInternal(data, signed_data, tamga::core::TimestampMode::Required),
                "SignDataInternal with TimestampMode::Required should fail when no TSP URL can be resolved");
    ExpectTrue(signed_data.empty(), "TimestampMode::Required should clear attached output on TSP failure");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::OnlineServiceUnavailable,
               "Internal TimestampMode::Required failure should be OnlineServiceUnavailable");
#endif
}

#if TAMGA_CRYPTONITE_ENABLED
namespace {

std::string TimestampTimeForTest(std::time_t value) {
    std::tm utc{};
#if defined(_WIN32)
    if (gmtime_s(&utc, &value) != 0) return {};
#else
    if (gmtime_r(&value, &utc) == nullptr) return {};
#endif
    char output[32]{};
    return std::strftime(output, sizeof(output), "%Y%m%d%H%M%SZ", &utc) ? output : std::string{};
}

// Створює окремий TSA leaf із підписом іншого ключа. На відміну від
// self-signed фікстури він ловить помилкове використання endpoint як issuer.
DstuFixture IssueTsaForTimestampTest(const DstuFixture& issuer, const DstuFixture& leaf,
                                    bool is_ca = false, bool is_ocsp = false) {
    DstuFixture result;
    Pkcs12Ctx* issuer_storage = nullptr;
    Pkcs12Ctx* leaf_storage = nullptr;
    SignAdapter* issuer_signer = nullptr;
    SignAdapter* leaf_signer = nullptr;
    DigestAdapter* digest = nullptr;
    Certificate_t* issuer_cert = nullptr;
    Certificate_t* template_cert = nullptr;
    Certificate_t* issued_cert = nullptr;
    CertificateRequestEngine* request_engine = nullptr;
    CertificationRequest_t* request = nullptr;
    CertificateEngine* engine = nullptr;
    ByteArray* issuer_blob = ba_alloc_from_uint8(issuer.pkcs12_blob.data(), issuer.pkcs12_blob.size());
    ByteArray* leaf_blob = ba_alloc_from_uint8(leaf.pkcs12_blob.data(), leaf.pkcs12_blob.size());
    ByteArray* certificate_der = nullptr;
    ByteArray* issuer_certificate_ba = ba_alloc_from_uint8(issuer.cert_der.data(), issuer.cert_der.size());
    const std::uint8_t serial_value[] = {static_cast<std::uint8_t>(is_ca ? 0x44 : (is_ocsp ? 0x43 : 0x42))};
    ByteArray* serial = ba_alloc_from_uint8(serial_value, sizeof(serial_value));
    do {
        if (!issuer_blob || !leaf_blob || !serial || !issuer_certificate_ba) break;
        if (pkcs12_decode("Tamga", issuer_blob, "test", &issuer_storage) != RET_OK ||
            pkcs12_decode("Tamga", leaf_blob, "test", &leaf_storage) != RET_OK) break;
        if (pkcs12_select_key(issuer_storage, "signer", "test") != RET_OK ||
            pkcs12_select_key(leaf_storage, "signer", "test") != RET_OK) break;
        if (pkcs12_get_sign_adapter(issuer_storage, &issuer_signer) != RET_OK ||
            pkcs12_get_sign_adapter(leaf_storage, &leaf_signer) != RET_OK) break;
        if (issuer_signer->get_cert(issuer_signer, &issuer_cert) != RET_OK ||
            leaf_signer->get_cert(leaf_signer, &template_cert) != RET_OK) break;
        if (cert_decode(issuer_cert, issuer_certificate_ba) != RET_OK ||
            issuer_signer->set_cert(issuer_signer, issuer_cert) != RET_OK) break;
        if (digest_adapter_init_by_cert(issuer_cert, &digest) != RET_OK ||
            ecert_request_alloc(leaf_signer, &request_engine) != RET_OK) break;
        const char* subject = is_ca ? "{CN=Tamga timestamp intermediate}{O=Tamga}{C=UA}" :
            (is_ocsp ? "{CN=Tamga OCSP responder}{O=Tamga}{C=UA}" : "{CN=Tamga TSA leaf}{O=Tamga}{C=UA}");
        if (ecert_request_set_subj_name(request_engine, subject) != RET_OK ||
            ecert_request_generate(request_engine, &request) != RET_OK) break;
        if (is_ca) {
            Extension_t* extension = nullptr;
            if (ext_create_basic_constraints(true, nullptr, true, 2, &extension) != RET_OK) break;
            if (ASN_SEQUENCE_ADD(&template_cert->tbsCertificate.extensions->list, extension) != RET_OK) {
                ASN_FREE(&Extension_desc, extension);
                break;
            }
        }
        if (is_ocsp) {
            OBJECT_IDENTIFIER_t* purpose = nullptr;
            if (pkix_create_oid(oids_get_oid_numbers_by_id(OID_OCSP_KEY_PURPOSE_ID), &purpose) != RET_OK) break;
            Extension_t* extension = nullptr;
            const int rc = ext_create_ext_key_usage(false, &purpose, 1, &extension);
            ASN_FREE(&OBJECT_IDENTIFIER_desc, purpose);
            if (rc != RET_OK) break;
            bool replaced = false;
            auto& extensions = template_cert->tbsCertificate.extensions->list;
            for (int i = 0; i < extensions.count; ++i) {
                if (pkix_check_oid_equal(&extensions.array[i]->extnID, oids_get_oid_numbers_by_id(OID_EXT_KEY_USAGE_EXTENSION_ID))) {
                    ASN_FREE(&Extension_desc, extensions.array[i]);
                    extensions.array[i] = extension;
                    replaced = true;
                    break;
                }
            }
            if (!replaced) {
                ASN_FREE(&Extension_desc, extension);
                break;
            }
        }
        if (ecert_alloc(issuer_signer, digest, false, &engine) != RET_OK) break;
        std::time_t not_before = std::time(nullptr) - 86400;
        std::time_t not_after = not_before + 365 * 86400;
        if (ecert_generate(engine, request, 2, serial, &not_before, &not_after,
                           template_cert->tbsCertificate.extensions, &issued_cert) != RET_OK) break;
        if (cert_encode(issued_cert, &certificate_der) != RET_OK) break;
        result.cert_der.assign(ba_get_buf(certificate_der), ba_get_buf(certificate_der) + ba_get_len(certificate_der));
        // Сертифікат задається явно; тестові підписувачі зв'язують його з
        // приватним ключем через set_cert, не вибираючи старий CertBag.
        result.pkcs12_blob = leaf.pkcs12_blob;
        result.valid = true;
    } while (false);
    ba_free(issuer_blob); ba_free(leaf_blob); ba_free(serial);
    ba_free(certificate_der); ba_free(issuer_certificate_ba);
    cert_free(issuer_cert); cert_free(template_cert); cert_free(issued_cert);
    if (request) ASN_FREE(&CertificationRequest_desc, request);
    ecert_request_free(request_engine); ecert_free(engine);
    digest_adapter_free(digest);
    sign_adapter_free(issuer_signer); sign_adapter_free(leaf_signer);
    pkcs12_free(issuer_storage); pkcs12_free(leaf_storage);
    return result;
}

std::vector<std::uint8_t> TimestampWithoutCertificatesForTest(const std::vector<std::uint8_t>& token) {
    std::vector<std::uint8_t> output;
    ByteArray* encoded = ba_alloc_from_uint8(token.data(), token.size());
    ByteArray* rewritten = nullptr;
    ContentInfo_t* content = cinfo_alloc();
    SignedData_t* data = nullptr;
    if (encoded && content && cinfo_decode(content, encoded) == RET_OK &&
        cinfo_get_signed_data(content, &data) == RET_OK && data) {
        ASN_FREE(&CertificateSet_desc, data->certificates);
        data->certificates = nullptr;
        if (cinfo_init_by_signed_data(content, data) == RET_OK && cinfo_encode(content, &rewritten) == RET_OK && rewritten)
            output.assign(ba_get_buf(rewritten), ba_get_buf(rewritten) + ba_get_len(rewritten));
    }
    ba_free(encoded); ba_free(rewritten); cinfo_free(content); sdata_free(data);
    return output;
}

// Справжня підписана OCSP-відповідь від делегованого responder із OCSP EKU.
// Мережа не використовується; джерело статусу — перевірений порожній CRL.
std::vector<std::uint8_t> GoodOcspForTimestampTest(const DstuFixture& issuer,
                                                  const DstuFixture& responder,
                                                  const DstuFixture& tsa,
                                                  const std::vector<std::uint8_t>& crl_der) {
    std::vector<std::uint8_t> output;
    Pkcs12Ctx* storage = nullptr;
    SignAdapter* signer = nullptr;
    VerifyAdapter* verifier = nullptr;
    VerifyAdapter* request_verifier = nullptr;
    DigestAdapter* digest = nullptr;
    Certificate_t* issuer_cert = cert_alloc();
    Certificate_t* tsa_cert = cert_alloc();
    Certificate_t* responder_cert = cert_alloc();
    CertificateList_t* crl = crl_alloc();
    auto* crls = static_cast<CertificateLists_t*>(calloc(1, sizeof(CertificateLists_t)));
    OCSPRequest_t* request = nullptr;
    OCSPResponse_t* response = nullptr;
    OcspResponseEngine* engine = nullptr;
    ByteArray* issuer_ba = ba_alloc_from_uint8(issuer.cert_der.data(), issuer.cert_der.size());
    ByteArray* tsa_ba = ba_alloc_from_uint8(tsa.cert_der.data(), tsa.cert_der.size());
    ByteArray* crl_ba = ba_alloc_from_uint8(crl_der.data(), crl_der.size());
    ByteArray* storage_ba = ba_alloc_from_uint8(responder.pkcs12_blob.data(), responder.pkcs12_blob.size());
    ByteArray* responder_ba = ba_alloc_from_uint8(responder.cert_der.data(), responder.cert_der.size());
    ByteArray* encoded = nullptr;
    do {
        if (!issuer_cert || !tsa_cert || !responder_cert || !crl || !crls || !issuer_ba || !tsa_ba || !crl_ba || !storage_ba || !responder_ba) break;
        if (cert_decode(issuer_cert, issuer_ba) != RET_OK || cert_decode(tsa_cert, tsa_ba) != RET_OK ||
            crl_decode(crl, crl_ba) != RET_OK) break;
        if (ASN_SEQUENCE_ADD(&crls->list, crl) != RET_OK) break;
        crl = nullptr;
        if (pkcs12_decode("Tamga", storage_ba, "test", &storage) != RET_OK ||
            pkcs12_select_key(storage, "signer", "test") != RET_OK ||
            pkcs12_get_sign_adapter(storage, &signer) != RET_OK) break;
        if (cert_decode(responder_cert, responder_ba) != RET_OK || signer->set_cert(signer, responder_cert) != RET_OK) break;
        if (verify_adapter_init_by_cert(issuer_cert, &verifier) != RET_OK ||
            verify_adapter_init_by_cert(tsa_cert, &request_verifier) != RET_OK ||
            digest_adapter_init_default(&digest) != RET_OK) break;
        if (eocspreq_generate_from_cert(issuer_cert, tsa_cert, &request) != RET_OK ||
            eocspresp_alloc(verifier, signer, crls, digest, true, false,
                            OCSP_RESPONSE_BY_NAME, &engine) != RET_OK) break;
        eocspresp_set_sign_required(engine, false);
        // API cryptonite вимагає непорожній req_va навіть для непідписаного
        // запиту (is_sign_required=false). Передаємо адаптер заявника TSA.
        if (eocspresp_generate(engine, request, request_verifier, std::time(nullptr), &response) != RET_OK ||
            ocspresp_encode(response, &encoded) != RET_OK || !encoded) break;
        output.assign(ba_get_buf(encoded), ba_get_buf(encoded) + ba_get_len(encoded));
    } while (false);
    ba_free(issuer_ba); ba_free(tsa_ba); ba_free(crl_ba); ba_free(storage_ba); ba_free(responder_ba); ba_free(encoded);
    eocspresp_free(engine); ocspreq_free(request); ocspresp_free(response);
    if (crls) ASN_FREE(&CertificateLists_desc, crls);
    crl_free(crl); cert_free(issuer_cert); cert_free(tsa_cert); cert_free(responder_cert);
    verify_adapter_free(verifier); verify_adapter_free(request_verifier); digest_adapter_free(digest);
    sign_adapter_free(signer); pkcs12_free(storage);
    return output;
}

// Змінюємо саме криптографічний підпис, не необов'язкові certs після нього.
std::vector<std::uint8_t> TamperOcspSignatureForTimestampTest(const std::vector<std::uint8_t>& input) {
    std::vector<std::uint8_t> output;
    ByteArray* encoded = ba_alloc_from_uint8(input.data(), input.size());
    ByteArray* basic_der = nullptr;
    ByteArray* result_der = nullptr;
    OCSPResponse_t* response = ocspresp_alloc();
    BasicOCSPResponse_t* basic = nullptr;
    do {
        if (!encoded || !response || ocspresp_decode(response, encoded) != RET_OK || !response->responseBytes) break;
        basic = static_cast<BasicOCSPResponse_t*>(asn_decode_with_alloc(&BasicOCSPResponse_desc,
            response->responseBytes->response.buf, response->responseBytes->response.size));
        if (!basic || !basic->signature.buf || basic->signature.size <= 0) break;
        basic->signature.buf[basic->signature.size - 1] ^= 1;
        if (asn_encode_ba(&BasicOCSPResponse_desc, basic, &basic_der) != RET_OK ||
            asn_ba2OCTSTRING(basic_der, &response->responseBytes->response) != RET_OK ||
            ocspresp_encode(response, &result_der) != RET_OK || !result_der) break;
        output.assign(ba_get_buf(result_der), ba_get_buf(result_der) + ba_get_len(result_der));
    } while (false);
    ba_free(encoded); ba_free(basic_der); ba_free(result_der);
    ocspresp_free(response);
    ASN_FREE(&BasicOCSPResponse_desc, basic);
    return output;
}

// Зберігаємо issuer DN та коректний ASN.1, пошкоджуючи лише підпис CRL.
std::vector<std::uint8_t> TamperCrlSignatureForTimestampTest(const std::vector<std::uint8_t>& input) {
    std::vector<std::uint8_t> output;
    ByteArray* encoded = ba_alloc_from_uint8(input.data(), input.size());
    ByteArray* result_der = nullptr;
    CertificateList_t* crl = crl_alloc();
    if (encoded && crl && crl_decode(crl, encoded) == RET_OK &&
        crl->signatureValue.buf && crl->signatureValue.size > 0) {
        crl->signatureValue.buf[crl->signatureValue.size - 1] ^= 1;
        if (crl_encode(crl, &result_der) == RET_OK && result_der)
            output.assign(ba_get_buf(result_der), ba_get_buf(result_der) + ba_get_len(result_der));
    }
    ba_free(encoded); ba_free(result_der); crl_free(crl);
    return output;
}

} // namespace

void TestTimestampEngineSuite() {
    using namespace tamga::core;
    using namespace tamga::asic;
    using namespace tamga::core::validation;
    std::cerr << "--- TestTimestampEngineSuite ---\n";

    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize");
    ExpectSessionTrue(session,
        session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
        "ReadPrivateKeyBinary should load key");

    std::vector<std::uint8_t> data = { 'T', 'e', 's', 't', ' ', 'D', 'a', 't', 'a' };
    std::vector<std::uint8_t> signature;
    ExpectSessionTrue(session, session.SignData(data, signature), "SignData should succeed");

    std::vector<std::uint8_t> sig_val;
    std::string err;
    ExpectTrue(CryptoniteAdapter::GetSignatureValue(signature, sig_val, err), "GetSignatureValue should succeed");

    // 1. TSTInfo imprint mismatch -> invalid
    {
        std::vector<std::uint8_t> bad_imprint(32, 0xAA);
        auto bad_tst_info = CreateTstInfoDer(bad_imprint, "20260615220000Z");
        std::vector<std::uint8_t> mock_tsp_token;
        ExpectTrue(GenerateMockTspToken(fixture.pkcs12_blob, fixture.cert_der, bad_tst_info, mock_tsp_token),
                   "GenerateMockTspToken should succeed");

        std::vector<std::uint8_t> cms_with_tsp;
        ExpectTrue(CryptoniteAdapter::AppendTspToken(signature, mock_tsp_token, cms_with_tsp, err), "AppendTspToken should succeed");

        TimestampEngineInput engine_input;
        engine_input.cms_der = cms_with_tsp;
        engine_input.level = ValidationLevel::Basic;
        engine_input.profile = ValidationProfile::Strict;

        TimestampEngine engine;
        auto res = engine.Validate(engine_input);
        ExpectFalse(res.valid, "Imprint mismatch must be invalid");
        ExpectTrue(res.status == policy::TimestampStatus::InvalidImprint, "Imprint mismatch status must be InvalidImprint");
    }

    // 2. Imprint match but TSA chain missing -> UntrustedTsa
    {
        std::vector<std::uint8_t> good_imprint;
        Dstu7564Ctx* ctx = dstu7564_alloc(DSTU7564_SBOX_1);
        dstu7564_init(ctx, 32);
        ByteArray* sig_ba = ba_alloc_from_uint8(sig_val.data(), sig_val.size());
        dstu7564_update(ctx, sig_ba);
        ByteArray* hash_ba = nullptr;
        dstu7564_final(ctx, &hash_ba);
        good_imprint.assign(ba_get_buf(hash_ba), ba_get_buf(hash_ba) + ba_get_len(hash_ba));
        ba_free(hash_ba);
        ba_free(sig_ba);
        dstu7564_free(ctx);

        auto good_tst_info = CreateTstInfoDer(good_imprint, "20260615220000Z");
        std::vector<std::uint8_t> mock_tsp_token;
        ExpectTrue(GenerateMockTspToken(fixture.pkcs12_blob, fixture.cert_der, good_tst_info, mock_tsp_token),
                   "GenerateMockTspToken should succeed");

        std::vector<std::uint8_t> cms_with_tsp;
        ExpectTrue(CryptoniteAdapter::AppendTspToken(signature, mock_tsp_token, cms_with_tsp, err), "AppendTspToken should succeed");

        TimestampEngineInput engine_input;
        engine_input.cms_der = cms_with_tsp;
        engine_input.level = ValidationLevel::Basic;
        engine_input.profile = ValidationProfile::Strict;

        TimestampEngine engine;
        auto res = engine.Validate(engine_input);
        ExpectFalse(res.valid, "Matching imprint but untrusted TSA chain should be invalid/untrusted");
        ExpectTrue(res.status == policy::TimestampStatus::UntrustedTsa ||
                   res.status == policy::TimestampStatus::TsaExpired,
                   "Should fail TSA chain or timestamp-time validation");
    }

    // 3. TSA EKU missing -> invalid for extended
    {
        std::vector<std::uint8_t> good_imprint;
        Dstu7564Ctx* ctx = dstu7564_alloc(DSTU7564_SBOX_1);
        dstu7564_init(ctx, 32);
        ByteArray* sig_ba = ba_alloc_from_uint8(sig_val.data(), sig_val.size());
        dstu7564_update(ctx, sig_ba);
        ByteArray* hash_ba = nullptr;
        dstu7564_final(ctx, &hash_ba);
        good_imprint.assign(ba_get_buf(hash_ba), ba_get_buf(hash_ba) + ba_get_len(hash_ba));
        ba_free(hash_ba);
        ba_free(sig_ba);
        dstu7564_free(ctx);

        auto good_tst_info = CreateTstInfoDer(good_imprint, "20260615220000Z");
        std::vector<std::uint8_t> mock_tsp_token;
        ExpectTrue(GenerateMockTspToken(fixture.pkcs12_blob, fixture.cert_der, good_tst_info, mock_tsp_token),
                   "GenerateMockTspToken should succeed");

        std::vector<std::uint8_t> cms_with_tsp;
        ExpectTrue(CryptoniteAdapter::AppendTspToken(signature, mock_tsp_token, cms_with_tsp, err), "AppendTspToken should succeed");

        TimestampEngineInput engine_input;
        engine_input.cms_der = cms_with_tsp;
        engine_input.current_trust_anchors_der = { fixture.cert_der };
        engine_input.level = ValidationLevel::Extended;
        engine_input.profile = ValidationProfile::Strict;

        TimestampEngine engine;
        auto res = engine.Validate(engine_input);
        ExpectFalse(res.valid, "EKU missing must be invalid for extended validation level");
        ExpectTrue(res.status == policy::TimestampStatus::UntrustedTsa ||
                   res.status == policy::TimestampStatus::TsaExpired,
                   "EKU missing or timestamp-time invalid status must fail closed");
    }

    // 4. Trusted timestamp candidate selected only after TSA validation
    {
        std::vector<std::uint8_t> good_imprint;
        Dstu7564Ctx* ctx = dstu7564_alloc(DSTU7564_SBOX_1);
        dstu7564_init(ctx, 32);
        ByteArray* sig_ba = ba_alloc_from_uint8(sig_val.data(), sig_val.size());
        dstu7564_update(ctx, sig_ba);
        ByteArray* hash_ba = nullptr;
        dstu7564_final(ctx, &hash_ba);
        good_imprint.assign(ba_get_buf(hash_ba), ba_get_buf(hash_ba) + ba_get_len(hash_ba));
        ba_free(hash_ba);
        ba_free(sig_ba);
        dstu7564_free(ctx);

        auto good_tst_info = CreateTstInfoDer(good_imprint, "20260615220000Z");
        std::vector<std::uint8_t> mock_tsp_token;
        ExpectTrue(GenerateMockTspToken(fixture.pkcs12_blob, fixture.cert_der, good_tst_info, mock_tsp_token),
                   "GenerateMockTspToken should succeed");

        std::vector<std::uint8_t> cms_with_tsp;
        ExpectTrue(CryptoniteAdapter::AppendTspToken(signature, mock_tsp_token, cms_with_tsp, err), "AppendTspToken should succeed");

        TimestampEngineInput engine_input;
        engine_input.cms_der = cms_with_tsp;
        engine_input.current_trust_anchors_der = { fixture.cert_der };
        engine_input.level = ValidationLevel::Basic;
        engine_input.profile = ValidationProfile::Strict;

        TimestampEngine engine;
        auto res = engine.Validate(engine_input);
        ExpectFalse(res.valid, "Basic level must not bypass TSA EKU/validity policy checks");
        ExpectTrue(res.status == policy::TimestampStatus::UntrustedTsa ||
                   res.status == policy::TimestampStatus::TsaExpired,
                   "Basic level status must fail closed when TSA policy checks fail");
        ExpectTrue(res.gen_time == "20260615220000Z", "genTime should match");
    }

    // Відсутність доказу відкликання не є повною валідацією мітки, навіть
    // якщо м'яка політика дозволяє продовжити перевірку самого підпису.
    {
        const auto tsa = GenerateDstuTsaFixture();
        ExpectTrue(tsa.valid, "TSA-фікстура з EKU має створитися");
        if (!tsa.valid) {
            return;
        }
        TimestampEngineInput input;
        input.explicit_timestamp_imprint_source = {'t', 's', 'a', '-', 's', 'o', 'f', 't'};
        std::string error;
        std::vector<std::uint8_t> good_crl;
        ExpectTrue(GenerateGoodCrlForTest(tsa, good_crl, error), "Підписаний CRL TSA має створитися");
        ExpectTrue(MockTsaTimestamp(tsa, input.explicit_timestamp_imprint_source,
                                    input.explicit_timestamp_token_der, error),
                   "Мок-TSA має створити криптографічно коректний токен");
        input.tsa_trust_anchors_der = {tsa.cert_der};
        input.policy.revocation_hard_fail = false;
        input.plan.network_allowed = false;
        const auto crypto = policy::ValidateTimestampToken(input.explicit_timestamp_token_der,
                                                           input.explicit_timestamp_imprint_source);
        ExpectTrue(crypto.valid, "Контроль: підпис та імпринт мітки коректні");
        const auto result = TimestampEngine{}.Validate(input);
        ExpectFalse(result.valid,
                    "Невідоме відкликання TSA за soft-fail не повинно давати повний timestamp-valid");
        ExpectTrue(result.policy_acceptable && result.crypto_valid && result.trust_valid && result.eku_valid,
                   "Soft-fail відрізняє прийнятність policy від повної перевірки мітки");
        ExpectTrue(result.reason_code == "TSA_REVOCATION_UNKNOWN",
                   "Відсутній CRL/OCSP повинен мати точний код причини");
        input.policy.revocation_hard_fail = true;
        const auto strict = TimestampEngine{}.Validate(input);
        ExpectFalse(strict.valid || strict.policy_acceptable, "Hard-fail не приймає невідоме відкликання");

        input.embedded_crls_der = {good_crl};
        const auto full = TimestampEngine{}.Validate(input);
        ExpectTrue(full.valid && full.policy_acceptable && full.revocation_status == policy::RevocationStatus::Good,
                   "Вбудованого перевіреного CRL достатньо без файлового кешу та мережі");
        ExpectTrue(full.crl_attempted && full.revocation_checked && !full.ocsp_attempted,
                   "Деталі повинні показувати фактично використаний CRL");
        ExpectTrue(full.tsa_issuer_certificate_der == tsa.cert_der,
                   "Для self-signed TSA власний issuer має бути криптографічно перевірений");
        const auto foreign_issuer = IssueTsaForTimestampTest(tsa, GenerateDstuFixture(), true);
        std::vector<std::uint8_t> foreign_crl;
        ExpectTrue(foreign_issuer.valid && GenerateGoodCrlForTest(foreign_issuer, foreign_crl, error),
                   "Коректний CRL іншого видавця має створитися");
        input.embedded_crls_der = {foreign_crl};
        const auto unrelated = TimestampEngine{}.Validate(input);
        ExpectTrue(!unrelated.valid && unrelated.reason_code == "TSA_REVOCATION_UNKNOWN" &&
                   unrelated.revocation_status == policy::RevocationStatus::Unknown,
                   "CRL іншого issuer DN не є некоректним доказом TSA: її статус лишається невідомим");
        input.embedded_crls_der = {foreign_crl, good_crl};
        ExpectTrue(TimestampEngine{}.Validate(input).valid,
                   "Сторонній CRL не заважає використати застосовний перевірений CRL");
        const auto bad_signature_crl = TamperCrlSignatureForTimestampTest(good_crl);
        ExpectTrue(!bad_signature_crl.empty() && bad_signature_crl != good_crl,
                   "Негативна фікстура зберігає структуру CRL та змінює його підпис");
        input.embedded_crls_der = {bad_signature_crl};
        const auto same_issuer_invalid = TimestampEngine{}.Validate(input);
        ExpectTrue(!same_issuer_invalid.valid && same_issuer_invalid.reason_code == "TSA_REVOCATION_INVALID" &&
                   same_issuer_invalid.revocation_status == policy::RevocationStatus::Invalid,
                   "CRL заявленого видавця з хибним підписом залишається Invalid, не Unknown");
        input.embedded_crls_der = {good_crl};
        input.embedded_ocsp_responses_der = {{0x30, 0x00}};
        const auto ocsp_fallback = TimestampEngine{}.Validate(input);
        ExpectTrue(ocsp_fallback.valid && ocsp_fallback.ocsp_attempted && ocsp_fallback.crl_attempted,
                   "Некоректний вбудований OCSP розглядається, а перевірений CRL дає визначений результат");
        input.embedded_ocsp_responses_der.clear();
        input.embedded_crls_der = {{0x30, 0x00}, good_crl};
        ExpectTrue(TimestampEngine{}.Validate(input).valid,
                   "Некоректний сторонній CRL не перекриває справжній позитивний доказ");
        input.embedded_crls_der = {{0x30, 0x00}};
        const auto invalid_crl = TimestampEngine{}.Validate(input);
        ExpectTrue(!invalid_crl.valid && invalid_crl.reason_code == "TSA_REVOCATION_INVALID" &&
                   invalid_crl.revocation_status == policy::RevocationStatus::Invalid,
                   "Некоректний CRL має зберігати типізовану причину без підміни на unknown");

        const auto original_token = input.explicit_timestamp_token_der;
        std::vector<std::uint8_t> future_imprint;
        ExpectTrue(ComputeKupyna256(input.explicit_timestamp_imprint_source, future_imprint), "Імпринт майбутньої мітки обчислюється");
        const auto future_tst = CreateTstInfoDer(future_imprint, TimestampTimeForTest(std::time(nullptr) + 60 * 86400));
        ExpectTrue(GenerateMockTspToken(tsa.pkcs12_blob, tsa.cert_der, future_tst,
                                        input.explicit_timestamp_token_der), "Мітка після nextUpdate CRL створюється");
        input.embedded_crls_der = {good_crl};
        const auto stale = TimestampEngine{}.Validate(input);
        ExpectTrue(!stale.valid && stale.reason_code == "TSA_REVOCATION_STALE" &&
                   stale.revocation_status == policy::RevocationStatus::Stale && stale.crl_attempted,
                   "Застарілий CRL не перетворюється на загальний unknown");
        input.explicit_timestamp_token_der = original_token;

        input.tsa_trust_anchors_der.clear();
        input.additional_tsa_candidate_certificates_der = {tsa.cert_der};
        const auto no_anchor = TimestampEngine{}.Validate(input);
        ExpectFalse(no_anchor.valid || no_anchor.trust_valid,
                    "Вбудований сертифікат і його CRL не створюють якір довіри");
        input.historical_tsa_trust_anchors_der = {tsa.cert_der};
        input.policy.allow_historical_trust = true;
        const auto historical = TimestampEngine{}.Validate(input);
        ExpectTrue(historical.valid && historical.historical_trust_used && historical.trust_source == "historical-tl",
                   "Історичний endpoint має лишати явне походження довіри");
        input.policy.allow_historical_trust = false;
        ExpectFalse(TimestampEngine{}.Validate(input).valid, "Заборонене історичне джерело не приймається");
    }

    {
        const auto no_eku = GenerateDstuFixture();
        ExpectTrue(no_eku.valid, "Фікстура без EKU має створитися");
        if (!no_eku.valid) return;
        TimestampEngineInput input;
        input.tsa_trust_anchors_der = {no_eku.cert_der};
        input.explicit_timestamp_imprint_source = {'e', 'k', 'u'};
        std::string error;
        ExpectTrue(MockTsaTimestamp(no_eku, input.explicit_timestamp_imprint_source,
                                    input.explicit_timestamp_token_der, error), "Токен без EKU має створитися");
        const auto result = TimestampEngine{}.Validate(input);
        ExpectTrue(result.crypto_valid && result.certificate_time_valid && result.trust_valid,
                   "Передумови негативного EKU-тесту повинні бути виконані");
        ExpectFalse(result.valid || result.eku_valid, "Відсутня EKU timestamping забороняє мітку");
        ExpectTrue(result.reason_code == "TSA_EKU_INVALID", "Помилка EKU не маскується expiry або відсутнім trust");
    }

    // Endpoint довірений прямо, але CRL підписаний іншим CA. TSA не можна
    // використати як власний issuer лише через її присутність у tsa-store.
    {
        const auto issuer = GenerateDstuFixture();
        const auto template_tsa = GenerateDstuTsaFixture();
        const auto tsa = IssueTsaForTimestampTest(issuer, template_tsa);
        ExpectTrue(tsa.valid, "Окремий TSA leaf має бути випущений CA");
        if (!tsa.valid) return;
        TimestampEngineInput input;
        input.tsa_trust_anchors_der = {tsa.cert_der};
        input.policy.revocation_hard_fail = true;
        input.explicit_timestamp_imprint_source = {'d', 's', 's', '-', 't', 's', 'a'};
        std::vector<std::uint8_t> crl;
        std::string error;
        ExpectTrue(GenerateGoodCrlForTest(issuer, crl, error), "CRL видавця TSA має створитися");
        ExpectTrue(MockTsaTimestamp(tsa, input.explicit_timestamp_imprint_source,
                                    input.explicit_timestamp_token_der, error), "Токен TSA leaf має створитися");
        input.embedded_crls_der = {crl};
        const auto missing_issuer = TimestampEngine{}.Validate(input);
        ExpectFalse(missing_issuer.valid, "Без видавця CRL TSA не може підтвердити відкликання");
        ExpectTrue(missing_issuer.reason_code == "TSA_ISSUER_MISSING" && missing_issuer.trust_valid,
                   "Довіра endpoint і наявність issuer — різні результати");
        input.additional_tsa_candidate_certificates_der = {issuer.cert_der};
        const auto resolved = TimestampEngine{}.Validate(input);
        ExpectTrue(resolved.valid && resolved.tsa_issuer_certificate_der == issuer.cert_der,
                   "Issuer з DSS має перевірити CRL довіреного TSA endpoint");

        input.explicit_timestamp_token_der = TimestampWithoutCertificatesForTest(input.explicit_timestamp_token_der);
        ExpectFalse(input.explicit_timestamp_token_der.empty(), "Токен без certificates має кодуватися");
        const auto external_signer = TimestampEngine{}.Validate(input);
        ExpectTrue(external_signer.valid,
                   "Відсутній у токені TSA signer знаходиться серед локальних кандидатів за SID та підписом");

        input.tsa_trust_anchors_der.clear();
        input.current_trust_anchors_der = {issuer.cert_der};
        input.additional_tsa_candidate_certificates_der = {tsa.cert_der};
        const auto chain_trust = TimestampEngine{}.Validate(input);
        ExpectTrue(chain_trust.valid, "TSA leaf із DSS має будувати шлях до окремого довіреного CA");

        const auto responder = IssueTsaForTimestampTest(issuer, template_tsa, false, true);
        ExpectTrue(responder.valid, "OCSP responder із потрібним EKU має створитися");
        const auto ocsp = GoodOcspForTimestampTest(issuer, responder, tsa, crl);
        ExpectFalse(ocsp.empty(), "Підписана позитивна OCSP-відповідь має створитися офлайн");
        policy::OcspValidationInput ocsp_check;
        ocsp_check.signer_certificate_der = tsa.cert_der;
        ocsp_check.issuer_certificate_der = issuer.cert_der;
        ocsp_check.response_der = ocsp;
        const auto verified_ocsp = policy::OcspValidator{}.Validate(ocsp_check);
        ExpectTrue(verified_ocsp.status == policy::RevocationStatus::Good && verified_ocsp.response_der == ocsp,
                   "Лише перевірена OCSP-відповідь повертається як доказ для DSS");
        ocsp_check.response_der = TamperOcspSignatureForTimestampTest(ocsp);
        ExpectTrue(!ocsp_check.response_der.empty() && ocsp_check.response_der != ocsp,
                   "Мутація повинна змінити BIT STRING підпису OCSP зі збереженням структури ASN.1");
        const auto tampered_ocsp = policy::OcspValidator{}.Validate(ocsp_check);
        ExpectTrue(tampered_ocsp.status == policy::RevocationStatus::Invalid && tampered_ocsp.response_der.empty(),
                   "Зіпсована OCSP-відповідь не повертається для пакування DSS");
        input.embedded_crls_der.clear();
        input.embedded_ocsp_responses_der = {ocsp};
        ExpectTrue(MockTsaTimestamp(tsa, input.explicit_timestamp_imprint_source,
                                    input.explicit_timestamp_token_der, error), "Мітка після випуску OCSP має створитися");
        const auto ocsp_only = TimestampEngine{}.Validate(input);
        ExpectTrue(ocsp_only.valid && ocsp_only.ocsp_attempted && !ocsp_only.crl_attempted &&
                   ocsp_only.revocation_status == policy::RevocationStatus::Good,
                   "Лише вбудований OCSP з перевіреними CertID, підписом і часом має підтвердити TSA");
#if defined(TAMGA_PDF_SIGNATURES_ENABLED)
        tamga::pades::PadesValidationEvidence cached_evidence;
        cached_evidence.ocsp_responses = {ocsp};
        OcspSettings ocsp_settings;
        ExpectTrue(pades_detail::CollectPadesCertificateEvidence(tsa.cert_der, {tsa.cert_der, issuer.cert_der},
            {issuer.cert_der}, {}, true, ocsp_settings, ocsp_only.validation_time, cached_evidence, error),
            "Збір доказів PAdES приймає вже перевірений кешований OCSP без мережі");
        ExpectTrue(pades_detail::CollectPadesCertificateEvidence(tsa.cert_der, {tsa.cert_der, issuer.cert_der},
            {issuer.cert_der}, {}, true, ocsp_settings, ocsp_only.validation_time, cached_evidence, error) &&
            cached_evidence.ocsp_responses.size() == 1U,
            "Повторний збір перевіряє OCSP, не додаючи дублікат DER");
        ExpectFalse(pades_detail::CollectPadesCertificateEvidence(tsa.cert_der, {tsa.cert_der, issuer.cert_der},
            {issuer.cert_der}, {}, true, ocsp_settings, "2100-01-01T00:00:00Z", cached_evidence, error),
            "Наявність OCSP у кеші не підтверджує TSA на іншому моменті поза вікном відповіді");
#endif
        input.embedded_ocsp_responses_der = {{0x30, 0x00}};
        const auto invalid_ocsp = TimestampEngine{}.Validate(input);
        ExpectTrue(!invalid_ocsp.valid && invalid_ocsp.reason_code == "TSA_REVOCATION_INVALID" &&
                   invalid_ocsp.ocsp_attempted,
                   "Відмова розбору вбудованого OCSP зберігає окрему типізовану причину");
    }

    {
        const auto root = GenerateDstuFixture();
        const auto intermediate = IssueTsaForTimestampTest(root, GenerateDstuFixture(), true);
        const auto tsa = IssueTsaForTimestampTest(intermediate, GenerateDstuTsaFixture());
        ExpectTrue(intermediate.valid && tsa.valid, "TSA-ланцюг root/intermediate/leaf має створитися");
        if (!intermediate.valid || !tsa.valid) return;
        TimestampEngineInput input;
        input.current_trust_anchors_der = {root.cert_der};
        input.additional_tsa_candidate_certificates_der = {intermediate.cert_der};
        input.policy.revocation_hard_fail = true;
        input.explicit_timestamp_imprint_source = {'c', 'h', 'a', 'i', 'n'};
        std::vector<std::uint8_t> crl;
        std::string error;
        ExpectTrue(GenerateGoodCrlForTest(intermediate, crl, error), "CRL проміжного CA має створитися");
        input.embedded_crls_der = {crl};
        ExpectTrue(MockTsaTimestamp(tsa, input.explicit_timestamp_imprint_source,
                                    input.explicit_timestamp_token_der, error), "Мітка TSA під проміжним CA має створитися");
        const auto with_dss = TimestampEngine{}.Validate(input);
        ExpectTrue(with_dss.valid && with_dss.tsa_issuer_certificate_der == intermediate.cert_der,
                   "Проміжний CA лише з DSS має брати участь у побудові шляху та перевірці CRL");
        input.additional_tsa_candidate_certificates_der.clear();
        ExpectFalse(TimestampEngine{}.Validate(input).valid,
                    "Без DSS intermediate той самий токен не має повного шляху");
    }

    // Не приймаємо календарно хибний genTime і не замінюємо його now.
    // TSTInfo змінюється ДО підпису, тож негативний результат не є підміною CMS.
    {
        const auto tsa = GenerateDstuTsaFixture();
        ExpectTrue(tsa.valid, "TSA-фікстура для перевірки часу має створитися");
        if (!tsa.valid) return;
        TimestampEngineInput input;
        input.tsa_trust_anchors_der = {tsa.cert_der};
        input.explicit_timestamp_imprint_source = {'g', 'e', 'n', 'T', 'i', 'm', 'e'};
        std::vector<std::uint8_t> imprint;
        ExpectTrue(ComputeKupyna256(input.explicit_timestamp_imprint_source, imprint), "Імпринт часу має обчислитися");
        const std::string valid_time = "20260615220000Z";
        auto tst_info = CreateTstInfoDer(imprint, valid_time);
        auto time_position = std::search(tst_info.begin(), tst_info.end(), valid_time.begin(), valid_time.end());
        ExpectTrue(time_position != tst_info.end(), "Фікстура повинна містити явний genTime");
        if (time_position == tst_info.end()) return;
        time_position[4] = '1'; time_position[5] = '3';
        ExpectTrue(GenerateMockTspToken(tsa.pkcs12_blob, tsa.cert_der, tst_info,
                                        input.explicit_timestamp_token_der), "TSTInfo з хибним місяцем підписується");
        const auto invalid = TimestampEngine{}.Validate(input);
        ExpectFalse(invalid.valid || invalid.gen_time_valid, "Місяць 13 має відхилятися без fallback");
        ExpectTrue(invalid.crypto_valid && invalid.reason_code == "TIMESTAMP_TIME_INVALID",
                   "Неправильний календар має відрізнятися від неправильного підпису");

        // Фікстура чинна один рік. Перевіряємо прострочення в межах time_t,
        // а 2099 рік окремо перевіряє відмову платформ із 32-бітним часом.
        const auto after_certificate = TimestampTimeForTest(std::time(nullptr) + 2 * 365 * 86400);
        for (const std::string& outside : {std::string("20000101000000Z"), after_certificate,
                                          std::string("20990101000000Z")}) {
            const auto valid_tst = CreateTstInfoDer(imprint, outside);
            ExpectTrue(GenerateMockTspToken(tsa.pkcs12_blob, tsa.cert_der, valid_tst,
                                            input.explicit_timestamp_token_der), "Історичний/майбутній TSTInfo підписується");
            const auto expired = TimestampEngine{}.Validate(input);
            ExpectFalse(expired.valid, "genTime поза строком TSA не є валідним");
            if (outside == "20990101000000Z" && std::numeric_limits<std::time_t>::digits < 32) {
                ExpectTrue(expired.crypto_valid && !expired.gen_time_valid &&
                           expired.reason_code == "TIMESTAMP_TIME_INVALID",
                           "Час поза діапазоном time_t відхиляється без fallback на now");
                continue;
            }
            ExpectTrue(expired.gen_time_valid && !expired.certificate_time_valid &&
                       expired.reason_code == "TSA_CERTIFICATE_TIME_INVALID",
                       "Строк сертифіката оцінюється на genTime, а не на now");
        }
    }
}
#endif  // TAMGA_CRYPTONITE_ENABLED

void TestTimestampModeRequiredRawFileClearsStaleOutput() {
#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize online for required raw file timestamp test");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "ReadPrivateKeyBinary should load key for required raw file timestamp test");

    std::vector<std::uint8_t> signature = {0xde, 0xad};
    const std::vector<std::uint8_t> data = {'t', 's', 'p', '-', 'd', 'o', 'w', 'n'};
    ExpectFalse(session.SignData(data, signature, tamga::core::TimestampMode::Required),
                "TimestampMode::Required should fail when no configured or resolved TSP URL is available");
    ExpectTrue(signature.empty(), "TimestampMode::Required should clear detached output when no TSP URL is available");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::OnlineServiceUnavailable,
               "Missing TSP URL should set OnlineServiceUnavailable");

    const auto input_path = MakeTemporaryFixturePath(".bin");
    const auto signature_path = MakeTemporaryFixturePath(".p7s");
    ExpectTrue(WriteBinaryFile(input_path, data), "RawSignFile input fixture should be writable");
    ExpectTrue(WriteBinaryFile(signature_path, {0xca, 0xfe, 0xba, 0xbe}),
               "RawSignFile stale signature fixture should be writable");

    ExpectFalse(session.RawSignFile(input_path.u8string(),
                                    signature_path.u8string(),
                                    tamga::core::TimestampMode::Required),
                "RawSignFile with TimestampMode::Required should fail when no configured or resolved TSP URL is available");
    ExpectTrue(std::filesystem::file_size(signature_path) == 0,
               "Failed Required RawSignFile should clear stale signature output file");

    const auto missing_signature_path = MakeTemporaryFixturePath(".missing.p7s");
    ExpectFalse(session.RawSignFile(input_path.u8string(),
                                    missing_signature_path.u8string(),
                                    tamga::core::TimestampMode::Required),
                "RawSignFile Required failure should also fail when output file did not exist");
    ExpectFalse(std::filesystem::exists(missing_signature_path),
                "Failed Required RawSignFile should not create an empty output file when none existed");

    const auto protected_signature_path = MakeTemporaryFixturePath(".protected.p7s");
    const std::vector<std::uint8_t> protected_bytes = {0x11, 0x22, 0x33};
    ExpectTrue(WriteBinaryFile(protected_signature_path, protected_bytes),
               "RawSignFile protected signature fixture should be writable");
    tamga::core::FileStoreSettings file_settings;
    file_settings.allow_overwrite = false;
    ExpectSessionTrue(session,
                      session.SetFileStoreSettings(file_settings),
                      "File store settings should disable overwrite for RawSignFile");
    ExpectFalse(session.RawSignFile(input_path.u8string(),
                                    protected_signature_path.u8string(),
                                    tamga::core::TimestampMode::Required),
                "RawSignFile should fail before signing when overwrite is disabled and output exists");
    ExpectTrue(ReadBinaryFixture(protected_signature_path) == protected_bytes,
               "RawSignFile must not clear an existing signature when allow_overwrite=false");

    std::error_code ignored;
    std::filesystem::remove(input_path, ignored);
    std::filesystem::remove(signature_path, ignored);
    std::filesystem::remove(missing_signature_path, ignored);
    std::filesystem::remove(protected_signature_path, ignored);
#endif
}

void TestTimestampModeFailuresClearStaleOutput() {
    const std::vector<std::uint8_t> data = {'s', 't', 'a', 'l', 'e'};

    tamga::core::Session uninitialized;
    std::vector<std::uint8_t> signature = {0xde, 0xad};
    ExpectFalse(uninitialized.SignData(data, signature, tamga::core::TimestampMode::Required),
                "Required SignData should fail before Initialize");
    ExpectTrue(signature.empty(), "Failed Required SignData should clear stale detached output before Initialize");

    tamga::core::Session missing_key;
    ExpectTrue(missing_key.Initialize(), "Session should initialize for missing key failure test");
    std::vector<std::uint8_t> signed_data = {0xbe, 0xef};
    ExpectFalse(missing_key.SignDataInternal(data, signed_data, tamga::core::TimestampMode::Required),
                "Required SignDataInternal should fail without a loaded key");
    ExpectTrue(signed_data.empty(), "Failed Required SignDataInternal should clear stale attached output without a key");

    std::vector<std::uint8_t> file_signature = {0xca, 0xfe};
    ExpectFalse(missing_key.SignFile("__missing_timestamp_input__.bin",
                                     file_signature,
                                     tamga::core::TimestampMode::Required),
                "Required SignFile should fail for a missing input file");
    ExpectTrue(file_signature.empty(), "Failed Required SignFile should clear stale file signature output");
}

void TestTimestampModeBestEffortClearsTspFailure() {
#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize online for timestamp best-effort test");

    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "ReadPrivateKeyBinary should load key for timestamp best-effort test");

    std::vector<std::uint8_t> signature;
    const std::vector<std::uint8_t> data = {'t', 's', 'p', '-', 'b', 'e'};
    ExpectSessionTrue(session,
                      session.SignData(data, signature, tamga::core::TimestampMode::BestEffort),
                      "TimestampMode::BestEffort should return BES signature when no TSP URL is available");
    ExpectFalse(signature.empty(), "TimestampMode::BestEffort fallback should produce a BES signature");

    bool has_tsp = true;
    std::string err;
    ExpectTrue(tamga::core::CryptoniteAdapter::HasSignatureTimestampToken(signature, has_tsp, err),
               "BestEffort fallback signature should still produce inspectable CMS");
    ExpectFalse(has_tsp, "TimestampMode::BestEffort fallback should not embed TSP token");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::None,
               "TimestampMode::BestEffort fallback should clear TSP failure error");

    std::vector<std::uint8_t> signed_data;
    ExpectSessionTrue(session,
                      session.SignDataInternal(data, signed_data, tamga::core::TimestampMode::BestEffort),
                      "Internal TimestampMode::BestEffort should return BES signature when no TSP URL is available");
    ExpectFalse(signed_data.empty(), "Internal TimestampMode::BestEffort fallback should produce a BES signature");
    has_tsp = true;
    ExpectTrue(tamga::core::CryptoniteAdapter::HasSignatureTimestampToken(signed_data, has_tsp, err),
               "Internal BestEffort fallback signature should still produce inspectable CMS");
    ExpectFalse(has_tsp, "Internal TimestampMode::BestEffort fallback should not embed TSP token");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::None,
               "Internal TimestampMode::BestEffort fallback should clear TSP failure error");
#endif
}
