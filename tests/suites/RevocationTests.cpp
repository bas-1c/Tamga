// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Відкликання: CRL (кеш, свіжість, підпис, стійкість до зіпсованих записів)
// і OCSP. Сюди ж AIA-фетчер — це крок отримання видавця, без якого
// перевірка відкликання не має на чому працювати.

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

#if TAMGA_CRYPTONITE_ENABLED
namespace {

// Справжній підписаний CRL для self-issued фікстури; issuer DN та підпис
// узгоджені, тому сценарії before/after перевіряють саме час відкликання.
bool GenerateRevokedCrlForEngineTest(const DstuFixture& fixture, std::vector<std::uint8_t>& output) {
    output.clear();
    Pkcs12Ctx* storage = nullptr;
    SignAdapter* signer = nullptr;
    VerifyAdapter* verifier = nullptr;
    Certificate_t* certificate = nullptr;
    CrlEngine* engine = nullptr;
    CertificateList_t* crl = nullptr;
    ByteArray* key_der = ba_alloc_from_uint8(fixture.pkcs12_blob.data(), fixture.pkcs12_blob.size());
    ByteArray* cert_der = ba_alloc_from_uint8(fixture.cert_der.data(), fixture.cert_der.size());
    ByteArray* serial_der_octets = nullptr;
    ByteArray* encoded = nullptr;
    do {
        if (!key_der || !cert_der || pkcs12_decode("Tamga", key_der, "test", &storage) != RET_OK ||
            pkcs12_select_key(storage, nullptr, "test") != RET_OK ||
            pkcs12_get_sign_adapter(storage, &signer) != RET_OK) break;
        certificate = cert_alloc();
        if (!certificate || cert_decode(certificate, cert_der) != RET_OK ||
            signer->set_cert(signer, certificate) != RET_OK ||
            verify_adapter_init_by_cert(certificate, &verifier) != RET_OK) break;
        // ecrl_add_revoked_cert бере cert_get_sn у зворотному порядку байтів,
        // тоді як add_by_sn копіює їх у ASN.1 INTEGER без перестановки.
        // Передаємо точні DER-октети serial; підпис сертифіката перевіряємо явно.
        if (cert_verify(certificate, verifier) != RET_OK) break;
        serial_der_octets = ba_alloc_from_uint8(certificate->tbsCertificate.serialNumber.buf,
                                                certificate->tbsCertificate.serialNumber.size);
        if (!serial_der_octets) break;
        if (ecrl_alloc(nullptr, signer, verifier, nullptr, "tamga-revoked-test", CRL_FULL,
                       "Tamga revoked fixture", &engine) != RET_OK ||
            ecrl_add_revoked_cert_by_sn(engine, serial_der_octets, nullptr, nullptr) != RET_OK ||
            ecrl_generate_diff_next_update(engine, 30 * 86400, &crl) != RET_OK ||
            crl_encode(crl, &encoded) != RET_OK || !encoded) break;
        output.assign(ba_get_buf(encoded), ba_get_buf(encoded) + ba_get_len(encoded));
    } while (false);
    ba_free(key_der); ba_free(cert_der); ba_free(serial_der_octets); ba_free(encoded);
    crl_free(crl); ecrl_free(engine); cert_free(certificate);
    verify_adapter_free(verifier); sign_adapter_free(signer); pkcs12_free(storage);
    return !output.empty();
}

} // namespace
#endif

void TestAiaIssuerFetcherExtractsCaIssuersUrl() {
    const auto der = BuildSyntheticAiaDerForTest("https://example.test/issuer.cer");
    const auto urls = tamga::core::policy::AiaIssuerFetcher::ExtractCaIssuersUrls(der);
    ExpectTrue(urls.size() == 1U, "AIA parser should find one CA Issuers URL");
    ExpectTrue(urls.front() == "https://example.test/issuer.cer",
               "AIA parser should preserve CA Issuers URL");
}

void TestAiaIssuerFetcherParsesDerAndPemCertificates() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto root = ReadBinaryFixture(pki_dir / "root_certificate.cer");
    if (root.empty()) {
        RecordSkip("Cryptonite PKI fixtures not available");
        return;
    }

    std::string error;
    auto der_certs = tamga::core::policy::AiaIssuerFetcher::ParseDownloadedCertificates(root, error);
    ExpectTrue(der_certs.size() == 1U, "AIA parser should accept downloaded DER certificate");

    const std::string pem = "-----BEGIN CERTIFICATE-----\n" +
                            tamga::util::Base64Encode(root) +
                            "\n-----END CERTIFICATE-----\n";
    const std::vector<std::uint8_t> pem_blob(pem.begin(), pem.end());
    auto pem_certs = tamga::core::policy::AiaIssuerFetcher::ParseDownloadedCertificates(pem_blob, error);
    ExpectTrue(pem_certs.size() == 1U, "AIA parser should accept downloaded PEM certificate");
#endif
}

void TestAiaIssuerFetcherDownloadsAndCachesIssuer() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto root = ReadBinaryFixture(pki_dir / "root_certificate.cer");
    if (root.empty()) {
        RecordSkip("Cryptonite PKI fixtures not available");
        return;
    }

    const auto work_dir = MakeTemporaryFixturePath(".aia-cache");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);

    std::size_t calls = 0;
    tamga::core::HttpClient::ScopedMockTransport mock(
        [root, &calls](const tamga::core::HttpRequest& request) {
            ++calls;
            ExpectTrue(request.method == "GET", "AIA issuer download should use HTTP GET");
            ExpectTrue(request.url == "https://example.test/issuer.cer",
                       "AIA issuer download should request CA Issuers URL");
            tamga::core::HttpResponse response;
            response.succeeded = true;
            response.status_code = 200;
            response.body = root;
            return response;
        });

    tamga::core::policy::AiaIssuerFetchInput input;
    input.network_enabled = true;
    input.work_dir = work_dir.u8string();
    input.timeout_ms = 1000;
    input.seed_certificates_der.push_back(BuildSyntheticAiaDerForTest("https://example.test/issuer.cer"));

    tamga::core::policy::AiaIssuerFetcher fetcher;
    const auto result = fetcher.FetchMissingIssuers(input);
    ExpectTrue(result.downloaded_count == 1U, "AIA fetcher should download one issuer certificate");
    ExpectTrue(calls == 1U, "AIA fetcher should call HTTP once for one URL");
    ExpectTrue(CountCerFilesForTest(work_dir / "intermediate-store") == 1U,
               "AIA fetcher should cache downloaded issuer certificate in intermediate-store");

    std::filesystem::remove_all(work_dir, ec);
#endif
}

void TestAiaIssuerFetcherRequiresExplicitNetworkOptIn() {
    std::atomic<int> calls{0};
    tamga::core::HttpClient::ScopedMockTransport mock(
        [&calls](const tamga::core::HttpRequest&) {
            ++calls;
            tamga::core::HttpResponse response;
            response.succeeded = true;
            response.status_code = 200;
            return response;
        });

    tamga::core::policy::AiaIssuerFetchInput input;
    input.work_dir = MakeTemporaryFixturePath(".aia-no-opt-in").u8string();
    input.seed_certificates_der.push_back(
        BuildSyntheticAiaDerForTest("https://example.test/issuer.cer"));
    const auto result = tamga::core::policy::AiaIssuerFetcher{}.FetchMissingIssuers(input);
    ExpectFalse(result.attempted, "AIA fetcher must remain offline without explicit network opt-in");
    ExpectTrue(calls.load() == 0, "AIA fetcher without opt-in must not invoke HTTP transport");
}

void TestCryptoniteAdapterGetCrlNextUpdate() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto crl = ReadBinaryFixture(pki_dir / "full.crl");
    if (crl.empty()) {
        RecordSkip("Cryptonite CRL fixture full.crl not available");
        return;
    }

    std::time_t next_update = 0;
    const bool ok = tamga::core::CryptoniteAdapter::GetCrlNextUpdate(crl, next_update);
    ExpectTrue(ok, "GetCrlNextUpdate should parse a valid CRL");
    ExpectTrue(next_update > 0, "GetCrlNextUpdate should yield a non-zero nextUpdate time");

    std::time_t empty_nu = 12345;
    ExpectFalse(tamga::core::CryptoniteAdapter::GetCrlNextUpdate({}, empty_nu),
                "GetCrlNextUpdate must reject empty CRL input");
    ExpectTrue(empty_nu == 0, "GetCrlNextUpdate must zero the out-param on failure");

    std::time_t corrupt_nu = 54321;
    const std::vector<std::uint8_t> corrupted_crl = {0x30, 0x01, 0xFF};
    ExpectFalse(tamga::core::CryptoniteAdapter::GetCrlNextUpdate(corrupted_crl, corrupt_nu),
                "GetCrlNextUpdate must reject corrupted CRL input");
    ExpectTrue(corrupt_nu == 0, "GetCrlNextUpdate must zero the out-param on corrupted input failure");
#endif
}

void TestCrlCacheFreshnessByNextUpdate() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto crl = ReadBinaryFixture(pki_dir / "full.crl");
    if (crl.empty()) {
        RecordSkip("Cryptonite CRL fixture full.crl not available");
        return;
    }

    std::time_t next_update = 0;
    ExpectTrue(tamga::core::CryptoniteAdapter::GetCrlNextUpdate(crl, next_update),
               "Precondition: CRL nextUpdate must be readable");

    ExpectTrue(tamga::core::policy::IsCachedCrlFresh(crl, next_update - 1),
               "CRL must be considered fresh strictly before nextUpdate");
    ExpectFalse(tamga::core::policy::IsCachedCrlFresh(crl, next_update + 1),
                "CRL must be considered stale at/after nextUpdate");
    ExpectFalse(tamga::core::policy::IsCachedCrlFresh({}, next_update),
                "Empty CRL bytes must never be considered fresh");
#endif
}

void TestExtractCrlDistributionUrls() {
    auto make_der = [](const std::string& s) {
        return std::vector<std::uint8_t>(s.begin(), s.end());
    };

    {
        const auto der = make_der("not-a-certificate http://example.com/file.crl");
        const auto urls = tamga::core::policy::ExtractCrlDistributionUrls(der);
        ExpectTrue(urls.empty(), "CRL URL extraction must ignore raw strings that are not certificate DER");
    }

#if TAMGA_CRYPTONITE_ENABLED
    {
        const auto cert_der = ReadBinaryFixture(std::filesystem::path(TAMGA_TEST_SOURCE_DIR) /
                                                "vendor" / "cryptonite" / "src" / "pkixUtest" /
                                                "resources" / "acsk_cert.cer");
        ExpectFalse(cert_der.empty(), "ACSK certificate fixture should be available");
        const auto urls = tamga::core::policy::ExtractCrlDistributionUrls(cert_der);
        const auto expected = std::string("http://acskidd.gov.ua/download/crls/ACSKIDDDFS-Full.crl");
        ExpectTrue(std::find(urls.begin(), urls.end(), expected) != urls.end(),
                   "CRL URL extraction should read uniformResourceIdentifier from certificate CDP extension");
    }
#else
    {
        const auto der = make_der("not-a-certificate http://example.com/other.crl");
        const auto urls = tamga::core::policy::ExtractCrlDistributionUrls(der);
        ExpectTrue(urls.empty(), "CRL URL extraction should fail closed when cryptonite is disabled");
    }
#endif
}


void TestCrlValidatorUnknownWhenNoCrls() {
    tamga::core::policy::CrlValidator validator;
    tamga::core::policy::CrlValidationInput input;
#if TAMGA_CRYPTONITE_ENABLED
    input.signer_certificate_der = GenerateDstuFixture().cert_der;
#endif
    const auto result = validator.Validate(input);
    ExpectTrue(result.checked == false, "No CRLs should not count as checked");
    ExpectTrue(result.status == tamga::core::policy::RevocationStatus::Unknown,
               "No CRLs should produce unknown revocation");
}

void TestCrlValidatorInvalidWhenCrlCannotDecode() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    tamga::core::policy::CrlValidator validator;
    tamga::core::policy::CrlValidationInput input;
    input.signer_certificate_der = fixture.cert_der;
    input.issuer_certificate_der = fixture.cert_der;
    input.crls_der.push_back(std::vector<std::uint8_t>{'n','o','t','-','c','r','l'});
    const auto result = validator.Validate(input);
    ExpectTrue(result.status == tamga::core::policy::RevocationStatus::Invalid,
               "Malformed CRL should produce invalid revocation status");
#endif
}

void TestCrlValidatorRejectsUnsignedGoodWhenIssuerPresent() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto user = ReadBinaryFixture(pki_dir / "userfiz_certificate.cer");
    const auto wrong_issuer = ReadBinaryFixture(pki_dir / "userfiz_certificate.cer");
    const auto crl = ReadBinaryFixture(pki_dir / "full.crl");
    if (user.empty() || wrong_issuer.empty() || crl.empty()) {
        RecordSkip("Cryptonite CRL fixtures not available");
        return;
    }

    tamga::core::policy::CrlValidator validator;
    tamga::core::policy::CrlValidationInput input;
    input.signer_certificate_der = user;
    input.issuer_certificate_der = wrong_issuer;
    input.crls_der.push_back(crl);
    const auto result = validator.Validate(input);
    ExpectTrue(result.status == tamga::core::policy::RevocationStatus::Invalid,
               "CRL with invalid issuer signature must not produce Good revocation status");
#endif
}

void TestCrlValidatorScansPastMalformedCrlsForGood() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto root = ReadBinaryFixture(pki_dir / "root_certificate.cer");
    const auto user = ReadBinaryFixture(pki_dir / "userfiz_certificate.cer");
    const auto full_crl = ReadBinaryFixture(pki_dir / "full.crl");
    if (root.empty() || user.empty() || full_crl.empty()) {
        RecordSkip("Cryptonite CRL fixtures not available");
        return;
    }

    // С-01: свіжість CRL тепер перевіряється проти validation_time. Фікстура
    // vendored cryptonite давно вийшла за своє вікно [thisUpdate, nextUpdate],
    // тож без явного часу валідації вона (правильно) більше не доводить
    // "не відкликаний". Задаємо момент усередині вікна — саме так виглядає
    // історична валідація підпису на час його створення.
    std::time_t crl_this_update = 0;
    std::time_t crl_next_update = 0;
    ExpectTrue(tamga::core::CryptoniteAdapter::GetCrlValidityWindow(full_crl, crl_this_update,
                                                                    crl_next_update),
               "CRL validity window must be readable");
    char validation_time_buf[32] = {0};
    if (crl_this_update > 0) {
        const std::time_t inside_window = crl_this_update + 60;
        std::tm tm_utc{};
#ifdef _WIN32
        gmtime_s(&tm_utc, &inside_window);
#else
        gmtime_r(&inside_window, &tm_utc);
#endif
        std::strftime(validation_time_buf, sizeof(validation_time_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    }

    tamga::core::policy::CrlValidator validator;
    tamga::core::policy::CrlValidationInput input;
    input.signer_certificate_der = user;
    input.issuer_certificate_der = root;
    input.validation_time = validation_time_buf;
    input.crls_der.push_back(std::vector<std::uint8_t>{'n','o','t','-','c','r','l'});
    input.crls_der.push_back(full_crl);
    const auto result = validator.Validate(input);
    ExpectTrue(result.status == tamga::core::policy::RevocationStatus::Good,
               "Valid good CRL should be returned after earlier malformed CRLs");

    // Зворотний бік С-01: той самий CRL, оцінений СЬОГОДНІ, вже не є доказом.
    tamga::core::policy::CrlValidationInput stale_input = input;
    stale_input.validation_time.clear();
    const auto stale_result = validator.Validate(stale_input);
    ExpectTrue(stale_result.status != tamga::core::policy::RevocationStatus::Good,
               "CRL outside its validity window must not prove 'not revoked'");
    ExpectFalse(result.revoked, "Good status should keep result.revoked false");
#endif
}

void TestOcspValidatorUnavailable() {
#if TAMGA_CRYPTONITE_ENABLED
    tamga::core::policy::OcspValidator validator;
    tamga::core::policy::OcspValidationInput input;
    input.url = "https://ocsp.example.test";
    input.timeout_ms = 1000;
    input.signer_certificate_der = GenerateDstuFixture().cert_der;
    input.issuer_certificate_der = input.signer_certificate_der;

    tamga::core::HttpClient::ScopedMockTransport mock(
        [](const tamga::core::HttpRequest& request) {
            ExpectTrue(request.accept == "application/ocsp-response",
                       "OCSP request should accept application/ocsp-response");
            tamga::core::HttpResponse response;
            response.succeeded = false;
            response.status_code = 0;
            response.message = "network unavailable";
            return response;
        });

    const auto result = validator.Validate(input);
    ExpectTrue(result.checked, "OCSP validator should count configured request as checked");
    ExpectTrue(result.status == tamga::core::policy::RevocationStatus::ResponderUnavailable,
               "Network failure should map to responder unavailable");
#else
    RecordSkip("Cryptonite OCSP fixtures not available");
#endif
}

void TestOcspStatusMappingRequiresRequestedCertId() {
    tamga::core::policy::detail::OcspCertIdFields requested;
    requested.issuer_name_hash = std::vector<std::uint8_t>{0x01};
    requested.issuer_key_hash = std::vector<std::uint8_t>{0x02};
    requested.serial_number = std::vector<std::uint8_t>{0x03};

    tamga::core::policy::detail::OcspMappedCertificateStatus other;
    other.cert_id.issuer_name_hash = requested.issuer_name_hash;
    other.cert_id.issuer_key_hash = requested.issuer_key_hash;
    other.cert_id.serial_number = std::vector<std::uint8_t>{0x7f};
    other.status = "good";

    bool revoked = false;
    std::string message;
    const auto result = tamga::core::policy::detail::MapOcspStatusForRequestedCertId(
        requested,
        std::vector<tamga::core::policy::detail::OcspMappedCertificateStatus>{other},
        revoked,
        message);

    ExpectTrue(result == tamga::core::policy::RevocationStatus::Unknown,
               "OCSP status for another CertID must not apply to requested signer");
    ExpectFalse(revoked, "Mismatched OCSP status must not mark requested signer revoked");
}

void TestOcspStatusMergeUsesResponseOrderForDuplicateSerials() {
    tamga::core::policy::detail::OcspMappedCertificateStatus first_cert_id;
    first_cert_id.cert_id.issuer_name_hash = std::vector<std::uint8_t>{0x10};
    first_cert_id.cert_id.issuer_key_hash = std::vector<std::uint8_t>{0x11};
    first_cert_id.cert_id.serial_number = std::vector<std::uint8_t>{0x01};

    tamga::core::policy::detail::OcspMappedCertificateStatus second_cert_id;
    second_cert_id.cert_id.issuer_name_hash = std::vector<std::uint8_t>{0x20};
    second_cert_id.cert_id.issuer_key_hash = std::vector<std::uint8_t>{0x21};
    second_cert_id.cert_id.serial_number = std::vector<std::uint8_t>{0x01};

    tamga::core::policy::detail::OcspMappedCertificateStatus first_api_status;
    first_api_status.cert_id.serial_number = std::vector<std::uint8_t>{0x01};
    first_api_status.status = "revoked";

    tamga::core::policy::detail::OcspMappedCertificateStatus second_api_status;
    second_api_status.cert_id.serial_number = std::vector<std::uint8_t>{0x01};
    second_api_status.status = "good";

    auto merged = tamga::core::policy::detail::MergeOcspStatusesByResponseOrder(
        std::vector<tamga::core::policy::detail::OcspMappedCertificateStatus>{first_cert_id, second_cert_id},
        std::vector<tamga::core::policy::detail::OcspMappedCertificateStatus>{first_api_status, second_api_status});

    bool revoked = false;
    std::string message;
    const auto result = tamga::core::policy::detail::MapOcspStatusForRequestedCertId(
        second_cert_id.cert_id,
        merged,
        revoked,
        message);

    ExpectTrue(result == tamga::core::policy::RevocationStatus::Good,
               "Duplicate serial OCSP statuses must stay aligned by SingleResponse order");
    ExpectFalse(revoked, "Revoked status from another CertID with same serial must not leak into requested signer");
}

void TestOcspValidatorInvalidResponse() {
#if TAMGA_CRYPTONITE_ENABLED
    tamga::core::policy::OcspValidator validator;
    tamga::core::policy::OcspValidationInput input;
    input.url = "https://ocsp.example.test";
    input.timeout_ms = 1000;
    input.signer_certificate_der = GenerateDstuFixture().cert_der;
    input.issuer_certificate_der = input.signer_certificate_der;

    tamga::core::HttpClient::ScopedMockTransport mock(
        [](const tamga::core::HttpRequest&) {
            tamga::core::HttpResponse response;
            response.succeeded = true;
            response.status_code = 200;
            response.body = std::vector<std::uint8_t>{'n','o','t','-','o','c','s','p'};
            response.message = "OK";
            return response;
        });

    const auto result = validator.Validate(input);
    ExpectTrue(result.status == tamga::core::policy::RevocationStatus::Invalid,
               "Malformed OCSP response should map to invalid");
#else
    RecordSkip("Cryptonite OCSP fixtures not available");
#endif
}

void TestVerifyReportInvalidRevocationMapping() {
#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU4145 fixture generation should succeed for revocation report test");
    if (!fixture.valid) {
        return;
    }

    const auto work_dir = MakeTemporaryFixturePath(".invalid-crl-policy");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir / "trust-store", ec);
    std::filesystem::create_directories(work_dir / "crl-store", ec);
    ExpectTrue(WriteBinaryFile(work_dir / "trust-store" / "fixture.cer", fixture.cert_der),
               "Revocation report test should write trust anchor");
    ExpectTrue(WriteBinaryFile(work_dir / "crl-store" / "broken.crl",
                               std::vector<std::uint8_t>{'n','o','t','-','c','r','l'}),
               "Revocation report test should write malformed CRL");

    tamga::core::Session session;
    tamga::core::Settings settings;
    settings.offline_mode = true;
    settings.work_dir = work_dir.string();
    ExpectTrue(session.SetSettings(settings), "Session should accept revocation report work dir");
    ExpectTrue(session.Initialize(), "Session should initialize for revocation report test");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "Fixture key should load for revocation report test");

    const std::vector<std::uint8_t> payload = {'c', 'r', 'l'};
    std::vector<std::uint8_t> signature;
    ExpectSessionTrue(session, session.SignData(payload, signature),
                      "Signing should succeed for revocation report test");
    bool is_valid = false;
    ExpectSessionTrue(session, session.VerifyData(payload, signature, is_valid),
                      "VerifyData should execute for invalid CRL policy report");
    ExpectTrue(is_valid, "Invalid CRL policy must preserve VerifyData integrity Boolean");

    std::string report;
    ExpectTrue(session.GetLastVerifyReport(report), "GetLastVerifyReport should expose invalid CRL policy");
    ExpectContains(report, "\"revocationStatus\":\"invalid\"",
                   "Invalid CRL policy should expose revocationStatus invalid");
    ExpectContains(report, "\"trustValid\":false",
                   "Invalid CRL policy should mark trustValid false");
    ExpectContains(report, "\"trustStatus\":\"revocation-check-invalid\"",
                   "Invalid CRL policy should expose revocation-check-invalid trustStatus");
    ExpectContains(report, "\"errorCode\":\"RevocationCheckFailed\"",
                   "Invalid CRL policy should preserve RevocationCheckFailed error code");

    std::filesystem::remove_all(work_dir, ec);
#endif
}

void TestRevocationEngine() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    const auto root = ReadBinaryFixture(pki_dir / "root_certificate.cer");
    const auto user_fiz = ReadBinaryFixture(pki_dir / "userfiz_certificate.cer");
    const auto user_ur = ReadBinaryFixture(pki_dir / "userur_certificate.cer");
    const auto full_crl = ReadBinaryFixture(pki_dir / "full.crl");

    if (root.empty() || user_fiz.empty() || user_ur.empty() || full_crl.empty()) {
        RecordSkip("Cryptonite fixtures not available for revocation engine test");
        return;
    }

    using namespace tamga::core::validation;
    RevocationEngine engine;

    // 1. role-aware revocation engine (Signer, TSA, etc.)
    {
        RevocationEngineInput input;
        input.certificate_der = user_fiz;
        input.issuer_certificate_der = root;
        input.role = CertificateRole::Tsa;
        input.revocation_hard_fail = false;

        auto res = engine.Validate(input);
        ExpectTrue(Contains(res.because[0], "Tsa"), "TSA role should be logged");
    }

    // 2. signer revocation unknown + strict standard -> indeterminate
    {
        RevocationEngineInput input;
        input.certificate_der = user_fiz;
        input.issuer_certificate_der = root;
        input.role = CertificateRole::Signer;
        input.revocation_hard_fail = true;

        auto res = engine.Validate(input);
        ExpectTrue(res.overall_status == OverallStatus::Indeterminate,
                   "Unknown revocation + strict standard -> Indeterminate overall status");
    }

    // 2a. signer revocation unknown + soft-fail policy stays indeterminate
    {
        RevocationEngineInput input;
        input.certificate_der = user_fiz;
        input.issuer_certificate_der = root;
        input.role = CertificateRole::Signer;
        input.revocation_hard_fail = false;

        auto res = engine.Validate(input);
        ExpectTrue(res.overall_status == OverallStatus::Indeterminate,
                   "Unknown revocation must not become Valid under soft-fail policy");
        ExpectTrue(res.revocation_status == tamga::core::policy::RevocationStatus::NotChecked ||
                   res.revocation_status == tamga::core::policy::RevocationStatus::Unknown,
                   "Soft-fail unknown revocation should remain not-checked/unknown");
    }

    // 3. Відкликання підтверджується застосовним криптографічно перевіреним
    // CRL, а не штучним збігом серійного номера з CRL стороннього видавця.
    const auto revoked_fixture = GenerateDstuFixture();
    std::vector<std::uint8_t> revoked_crl;
    ExpectTrue(revoked_fixture.valid && GenerateRevokedCrlForEngineTest(revoked_fixture, revoked_crl),
               "Справжній підписаний CRL з відкликаною фікстурою має створитися");
    const auto checked_revocation = tamga::core::CryptoniteAdapter::CheckCertificateRevocation(
        revoked_fixture.cert_der, revoked_crl, revoked_fixture.cert_der);
    const std::string revocation_diagnostic =
        "Передумова: підпис CRL коректний та сертифікат справді присутній серед відкликаних; checked=" +
        std::to_string(checked_revocation.checked) + ", crl_valid=" + std::to_string(checked_revocation.crl_valid) +
        ", revoked=" + std::to_string(checked_revocation.revoked) + ", message=" + checked_revocation.message;
    ExpectTrue(checked_revocation.checked && checked_revocation.crl_valid && checked_revocation.revoked,
               revocation_diagnostic.c_str());

    time_t rev_time = 0;
    {
        RevocationEngineInput input;
        input.certificate_der = revoked_fixture.cert_der;
        input.issuer_certificate_der = revoked_fixture.cert_der;
        input.role = CertificateRole::Signer;
        input.crls_der.push_back(revoked_crl);
        input.revocation_hard_fail = true;

        auto res = engine.Validate(input);
        ExpectTrue(res.overall_status == OverallStatus::Invalid, "Should be invalid when revoked");
        ExpectTrue(res.revocation_status == tamga::core::policy::RevocationStatus::Revoked, "Should be Revoked");
        ExpectTrue(res.revocation_time > 0, "Revocation time should be populated");
        rev_time = res.revocation_time;
    }

    if (rev_time > 0) {
        time_t before_rev = rev_time - 3600;
        struct tm tm_before;
#ifdef _WIN32
        gmtime_s(&tm_before, &before_rev);
#else
        gmtime_r(&before_rev, &tm_before);
#endif
        char time_str[64];
        std::strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_before);

        RevocationEngineInput input;
        input.certificate_der = revoked_fixture.cert_der;
        input.issuer_certificate_der = revoked_fixture.cert_der;
        input.role = CertificateRole::Signer;
        input.crls_der.push_back(revoked_crl);
        input.validation_time = time_str;
        input.revocation_hard_fail = true;

        auto res = engine.Validate(input);
        ExpectTrue(res.overall_status == OverallStatus::Valid,
                   "Should be Valid if signature evaluation time is before revocation time");
    }

    // 4. OCSP responder unavailable + offline -> no network call and indeterminate when required
    {
        RevocationEngineInput input;
        input.certificate_der = user_fiz;
        input.issuer_certificate_der = root;
        input.role = CertificateRole::Signer;
        input.ocsp_url = "http://ocsp.example.test";
        input.network_allowed = false;
        input.revocation_hard_fail = true;

        auto res = engine.Validate(input);
        ExpectTrue(res.overall_status == OverallStatus::Indeterminate,
                   "Offline + no CRL -> Indeterminate overall status");
        ExpectTrue(res.revocation_status == tamga::core::policy::RevocationStatus::NotChecked ||
                   res.revocation_status == tamga::core::policy::RevocationStatus::Unknown,
                   "Should not be checked/good/revoked");
    }

    // 5. evidence IDs are correctly populated for both OCSP and CRL validation results.
    // CRL:
    {
        RevocationEngineInput input;
        input.certificate_der = user_fiz;
        input.issuer_certificate_der = root;
        input.role = CertificateRole::Signer;
        input.crls_der.push_back(full_crl);

        auto res = engine.Validate(input);
        ExpectFalse(res.evidence_ids.empty(), "Should populate evidence IDs for CRL");
        ExpectTrue(Contains(res.evidence_ids[0], "sha256:"), "CRL evidence ID should be sha256 hex format");
    }
    // OCSP:
    {
        RevocationEngineInput input;
        input.certificate_der = user_fiz;
        input.issuer_certificate_der = root;
        input.role = CertificateRole::Signer;
        input.embedded_ocsp_response = {1, 2, 3};

        auto res = engine.Validate(input);
        ExpectFalse(res.evidence_ids.empty(), "Should populate evidence IDs for OCSP");
        ExpectTrue(Contains(res.evidence_ids[0], "sha256:"), "OCSP request evidence ID should be sha256 hex format");
        ExpectTrue(Contains(res.evidence_ids[1], "sha256:"), "OCSP response evidence ID should be sha256 hex format");
    }
#endif
}
