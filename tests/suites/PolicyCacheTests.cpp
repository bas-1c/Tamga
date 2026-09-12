#include "support/FixturePaths.h"
// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Кеш політики: матеріалізація довірчого сховища й метаданих, кириличні
// шляхи, збереження старого кешу при збої, вибір granted TSA-сервісу.
// Наскрізна тема — withdrawn і не-TSA сервіси не мають потрапляти у вибір.

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

void TestPolicyCacheMaterializesTrustStoreAndMetadata() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto xml_path = tamga_test::TestDataRoot() / "tests" / "TL-UA-EC.xml";
    const auto xml = ReadBinaryFixture(xml_path);
    tamga::core::policy::TrustListParser parser;
    const auto parsed = parser.Parse(std::string(xml.begin(), xml.end()));
    ExpectTrue(parsed.ok, "Real TL XML fixture should parse before materialization");

    const auto work_dir = MakeTemporaryFixturePath(".cache-materialized");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir, ec);

    tamga::core::policy::PolicyCache cache(work_dir.string());
    tamga::core::policy::PolicyCacheState state;
    state.source_url = "https://czo.gov.ua/download/tl/TL-UA-EC.xml";
    state.cache_status = "fresh";
    state.last_sync = "2026-06-15T00:00:00Z";
    state.update_succeeded = true;

    ExpectTrue(cache.WriteTrustListMaterialized(xml, state, parsed),
               "PolicyCache should materialize trust-store from real TL XML");
    ExpectTrue(std::filesystem::exists(cache.TrustListPath()), "Materialized write should cache raw TL XML");
    ExpectTrue(std::filesystem::exists(cache.StatePath()), "Materialized write should cache state JSON");
    ExpectTrue(std::filesystem::exists(cache.TrustStoreMetadataPath()),
               "Materialized write should create trust-store metadata JSON");

    const std::size_t cer_count = CountCerFilesForTest(cache.TrustStoreDir());
    ExpectTrue(cer_count > 0, "Materialized write should create .cer trust anchors");

    const auto metadata_blob = ReadBinaryFixture(cache.TrustStoreMetadataPath());
    const std::string metadata(metadata_blob.begin(), metadata_blob.end());
    ExpectValidJson(metadata, "Trust-store metadata should be valid JSON");
    ExpectContains(metadata, "\"sourceUrl\":\"https://czo.gov.ua/download/tl/TL-UA-EC.xml\"",
                   "Metadata should preserve source TL URL");
    ExpectContains(metadata, "\"serviceType\":\"http://czo.gov.ua/TrstSvc/Svctype/CA/QC\"",
                   "Metadata should include CA service type");
    ExpectContains(metadata, "\"status\":\"http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted\"",
                   "Metadata should include granted service status");
    ExpectContains(metadata, "\"materializedTrustAnchor\":true",
                   "Metadata should identify materialized CA trust anchors");
    ExpectContains(metadata, "\"materializedTrustAnchor\":false",
                   "Metadata should retain non-anchor services such as TSA");
#else
    // V-05: матеріалізація довірчого списку розбирає сертифікати через
    // cryptonite (PolicyCache.cpp:196 під тим самим guard), тож у
    // діагностичній збірці vendor=OFF цей сценарій недосяжний за побудовою.
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestPolicyCacheUsesUtf8WorkDirForCyrillicPaths() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto xml = BuildGrantedCaTrustListXmlForTest();
    tamga::core::policy::TrustListParser parser;
    const auto parsed = parser.Parse(std::string(xml.begin(), xml.end()));

    const auto work_dir = MakeTemporaryFixturePath(".unicode-work") / u8"Калина" / "work";
    const std::string work_dir_utf8 = work_dir.u8string();
    std::error_code ec;
    std::filesystem::remove_all(work_dir.parent_path().parent_path(), ec);

    tamga::core::policy::PolicyCache cache(work_dir_utf8);
    tamga::core::policy::PolicyCacheState state;
    state.source_url = "https://czo.gov.ua/download/tl/TL-UA-EC.xml";
    state.cache_status = "fresh";
    state.last_sync = "2026-06-15T00:00:00Z";
    state.update_succeeded = true;

    ExpectTrue(cache.WriteTrustListMaterialized(xml, state, parsed),
               "PolicyCache should write materialized trust data under UTF-8 Cyrillic workDir");
    ExpectTrue(std::filesystem::exists(work_dir / "trust-list" / "TL-UA-EC.xml"),
               "PolicyCache should create trust-list XML in the exact Cyrillic workDir");
    ExpectTrue(std::filesystem::exists(work_dir / "policy" / "trust-store-metadata.json"),
               "PolicyCache should create metadata in the exact Cyrillic workDir");
    ExpectTrue(CountCerFilesForTest(work_dir / "trust-store") > 0,
               "PolicyCache should create .cer anchors in the exact Cyrillic workDir");

    std::filesystem::remove_all(work_dir.parent_path().parent_path(), ec);
#else
    // V-05: матеріалізація довірчого списку розбирає сертифікати через
    // cryptonite (PolicyCache.cpp:196 під тим самим guard), тож у
    // діагностичній збірці vendor=OFF цей сценарій недосяжний за побудовою.
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestPolicyCacheMaterializedWriteKeepsOldCacheOnMetadataFailure() {
    const auto xml = BuildGrantedCaTrustListXmlForTest();
    tamga::core::policy::TrustListParser parser;
    const auto parsed = parser.Parse(std::string(xml.begin(), xml.end()));

    const auto work_dir = MakeTemporaryFixturePath(".cache-materialized-atomic");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir, ec);

    tamga::core::policy::PolicyCache cache(work_dir.string());
    tamga::core::policy::PolicyCacheState old_state;
    old_state.source_url = "https://example.test/old.xml";
    old_state.cache_status = "fresh";
    old_state.last_sync = "2026-06-14T00:00:00Z";
    old_state.update_succeeded = true;
    ExpectTrue(cache.WriteTrustList(std::vector<std::uint8_t>{'<','o','l','d','/','>'}, old_state),
               "Test should seed old trust list cache");
    std::filesystem::create_directories(cache.TrustStoreDir(), ec);
    ExpectTrue(WriteBinaryFile(cache.TrustStoreDir() / "old.cer", std::vector<std::uint8_t>{'o','l','d'}),
               "Test should seed old trust-store anchor");

    std::filesystem::path blocked_metadata_temp = cache.TrustStoreMetadataPath();
    blocked_metadata_temp += ".tmp";
    std::filesystem::create_directories(blocked_metadata_temp, ec);
    ExpectTrue(WriteBinaryFile(blocked_metadata_temp / "block", std::vector<std::uint8_t>{'x'}),
               "Test should block metadata temp path with a non-empty directory");

    tamga::core::policy::PolicyCacheState new_state = old_state;
    new_state.source_url = "https://example.test/new.xml";
    new_state.last_sync = "2026-06-15T00:00:00Z";
    ExpectFalse(cache.WriteTrustListMaterialized(std::vector<std::uint8_t>{'<','n','e','w','/','>'}, new_state, parsed),
                "Materialized write should fail when metadata temp path cannot be staged");

    const auto cached_xml = ReadBinaryFixture(cache.TrustListPath());
    ExpectTrue(std::string(cached_xml.begin(), cached_xml.end()) == "<old/>",
               "Materialized write failure should keep previous trust-list XML");
    ExpectTrue(std::filesystem::exists(cache.TrustStoreDir() / "old.cer"),
               "Materialized write failure should keep previous trust-store file");
    ExpectTrue(CountCerFilesForTest(cache.TrustStoreDir()) == 1,
               "Materialized write failure should not leak newly staged trust anchors");

    tamga::core::policy::PolicyCacheState read_state;
    ExpectTrue(cache.ReadState(read_state), "Previous cache state should remain readable");
    ExpectTrue(read_state.source_url == old_state.source_url, "Previous cache state should not be replaced");

    std::filesystem::remove_all(work_dir, ec);
}

void TestPolicyCacheDoesNotMaterializeLegacyShortServiceTypes() {
    const auto xml = BuildTrustListXmlForTest("CA", "granted");
    tamga::core::policy::TrustListParser parser;
    const auto parsed = parser.Parse(std::string(xml.begin(), xml.end()));

    const auto work_dir = MakeTemporaryFixturePath(".cache-short-service-type");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir, ec);

    tamga::core::policy::PolicyCache cache(work_dir.string());
    tamga::core::policy::PolicyCacheState state;
    state.source_url = "https://example.test/tl.xml";
    state.cache_status = "fresh";
    state.last_sync = "2026-06-15T00:00:00Z";
    state.update_succeeded = true;

    ExpectTrue(cache.WriteTrustListMaterialized(xml, state, parsed),
               "PolicyCache may cache non-official service metadata");
    ExpectTrue(CountCerFilesForTest(cache.TrustStoreDir()) == 0,
               "PolicyCache should not materialize short CA/granted legacy values as trust anchors");
    const auto metadata_blob = ReadBinaryFixture(cache.TrustStoreMetadataPath());
    const std::string metadata(metadata_blob.begin(), metadata_blob.end());
    ExpectContains(metadata, "\"materializedTrustAnchor\":false",
                   "Metadata should mark non-official CA/granted values as non-materialized");

    std::filesystem::remove_all(work_dir, ec);
}

// ME-06 (повний фікс): PolicyCache::ResolveGrantedTspUrl() читає
// trust-store-metadata.json і повертає перший tspUrl GRANTED TSA-сервісу
// (MR-TSA/QTST чи National-TSA/QTST), без прив'язки до issuer'а
// конкретного сертифіката (рішення користувача).
void TestPolicyCacheResolveGrantedTspUrlFindsTsaService() {
    const auto xml = BuildTrustListXmlForTest("http://czo.gov.ua/TrstSvc/Svctype/National-TSA/QTST",
                                              "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted");
    tamga::core::policy::TrustListParser parser;
    const auto parsed = parser.Parse(std::string(xml.begin(), xml.end()));
    ExpectTrue(parsed.ok, "Synthetic granted TSA TL XML should parse");

    const auto work_dir = MakeTemporaryFixturePath(".cache-tsa-resolve");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir, ec);

    tamga::core::policy::PolicyCache cache(work_dir.string());
    tamga::core::policy::PolicyCacheState state;
    state.source_url = "https://example.test/tl.xml";
    state.cache_status = "fresh";
    state.last_sync = "2026-06-15T00:00:00Z";
    state.update_succeeded = true;

    ExpectTrue(cache.WriteTrustListMaterialized(xml, state, parsed),
               "PolicyCache should materialize TSA service metadata");
    ExpectTrue(cache.ResolveGrantedTspUrl() == "https://example.test/tsp",
               "ME-06: ResolveGrantedTspUrl must find the granted TSA service's tspUrl");

    std::filesystem::remove_all(work_dir, ec);
}

void TestPolicyCacheResolveGrantedTspUrlIgnoresNonTsaService() {
    const auto xml = BuildGrantedCaTrustListXmlForTest();  // CA/QC, has its own <TSP> tag but is not a TSA
    tamga::core::policy::TrustListParser parser;
    const auto parsed = parser.Parse(std::string(xml.begin(), xml.end()));
    ExpectTrue(parsed.ok, "Synthetic granted CA TL XML should parse");

    const auto work_dir = MakeTemporaryFixturePath(".cache-tsa-ignore-ca");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir, ec);

    tamga::core::policy::PolicyCache cache(work_dir.string());
    tamga::core::policy::PolicyCacheState state;
    state.source_url = "https://example.test/tl.xml";
    state.cache_status = "fresh";
    state.last_sync = "2026-06-15T00:00:00Z";
    state.update_succeeded = true;

    ExpectTrue(cache.WriteTrustListMaterialized(xml, state, parsed),
               "PolicyCache should materialize CA service metadata");
    ExpectTrue(cache.ResolveGrantedTspUrl().empty(),
               "ME-06: ResolveGrantedTspUrl must ignore non-TSA service types");

    std::filesystem::remove_all(work_dir, ec);
}

void TestPolicyCacheResolveGrantedTspUrlIgnoresWithdrawnTsaService() {
    const auto xml = BuildTrustListXmlForTest("http://czo.gov.ua/TrstSvc/Svctype/National-TSA/QTST",
                                              "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/withdrawn");
    tamga::core::policy::TrustListParser parser;
    const auto parsed = parser.Parse(std::string(xml.begin(), xml.end()));
    ExpectTrue(parsed.ok, "Synthetic withdrawn TSA TL XML should parse");

    const auto work_dir = MakeTemporaryFixturePath(".cache-tsa-withdrawn");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir, ec);

    tamga::core::policy::PolicyCache cache(work_dir.string());
    tamga::core::policy::PolicyCacheState state;
    state.source_url = "https://example.test/tl.xml";
    state.cache_status = "fresh";
    state.last_sync = "2026-06-15T00:00:00Z";
    state.update_succeeded = true;

    ExpectTrue(cache.WriteTrustListMaterialized(xml, state, parsed),
               "PolicyCache should materialize withdrawn TSA service metadata");
    ExpectTrue(cache.ResolveGrantedTspUrl().empty(),
               "ME-06: ResolveGrantedTspUrl must ignore non-granted (withdrawn) TSA services");

    std::filesystem::remove_all(work_dir, ec);
}

void TestPolicyCacheResolveGrantedTspUrlEmptyWithoutCache() {
    const auto work_dir = MakeTemporaryFixturePath(".cache-tsa-missing");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir, ec);

    tamga::core::policy::PolicyCache cache(work_dir.string());
    ExpectTrue(cache.ResolveGrantedTspUrl().empty(),
               "ME-06: ResolveGrantedTspUrl must return empty when no trust-store-metadata.json exists");

    std::filesystem::remove_all(work_dir, ec);
}
