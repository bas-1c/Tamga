// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Контейнери ASiC-S / ASiC-E: round-trip, межа розміру, мітка часу,
// нормалізація імен записів у маніфесті CAdES.

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

void TestAsicContainerRoundTrip() {
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestAsicContainerRoundTrip ---\n";

    // 1. Тест для ASiC-S
    {
        AsicWriter writer(AsicType::AsicS);
        std::vector<std::uint8_t> doc = {'h', 'e', 'l', 'l', 'o', ' ', 'a', 's', 'i', 'c', '-', 's'};
        std::vector<std::uint8_t> sig = {'s', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e'};

        ExpectTrue(writer.AddFile("doc.pdf", doc), "Add doc.pdf to ASiC-S");
        ExpectTrue(writer.AddFile("doc.pdf.p7s", sig), "Add doc.pdf.p7s to ASiC-S");

        std::vector<std::uint8_t> container;
        std::string err;
        ExpectTrue(writer.Finalize(container, err), "Finalize ASiC-S container");
        ExpectFalse(container.empty(), "ASiC-S container should not be empty");

        // Читаємо
        AsicReader reader;
        ExpectTrue(reader.LoadFromBuffer(container, err), "Load ASiC-S container");

        std::string mime;
        ExpectTrue(reader.GetMimetype(mime), "Get mimetype from ASiC-S");
        ExpectTrue(mime == "application/vnd.etsi.asic-s+zip", "ASiC-S mimetype should be correct");

        std::vector<AsicFileEntry> files;
        ExpectTrue(reader.GetFiles(files, err), "Get files from ASiC-S");
        ExpectTrue(files.size() == 3, "ASiC-S must contain 3 files (mimetype, doc.pdf, doc.pdf.p7s)");

        std::vector<std::uint8_t> ext_doc;
        ExpectTrue(reader.ExtractFile("doc.pdf", ext_doc, err), "Extract doc.pdf");
        ExpectTrue(ext_doc == doc, "Extracted doc.pdf matches original");
    }

    // 2. Тест для ASiC-E
    {
        AsicWriter writer(AsicType::AsicE);
        std::vector<std::uint8_t> doc = {'h', 'e', 'l', 'l', 'o', ' ', 'a', 's', 'i', 'c', '-', 'e'};
        std::vector<std::uint8_t> sig = {'m', 'a', 'n', 'i', 'f', 'e', 's', 't', '-', 's', 'i', 'g'};

        ExpectTrue(writer.AddFile("doc.pdf", doc), "Add doc.pdf to ASiC-E");
        ExpectTrue(writer.AddFile("META-INF/signature.xml", sig), "Add META-INF/signature.xml to ASiC-E");

        std::vector<std::uint8_t> container;
        std::string err;
        ExpectTrue(writer.Finalize(container, err), "Finalize ASiC-E container");

        AsicReader reader;
        ExpectTrue(reader.LoadFromBuffer(container, err), "Load ASiC-E container");

        std::string mime;
        ExpectTrue(reader.GetMimetype(mime), "Get mimetype from ASiE");
        ExpectTrue(mime == "application/vnd.etsi.asic-e+zip", "ASiC-E mimetype should be correct");
    }
}

// HI-05: AsicReader::LoadFromFile must reject an oversized input file by its
// on-disk size BEFORE allocating a buffer for the whole content. Uses a
// sparse file (seek + single trailing byte) so the test does not actually
// materialize hundreds of MiB on disk or in memory.
void TestAsicReaderLoadFromFileRejectsOversizedContainer() {
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestAsicReaderLoadFromFileRejectsOversizedContainer ---\n";

    const auto path = MakeTemporaryFixturePath(".oversized.asice");
    constexpr std::uint64_t kOversizeBytes = 300ULL * 1024ULL * 1024ULL + 1ULL;
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        ExpectTrue(out.is_open(), "Open sparse oversized fixture for writing");
        out.seekp(static_cast<std::streamoff>(kOversizeBytes - 1));
        out.put('\0');
        ExpectTrue(out.good(), "Write sparse oversized fixture");
    }

    AsicReader reader;
    std::string error_message;
    const bool loaded = reader.LoadFromFile(path.u8string(), error_message);
    ExpectFalse(loaded, "LoadFromFile must reject a container above the compressed-size limit");
    ExpectTrue(error_message.find("too large") != std::string::npos,
               "Rejection error should mention the size limit");

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

void TestSignFileAsicSAndEIntegration() {
#if TAMGA_CRYPTONITE_ENABLED
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestSignFileAsicSAndEIntegration ---\n";

    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    // Негативна регресія для колишньої неявної підміни алгоритму: навіть якщо
    // outer signatureAlgorithm сертифіката вказує на Купину, ЯВНО запитаний
    // ГОСТ має лишитися ГОСТ. Сертифікат тут лише перемикає старий
    // digest_adapter_init_by_cert; криптографічний підпис сертифіката для цього
    // unit-рівневого обчислення не перевіряється.
    std::vector<std::uint8_t> kupyna_outer_cert;
    {
        ByteArray* cert_ba = ba_alloc_from_uint8(fixture.cert_der.data(), fixture.cert_der.size());
        Certificate_t* cert = cert_alloc();
        ByteArray* encoded = nullptr;
        const bool prepared = cert_ba != nullptr && cert != nullptr &&
            cert_decode(cert, cert_ba) == RET_OK &&
            pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_DSTU7564_ID),
                         &cert->signatureAlgorithm.algorithm) == RET_OK &&
            cert_encode(cert, &encoded) == RET_OK && encoded != nullptr;
        ExpectTrue(prepared, "should prepare a certificate with Kupyna outer signatureAlgorithm");
        if (prepared) {
            kupyna_outer_cert.assign(ba_get_buf(encoded), ba_get_buf(encoded) + ba_get_len(encoded));
        }
        ba_free(encoded);
        cert_free(cert);
        ba_free(cert_ba);
    }
    const std::vector<std::uint8_t> digest_probe{
        'A', 'S', 'i', 'C', '-', 'd', 'i', 'g', 'e', 's', 't'};
    ImprintResult explicit_gost;
    ImprintResult certificate_aware_gost;
    ImprintResult explicit_kupyna;
    std::string digest_error;
    ExpectTrue(ComputeImprint(ImprintDigest::Gost34311, digest_probe, explicit_gost, digest_error),
               "explicit GOST digest should be available");
    ExpectFalse(ComputeImprintByCertificate(kupyna_outer_cert, ImprintDigest::Gost34311,
                                            digest_probe, certificate_aware_gost, digest_error),
                "Kupyna certificate must not be accepted for an explicitly requested GOST digest");
    ExpectContains(digest_error, "не відповідає явно оголошеному XMLDSIG алгоритму",
                   "digest mismatch must fail closed with an actionable diagnostic");
    ExpectTrue(ComputeImprint(ImprintDigest::Kupyna256, digest_probe, explicit_kupyna, digest_error),
               "explicit Kupyna digest should be available");
    ExpectFalse(explicit_gost.hash == explicit_kupyna.hash,
                "explicit GOST digest must remain distinguishable from Kupyna");

    // Підготовка тимчасової папки
    namespace fs = std::filesystem;
    const fs::path tmp_dir = MakeTemporaryFixturePath(".asic");
    std::error_code ec;
    fs::create_directories(tmp_dir, ec);
    const std::string input_path = (tmp_dir / "test_doc.pdf").u8string();
    const std::string asics_path = (tmp_dir / "test_doc.asics").u8string();
    const std::string asice_path = (tmp_dir / "test_doc.asice").u8string();
    const std::string asice_cades_path = (tmp_dir / "test_doc.cades.asice").u8string();
    const std::string asice_cosigned_path = (tmp_dir / "test_doc.cosigned.asice").u8string();
    const std::string multi_asice_path = (tmp_dir / "multi.cades.asice").u8string();
    const std::string multi_cosigned_path = (tmp_dir / "multi.cosigned.asice").u8string();
    const std::string multi_tampered_path = (tmp_dir / "multi.tampered.asice").u8string();

    // Записати тестовий документ
    const std::string content = "Test document for ASiC signing";
    {
        std::ofstream f(input_path, std::ios::binary);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    // Ініціалізувати сесію
    Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for ASiC test");
    ExpectSessionTrue(session,
        session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
        "ReadPrivateKeyBinary should load key for ASiC test");

    // B-02: XAdES-частина потребує підсистеми XML і не може виконуватися в
    // базовій конфігурації.
    //
    // З версії 0.8.0 (ETSI EN 319 162-1) `SignFileAsicS`/`SignFileAsicE`
    // делегують у `SignFileAsicXades` — контейнери підписуються XAdES
    // (`META-INF/signatures.xml`), а не CAdES. Без
    // `TAMGA_ENABLE_XML_SIGNATURES` ці методи коректно повертають
    // `NotSupported` (fail-closed, `SessionXmlOps.ipp`), але гейт цього тесту
    // за зміною можливостей не пішов — і базова конфігурація стала червоною
    // (37/38). CAdES-частина нижче від XML не залежить і виконується всюди.
#if defined(TAMGA_XML_SIGNATURES_ENABLED)
    // --- ASiC-S ---
    ExpectSessionTrue(session, session.SignFileAsicS(input_path, asics_path),
        "SignFileAsicS should produce ASiC-S container");
    ExpectTrue(fs::exists(asics_path), "ASiC-S output file should exist");

    bool asics_valid = false;
    ExpectSessionTrue(session, session.VerifyFileAsicS(asics_path, asics_valid),
        "VerifyFileAsicS should succeed");
    ExpectTrue(asics_valid, "ASiC-S signature should be valid");

    AsicReader asics_reader;
    std::string asics_error;
    ExpectTrue(asics_reader.LoadFromFile(asics_path, asics_error),
               "ASiC-S should be readable for algorithm-profile inspection");
    std::vector<std::uint8_t> asics_signature_bytes;
    ExpectTrue(asics_reader.ExtractFile("META-INF/signatures.xml", asics_signature_bytes, asics_error),
               "ASiC-S should contain META-INF/signatures.xml");
    const std::string asics_signature_xml(asics_signature_bytes.begin(), asics_signature_bytes.end());
    ExpectContains(asics_signature_xml, "xmldsig-more#dstu4145-dstu7564-256",
                   "ASiC-S must declare the fixed Kupyna SignatureMethod profile");
    ExpectContains(asics_signature_xml, "xmlenc#dstu7564-256",
                   "ASiC-S must declare Kupyna DigestMethod values");
    ExpectTrue(asics_signature_xml.find("gost34311") == std::string::npos,
               "ASiC-S must not select GOST from the certificate outer signatureAlgorithm");

    // --- ASiC-E ---
    ExpectSessionTrue(session, session.SignFileAsicE(input_path, asice_path),
        "SignFileAsicE should produce ASiC-E container");
    ExpectTrue(fs::exists(asice_path), "ASiC-E output file should exist");

    bool asice_valid = false;
    ExpectSessionTrue(session, session.VerifyFileAsicE(asice_path, asice_valid),
        "VerifyFileAsicE should succeed");
    ExpectTrue(asice_valid, "ASiC-E signature should be valid");

    // Регресія для зовнішнього валідатора Дії (помилка формату 33). Власний
    // round-trip приймав XAdES, який відрізнявся від профілю реально
    // прийнятого Дією: не було Id у посилання на документ і зв'язаного
    // DataObjectFormat, використовувалися SigningCertificate та inclusive
    // C14N для SignedProperties.
    AsicReader asice_reader;
    std::string asice_error;
    ExpectTrue(asice_reader.LoadFromFile(asice_path, asice_error),
               "ASiC-E should be readable for Diia-profile inspection");
    std::vector<std::uint8_t> signature_bytes;
    ExpectTrue(asice_reader.ExtractFile("META-INF/signatures001.xml", signature_bytes, asice_error),
               "ASiC-E should contain META-INF/signatures001.xml");
    const std::string signature_xml(signature_bytes.begin(), signature_bytes.end());
    const std::string reference_prefix = "<ds:Reference Id=\"id-";
    const std::size_t reference_begin = signature_xml.find(reference_prefix);
    ExpectTrue(reference_begin != std::string::npos,
               "Diia-profile document Reference must have a generated Id");
    std::string document_reference_id;
    if (reference_begin != std::string::npos) {
        const std::size_t id_begin = reference_begin + std::string("<ds:Reference Id=\"").size();
        const std::size_t id_end = signature_xml.find('\"', id_begin);
        if (id_end != std::string::npos) {
            document_reference_id = signature_xml.substr(id_begin, id_end - id_begin);
        }
    }
    ExpectTrue(document_reference_id.size() > std::string("id--1").size() &&
                   document_reference_id.rfind("id-", 0) == 0 &&
                   document_reference_id.compare(document_reference_id.size() - 2, 2, "-1") == 0,
               "Diia-profile document Reference Id must use id-<guid>-1 format");
    const std::string guid = document_reference_id.size() > 5
                                 ? document_reference_id.substr(3, document_reference_id.size() - 5)
                                 : std::string{};
    ExpectTrue(guid.size() == 32 && guid.find_first_not_of("0123456789abcdef") == std::string::npos,
               "Diia-profile GUID must use exactly 32 lowercase hexadecimal characters");
    ExpectContains(signature_xml,
                   "<ds:Reference Id=\"" + document_reference_id +
                       "\" Type=\"\" URI=\"test_doc.pdf\"",
                   "Diia-profile document Reference must physically serialize Type=\"\"");
    ExpectContains(signature_xml, "Id=\"id-" + guid + "\"",
                   "Diia-profile Signature Id must share the document Reference GUID");
    ExpectContains(signature_xml, "Id=\"xades-id-" + guid + "\"",
                   "Diia-profile SignedProperties Id must share the document Reference GUID");
    ExpectContains(signature_xml,
                   "<asic:XAdESSignatures xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\" "
                   "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" "
                   "xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" "
                   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"",
                   "Diia-profile root must declare ASiC, XMLDSIG, XAdES and XSI namespaces");
    ExpectContains(signature_xml,
                   "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
                   "Diia-profile SignedProperties must use exclusive C14N");
    ExpectContains(signature_xml,
                   "<xades:SigningCertificateV2>",
                   "Diia-profile XAdES must use SigningCertificateV2");
    ExpectTrue(signature_xml.find("<xades:SigningCertificate>") == std::string::npos,
               "Diia-profile XAdES must not emit obsolete SigningCertificate");
    ExpectContains(signature_xml,
                   "<xades:DataObjectFormat ObjectReference=\"#" + document_reference_id +
                       "\"><xades:MimeType>application/pdf</xades:MimeType></xades:DataObjectFormat>",
                   "Diia-profile DataObjectFormat must target the document Reference");
    ExpectContains(signature_xml, "xmldsig-more#dstu4145-dstu7564-256",
                   "ASiC-E must declare the fixed Kupyna SignatureMethod profile");
    ExpectContains(signature_xml, "xmlenc#dstu7564-256",
                   "ASiC-E must declare Kupyna DigestMethod values");
    ExpectTrue(signature_xml.find("gost34311") == std::string::npos,
               "ASiC-E must not select GOST from the certificate outer signatureAlgorithm");

#else
    std::cerr << "  (XAdES-частину ASiC пропущено: збірка без "
                 "TAMGA_ENABLE_XML_SIGNATURES)\n";
#endif

    // --- ASiC-E + CAdES, точна розкладка еталонів Дії ---
    ExpectSessionTrue(session, session.SignFileAsicECades(input_path, asice_cades_path),
        "SignFileAsicECades should produce ASiC-E CAdES container");

    AsicReader cades_reader;
    std::string cades_error;
    ExpectTrue(cades_reader.LoadFromFile(asice_cades_path, cades_error),
               "ASiC-E CAdES should be readable for Diia-layout inspection");
    std::vector<AsicFileEntry> cades_entries;
    ExpectTrue(cades_reader.GetFiles(cades_entries, cades_error),
               "ASiC-E CAdES entries should be readable");
    const std::vector<std::string> expected_cades_entries{
        "mimetype", "test_doc.pdf", "META-INF/ASiCManifest001.xml",
        "META-INF/signature001.p7s"};
    ExpectTrue(cades_entries.size() == expected_cades_entries.size(),
               "ASiC-E CAdES must contain exactly the Diia-profile entries");
    if (cades_entries.size() == expected_cades_entries.size()) {
        for (std::size_t i = 0; i < expected_cades_entries.size(); ++i) {
            ExpectTrue(cades_entries[i].name == expected_cades_entries[i],
                       "ASiC-E CAdES must order the numbered manifest before its signature");
        }
    }

    std::vector<std::uint8_t> cades_manifest_bytes;
    ExpectTrue(cades_reader.ExtractFile("META-INF/ASiCManifest001.xml", cades_manifest_bytes,
                                       cades_error),
               "ASiC-E CAdES must contain the numbered manifest");
    const std::string cades_manifest(cades_manifest_bytes.begin(), cades_manifest_bytes.end());
    ExpectContains(cades_manifest,
                   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"",
                   "ASiC-E CAdES manifest must declare xsi like the Diia reference");
    ExpectContains(cades_manifest,
                   "URI=\"META-INF/signature001.p7s\" "
                   "MimeType=\"application/x-pkcs7-signature\"",
                   "ASiC-E CAdES SigReference must target the numbered signature");
    ExpectContains(cades_manifest, "http://www.w3.org/2001/04/xmlenc#dstu7564-256",
                   "ASiC-E CAdES DataObjectReference must declare Kupyna-256");
    ExpectTrue(cades_manifest.find("gost34311") == std::string::npos,
               "ASiC-E CAdES manifest must not mix a GOST data digest into the Kupyna profile");

    ImprintResult expected_cades_imprint;
    std::string expected_cades_imprint_error;
    const std::vector<std::uint8_t> cades_payload(content.begin(), content.end());
    ExpectTrue(ComputeImprint(ImprintDigest::Kupyna256, cades_payload,
                             expected_cades_imprint, expected_cades_imprint_error),
               "ASiC-E CAdES expected Kupyna digest should compute");
    ExpectContains(cades_manifest, tamga::util::Base64Encode(expected_cades_imprint.hash),
                   "ASiC-E CAdES DigestValue must be the actual Kupyna digest of the payload");

    bool cades_valid = false;
    ExpectSessionTrue(session, session.VerifyFileAsicE(asice_cades_path, cades_valid),
                      "VerifyFileAsicE should execute for generated ASiC-E CAdES");
    ExpectTrue(cades_valid, "generated ASiC-E CAdES signature should be valid");

    // AddSignatureToAsicE має створити новий маніфест, підписати саме його й
    // зберегти той самий тризначний суфікс у зв'язаній парі. Раніше helper
    // додавав порожній manifest_xml, тому Pack гарантовано відмовляв.
    ExpectSessionTrue(session,
                      session.AddSignatureToAsicE(asice_cades_path, asice_cosigned_path),
                      "AddSignatureToAsicE should add a second conforming CAdES signature");
    AsicReader cosigned_reader;
    std::string cosigned_error;
    ExpectTrue(cosigned_reader.LoadFromFile(asice_cosigned_path, cosigned_error),
               "co-signed ASiC-E should be readable");
    std::vector<std::uint8_t> second_manifest;
    std::vector<std::uint8_t> second_signature;
    ExpectTrue(cosigned_reader.ExtractFile("META-INF/ASiCManifest002.xml", second_manifest,
                                           cosigned_error),
               "co-signed ASiC-E should contain ASiCManifest002.xml");
    ExpectTrue(cosigned_reader.ExtractFile("META-INF/signature002.p7s", second_signature,
                                           cosigned_error),
               "co-signed ASiC-E should contain signature002.p7s");
    bool cosigned_valid = false;
    ExpectSessionTrue(session, session.VerifyFileAsicE(asice_cosigned_path, cosigned_valid),
                      "VerifyFileAsicE should execute for co-signed ASiC-E");
    ExpectTrue(cosigned_valid, "all signatures in co-signed ASiC-E should be valid");

    // Один CAdES-підпис ASiC-E може покривати кілька DataObjectReference через
    // підписаний маніфест. Генератор co-sign уже створює саме таку структуру,
    // тому verifier не повинен звужувати її до одного документа.
    AsicEContent multi_content;
    multi_content.files = {
        {"first.pdf", {'f', 'i', 'r', 's', 't'}},
        {"second.txt", {'s', 'e', 'c', 'o', 'n', 'd'}}};
    std::vector<AsicDataObjectRef> multi_refs;
    for (const auto& file : multi_content.files) {
        ImprintResult imprint;
        std::string imprint_error;
        ExpectTrue(ComputeImprint(ImprintDigest::Kupyna256, file.data, imprint, imprint_error),
                   "multi-document manifest digest should compute");
        multi_refs.push_back({file.filename,
                              GetMimeTypeFromFilename(file.filename),
                              "http://www.w3.org/2001/04/xmlenc#dstu7564-256",
                              tamga::util::Base64Encode(imprint.hash)});
    }
    const std::string multi_manifest =
        GenerateAsicManifestXml("META-INF/signature001.p7s", multi_refs);
    std::vector<std::uint8_t> multi_signature;
    ExpectSessionTrue(
        session,
        session.SignData(std::vector<std::uint8_t>(multi_manifest.begin(), multi_manifest.end()),
                         multi_signature),
        "multi-document manifest should be signed");
    multi_content.signatures.push_back({"META-INF/signature001.p7s",
                                        multi_signature,
                                        "META-INF/ASiCManifest001.xml",
                                        multi_manifest});
    std::vector<std::uint8_t> multi_container;
    std::string multi_error;
    ExpectTrue(AsicEContainer::Pack(multi_content, multi_container, multi_error),
               "multi-document ASiC-E CAdES should pack");
    ExpectTrue(WriteBinaryFile(multi_asice_path, multi_container),
               "multi-document ASiC-E CAdES should be written");
    bool multi_valid = false;
    ExpectSessionTrue(session, session.VerifyFileAsicE(multi_asice_path, multi_valid),
                      "multi-document ASiC-E CAdES verification should execute");
    ExpectTrue(multi_valid, "one manifest signature must cover both ASiC-E documents");

    AsicEContent tampered_multi_content = multi_content;
    tampered_multi_content.files[1].data[0] ^= 0x01;
    std::vector<std::uint8_t> tampered_multi_container;
    ExpectTrue(AsicEContainer::Pack(tampered_multi_content, tampered_multi_container, multi_error),
               "tampered multi-document ASiC-E CAdES should repack");
    ExpectTrue(WriteBinaryFile(multi_tampered_path, tampered_multi_container),
               "tampered multi-document ASiC-E CAdES should be written");
    bool tampered_multi_valid = true;
    ExpectSessionTrue(session,
                      session.VerifyFileAsicE(multi_tampered_path, tampered_multi_valid),
                      "tampered second ASiC-E document verification should execute");
    ExpectFalse(tampered_multi_valid,
                "changing the second DataObjectReference payload must invalidate ASiC-E");

    ExpectSessionTrue(session,
                      session.AddSignatureToAsicE(multi_asice_path, multi_cosigned_path),
                      "multi-document ASiC-E CAdES should accept a co-signature");
    bool multi_cosigned_valid = false;
    ExpectSessionTrue(session,
                      session.VerifyFileAsicE(multi_cosigned_path, multi_cosigned_valid),
                      "co-signed multi-document ASiC-E verification should execute");
    ExpectTrue(multi_cosigned_valid,
               "every co-signature manifest must cover both ASiC-E documents");

    // Cleanup
    fs::remove_all(tmp_dir, ec);
#else
    RecordSkip("Cryptonite not enabled");
#endif
}

// Регресія на дефект, знайдений 2026-09-03: ASiC-S із `signature.p7s` І
// `timestamp.tst` одночасно має ВІДХИЛЯТИСЬ.
//
// Tamga сама створювала такі контейнери: `SignData` у режимі BestEffort уже
// вкладав мітку часу в CMS (`id-aa-signatureTimeStampToken`), після чого
// `SignFileAsicS` робив ДРУГИЙ запит до TSA і клав окремий токен у
// `META-INF/timestamp.tst`. За ETSI EN 319 162-1 §4.3.3.2 у META-INF ASiC-S
// має бути АБО підпис, АБО позначка часу — це два різні профілі. Сторонні
// валідатори (сервіс Дії) відхиляли такий файл на розборі; наш власний читач
// приймав його мовчки, тож дефект не було видно зсередини.
//
// Що цей тест НЕ покриває більше. Доти тут жила перевірка контейнерної мітки
// часу (partial -> причина EKU -> invalid на зіпсованому токені). Вона
// будувалася саме на такому комбінованому контейнері, тож разом із fail-closed
// правилом стала недосяжною. Профіль timestamp-only ASiC-S (позначка часу БЕЗ
// підпису, токен штампує документ) не реалізований — доки він не з'явиться,
// цей шлях перевірки лишається без тестового покриття. Свідомий компроміс,
// зафіксований у docs/bugfix-log.md.
void TestAsicContainerTimestampValidated() {
#if TAMGA_CRYPTONITE_ENABLED
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestAsicContainerTimestampValidated ---\n";

    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for ASiC timestamp test");
    ExpectSessionTrue(session,
        session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
        "ReadPrivateKeyBinary should load key for ASiC timestamp test");

    const std::vector<std::uint8_t> file_data{'A','S','i','C','-','T','S'};
    std::vector<std::uint8_t> cms;
    ExpectTrue(session.SignData(file_data, cms, TimestampMode::Disabled),
               "SignData should produce CMS blob for ASiC timestamp test");

    std::vector<std::uint8_t> token;
    std::string ts_err;
    ExpectTrue(MockTsaTimestamp(fixture, cms, token, ts_err),
               "MockTsaTimestamp should mint a container timestamp token");

    namespace fs = std::filesystem;
    const fs::path tmp_dir = MakeTemporaryFixturePath(".asic-ts");
    std::error_code ec;
    fs::create_directories(tmp_dir, ec);

    // Публічний пакувальник відхиляє суперечливу комбінацію до запису ZIP.
    AsicSContent content;
    content.filename = "doc.txt";
    content.file_data = file_data;
    content.signature_data = cms;
    content.timestamp_data = token;
    std::vector<std::uint8_t> container;
    std::string pack_err;
    ExpectFalse(AsicSContainer::Pack(content, container, pack_err),
                "packer must reject signature.p7s beside timestamp.tst");

    // Для регресії читача будуємо історичну некоректну розкладку нижчим
    // AsicWriter: такі файли вже могли бути створені старою версією Tamga.
    AsicWriter legacy_writer(AsicType::AsicS);
    ExpectTrue(legacy_writer.AddFile(content.filename, content.file_data, true),
               "legacy fixture must contain the data object");
    ExpectTrue(legacy_writer.AddFile("META-INF/signature.p7s", content.signature_data, false),
               "legacy fixture must contain signature.p7s");
    ExpectTrue(legacy_writer.AddFile("META-INF/timestamp.tst", content.timestamp_data, false),
               "legacy fixture must contain timestamp.tst");
    ExpectTrue(legacy_writer.Finalize(container, pack_err),
               "legacy combined container fixture should be assembled");

    // 1. Розбір відхиляє контейнер і називає причину стандартом.
    AsicSContent parsed;
    std::string unpack_err;
    ExpectFalse(AsicSContainer::Unpack(container, parsed, unpack_err),
                "ASiC-S with both signature.p7s and timestamp.tst must be rejected");
    ExpectContains(unpack_err, "4.3.3.2",
                   "rejection must cite ETSI EN 319 162-1 clause 4.3.3.2");

    // 2. Той самий вердикт через публічний шлях перевірки.
    const fs::path combined_path = tmp_dir / "combined.asics";
    {
        std::ofstream f(combined_path, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(container.data()),
                static_cast<std::streamsize>(container.size()));
        ExpectTrue(f.good(), "should write the combined container fixture");
    }
    bool combined_valid = true;
    session.VerifyFileAsicS(combined_path.u8string(), combined_valid);
    ExpectFalse(combined_valid, "VerifyFileAsicS must not report the combined container as valid");

    // 3. Контейнер БЕЗ окремого токена (мітка часу живе всередині CAdES) —
    //    саме те, що Tamga тепер створює, — лишається читабельним.
    AsicSContent signature_only = content;
    signature_only.timestamp_data.clear();
    std::vector<std::uint8_t> conformant;
    ExpectTrue(AsicSContainer::Pack(signature_only, conformant, pack_err),
               "should pack a conformant ASiC-S without a sidecar timestamp");
    AsicSContent reparsed;
    ExpectTrue(AsicSContainer::Unpack(conformant, reparsed, unpack_err),
               "conformant ASiC-S must still be accepted");
    ExpectTrue(reparsed.timestamp_data.empty(),
               "conformant ASiC-S carries no sidecar timestamp entry");

    fs::remove_all(tmp_dir, ec);
#else
    RecordSkip("Cryptonite not enabled");
#endif
}

// ME-03: legacy CAdES ASiC-E (Session::VerifyFileAsicE / FindAsicEReferencedFile)
// previously normalized manifest URIs and entry names with a bare leading-'/'
// strip only -- no percent-decode, no "./"-strip, unlike the XAdES path
// (tamga::util::NormalizeAsicEntryUri, WP-7 ME-05). A manifest with
// URI="./document.pdf" or a percent-encoded filename would resolve correctly
// for XAdES ASiC-E but fail ("missing data object") for CAdES ASiC-E on the
// exact same style of container. This exercises the now-shared normalization
// on the CAdES path directly (no XML signatures involved).
void TestCadesAsicEManifestUriNormalization() {
#if TAMGA_CRYPTONITE_ENABLED
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestCadesAsicEManifestUriNormalization ---\n";

    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for CAdES ASiC-E URI test");
    ExpectSessionTrue(session,
        session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
        "ReadPrivateKeyBinary should load key for CAdES ASiC-E URI test");

    auto build_and_verify = [&](const std::string& entry_name, const std::string& manifest_uri,
                                const char* label) {
        const std::vector<std::uint8_t> doc(entry_name.begin(), entry_name.end());
        std::vector<std::uint8_t> signature;
        ExpectSessionTrue(session, session.SignData(doc, signature, TimestampMode::Disabled),
                          (std::string(label) + ": SignData should succeed").c_str());

        AsicEContent content;
        content.files.push_back({entry_name, doc});

        AsicEContent::SignatureEntry se;
        se.sig_filename = "META-INF/signature1.p7s";
        se.signature_data = signature;
        se.manifest_filename = "META-INF/ASiCManifest1.xml";
        // Порожні digest-поля тут НАВМИСНІ: маніфест будується у старому
        // форматі, без DigestMethod/DigestValue. Записані явно, бо GCC із
        // `-Wextra -Werror` відхиляє агрегатну ініціалізацію з пропущеними
        // членами, а мовчазне `{}` не показало б, що це рішення, а не недогляд.
        se.manifest_xml = GenerateAsicManifestXml(
            se.sig_filename,
            {{manifest_uri, "application/octet-stream", /*digest_uri=*/"", /*digest_base64=*/""}});
        content.signatures.push_back(se);

        std::vector<std::uint8_t> container;
        std::string err;
        ExpectTrue(AsicEContainer::Pack(content, container, err),
                  (std::string(label) + ": AsicEContainer::Pack should succeed").c_str());

        const auto tmp_path = MakeTemporaryFixturePath(".cades-uri-norm.asice");
        ExpectTrue(WriteBinaryFile(tmp_path, container),
                  (std::string(label) + ": container should be written to disk").c_str());

        bool is_valid = false;
        ExpectSessionTrue(session, session.VerifyFileAsicE(tmp_path.string(), is_valid),
                          (std::string(label) + ": VerifyFileAsicE should succeed").c_str());
        ExpectTrue(is_valid, (std::string(label) + ": CAdES ASiC-E signature should validate").c_str());

        std::error_code ec;
        std::filesystem::remove(tmp_path, ec);
    };

    build_and_verify("document.pdf", "./document.pdf", "'./'-prefixed manifest URI");
    build_and_verify("rahunok 2.pdf", "rahunok%202.pdf", "percent-encoded manifest URI");
#else
    RecordSkip("Cryptonite not enabled");
#endif
}

// Р-1 (знахідка сторожі точок застосування): ASiC-S мовчки приймав контейнер
// із КІЛЬКОМА документами.
//
// `AsicSContainer::Unpack` у циклі по записах робив
// `out_content.filename = entry.name; out_content.file_data = entry.data;` —
// тобто кожен наступний документ ПЕРЕЗАПИСУВАВ попередній. Лишався останній за
// порядком у ZIP, підпис перевірявся проти нього, а решта вмісту не була
// покрита жодним підписом і ніде не згадувалась. ETSI TS 102 918 вимагає для
// ASiC-S рівно один підписаний обʼєкт.
//
// Це той самий клас, що К-01/E і П-03: вміст, не покритий підписом, їде разом
// із валідним підписом і не потрапляє у вердикт. Знайдено не читанням коду, а
// сторожею `TestCoverageInvariantIsAppliedOnEveryContainerPath`, яка зажадала
// від кожного контейнерного шляху оголосити покриття.
void TestAsicSRejectsMultipleDataObjects() {
#if TAMGA_CRYPTONITE_ENABLED
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestAsicSRejectsMultipleDataObjects ---" << std::endl;

    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    Session session;
    ExpectTrue(PrepareInitializedSession(session),
               "Session should initialize for ASiC-S multi-document test");
    ExpectSessionTrue(session,
        session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
        "ReadPrivateKeyBinary should load key for ASiC-S multi-document test");

    const std::vector<std::uint8_t> doc = {'s', 'i', 'g', 'n', 'e', 'd'};
    std::vector<std::uint8_t> signature;
    ExpectSessionTrue(session, session.SignData(doc, signature, TimestampMode::Disabled),
                      "SignData should succeed for ASiC-S multi-document test");

    // `extra_first` керує ПОРЯДКОМ записів у ZIP, і це принципово. Старий
    // `Unpack` лишав ОСТАННІЙ документ, тож при extra_first=false підпис не
    // сходився з `extra.bin` і контейнер відхилявся — але з хибної причини
    // («підпис невалідний»), а не через непокритий вміст. Справжній дефект
    // видно лише при extra_first=true: підписаний документ виграє, підпис
    // сходиться, і контейнер приймається РАЗОМ із непокритим `extra.bin`.
    auto build_and_verify = [&](bool add_second_document, bool extra_first, const char* label) {
        AsicWriter writer(AsicType::AsicS);
        const std::vector<std::uint8_t> extra = {'u', 'n', 's', 'i', 'g', 'n', 'e', 'd'};
        if (add_second_document && extra_first) {
            ExpectTrue(writer.AddFile("extra.bin", extra),
                      (std::string(label) + ": AddFile(extra.bin)").c_str());
        }
        ExpectTrue(writer.AddFile("document.txt", doc),
                  (std::string(label) + ": AddFile(document.txt)").c_str());
        if (add_second_document && !extra_first) {
            ExpectTrue(writer.AddFile("extra.bin", extra),
                      (std::string(label) + ": AddFile(extra.bin)").c_str());
        }
        ExpectTrue(writer.AddFile("META-INF/signatures.p7s", signature, false),
                  (std::string(label) + ": AddFile(signature)").c_str());

        std::vector<std::uint8_t> container;
        std::string err;
        ExpectTrue(writer.Finalize(container, err),
                  (std::string(label) + ": Finalize should succeed").c_str());

        const auto tmp_path = MakeTemporaryFixturePath(".asics-multidoc.asics");
        ExpectTrue(WriteBinaryFile(tmp_path, container),
                  (std::string(label) + ": container should be written to disk").c_str());

        bool is_valid = true;
        const bool ok = session.VerifyFileAsicS(tmp_path.string(), is_valid);
        std::string report;
        session.GetLastVerifyReport(report);

        std::error_code ec;
        std::filesystem::remove(tmp_path, ec);
        return std::make_tuple(ok, is_valid, report);
    };

    // Позитивний контроль: рівно один документ — контейнер валідний і ЯВНО
    // оголошує покриття. Без цієї половини тест був би зелений і на
    // реалізації, що відхиляє будь-який ASiC-S.
    {
        const auto [ok, is_valid, report] = build_and_verify(false, false, "single document");
        ExpectTrue(ok, "single-document ASiC-S: VerifyFileAsicS should succeed");
        ExpectTrue(is_valid, "single-document ASiC-S must stay valid");
        ExpectContains(report, "\"containerType\":\"ASiC-S\"",
                       "single-document ASiC-S must report its container type");
        ExpectContains(report, "\"coverageStatus\":\"complete\"",
                       "single-document ASiC-S must declare coverage explicitly");
    }

    // Власне дефект: непокритий документ ПЕРЕД підписаним. Старий Unpack лишав
    // останній запис, тож підпис сходився, контейнер приймався — і `extra.bin`
    // їхав усередині, не покритий жодним підписом і не згаданий у звіті.
    {
        const auto [ok, is_valid, report] = build_and_verify(true, true, "unsigned entry first");
        ExpectFalse(is_valid,
                    "ASiC-S with two data objects must NOT be reported valid "
                    "(ETSI TS 102 918: рівно один підписаний обʼєкт)");
        ExpectContains(report, "ASiC-S",
                       "report should mention the ASiC-S container");
        (void)ok;
    }

    // Той самий контейнер у зворотному порядку. Він відхилявся й раніше, але з
    // ХИБНОЇ причини — «підпис невалідний» замість «зайвий документ». Тепер
    // причина мусить бути та сама, що вище.
    {
        const auto [ok, is_valid, report] = build_and_verify(true, false, "unsigned entry last");
        ExpectFalse(is_valid, "ASiC-S with two data objects must NOT be reported valid");
        ExpectContains(report, "ASiC-S", "report should mention the ASiC-S container");
        (void)ok;
    }
#else
    RecordSkip("Cryptonite not enabled");
#endif
}

// П-03: legacy CAdES ASiC-E перевіряв КОЖЕН підпис проти РІВНО ОДНОГО обʼєкта
// з маніфесту, але ніколи не збирав множину покритих файлів і не звіряв її зі
// вмістом контейнера. `container_coverage_complete` на цьому шляху не
// присвоювалося зовсім, тож лишалося дефолтним `true` — і гейт К-01 у
// `SummaryCheck` тут був no-op.
//
// Наслідок: контейнер із валідно підписаним `document.pdf` і додатковим
// НЕПІДПИСАНИМ `payload-not-signed.bin` приймався як валідний.
//
// Сестринський шлях `VerifyFileAsicEXades` цей інваріант має й він працює
// (аудит 2026-08-29 виміряв контраст на справжньому контейнері Дії: XAdES дав
// CONTAINER_COVERAGE_INCOMPLETE, CAdES — coverageComplete=true). Тест
// закріплює, що обидва шляхи тепер поводяться однаково.
void TestCadesAsicECoverageRejectsUnsignedEntry() {
#if TAMGA_CRYPTONITE_ENABLED
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestCadesAsicECoverageRejectsUnsignedEntry ---\n";

    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    Session session;
    ExpectTrue(PrepareInitializedSession(session),
               "Session should initialize for CAdES ASiC-E coverage test");
    ExpectSessionTrue(session,
        session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
        "ReadPrivateKeyBinary should load key for CAdES ASiC-E coverage test");

    const std::vector<std::uint8_t> doc = {'s', 'i', 'g', 'n', 'e', 'd'};
    std::vector<std::uint8_t> signature;
    ExpectSessionTrue(session, session.SignData(doc, signature, TimestampMode::Disabled),
                      "SignData should succeed for CAdES ASiC-E coverage test");

    // `extra_entry` != nullptr -> у контейнер кладеться додатковий файл, який
    // не згаданий у жодному маніфесті.
    auto build_and_verify = [&](const char* extra_entry, const char* label) {
        AsicEContent content;
        content.files.push_back({"document.pdf", doc});
        if (extra_entry != nullptr) {
            const std::vector<std::uint8_t> payload = {'u', 'n', 's', 'i', 'g', 'n', 'e', 'd'};
            content.files.push_back({extra_entry, payload});
        }

        AsicEContent::SignatureEntry se;
        se.sig_filename = "META-INF/signature1.p7s";
        se.signature_data = signature;
        se.manifest_filename = "META-INF/ASiCManifest1.xml";
        // Те саме, що вище: маніфест старого формату, digest-поля порожні
        // свідомо.
        se.manifest_xml = GenerateAsicManifestXml(
            se.sig_filename,
            {{"document.pdf", "application/octet-stream", /*digest_uri=*/"", /*digest_base64=*/""}});
        content.signatures.push_back(se);

        std::vector<std::uint8_t> container;
        std::string err;
        ExpectTrue(AsicEContainer::Pack(content, container, err),
                  (std::string(label) + ": AsicEContainer::Pack should succeed").c_str());

        const auto tmp_path = MakeTemporaryFixturePath(".cades-coverage.asice");
        ExpectTrue(WriteBinaryFile(tmp_path, container),
                  (std::string(label) + ": container should be written to disk").c_str());

        bool is_valid = false;
        ExpectSessionTrue(session, session.VerifyFileAsicE(tmp_path.string(), is_valid),
                          (std::string(label) + ": VerifyFileAsicE should succeed").c_str());

        std::string report;
        ExpectTrue(session.GetLastVerifyReport(report),
                  (std::string(label) + ": report should be readable").c_str());

        std::error_code ec;
        std::filesystem::remove(tmp_path, ec);
        return std::make_pair(is_valid, report);
    };

    // Позитивний контроль: без зайвого файлу контейнер лишається валідним.
    // Без цього тест був би зелений і на реалізації, що відхиляє все підряд.
    {
        const auto [is_valid, report] = build_and_verify(nullptr, "fully covered");
        ExpectTrue(is_valid, "fully covered CAdES ASiC-E container must stay valid");
        ExpectContains(report, "\"containerCoverageComplete\":true",
                       "fully covered container must report containerCoverageComplete=true");
        ExpectContains(report, "\"coverageStatus\":\"complete\"",
                       "fully covered container must report coverageStatus=complete");
    }

    // Власне дефект: непокритий файл у контейнері.
    {
        const auto [is_valid, report] = build_and_verify("payload-not-signed.bin", "unsigned entry");
        ExpectFalse(is_valid,
                    "CAdES ASiC-E container with an unsigned entry must NOT be reported valid");
        ExpectContains(report, "\"containerCoverageComplete\":false",
                       "unsigned entry must set containerCoverageComplete=false");
        ExpectContains(report, "\"coverageStatus\":\"container-object-not-signed\"",
                       "unsigned entry must set coverageStatus=container-object-not-signed");
        ExpectContains(report, "payload-not-signed.bin",
                       "report must name the uncovered entry");
        ExpectContains(report, "CONTAINER_COVERAGE_INCOMPLETE",
                       "summary must report CONTAINER_COVERAGE_INCOMPLETE");
    }
#else
    RecordSkip("Cryptonite not enabled");
#endif
}

// ME-03: same fail-closed ambiguity guard as VerifyFileAsicEXades (WP-7
// ME-05), now also applied to the legacy CAdES ASiC-E path.
void TestCadesAsicEAmbiguousNormalizedEntryNamesRejected() {
#if TAMGA_CRYPTONITE_ENABLED
    using namespace tamga::core;
    using namespace tamga::asic;
    std::cerr << "--- TestCadesAsicEAmbiguousNormalizedEntryNamesRejected ---\n";

    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for ambiguous CAdES ASiC-E test");
    ExpectSessionTrue(session,
        session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
        "ReadPrivateKeyBinary should load key for ambiguous CAdES ASiC-E test");

    const std::vector<std::uint8_t> doc = {'h', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> signature;
    ExpectSessionTrue(session, session.SignData(doc, signature, TimestampMode::Disabled),
                      "SignData should succeed for ambiguous CAdES ASiC-E test");

    AsicEContent content;
    content.files.push_back({"file.pdf", doc});
    content.files.push_back({"./file.pdf", doc});  // colliding normalized name

    AsicEContent::SignatureEntry se;
    se.sig_filename = "META-INF/signature1.p7s";
    se.signature_data = signature;
    se.manifest_filename = "META-INF/ASiCManifest1.xml";
    // Третє місце того самого класу: маніфест старого формату, digest-поля
    // порожні свідомо.
    se.manifest_xml = GenerateAsicManifestXml(
        se.sig_filename,
        {{"file.pdf", "application/octet-stream", /*digest_uri=*/"", /*digest_base64=*/""}});
    content.signatures.push_back(se);

    std::vector<std::uint8_t> container;
    std::string err;
    ExpectTrue(AsicEContainer::Pack(content, container, err),
              "AsicEContainer::Pack should succeed for ambiguous CAdES ASiC-E container");

    const auto tmp_path = MakeTemporaryFixturePath(".cades-ambiguous.asice");
    ExpectTrue(WriteBinaryFile(tmp_path, container), "ambiguous CAdES ASiC-E container should be written to disk");

    bool is_valid = true;
    // VerifyFileAsicE treats structural errors (missing/ambiguous data object)
    // the same way it already treats "missing data object" -- the call itself
    // succeeds (ok=true), but is_valid is reported false with a diagnostic
    // message. This differs from VerifyFileAsicEXades, which fails the call
    // outright for its own ambiguity guard.
    const bool ok = session.VerifyFileAsicE(tmp_path.string(), is_valid);
    ExpectTrue(ok, "VerifyFileAsicE call should still succeed while reporting the container invalid");
    ExpectFalse(is_valid, "ambiguous CAdES ASiC-E container must not be reported valid");

    std::string report;
    ExpectTrue(session.GetLastVerifyReport(report), "report should be readable after CAdES ASiC-E rejection");
    ExpectContains(report, "неоднозначні entry-імена", "report should explain the ambiguous-entry rejection");

    // Причина відмови мусить бути й у `GetError()`, а не лише у звіті. Доти
    // цей шлях викликав `ClearError()`, і 1С отримувала `Ложь` без пояснення,
    // хоча пояснення вже було в JSON. Сестринський XAdES-шлях повідомляв його
    // завжди — розходилися саме канали, якими користувач шукає причину.
    const auto last_error = session.GetLastError();
    ExpectTrue(last_error.code == ErrorCode::InvalidArgument,
               "structural CAdES ASiC-E rejection must leave InvalidArgument in the session error");
    ExpectTrue(last_error.message.find("неоднозначні entry-імена") != std::string::npos,
               "GetError() must explain WHY the container was rejected, not stay empty");

    // ADR-029: обидва шляхи ASiC-E тепер називають ту саму подію тим самим
    // кодом. Раніше CAdES давав SIGNATURE_INVALID («криптографія не
    // зійшлася» — до неї не дійшло), а XAdES — VERIFICATION_EXECUTION_FAILED
    // («не вдалося завершити» — звучить як збій інфраструктури й провокує
    // повтор спроби, безглуздий для поламаного файлу).
    ExpectContains(report, "\"code\":\"CONTAINER_MALFORMED\"",
                   "malformed container must get its own verdict on the CAdES path too");
    ExpectContains(report, "container-malformed",
                   "summaryCode must name the structural cause");

    std::error_code ec;
    std::filesystem::remove(tmp_path, ec);
#else
    RecordSkip("Cryptonite not enabled");
#endif
}
