// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// PAdES: B/T/LT/LTA, інкрементальне підписання, ByteRange і граф обʼєктів.
// Тут закріплено К-01: підпис, що не покриває весь документ, робить
// документ невалідним, хай навіть криптографічно бездоганним.

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
#include <regex>
#include <set>
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
#include "core/session/PadesTimestampVerdict.h"
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

#if defined(TAMGA_PDF_SIGNATURES_ENABLED)
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFObjectHandle.hh>
#endif

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

#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_PDF_SIGNATURES_ENABLED)
namespace {

// Власна безпечна фікстура: ненульове покоління Catalog, метадані та форма
// не дозволяють зеленому тесту приховати втрату ідентичності об'єктів.
std::vector<std::uint8_t> MakePadesRevisionFixture() {
    const std::vector<std::pair<int, std::string>> objects{
        {0, "<< /Type /Pages /Kids [2 0 R] /Count 1 >>"},
        {0, "<< /Type /Page /Parent 1 0 R /MediaBox [0 0 200 200]"
            " /Resources << >> /Contents 3 0 R /Annots [8 0 R] >>"},
        {0, "<< /Length 4 >>\nstream\nq Q\nendstream"},
        {0, "<< /Title (Tamga revision fixture) /Author (Tamga tests) >>"},
        {3, "<< /Type /Catalog /Pages 1 0 R /AcroForm 7 0 R /Lang (uk-UA) >>"},
        {0, "<< /FT /Tx /T (ExistingField) /V (preserved) >>"},
        {0, "<< /Fields [6 0 R] /NeedAppearances false /DA (/Helv 0 Tf 0 g) >>"},
        {0, "<< /Type /Annot /Subtype /Text /Rect [10 10 20 20]"
            " /P 2 0 R /Contents (Existing annotation) >>"},
    };
    std::string pdf = "%PDF-1.7\n";
    std::vector<std::size_t> offsets;
    for (std::size_t i = 0; i < objects.size(); ++i) {
        offsets.push_back(pdf.size());
        pdf += std::to_string(i + 1) + " " + std::to_string(objects[i].first) +
               " obj\n" + objects[i].second + "\nendobj\n";
    }
    const auto xref = pdf.size();
    std::ostringstream tail;
    tail << "xref\n0 " << objects.size() + 1 << "\n0000000000 65535 f \n";
    for (std::size_t i = 0; i < objects.size(); ++i) {
        tail << std::setfill('0') << std::setw(10) << offsets[i] << ' '
             << std::setw(5) << objects[i].first << " n \n";
    }
    tail << "trailer\n<< /Size " << objects.size() + 1
         << " /Root 5 3 R /Info 4 0 R"
         << " /ID [<00112233445566778899aabbccddeeff>"
         << " <102132435465768798a9bacbdcedfe0f>] >>\n"
         << "startxref\n" << xref << "\n%%EOF\n";
    pdf += tail.str();
    return {pdf.begin(), pdf.end()};
}

struct PadesTestRevision {
    std::size_t xref{0};
    std::size_t end{0};
};

std::vector<PadesTestRevision> ReadPadesTestRevisions(const std::string& pdf) {
    // Пошук обмежений власною фікстурою та незжатими ревізіями будівника;
    // граф об'єктів і значення словників нижче незалежно розбирає qpdf.
    const std::regex ending("startxref\\s+([0-9]+)\\s+%%EOF(?:\\r?\\n)?");
    std::vector<PadesTestRevision> revisions;
    for (auto i = std::sregex_iterator(pdf.begin(), pdf.end(), ending);
         i != std::sregex_iterator(); ++i) {
        revisions.push_back({static_cast<std::size_t>(std::stoull((*i)[1].str())),
                             static_cast<std::size_t>(i->position() + i->length())});
    }
    return revisions;
}

void CheckPadesTestXref(const std::string& pdf, const PadesTestRevision& revision) {
    const bool points_to_xref = revision.xref < revision.end &&
                               pdf.compare(revision.xref, 4, "xref") == 0;
    ExpectTrue(points_to_xref, "PAdES revision startxref must point to its xref table");
    if (!points_to_xref) return;
    std::istringstream table(pdf.substr(revision.xref + 4, revision.end - revision.xref - 4));
    std::string first;
    while (table >> first && first != "trailer") {
        const int first_object = std::stoi(first);
        int count = 0;
        table >> count;
        for (int i = 0; i < count; ++i) {
            std::size_t offset = 0;
            int generation = 0;
            char state = 0;
            table >> offset >> generation >> state;
            ExpectTrue(static_cast<bool>(table), "PAdES xref entries must be complete");
            if (state == 'n') {
                const std::string header = std::to_string(first_object + i) + " " +
                                           std::to_string(generation) + " obj";
                ExpectTrue(offset < revision.xref && pdf.compare(offset, header.size(), header) == 0,
                           "PAdES xref must preserve each object number and generation");
            }
        }
    }
    ExpectTrue(first == "trailer", "PAdES xref table must end at a trailer");
}

void CheckPadesDecimalByteRanges(const std::string& pdf, std::size_t expected_count) {
    const std::regex byte_range("/ByteRange\\s*\\[([^\\]]*)\\]");
    std::size_t count = 0;
    for (auto i = std::sregex_iterator(pdf.begin(), pdf.end(), byte_range);
         i != std::sregex_iterator(); ++i) {
        ++count;
        std::istringstream numbers((*i)[1].str());
        std::string number;
        int number_count = 0;
        while (numbers >> number) {
            ++number_count;
            const bool decimal = std::all_of(number.begin(), number.end(), [](char c) {
                return c >= '0' && c <= '9';
            });
            ExpectTrue(decimal && (number.size() == 1 || number.front() != '0'),
                       "PAdES ByteRange must use decimal tokens without leading zeroes");
        }
        ExpectTrue(number_count == 4, "PAdES ByteRange must contain exactly four numbers");
    }
    ExpectTrue(count == expected_count, "PAdES must expose every expected ByteRange to lexical checks");
}

} // namespace
#endif

void TestPadesIncrementalRevisionStructure() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_PDF_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for PAdES revision structure");
    if (!fixture.valid) return;
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::pades::PadesBuilder builder(crypto, tsp);
    tamga::pades::PadesVerifier verifier(crypto, tsp);
    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";
    const auto original = MakePadesRevisionFixture();
    std::string error;
    // Цикл у дереві сторінок має давати контрольовану відмову, не виняток API.
    std::string cyclic_pdf(original.begin(), original.end());
    const auto kids_position = cyclic_pdf.find("/Kids [2 0 R]");
    ExpectTrue(kids_position != std::string::npos, "PAdES fixture must expose its page tree");
    if (kids_position != std::string::npos) {
        cyclic_pdf.replace(kids_position, 13, "/Kids [1 0 R]");
        std::vector<std::uint8_t> rejected;
        try {
            ExpectFalse(builder.SignPdf({}, {cyclic_pdf.begin(), cyclic_pdf.end()},
                                        key, rejected, error),
                        "PAdES must reject a cyclic page tree");
            ExpectTrue(rejected.empty(), "Rejected page tree must not produce a signed PDF");
        } catch (...) {
            ExpectTrue(false, "PAdES must not expose a page-tree parser exception to callers");
        }
    }
    // PAdES заявляє час у PDF /M, але звичайний CMS зберігає історичний
    // атрибут signingTime. Позитивний контроль також перевіряє сам extractor.
    std::vector<std::uint8_t> ordinary_cms;
    ExpectTrue(crypto.SignDetached(key.use_pkcs12, key.key_material, key.certificate_der,
                                  key.password, original, ordinary_cms, error),
               "Ordinary detached CMS signing must remain available");
    std::string ordinary_signing_time;
    ExpectTrue(crypto.ExtractSigningTime(ordinary_cms, ordinary_signing_time) &&
                   !ordinary_signing_time.empty(),
               "Ordinary detached CMS must retain its signingTime attribute");
    QPDF original_pdf;
    original_pdf.setAttemptRecovery(false);
    original_pdf.processMemoryFile("revision-fixture.pdf",
                                   reinterpret_cast<const char*>(original.data()), original.size());
    const auto original_root = original_pdf.getRoot().getObjGen();
    const auto original_info = original_pdf.getTrailer().getKey("/Info").getObjGen();
    const auto original_id = original_pdf.getTrailer().getKey("/ID").getArrayItem(0).getStringValue();
    const auto original_field = original_pdf.getRoot().getKey("/AcroForm")
                                    .getKey("/Fields").getArrayItem(0).getObjGen();
    const auto original_page = original_pdf.getAllPages().front().getObjGen();
    ExpectTrue(original_root.getObj() != 1 && original_root.getGen() != 0,
               "PAdES fixture must exercise a non-default Catalog object and generation");
    ExpectTrue(original_pdf.getWarnings().empty(), "PAdES revision fixture must parse without recovery warnings");

    std::vector<std::uint8_t> crl;
    ExpectTrue(GenerateGoodCrlForTest(fixture, crl, error), "PAdES revision fixture CRL must be generated");
    const std::regex pdf_date("D:[0-9]{14}(Z|[+-][0-9]{2}'[0-9]{2}')");
    const std::vector<tamga::pades::PadesProfile> profiles{
        tamga::pades::PadesProfile::B, tamga::pades::PadesProfile::T,
        tamga::pades::PadesProfile::LT, tamga::pades::PadesProfile::LTA};
    for (const auto profile : profiles) {
        const bool has_dss = profile >= tamga::pades::PadesProfile::LT;
        const bool has_document_timestamp = profile == tamga::pades::PadesProfile::LTA;
        tamga::pades::PadesParameters params;
        params.profile = profile;
        params.field_name = "ExistingField";
        params.timestamp_provider = [&fixture](const std::vector<std::uint8_t>& bytes,
                                               std::vector<std::uint8_t>& token, std::string& detail) {
            return MockTsaTimestamp(fixture, bytes, token, detail);
        };
        if (has_dss) {
            params.certificate_chain.push_back(fixture.cert_der);
            params.crls.push_back(crl);
        }
        std::vector<std::uint8_t> signed_pdf;
        const bool signed_ok = builder.SignPdf(params, original, key, signed_pdf, error);
        ExpectTrue(signed_ok, "PAdES revision structure signing must succeed");
        if (!signed_ok) {
            std::cerr << "  PAdES revision signing: " << error << '\n';
            continue;
        }
        ExpectTrue(signed_pdf.size() > original.size() &&
                       std::equal(original.begin(), original.end(), signed_pdf.begin()),
                   "PAdES must preserve every original byte");
        const std::string text(signed_pdf.begin(), signed_pdf.end());
        const auto revisions = ReadPadesTestRevisions(text);
        const std::size_t expected_revisions = has_document_timestamp ? 4U : (has_dss ? 3U : 2U);
        ExpectTrue(revisions.size() == expected_revisions,
                   "PAdES B/T adds one revision; LT adds signature+DSS; LTA adds signature+DSS+DocTimeStamp");
        CheckPadesDecimalByteRanges(text, has_document_timestamp ? 2U : 1U);
        std::set<std::string> revision_ids;
        for (std::size_t i = 0; i < revisions.size(); ++i) {
            CheckPadesTestXref(text, revisions[i]);
            QPDF revision;
            revision.setAttemptRecovery(false);
            revision.processMemoryFile("signed-revision.pdf", text.data(), revisions[i].end);
            auto root = revision.getRoot();
            auto trailer = revision.getTrailer();
            ExpectTrue(root.getObjGen() == original_root,
                       "PAdES every revision must retain the original Catalog object and generation");
            ExpectTrue(trailer.getKey("/Info").getObjGen() == original_info,
                       "PAdES every trailer must retain the original Info reference");
            ExpectTrue(trailer.getKey("/Info").getKey("/Title").getStringValue() == "Tamga revision fixture",
                       "PAdES document title must survive incremental signing");
            auto ids = trailer.getKey("/ID");
            const bool has_ids = ids.isArray() && ids.getArrayNItems() == 2;
            ExpectTrue(has_ids, "PAdES every trailer must retain both file identifiers");
            if (has_ids) {
                ExpectTrue(ids.getArrayItem(0).getStringValue() == original_id,
                           "PAdES first file identifier must remain stable");
                const auto second_id = ids.getArrayItem(1).getStringValue();
                ExpectTrue(!second_id.empty() && revision_ids.insert(second_id).second,
                           "PAdES second file identifier must change for each revision");
            }
            if (i > 0) {
                ExpectTrue(trailer.getKey("/Prev").isInteger() &&
                               trailer.getKey("/Prev").getIntValue() ==
                                   static_cast<long long>(revisions[i - 1].xref),
                           "PAdES Prev must point to the immediately preceding xref");
            }
            int max_object = 0;
            for (auto& object : revision.getAllObjects()) {
                max_object = std::max(max_object, object.getObjectID());
            }
            ExpectTrue(trailer.getKey("/Size").getIntValue() == static_cast<long long>(max_object) + 1,
                       "PAdES trailer Size must include all objects, including reused Catalog");
            ExpectTrue(root.getKey("/Lang").getStringValue() == "uk-UA",
                       "PAdES Catalog metadata must survive incremental signing");
            auto form = root.getKey("/AcroForm");
            auto fields = form.getKey("/Fields");
            ExpectTrue(fields.isArray() && fields.getArrayNItems() >= 1,
                       "PAdES must retain existing AcroForm fields");
            if (fields.isArray() && fields.getArrayNItems() >= 1) {
                ExpectTrue(fields.getArrayItem(0).getObjGen() == original_field &&
                               fields.getArrayItem(0).getKey("/V").getStringValue() == "preserved",
                           "PAdES existing field identity and value must remain unchanged");
            }
            ExpectTrue(form.getKey("/DA").getStringValue() == "/Helv 0 Tf 0 g",
                       "PAdES must retain AcroForm default appearance");
            const auto pages = revision.getAllPages();
            ExpectTrue(pages.size() == 1, "PAdES must retain the original page count");
            if (!pages.empty()) {
                auto page = pages.front();
                auto annotations = page.getKey("/Annots");
                ExpectTrue(page.getObjGen() == original_page && annotations.isArray() &&
                               annotations.getArrayNItems() == 1 &&
                               annotations.getArrayItem(0).getKey("/Contents").getStringValue() == "Existing annotation",
                           "PAdES must preserve existing page and annotation objects");
            }
            ExpectTrue(root.hasKey("/DSS") == (has_dss && i >= 2),
                       "PAdES DSS must first appear in a separate revision after the main signature");
            if (has_dss && i >= 2 && root.hasKey("/DSS")) {
                ExpectTrue(root.getKey("/DSS").getKey("/Type").getName() == "/DSS",
                           "PAdES validation store must have Type DSS");
            }
            ExpectTrue(revision.getWarnings().empty(), "PAdES every revision must parse without recovery warnings");
        }

        QPDF final_pdf;
        final_pdf.processMemoryFile("signed-final.pdf", text.data(), text.size());
        auto fields = final_pdf.getRoot().getKey("/AcroForm").getKey("/Fields");
        ExpectTrue(fields.getArrayNItems() == (has_document_timestamp ? 3 : 2),
                   "PAdES must append new fields without replacing a colliding existing field name");
        for (int i = 1; i < fields.getArrayNItems(); ++i) {
            auto widget = fields.getArrayItem(i);
            auto signature = widget.getKey("/V");
            ExpectTrue(widget.getKey("/P").getObjGen() == original_page,
                       "PAdES signature widget must reference the first page");
            ExpectTrue(std::regex_match(widget.getKey("/M").getStringValue(), pdf_date),
                       "PAdES signature widget must have a valid PDF modification date");
            auto rectangle = widget.getKey("/Rect");
            ExpectTrue(rectangle.isArray() && rectangle.getArrayNItems() == 4,
                       "PAdES signature widget must have a four-number rectangle");
            if (rectangle.isArray() && rectangle.getArrayNItems() == 4) {
                ExpectTrue(rectangle.getArrayItem(0).getNumericValue() == 0 &&
                               rectangle.getArrayItem(1).getNumericValue() == 0 &&
                               rectangle.getArrayItem(2).getNumericValue() == 50 &&
                               rectangle.getArrayItem(3).getNumericValue() == 50,
                           "PAdES signature widget rectangle must be 0 0 50 50");
            }
            ExpectTrue(widget.getKey("/T").getStringValue() != "ExistingField",
                       "PAdES signature field names must not collide with an existing field");
            if (signature.getKey("/Type").getName() == "/Sig") {
                ExpectTrue(std::regex_match(signature.getKey("/M").getStringValue(), pdf_date),
                           "PAdES main signature must have a valid PDF signing date");
                ExpectTrue(signature.getKey("/Reason").isString() &&
                               signature.getKey("/Reason").getStringValue().empty(),
                           "PAdES main signature must retain an explicit empty Reason");
            }
        }
        const auto signatures = tamga::pades::PdfParser::ExtractSignatureFields(signed_pdf);
        ExpectTrue(signatures.size() == (has_document_timestamp ? 2U : 1U),
                   "PAdES structural test must reach every actual signature field");
        for (const auto& signature : signatures) {
            const auto& range = signature.byte_range;
            const bool document_timestamp = signature.sub_filter == "ETSI.RFC3161";
            ExpectTrue(range.offset1 == 0, "PAdES ByteRange must start at the beginning of the file");
            const bool bounded_contents = range.length1 < range.offset2 &&
                                          range.offset2 <= signed_pdf.size();
            ExpectTrue(bounded_contents, "PAdES Contents exclusion must have in-bounds endpoints");
            if (bounded_contents) {
                ExpectTrue(signed_pdf[static_cast<std::size_t>(range.length1)] == '<' &&
                               signed_pdf[static_cast<std::size_t>(range.offset2 - 1)] == '>',
                           "PAdES ByteRange must exclude the complete Contents PDF string including angle brackets");
            }
            if (revisions.size() >= 2 && !document_timestamp) {
                ExpectTrue(range.offset2 + range.length2 == revisions[1].end,
                           "PAdES main signature must stop at its own revision before DSS");
            }
            if (document_timestamp && revisions.size() >= 4) {
                ExpectTrue(range.length1 >= revisions[2].end &&
                               range.offset2 + range.length2 == signed_pdf.size(),
                           "PAdES document timestamp must cover the complete preceding DSS revision");
            }
        }
        tamga::pades::PadesVerificationResult verified;
        ExpectTrue(verifier.VerifyPdf(signed_pdf, verified, error) && verified.signature_valid,
                   "PAdES structural fixes must preserve main CMS cryptographic integrity");
        ExpectFalse(verified.signer_cms_der.empty(),
                    "PAdES signingTime regression must inspect a real main CMS signature");
        std::string cms_signing_time;
        ExpectFalse(crypto.ExtractSigningTime(verified.signer_cms_der, cms_signing_time),
                    "PAdES CMS must omit signingTime; claimed signing time belongs only in PDF M");
        if (profile != tamga::pades::PadesProfile::B) {
            ExpectTrue(verified.timestamps_valid, "PAdES structural fixes must preserve mock timestamp integrity");
        }
    }
#endif
}

void TestPadesBSignVerifyRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_PDF_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for PAdES-B round-trip");
    if (!fixture.valid) {
        return;
    }
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::pades::PadesBuilder builder(crypto, tsp);
    tamga::pades::PadesVerifier verifier(crypto, tsp);

    tamga::pades::PadesParameters params;
    params.profile = tamga::pades::PadesProfile::B;
    params.reason = "Tamga test";

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    const std::vector<std::uint8_t> doc = MakeMinimalPdf("hello-pdf");
    std::vector<std::uint8_t> signed_pdf;
    std::string error;
    ExpectTrue(builder.SignPdf(params, doc, key, signed_pdf, error), "PAdES-B SignPdf should succeed");
    ExpectFalse(signed_pdf.empty(), "signed PDF must be non-empty");

    std::string pdf_error;
    ExpectTrue(tamga::pades::PdfParser::IsValidPdf(signed_pdf, pdf_error),
               "signed PDF must be well-formed for qpdf");

    tamga::pades::PadesVerificationResult result;
    ExpectTrue(verifier.VerifyPdf(signed_pdf, result, error), "PAdES-B VerifyPdf should run");
    ExpectTrue(result.byte_range_valid, "ByteRange must cover the document");
    ExpectTrue(result.signature_valid, "PAdES-B detached CMS must be valid");
    ExpectTrue(result.signature_count == 1, "PAdES-B must report exactly 1 main signature");

    // Підробка підписаного байта (у вмісті документа) має ламати підпис.
    std::vector<std::uint8_t> tampered = signed_pdf;
    const std::string text(tampered.begin(), tampered.end());
    const auto p = text.find("hello-pdf");
    if (p != std::string::npos) {
        tampered[p] = 'H';
        tamga::pades::PadesVerificationResult tampered_result;
        ExpectTrue(verifier.VerifyPdf(tampered, tampered_result, error),
                   "PAdES-B verify of tampered PDF should run");
        ExpectFalse(tampered_result.signature_valid, "tampered PAdES-B must be invalid");
    }
#else
    std::cerr << "  (skipped: PDF signatures or cryptonite not enabled)\n";
#endif
}

void TestPadesIncrementalSigningPreservesExistingPdf() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_PDF_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for PAdES incremental signing");
    if (!fixture.valid) return;

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::pades::PadesBuilder builder(crypto, tsp);
    tamga::pades::PadesVerifier verifier(crypto, tsp);
    tamga::pades::PadesParameters params;
    params.profile = tamga::pades::PadesProfile::B;

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    const std::vector<std::uint8_t> original = MakeMinimalPdf("incremental-original");
    std::vector<std::uint8_t> first;
    std::string error;
    ExpectTrue(builder.SignPdf(params, original, key, first, error),
               "first PAdES incremental signing should succeed");
    ExpectTrue(first.size() > original.size(), "first signing must append an incremental revision");
    ExpectTrue(std::equal(original.begin(), original.end(), first.begin()),
               "first signing must preserve the original PDF byte prefix");

    std::vector<std::uint8_t> second;
    ExpectTrue(builder.SignPdf(params, first, key, second, error),
               "second PAdES incremental signing should succeed");
    ExpectTrue(second.size() > first.size(), "second signing must append another revision");
    ExpectTrue(std::equal(first.begin(), first.end(), second.begin()),
               "co-signing must preserve the complete previous revision byte-for-byte");

    tamga::pades::PadesVerificationResult result;
    ExpectTrue(verifier.VerifyPdf(second, result, error),
               "verification of incrementally co-signed PDF should run");
    ExpectTrue(result.signature_valid, "both incremental PAdES signatures must remain valid");
    ExpectTrue(result.signature_count == 2,
               "incrementally co-signed PDF must report two main signatures");

    std::vector<std::uint8_t> not_pdf{'h', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> ignored;
    ExpectFalse(builder.SignPdf(params, not_pdf, key, ignored, error),
                "SignPdf must reject non-PDF input instead of wrapping arbitrary bytes");
#else
    std::cerr << "  (skipped: PDF signatures or cryptonite not enabled)\n";
#endif
}

void TestPadesByteRangeRejectsOverflow() {
#if defined(TAMGA_PDF_SIGNATURES_ENABLED)
    const std::vector<std::uint8_t> pdf = {'p', 'd', 'f'};
    tamga::pades::ByteRange malicious;
    malicious.offset1 = std::numeric_limits<std::uint64_t>::max();
    malicious.length1 = 1;
    malicious.offset2 = 0;
    malicious.length2 = std::numeric_limits<std::uint64_t>::max();
    const auto extracted = tamga::pades::PdfByteRange::ExtractSignedBytes(pdf, malicious);
    ExpectTrue(extracted.empty(),
               "malformed overflowing PAdES ByteRange must not produce out-of-bounds iterators");
#else
    std::cerr << "  (skipped: PDF signatures not enabled)\n";
#endif
}

void TestPadesTandLtaSignVerifyRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_PDF_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for PAdES-T/LTA round-trip");
    if (!fixture.valid) {
        return;
    }
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::pades::PadesBuilder builder(crypto, tsp);
    tamga::pades::PadesVerifier verifier(crypto, tsp);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    auto provider = [&fixture](const std::vector<std::uint8_t>& tbs,
                               std::vector<std::uint8_t>& token, std::string& err) {
        return MockTsaTimestamp(fixture, tbs, token, err);
    };
    const std::vector<std::uint8_t> doc = MakeMinimalPdf("pades-lta");

    // PAdES-T: вбудована signature-timestamp у CMS.
    {
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::T;
        params.timestamp_provider = provider;
        std::vector<std::uint8_t> signed_pdf;
        std::string error;
        ExpectTrue(builder.SignPdf(params, doc, key, signed_pdf, error), "PAdES-T SignPdf should succeed");
        tamga::pades::PadesVerificationResult result;
        ExpectTrue(verifier.VerifyPdf(signed_pdf, result, error), "PAdES-T VerifyPdf should run");
        ExpectTrue(result.signature_valid, "PAdES-T signature must be valid");
        ExpectTrue(result.timestamps_valid, "PAdES-T embedded timestamp must validate");
        ExpectTrue(result.detected_profile == tamga::pades::PadesProfile::T, "profile must be T");
    }

    // PAdES-LT: підпис T, а потім окрема ревізія з DSS.
    {
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::LT;
        params.timestamp_provider = provider;
        params.certificate_chain.push_back(fixture.cert_der);
        params.crls.push_back(fixture.cert_der);  // структурний revocation-блоб
        std::vector<std::uint8_t> signed_pdf;
        std::string error;
        ExpectTrue(builder.SignPdf(params, doc, key, signed_pdf, error), "PAdES-LT SignPdf should succeed");
        ExpectTrue(std::string(signed_pdf.begin(), signed_pdf.end()).find("/DSS") != std::string::npos,
                   "PAdES-LT must contain /DSS");

        tamga::pades::PadesVerificationResult result;
        ExpectTrue(verifier.VerifyPdf(signed_pdf, result, error), "PAdES-LT VerifyPdf should run");
        ExpectTrue(result.signature_valid, "PAdES-LT main signature must be valid");
        ExpectTrue(result.ltv_valid, "PAdES-LT DSS must be present");
        ExpectTrue(result.timestamps_valid, "PAdES-LT embedded timestamp must validate");
        ExpectTrue(result.detected_profile == tamga::pades::PadesProfile::LT, "profile must be LT");
    }

    // PAdES-LTA: LT + документний timestamp окремою інкрементальною секцією.
    {
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::LTA;
        params.timestamp_provider = provider;
        params.certificate_chain.push_back(fixture.cert_der);
        params.crls.push_back(fixture.cert_der);
        std::vector<std::uint8_t> signed_pdf;
        std::string error;
        ExpectTrue(builder.SignPdf(params, doc, key, signed_pdf, error), "PAdES-LTA SignPdf should succeed");
        const std::string s(signed_pdf.begin(), signed_pdf.end());
        ExpectTrue(s.find("/DSS") != std::string::npos, "PAdES-LTA must contain /DSS");
        ExpectTrue(s.find("DocTimeStamp") != std::string::npos, "PAdES-LTA must contain DocTimeStamp");

        tamga::pades::PadesVerificationResult result;
        ExpectTrue(verifier.VerifyPdf(signed_pdf, result, error), "PAdES-LTA VerifyPdf should run");
        ExpectTrue(result.signature_valid, "PAdES-LTA main signature must remain valid");
        ExpectTrue(result.ltv_valid, "PAdES-LTA DSS must be present");
        ExpectTrue(result.timestamps_valid, "PAdES-LTA timestamps (embedded + doc) must validate");
        ExpectTrue(result.detected_profile == tamga::pades::PadesProfile::LTA, "profile must be LTA");
        // F-002: DocTimeStamp (ETSI.RFC3161) не враховується як основний підпис.
        ExpectTrue(result.signature_count == 1, "PAdES-LTA must have 1 main signature; DocTimeStamp is separate");
    }
#else
    std::cerr << "  (skipped: PDF signatures or cryptonite not enabled)\n";
#endif
}

void TestSessionSignVerifyPdfRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_PDF_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for Session PAdES round-trip");
    if (!fixture.valid) {
        return;
    }
    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize");
    ExpectSessionTrue(session, session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test"),
                      "Session should load DSTU pkcs12 key");
    const std::vector<std::uint8_t> doc = MakeMinimalPdf("session-pdf");
    std::vector<std::uint8_t> signed_pdf;
    ExpectSessionTrue(session, session.SignPdf(doc, signed_pdf), "Session::SignPdf should succeed");
    bool is_valid = false;
    ExpectSessionTrue(session, session.VerifyPdf(signed_pdf, is_valid), "Session::VerifyPdf should run");
    ExpectTrue(is_valid, "Session PAdES round-trip must be valid");
#else
    std::cerr << "  (skipped: PDF signatures or cryptonite not enabled)\n";
#endif
}

void TestPhase7XadesPadesReport() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED) && defined(TAMGA_PDF_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for Phase 7 report");
    if (!fixture.valid) {
        return;
    }
    auto provider = [&fixture](const std::vector<std::uint8_t>& tbs,
                               std::vector<std::uint8_t>& token, std::string& err) {
        return MockTsaTimestamp(fixture, tbs, token, err);
    };
    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    // XAdES-T -> Session report.
    {
        tamga::core::CryptoniteAdapter crypto;
        tamga::core::TspClient tsp;
        tamga::xades::XadesBuilder builder(crypto, tsp);
        tamga::xades::XadesParameters params;
        params.profile = tamga::xades::XadesProfile::T;
        params.xml_params.signature_id = "p7";
        params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
        params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
        tamga::xmldsig::XmlReference ref;
        ref.uri = "";
        ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                          "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
        ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        params.xml_params.references.push_back(ref);
        params.timestamp_provider = provider;
        std::string signed_xml;
        std::string err;
        ExpectTrue(builder.Sign("<Doc><Data>p7</Data></Doc>", params, key, signed_xml, err),
                   "Phase7 XAdES-T sign");

        tamga::core::Session session;
        ExpectTrue(session.Initialize(), "session init (xades)");
        bool valid = false;
        ExpectSessionTrue(session, session.VerifyXml(signed_xml, valid), "Session VerifyXml");
        ExpectTrue(valid, "XAdES-T valid via Session");
        std::string json;
        ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport (xades)");
        ExpectContains(json, "\"format\":\"XAdES\"", "report exposes XAdES format");
        ExpectContains(json, "\"profile\":\"XAdES-T\"", "report exposes XAdES-T profile");
        // В-03: XAdES-T тут перевіряється без trust-матеріалу, тож
        // TimestampEngine не запускається і мітка лишається частковою.
        ExpectContains(json, "\"timestampStatus\":\"timestamp-partial\"",
                       "XAdES-T timestamp without TSA trust is partial, not valid");
        ExpectContains(json, "\"timestampChecked\":true", "timestamp was still checked");
        ExpectContains(json, "\"trustChecked\":true", "XAdES signer cert ran through trust path");
    }

    // PAdES-LTA -> Session report.
    {
        tamga::core::CryptoniteAdapter crypto;
        tamga::core::TspClient tsp;
        tamga::pades::PadesBuilder builder(crypto, tsp);
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::LTA;
        params.timestamp_provider = provider;
        params.certificate_chain.push_back(fixture.cert_der);
        params.crls.push_back(fixture.cert_der);
        std::vector<std::uint8_t> signed_pdf;
        std::string err;
        ExpectTrue(builder.SignPdf(params, MakeMinimalPdf("p7"), key, signed_pdf, err),
                   "Phase7 PAdES-LTA sign");

        tamga::core::Session session;
        ExpectTrue(session.Initialize(), "session init (pades)");
        bool valid = false;
        ExpectSessionTrue(session, session.VerifyPdf(signed_pdf, valid), "Session VerifyPdf");
        ExpectTrue(valid, "PAdES-LTA main signature valid via Session");
        std::string json;
        ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport (pades)");
        ExpectContains(json, "\"format\":\"PAdES\"", "report exposes PAdES format");
        ExpectContains(json, "\"profile\":\"PAdES-LTA\"", "report exposes PAdES-LTA profile");
        ExpectContains(json, "\"ltvValid\":true", "report exposes LTV");
        // В-03: PAdES не проганяє токен крізь TimestampEngine, тож повний
        // вердикт неможливий — чесний статус частковий.
        ExpectContains(json, "\"timestampStatus\":\"timestamp-partial\"",
                       "PAdES-LTA timestamp without TSA trust is partial, not valid");
        ExpectContains(json, "\"tspChecked\":true", "timestamp token was processed");
        ExpectContains(json, "\"trustChecked\":true", "PAdES signer cert ran through trust path");
        // HI-02: PAdES's structural ltv_valid (DSS + /Certs present) is NOT
        // gated on trust-chain confirmation (unlike XAdES's, see
        // TestSessionVerifyXmlLtvEvidenceSplitFields) -- so this is the
        // clean case demonstrating the gap the audit flagged: legacy
        // ltvValid=true for a self-signed, untrusted test fixture (no
        // work_dir/trust-anchor infra configured), while the new
        // evidenceValidated correctly reports false because trust/revocation
        // were never actually confirmed.
        ExpectContains(json, "\"trustValid\":false",
                       "sanity: self-signed test fixture without trust-anchor infra must be untrusted");
        ExpectContains(json, ",\"valid\":true,\"evidenceBound\":true,\"evidenceValidated\":false,\"fullyValidated\":false",
                       "HI-02: PAdES ltv block must keep legacy valid=true (unchanged contract) "
                       "while evidenceValidated correctly reports false for an untrusted chain");
        // Регресія: попри legacy ltvValid=true, публічний checks.ltv.code МАЄ
        // НЕ стверджувати LTV_VALID -- це й була прогалина audit-звіту.
        ExpectFalse(json.find("\"ltv\":{\"status\":\"valid\",\"code\":\"LTV_VALID\"") != std::string::npos,
                   "HI-02: PAdES checks.ltv must not claim LTV_VALID for an untrusted chain "
                   "despite legacy ltvValid=true");
    }
#else
    std::cerr << "  (skipped: XML+PDF signatures or cryptonite not enabled)\n";
#endif
}

// PAdES DSS/LTV binding: до цього фіксу PadesVerifier::VerifyPdf лише шукав
// підрядки "/DSS"/"/Certs" (жодного парсингу обʼєктного графа), а
// Session::VerifyPdf передавав ПОРОЖНІ {} замість DSS-сертифікатів/CRL/OCSP у
// RunFormatTrustValidationOn -- embedded evidence ніколи РЕАЛЬНО не бралось
// участь у trust/revocation-перевірці. Цей тест (мовою LO-01's
// TestSessionVerifyXmlLtvEvidenceValidatedTrustedPath, тут -- для PAdES)
// доводить, що DSS-вміст тепер СПРАВДІ дереференсується й використовується:
// генерує СПРАВЖНІЙ CRL (GenerateGoodCrlForTest), кладе його в PAdES-LT DSS
// (не placeholder-блоб, як в TestPadesTandLtaSignVerifyRoundTrip), і
// перевіряє, що revocationStatus дійсно стає "valid" -- це можливо лише
// якщо PdfParser::ParseDss дереференсував /CRLs і ці байти дійшли до
// ValidationEngine.
void TestSessionVerifyPdfLtvEvidenceValidatedTrustedPath() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_PDF_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    const auto tsa = GenerateDstuTsaFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for PAdES LTV trusted-path test");
    ExpectTrue(tsa.valid, "TSA з належним EKU для повного PAdES-LT");
    if (!fixture.valid || !tsa.valid) {
        return;
    }

    std::vector<std::uint8_t> good_crl_der;
    std::string crl_error;
    ExpectTrue(GenerateGoodCrlForTest(fixture, good_crl_der, crl_error),
              ("PAdES LTV test should generate a genuinely valid, signed CRL: " + crl_error).c_str());
    std::vector<std::uint8_t> tsa_crl;
    ExpectTrue(GenerateGoodCrlForTest(tsa, tsa_crl, crl_error), "Справжній CRL TSA має створюватися");

    const auto work_dir = MakeTemporaryFixturePath(".pades-ltv-trusted-path");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir / "trust-store", ec);
    std::filesystem::create_directories(work_dir / "tsa-store", ec);
    ExpectTrue(WriteBinaryFile(work_dir / "trust-store" / "fixture.cer", fixture.cert_der),
               "PAdES LTV test should write signer trust anchor");
    ExpectTrue(WriteBinaryFile(work_dir / "tsa-store" / "fixture.cer", tsa.cert_der),
               "PAdES-LT тест довіряє окремому TSA з належним EKU");

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::pades::PadesBuilder builder(crypto, tsp);
    tamga::pades::PadesParameters params;
    params.profile = tamga::pades::PadesProfile::LT;
    params.timestamp_provider = [&tsa](const std::vector<std::uint8_t>& tbs,
                                           std::vector<std::uint8_t>& token, std::string& err) {
        return MockTsaTimestamp(tsa, tbs, token, err);
    };
    params.certificate_chain.push_back(fixture.cert_der);
    params.certificate_chain.push_back(tsa.cert_der);
    // Справжній CRL (не placeholder-блоб, як в інших PAdES-тестах цього
    // файлу) -- потрібен саме для того, щоб RevocationEngine/CrlValidator
    // дійсно підтвердили відкликання ("valid"), а не впали на decode-помилці.
    params.crls.push_back(good_crl_der);
    params.crls.push_back(tsa_crl);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    const std::vector<std::uint8_t> doc = MakeMinimalPdf("pades-ltv");
    std::vector<std::uint8_t> signed_pdf;
    std::string error;
    ExpectTrue(builder.SignPdf(params, doc, key, signed_pdf, error), "PAdES-LT sign for LTV trusted-path test");

    tamga::core::Session session;
    tamga::core::Settings settings;
    settings.offline_mode = true;
    settings.work_dir = work_dir.string();
    ExpectTrue(session.SetSettings(settings), "PAdES LTV test should accept offline work_dir settings");
    ExpectTrue(session.Initialize(), "session init (PAdES LTV trusted-path)");
    bool valid = false;
    ExpectSessionTrue(session, session.VerifyPdf(signed_pdf, valid), "Session::VerifyPdf should run");
    std::string json;
    ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed");

    // Головна ціль тесту: доводить, що DSS /CRLs дійсно дереференсується
    // (PdfParser::ParseDss) і йде в RunFormatTrustValidationOn -- раніше
    // тут завжди передавались порожні {}, тож revocationStatus не міг
    // стати нічим, окрім "not-checked"/"invalid".
    ExpectContains(json, "\"revocationStatus\":\"valid\"",
                   "sanity: genuine DSS-embedded CRL must confirm revocation as valid, not invalid/not-checked");

    // Той самий "щасливий шлях" HI-02, тепер підтверджений і для PAdES.
    ExpectContains(json, ",\"evidenceBound\":true,\"evidenceValidated\":true,\"fullyValidated\":true",
                   "PAdES LTV binding: trusted anchor + confirmed DSS revocation must yield evidenceValidated=true");
    ExpectContains(json, "\"ltv\":{\"status\":\"valid\",\"code\":\"LTV_VALID\"",
                   "PAdES LTV binding: checks.ltv must report LTV_VALID when DSS evidence is bound and validated");

    std::filesystem::remove_all(work_dir, ec);
#else
    std::cerr << "  (skipped: PDF signatures or cryptonite not enabled)\n";
#endif
}

// S-005/F-002: PdfParser::ExtractSignatureFields витягує поля підпису через
// обʼєктний граф qpdf (а не пошуком підрядків), повертає правильний SubFilter
// і ByteRange, що покриває весь файл. Для LTA-PDF: основний підпис +
// DocTimeStamp (ETSI.RFC3161) — кожен класифікується окремо.
void TestPadesObjectGraphSignatureExtraction() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_PDF_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for object-graph sig extraction");
    if (!fixture.valid) return;

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::pades::PadesBuilder builder(crypto, tsp);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    // PAdES-B: один основний підпис.
    {
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::B;
        const std::vector<std::uint8_t> doc = MakeMinimalPdf("og-b");
        std::vector<std::uint8_t> signed_pdf;
        std::string err;
        ExpectTrue(builder.SignPdf(params, doc, key, signed_pdf, err), "PAdES-B for object-graph test");

        const auto fields = tamga::pades::PdfParser::ExtractSignatureFields(signed_pdf);
        ExpectTrue(fields.size() == 1, "PAdES-B: ExtractSignatureFields must return 1 field");
        if (!fields.empty()) {
            ExpectTrue(fields[0].sub_filter == "ETSI.CAdES.detached",
                       "PAdES-B SubFilter must identify the embedded CAdES signature");
            // S-005: перевірка покриття через offset2+length2==file_size
            const bool br_ok = (fields[0].byte_range.offset1 == 0) &&
                               (fields[0].byte_range.offset2 + fields[0].byte_range.length2 ==
                                static_cast<std::uint64_t>(signed_pdf.size()));
            ExpectTrue(br_ok, "PAdES-B ByteRange must start at 0 and end at file boundary");
            ExpectFalse(fields[0].signature.empty(), "PAdES-B /Contents must be non-empty");
        }
    }

    // PAdES-LTA: один основний підпис + один DocTimeStamp → 2 поля, різних класів.
    {
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::LTA;
        params.timestamp_provider = [&fixture](const std::vector<std::uint8_t>& tbs,
                                               std::vector<std::uint8_t>& token, std::string& err) {
            return MockTsaTimestamp(fixture, tbs, token, err);
        };
        params.certificate_chain.push_back(fixture.cert_der);
        params.crls.push_back(fixture.cert_der);
        const std::vector<std::uint8_t> doc = MakeMinimalPdf("og-lta");
        std::vector<std::uint8_t> signed_pdf;
        std::string err;
        ExpectTrue(builder.SignPdf(params, doc, key, signed_pdf, err), "PAdES-LTA for object-graph test");

        const auto fields = tamga::pades::PdfParser::ExtractSignatureFields(signed_pdf);
        ExpectTrue(fields.size() == 2, "PAdES-LTA: ExtractSignatureFields must return 2 fields");
        int main_count = 0, dts_count = 0;
        for (const auto& f : fields) {
            if (f.sub_filter == "ETSI.RFC3161") ++dts_count;
            else ++main_count;
        }
        ExpectTrue(main_count == 1, "PAdES-LTA: exactly 1 main signature field");
        ExpectTrue(dts_count == 1, "PAdES-LTA: exactly 1 DocTimeStamp field (ETSI.RFC3161)");
    }
#else
    std::cerr << "  (skipped: PDF signatures or cryptonite not enabled)\n";
#endif
}

void TestAsicEXadesEnabledDispatchDoesNotReturnNotSupported() {
#if defined(TAMGA_XML_SIGNATURES_ENABLED)
    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "session init (asic-e-xades dispatch)");

    bool valid = true;
    const bool ok = session.VerifyFileAsicEXades("missing-container.asice", valid);
    ExpectFalse(ok, "VerifyFileAsicEXades should reject a missing container");
    ExpectFalse(valid, "VerifyFileAsicEXades should clear validity on failure");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
               "XML-enabled VerifyFileAsicEXades should reach file validation, not NotSupported");
    ExpectFalse(session.GetLastError().message.find("XMLDSIG support requires building with TAMGA_ENABLE_XML_SIGNATURES") != std::string::npos,
                "XML-enabled VerifyFileAsicEXades should not report the XMLDSIG feature-flag error");

    std::string report;
    ExpectTrue(session.GetLastVerifyReport(report), "GetLastVerifyReport (asic-e-xades missing file)");
    ExpectContains(report, "\"operation\":\"VerifyFileAsicEXades\"", "report records ASiC-E XAdES operation");
    ExpectContains(report, "\"containerType\":\"ASiC-E\"", "report records ASiC-E container type");
    ExpectContains(report, "\"format\":\"XAdES\"", "report records XAdES signature format");
#else
    std::cerr << "  (skipped: XML signatures not enabled)\n";
#endif
}

// ПД-01: PAdES timestamp evidence доходить до КАНОНІЧНОГО TimestampEngine.
//
// Що було. `Session::VerifyPdf` передавав у `RunFormatTrustValidationOn`
// ПОРОЖНІЙ `cms_der` (SessionPdfOps.ipp, аргумент `{}`).
// `ValidationEngine::Validate` запускає `TimestampEngine` рівно тоді, коли
// `context.cms_der` непорожній (ValidationEngine.cpp:453), тож для PAdES
// `timestamp_attempted` НІКОЛИ не ставав true, проєкція давала
// "timestamp-not-validated", і `ApplyFormatTimestampVerdict` не мала чим
// підвищити крипто-результат: статус мітки назавжди лишався
// `timestamp-partial`. Труба була прокладена, доказ у неї не подавався.
//
// Що доводить тест — чотири випадки на тому самому механізмі:
//   1) PAdES-T + довірений mock-TSA (сертифікат у `tsa-store`, EKU
//      id-kp-timeStamping, власний CRL у `crl-store`) -> `timestamp-valid`.
//      САМЕ ЦЕ падало до зміни: було `timestamp-partial`.
//   2) той самий PDF без жодного trust-матеріалу -> `timestamp-partial`.
//      Доказ, що підвищення статусу дає канонічний рушій, а не сама лише
//      наявність байтів мітки (інакше це був би fail-open).
//   3) підроблена мітка (токен над ІНШИМИ байтами) при ПОВНОМУ trust-
//      матеріалі -> `timestamp-invalid`. Вердикт гірший, а не кращий.
//   4) PAdES-LTA: документна мітка (SubFilter ETSI.RFC3161) не лежить у CMS
//      взагалі, тож подається в той самий рушій явним входом
//      (`explicit_timestamp_token_der`) -> `timestamp-valid`.
void TestSessionVerifyPdfTimestampReachesCanonicalEngine() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_PDF_SIGNATURES_ENABLED)
    // Відтворюємо саме фінальний коміт Session: форматний результат
    // негативний, але наявні канонічні деталі позитивні. Друга незалежна
    // агрегація не має права скасувати форматну відмову.
    {
        tamga::core::VerifyReport report;
        tamga::core::TimestampEntry detail;
        detail.valid = true;
        detail.status = "timestamp-valid";
        report.timestamp_details.push_back(detail);
        tamga::core::pades_detail::ApplyPadesTimestampVerdict(report, false, true);
        ExpectTrue(!report.timestamp_valid && report.timestamp_status == "timestamp-invalid",
                   "PAdES: позитивні TSA details не скасовують негативний форматний результат");
        tamga::core::pades_detail::ApplyPadesTimestampVerdict(report, true, true);
        ExpectTrue(report.timestamp_valid && report.timestamp_status == "timestamp-valid",
                   "PAdES: форматно коректні мітки з позитивними details лишаються валідними");
        report.timestamp_details.front().valid = false;
        report.timestamp_details.front().status = "timestamp-invalid";
        tamga::core::pades_detail::ApplyPadesTimestampVerdict(report, true, true);
        ExpectTrue(!report.timestamp_valid && report.timestamp_status == "timestamp-invalid",
                   "PAdES: негативна окрема мітка зберігає пріоритет навіть за коректного формату");
    }
    const auto signer = GenerateDstuFixture();
    const auto tsa = GenerateDstuTsaFixture();
    ExpectTrue(signer.valid, "DSTU signer fixture for PAdES canonical-timestamp test");
    ExpectTrue(tsa.valid, "DSTU TSA fixture (with timestamping EKU) for PAdES canonical-timestamp test");
    if (!signer.valid || !tsa.valid) {
        return;
    }

    // Справжні (порожні, підписані) CRL: для TSA — щоб RevocationEngine мав
    // ВИЗНАЧЕНИЙ статус (профіль strict/standard вмикає revocation hard-fail,
    // тож "не перевірено" зупинило б мітку раніше за все інше); для підписанта
    // — щоб DSS ніс валідний доказ, а не структурний блоб.
    std::vector<std::uint8_t> tsa_crl;
    std::vector<std::uint8_t> signer_crl;
    std::string crl_error;
    ExpectTrue(GenerateGoodCrlForTest(tsa, tsa_crl, crl_error),
               ("mock TSA CRL should be generated: " + crl_error).c_str());
    ExpectTrue(GenerateGoodCrlForTest(signer, signer_crl, crl_error),
               ("signer CRL should be generated: " + crl_error).c_str());

    // Той самий TSA у наступному токені не може обходити перевірку часу
    // через кеш DER-сертифіката. Перевіряємо справжній production-колектор
    // офлайн, без PDF-транспорту й без іншого джерела CRL/OCSP.
    {
        std::time_t this_update{}, next_update{};
        const bool window = tamga::core::CryptoniteAdapter::GetCrlValidityWindow(
            tsa_crl, this_update, next_update);
        ExpectTrue(window && next_update > this_update, "CRL має придатне вікно для тесту повторного TSA");
        auto iso_time = [](std::time_t instant) {
            std::tm value{};
#ifdef _WIN32
            if (gmtime_s(&value, &instant) != 0) return std::string{};
#else
            if (gmtime_r(&instant, &value) == nullptr) return std::string{};
#endif
            char buffer[32]{};
            std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &value);
            return std::string(buffer);
        };
        if (window && next_update > this_update) {
            tamga::pades::PadesValidationEvidence evidence;
            evidence.crls = {tsa_crl};
            tamga::core::OcspSettings ocsp_settings;
            const std::vector<std::vector<std::uint8_t>> candidates{tsa.cert_der};
            const auto fresh = iso_time(this_update + 1);
            const auto stale = iso_time(next_update + 1);
            std::string error;
            auto collect = [&](const std::string& time) {
                return tamga::core::pades_detail::CollectPadesCertificateEvidence(
                    tsa.cert_der, candidates, candidates, {}, true, ocsp_settings, time, evidence, error);
            };
            ExpectTrue(collect(fresh), "Перший токен має використовувати чинний вбудований CRL");
            ExpectTrue(collect(fresh), "Повторний токен у тому самому вікні має повторно використовувати CRL");
            ExpectTrue(evidence.crls.size() == 1 && evidence.certificate_chain.size() == 1,
                       "Повторне використання не додає нових доказів і не запускає LTA-renewal");
            ExpectFalse(collect(stale),
                        "Той самий TSA після nextUpdate не може успадкувати попередній позитивний результат");
            ExpectTrue(collect(fresh), "Невдалий новий момент не псує чинний історичний доказ");
            ExpectFalse(collect("not-a-time"), "Некоректний час не має мовчки означати поточний");
        }
    }

    const auto work_dir = MakeTemporaryFixturePath(".pades-ts-canonical");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);
    std::filesystem::create_directories(work_dir / "trust-store", ec);
    std::filesystem::create_directories(work_dir / "tsa-store", ec);
    std::filesystem::create_directories(work_dir / "crl-store", ec);
    ExpectTrue(WriteBinaryFile(work_dir / "trust-store" / "signer.cer", signer.cert_der),
               "signer trust anchor should be written");
    ExpectTrue(WriteBinaryFile(work_dir / "tsa-store" / "mock-tsa.cer", tsa.cert_der),
               "mock TSA endpoint certificate should be written into tsa-store");
    ExpectTrue(WriteBinaryFile(work_dir / "crl-store" / "mock-tsa.crl", tsa_crl),
               "mock TSA CRL should be written into crl-store");

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::pades::PadesBuilder builder(crypto, tsp);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = signer.pkcs12_blob;
    key.certificate_der = signer.cert_der;
    key.password = "test";

    auto good_provider = [&tsa](const std::vector<std::uint8_t>& tbs,
                                std::vector<std::uint8_t>& token, std::string& err) {
        return MockTsaTimestamp(tsa, tbs, token, err);
    };
    // Підроблена мітка: коректно підписаний токен ТІЄЇ САМОЇ TSA, але над
    // іншими байтами — messageImprint не збігається з SignatureValue підпису.
    auto forged_provider = [&tsa](const std::vector<std::uint8_t>& tbs,
                                  std::vector<std::uint8_t>& token, std::string& err) {
        std::vector<std::uint8_t> other_bytes = tbs;
        other_bytes.push_back(0x2A);
        return MockTsaTimestamp(tsa, other_bytes, token, err);
    };

    const std::vector<std::uint8_t> doc = MakeMinimalPdf("pades-ts-canonical");

    auto verify_with = [&](const std::vector<std::uint8_t>& pdf, bool with_trust_material,
                           std::string& json_out) {
        tamga::core::Session session;
        tamga::core::Settings settings;
        settings.offline_mode = true;  // жодних мережевих TSP/OCSP/CRL-звернень
        if (with_trust_material) {
            settings.work_dir = work_dir.u8string();
        }
        ExpectTrue(session.SetSettings(settings), "session should accept offline settings");
        ExpectTrue(session.Initialize(), "session should initialize");
        bool is_valid = false;
        ExpectSessionTrue(session, session.VerifyPdf(pdf, is_valid), "Session::VerifyPdf should run");
        ExpectTrue(session.GetLastVerifyReport(json_out), "GetLastVerifyReport should succeed");
    };

    // --- 1) PAdES-T + довірений TSA -> повний вердикт ------------------------
    std::vector<std::uint8_t> pades_t;
    {
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::T;
        params.timestamp_provider = good_provider;
        std::string error;
        ExpectTrue(builder.SignPdf(params, doc, key, pades_t, error),
                   "PAdES-T should be signed for the canonical-timestamp test");

        std::string json;
        verify_with(pades_t, /*with_trust_material=*/true, json);
        ExpectContains(json, "\"timestamp\":{\"status\":\"valid\",\"code\":\"TIMESTAMP_VALID\"",
                       "ПД-01: signature timestamp evidence must reach the canonical TimestampEngine "
                       "and yield a full verdict (was permanently timestamp-partial while cms_der "
                       "was passed as empty)");
    }

    // --- 2) той самий PDF без trust-матеріалу -> лишається частковим ---------
    {
        std::string json;
        verify_with(pades_t, /*with_trust_material=*/false, json);
        ExpectContains(json, "\"timestampStatus\":\"timestamp-partial\"",
                       "ПД-01: without trust material the canonical engine must not confirm the TSA — "
                       "the status is raised by the engine's verdict, not by the mere presence of a token");
    }

    // Перший довірений timestamp не має приховувати TSA без належного EKU
    // у другому CMS: форматний криптографічний шар приймає обидва токени.
    {
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::T;
        params.timestamp_provider = [&signer](const std::vector<std::uint8_t>& tbs,
                                             std::vector<std::uint8_t>& token, std::string& error) {
            return MockTsaTimestamp(signer, tbs, token, error);
        };
        ExpectTrue(WriteBinaryFile(work_dir / "tsa-store" / "wrong-eku.cer", signer.cert_der),
                   "Другий TSA-кандидат має бути явно довіреним для перевірки саме EKU");
        ExpectTrue(WriteBinaryFile(work_dir / "crl-store" / "wrong-eku.crl", signer_crl),
                   "Доказ відкликання другого TSA має бути доступним");
        std::vector<std::uint8_t> cosigned;
        std::string error;
        ExpectTrue(builder.SignPdf(params, pades_t, key, cosigned, error),
                   "PDF з двома незалежними основними CMS має формуватися");
        tamga::pades::PadesVerifier verifier(crypto, tsp);
        tamga::pades::PadesVerificationResult parsed;
        ExpectTrue(verifier.VerifyPdf(cosigned, parsed, error), "Мультипідпис має розбиратися");
        ExpectTrue(parsed.signature_count == 2 && parsed.main_signatures.size() == 2,
                   "Канонічний шар має отримувати обидва CMS, не лише перший");
        ExpectTrue(parsed.timestamps_valid, "Обидва токени криптографічно правильні до перевірки EKU");
        std::string json;
        verify_with(cosigned, /*with_trust_material=*/true, json);
        ExpectContains(json, "\"timestamp\":{\"status\":\"invalid\",\"code\":\"TIMESTAMP_INVALID\"",
                       "Агрегований timestamp має бути негативним через другий TSA без EKU");
        ExpectContains(json, "\"index\":2,\"signatureValid\":true",
                       "Публічний звіт повинен показувати другого підписувача, а не лише першого");
        ExpectContains(json, "\"timestampStatus\":\"timestamp-valid\"",
                       "Незалежний позитивний результат першого TSA має лишитися в деталях");
    }

    // --- 3) підроблена мітка при повному trust-матеріалі -> ГІРШИЙ вердикт ---
    {
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::T;
        params.timestamp_provider = forged_provider;
        std::vector<std::uint8_t> forged_pdf;
        std::string error;
        ExpectTrue(builder.SignPdf(params, doc, key, forged_pdf, error),
                   "PAdES-T with a forged timestamp should still be produced");

        std::string json;
        verify_with(forged_pdf, /*with_trust_material=*/true, json);
        ExpectContains(json, "\"timestampStatus\":\"timestamp-invalid\"",
                       "fail-closed: a timestamp whose imprint does not match the signature must get a "
                       "WORSE verdict, never a better one, even with a fully trusted TSA");
        ExpectFalse(json.find("\"timestampStatus\":\"timestamp-valid\"") != std::string::npos,
                    "fail-closed: a forged timestamp must never be reported as valid");
    }

    // --- 4) PAdES-LTA: документна мітка часу через explicit-вхід -------------
    {
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::LTA;
        params.timestamp_provider = good_provider;
        params.certificate_chain.push_back(signer.cert_der);
        params.certificate_chain.push_back(tsa.cert_der);
        params.crls.push_back(signer_crl);
        params.crls.push_back(tsa_crl);
        std::vector<std::uint8_t> lta_pdf;
        std::string error;
        ExpectTrue(builder.SignPdf(params, doc, key, lta_pdf, error),
                   "PAdES-LTA should be signed for the canonical-timestamp test");

        std::string json;
        // Позитивний контроль DSS-only: CRL TSA є лише в PDF, не в локальному кеші.
        std::filesystem::remove(work_dir / "crl-store" / "mock-tsa.crl", ec);
        verify_with(lta_pdf, /*with_trust_material=*/true, json);
        ExpectContains(json, "\"profile\":\"PAdES-LTA\"",
                       "sanity: the LTA document must be detected as PAdES-LTA");
        ExpectContains(json, "\"timestamp\":{\"status\":\"valid\",\"code\":\"TIMESTAMP_VALID\"",
                       "ПД-01: the DocTimeStamp is not part of the signature CMS — it must reach the same "
                       "canonical engine through the explicit token input");
    }

    // Новий TSA у фактичній архівній відповіді потребує DSS+DocTimeStamp,
    // а не зміни вже підписаних байтів. Повторний токен того самого TSA
    // не є новим доказом і не має спричиняти нескінченне оновлення.
    {
        const auto archive_tsa = GenerateDstuTsaFixture();
        ExpectTrue(archive_tsa.valid, "Окремий TSA архівної мітки має створюватися");
        std::vector<std::uint8_t> archive_crl;
        ExpectTrue(GenerateGoodCrlForTest(archive_tsa, archive_crl, crl_error),
                   "CRL архівного TSA має створюватися");
        tamga::pades::PadesParameters params;
        params.profile = tamga::pades::PadesProfile::LTA;
        params.certificate_chain = {signer.cert_der};
        params.crls = {signer_crl};
        unsigned requests = 0;
        params.timestamp_provider = [&](const auto& bytes, auto& token, auto& error) {
            return MockTsaTimestamp(++requests == 1 ? tsa : archive_tsa, bytes, token, error);
        };
        unsigned collected_tokens = 0;
        params.timestamp_evidence_provider = [&](const auto& token, const auto& bytes,
                                                  tamga::pades::PadesValidationEvidence& evidence,
                                                  std::string& error) {
            ++collected_tokens;
            const auto checked = tamga::core::policy::ValidateTimestampToken(token, bytes);
            if (!checked.valid) { error = checked.message; return false; }
            evidence.certificate_chain = {checked.tsa_certificate_der};
            evidence.crls = {checked.tsa_certificate_der == tsa.cert_der ? tsa_crl : archive_crl};
            return true;
        };
        std::vector<std::uint8_t> renewed_pdf;
        std::string error;
        ExpectTrue(builder.SignPdf(params, doc, key, renewed_pdf, error),
                   "Заміна TSA має завершуватися обмеженим оновленням архівних доказів");
        ExpectTrue(requests == 3 && collected_tokens == 3,
                   "Потрібні лише основна мітка й дві архівні відповіді, без попередніх запитів");
        tamga::pades::PadesVerifier verifier(crypto, tsp);
        tamga::pades::PadesVerificationResult parsed;
        ExpectTrue(verifier.VerifyPdf(renewed_pdf, parsed, error), "Оновлений LTA має розбиратися");
        ExpectTrue(parsed.signature_valid && parsed.timestamps_valid && parsed.coverage_complete,
                   "Оновлення доказів не змінює попередні ByteRange і CMS");
        ExpectTrue(parsed.document_timestamp_tokens_der.size() == 2 &&
                       parsed.dss_certificates_der.size() == 3 && parsed.dss_crls_der.size() == 3,
                   "DSS повинен містити докази обох фактичних TSA та підписувача");
        const auto revisions = ReadPadesTestRevisions(std::string(renewed_pdf.begin(), renewed_pdf.end()));
        ExpectTrue(revisions.size() == 6,
                   "Новий архівний TSA додає рівно дві ревізії до звичних чотирьох із оригіналом");

        requests = 0;
        collected_tokens = 0;
        params.timestamp_provider = good_provider;
        params.timestamp_evidence_provider = [&](const auto&, const auto&,
                                                  tamga::pades::PadesValidationEvidence& evidence,
                                                  std::string&) {
            // Навмисно нестабільний тестовий постачальник доказів.
            evidence.ocsp_responses = {{0x30, 0x01, static_cast<std::uint8_t>(++collected_tokens)}};
            return true;
        };
        std::vector<std::uint8_t> unstable;
        ExpectFalse(builder.SignPdf(params, doc, key, unstable, error),
                    "Нескінченна зміна доказів TSA має завершуватися контрольованою відмовою");
        ExpectTrue(unstable.empty() && collected_tokens == 5,
                   "Ліміт — основний токен і максимум чотири архівні токени, без часткового PDF");
    }

    std::filesystem::remove_all(work_dir, ec);
#else
    std::cerr << "  (skipped: PDF signatures or cryptonite not enabled)\n";
#endif
}

// А-07: профіль PAdES тепер задається на точці входу. До цієї зміни
// `Session::SignPdf` жорстко ставив `PadesProfile::B`, хоча `PadesBuilder`
// реалізує T/LT/LTA — рушій умів більше за контракт.
//
// Тест закріплює насамперед FAIL-CLOSED частину, бо саме вона легко
// втрачається при подальших правках: якщо матеріалу для заявленого рівня
// немає, документ НЕ створюється і рівень НЕ понижується мовчки. PDF, що
// заявляє LT і не несе доказів валідації, — хибне твердження всередині
// підписаного документа, і виявить його вже перевіряльник.
void TestSessionSignPdfProfileSelection() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_PDF_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for Session PAdES profile selection");
    if (!fixture.valid) {
        return;
    }
    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize");
    ExpectSessionTrue(session, session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test"),
                      "Session should load DSTU pkcs12 key");

    const std::vector<std::uint8_t> doc = MakeMinimalPdf("profile-selection");

    // 1. Порожній профіль = B: історична двоаргументна форма не змінилася.
    std::vector<std::uint8_t> signed_default;
    ExpectSessionTrue(session, session.SignPdf(doc, signed_default),
                      "SignPdf without a profile must keep working (PAdES-B)");
    std::vector<std::uint8_t> signed_empty_profile;
    ExpectSessionTrue(session, session.SignPdf(doc, "", signed_empty_profile),
                      "An empty profile string must mean PAdES-B");

    // 2. Явний B у обох формах написання.
    std::vector<std::uint8_t> signed_b;
    ExpectSessionTrue(session, session.SignPdf(doc, "pades-b", signed_b),
                      "\"pades-b\" must be accepted");
    std::vector<std::uint8_t> signed_b_short;
    ExpectSessionTrue(session, session.SignPdf(doc, "B", signed_b_short),
                      "Short and upper-case profile names must be accepted");

    // 3. Невідомий профіль відхиляється, а не мовчки трактується як B.
    std::vector<std::uint8_t> ignored;
    ExpectFalse(session.SignPdf(doc, "pades-zzz", ignored),
                "An unknown PAdES profile must be rejected, not silently downgraded");
    ExpectTrue(ignored.empty(), "A rejected profile must not produce output bytes");

    // 4. Fail-closed: T і вище потребують TSA й онлайн-режиму. Сесія тут
    //    офлайн (типовий режим), тож обидва рівні мусять відмовити — і саме
    //    відмовити, а не видати документ рівнем нижче.
    std::vector<std::uint8_t> ignored_t;
    ExpectFalse(session.SignPdf(doc, "pades-t", ignored_t),
                "PAdES-T must refuse offline instead of emitting an untimestamped document");
    ExpectTrue(ignored_t.empty(), "A refused PAdES-T must not produce output bytes");

    std::vector<std::uint8_t> ignored_lt;
    ExpectFalse(session.SignPdf(doc, "pades-lt", ignored_lt),
                "PAdES-LT must refuse without validation material instead of emitting an empty /DSS");
    ExpectTrue(ignored_lt.empty(), "A refused PAdES-LT must not produce output bytes");

    std::vector<std::uint8_t> ignored_lta;
    ExpectFalse(session.SignPdf(doc, "pades-lta", ignored_lta),
                "PAdES-LTA must refuse without validation material");

    // 5. Відмова не псує сесію: наступний коректний виклик проходить.
    std::vector<std::uint8_t> signed_after_failures;
    ExpectSessionTrue(session, session.SignPdf(doc, "pades-b", signed_after_failures),
                      "A refused profile must leave the session usable");
#else
    std::cerr << "  (skipped: PDF signatures or cryptonite not enabled)\n";
#endif
}
