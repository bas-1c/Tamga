// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Внутрішні деталі XML-рушія: відображення URI на алгоритми дайджесту,
// канонікалізація, захист від XXE, конвеєр enveloped-посилань, нормалізація
// імен записів ASiC-E.

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

// Phase 1: XmlDigestEngine має зіставляти XMLDSIG DigestMethod URI з проєктним
// ImprintDigest і рахувати дайджест через ComputeImprint. SHA-256 доступний
// без cryptonite (чистий Sha256Helper), решта алгоритмів — лише зі збіркою
// cryptonite, тож перевіряємо їх під відповідним guard-ом.
void TestXmlDigestEngineUriMapping() {
    using tamga::xmldsig::XmlDigestEngine;
    using tamga::core::ImprintDigest;

    // Мапінг канонічних W3C URI.
    ExpectTrue(XmlDigestEngine::MapDigestUri("http://www.w3.org/2001/04/xmlenc#sha256")
                   == std::optional<ImprintDigest>(ImprintDigest::Sha256),
               "xmlenc#sha256 URI maps to Sha256");
    ExpectTrue(XmlDigestEngine::MapDigestUri("http://www.w3.org/2001/04/xmldsig-more#sha384")
                   == std::optional<ImprintDigest>(ImprintDigest::Sha384),
               "xmldsig-more#sha384 URI maps to Sha384");
    ExpectTrue(XmlDigestEngine::MapDigestUri("http://www.w3.org/2001/04/xmlenc#sha512")
                   == std::optional<ImprintDigest>(ImprintDigest::Sha512),
               "xmlenc#sha512 URI maps to Sha512");

    // Запасний шлях через ImprintFromDigestOid (bare-імена, у т.ч. українські).
    ExpectTrue(XmlDigestEngine::MapDigestUri("kupyna256")
                   == std::optional<ImprintDigest>(ImprintDigest::Kupyna256),
               "bare kupyna256 maps to Kupyna256");
    ExpectTrue(XmlDigestEngine::MapDigestUri("gost34311")
                   == std::optional<ImprintDigest>(ImprintDigest::Gost34311),
               "bare gost34311 maps to Gost34311");

    // SHA-1 свідомо не підтримується; невідомий URI також.
    ExpectFalse(XmlDigestEngine::MapDigestUri("http://www.w3.org/2000/09/xmldsig#sha1").has_value(),
                "legacy SHA-1 URI is unsupported");
    ExpectFalse(XmlDigestEngine::MapDigestUri("http://example.com/unknown").has_value(),
                "unknown URI does not map");

    // Обчислення SHA-256 збігається з еталонним Sha256Helper.
    XmlDigestEngine engine;
    const std::vector<std::uint8_t> data = {'a', 'b', 'c'};
    std::vector<std::uint8_t> digest;
    std::string error;
    const bool ok = engine.ComputeDigest(
        data, "http://www.w3.org/2001/04/xmlenc#sha256", digest, error);
    ExpectTrue(ok, "SHA-256 digest computation should succeed");
    const auto reference = tamga::core::policy::Sha256(data);
    ExpectTrue(digest.size() == reference.size()
                   && std::equal(digest.begin(), digest.end(), reference.begin()),
               "XmlDigestEngine SHA-256 must equal Sha256Helper output");

    // Невідомий URI -> false з повідомленням.
    std::vector<std::uint8_t> ignored;
    std::string bad_error;
    ExpectFalse(engine.ComputeDigest(data, "urn:bogus", ignored, bad_error),
                "unknown digest URI should fail");
    ExpectFalse(bad_error.empty(), "failure should report an error message");
}

#if defined(TAMGA_XMLSEC_CROSSCHECK_ENABLED)
// Q-013: XmlSecContext crosscheck (лише з TAMGA_ENABLE_XMLSEC_CROSSCHECK).

void TestXmlSecContextInitTeardown() {
    using tamga::xmldsig::XmlSecContext;
    // Вкладена ініціалізація та re-init після повного teardown не мають падати.
    {
        XmlSecContext a;
        XmlSecContext b;
    }
    {
        XmlSecContext c;
    }
    ExpectTrue(true, "XmlSecContext nested init/teardown should not throw");
}

#endif  // TAMGA_XMLSEC_CROSSCHECK_ENABLED

#if defined(TAMGA_XML_SIGNATURES_ENABLED)
// Phase 2: XMLDSIG-ядро на libxml2 (доступне лише за TAMGA_ENABLE_XML_SIGNATURES).

void TestXmlCanonicalizer() {
    using tamga::xmldsig::XmlCanonicalizer;
    using tamga::xmldsig::CanonicalizationMethod;
    XmlCanonicalizer c;
    std::string out;
    std::string err;

    // Інклюзивна C14N: атрибути сортуються, порожній елемент розкривається,
    // коментар вилучається.
    ExpectTrue(c.Canonicalize("<doc><!-- c --><e2 b=\"2\" a=\"1\"/></doc>",
                              CanonicalizationMethod::C14N, out, err),
               "C14N should succeed");
    ExpectTrue(out == "<doc><e2 a=\"1\" b=\"2\"></e2></doc>",
               "C14N must sort attributes, expand empty element and drop comment");

    // WithComments зберігає коментар.
    out.clear();
    err.clear();
    ExpectTrue(c.Canonicalize("<doc><!-- c --><e2 b=\"2\" a=\"1\"/></doc>",
                              CanonicalizationMethod::C14N_WithComments, out, err),
               "C14N#WithComments should succeed");
    ExpectTrue(out.find("<!-- c -->") != std::string::npos,
               "C14N#WithComments must preserve comments");

    // Некоректний XML -> false з повідомленням.
    out.clear();
    err.clear();
    ExpectFalse(c.Canonicalize("<broken", CanonicalizationMethod::C14N, out, err),
                "malformed XML should fail canonicalization");
    ExpectFalse(err.empty(), "canonicalization failure should report an error");
}

void TestXmlXxeHardening() {
#if defined(TAMGA_XML_SIGNATURES_ENABLED)
    using tamga::xmldsig::XmlCanonicalizer;
    using tamga::xmldsig::CanonicalizationMethod;
    XmlCanonicalizer c;
    std::string out;
    std::string err;
    // XXE-payload: зовнішня сутність на локальний файл. Hardening (без NOENT/
    // DTDLOAD, NONET) має НЕ резолвити її — вміст файлу не повинен потрапити
    // у канонічну форму.
    const std::string xxe =
        "<!DOCTYPE doc [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
        "<doc>&xxe;</doc>";
    const bool ok = c.Canonicalize(xxe, CanonicalizationMethod::C14N, out, err);
    // Незалежно від того, чи парсер прийняв документ, вміст /etc/passwd НЕ
    // повинен зʼявитися (XXE заблоковано).
    ExpectTrue(out.find("root:") == std::string::npos,
               "XXE: external entity content must not leak into C14N output");
    ExpectTrue(out.find("/bin/") == std::string::npos,
               "XXE: external file content must not be resolved");
    (void)ok;
#else
    std::cerr << "  (skipped: XML signatures not enabled)\n";
#endif
}

void TestXmlEnvelopedReferencePipeline() {
    using namespace tamga::xmldsig;
    static const char* kDoc =
        "<Doc Id=\"o1\"><Data>hello</Data>"
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        "<SignedInfo>"
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
        "<SignatureMethod Algorithm=\"urn:dstu\"/>"
        "<Reference URI=\"\">"
        "<Transforms>"
        "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
        "<Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>"
        "</Transforms>"
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
        "<DigestValue>placeholder</DigestValue>"
        "</Reference>"
        "</SignedInfo>"
        "<SignatureValue>AA==</SignatureValue>"
        "</Signature></Doc>";

    XmlReferenceResolver resolver;
    XmlTransformEngine transforms;
    XmlDigestEngine digest;
    std::string err;

    std::vector<XmlReference> refs;
    ExpectTrue(resolver.ExtractReferences(kDoc, refs, err), "ExtractReferences should succeed");
    ExpectTrue(refs.size() == 1, "document has exactly one ds:Reference");
    if (refs.size() != 1) {
        return;
    }
    const XmlReference& ref = refs[0];
    ExpectTrue(ref.uri.empty(), "enveloped reference URI is empty");
    ExpectTrue(ref.transforms.size() == 2, "reference declares two transforms");
    ExpectTrue(ref.digest_method == "http://www.w3.org/2001/04/xmlenc#sha256",
               "reference digest method is SHA-256");

    std::string resolved;
    ExpectTrue(resolver.ResolveReference(kDoc, ref, resolved, err),
               "ResolveReference (empty URI) should return whole document");

    std::string octets;
    ExpectTrue(transforms.ApplyTransforms(resolved, ref, octets, err),
               "ApplyTransforms (enveloped + C14N) should succeed");
    // enveloped вилучає ds:Signature, далі інклюзивна C14N.
    ExpectTrue(octets == "<Doc Id=\"o1\"><Data>hello</Data></Doc>",
               "enveloped + C14N must yield the canonical signed octets");

    std::vector<std::uint8_t> bytes(octets.begin(), octets.end());
    std::vector<std::uint8_t> computed;
    ExpectTrue(digest.ComputeDigest(bytes, ref.digest_method, computed, err),
               "digest over transformed octets should succeed");
    // Golden DigestValue (base64 SHA-256 канонічних октетів).
    ExpectTrue(tamga::util::Base64Encode(computed) == "KV3x55fmHjIVW02AEAU7FxKFOafxw6eWfbp7+rEZUgo=",
               "reference digest must match the golden SHA-256 value");
}

void TestXmlExternalReferenceKeepsRawOctetsWithoutTransforms() {
    using namespace tamga::xmldsig;
    XmlTransformEngine transforms;
    XmlReference ref;
    ref.uri = "invoice.xml";
    const std::string original = "<Invoice>\n  <Line amount=\"1.00\"></Line>\n</Invoice>";

    std::string octets;
    std::string err;
    ExpectTrue(transforms.ApplyTransforms(original, ref, octets, err),
               "external reference without transforms should be accepted as raw octets");
    ExpectTrue(octets == original,
               "external XML reference without transforms must not be canonicalized before digest");
}

#if defined(TAMGA_XML_SIGNATURES_ENABLED)
// WP-7 (ME-05): якщо ДВА різних ASiC-E entry-імені нормалізуються в один і
// той самий канонічний ключ (тут: "file.pdf" і "./file.pdf"), Session::
// VerifyFileAsicEXades має відхилити контейнер цілком (fail-closed) замість
// мовчазного вибору "останнього" запису — інакше атакуючий міг би приховати
// справжній підписаний файл під невизначеністю нормалізації.
void TestAsicEAmbiguousNormalizedEntryNamesRejected() {
    tamga::asic::AsicWriter writer(tamga::asic::AsicType::AsicE);
    const std::vector<std::uint8_t> doc = {'h', 'e', 'l', 'l', 'o'};
    const std::vector<std::uint8_t> sig_stub = {'x'};
    ExpectTrue(writer.AddFile("file.pdf", doc), "Add file.pdf to ambiguous ASiC-E container");
    ExpectTrue(writer.AddFile("./file.pdf", doc), "Add ./file.pdf (colliding normalized name)");
    ExpectTrue(writer.AddFile("META-INF/signatures1.xml", sig_stub), "Add stub signatures entry");

    std::vector<std::uint8_t> container;
    std::string err;
    ExpectTrue(writer.Finalize(container, err), "Finalize ambiguous ASiC-E container");

    const auto tmp_path = MakeTemporaryFixturePath(".ambiguous-asice-entries.asice");
    ExpectTrue(WriteBinaryFile(tmp_path, container), "Write ambiguous ASiC-E container to disk");

    tamga::core::Session session;
    ExpectTrue(session.Initialize(), "Session should initialize for ambiguous-entry test");
    bool is_valid = true;
    const bool ok = session.VerifyFileAsicEXades(tmp_path.string(), is_valid);
    // ADR-029: виклик тепер ВІДПРАЦЬОВУЄ і виносить вердикт, замість того щоб
    // завалитися. Доти цей шлях повертав false, а сестринський CAdES на ту саму
    // структурну ваду — true з is_valid=false. Два шляхи одного формату
    // розповідали про однакову подію по-різному, і жодна з двох назв не була
    // правдою: до криптографії не дійшло, а інфраструктура не збоїла.
    ExpectTrue(ok, "VerifyFileAsicEXades call executes and renders a verdict (ADR-029)");
    ExpectFalse(is_valid, "ambiguous container must not be reported valid");

    std::string report;
    ExpectTrue(session.GetLastVerifyReport(report), "report should be readable after rejection");
    ExpectContains(report, "неоднозначні entry-імена", "report should explain the ambiguous-entry rejection");
    ExpectContains(report, "\"code\":\"CONTAINER_MALFORMED\"",
                   "malformed container must get its own verdict, not SIGNATURE_INVALID");
    ExpectContains(report, "container-malformed",
                   "summaryCode must name the structural cause");

    std::error_code ec;
    std::filesystem::remove(tmp_path, ec);
}
#endif  // TAMGA_XML_SIGNATURES_ENABLED

void TestXmlExternalReferencePercentDecodedLookup() {
    using namespace tamga::xmldsig;
    XmlReferenceResolver resolver;
    XmlReference ref;
    ref.uri = "rahunok%202.pdf";

    const std::vector<std::uint8_t> payload = {'P', 'D', 'F'};
    const std::map<std::string, std::vector<std::uint8_t>> external_references = {
        {"rahunok 2.pdf", payload},
    };

    std::string resolved;
    std::string err;
    ExpectTrue(resolver.ResolveReference("<Signature/>", ref, external_references, resolved, err),
               "external reference URI should be percent-decoded before ASiC-E entry lookup");
    ExpectTrue(resolved == "PDF", "percent-decoded external reference should return mapped entry bytes");

    ref.uri = "%2e%2e/secret.pdf";
    ExpectFalse(resolver.ResolveReference("<Signature/>", ref, external_references, resolved, err),
                "percent-decoded traversal URI must be rejected");

    ref.uri = "file%3A///secret.pdf";
    ExpectFalse(resolver.ResolveReference("<Signature/>", ref, external_references, resolved, err),
                "percent-decoded file URI must be rejected");

    // WP-7 (ME-05): NormalizeAsicEntryUri тепер прибирає провідний "./" —
    // раніше це робив лише best-effort NormalizeCoverageUri (coverage-
    // перевірка), а НЕ фактичний резолвінг вмісту тут, тож
    // URI="./rahunok 2.pdf" міг пройти coverage-перевірку, але провалити
    // дайджест через "не знайдено ASiC-E entry".
    ref.uri = "./rahunok%202.pdf";
    ExpectTrue(resolver.ResolveReference("<Signature/>", ref, external_references, resolved, err),
               "leading './' in external reference URI must be stripped before ASiC-E entry lookup");
    ExpectTrue(resolved == "PDF", "'./'-prefixed external reference should resolve to the same entry");
}
#endif  // TAMGA_XML_SIGNATURES_ENABLED

// WP-7 (ME-05): пряме unit-покриття централізованого NormalizeAsicEntryUri —
// percent-decode, "./"-strip, помилка на некоректному percent-encoding. Не
// потребує TAMGA_XML_SIGNATURES_ENABLED (чиста функція над std::string).
void TestNormalizeAsicEntryUri() {
    std::string out;
    std::string error;

    ExpectTrue(tamga::util::NormalizeAsicEntryUri("rahunok%202.pdf", out, error),
               "NormalizeAsicEntryUri should decode a valid percent-encoded URI");
    ExpectTrue(out == "rahunok 2.pdf", "percent-decoded output should match the literal space");

    ExpectTrue(tamga::util::NormalizeAsicEntryUri("./rahunok2.pdf", out, error),
               "NormalizeAsicEntryUri should accept a './'-prefixed URI");
    ExpectTrue(out == "rahunok2.pdf", "leading './' must be stripped");

    ExpectTrue(tamga::util::NormalizeAsicEntryUri("./rahunok%202.pdf", out, error),
               "NormalizeAsicEntryUri should combine './'-strip and percent-decode");
    ExpectTrue(out == "rahunok 2.pdf", "combined './'-strip + percent-decode must match plain entry name");

    ExpectTrue(tamga::util::NormalizeAsicEntryUri("rahunok2.pdf", out, error),
               "NormalizeAsicEntryUri should pass through a plain name unchanged");
    ExpectTrue(out == "rahunok2.pdf", "plain name without './' or '%' must be returned as-is");

    ExpectFalse(tamga::util::NormalizeAsicEntryUri("bad%2", out, error),
                "NormalizeAsicEntryUri must reject truncated percent-encoding");
    ExpectFalse(tamga::util::NormalizeAsicEntryUri("bad%zz", out, error),
                "NormalizeAsicEntryUri must reject non-hex percent-encoding");
}
