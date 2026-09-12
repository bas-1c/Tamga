// П-13: namespace-aware класифікація профілю XAdES.
//
// Розділяємо два різні за наслідками випадки:
//   * пошук заради ВІДХИЛЕННЯ — ширше трактування (за локальною назвою)
//     робить перевірку СУВОРІШОЮ, тож звужувати його небезпечно;
//   * пошук заради КЛАСИФІКАЦІЇ (`format_profile`, поля LTV-доказів у звіті
//     для 1С) — там ширше трактування нічого не рятує: вузол із ЧУЖОГО
//     namespace може визначити профіль підпису. Саме це перевіряють тести.

#include <cstddef>
#include <cstdint>
#include <map>
#include <iostream>
#include <string>
#include <vector>

#include "core/CryptoniteAdapter.h"
#include "core/SignatureRequest.h"
#include "core/TspClient.h"
#include "xades/XadesBuilder.h"
#include "xades/XadesTypes.h"
#include "xades/XadesVerifier.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xmldsig/XmlTransformEngine.h"

#include "support/TestSupport.h"
#include "suites/Suites.h"

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

using namespace tamga_tests;

#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
namespace {

// Вставляє фрагмент усередину єдиного ds:Signature (перед закривним тегом).
// Вставка саме туди навмисна: enveloped-signature transform вилучає піддерево
// ds:Signature з дайджест-входу, тож підпис лишається криптографічно дійсним —
// і будь-яка зміна класифікації походить винятково від чужого вузла.
std::string InjectInsideSignature(const std::string& xml, const std::string& snippet) {
    const std::string close_tag = "</ds:Signature>";
    const auto pos = xml.rfind(close_tag);
    if (pos == std::string::npos) {
        return std::string{};
    }
    return xml.substr(0, pos) + snippet + xml.substr(pos);
}

// Мінімальний XAdES-BES для інʼєкційних сценаріїв.
bool BuildBesSignature(const DstuFixture& fixture,
                       tamga::xades::XadesBuilder& builder,
                       tamga::xmldsig::CanonicalizationMethod c14n,
                       const char* c14n_transform_uri,
                       std::string& signed_xml,
                       std::string& error) {
    tamga::xades::XadesParameters params;
    params.profile = tamga::xades::XadesProfile::BES;
    params.xml_params.signature_id = "sigNs";
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = c14n;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature", c14n_transform_uri};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    return builder.Sign("<Doc><Data>ns</Data></Doc>", params, key, signed_xml, error);
}

}  // namespace
#endif

// П-13 (головне): чужий namespace НЕ має визначати профіль XAdES і поля
// LTV-доказів у звіті. До виправлення `<evil:CompleteCertificateRefs/>` давав
// XAdES-C, `<evil:SignatureTimeStamp>` — XAdES-T, а
// `<evil:CertificateValues>`/`<evil:RevocationValues>` — ltvDataPresent=true.
void TestXadesProfileIgnoresForeignNamespaceProperties() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for XAdES foreign-namespace profile test");
    if (!fixture.valid) {
        return;
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesBuilder builder(crypto, tsp);
    tamga::xades::XadesVerifier verifier(xml_verifier, crypto, tsp);

    std::string signed_xml;
    std::string error;
    ExpectTrue(BuildBesSignature(fixture, builder, tamga::xmldsig::CanonicalizationMethod::C14N,
                                 "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", signed_xml, error),
               "XAdES-BES Sign for foreign-namespace profile test should succeed");

    // Санітарна база: без інʼєкції це B-B.
    tamga::xades::XadesVerificationResult base;
    ExpectTrue(verifier.Verify(signed_xml, base, error), "baseline XAdES Verify should run");
    ExpectTrue(base.signature_valid, "baseline XAdES-BES signature must be valid");
    ExpectTrue(base.format_profile == "XAdES-B-B", "baseline profile must be XAdES-B-B");

    const std::string evil_ns = " xmlns:evil=\"urn:x-tamga:not-xades\"";

    // 1) Чужий CompleteCertificateRefs не має піднімати профіль до XAdES-C.
    {
        const std::string injected = InjectInsideSignature(
            signed_xml, "<evil:Blob" + evil_ns + "><evil:CompleteCertificateRefs/></evil:Blob>");
        ExpectFalse(injected.empty(), "injection point </ds:Signature> must be found");
        tamga::xades::XadesVerificationResult r;
        ExpectTrue(verifier.Verify(injected, r, error), "Verify with foreign CompleteCertificateRefs should run");
        ExpectTrue(r.signature_valid, "foreign-namespace node must not break the signature itself");
        ExpectTrue(r.format_profile == "XAdES-B-B",
                   "P-13: evil:CompleteCertificateRefs must NOT classify the signature as XAdES-C");
        ExpectTrue(r.detected_profile == tamga::xades::XadesProfile::BES,
                   "P-13: detected_profile must stay BES for a foreign-namespace CompleteCertificateRefs");
        ExpectFalse(r.cert_refs_complete,
                    "P-13: cert_refs_complete must not be set by a foreign-namespace node");
    }

    // 2) Чужий SignatureTimeStamp не має піднімати профіль до XAdES-T.
    {
        const std::string injected = InjectInsideSignature(
            signed_xml,
            "<evil:Blob" + evil_ns +
                "><evil:SignatureTimeStamp><evil:EncapsulatedTimeStamp>AAAA"
                "</evil:EncapsulatedTimeStamp></evil:SignatureTimeStamp></evil:Blob>");
        ExpectFalse(injected.empty(), "injection point </ds:Signature> must be found");
        tamga::xades::XadesVerificationResult r;
        ExpectTrue(verifier.Verify(injected, r, error), "Verify with foreign SignatureTimeStamp should run");
        ExpectTrue(r.format_profile == "XAdES-B-B",
                   "P-13: evil:SignatureTimeStamp must NOT classify the signature as XAdES-T");
        ExpectFalse(r.signature_timestamp_present,
                    "P-13: signature_timestamp_present must not be set by a foreign-namespace node");
        ExpectTrue(r.timestamp_token_count == 0,
                   "P-13: foreign-namespace EncapsulatedTimeStamp must not be counted");
    }

    // 3) Чужі CertificateValues/RevocationValues не мають давати LTV-докази.
    {
        const std::string injected = InjectInsideSignature(
            signed_xml,
            "<evil:Blob" + evil_ns +
                "><evil:CertificateValues><evil:EncapsulatedX509Certificate>AAAA"
                "</evil:EncapsulatedX509Certificate></evil:CertificateValues>"
                "<evil:RevocationValues><evil:OCSPValues><evil:EncapsulatedOCSPValue>AAAA"
                "</evil:EncapsulatedOCSPValue></evil:OCSPValues></evil:RevocationValues></evil:Blob>");
        ExpectFalse(injected.empty(), "injection point </ds:Signature> must be found");
        tamga::xades::XadesVerificationResult r;
        ExpectTrue(verifier.Verify(injected, r, error), "Verify with foreign LTV values should run");
        ExpectFalse(r.certificate_values_present,
                    "P-13: evil:CertificateValues must not set certificate_values_present");
        ExpectFalse(r.revocation_values_present,
                    "P-13: evil:RevocationValues must not set revocation_values_present");
        ExpectFalse(r.ltv_data_present,
                    "P-13: foreign-namespace LTV values must not count as LTV evidence");
        ExpectTrue(r.certificate_values_count == 0,
                   "P-13: foreign-namespace EncapsulatedX509Certificate must not be counted");
        ExpectTrue(r.format_profile == "XAdES-B-B",
                   "P-13: foreign-namespace LTV values must not change the profile");
    }

    // 4) Чужий X509Certificate не має підмінювати сертифікат підписувача:
    // без ds:X509Certificate у власному KeyInfo підпис не має вважатися
    // дійсним (fail-closed), а не братися з чужого вузла.
    {
        std::string stripped = signed_xml;
        const std::string open_tag = "<ds:X509Certificate>";
        const std::string close_tag = "</ds:X509Certificate>";
        const auto open_pos = stripped.find(open_tag);
        const auto close_pos = stripped.find(close_tag);
        ExpectTrue(open_pos != std::string::npos && close_pos != std::string::npos,
                   "signed XML must carry ds:X509Certificate");
        if (open_pos != std::string::npos && close_pos != std::string::npos) {
            const std::size_t body = open_pos + open_tag.size();
            const std::string cert_b64 = stripped.substr(body, close_pos - body);
            stripped.erase(open_pos, close_pos + close_tag.size() - open_pos);
            const std::string injected = InjectInsideSignature(
                stripped, "<evil:Blob" + evil_ns + "><evil:X509Certificate>" + cert_b64 +
                              "</evil:X509Certificate></evil:Blob>");
            ExpectFalse(injected.empty(), "injection point </ds:Signature> must be found");
            tamga::xades::XadesVerificationResult r;
            std::string local_error;
            const bool executed = verifier.Verify(injected, r, local_error);
            ExpectFalse(executed && r.signature_valid,
                        "P-13: certificate from a foreign namespace must not make the signature valid");
        }
    }
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// П-13 (випадок 1, «пошук заради відхилення»): нормативні вузли DS у чужому
// namespace. Тут ширше трактування вже було СУВОРІШИМ — тест фіксує це як
// інваріант, щоб звуження namespace-перевірки випадково не відкрило обхід.
void TestXadesForeignNamespaceStructuralNodesRejected() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for foreign-namespace DS node test");
    if (!fixture.valid) {
        return;
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesBuilder builder(crypto, tsp);

    std::string signed_xml;
    std::string error;
    ExpectTrue(BuildBesSignature(fixture, builder, tamga::xmldsig::CanonicalizationMethod::C14N,
                                 "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", signed_xml, error),
               "XAdES-BES Sign for foreign-namespace DS node test should succeed");

    const std::string evil_ns = " xmlns:evil=\"urn:x-tamga:not-dsig\"";
    struct Case {
        const char* label;
        std::string snippet;
    };
    const Case cases[] = {
        {"evil:SignedInfo", "<evil:Blob" + evil_ns + "><evil:SignedInfo/></evil:Blob>"},
        {"evil:SignatureValue",
         "<evil:Blob" + evil_ns + "><evil:SignatureValue>AAAA</evil:SignatureValue></evil:Blob>"},
        {"evil:Reference+DigestValue",
         "<evil:Blob" + evil_ns +
             "><evil:Reference URI=\"\"><evil:DigestValue>AAAA</evil:DigestValue></evil:Reference></evil:Blob>"},
        {"evil:SignedProperties", "<evil:Blob" + evil_ns + "><evil:SignedProperties/></evil:Blob>"},
    };

    for (const Case& c : cases) {
        const std::string injected = InjectInsideSignature(signed_xml, c.snippet);
        ExpectFalse(injected.empty(), "injection point </ds:Signature> must be found");
        tamga::xmldsig::XmlSignatureVerificationResult r;
        std::string local_error;
        const bool executed = xml_verifier.Verify(injected, r, local_error);
        // Інваріант: чужий структурний вузол НЕ має давати «підпис дійсний»
        // із зіпсованими дайджестами. Прийнятні два наслідки: відмова розбору
        // (fail-closed) або дійсний підпис, у якому чужий вузол просто
        // проігноровано. Неприйнятно: чужий вузол став нормативним.
        if (executed && r.signature_valid) {
            std::cerr << "  [" << c.label << "] accepted as valid (foreign node ignored)\n";
        } else {
            std::cerr << "  [" << c.label << "] rejected: " << local_error << '\n';
        }
        ExpectTrue(!executed || !r.signature_valid || r.digest_valid,
                   "foreign structural node must not yield a valid signature with broken digests");
    }
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}

// П-13 (супутнє): позиційний XPath-скоуп підпису рахував ds:Signature ЗА
// ЛОКАЛЬНОЮ НАЗВОЮ, тоді як список верхньорівневих підписів збирається
// namespace-aware (`IsDsigElementNamed`). Через це `<evil:Signature>` перед
// справжнім ds:Signature зсував нумерацію: C14N ds:SignedInfo бралася з
// ЧУЖОГО елемента. Наслідок — SignatureValue звірявся з незміненою копією
// SignedInfo, тоді як реальний (підмінений) SignedInfo визначав, що саме
// перевіряється дайджестами.
void TestXmlDsigSignatureScopeIsNamespaceAware() {
#if TAMGA_CRYPTONITE_ENABLED && defined(TAMGA_XML_SIGNATURES_ENABLED)
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for namespace-aware signature scope test");
    if (!fixture.valid) {
        return;
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesBuilder builder(crypto, tsp);

    // Exclusive C14N — саме за нього копія SignedInfo поза ds:Signature дає
    // ТІ САМІ канонічні байти (невикористані xmlns відкидаються).
    std::string signed_xml;
    std::string error;
    ExpectTrue(BuildBesSignature(fixture, builder, tamga::xmldsig::CanonicalizationMethod::C14N_Exclusive,
                                 "http://www.w3.org/2001/10/xml-exc-c14n#", signed_xml, error),
               "XAdES-BES (exc-c14n) Sign for scope test should succeed");

    const std::string si_open = "<ds:SignedInfo>";
    const std::string si_close = "</ds:SignedInfo>";
    const auto si_begin = signed_xml.find(si_open);
    const auto si_end = signed_xml.find(si_close);
    ExpectTrue(si_begin != std::string::npos && si_end != std::string::npos,
               "signed XML must carry ds:SignedInfo");
    if (si_begin == std::string::npos || si_end == std::string::npos) {
        return;
    }
    const std::size_t inner_begin = si_begin + si_open.size();
    const std::string pristine_signed_info =
        std::string("<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">") +
        signed_xml.substr(inner_begin, si_end + si_close.size() - inner_begin);

    // Підміняємо перший ds:DigestValue у СПРАВЖНЬОМУ SignedInfo.
    std::string tampered = signed_xml;
    const std::string dv_open = "<ds:DigestValue>";
    const auto dv = tampered.find(dv_open);
    ExpectTrue(dv != std::string::npos && dv < si_end, "first ds:DigestValue must live inside ds:SignedInfo");
    if (dv == std::string::npos) {
        return;
    }
    const std::size_t dv_char = dv + dv_open.size();
    tampered[dv_char] = (tampered[dv_char] == 'A') ? 'B' : 'A';

    // Вставляємо чужий <evil:Signature> З КОПІЄЮ незміненого SignedInfo ПЕРЕД
    // справжнім ds:Signature.
    const auto sig_pos = tampered.find("<ds:Signature ");
    ExpectTrue(sig_pos != std::string::npos, "ds:Signature opening tag must be found");
    if (sig_pos == std::string::npos) {
        return;
    }
    const std::string attack =
        tampered.substr(0, sig_pos) +
        "<evil:Signature xmlns:evil=\"urn:x-tamga:not-dsig\">" + pristine_signed_info +
        "</evil:Signature>" + tampered.substr(sig_pos);

    std::map<std::string, std::vector<std::uint8_t>> no_external;
    std::vector<tamga::xmldsig::XmlSignatureVerificationResult> results;
    std::string local_error;
    const bool executed = xml_verifier.VerifyAll(attack, no_external, results, local_error);
    if (!executed) {
        std::cerr << "  scope-test: VerifyAll rejected the document: " << local_error << '\n';
        return;  // відмова — теж прийнятний (fail-closed) результат
    }
    ExpectTrue(results.size() == 1, "namespace-aware collection must see exactly one ds:Signature");
    if (results.size() != 1) {
        return;
    }
    ExpectFalse(results[0].signature_value_valid,
                "P-13: SignatureValue must not be checked against a SignedInfo copy from a foreign namespace");
    ExpectFalse(results[0].digest_valid, "sanity: tampered ds:DigestValue must break the reference digest");
#else
    std::cerr << "  (skipped: XML signatures or cryptonite not enabled)\n";
#endif
}
