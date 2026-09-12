#include "core/policy/TlXmlSigCheck.h"

#if defined(TAMGA_XML_SIGNATURES_ENABLED)
#include "core/CryptoniteAdapter.h"
#include "util/Base64.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xmldsig/XmlTransformEngine.h"
#include "xmldsig/detail/XmlDocUtil.h"

#include <algorithm>
#include <cctype>
#endif

namespace tamga::core::policy {

#if defined(TAMGA_XML_SIGNATURES_ENABLED)
namespace {

using namespace tamga::xmldsig::detail;

// Витягує DER сертифіката ПІДПИСАНТА — саме з ds:Signature/ds:KeyInfo.
//
// Раніше тут стояв FindFirstElement(root->children, "X509Certificate"), який
// шукає за локальним іменем по ВСЬОМУ документу. У довірчому списку ЦЗО
// `<X509Certificate>` без префікса трапляється 50 разів — це сертифікати
// довірчих послуг у тілі TSL, і перший із них лежить на зміщенні ~3 КБ, тоді як
// `ds:Signature` починається аж наприкінці файлу (~190 КБ).
//
// Тобто закріплений сертифікат ЦЗО порівнювався з ПЕРШИМ-ЛІПШИМ сертифікатом
// довірчої послуги, і перевірка pinned-cert не могла пройти НІКОЛИ — незалежно
// від того, наскільки правильний сертифікат передав користувач. Виявлено на
// справжньому сертифікаті підписанта TL, отриманому з czo.gov.ua; без нього
// дефект був невидимий, бо шлях просто ніколи не доходив до успіху.
std::vector<std::uint8_t> ExtractFirstX509CertDer(const std::string& xml) {
    std::string parse_error;
    XmlDocPtr doc = ParseHardened(xml, parse_error);
    if (!doc) return {};
    xmlNodePtr root = xmlDocGetRootElement(doc.get());
    if (!root) return {};
    // Спершу локалізуємо ds:Signature, і лише в ньому шукаємо сертифікат.
    xmlNodePtr signature = FindFirstElement(root->children, "Signature");
    if (!signature) return {};
    xmlNodePtr key_info = FindFirstElementInSubtree(signature, "KeyInfo");
    if (!key_info) return {};
    xmlNodePtr cert_node = FindFirstElementInSubtree(key_info, "X509Certificate");
    if (!cert_node) return {};
    xmlChar* content = xmlNodeGetContent(cert_node);
    if (!content) return {};
    std::string b64(reinterpret_cast<const char*>(content));
    xmlFree(content);
    b64.erase(
        std::remove_if(b64.begin(), b64.end(),
                       [](char c) { return std::isspace(static_cast<unsigned char>(c)); }),
        b64.end());
    std::vector<std::uint8_t> der;
    if (!tamga::util::Base64Decode(b64, der) || der.empty()) return {};
    return der;
}

}  // namespace
#endif  // TAMGA_XML_SIGNATURES_ENABLED

TlXmlSigCheckResult VerifyTlXmlSignature(
    const std::string& xml,
    const std::vector<std::uint8_t>& pinned_cert_der) {
    TlXmlSigCheckResult result;

#if defined(TAMGA_XML_SIGNATURES_ENABLED)
    if (xml.empty()) {
        result.error = "TL XML is empty";
        return result;
    }

    // Pinned-cert check: if a pinned cert is supplied, the cert in ds:KeyInfo
    // must match it exactly before the cryptographic verification runs.
    if (!pinned_cert_der.empty()) {
        const std::vector<std::uint8_t> embedded = ExtractFirstX509CertDer(xml);
        if (embedded.empty()) {
            result.error = "ds:KeyInfo/X509Certificate not found in TL XML";
            return result;
        }
        if (embedded != pinned_cert_der) {
            result.error = "TL XML signer certificate does not match the pinned certificate";
            return result;
        }
    }

    // Cryptographic signature verification.
    tamga::core::CryptoniteAdapter crypto;
    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::xmldsig::XmlSignatureVerifier verifier(canonicalizer, transform_engine,
                                                   digest_engine, crypto);

    tamga::xmldsig::XmlSignatureVerificationResult verify_result;
    std::string error_message;
    if (!verifier.Verify(xml, verify_result, error_message)) {
        result.error = error_message.empty() ? "TL XML signature verification error" : error_message;
        return result;
    }
    if (!verify_result.signature_valid) {
        // Алгоритм підпису недоступний у цій збірці — це прогалина, а не
        // невалідний підпис. Політика `PreferAvailable` тоді пропускає TL зі
        // статусом `not-verified-unsupported`, а `Require` обриває синхронізацію.
        // Без цього розрізнення діагностична збірка без vendored cryptonite
        // поза Windows відхиляла б кожен справжній TL ЦЗО як зламаний.
        result.not_supported = verify_result.signature_algorithm_unsupported;
        result.error = verify_result.signature_value_error.empty()
                           ? "TL XML signature is not valid"
                           : verify_result.signature_value_error;
        return result;
    }
    result.succeeded = true;
    return result;
#else
    (void)xml;
    (void)pinned_cert_der;
    result.not_supported = true;
    result.error = "TL XML signature verification requires TAMGA_ENABLE_XML_SIGNATURES";
    return result;
#endif
}

}  // namespace tamga::core::policy
