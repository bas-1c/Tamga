#include "xmldsig/XmlSignatureVerifier.h"
#include "xmldsig/XmlHelpers.h"
#include "util/Hex.h"

#if defined(TAMGA_XML_SIGNATURES_ENABLED)

#include "core/CryptoniteAdapter.h"
#include "core/RsaVerifier.h"
#include "core/policy/ImprintDigest.h"
#include "util/Base64.h"
#include "xmldsig/XmlAlgorithmRegistry.h"
#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/detail/XmlDocUtil.h"

#include <cctype>
#include <iomanip>
#include <optional>
#include <sstream>

namespace tamga::xmldsig {

// ADR-027: HexEncode — одна реалізація в `util/Hex`.
using tamga::util::HexEncode;

namespace {

using namespace tamga::xmldsig::detail;

// B-3: SignatureMethod URI -> алгоритм гешу для RSASSA-PKCS1-v1_5.
// nullopt означає «це не RSA» — тоді працює звичайний шлях через cryptonite
// (ДСТУ 4145 / ECDSA). Порівнюємо саме хвіст URI, а не підрядок будь-де, щоб
// випадковий збіг у домені чи шляху не перемикав гілку перевірки.
std::optional<tamga::core::RsaHashAlg> MapRsaSignatureMethod(const std::string& uri) {
    const auto pos = uri.find_last_of("#/:");
    std::string tail = (pos == std::string::npos) ? uri : uri.substr(pos + 1);
    for (char& ch : tail) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    if (tail == "rsa-sha256") return tamga::core::RsaHashAlg::Sha256;
    if (tail == "rsa-sha384") return tamga::core::RsaHashAlg::Sha384;
    if (tail == "rsa-sha512") return tamga::core::RsaHashAlg::Sha512;
    return std::nullopt;
}



// ЗАВЖДИ викликається зі СПЕЦИФІЧНИМ ds:Signature-вузлом (не з коренем
// документа) — пошук має бути СТРОГО у власному піддереві цього підпису
// (FindFirstElementInSubtree), інакше для документа з кількома ds:Signature
// відсутність X509Certificate у ВЛАСНОМУ KeyInfo цього підпису могла б
// "просочитись" у сусідній ds:Signature і підмінити сертифікат, яким
// перевіряється SignatureValue цього підпису (WP-2, cross-contamination).
// П-13: сертифікат підписувача береться ЛИШЕ з `ds:X509Certificate`. Раніше
// збіг за самою локальною назвою дозволяв вузлу з чужого namespace
// (`evil:X509Certificate`) стати сертифікатом, яким звіряється SignatureValue
// і який далі йде у trust-валідацію як `signer_certificate_der`. Звуження тут
// fail-closed: без ds:X509Certificate підпис не звіряється взагалі.
bool ExtractEmbeddedCertificate(xmlNodePtr signature_scope_node, std::vector<std::uint8_t>& cert_der) {
    cert_der.clear();
    xmlNodePtr cert_node = FindFirstDsigElementInSubtree(signature_scope_node, "X509Certificate");
    return cert_node != nullptr && tamga::util::Base64Decode(TrimmedText(cert_node), cert_der) &&
           !cert_der.empty();
}

bool IsSignedPropertiesReference(const XmlReference& ref) {
    return ref.type.find("SignedProperties") != std::string::npos;
}

// Same-document "#id"-посилання (без xpointer) — кандидат на канонікалізацію
// безпосередньо у вихідному документі (без серіалізації/перепарсингу, що
// губить namespace-контекст, успадкований від елементів-предків).

// Чи складається ref.transforms щонайбільше з одного (C14N) перетворення —
// саме такий випадок коректно покриває новий шлях канонікалізації по Id.
// Для будь-якої іншої комбінації (enveloped-signature тощо) лишаємо старий
// resolve+transform шлях незмінним.

std::string LegacyReferenceStatus(const XmlReferenceVerificationDetail& detail) {
    std::string status = detail.status;
    if (!detail.uri.empty()) {
        status += ": " + detail.uri;
    }
    if (!detail.error.empty()) {
        status += " (" + detail.error + ")";
    }
    return status;
}

void FillDigestDiagnostics(XmlReferenceVerificationDetail& detail,
                           const std::vector<std::uint8_t>& expected,
                           const std::vector<std::uint8_t>& computed) {
    detail.expected_hex = HexEncode(expected);
    detail.computed_hex = HexEncode(computed);
    detail.computed_base64 = tamga::util::Base64Encode(computed);
}

// WP-2: повна перевірка ОДНОГО ds:Signature, прив'язана до
// signature_position_1based-го (1-based, порядок документа) верхньорівневого
// ds:Signature. Спільна логіка для XmlSignatureVerifier::Verify (виклик з
// position=1 після перевірки, що підпис рівно один) і ::VerifyAll (кілька
// підписів) — усі дайджести ds:Reference, канонікалізація SignedInfo, звірка
// криптографічного підпису через CryptoniteAdapter.
bool VerifySignatureAtPosition(xmlDocPtr doc_raw,
                               xmlNodePtr root,
                               xmlNodePtr signature_node,
                               int signature_position_1based,
                               const std::string& signed_xml,
                               const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                               XmlTransformEngine& transform_engine,
                               XmlDigestEngine& digest_engine,
                               XmlSignatureVerificationResult& result,
                               std::string& error_message) {
    result = XmlSignatureVerificationResult{};

    std::vector<std::uint8_t> cert_der;
    if (ExtractEmbeddedCertificate(signature_node, cert_der)) {
        result.signing_cert_id = "embedded-x509";
    } else {
        result.signing_cert_id = "(no certificate in KeyInfo)";
    }

    // 1. Перевірка дайджестів усіх ds:Reference цього конкретного підпису.
    XmlReferenceResolver resolver;
    std::vector<XmlReference> refs;
    if (!resolver.ExtractReferencesForSignature(signed_xml, signature_position_1based, refs, error_message)) {
        return false;
    }

    bool all_digests = true;
    for (const XmlReference& ref : refs) {
        XmlReferenceVerificationDetail detail;
        detail.uri = ref.uri;
        detail.type = ref.type;
        detail.digest_method = ref.digest_method;
        detail.expected_base64 = ref.digest_value_base64;

        std::vector<std::uint8_t> expected;
        if (!tamga::util::Base64Decode(ref.digest_value_base64, expected)) {
            all_digests = false;
            detail.status = "digest-failed";
            detail.error = "invalid DigestValue base64";
            result.reference_statuses.push_back(LegacyReferenceStatus(detail));
            result.reference_details.push_back(std::move(detail));
            continue;
        }
        detail.expected_hex = HexEncode(expected);

        // Same-document Id-фрагмент має бути унікальним ГЛОБАЛЬНО (по всьому
        // документу, не лише в межах цього підпису) — інакше інший підпис
        // міг би посилатись на той самий Id (класичний XSW).
        std::string id_fragment;
        if (IsIdFragmentUri(ref.uri, id_fragment) &&
            CountElementsById(root, id_fragment) != 1) {
            all_digests = false;
            detail.status = "resolve-failed";
            detail.error = "duplicate or missing Id for referenced fragment";
            result.reference_statuses.push_back(LegacyReferenceStatus(detail));
            result.reference_details.push_back(std::move(detail));
            continue;
        }

        std::string err;
        std::string octets;
        std::string fragment;
        if (IsIdFragmentUri(ref.uri, fragment) && IsCanonicalizationOnlyTransform(ref.transforms)) {
            int ref_mode = XML_C14N_1_0;
            int ref_comments = 0;
            if (!ref.transforms.empty()) {
                C14nUriToMode(ref.transforms.front(), ref_mode, ref_comments);
            }
            if (!CanonicalizeSubtreeById(doc_raw, fragment, ref_mode, ref_comments, octets, err)) {
                all_digests = false;
                detail.status = "transform-failed";
                detail.error = err;
                result.reference_statuses.push_back(LegacyReferenceStatus(detail));
                result.reference_details.push_back(std::move(detail));
                continue;
            }
        } else {
            std::string resolved;
            if (!resolver.ResolveReference(signed_xml, ref, external_references, resolved, err)) {
                all_digests = false;
                detail.status = "resolve-failed";
                detail.error = err;
                result.reference_statuses.push_back(LegacyReferenceStatus(detail));
                result.reference_details.push_back(std::move(detail));
                continue;
            }

            if (!transform_engine.ApplyTransforms(resolved, ref, octets, err)) {
                all_digests = false;
                detail.status = "transform-failed";
                detail.error = err;
                result.reference_statuses.push_back(LegacyReferenceStatus(detail));
                result.reference_details.push_back(std::move(detail));
                continue;
            }
        }

        std::vector<std::uint8_t> bytes(octets.begin(), octets.end());
        std::vector<std::uint8_t> digest;
        if (!digest_engine.ComputeDigestByCertificate(bytes, ref.digest_method, cert_der, digest, err)) {
            all_digests = false;
            detail.status = "digest-failed";
            detail.error = err;
            result.reference_statuses.push_back(LegacyReferenceStatus(detail));
            result.reference_details.push_back(std::move(detail));
            continue;
        }

        FillDigestDiagnostics(detail, expected, digest);
        if (IsSignedPropertiesReference(ref)) {
            result.signed_properties_canonicalized_length = bytes.size();
            result.signed_properties_hash_hex = detail.computed_hex;
            result.signed_properties_hash_base64 = detail.computed_base64;
        }

        if (digest != expected) {
            all_digests = false;
            detail.status = "mismatch";
            detail.error = "computed digest does not match DigestValue";
            result.reference_statuses.push_back(LegacyReferenceStatus(detail));
            result.reference_details.push_back(std::move(detail));
            continue;
        }

        detail.status = "ok";
        result.reference_statuses.push_back(LegacyReferenceStatus(detail));
        result.reference_details.push_back(std::move(detail));
    }
    result.digest_valid = all_digests;

    // Без вбудованого сертифіката підпис звірити нічим — виходимо ДО
    // канонікалізації SignedInfo/обчислення imprint, щоб не витрачати роботу
    // на дані, які однаково не будуть використані для звірки підпису.
    if (cert_der.empty()) {
        result.signature_valid = false;
        result.signature_value_valid = false;
        result.signature_value_error = "no certificate in KeyInfo";
        return true;
    }

    // 2. Канонікалізація SignedInfo (у межах цього конкретного підпису) і
    // звірка підпису.
    xmlNodePtr signed_info = FindFirstElementInSubtree(signature_node, "SignedInfo");
    if (signed_info == nullptr) {
        error_message = "Не знайдено ds:SignedInfo";
        return false;
    }

    int mode = XML_C14N_1_0;
    int comments = 0;
    if (xmlNodePtr cm = FindFirstElement(signed_info->children, "CanonicalizationMethod")) {
        C14nUriToMode(GetAttr(cm, "Algorithm"), mode, comments);
    }
    std::string signed_info_octets;
    if (!CanonicalizeSubtreeWithinSignature(doc_raw, signature_position_1based, "SignedInfo", mode, comments,
                                            signed_info_octets, error_message)) {
        return false;
    }

    xmlNodePtr sm = FindFirstElement(signed_info->children, "SignatureMethod");
    if (sm == nullptr) {
        error_message = "Не знайдено ds:SignatureMethod у ds:SignedInfo";
        return false;
    }
    const std::string sm_uri = GetAttr(sm, "Algorithm");
    const auto si_alg = XmlDigestEngine::MapSignatureMethodUri(sm_uri);
    if (!si_alg) {
        error_message = "Непідтримуваний SignatureMethod URI: " + sm_uri;
        return false;
    }

    // B-3: RSASSA-PKCS1-v1_5 (rsa-sha256/384/512) — окрема гілка вибору
    // алгоритму. На Windows її виконує незмінний CNG backend, поза Windows —
    // RSA-capable PKIX VerifyAdapter vendored cryptonite.
    const auto rsa_hash = MapRsaSignatureMethod(sm_uri);

    tamga::core::ImprintResult imprint;
    const std::vector<std::uint8_t> si_bytes(signed_info_octets.begin(), signed_info_octets.end());
    result.signed_info_canonicalized_length = si_bytes.size();
    if (rsa_hash) {
        // Для RSA дайджест визначено самим SignatureMethod і НЕ параметризується
        // сертифікатом (на відміну від ГОСТ 34.311, де sbox/sync беруться звідти).
        if (!tamga::core::ComputeImprint(*si_alg, si_bytes, imprint, error_message)) {
            return false;
        }
    } else if (!tamga::core::ComputeImprintByCertificate(cert_der, *si_alg, si_bytes, imprint, error_message)) {
        return false;
    }
    result.signed_info_hash_hex = HexEncode(imprint.hash);
    result.signed_info_hash_base64 = tamga::util::Base64Encode(imprint.hash);

    if (result.signed_properties_canonicalized_length == 0 &&
        CountElementsInSubtree(signature_node, "SignedProperties") == 1) {
        std::string signed_props_octets;
        std::string signed_props_error;
        if (CanonicalizeSubtreeWithinSignature(doc_raw, signature_position_1based, "SignedProperties", mode,
                                               comments, signed_props_octets, signed_props_error)) {
            std::vector<std::uint8_t> signed_props_bytes(signed_props_octets.begin(), signed_props_octets.end());
            std::vector<std::uint8_t> signed_props_hash;
            if (digest_engine.ComputeDigestByCertificate(signed_props_bytes, sm_uri, cert_der,
                                                          signed_props_hash, signed_props_error)) {
                result.signed_properties_canonicalized_length = signed_props_bytes.size();
                result.signed_properties_hash_hex = HexEncode(signed_props_hash);
                result.signed_properties_hash_base64 = tamga::util::Base64Encode(signed_props_hash);
            }
        }
    }

    xmlNodePtr sv = FindFirstElementInSubtree(signature_node, "SignatureValue");
    std::vector<std::uint8_t> signature;
    if (sv == nullptr || !tamga::util::Base64Decode(TrimmedText(sv), signature)) {
        result.signature_value_valid = false;
        result.signature_value_error = "Відсутнє або некоректне ds:SignatureValue";
        error_message = result.signature_value_error;
        return false;
    }

    if (rsa_hash) {
        const auto rsa = tamga::core::VerifyRsaPkcs1(cert_der, *rsa_hash, imprint.hash, signature);
        if (!rsa.executed) {
            // Не змогли перевірити — це НЕ «підпис валідний», але й НЕ «підпис
            // невалідний». Позначаємо саме як непідтримуваний алгоритм: це
            // лишається потрібним для діагностичної збірки vendor=OFF.
            result.signature_valid = false;
            result.signature_value_valid = false;
            result.signature_algorithm_unsupported = true;
            result.signature_value_error =
                rsa.message.empty() ? "RSA signature verification could not be performed" : rsa.message;
            error_message = result.signature_value_error;
            return true;
        }
        result.signature_valid = rsa.valid;
        result.signature_value_valid = rsa.valid;
        if (!rsa.valid) {
            result.signature_value_error =
                rsa.message.empty() ? "RSA signature does not match" : rsa.message;
        }
        return true;
    }

    bool is_valid = false;
    std::string verify_error;
    if (!tamga::core::CryptoniteAdapter::VerifyHash(cert_der, imprint.hash, signature,
                                                    is_valid, verify_error)) {
        result.signature_valid = false;
        result.signature_value_valid = false;
        result.signature_value_error = verify_error;
        error_message = verify_error;
        return true;  // обробка відбулась; підпис вважаємо невалідним
    }
    result.signature_valid = is_valid;
    result.signature_value_valid = is_valid;
    if (!is_valid) {
        result.signature_value_error = verify_error.empty() ? "VerifyHash returned invalid signature" : verify_error;
    }
    return true;
}

}  // namespace

XmlSignatureVerifier::XmlSignatureVerifier(XmlCanonicalizer& canonicalizer,
                                           XmlTransformEngine& transform_engine,
                                           XmlDigestEngine& digest_engine,
                                           tamga::core::CryptoniteAdapter& crypto)
    : canonicalizer_(canonicalizer),
      transform_engine_(transform_engine),
      digest_engine_(digest_engine),
      crypto_(crypto) {}

bool XmlSignatureVerifier::Verify(const std::string& signed_xml,
                                  XmlSignatureVerificationResult& result,
                                  std::string& error_message) {
    static const std::map<std::string, std::vector<std::uint8_t>> empty_external;
    return Verify(signed_xml, empty_external, result, error_message);
}

bool XmlSignatureVerifier::Verify(const std::string& signed_xml,
                                  const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                                  XmlSignatureVerificationResult& result,
                                  std::string& error_message) {
    result = XmlSignatureVerificationResult{};

    XmlDocPtr doc = ParseHardened(signed_xml, error_message);
    if (!doc) {
        return false;
    }
    xmlNodePtr root = xmlDocGetRootElement(doc.get());

    // WP-1 (анти-wrapping): усі складові підпису беруться в межах ОДНОГО
    // ds:Signature; неоднозначність (дублікати) відхиляється, щоб глобальний
    // пошук «перший за local-name» не можна було експлуатувати XML Signature
    // Wrapping. Множинні підписи підтримує VerifyAll (WP-2, per-signature verdict).
    const int signature_count = CountElementsByLocalName(root, "Signature");
    if (signature_count == 0) {
        error_message = "Не знайдено ds:Signature";
        return false;
    }
    if (signature_count > 1) {
        error_message = "Кілька ds:Signature у документі поки не підтримуються (захист від wrapping)";
        return false;
    }
    if (CountElementsByLocalName(root, "SignedInfo") != 1) {
        error_message = "Очікується рівно один ds:SignedInfo (захист від wrapping)";
        return false;
    }
    if (CountElementsByLocalName(root, "SignatureValue") != 1) {
        error_message = "Очікується рівно один ds:SignatureValue (захист від wrapping)";
        return false;
    }
    if (CountElementsByLocalName(root, "SignedProperties") > 1) {
        error_message = "Кілька xades:SignedProperties у документі (захист від wrapping)";
        return false;
    }

    // Q-005: делегуємо до спільної реалізації VerifySignatureAtPosition з
    // position=1 (єдиний підпис уже підтверджений вище). Усуває ~250 рядків
    // дубльованої логіки і розбіжності: SignedProperties-guard (відсутній тут),
    // cert_der.empty()-check (після vs до SignedInfo C14N), SM null-guard.
    // П-13: єдиний кандидат уже підтверджений вище (лічильник навмисно
    // ширший — за локальною назвою, бо там ширше трактування ВІДХИЛЯЄ
    // більше). Але сам вузол підпису має бути саме `ds:Signature`: інакше
    // документ, у якому єдиний елемент з локальною назвою `Signature`
    // належить чужому namespace, перевірявся б як XMLDSIG-підпис.
    xmlNodePtr signature_node = FindFirstDsigElement(root, "Signature");
    if (signature_node == nullptr) {
        error_message = "Не знайдено ds:Signature у namespace XMLDSIG";
        return false;
    }
    return VerifySignatureAtPosition(doc.get(), root, signature_node, 1, signed_xml,
                                     external_references, transform_engine_, digest_engine_,
                                     result, error_message);
}

bool XmlSignatureVerifier::VerifyAll(const std::string& signed_xml,
                                     const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                                     std::vector<XmlSignatureVerificationResult>& results,
                                     std::string& error_message) {
    results.clear();

    XmlDocPtr doc = ParseHardened(signed_xml, error_message);
    if (!doc) {
        return false;
    }
    xmlNodePtr root = xmlDocGetRootElement(doc.get());

    std::vector<xmlNodePtr> signature_nodes;
    bool nested_found = false;
    CollectTopLevelSignatureNodes(root, signature_nodes, nested_found);
    if (nested_found) {
        error_message = "Вкладений ds:Signature у межах іншого ds:Signature (захист від wrapping)";
        return false;
    }
    if (signature_nodes.empty()) {
        error_message = "Не знайдено ds:Signature";
        return false;
    }

    for (std::size_t i = 0; i < signature_nodes.size(); ++i) {
        xmlNodePtr signature_node = signature_nodes[i];
        const int position = static_cast<int>(i) + 1;

        if (CountElementsInSubtree(signature_node, "SignedInfo") != 1) {
            error_message = "Очікується рівно один ds:SignedInfo у межах кожного ds:Signature (захист від wrapping)";
            return false;
        }
        if (CountElementsInSubtree(signature_node, "SignatureValue") != 1) {
            error_message = "Очікується рівно один ds:SignatureValue у межах кожного ds:Signature (захист від wrapping)";
            return false;
        }
        if (CountElementsInSubtree(signature_node, "SignedProperties") > 1) {
            error_message = "Кілька xades:SignedProperties у межах одного ds:Signature (захист від wrapping)";
            return false;
        }

        XmlSignatureVerificationResult result;
        if (!VerifySignatureAtPosition(doc.get(), root, signature_node, position, signed_xml,
                                       external_references, transform_engine_, digest_engine_, result,
                                       error_message)) {
            return false;
        }
        results.push_back(std::move(result));
    }
    return true;
}

}  // namespace tamga::xmldsig

#endif  // TAMGA_XML_SIGNATURES_ENABLED
