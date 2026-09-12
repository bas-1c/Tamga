#include "xmldsig/XmlSignatureBuilder.h"
#include "xmldsig/XmlHelpers.h"

#if defined(TAMGA_XML_SIGNATURES_ENABLED)

#include "core/CryptoniteAdapter.h"
#include "core/policy/ImprintDigest.h"
#include "util/Base64.h"
#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/detail/XmlDocUtil.h"

namespace tamga::xmldsig {

namespace {

using namespace tamga::xmldsig::detail;





// Same-document "#id"-посилання (без xpointer) — кандидат на канонікалізацію
// безпосередньо в оригінальному документі (без серіалізації/перепарсингу, що
// губить namespace-контекст, успадкований від елементів-предків).

// Чи складається transforms щонайбільше з одного (C14N) перетворення — лише
// такий випадок коректно покриває канонікалізація по Id; інакше лишаємо
// старий resolve+transform шлях (наприклад enveloped-signature).

}  // namespace

XmlSignatureBuilder::XmlSignatureBuilder(XmlCanonicalizer& canonicalizer,
                                         XmlTransformEngine& transform_engine,
                                         XmlDigestEngine& digest_engine,
                                         tamga::core::CryptoniteAdapter& crypto)
    : canonicalizer_(canonicalizer),
      transform_engine_(transform_engine),
      digest_engine_(digest_engine),
      crypto_(crypto) {}

bool XmlSignatureBuilder::Sign(const std::string& xml_to_sign,
                               const XmlSignatureParameters& params,
                               const tamga::core::SigningKey& signing_key,
                               std::string& signed_xml_out,
                               std::string& error_message) {
    if (params.references.empty()) {
        error_message = "XMLDSIG-підпис потребує хоча б одне посилання";
        return false;
    }

    // 1. Парсимо документ один раз — він використовується і для дайджестів
    // посилань (до вставки Signature), і пізніше для побудови дерева підпису.
    XmlDocPtr doc = ParseHardened(xml_to_sign, error_message);
    if (!doc) {
        return false;
    }
    xmlNodePtr root = xmlDocGetRootElement(doc.get());
    if (root == nullptr) {
        error_message = "Порожній XML-документ";
        return false;
    }

    // Дайджести посилань рахуємо над оригіналом (до вставки Signature):
    // enveloped-трансформ усуне Signature, тож канонічна форма збігається.
    XmlReferenceResolver resolver;
    std::vector<std::string> digest_b64(params.references.size());
    for (std::size_t i = 0; i < params.references.size(); ++i) {
        const XmlReference& ref = params.references[i];
        std::string octets;
        std::string fragment;
        if (IsIdFragmentUri(ref.uri, fragment) && IsCanonicalizationOnlyTransform(ref.transforms)) {
            // Канонікалізуємо елемент прямо в оригінальному документі (XPath
            // node-set), не серіалізуючи його окремо — інакше губляться
            // namespace-декларації, успадковані від елементів-предків.
            int ref_mode = XML_C14N_1_0;
            int ref_comments = 0;
            if (!ref.transforms.empty()) {
                C14nUriToMode(ref.transforms.front(), ref_mode, ref_comments);
            }
            if (!CanonicalizeSubtreeById(doc.get(), fragment, ref_mode, ref_comments, octets, error_message)) {
                return false;
            }
        } else {
            std::string resolved;
            if (!resolver.ResolveReference(xml_to_sign, ref, resolved, error_message)) {
                return false;
            }
            if (!transform_engine_.ApplyTransforms(resolved, ref, octets, error_message)) {
                return false;
            }
        }
        std::vector<std::uint8_t> bytes(octets.begin(), octets.end());
        std::vector<std::uint8_t> digest;
        if (!digest_engine_.ComputeDigest(bytes, ref.digest_method, digest, error_message)) {
            return false;
        }
        digest_b64[i] = tamga::util::Base64Encode(digest);
    }

    // 2. Будуємо дерево підпису у документі (правильний namespace-контекст).

    xmlNodePtr sig = xmlNewNode(nullptr, reinterpret_cast<const xmlChar*>("Signature"));
    xmlNsPtr ns_ds = xmlNewNs(sig, reinterpret_cast<const xmlChar*>(DsigNamespace()), nullptr);
    xmlSetNs(sig, ns_ds);
    xmlAddChild(root, sig);
    if (!params.signature_id.empty()) {
        SetAttr(sig, "Id", params.signature_id);
    }

    xmlNodePtr signed_info = AddChild(sig, ns_ds, "SignedInfo");
    xmlNodePtr c14n_method = AddChild(signed_info, ns_ds, "CanonicalizationMethod");
    SetAttr(c14n_method, "Algorithm", C14nMethodToUri(params.c14n_method));
    xmlNodePtr sig_method = AddChild(signed_info, ns_ds, "SignatureMethod");
    SetAttr(sig_method, "Algorithm", params.signature_method_uri);

    for (std::size_t i = 0; i < params.references.size(); ++i) {
        const XmlReference& ref = params.references[i];
        xmlNodePtr reference = AddChild(signed_info, ns_ds, "Reference");
        if (!ref.id.empty()) {
            SetAttr(reference, "Id", ref.id);
        }
        SetAttr(reference, "URI", ref.uri);
        if (ref.emit_type_attribute || !ref.type.empty()) {
            SetAttr(reference, "Type", ref.type);
        }
        if (!ref.transforms.empty()) {
            xmlNodePtr transforms = AddChild(reference, ns_ds, "Transforms");
            for (const std::string& t : ref.transforms) {
                xmlNodePtr tn = AddChild(transforms, ns_ds, "Transform");
                SetAttr(tn, "Algorithm", t);
            }
        }
        xmlNodePtr digest_method = AddChild(reference, ns_ds, "DigestMethod");
        SetAttr(digest_method, "Algorithm", ref.digest_method);
        AddTextChild(reference, ns_ds, "DigestValue", digest_b64[i]);
    }

    xmlNodePtr signature_value = AddChild(sig, ns_ds, "SignatureValue");

    // KeyInfo: вбудовуємо сертифікат підписувача (для самодостатньої верифікації).
    if (!signing_key.certificate_der.empty()) {
        xmlNodePtr key_info = AddChild(sig, ns_ds, "KeyInfo");
        xmlNodePtr x509_data = AddChild(key_info, ns_ds, "X509Data");
        AddTextChild(x509_data, ns_ds, "X509Certificate",
                     tamga::util::Base64Encode(signing_key.certificate_der));
    }

    // 3. Канонікалізуємо SignedInfo (із namespace-вузлами) і підписуємо його геш.
    int mode = 0;
    int comments = 0;
    C14nUriToMode(C14nMethodToUri(params.c14n_method), mode, comments);
    std::string signed_info_octets;
    if (!CanonicalizeSubtreeByLocalName(doc.get(), "SignedInfo", mode, comments,
                                        signed_info_octets, error_message)) {
        return false;
    }

    const auto si_alg = XmlDigestEngine::MapSignatureMethodUri(params.signature_method_uri);
    if (!si_alg) {
        error_message = "Непідтримуваний SignatureMethod URI: " + params.signature_method_uri;
        return false;
    }
    tamga::core::ImprintResult imprint;
    const std::vector<std::uint8_t> si_bytes(signed_info_octets.begin(), signed_info_octets.end());
    if (!tamga::core::ComputeImprint(*si_alg, si_bytes, imprint, error_message)) {
        return false;
    }

    std::vector<std::uint8_t> signature;
    if (!tamga::core::CryptoniteAdapter::SignHash(signing_key.use_pkcs12,
                                                  signing_key.key_material,
                                                  signing_key.certificate_der,
                                                  signing_key.password,
                                                  imprint.hash,
                                                  signature,
                                                  error_message)) {
        return false;
    }

    const std::string signature_b64 = tamga::util::Base64Encode(signature);
    xmlNodeSetContent(signature_value, reinterpret_cast<const xmlChar*>(signature_b64.c_str()));

    // 4. Серіалізуємо підписаний документ (без XML-декларації).
    signed_xml_out = SerializeNode(doc.get(), root);
    if (signed_xml_out.empty()) {
        error_message = "Не вдалося серіалізувати підписаний документ";
        return false;
    }
    return true;
}

}  // namespace tamga::xmldsig

#endif  // TAMGA_XML_SIGNATURES_ENABLED
