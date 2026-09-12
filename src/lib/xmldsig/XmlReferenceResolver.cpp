#include "xmldsig/XmlReferenceResolver.h"

#if defined(TAMGA_XML_SIGNATURES_ENABLED)

#include <algorithm>
#include <cctype>

#include "util/AsicUri.h"
#include "xmldsig/detail/XmlDocUtil.h"

namespace tamga::xmldsig {

namespace {

using namespace tamga::xmldsig::detail;

// Збирає текстовий вміст елемента (конкатенація текстових вузлів) із обрізанням
// зовнішніх пробілів — для ds:DigestValue.
std::string ElementText(xmlNodePtr node) {
    xmlChar* content = xmlNodeGetContent(node);
    if (content == nullptr) {
        return std::string{};
    }
    std::string text(reinterpret_cast<const char*>(content));
    xmlFree(content);
    const auto first = text.find_first_not_of(" \t\r\n");
    const auto last = text.find_last_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return std::string{};
    }
    return text.substr(first, last - first + 1);
}


bool IsUnsafeExternalUri(const std::string& uri) {
    if (uri.empty() || uri.front() == '#') return false;
    std::string lower = uri;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch){ return static_cast<char>(std::tolower(ch)); });
    if (lower.rfind("file://", 0) == 0 || lower.rfind("http://", 0) == 0 || lower.rfind("https://", 0) == 0) return true;
    if (!uri.empty() && (uri.front() == '/' || uri.front() == '\\')) return true;
    if (uri.size() >= 2 && std::isalpha(static_cast<unsigned char>(uri[0])) && uri[1] == ':') return true;
    if (uri.find("..") != std::string::npos) return true;
    if (uri.find('\\') != std::string::npos) return true;
    return false;
}

// Спільний цикл видобування ds:Reference із конкретного вузла SignedInfo.
// Винесено окремо, щоб ExtractReferences (перший SignedInfo у документі) і
// ExtractReferencesForSignature (SignedInfo конкретного ds:Signature, WP-2)
// не дублювали логіку розбору Transforms/DigestMethod/DigestValue.
bool ExtractReferencesFromSignedInfoNode(xmlNodePtr signed_info,
                                         std::vector<XmlReference>& out,
                                         std::string& error_message) {
    for (xmlNodePtr child = signed_info->children; child != nullptr; child = child->next) {
        if (!IsElementNamed(child, "Reference")) {
            continue;
        }
        XmlReference ref;
        ref.id = GetAttr(child, "Id");
        ref.uri = GetAttr(child, "URI");
        ref.type = GetAttr(child, "Type");
        ref.emit_type_attribute =
            xmlHasProp(child, reinterpret_cast<const xmlChar*>("Type")) != nullptr;

        if (xmlNodePtr transforms = FindFirstElement(child->children, "Transforms")) {
            for (xmlNodePtr t = transforms->children; t != nullptr; t = t->next) {
                if (IsElementNamed(t, "Transform")) {
                    ref.transforms.push_back(GetAttr(t, "Algorithm"));
                }
            }
        }
        if (xmlNodePtr digest_method = FindFirstElement(child->children, "DigestMethod")) {
            ref.digest_method = GetAttr(digest_method, "Algorithm");
        }
        if (xmlNodePtr digest_value = FindFirstElement(child->children, "DigestValue")) {
            ref.digest_value_base64 = ElementText(digest_value);
        }
        out.push_back(std::move(ref));
    }

    if (out.empty()) {
        error_message = "ds:SignedInfo не містить жодного ds:Reference";
        return false;
    }
    return true;
}

}  // namespace

bool XmlReferenceResolver::ExtractReferences(const std::string& signature_xml,
                                             std::vector<XmlReference>& out,
                                             std::string& error_message) {
    out.clear();
    XmlDocPtr doc = ParseHardened(signature_xml, error_message);
    if (!doc) {
        return false;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc.get());
    xmlNodePtr signed_info = FindFirstElement(root, "SignedInfo");
    if (signed_info == nullptr) {
        error_message = "У документі не знайдено ds:SignedInfo";
        return false;
    }

    return ExtractReferencesFromSignedInfoNode(signed_info, out, error_message);
}

bool XmlReferenceResolver::ExtractReferencesForSignature(const std::string& signed_xml,
                                                          int signature_position_1based,
                                                          std::vector<XmlReference>& out,
                                                          std::string& error_message) {
    out.clear();
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
    if (signature_position_1based < 1 ||
        static_cast<std::size_t>(signature_position_1based) > signature_nodes.size()) {
        error_message = "Некоректний індекс підпису";
        return false;
    }
    xmlNodePtr signature_node = signature_nodes[static_cast<std::size_t>(signature_position_1based) - 1];

    if (CountElementsInSubtree(signature_node, "SignedInfo") != 1) {
        error_message = "У межах підпису має бути рівно один ds:SignedInfo (захист від wrapping)";
        return false;
    }
    xmlNodePtr signed_info = FindFirstElementInSubtree(signature_node, "SignedInfo");
    if (signed_info == nullptr) {
        error_message = "У межах підпису не знайдено ds:SignedInfo";
        return false;
    }

    return ExtractReferencesFromSignedInfoNode(signed_info, out, error_message);
}

bool XmlReferenceResolver::ResolveReference(const std::string& xml,
                                            const XmlReference& ref,
                                            std::string& out,
                                            std::string& error_message) {
    XmlDocPtr doc = ParseHardened(xml, error_message);
    if (!doc) {
        return false;
    }
    xmlNodePtr root = xmlDocGetRootElement(doc.get());
    if (root == nullptr) {
        error_message = "Порожній XML-документ";
        return false;
    }

    // Порожній URI -> весь документ (типово для enveloped).
    if (ref.uri.empty()) {
        out = SerializeNode(doc.get(), root);
        return true;
    }

    // Same-document fragment "#id".
    if (ref.uri.front() == '#') {
        const std::string fragment = ref.uri.substr(1);
        if (fragment.rfind("xpointer", 0) == 0) {
            error_message = "XPointer-посилання поки не підтримуються: " + ref.uri;
            return false;
        }
        xmlNodePtr target = FindElementById(root, fragment);
        if (target == nullptr) {
            error_message = "Не знайдено елемент із Id=" + fragment;
            return false;
        }
        out = SerializeNode(doc.get(), target);
        return true;
    }

    error_message = "Зовнішні (detached) URI-посилання поки не підтримуються: " + ref.uri;
    return false;
}

bool XmlReferenceResolver::ResolveReference(const std::string& xml,
                                            const XmlReference& ref,
                                            const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                                            std::string& out,
                                            std::string& error_message) {
    if (!ref.uri.empty() && ref.uri.front() != '#') {
        std::string entry_uri;
        if (!tamga::util::NormalizeAsicEntryUri(ref.uri, entry_uri, error_message)) {
            return false;
        }
        if (IsUnsafeExternalUri(entry_uri)) {
            error_message = "Небезпечне зовнішнє URI-посилання: " + ref.uri;
            return false;
        }
        // WP-7 (ME-05): external_references очікується вже нормалізованим
        // (тими самими правилами NormalizeAsicEntryUri) на боці викликача —
        // Session::VerifyFileAsicEXades будує його з ASiC-E entry-імен
        // саме так, щоб обидві сторони порівняння мали однаковий канонічний
        // вигляд (напр. ds:Reference URI="./file.pdf" тепер коректно
        // резолвиться до entry "file.pdf").
        const auto it = external_references.find(entry_uri);
        if (it == external_references.end()) {
            error_message = "Не знайдено ASiC-E entry для ds:Reference URI=" + ref.uri;
            return false;
        }
        out.assign(it->second.begin(), it->second.end());
        return true;
    }
    return ResolveReference(xml, ref, out, error_message);
}

}  // namespace tamga::xmldsig

#endif  // TAMGA_XML_SIGNATURES_ENABLED
