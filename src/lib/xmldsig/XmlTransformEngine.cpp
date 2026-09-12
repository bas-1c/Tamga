#include "xmldsig/XmlTransformEngine.h"

#if defined(TAMGA_XML_SIGNATURES_ENABLED)

#include <vector>

#include <libxml/c14n.h>

#include "util/Base64.h"
#include "xmldsig/detail/XmlDocUtil.h"

namespace tamga::xmldsig {

namespace {

using namespace tamga::xmldsig::detail;

constexpr const char* kEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
constexpr const char* kBase64 = "http://www.w3.org/2000/09/xmldsig#base64";
constexpr const char* kC14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
constexpr const char* kC14nComments = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
constexpr const char* kExcl = "http://www.w3.org/2001/10/xml-exc-c14n#";
constexpr const char* kExclComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

// Чи є URI трансформ канонікалізацією; повертає mode/comments libxml2.
bool C14nParams(const std::string& uri, int& mode, int& comments) {
    if (uri == kC14n) { mode = XML_C14N_1_0; comments = 0; return true; }
    if (uri == kC14nComments) { mode = XML_C14N_1_0; comments = 1; return true; }
    if (uri == kExcl) { mode = XML_C14N_EXCLUSIVE_1_0; comments = 0; return true; }
    if (uri == kExclComments) { mode = XML_C14N_EXCLUSIVE_1_0; comments = 1; return true; }
    return false;
}

// Рекурсивно від'єднує і звільняє всі елементи ds:Signature (enveloped-transform).
void RemoveSignatures(xmlNodePtr root) {
    xmlNodePtr node = root;
    while (node != nullptr) {
        xmlNodePtr next = node->next;
        if (node->type == XML_ELEMENT_NODE &&
            xmlStrcmp(node->name, reinterpret_cast<const xmlChar*>("Signature")) == 0) {
            // Перевіряємо namespace ds.
            if (node->ns != nullptr && node->ns->href != nullptr &&
                xmlStrcmp(node->ns->href, reinterpret_cast<const xmlChar*>(DsigNamespace())) == 0) {
                xmlUnlinkNode(node);
                xmlFreeNode(node);
                node = next;
                continue;
            }
        }
        if (node->children != nullptr) {
            RemoveSignatures(node->children);
        }
        node = next;
    }
}

// Канонікалізує поточний документ у octets.
bool CanonicalizeDoc(xmlDocPtr doc, int mode, int comments, std::string& out, std::string& error) {
    xmlChar* result = nullptr;
    const int len = xmlC14NDocDumpMemory(doc, nullptr, mode, nullptr, comments, &result);
    if (len < 0 || result == nullptr) {
        if (result != nullptr) {
            xmlFree(result);
        }
        error = "Помилка канонікалізації у трансформ-пайплайні";
        return false;
    }
    out.assign(reinterpret_cast<const char*>(result), static_cast<std::size_t>(len));
    xmlFree(result);
    return true;
}

}  // namespace

bool XmlTransformEngine::ApplyTransforms(const std::string& xml,
                                         const XmlReference& ref,
                                         std::string& out,
                                         std::string& error_message) {
    if (!ref.uri.empty() && ref.uri.front() != '#' && ref.transforms.empty()) {
        out = xml;
        error_message.clear();
        return true;
    }

    XmlDocPtr doc = ParseHardened(xml, error_message);
    if (!doc) {
        if (ref.transforms.empty()) {
            out = xml;
            error_message.clear();
            return true;
        }
        return false;
    }

    bool have_octets = false;
    std::string octets;

    for (const std::string& uri : ref.transforms) {
        if (uri == kEnveloped) {
            if (have_octets) {
                error_message = "enveloped-signature трансформ після канонікалізації не підтримується";
                return false;
            }
            RemoveSignatures(xmlDocGetRootElement(doc.get()));
            continue;
        }

        int mode = 0;
        int comments = 0;
        if (C14nParams(uri, mode, comments)) {
            if (have_octets) {
                error_message = "повторна канонікалізація над octet-stream не підтримується";
                return false;
            }
            if (!CanonicalizeDoc(doc.get(), mode, comments, octets, error_message)) {
                return false;
            }
            have_octets = true;
            continue;
        }

        if (uri == kBase64) {
            if (!have_octets) {
                // W3C XMLDSIG §6.6.2: якщо на вхід base64-трансформу
                // подано node-set, декодується РЯДКОВЕ ЗНАЧЕННЯ вузлів,
                // а не їхня канонічна форма. Раніше ми вимагали тут
                // попередньої канонікалізації — і відхиляли коректний
                // XAdES enveloping, де `ds:Object` містить base64 без
                // жодного c14n перед ним (знайдено звіркою проти ETSI DSS).
                xmlNodePtr root = xmlDocGetRootElement(doc.get());
                if (root == nullptr) {
                    error_message = "base64-трансформ: порожній вхідний node-set";
                    return false;
                }
                xmlChar* content = xmlNodeGetContent(root);
                if (content == nullptr) {
                    error_message = "base64-трансформ: не вдалося взяти рядкове значення вузла";
                    return false;
                }
                octets.assign(reinterpret_cast<const char*>(content));
                xmlFree(content);
                have_octets = true;
            }
            std::vector<std::uint8_t> decoded;
            if (!tamga::util::Base64Decode(octets, decoded)) {
                error_message = "Помилка base64-декодування у трансформ-пайплайні";
                return false;
            }
            octets.assign(decoded.begin(), decoded.end());
            continue;
        }

        error_message = "Непідтримуваний трансформ: " + uri;
        return false;
    }

    // Якщо канонікалізацію явно не застосовано (наприклад, лише enveloped),
    // node-set перетворюється на octets дефолтною інклюзивною C14N (W3C).
    if (!have_octets) {
        if (!CanonicalizeDoc(doc.get(), XML_C14N_1_0, 0, octets, error_message)) {
            return false;
        }
    }

    out = std::move(octets);
    return true;
}

}  // namespace tamga::xmldsig

#endif  // TAMGA_XML_SIGNATURES_ENABLED
