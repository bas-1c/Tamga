#include "xmldsig/XmlCanonicalizer.h"

#if defined(TAMGA_XML_SIGNATURES_ENABLED)

#include <libxml/c14n.h>
#include <libxml/xmlstring.h>

#include "xmldsig/detail/XmlDocUtil.h"

namespace tamga::xmldsig {

namespace {

using detail::ParseHardened;
using detail::XmlDocPtr;
using detail::XmlXPathCtxPtr;
using detail::XmlXPathObjPtr;

// Розкладає метод C14N на (libxml2 mode, with_comments).
bool ResolveMode(CanonicalizationMethod method, int& mode, int& with_comments) {
    switch (method) {
        case CanonicalizationMethod::C14N:
            mode = XML_C14N_1_0;
            with_comments = 0;
            return true;
        case CanonicalizationMethod::C14N_WithComments:
            mode = XML_C14N_1_0;
            with_comments = 1;
            return true;
        case CanonicalizationMethod::C14N_Exclusive:
            mode = XML_C14N_EXCLUSIVE_1_0;
            with_comments = 0;
            return true;
        case CanonicalizationMethod::C14N_Exclusive_WithComments:
            mode = XML_C14N_EXCLUSIVE_1_0;
            with_comments = 1;
            return true;
    }
    return false;
}

}  // namespace

bool XmlCanonicalizer::Canonicalize(const std::string& xml,
                                    CanonicalizationMethod method,
                                    std::string& out,
                                    std::string& error_message,
                                    const std::string& xpath,
                                    const std::vector<std::string>& inclusive_namespaces) {
    int mode = 0;
    int with_comments = 0;
    if (!ResolveMode(method, mode, with_comments)) {
        error_message = "Невідомий метод канонікалізації";
        return false;
    }

    XmlDocPtr doc = ParseHardened(xml, error_message);
    if (!doc) {
        return false;
    }

    // InclusiveNamespaces PrefixList для ексклюзивної C14N: NULL-термінований
    // масив xmlChar*. Тримаємо як C-масив покажчиків на байти рядків зі
    // стабільного контейнера.
    std::vector<xmlChar*> ns_prefixes;
    if (!inclusive_namespaces.empty()) {
        ns_prefixes.reserve(inclusive_namespaces.size() + 1);
        for (const std::string& prefix : inclusive_namespaces) {
            ns_prefixes.push_back(reinterpret_cast<xmlChar*>(const_cast<char*>(prefix.c_str())));
        }
        ns_prefixes.push_back(nullptr);
    }
    xmlChar** inclusive_ns_ptr = ns_prefixes.empty() ? nullptr : ns_prefixes.data();

    // Опційний XPath: відбирає підмножину вузлів. Без XPath -> весь документ.
    XmlXPathObjPtr xpath_obj;
    xmlNodeSetPtr nodes = nullptr;
    if (!xpath.empty()) {
        XmlXPathCtxPtr ctx{xmlXPathNewContext(doc.get())};
        if (!ctx) {
            error_message = "Не вдалося створити XPath-контекст";
            return false;
        }
        xpath_obj.reset(xmlXPathEvalExpression(
            reinterpret_cast<const xmlChar*>(xpath.c_str()), ctx.get()));
        if (!xpath_obj) {
            error_message = "Помилка обчислення XPath-виразу: " + xpath;
            return false;
        }
        nodes = xpath_obj->nodesetval;
    }

    xmlChar* result = nullptr;
    const int len = xmlC14NDocDumpMemory(doc.get(),
                                         nodes,
                                         mode,
                                         inclusive_ns_ptr,
                                         with_comments,
                                         &result);
    if (len < 0 || result == nullptr) {
        if (result != nullptr) {
            xmlFree(result);
        }
        error_message = "xmlC14NDocDumpMemory не вдалося";
        return false;
    }

    out.assign(reinterpret_cast<const char*>(result), static_cast<std::size_t>(len));
    xmlFree(result);
    return true;
}

}  // namespace tamga::xmldsig

#endif  // TAMGA_XML_SIGNATURES_ENABLED
