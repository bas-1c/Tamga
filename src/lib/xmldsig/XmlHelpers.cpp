#include "xmldsig/XmlHelpers.h"

#include <algorithm>
#include <cctype>

#include "xmldsig/detail/XmlDocUtil.h"

namespace tamga::xmldsig {
xmlNodePtr AddChild(xmlNodePtr parent, xmlNsPtr ns, const char* name) {
    return xmlNewChild(parent, ns, reinterpret_cast<const xmlChar*>(name), nullptr);
}

xmlNodePtr AddTextChild(xmlNodePtr parent, xmlNsPtr ns, const char* name, const std::string& text) {
    return xmlNewTextChild(parent, ns, reinterpret_cast<const xmlChar*>(name),
                           reinterpret_cast<const xmlChar*>(text.c_str()));
}

void SetAttr(xmlNodePtr node, const char* name, const std::string& value) {
    xmlSetProp(node, reinterpret_cast<const xmlChar*>(name),
               reinterpret_cast<const xmlChar*>(value.c_str()));
}

std::string TrimmedText(xmlNodePtr node) {
    if (node == nullptr) {
        return std::string{};
    }
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


bool IsIdFragmentUri(const std::string& uri, std::string& fragment) {
    if (uri.size() < 2 || uri.front() != '#') {
        return false;
    }
    fragment = uri.substr(1);
    return fragment.rfind("xpointer", 0) != 0;
}

bool IsCanonicalizationOnlyTransform(const std::vector<std::string>& transforms) {
    if (transforms.size() > 1) {
        return false;
    }
    if (transforms.empty()) {
        return true;
    }
    int mode = 0;
    int comments = 0;
    return detail::C14nUriToMode(transforms.front(), mode, comments);
}

const char* C14nMethodToUri(CanonicalizationMethod method) {
    switch (method) {
        case CanonicalizationMethod::C14N:
            return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        case CanonicalizationMethod::C14N_WithComments:
            return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
        case CanonicalizationMethod::C14N_Exclusive:
            return "http://www.w3.org/2001/10/xml-exc-c14n#";
        case CanonicalizationMethod::C14N_Exclusive_WithComments:
            return "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
    }
    return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
}

} // namespace tamga::xmldsig
