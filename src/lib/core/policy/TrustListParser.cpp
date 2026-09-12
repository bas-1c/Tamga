#include "core/policy/TrustListParser.h"

#include "util/Base64.h"
#include "xml/XmlCore.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>
#include <vector>

// ADR-030: довірчий список ЦЗО розбирається libxml2, а не пошуком підрядків.
//
// Що тут було раніше і чому це прибрано. Модуль мав власний сканер:
// `ExtractTagValues`/`ExtractTagBlocks` шукали `<` і `>`, `StripCommentsAndCdata`
// вручну вирізав коментарі та CDATA, `ReadElementName` брав байти до пробілу.
// Ключовий рядок — `xml.find('>', name_pos)` — визначав межу тега БЕЗ
// урахування лапок. Це рівно та помилка, яку в цьому ж дереві вже знаходили і
// виправляли в двійнику (`asic/AsicContainers.cpp`, С-21), але виправлення
// туди не дійшло: атрибут із `>` усередині значення (наприклад
// `<CRL note="a>b">`) обривав тег достроково, і далі розбір розходився з
// канонічним XML — у парсері, який визначає КОРІНЬ ДОВІРИ всієї системи.
//
// Тепер клас помилки закритий структурно: межі тегів, лапки, коментарі, CDATA,
// символьні посилання і QName розбирає libxml2.

namespace tamga::core::policy {
namespace {

std::string Trim(const std::string& value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](const unsigned char ch) {
        return std::isspace(ch) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](const unsigned char ch) {
        return std::isspace(ch) != 0;
    }).base();
    if (first >= last) {
        return {};
    }
    return std::string(first, last);
}

// Обрізані текстові значення всіх елементів із заданою локальною назвою у
// піддереві `root` (включно з самим `root`), у порядку документа.
std::vector<std::string> ElementValues(const xmlNode* root, const char* local_name) {
    std::vector<std::string> values;
    tamga::xml::ForEachElement(root, [&](const xmlNode* node) {
        if (tamga::xml::MatchesElement(node, local_name, nullptr)) {
            values.push_back(Trim(tamga::xml::NodeContent(node)));
        }
    });
    return values;
}

// Всі елементи із заданою локальною назвою у піддереві, у порядку документа.
std::vector<const xmlNode*> ElementsNamed(const xmlNode* root, const char* local_name) {
    std::vector<const xmlNode*> nodes;
    tamga::xml::ForEachElement(root, [&](const xmlNode* node) {
        if (tamga::xml::MatchesElement(node, local_name, nullptr)) {
            nodes.push_back(node);
        }
    });
    return nodes;
}

std::string FirstElementValue(const xmlNode* root, const char* local_name) {
    const auto values = ElementValues(root, local_name);
    return values.empty() ? std::string{} : values.front();
}

void AppendNonEmpty(const std::vector<std::string>& values, std::vector<std::string>& out) {
    for (const auto& value : values) {
        if (!value.empty()) {
            out.push_back(value);
        }
    }
}

std::vector<std::vector<std::uint8_t>> DecodeCertificates(const xmlNode* root) {
    std::vector<std::vector<std::uint8_t>> certificates;
    for (const auto& encoded_certificate : ElementValues(root, "X509Certificate")) {
        std::vector<std::uint8_t> decoded_certificate;
        if (tamga::util::Base64Decode(encoded_certificate, decoded_certificate) && !decoded_certificate.empty()) {
            certificates.push_back(std::move(decoded_certificate));
        }
    }
    return certificates;
}

TrustListEndpoints ExtractEndpoints(const xmlNode* root) {
    TrustListEndpoints endpoints;
    AppendNonEmpty(ElementValues(root, "CRL"), endpoints.crl_urls);
    AppendNonEmpty(ElementValues(root, "OCSP"), endpoints.ocsp_urls);
    AppendNonEmpty(ElementValues(root, "TSP"), endpoints.tsp_urls);
    return endpoints;
}

// Один запис служби з піддерева `TSPService` або `Service`.
TrustListServiceRecord BuildServiceRecord(const xmlNode* service_node, const std::string& provider_name) {
    TrustListServiceRecord service;
    service.provider_name = provider_name;
    service.service_type = FirstElementValue(service_node, "ServiceTypeIdentifier");
    if (service.service_type.empty()) {
        service.service_type = FirstElementValue(service_node, "ServiceType");
    }
    service.status = FirstElementValue(service_node, "ServiceStatus");
    service.subject_name = FirstElementValue(service_node, "X509SubjectName");
    service.certificates = DecodeCertificates(service_node);
    service.endpoints = ExtractEndpoints(service_node);
    return service;
}

void CollectServices(const xmlNode* provider_node,
                     const char* service_local_name,
                     const std::string& provider_name,
                     std::vector<TrustListServiceRecord>& out) {
    for (const xmlNode* service_node : ElementsNamed(provider_node, service_local_name)) {
        TrustListServiceRecord service = BuildServiceRecord(service_node, provider_name);
        if (!service.certificates.empty() || !service.service_type.empty() || !service.status.empty()) {
            out.push_back(std::move(service));
        }
    }
}

} // namespace

TrustListParseResult TrustListParser::Parse(const std::string& xml) const {
    TrustListParseResult result;

    std::string parse_error;
    const auto doc = tamga::xml::ParseHardened(xml, parse_error);
    const xmlNode* root = tamga::xml::RootElement(doc);
    if (root == nullptr) {
        // ЗМІНА КОНТРАКТУ (свідома): раніше будь-який непридатний вхід давав
        // одне й те саме "Trust list does not contain supported entries", бо
        // сканер не мав поняття «некоректний XML». Тепер відмова парсера
        // (XXE-конструкція, DTD, перевищення межі розміру, зламана розмітка)
        // повідомляється окремо. Повідомлення споживає лише
        // `TrustListSync` як текст діагностики; жодна логіка на нього не
        // спирається.
        result.ok = false;
        result.message = parse_error.empty() ? "Trust list XML is empty or has no root element"
                                             : parse_error;
        return result;
    }

    result.certificates = DecodeCertificates(root);
    result.endpoints = ExtractEndpoints(root);

    for (const xmlNode* provider_node : ElementsNamed(root, "TrustServiceProvider")) {
        const std::string provider_name = FirstElementValue(provider_node, "Name");
        // Порядок збереження записів той самий, що й до ADR-030: спершу всі
        // `TSPService` постачальника, потім усі `Service`.
        CollectServices(provider_node, "TSPService", provider_name, result.services);
        CollectServices(provider_node, "Service", provider_name, result.services);
    }

    result.ok = !result.certificates.empty() ||
                !result.endpoints.crl_urls.empty() ||
                !result.endpoints.ocsp_urls.empty() ||
                !result.endpoints.tsp_urls.empty() ||
                !result.services.empty();
    result.message = result.ok ? "Trust list parsed" : "Trust list does not contain supported entries";
    return result;
}

} // namespace tamga::core::policy
