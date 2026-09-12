#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace tamga::xmldsig {

// Опис одного елемента ds:Reference: Id самого посилання, URI цілі, тип,
// ланцюг трансформацій, метод і значення дайджесту.
struct XmlReference {
    std::string id;
    std::string uri;
    std::string type;
    // Дає змогу відрізнити відсутній Type від нормативно потрібного Type="".
    bool emit_type_attribute{false};
    std::vector<std::string> transforms;  // Algorithm-URI кожного ds:Transform
    std::string digest_method;            // Algorithm-URI ds:DigestMethod
    std::string digest_value_base64;      // текст ds:DigestValue
};

// Витягує елементи ds:Reference з підпису та резолвить дані, на які вони
// посилаються, у межах документа. Реалізація на libxml2, доступна лише у
// збірці з TAMGA_ENABLE_XML_SIGNATURES.
class XmlReferenceResolver {
public:
    // Розбирає ds:SignedInfo у переданому XMLDSIG-документі та повертає всі
    // ds:Reference. false + error_message при помилці парсингу/відсутності
    // SignedInfo.
    bool ExtractReferences(const std::string& signature_xml,
                           std::vector<XmlReference>& out,
                           std::string& error_message);

    // WP-2: те саме, але SignedInfo береться СТРОГО в межах
    // signature_position_1based-го (1-based, порядок документа) верхньорівневого
    // ds:Signature — для документів із кількома ds:Signature. Відхиляє
    // документ, якщо десь є вкладений ds:Signature (захист від wrapping) або
    // якщо цей конкретний ds:Signature не має рівно одного SignedInfo.
    bool ExtractReferencesForSignature(const std::string& signed_xml,
                                       int signature_position_1based,
                                       std::vector<XmlReference>& out,
                                       std::string& error_message);

    // Розв'язує URI посилання у межах xml-документа і повертає відповідний
    // XML-фрагмент (серіалізований). Підтримує порожній URI (весь документ) і
    // same-document fragment "#id" (атрибути Id/ID/id). false + error_message,
    // якщо ціль не знайдено або URI не підтримується.
    bool ResolveReference(const std::string& xml,
                          const XmlReference& ref,
                          std::string& out,
                          std::string& error_message);

    bool ResolveReference(const std::string& xml,
                          const XmlReference& ref,
                          const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                          std::string& out,
                          std::string& error_message);
};

}  // namespace tamga::xmldsig
