#pragma once

#include <string>
#include <vector>

namespace tamga::xmldsig {

// Метод канонікалізації XML за W3C C14N (інклюзивний/ексклюзивний, з коментарями
// або без них).
enum class CanonicalizationMethod {
    C14N,
    C14N_Exclusive,
    C14N_Exclusive_WithComments,
    C14N_WithComments,
};

// Виконує канонікалізацію XML-фрагмента обраним методом C14N; за потреби
// обмежує область XPath-виразом та враховує інклюзивні простори імен.
// Реалізація спирається на libxml2 (xmlC14NDocDumpMemory) і доступна лише у
// збірці з TAMGA_ENABLE_XML_SIGNATURES.
class XmlCanonicalizer {
public:
    // Канонікалізує xml обраним методом. Повертає false і заповнює
    // error_message при помилці парсингу/XPath/C14N. Якщо xpath порожній —
    // канонікалізується весь документ; інакше — вузли, відібрані XPath.
    // inclusive_namespaces задає InclusiveNamespaces PrefixList для
    // ексклюзивної канонікалізації.
    bool Canonicalize(const std::string& xml,
                      CanonicalizationMethod method,
                      std::string& out,
                      std::string& error_message,
                      const std::string& xpath = {},
                      const std::vector<std::string>& inclusive_namespaces = {});
};

}  // namespace tamga::xmldsig
