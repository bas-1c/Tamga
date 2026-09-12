#pragma once

#include <string>

#include "xmldsig/XmlReferenceResolver.h"

namespace tamga::xmldsig {

// Послідовно застосовує ланцюг трансформацій ds:Transforms (enveloped-signature,
// канонікалізація C14N/exclusive, base64) до резолвленого вузла посилання.
// Реалізація на libxml2, доступна лише у збірці з TAMGA_ENABLE_XML_SIGNATURES.
class XmlTransformEngine {
public:
    // Застосовує всі трансформації з ref.transforms по черзі до xml і повертає
    // підсумковий октетний потік для обчислення дайджесту. false +
    // error_message, якщо трансформацію не підтримано або сталася помилка.
    bool ApplyTransforms(const std::string& xml,
                         const XmlReference& ref,
                         std::string& out,
                         std::string& error_message);
};

}  // namespace tamga::xmldsig
