#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "core/SignatureRequest.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/XmlTransformEngine.h"

namespace tamga::core {
class CryptoniteAdapter;
}

namespace tamga::xmldsig {

// Параметри формування XMLDSIG-підпису: ідентифікатори, алгоритми, метод
// канонікалізації, перелік посилань та опційний KeyInfo.
struct XmlSignatureParameters {
    std::string signature_id;
    std::string signature_method_uri;
    CanonicalizationMethod c14n_method{CanonicalizationMethod::C14N_Exclusive};
    std::vector<XmlReference> references;
    std::optional<std::string> key_info_xml;
    // Зовнішні об'єкти даних, на які посилаються `references` за URI: файли
    // всередині контейнера ASiC, яких немає в самому XML-документі підпису.
    // Дайджест такого посилання рахується прямо з цих байтів, без резолвінгу
    // в документі й без трансформацій. Дзеркалить `external_references` у
    // XmlReferenceResolver, яким той самий випадок читається при перевірці.
    std::map<std::string, std::vector<std::uint8_t>> external_data;
};

// Збирає enveloped/detached XMLDSIG-підпис: канонікалізує, обчислює дайджести,
// формує ds:SignedInfo і підписує його через CryptoniteAdapter.
class XmlSignatureBuilder {
public:
    XmlSignatureBuilder(XmlCanonicalizer& canonicalizer, XmlTransformEngine& transform_engine,
        XmlDigestEngine& digest_engine, tamga::core::CryptoniteAdapter& crypto);

    // Будує повний enveloped ds:Signature над xml_to_sign і підписує
    // канонікалізований SignedInfo ключем signing_key (через
    // CryptoniteAdapter::SignHash). Повертає false + error_message при помилці.
    bool Sign(const std::string& xml_to_sign,
              const XmlSignatureParameters& params,
              const tamga::core::SigningKey& signing_key,
              std::string& signed_xml_out,
              std::string& error_message);

private:
    // Залежності утримуються за посиланням — їх життєвий цикл належить виклику.
    XmlCanonicalizer& canonicalizer_;
    XmlTransformEngine& transform_engine_;
    XmlDigestEngine& digest_engine_;
    tamga::core::CryptoniteAdapter& crypto_;
};

}  // namespace tamga::xmldsig
