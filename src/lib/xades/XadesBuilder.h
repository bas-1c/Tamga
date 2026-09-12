#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "core/SignatureRequest.h"
#include "xades/XadesTypes.h"
#include "xmldsig/XmlSignatureBuilder.h"

namespace tamga::core {
class CryptoniteAdapter;
class TspClient;
}  // namespace tamga::core

namespace tamga::xades {

// Постачальник RFC 3161 timestamp-токена для XAdES-T: отримує октети для
// штампування (C14N(ds:SignatureValue)) і повертає DER-токен. У продакшні
// обгортає TspClient; у тестах — мок-TSA.
using TimestampProvider = std::function<bool(const std::vector<std::uint8_t>& tbs,
                                             std::vector<std::uint8_t>& token,
                                             std::string& error)>;

// Параметри побудови XAdES-підпису поверх XMLDSIG.
struct XadesParameters {
    XadesProfile profile{XadesProfile::BES};
    // XMLDSIG-частина: метод підпису, канонікалізація, посилання на дані.
    tamga::xmldsig::XmlSignatureParameters xml_params;
    // Опційний Id xades:SignedProperties. Якщо не задано, зберігається
    // історичний формат `<SignatureId>-signedprops`.
    std::string signed_properties_id;
    // Опційне пре-заповнення кваліфікуючих властивостей (політика,
    // DataObjectFormat; SigningTime генерується автоматично, якщо порожній).
    QualifyingProperties qualifying_properties;
    // DigestMethod для CertDigest у SigningCertificateV2.
    std::string cert_digest_uri{"http://www.w3.org/2001/04/xmldsig-more#gost34311"};
    // DigestMethod для ds:Reference на SignedProperties.
    std::string signed_properties_digest_uri{"http://www.w3.org/2001/04/xmldsig-more#gost34311"};
    // Постачальник timestamp-токена; обовʼязковий для profile >= T.
    TimestampProvider timestamp_provider;
    // Trust-матеріал для C/X-L (інʼєктується викликом; у продакшні — з
    // chain/revocation сервісів). CA-сертифікати ланцюга та revocation-дані.
    std::vector<std::vector<std::uint8_t>> certificate_chain;
    std::vector<std::vector<std::uint8_t>> crls;
    std::vector<std::vector<std::uint8_t>> ocsp_responses;
    // DigestMethod для CompleteCertificateRefs/RevocationRefs.
    std::string cert_refs_digest_uri{"http://www.w3.org/2001/04/xmldsig-more#gost34311"};
};

// Будівник XAdES-підписів: огортає XMLDSIG-підпис кваліфікуючими властивостями
// (SignedProperties), які покриваються власним ds:Reference у SignedInfo.
// Реалізація доступна лише у збірці з TAMGA_ENABLE_XML_SIGNATURES.
class XadesBuilder {
public:
    XadesBuilder(tamga::core::CryptoniteAdapter& crypto, tamga::core::TspClient& tsp);

    // Будує XAdES-BES (і, у наступних кроках, T/C/X/X-L/A) над xml.
    // Повертає false + error_message при помилці.
    bool Sign(const std::string& xml,
              const XadesParameters& params,
              const tamga::core::SigningKey& signing_key,
              std::string& signed_xml_out,
              std::string& error_message);

private:
    tamga::core::CryptoniteAdapter& crypto_;
    tamga::core::TspClient& tsp_;
};

}  // namespace tamga::xades
