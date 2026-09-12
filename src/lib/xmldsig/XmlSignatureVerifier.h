#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlTransformEngine.h"

namespace tamga::core {
class CryptoniteAdapter;
}

namespace tamga::xmldsig {

struct XmlReferenceVerificationDetail {
    std::string uri;
    std::string type;
    std::string digest_method;
    std::string expected_base64;
    std::string expected_hex;
    std::string computed_base64;
    std::string computed_hex;
    std::string status;  // ok/mismatch/resolve-failed/transform-failed/digest-failed
    std::string error;
};

// Результат верифікації XMLDSIG: валідність підпису SignedInfo, валідність
// дайджестів посилань, ідентифікатор сертифіката та постатусний звіт по
// кожному ds:Reference.
struct XmlSignatureVerificationResult {
    bool signature_valid{false};
    bool digest_valid{false};
    std::string signing_cert_id;
    std::vector<std::string> reference_statuses;
    std::vector<XmlReferenceVerificationDetail> reference_details;
    std::size_t signed_info_canonicalized_length{0};
    std::string signed_info_hash_hex;
    std::string signed_info_hash_base64;
    std::size_t signed_properties_canonicalized_length{0};
    std::string signed_properties_hash_hex;
    std::string signed_properties_hash_base64;
    bool signature_value_valid{false};
    // true, коли підпис НЕ ПЕРЕВІРЕНО через відсутність алгоритму в цій збірці
    // (наприклад rsa-sha256 у діагностичній збірці vendor=OFF), а не через розбіжність.
    // Викликач зобовʼязаний розрізняти ці стани: «не змогли перевірити» — не те
    // саме, що «підпис невалідний», і політика реагує на них по-різному.
    bool signature_algorithm_unsupported{false};
    std::string signature_value_error;
};

// Перевіряє XMLDSIG-підпис: переобчислює дайджести посилань, канонікалізує
// SignedInfo і звіряє криптографічний підпис через CryptoniteAdapter.
class XmlSignatureVerifier {
public:
    XmlSignatureVerifier(XmlCanonicalizer& canonicalizer, XmlTransformEngine& transform_engine,
        XmlDigestEngine& digest_engine, tamga::core::CryptoniteAdapter& crypto);

    // Повна верифікація: переобчислення дайджестів усіх ds:Reference і звірка
    // підпису SignedInfo через CryptoniteAdapter::VerifyHash. Повертає false +
    // error_message лише при помилці обробки (парсинг/структура); результат
    // валідності — у result. true означає, що верифікація відпрацювала.
    bool Verify(const std::string& signed_xml,
                XmlSignatureVerificationResult& result,
                std::string& error_message);

    bool Verify(const std::string& signed_xml,
                const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                XmlSignatureVerificationResult& result,
                std::string& error_message);

    // WP-2: підтримка кількох ds:Signature в ОДНОМУ документі (на відміну
    // від ASiC-E multi-file co-signing, вже підтриманого на рівні Session).
    // Кожен верхньорівневий ds:Signature перевіряється НЕЗАЛЕЖНО зі своїм
    // власним SignedInfo/SignatureValue/SignedProperties/KeyInfo — жодні
    // складові не діляться між підписами. Повертає false + error_message
    // лише при структурній помилці (відсутність підписів, вкладений
    // ds:Signature, неоднозначна кількість SignedInfo/SignatureValue в межах
    // одного підпису — захист від wrapping); інакше results матиме по
    // одному запису на кожен ds:Signature в порядку документа, і кожен
    // запис несе власний (можливо invalid) вердикт.
    bool VerifyAll(const std::string& signed_xml,
                   const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                   std::vector<XmlSignatureVerificationResult>& results,
                   std::string& error_message);

private:
    // Залежності утримуються за посиланням — їх життєвий цикл належить виклику.
    XmlCanonicalizer& canonicalizer_;
    XmlTransformEngine& transform_engine_;
    XmlDigestEngine& digest_engine_;
    tamga::core::CryptoniteAdapter& crypto_;
};

}  // namespace tamga::xmldsig
