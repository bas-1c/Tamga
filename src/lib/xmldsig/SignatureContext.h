#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// WP-0 (заморожений контракт) — для WP-1/2/13/14/15.
//
// SignatureContext локалізує ОДИН ds:Signature і гарантує, що всі складові
// підпису (SignedInfo, SignatureValue, KeyInfo/X509Certificate,
// QualifyingProperties, references) беруться В МЕЖАХ цього вузла — захист від
// XML Signature Wrapping (CR-01).
//
// Контракт навмисно НЕ протікає libxml2-типами (xmlNodePtr тощо) у публічний
// інтерфейс (див. арх. зауваження A4): вузол адресується стабільним шляхом, а
// резолвлені фрагменти тримаються як байти/ідентифікатори. Реалізація — WP-1.

namespace tamga::xmldsig {

struct SignatureContext {
    // ds:Signature/@Id (може бути порожнім, якщо атрибут відсутній).
    std::string signature_id;

    // 0-based позиція цього ds:Signature серед усіх підписів документа.
    std::size_t signature_index{0};

    // Стабільний шлях до вузла ds:Signature (напр. XPath за позицією), який
    // обмежує подальші пошуки SignedInfo/SignatureValue/KeyInfo піддеревом.
    std::string signature_node_path;

    // Зареєстровані ID-атрибути документа для безпечного резолву #id з
    // контролем унікальності. Документ із дублікатом ID для referenced-
    // фрагмента має відхилятися.
    std::vector<std::string> registered_ids;
    bool has_duplicate_ids{false};

    // Сертифікат із KeyInfo/X509Certificate САМЕ цього підпису — той самий
    // обʼєкт, що передається у trust-валідацію (звʼязок crypto-cert == trust-cert).
    std::vector<std::uint8_t> signer_certificate_der;

    // Прапори, що підтверджують: складова знайдена у піддереві вузла, а не
    // глобальним «першим за local-name».
    bool signed_info_scoped{false};
    bool signature_value_scoped{false};
    bool key_info_scoped{false};
    bool qualifying_properties_scoped{false};
};

}  // namespace tamga::xmldsig
