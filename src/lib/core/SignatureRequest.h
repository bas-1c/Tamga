#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tamga::core {

// Формат підпису, який обирає виклик Session::Sign/Verify.
// CMS/CADES/ASICS/ASICE уже підтримуються наявними операціями; XADES/PADES
// додаються форматними підсистемами (ADR 012).
enum class SignatureFormat {
    CMS = 0,
    CADES,
    XADES,
    PADES,
    ASICS,
    ASICE,
};

// Матеріал ключа підписувача. Поля навмисно дзеркалять входи
// CryptoniteAdapter::SignDetached, щоб форматні модулі не вигадували власну
// абстракцію ключа і весь крипто-доступ лишався через адаптер.
struct SigningKey {
    bool use_pkcs12{false};
    std::vector<std::uint8_t> key_material;     // PKCS#12 контейнер або приватний ключ
    std::vector<std::uint8_t> certificate_der;  // сертифікат підписувача (DER)
    std::string password;                       // пароль контейнера, якщо є
};

// Уніфікований запит на підпис. Форматно-специфічні опції згруповані, але живуть
// в одному типі, щоб Session мав єдину точку входу для всіх форматів.
struct SignatureRequest {
    SignatureFormat format{SignatureFormat::CMS};
    bool detached{false};
    bool timestamp{false};
    bool long_term{false};

    // XMLDSIG / XAdES
    std::string xml_xpath;   // обмежений шаблон вузла для підпису/верифікації

    // PAdES
    std::string pdf_field_name;  // імʼя поля підпису у формі PDF

    // Профіль форматного рівня; конкретні enum-и оголошені у форматних модулях
    // (tamga::xades::XadesProfile, tamga::pades::PadesProfile). Зберігаємо як
    // рядок, щоб core не залежав від форматних заголовків.
    std::optional<std::string> profile_name;
};

}  // namespace tamga::core
