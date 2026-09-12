#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// ТЗ Рівень 3: мережеві джерела кандидатів на сертифікат підписувача.
//
// Роль цих класів навмисно вузька — ЗНАЙТИ кандидатів і віддати їх як DER.
// Рішення «прийняти» лишається за `CertificateResolver`, який пропускає кожного
// кандидата через `CertificateMatchesPrivateKey`. Тобто мережеве джерело не може
// підсунути чужий сертифікат: воно взагалі не має права нічого приймати.
//
// Через це коректність Рівня 3 перевіряється тестами без живої мережі —
// достатньо підмінити транспорт (той самий прийом, що `HttpClient::ScopedMockTransport`).

namespace tamga::core::net {

struct CertificateFetchRequest {
    // LDAP: ldap://host[:port][/base-dn]; HTTP: http(s)://…
    std::string url;
    // LDAP base DN, якщо не заданий у самому URL.
    std::string base_dn;
    // ЄДРПОУ / ДРФО / CN — звужує вибірку. Порожній рядок означає «взяти все, що
    // віддає каталог»: це припустимо, бо остаточний відбір усе одно робить
    // звірка з відкритим ключем, а не фільтр.
    std::string subject_hint;
    std::int32_t timeout_ms{10000};
};

struct CertificateFetchResult {
    // Запит було ВИКОНАНО (джерело доступне, відповідь розібрано). false означає
    // «не змогли запитати», а не «сертифіката немає».
    bool executed{false};
    std::vector<std::vector<std::uint8_t>> candidates;
    std::string message;
};

using CertificateFetchTransport = std::function<CertificateFetchResult(const CertificateFetchRequest&)>;

// LDAP-каталог КНЕДП (`userCertificate;binary`). Реалізація — winldap на Windows;
// на інших платформах повертає executed=false, а не вдає порожній результат.
class LdapCertificateFetcher final {
public:
    static CertificateFetchResult Fetch(const CertificateFetchRequest& request);

    // Підміна транспорту для тестів. Живої LDAP-служби в CI немає, тож перевіряти
    // треба саме поведінку резолвера навколо fetch-а — насамперед те, що
    // невідповідний ключу кандидат із мережі відхиляється.
    class ScopedMockTransport final {
    public:
        explicit ScopedMockTransport(CertificateFetchTransport transport);
        ~ScopedMockTransport();
        ScopedMockTransport(const ScopedMockTransport&) = delete;
        ScopedMockTransport& operator=(const ScopedMockTransport&) = delete;
    };
};

// CMP over HTTP (RFC 4210 + RFC 6712). Адреса береться з `CAs.json` ЦЗО
// (`cmpAddress`) — у довірчому списку її немає.
//
// Надсилається `genm` із **стандартним** infoType `id-it-caCerts`
// (1.3.6.1.5.5.7.4.17, RFC 4210 §5.3.19.15). Це свідомий вибір: він повністю
// специфікований і не вимагає вендорного профілю конкретного КНЕДП.
//
// Обмеження назване прямо: `id-it-caCerts` повертає сертифікати САМОГО КНЕДП,
// а не сертифікат користувача. Отримання власного сертифіката за ключем вимагає
// вендорного профілю з доказом володіння, який без облікового запису в
// конкретного надавача перевірити неможливо, і вигадувати його тут не будемо.
// Практична користь усе одно є: сертифікати КНЕДП добудовують ланцюг, а якщо
// каталог поверне придатний сертифікат — його прийме та сама звірка з ключем.
class CmpCertificateFetcher final {
public:
    static CertificateFetchResult Fetch(const CertificateFetchRequest& request);

    class ScopedMockTransport final {
    public:
        explicit ScopedMockTransport(CertificateFetchTransport transport);
        ~ScopedMockTransport();
        ScopedMockTransport(const ScopedMockTransport&) = delete;
        ScopedMockTransport& operator=(const ScopedMockTransport&) = delete;
    };

    // Кодує тіло запиту genm/id-it-caCerts. Винесено в API, щоб структуру
    // повідомлення можна було перевірити тестом без мережі.
    static std::vector<std::uint8_t> BuildCaCertsGenMessage();

    // Виловлює всі X.509-сертифікати з довільної DER-відповіді. Структуру
    // перевіряє cryptonite (`IsCertificateDer`), а не власний ASN.1-парсер:
    // повний розбір PKIMessage тут не потрібен, а сурогатний був би зайвим
    // місцем для помилок.
    static std::vector<std::vector<std::uint8_t>> HarvestCertificates(
        const std::vector<std::uint8_t>& der_blob);
};

// HTTP(S)-точка видачі: одиночний DER/PEM або PKCS#7 (`.p7b`) із набором.
class HttpCertificateFetcher final {
public:
    static CertificateFetchResult Fetch(const CertificateFetchRequest& request);

    class ScopedMockTransport final {
    public:
        explicit ScopedMockTransport(CertificateFetchTransport transport);
        ~ScopedMockTransport();
        ScopedMockTransport(const ScopedMockTransport&) = delete;
        ScopedMockTransport& operator=(const ScopedMockTransport&) = delete;
    };
};

}  // namespace tamga::core::net
