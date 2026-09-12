#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::core::net {

// Універсальний авто-резолвер відкритого сертифіката для приватного ключа.
//
// Проблема: більшість українських КНЕДП (Вчасно, ІІТ, ДПС, ПриватБанк, МВС, Дія)
// видають контейнери `.dat` / `key-6.dat` / PKCS#12 DER, які містять ЛИШЕ
// закритий ключ (`pkcs8ShroudedKeyBag`), без `certBag`. Відкритий сертифікат
// користувач отримує окремим файлом або з реєстру КНЕДП. Без сертифіката
// `PreparePkcs12Signer` завершується з `RET_PKIX_NO_CERTIFICATE`, і підпис
// неможливий.
//
// Каскад пошуку (кожен наступний рівень тільки якщо попередній не дав результату):
//   Рівень 1 — явно переданий сертифікат (`explicit_certificate_der` /
//              `explicit_certificate_path`);
//   Рівень 2 — sidecar-файли поруч із ключем + локальний кеш
//              `<work_dir>/cert-cache/<sha256(spki)>.cer`;
//   Рівень 3 — мережеві fetcher-и КНЕДП (LDAP / CMP / HTTP-шлюзи ЦЗО).
//
// FAIL-CLOSED (§6 ТЗ): будь-який кандидат — локальний чи мережевий — приймається
// ЛИШЕ після `CryptoniteAdapter::CertificateMatchesPrivateKey`. Сертифікат, що не
// відповідає відкритому ключу контейнера, ніколи не повертається, тому підпис не
// може бути створений із чужим або підставленим сертифікатом.
struct CertificateResolveRequest {
    // Матеріал ключа так, як його бачить Session (для PKCS#12 — увесь контейнер).
    std::vector<std::uint8_t> key_material;
    std::string password;

    // Рівень 1: явні джерела. `der` має пріоритет над `path`.
    std::vector<std::uint8_t> explicit_certificate_der;
    std::string explicit_certificate_path;

    // Рівень 2: шлях до файлу ключа — база для sidecar-пошуку. Може бути порожнім
    // (ключ прийшов як base64/бінарний блоб) — тоді sidecar-крок пропускається.
    //
    // Шлях без каталогу (`key.dat`) трактується як файл у поточному каталозі
    // процесу — так само, як його читає сама сесія. Тобто sidecar-пошук працює
    // і для відносних шляхів, а не лише для абсолютних (Q-02).
    std::string key_file_path;
    // Каталог кешу; зазвичай `settings.work_dir`. Порожній — кеш не використовується.
    std::string work_dir;

    // Рівень 3 вмикається лише коли offline_mode=false.
    bool offline_mode{true};
    std::int32_t network_timeout_ms{10000};
    // Явно вказаний КНЕДП (з дескриптора або налаштувань сесії) — дає прямий
    // запит замість каскадного опитування всього реєстру.
    std::string preferred_ca_hint;

    // Рівень 3: точки видачі. Порожні поля означають «джерело не налаштоване» —
    // тоді відповідний крок просто пропускається.
    //
    // Адреси можна задати явно, а можна лишити порожніми — тоді вони беруться з
    // реєстру КНЕДП (`CAs.json` ЦЗО) за `preferred_ca_hint`. Явно задане завжди
    // має пріоритет над реєстром.
    std::string ldap_url;
    std::string ldap_base_dn;
    std::string http_certificate_url;
    std::string cmp_url;
    // ЄДРПОУ / ДРФО / CN для звуження LDAP-вибірки. Не обовʼязковий: остаточний
    // відбір усе одно робить звірка з відкритим ключем, а не фільтр каталогу.
    std::string subject_identifier;
    // Джерело реєстру КНЕДП; порожнє — `CaSettingsRegistry::DefaultUrl()`.
    std::string ca_registry_url;
};

struct CertificateResolveResult {
    bool succeeded{false};
    std::vector<std::uint8_t> certificate_der;
    // Звідки взято сертифікат: "explicit-der", "explicit-path", "sidecar",
    // "cache", "ldap", "cmp", "czo-http". Порожнє при невдачі.
    std::string source;
    // Шлях/URL конкретного джерела — для діагностики.
    std::string source_detail;
    // sha256 SPKI у hex — ключ кешу й стабільний ідентифікатор підписанта.
    std::string spki_sha256;
    // Скільки кандидатів було відкинуто через невідповідність ключу. Ненульове
    // значення — сигнал, що поруч лежать чужі сертифікати (а не що щось зламано).
    int rejected_candidates{0};
    std::string message;
};

class CertificateResolver final {
public:
    CertificateResolveResult Resolve(const CertificateResolveRequest& request) const;

    // Обчислює sha256(SPKI) у нижньому регістрі hex — публічно, бо цим самим
    // ключем іменуються файли в `cert-cache` і його зручно логувати.
    static bool ComputeSpkiFingerprint(const std::vector<std::uint8_t>& key_material,
                                       const std::string& password,
                                       std::string& fingerprint_hex,
                                       std::string& error_message);
};

}  // namespace tamga::core::net
