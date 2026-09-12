#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::core {

class PemDerLoader {
public:
    struct PemBlock {
        std::string type;
        std::vector<std::uint8_t> der_payload;
    };

    struct LoadOptions {
        bool strict_mode{false};
    };

    static bool Load(const std::vector<std::uint8_t>& input,
                     std::vector<std::uint8_t>& der_payload,
                     std::string& type,
                     std::string& error_message);

    static bool LoadAll(const std::vector<std::uint8_t>& input,
                        std::vector<PemBlock>& blocks,
                        std::string& error_message,
                        LoadOptions options);
};

class JksKeyStoreParser {
public:
    struct PrivateKeyEntry {
        std::string alias;
        std::vector<std::uint8_t> private_key_pkcs8;
        std::vector<std::uint8_t> certificate;
        std::vector<std::vector<std::uint8_t>> certificate_chain;
    };

    static bool LoadPrivateKeyEntry(const std::vector<std::uint8_t>& input,
                                    const std::string& store_password,
                                    const std::string& key_password,
                                    const std::string& preferred_alias,
                                    PrivateKeyEntry& entry,
                                    std::string& error_message);
};

// Власний (не PKCS#12 і не PKCS#8) контейнер закритого ключа АТ «ІІТ»,
// відомий як `Key-6.dat`. Структура:
//
//   SEQUENCE
//     SEQUENCE                       -- AlgorithmIdentifier
//       OID 1.3.6.1.4.1.19398.1.1.1.2
//       SEQUENCE
//         OCTET STRING (4)           -- mac: ГОСТ 28147-89 imit від відкритого тексту
//         OCTET STRING (0..7)        -- pad: добивання шифротексту до кратності 8
//     OCTET STRING                   -- зашифрований PKCS#8 PrivateKeyInfo
//
// Схема захисту (встановлена експериментально, звірена з референсною
// реалізацією dstucrypt/gost89 і підтверджена MAC-ом фікстури):
//   * ключ: h = ГОСТ 34.311(пароль); далі 9999 разів h = ГОСТ 34.311(h);
//     таблиця замін ГОСТ 28147 №1, синхропосилка — 32 нульові байти;
//   * шифр: ГОСТ 28147-89 у режимі простої заміни (ECB) над `cryptData || pad`;
//   * відкритий текст — перші `cryptData.size()` байтів результату;
//   * контроль пароля: 4-байтний imit ГОСТ 28147-89 від відкритого тексту на
//     тому ж ключі має збігтися з полем `mac`.
class IitKeyContainerParser {
public:
    // Чи схожий буфер на контейнер ІІТ: перший AlgorithmIdentifier несе OID
    // з приватної гілки 1.3.6.1.4.1.19398.1.1.1.2.
    static bool Matches(const std::vector<std::uint8_t>& input);

    // Розшифровує контейнер і віддає PKCS#8 PrivateKeyInfo у `pkcs8`.
    // Повертає `false` з поясненням українською, якщо структура пошкоджена,
    // пароль не підходить (не збігся imit) або збірка йде без cryptonite.
    static bool Decrypt(const std::vector<std::uint8_t>& input,
                        const std::string& password,
                        std::vector<std::uint8_t>& pkcs8,
                        std::string& error_message);
};

// Контейнер `.ZS2` АЦСК «Україна» (M.E.Doc/SOTA) — профіль PKCS#12 з «новою»
// українською криптографією. Оболонка стандартна (PFX v3, `AuthenticatedSafe`,
// `pkcs8ShroudedKeyBag`, PBES2/PBKDF2), тому розширення файла ні на що не
// впливає: формат розпізнається за OID алгоритмів захисту ключа.
//
//   PRF   1.2.804.2.1.1.1.1.2.2.4    ДСТУ 7564 «Купина-256» у режимі KMAC
//   шифр  1.2.804.2.1.1.1.1.1.3.5.2  ДСТУ 7624 «Калина-256/256» CBC, IV 32 Б
//
// Чому окремий парсер, а не `pkcs12_decode` з cryptonite: `pkcs5.c` приймає
// лише ГОСТ 28147 та AES-256 як шифр і HMAC-ГОСТ34311/SHA-1 як PRF, тож
// відхиляє контейнер із RET_STORAGE_UNSUPPORTED_ENC_SCHEME_ALG (rc=536) ще до
// спроби підпису. Розшифровуємо самі й віддаємо звичайний PKCS#8 — `vendor/`
// лишається недоторканим.
//
// Виведення ключа (звірено з референсними реалізаціями UAPKI `cm-pkcs12` і
// dstucrypt/dstucrypt-algos, підтверджено на реальному контейнері):
//
//   ключ KMAC = пароль у UTF-8, ДОПОВНЕНИЙ НУЛЯМИ РІВНО ДО 32 БАЙТІВ
//   U1 = KMAC(salt || 00 00 00 01);  Uj = KMAC(U(j-1));  dk = U1 xor ... xor Un
//
// Саме доповнення пароля нулями відрізняє цю схему від звичайного
// PBKDF2 з KMAC як PRF — без нього ключ виходить інший.
class Zs2KeyContainerParser {
public:
    // Чи є буфер PKCS#12, у якому перший `pkcs8ShroudedKeyBag` захищено
    // Купиною-KMAC і Калиною. Пароль не потрібен.
    static bool Matches(const std::vector<std::uint8_t>& input);

    // Розшифровує ПЕРШИЙ ключовий мішок і віддає PKCS#8 `PrivateKeyInfo`.
    //
    // «Універсальний» контейнер (`DU`) містить два ключі — підпису і протоколів
    // розподілу ключів; перший мішок є ключем підпису. Якщо потрібен другий,
    // невідповідність виявить звірка з сертифікатом, а не тиха підміна.
    static bool Decrypt(const std::vector<std::uint8_t>& input,
                        const std::string& password,
                        std::vector<std::uint8_t>& pkcs8,
                        std::string& error_message);
};

} // namespace tamga::core
