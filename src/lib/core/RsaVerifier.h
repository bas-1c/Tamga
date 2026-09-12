#pragma once

#include <cstdint>
#include <string>
#include <vector>

// B-3: перевірка RSASSA-PKCS1-v1_5 підписів (rsa-sha256/384/512).
//
// Попередня оцінка цього модуля була помилковою: у cryptonite вже існує повний
// RSA-примітив, а прогалина була в PKIX VerifyAdapter та OID-таблиці. Локальний
// vendor-патч додає `rsaEncryption`/`sha*WithRSAEncryption`, розбирає
// RSAPublicKey із SubjectPublicKeyInfo і делегує verify_hash у `rsa_*`.
//
// На Windows production-поведінка лишається незмінною: CNG (bcrypt + crypt32)
// є основним backend. Cryptonite-шлях перевірено на тому самому реальному TL і
// використано поза Windows, тому OpenSSL/libcrypto не додається.
//
// Поза Windows перевірка доступна, коли збірку виконано зі стандартним
// `TAMGA_ENABLE_VENDOR_CRYPTONITE=ON`. У діагностичному режимі OFF функція
// повертає `executed=false`, не підміняючи результат.
//
// Чому не OpenSSL: проєкт свідомо не залежить від OpenSSL/libcrypto (див.
// коментар у CMakeLists.txt біля vendor/cryptonite) — уся криптографія йде через
// vendored cryptonite. Додавати цю залежність заради одного алгоритму на
// платформі, яка не є основним шляхом постачання (MSVC + 1С під Windows),
// невиправдано; RSA тепер проходить через уже vendored cryptonite.

namespace tamga::core {

enum class RsaHashAlg {
    Sha256,
    Sha384,
    Sha512,
};

struct RsaVerifyResult {
    // Перевірку було ВИКОНАНО (платформа підтримується, ключ розібрано).
    // false означає «не змогли перевірити», а НЕ «підпис невалідний».
    bool executed{false};
    bool valid{false};
    std::string message;
};

// Перевіряє PKCS#1 v1.5 підпис `signature` над готовим дайджестом `digest`
// відкритим ключем із `certificate_der`.
//
// FAIL-CLOSED: будь-яка неможливість виконати перевірку (не та платформа, не
// RSA-ключ, битий сертифікат) дає executed=false + valid=false. Викликач
// зобовʼязаний розрізняти ці стани й НЕ трактувати executed=false як успіх.
RsaVerifyResult VerifyRsaPkcs1(const std::vector<std::uint8_t>& certificate_der,
                               RsaHashAlg hash_alg,
                               const std::vector<std::uint8_t>& digest,
                               const std::vector<std::uint8_t>& signature);

// true, якщо SubjectPublicKeyInfo сертифіката несе RSA-ключ (OID
// rsaEncryption 1.2.840.113549.1.1.1). Дозволяє обрати гілку перевірки до того,
// як витрачати роботу на канонікалізацію.
bool CertificateHasRsaPublicKey(const std::vector<std::uint8_t>& certificate_der);

}  // namespace tamga::core
