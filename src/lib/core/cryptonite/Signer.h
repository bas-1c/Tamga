#pragma once

// Побудова sign-адаптера з контейнера приватного ключа (PKCS#12/`.dat` або
// «голий» PKCS#8) разом із сертифікатом підписанта.
//
// Виділено з CryptoniteAdapter.cpp (O-01). Потрібне і для підпису (SignOps.cpp),
// і для витягання SubjectPublicKeyInfo з ключа (KeyPairing.cpp), тому спільне.

#include "core/cryptonite/Internal.h"

#if TAMGA_CRYPTONITE_ENABLED

namespace tamga::core::cryptonite_detail {

// ВЛАСНИЙ код Tamga, не з cryptonite: сертифікат підписанта має розширення
// keyUsage, і воно не дозволяє підпис (немає ні `digitalSignature`, ні
// `nonRepudiation`). Типовий випадок — сертифікат ключа протоколів розподілу
// ключів з «універсального» контейнера КНЕДП.
//
// Значення від'ємне свідомо: усі коди cryptonite додатні, тож зіткнення
// неможливе, а `BuildSignerPreparationError` розпізнає його однозначно.
inline constexpr int kRcSignerCertificateForbidsSigning = -1001;

// Повідомлення про збій побудови signer-а. Власні коди Tamga дістають людський
// текст, коди cryptonite — стандартний `BuildRcError`. Одне місце на всі три
// точки виклику в SignOps.cpp.
std::string BuildSignerPreparationError(bool use_pkcs12, int rc);

// Повертають RET_OK і передають володіння `*sign_adapter` / `*certificate`
// викликачеві. При помилці обидва out-параметри лишаються nullptr.
// `fallback_certificate_der` — сертифікат, знайдений поза контейнером
// (явний шлях, sidecar `.cer`, кеш, LDAP/CMP). Використовується ЛИШЕ тоді, коли
// в самому PKCS#12 немає certBag: інакше підпис контейнерами без сертифіката
// (`.dat` КНЕДП, `.ZS2`) відмовляв із RET_STORAGE_CERT_NOT_FOUND навіть після
// успішної роботи авто-резолвера.
int PreparePkcs12Signer(const std::vector<std::uint8_t>& key_material,
                        const std::string& password,
                        const std::vector<std::uint8_t>& fallback_certificate_der,
                        SignAdapter** sign_adapter,
                        Certificate_t** certificate);

int PreparePkcs8Signer(const std::vector<std::uint8_t>& key_material,
                       const std::vector<std::uint8_t>& certificate_der,
                       SignAdapter** sign_adapter,
                       Certificate_t** certificate);

}  // namespace tamga::core::cryptonite_detail

#endif  // TAMGA_CRYPTONITE_ENABLED
