#include "core/cryptonite/Signer.h"

#include "core/cryptonite/CertUtil.h"

#include <utility>

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "storage_errors.h"
}

namespace tamga::core::cryptonite_detail {

std::string BuildSignerPreparationError(const bool use_pkcs12, const int rc) {
    if (rc == kRcSignerCertificateForbidsSigning) {
        return "Certificate keyUsage does not allow signing (no digitalSignature or nonRepudiation): "
               "this looks like the key-agreement certificate of the container, "
               "use the signing certificate instead";
    }
    if (rc == RET_STORAGE_CERT_NOT_FOUND || rc == RET_PKIX_NO_CERTIFICATE) {
        return "Не знайдено відкритий сертифікат для закритого ключа. "
               "Покладіть файл сертифіката (.cer/.crt) поруч із ключем або передайте "
               "через параметр certificatePath";
    }
    return BuildRcError(use_pkcs12 ? "pkcs12 signer preparation" : "pkcs8 signer preparation", rc);
}

namespace {

// Вибирає в контейнері саме той закритий ключ, якому відповідає `cert`.
//
// Навіщо. Українські КНЕДП («Вчасно», ДПС, ІІТ) видають «універсальні»
// контейнери з ДВОМА закритими ключами: ключем підпису (digitalSignature,
// nonRepudiation) і ключем протоколів розподілу ключів (keyAgreement,
// dataEncipherment). `pkcs12_select_key(ctx, nullptr, pwd)` бере ПЕРШИЙ ключ у
// контейнері. Поки ключ підпису лежить першим, це збігається з потрібним; коли
// порядок зворотний, підпис падає з RET_PKIX_NO_CERTIFICATE («сертифікат не
// відповідає закритому ключу»), хоча сертифікат правильний, і причина не видима
// користувачеві.
//
// Критерій відбору. `SignAdapter::set_cert` через `check_cert_corresponding`
// звіряє SubjectPublicKeyInfo сертифіката з відкритим ключем, обчисленим із
// вибраного закритого. Тобто вдалий `set_cert` — це вже готова відповідь «це
// той ключ», і окрема ручна звірка ключів не потрібна.
//
// Межі. `check_cert_corresponding` приймає інший сертифікат того самого
// відкритого ключа, але відхиляє сертифікат чужого ключа; наявність certBag не
// змінює математичний критерій. Ключі з однаковим alias у cryptonite
// нерозрізненні (`store_alias2key` шукає за іменем), тому повтори alias-ів
// пропускаються.
//
// Повертає true, якщо потрібний ключ знайдено і лишається вибраним у `pkcs12`.
bool SelectKeyMatchingCertificate(Pkcs12Ctx* pkcs12, const char* password, const Certificate_t* cert) {
    const Pkcs12Keypair* keys = nullptr;
    size_t key_count = 0;
    if (pkcs12_enum_keys(pkcs12, &keys, &key_count) != RET_OK || keys == nullptr || key_count < 2) {
        // Один ключ або перелік недоступний — вибирати нема з чого, хай працює
        // звичайний шлях.
        return false;
    }

    std::vector<std::string> tried_aliases;
    tried_aliases.reserve(key_count);
    for (size_t i = 0; i < key_count; ++i) {
        const char* const alias = keys[i].alias;
        if (alias == nullptr) {
            continue;
        }
        if (std::find(tried_aliases.begin(), tried_aliases.end(), alias) != tried_aliases.end()) {
            continue;
        }
        tried_aliases.emplace_back(alias);

        if (pkcs12_select_key(pkcs12, alias, password) != RET_OK) {
            continue;
        }

        SignAdapter* probe_raw = nullptr;
        if (pkcs12_get_sign_adapter(pkcs12, &probe_raw) != RET_OK) {
            continue;
        }
        ScopedSignAdapter probe(probe_raw, sign_adapter_free);
        if (probe->set_cert == nullptr) {
            continue;
        }
        if (probe->set_cert(probe.get(), cert) == RET_OK) {
            return true;
        }
    }

    return false;
}

}  // namespace

int PreparePkcs12Signer(const std::vector<std::uint8_t>& key_material,
                        const std::string& password,
                        const std::vector<std::uint8_t>& fallback_certificate_der,
                        SignAdapter** sign_adapter,
                        Certificate_t** certificate) {
    ScopedSignAdapter scoped_sign_adapter(nullptr, sign_adapter_free);
    *certificate = nullptr;

    ScopedByteArray key_ba(MakeByteArray(key_material), ba_free);
    if (key_ba == nullptr) {
        return RET_MEMORY_ALLOC_ERROR;
    }

    const char* const pwd = password.empty() ? nullptr : password.c_str();

    Pkcs12Ctx* pkcs12_raw = nullptr;
    int rc = pkcs12_decode("Tamga", key_ba.get(), pwd, &pkcs12_raw);
    if (rc != RET_OK) {
        return rc;
    }
    ScopedPkcs12Ctx pkcs12(pkcs12_raw, pkcs12_free);

    // Сертифікат, знайдений поза контейнером, розбираємо ДО вибору ключа: він
    // потрібен двічі — спершу як критерій вибору потрібного закритого ключа,
    // потім як сертифікат підписанта.
    ScopedCert external_cert(nullptr, cert_free);
    int external_cert_rc = RET_OK;
    if (!fallback_certificate_der.empty()) {
        ScopedByteArray external_cert_ba(MakeByteArray(fallback_certificate_der), ba_free);
        ScopedCert decoded(cert_alloc(), cert_free);
        if (external_cert_ba == nullptr || decoded == nullptr) {
            return RET_MEMORY_ALLOC_ERROR;
        }
        external_cert_rc = cert_decode(decoded.get(), external_cert_ba.get());
        if (external_cert_rc == RET_OK) {
            external_cert = std::move(decoded);
        }
    }

    // Без сертифіката від викликача поведінка не змінюється: перший ключ.
    if (external_cert == nullptr ||
        !SelectKeyMatchingCertificate(pkcs12.get(), pwd, external_cert.get())) {
        rc = pkcs12_select_key(pkcs12.get(), nullptr, pwd);
        if (rc != RET_OK) {
            return rc;
        }
    }

    SignAdapter* sign_adapter_raw = nullptr;
    rc = pkcs12_get_sign_adapter(pkcs12.get(), &sign_adapter_raw);
    if (rc != RET_OK) {
        return rc;
    }
    scoped_sign_adapter.reset(sign_adapter_raw);

    ScopedCert cert(nullptr, cert_free);
    bool certificate_is_external = false;
    if (external_cert != nullptr) {
        // Явний/автоматично знайдений сертифікат є критерієм вибору ключа і
        // сертифікатом підписанта. Це важливо для перевиданого сертифіката:
        // certBag може містити старий сертифікат того самого відкритого ключа.
        cert = std::move(external_cert);
        certificate_is_external = true;
    } else {
        ByteArray* cert_ba_raw = nullptr;
        rc = pkcs12_get_certificate(pkcs12.get(), KEY_USAGE_DIGITAL_SIGNATURE, &cert_ba_raw);
        if (rc != RET_OK || cert_ba_raw == nullptr) {
            ba_free(cert_ba_raw);
            cert_ba_raw = nullptr;
            rc = pkcs12_get_certificate(pkcs12.get(), 0, &cert_ba_raw);
        }
        ScopedByteArray cert_ba(cert_ba_raw, ba_free);

        // Контейнер без certBag — типовий випадок для `.dat` українських КНЕДП
        // і для `.ZS2`. Сертифікат до такого ключа добирає авто-резолвер сесії
        // (явний шлях -> sidecar -> кеш -> LDAP/CMP) і приймає його лише після
        // звірки SubjectPublicKeyInfo, тому тут він уже довірений.
        if (external_cert_rc != RET_OK) {
            // Сертифікат від викликача є, але не розбирається — саме ця
            // помилка інформативніша за «немає сертифіката».
            return external_cert_rc;
        }
        if (rc != RET_OK || cert_ba == nullptr) {
            return rc == RET_OK ? RET_PKIX_NO_CERTIFICATE : rc;
        }
        cert.reset(cert_alloc());
        if (cert == nullptr) {
            return RET_MEMORY_ALLOC_ERROR;
        }

        rc = cert_decode(cert.get(), cert_ba.get());
        if (rc != RET_OK) {
            return rc;
        }
    }

    // Гейт призначення ключа. Стоїть ПІСЛЯ вибору ключа і ДО побудови
    // підписувача, і перевіряє саме той сертифікат, яким підписуватимемо, —
    // байдуже, прийшов він ззовні чи з certBag.
    //
    // Навіщо. Вибір ключа за сертифікатом (див. `SelectKeyMatchingCertificate`)
    // зняв обмеження «лише перший ключ», і разом з ним зникла ВИПАДКОВА
    // перешкода: сертифікат ключа протоколів розподілу ключів із того самого
    // «універсального» контейнера тепер теж знаходить свій ключ. Без цього
    // гейта Tamga мовчки поставила б підпис ключем, який за призначенням
    // підписувати не має права: виміряно 2026-09-02 на ключі КНЕДП «Вчасно» —
    // `--cert CA-…194A3800.cer` (keyUsage=keyAgreement, critical) давав CMS
    // 2876 Б замість відмови. Такий підпис відхилить будь-який валідатор, а
    // користувач не побачив би причини.
    //
    // Відсутнє розширення keyUsage — не привід відмовляти (RFC 5280 його не
    // вимагає), див. `CertificateAllowsSigning`.
    if (!CertificateAllowsSigning(cert.get())) {
        return kRcSignerCertificateForbidsSigning;
    }

    if (certificate_is_external) {
        // Повернути сертифікат окремим out-параметром недостатньо: `SignAdapter`
        // із PKCS#12 без certBag не має сертифіката всередині, і наступний крок
        // `esigner_info_alloc()` падає з RET_PKIX_NO_CERTIFICATE (rc=272).
        // Сертифікат треба покласти в сам адаптер. `set_cert` копіює його і
        // додатково звіряє відповідність закритому ключу
        // (`check_cert_corresponding`), тобто це ще один fail-closed гейт, а не
        // просто присвоєння.
        if (scoped_sign_adapter->set_cert == nullptr) {
            return RET_PKIX_NO_CERTIFICATE;
        }
        rc = scoped_sign_adapter->set_cert(scoped_sign_adapter.get(), cert.get());
        if (rc != RET_OK) {
            return rc;
        }
    }

    *sign_adapter = scoped_sign_adapter.release();
    *certificate = cert.release();
    return RET_OK;
}

int PreparePkcs8Signer(const std::vector<std::uint8_t>& key_material,
                       const std::vector<std::uint8_t>& certificate_der,
                       SignAdapter** sign_adapter,
                       Certificate_t** certificate) {
    ScopedSignAdapter scoped_sign_adapter(nullptr, sign_adapter_free);
    *certificate = nullptr;

    if (certificate_der.empty()) {
        return RET_PKIX_NO_CERTIFICATE;
    }

    ScopedByteArray key_ba(MakeByteArray(key_material), ba_free);
    ScopedByteArray cert_ba(MakeByteArray(certificate_der), ba_free);
    if (key_ba == nullptr || cert_ba == nullptr) {
        return RET_MEMORY_ALLOC_ERROR;
    }

    ScopedPkcs8 pkcs8(pkcs8_alloc(), pkcs8_free);
    if (pkcs8 == nullptr) {
        return RET_MEMORY_ALLOC_ERROR;
    }

    int rc = pkcs8_decode(pkcs8.get(), key_ba.get());
    if (rc != RET_OK) {
        return rc;
    }

    ScopedCert cert(cert_alloc(), cert_free);
    if (cert == nullptr) {
        return RET_MEMORY_ALLOC_ERROR;
    }

    rc = cert_decode(cert.get(), cert_ba.get());
    if (rc != RET_OK) {
        return rc;
    }

    // Той самий гейт призначення ключа, що й у PKCS#12: сертифікат ключа
    // шифрування не має підписувати нічим, незалежно від формату контейнера
    // (JKS/PEM/PKCS#8 сюди приходять так само).
    if (!CertificateAllowsSigning(cert.get())) {
        return kRcSignerCertificateForbidsSigning;
    }

    SignAdapter* sign_adapter_raw = nullptr;
    rc = pkcs8_get_sign_adapter(pkcs8.get(), cert_ba.get(), &sign_adapter_raw);
    if (rc != RET_OK) {
        return rc;
    }
    scoped_sign_adapter.reset(sign_adapter_raw);

    *sign_adapter = scoped_sign_adapter.release();
    *certificate = cert.release();
    return RET_OK;
}

}  // namespace tamga::core::cryptonite_detail

#endif  // TAMGA_CRYPTONITE_ENABLED
