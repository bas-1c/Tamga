// Відношення «цей сертифікат належить цьому приватному ключу».
//
// Виділено з CryptoniteAdapter.cpp (O-01). Тут зібрано ЄДИНИЙ математичний
// критерій належності (порівняння SubjectPublicKeyInfo) і всі його споживачі:
// авто-резолвер сертифікатів і вибір сертифіката з ланцюга JKS (див. O-03).

#include "core/cryptonite/Internal.h"
#include "core/cryptonite/KeyPairing.h"
#include "core/cryptonite/Signer.h"

namespace tamga::core {

// Внутрішні помічники реалізації видимі без кваліфікації: код перенесено з
// CryptoniteAdapter.cpp без єдиної правки тіл функцій, тому директива тут
// свідома — вона обмежена цим TU і не впливає на публічний контракт.
using namespace cryptonite_detail;

namespace {
#if TAMGA_CRYPTONITE_ENABLED

// Кодує SubjectPublicKeyInfo_t у DER. Повертає false і лишає out незмінним при збої.
bool EncodeSpki(const SubjectPublicKeyInfo_t* spki, std::vector<std::uint8_t>& out) {
    if (spki == nullptr) {
        return false;
    }
    ByteArray* encoded_raw = nullptr;
    const int rc = asn_encode_ba(&SubjectPublicKeyInfo_desc, spki, &encoded_raw);
    ScopedByteArray encoded(encoded_raw, ba_free);
    if (rc != RET_OK || encoded == nullptr) {
        return false;
    }
    AssignFromByteArray(encoded.get(), out);
    return !out.empty();
}

// Витягує SPKI з контейнера БЕЗ вимоги наявності сертифіката. Саме цим цей шлях
// відрізняється від PreparePkcs12Signer: той падає з RET_PKIX_NO_CERTIFICATE, коли
// в контейнері немає certBag, — а це рівно той випадок, який обслуговує авто-резолвер.
//
// Порядок спроб: PKCS#12/.dat (pkcs12_get_sign_adapter -> get_pub_key), потім
// «голий» PKCS#8 (pkcs8_get_spki). Обидві функції cryptonite працюють без cert.
//
// `all_keys`:
//   false — лише ПЕРШИЙ ключ контейнера (`pkcs12_select_key(ctx, nullptr, pwd)`).
//           Це ідентифікатор контейнера для кешу `cert-cache/<sha256(spki)>.cer`,
//           і він має лишатися стабільним.
//   true  — SPKI УСІХ ключів. «Універсальні» контейнери КНЕДП містять два ключі
//           (підпис і протоколи розподілу ключів), і сертифікат підписанта може
//           відповідати другому з них.
int CollectSpkiFromKeyContainer(const std::vector<std::uint8_t>& key_material,
                                const std::string& password,
                                bool all_keys,
                                std::vector<std::vector<std::uint8_t>>& spki_list) {
    spki_list.clear();

    ScopedByteArray key_ba(MakeByteArray(key_material), ba_free);
    if (key_ba == nullptr) {
        return RET_MEMORY_ALLOC_ERROR;
    }

    const char* const pwd = password.empty() ? nullptr : password.c_str();

    // 1) PKCS#12 / .dat
    Pkcs12Ctx* pkcs12_raw = nullptr;
    int rc = pkcs12_decode("Tamga", key_ba.get(), pwd, &pkcs12_raw);
    if (rc == RET_OK && pkcs12_raw != nullptr) {
        ScopedPkcs12Ctx pkcs12(pkcs12_raw, pkcs12_free);

        // SPKI ключа, ВИБРАНОГО в сховищі.
        const auto append_selected_key_spki = [&pkcs12, &spki_list]() -> int {
            SignAdapter* adapter_raw = nullptr;
            int rc_local = pkcs12_get_sign_adapter(pkcs12.get(), &adapter_raw);
            if (rc_local != RET_OK || adapter_raw == nullptr) {
                return rc_local == RET_OK ? RET_INVALID_PARAM : rc_local;
            }
            ScopedSignAdapter adapter(adapter_raw, sign_adapter_free);
            if (adapter->get_pub_key == nullptr) {
                return RET_INVALID_PARAM;
            }
            SubjectPublicKeyInfo_t* pub_key_raw = nullptr;
            rc_local = adapter->get_pub_key(adapter.get(), &pub_key_raw);
            ScopedSpki pub_key(pub_key_raw, FreeSpki);
            if (rc_local != RET_OK || pub_key == nullptr) {
                return rc_local == RET_OK ? RET_INVALID_PARAM : rc_local;
            }
            std::vector<std::uint8_t> encoded;
            if (!EncodeSpki(pub_key.get(), encoded)) {
                return RET_INVALID_PARAM;
            }
            spki_list.push_back(std::move(encoded));
            return RET_OK;
        };

        std::vector<std::string> aliases;
        if (all_keys) {
            const Pkcs12Keypair* keys = nullptr;
            size_t key_count = 0;
            if (pkcs12_enum_keys(pkcs12.get(), &keys, &key_count) == RET_OK && keys != nullptr) {
                for (size_t i = 0; i < key_count; ++i) {
                    if (keys[i].alias == nullptr) {
                        continue;
                    }
                    // Ключі з однаковим alias у cryptonite нерозрізненні
                    // (`store_alias2key` шукає за іменем), тому повтори пропускаємо.
                    if (std::find(aliases.begin(), aliases.end(), keys[i].alias) != aliases.end()) {
                        continue;
                    }
                    aliases.emplace_back(keys[i].alias);
                }
            }
        }

        // Порожній список alias-ів (один ключ, перелік недоступний або
        // all_keys=false) — поточний шлях «перший ключ».
        if (aliases.empty()) {
            rc = pkcs12_select_key(pkcs12.get(), nullptr, pwd);
            if (rc != RET_OK) {
                return rc;
            }
            return append_selected_key_spki();
        }

        for (const auto& alias : aliases) {
            if (pkcs12_select_key(pkcs12.get(), alias.c_str(), pwd) != RET_OK) {
                continue;
            }
            // Збій на окремому ключі не має ховати решту ключів контейнера.
            (void)append_selected_key_spki();
        }
        return spki_list.empty() ? RET_INVALID_PARAM : RET_OK;
    }

    // 2) «Голий» PKCS#8 (уже розшифрований на етапі нормалізації контейнера).
    ScopedPkcs8 pkcs8(pkcs8_alloc(), pkcs8_free);
    if (pkcs8 == nullptr) {
        return RET_MEMORY_ALLOC_ERROR;
    }
    rc = pkcs8_decode(pkcs8.get(), key_ba.get());
    if (rc != RET_OK) {
        return rc;
    }
    // SPKI беремо через sign-адаптер — ТАК САМО, як у гілці PKCS#12 вище.
    //
    // Раніше тут стояв pkcs8_get_spki, і його результат виявився НЕПОРІВНЯННИМ
    // із SPKI сертифіката: для реального ключа з JKS він давав 72 байти, що
    // закінчуються OCTET STRING, тоді як SPKI сертифіката — 136 байтів із
    // BIT STRING. Через це CertificateMatchesPrivateKey відхиляв ЛЕГІТИМНИЙ
    // сертифікат, а з ним і весь авто-резолвер для PKCS#8/JKS-ключів: гейт
    // приймання один, і він відкидав усе. Для PKCS#12 дефект не проявлявся, бо
    // там уже використовувався get_pub_key.
    //
    // Що це справді був хибний негатив, доведено незалежно: підпис цим ключем
    // перевіряється тим самим сертифікатом (interop-diag --verify-pairing).
    SignAdapter* pkcs8_adapter_raw = nullptr;
    rc = pkcs8_get_sign_adapter(pkcs8.get(), nullptr, &pkcs8_adapter_raw);
    if (rc != RET_OK || pkcs8_adapter_raw == nullptr) {
        return rc == RET_OK ? RET_INVALID_PARAM : rc;
    }
    ScopedSignAdapter pkcs8_adapter(pkcs8_adapter_raw, sign_adapter_free);
    if (pkcs8_adapter->get_pub_key == nullptr) {
        return RET_INVALID_PARAM;
    }
    SubjectPublicKeyInfo_t* pub_key_from_pkcs8_raw = nullptr;
    rc = pkcs8_adapter->get_pub_key(pkcs8_adapter.get(), &pub_key_from_pkcs8_raw);
    ScopedSpki pub_key_from_pkcs8(pub_key_from_pkcs8_raw, FreeSpki);
    if (rc != RET_OK || pub_key_from_pkcs8 == nullptr) {
        return rc == RET_OK ? RET_INVALID_PARAM : rc;
    }
    std::vector<std::uint8_t> pkcs8_spki;
    if (!EncodeSpki(pub_key_from_pkcs8.get(), pkcs8_spki)) {
        return RET_INVALID_PARAM;
    }
    spki_list.push_back(std::move(pkcs8_spki));
    return RET_OK;
}

// SPKI ПЕРШОГО ключа контейнера — ідентифікатор контейнера для кешу і діагностики.
int ExtractSpkiFromKeyContainer(const std::vector<std::uint8_t>& key_material,
                                const std::string& password,
                                std::vector<std::uint8_t>& spki_der) {
    std::vector<std::vector<std::uint8_t>> spki_list;
    const int rc = CollectSpkiFromKeyContainer(key_material, password, /*all_keys=*/false, spki_list);
    if (rc != RET_OK) {
        return rc;
    }
    if (spki_list.empty()) {
        return RET_INVALID_PARAM;
    }
    spki_der = std::move(spki_list.front());
    return RET_OK;
}

#endif  // TAMGA_CRYPTONITE_ENABLED
}  // namespace

bool CryptoniteAdapter::ExtractSubjectPublicKeyInfo(const std::vector<std::uint8_t>& key_material,
                                                    const std::string& password,
                                                    std::vector<std::uint8_t>& spki_der,
                                                    std::string& error_message) {
    spki_der.clear();
#if TAMGA_CRYPTONITE_ENABLED
    if (key_material.empty()) {
        error_message = "ExtractSubjectPublicKeyInfo: key material is empty";
        return false;
    }

    const int rc = ExtractSpkiFromKeyContainer(key_material, password, spki_der);
    if (rc != RET_OK || spki_der.empty()) {
        spki_der.clear();
        error_message = BuildRcError("ExtractSubjectPublicKeyInfo: private key decode", rc);
        return false;
    }
    return true;
#else
    (void)key_material;
    (void)password;
    error_message = "ExtractSubjectPublicKeyInfo requires a cryptonite-enabled build";
    return false;
#endif
}

bool CryptoniteAdapter::ExtractCertificateSubjectPublicKeyInfo(
    const std::vector<std::uint8_t>& certificate_der,
    std::vector<std::uint8_t>& spki_der,
    std::string& error_message) {
    spki_der.clear();
#if TAMGA_CRYPTONITE_ENABLED
    if (certificate_der.empty()) {
        error_message = "ExtractCertificateSubjectPublicKeyInfo: certificate is empty";
        return false;
    }
    ScopedByteArray cert_ba(MakeByteArray(certificate_der), ba_free);
    ScopedCert cert(cert_alloc(), cert_free);
    if (cert_ba == nullptr || cert == nullptr) {
        error_message = "ExtractCertificateSubjectPublicKeyInfo: allocation failed";
        return false;
    }
    const int rc = cert_decode(cert.get(), cert_ba.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("ExtractCertificateSubjectPublicKeyInfo: cert_decode", rc);
        return false;
    }
    if (!EncodeSpki(&cert->tbsCertificate.subjectPublicKeyInfo, spki_der)) {
        error_message = "ExtractCertificateSubjectPublicKeyInfo: unable to encode SubjectPublicKeyInfo";
        return false;
    }
    return true;
#else
    (void)certificate_der;
    error_message = "ExtractCertificateSubjectPublicKeyInfo requires a cryptonite-enabled build";
    return false;
#endif
}

// Знімок відкритих ключів контейнера (O-02). Розкриття контейнера коштує
// десятки мілісекунд, а сама звірка з сертифікатом — частки мілісекунди, тож
// викликач, що перевіряє БАГАТО кандидатів проти ОДНОГО контейнера, платить за
// розкриття один раз замість разу на кандидата. Критерій приймання при цьому
// не змінюється: це той самий повний DER SubjectPublicKeyInfo.
bool ContainerPublicKeys::Load(const std::vector<std::uint8_t>& key_material,
                               const std::string& password,
                               ContainerPublicKeys& out,
                               std::string& error_message) {
    out.spki_list_.clear();
#if TAMGA_CRYPTONITE_ENABLED
    if (key_material.empty()) {
        error_message = "ContainerPublicKeys::Load: key material is empty";
        return false;
    }
    // Збираються УСІ ключі контейнера, а не лише перший.
    //
    // «Універсальні» контейнери українських КНЕДП містять два закритих ключі:
    // підпису і протоколів розподілу ключів. Виміряно 2026-09-02 на реальному
    // ключі КНЕДП «Вчасно» (`pkcs12_enum_keys` → 2 ключі, alias `key1`/`key2`,
    // certBag відсутній). Поки перевірявся лише перший ключ, правильний
    // сертифікат ключа підпису відхилявся ще в авто-резолвері
    // («The supplied certificate does not match the private key in the
    // container»), і виправлений вибір ключа в `PreparePkcs12Signer` до роботи
    // просто не доходив.
    const int rc =
        CollectSpkiFromKeyContainer(key_material, password, /*all_keys=*/true, out.spki_list_);
    if (rc != RET_OK || out.spki_list_.empty()) {
        out.spki_list_.clear();
        error_message = BuildRcError("ContainerPublicKeys::Load: private key decode", rc);
        return false;
    }
    return true;
#else
    (void)key_material;
    (void)password;
    error_message = "ContainerPublicKeys::Load requires a cryptonite-enabled build";
    return false;
#endif
}

bool ContainerPublicKeys::Matches(const std::vector<std::uint8_t>& certificate_der) const {
#if TAMGA_CRYPTONITE_ENABLED
    // Порожній знімок не збігається ні з чим: без доведеного набору відкритих
    // ключів контейнера приймати кандидата нема на чому.
    if (spki_list_.empty() || certificate_der.empty()) {
        return false;
    }
    std::vector<std::uint8_t> cert_spki;
    std::string ignored;
    if (!CryptoniteAdapter::ExtractCertificateSubjectPublicKeyInfo(certificate_der, cert_spki,
                                                                   ignored)) {
        return false;
    }
    // Порівняння повного DER SubjectPublicKeyInfo: збіг означає, що сертифікат
    // засвідчує саме цей відкритий ключ (той самий алгоритм і ті самі параметри
    // кривої ДСТУ 4145, а не лише однакові байти точки).
    for (const auto& key_spki : spki_list_) {
        if (!key_spki.empty() && key_spki == cert_spki) {
            return true;
        }
    }
    return false;
#else
    (void)certificate_der;
    return false;
#endif
}

bool CryptoniteAdapter::CertificateMatchesPrivateKey(const std::vector<std::uint8_t>& key_material,
                                                     const std::string& password,
                                                     const std::vector<std::uint8_t>& certificate_der) {
#if TAMGA_CRYPTONITE_ENABLED
    if (key_material.empty() || certificate_der.empty()) {
        return false;
    }
    // Одноразова форма тієї самої перевірки: розкрити контейнер, звірити,
    // забути. Публічний контракт не змінився, тож викликачам з ОДНИМ
    // кандидатом (`PreparePkcs12Signer`, тести) перебудовуватись не треба.
    //
    // Fail-closed властивість зберігається: сертифікат приймається лише тоді,
    // коли він математично прив'язаний до ключа ЦЬОГО контейнера, а далі
    // `PreparePkcs12Signer` вибирає саме той ключ і повторно звіряє його через
    // `SignAdapter::set_cert`. Ціна — у контейнері з двома ключами приймається
    // і сертифікат ключа шифрування, якщо користувач указав саме його;
    // призначення ключа (keyUsage) тут не оцінюється ні до, ні після зміни.
    ContainerPublicKeys keys;
    std::string ignored;
    if (!ContainerPublicKeys::Load(key_material, password, keys, ignored)) {
        return false;
    }
    return keys.Matches(certificate_der);
#else
    (void)key_material;
    (void)password;
    (void)certificate_der;
    return false;
#endif
}

bool CryptoniteAdapter::FindMatchingCertificate(const std::vector<std::uint8_t>& key_material,
                                                const std::vector<std::vector<std::uint8_t>>& chain,
                                                std::vector<std::uint8_t>& matching_cert) {
#if TAMGA_CRYPTONITE_ENABLED
    if (chain.empty()) {
        return false;
    }
    // O-03: ЄДИНИЙ критерій належності сертифіката ключу.
    //
    // Раніше тут будувався sign-адаптер (`PreparePkcs8Signer`), і успіх цієї
    // побудови вважався доказом відповідності. Це інший критерій, ніж у
    // `CertificateMatchesPrivateKey` (порівняння SubjectPublicKeyInfo), яким
    // користується авто-резолвер, — і на реальному JKS ПриватБанку вони давали
    // ПРОТИЛЕЖНІ відповіді: перший приймав сертифікат, другий відхиляв.
    //
    // Розбіжність тоді походила з дефекту SPKI для PKCS#8 (виправлено окремо),
    // але сама наявність двох незалежних критеріїв лишалася джерелом ризику:
    // вони могли розійтися знову, і жодне місце цього б не помітило.
    //
    // Тепер обидва шляхи — і вибір сертифіката з ланцюга JKS, і приймання
    // кандидата в резолвері — спираються на одну математичну перевірку.
    // Ключ, витягнутий із JKS, уже розшифрований, тому пароль порожній.
    //
    // O-02: тут теж перебір кандидатів проти ОДНОГО ключа, тому контейнер
    // розкривається один раз, а не на кожен сертифікат ланцюга. Критерій той
    // самий — `ContainerPublicKeys::Matches` порівнює той самий повний DER
    // SubjectPublicKeyInfo, що й `CertificateMatchesPrivateKey`.
    ContainerPublicKeys keys;
    std::string ignored;
    if (!ContainerPublicKeys::Load(key_material, std::string{}, keys, ignored)) {
        return false;
    }
    for (const auto& cert_der : chain) {
        if (keys.Matches(cert_der)) {
            matching_cert = cert_der;
            return true;
        }
    }
#else
    (void)key_material;
    (void)chain;
    (void)matching_cert;
#endif
    return false;
}

}  // namespace tamga::core
