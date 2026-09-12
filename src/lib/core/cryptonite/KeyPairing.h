#pragma once

// Знімок відкритих ключів контейнера — та сама звірка «сертифікат належить
// цьому ключу», але з одним розкриттям контейнера замість одного на кандидата.
//
// O-02. `CryptoniteAdapter::CertificateMatchesPrivateKey` самодостатній: він
// щоразу заново декодує контейнер (`pkcs12_decode` / `pkcs8_decode`), вибирає
// ключі й дістає з них SubjectPublicKeyInfo. Для однієї перевірки це правильно,
// але авто-резолвер сертифіката викликає його в циклі по КОЖНОМУ файлу
// `.cer/.crt/.der/.pem` у каталозі ключа. Для PKCS#12 із KDF-розкриттям це
// означає повне розшифрування контейнера на кожного кандидата.
//
// Виміряно 2026-09-09 (Release /O2, MSVC 19.51, ДСТУ 4145 M257_PB, найгірший
// порядок — правильний сертифікат останній у обході; медіана з 9 прогонів,
// два бінарники «до/після» запускалися по черзі в одному сеансі):
//                     до            після
//   PKCS#12  1  →   61 мс          61 мс
//   PKCS#12  10 →  402 мс          67 мс
//   PKCS#12  100→ 6070 мс          86 мс
//   PKCS#8   1  →   26 мс          23 мс
//   PKCS#8   10 →  139 мс          26 мс
//   PKCS#8   100→ 1914 мс          60 мс
// Гранична вартість кандидата падає з ~61 мс (PKCS#12) і ~19 мс (PKCS#8) до
// ~0,3 мс: лишається лише розбір самого сертифіката, а не контейнера.
//
// Що НЕ змінюється:
//   * критерій приймання той самий — повний DER SubjectPublicKeyInfo;
//   * підтримка КІЛЬКОХ ключів у контейнері: знімок містить SPKI всіх ключів
//     («універсальні» контейнери КНЕДП мають ключ підпису і ключ протоколів
//     розподілу ключів);
//   * fail-closed: без успішно завантаженого знімка не приймається ніщо.
//
// Секрет тут не зберігається і між сесіями не кешується: у знімку лежать лише
// ВІДКРИТІ ключі, а живе він рівно стільки, скільки триває один `Resolve`.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tamga::core {

class ContainerPublicKeys final {
public:
    // Одноразово розкриває контейнер і збирає SPKI УСІХ його ключів.
    // false — контейнер не вдалося розкрити; `out` лишається порожнім.
    static bool Load(const std::vector<std::uint8_t>& key_material,
                     const std::string& password,
                     ContainerPublicKeys& out,
                     std::string& error_message);

    // true, якщо `certificate_der` засвідчує один із ключів знімка.
    // Порожній знімок ніколи не збігається — це і є fail-closed.
    bool Matches(const std::vector<std::uint8_t>& certificate_der) const;

    bool Empty() const noexcept { return spki_list_.empty(); }
    std::size_t Size() const noexcept { return spki_list_.size(); }

private:
    std::vector<std::vector<std::uint8_t>> spki_list_;
};

}  // namespace tamga::core
