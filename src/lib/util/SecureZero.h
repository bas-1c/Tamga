#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tamga::util {

// С-05: єдиний спосіб затерти секрет у пам'яті.
//
// Раніше в одній функції `Session::SecureClearLoadedKey` співіснували два
// різні підходи: `loaded_key_`, `loaded_key_material_` і `loaded_certificate_`
// занулювалися звичайними циклами `for (auto& b : v) b = 0;`, а двома рядками
// нижче `SecureErase(std::string&)` робив те саме через `volatile`. Оскільки
// результат звичайного запису ніде не читається, компілятор має право усунути
// такий цикл як dead store — тобто приватний ключ міг лишатися у звільненій
// купі після `ResetKey()`/`Finalize()`.
//
// Реалізація спирається на платформні гарантії там, де вони є
// (`SecureZeroMemory` / `explicit_bzero` / `memset_s`), і на `volatile`-цикл
// як запасний варіант.
void SecureZero(void* data, std::size_t size) noexcept;

// Затирає вміст і звільняє ємність. `clear()` сам по собі ємності не звільняє,
// тож без `shrink_to_fit`/swap байти лишалися б у буфері контейнера.
void SecureClear(std::string& value) noexcept;
void SecureClear(std::vector<std::uint8_t>& value) noexcept;

// П-06: те саме для wide-рядка. Межа з 1С отримує пароль, пароль ключа й
// alias у `std::wstring` (`tVariant` віддає UTF-16), і без цієї перевантаженої
// форми межа мусила б або тримати власну RAII-обгортку, або лишати wide-копію
// секрета в купі. Другого механізму затирання в дереві бути не повинно —
// саме розходження двох механізмів дало С-05.
void SecureClear(std::wstring& value) noexcept;

// RAII-обгортка для проміжних копій секретів. Локальні `normalized`,
// `key_material`, `password_bytes` тощо раніше просто виходили з області
// видимості, лишаючи вміст у купі.
class ScopedSecret final {
public:
    explicit ScopedSecret(std::vector<std::uint8_t>& target) noexcept : bytes_(&target) {}
    explicit ScopedSecret(std::string& target) noexcept : text_(&target) {}
    explicit ScopedSecret(std::wstring& target) noexcept : wide_text_(&target) {}

    ScopedSecret(const ScopedSecret&) = delete;
    ScopedSecret& operator=(const ScopedSecret&) = delete;

    ~ScopedSecret() {
        if (bytes_ != nullptr) SecureClear(*bytes_);
        if (text_ != nullptr) SecureClear(*text_);
        if (wide_text_ != nullptr) SecureClear(*wide_text_);
    }

private:
    std::vector<std::uint8_t>* bytes_{nullptr};
    std::string* text_{nullptr};
    std::wstring* wide_text_{nullptr};
};

}  // namespace tamga::util
