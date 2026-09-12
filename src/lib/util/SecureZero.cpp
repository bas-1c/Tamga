#include "util/SecureZero.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cstring>
#endif

namespace tamga::util {

void SecureZero(void* data, const std::size_t size) noexcept {
    if (data == nullptr || size == 0) {
        return;
    }
#if defined(_WIN32)
    // Документована гарантія: виклик не усувається оптимізатором.
    SecureZeroMemory(data, size);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(data, size, 0, size);
#elif defined(__GLIBC__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    explicit_bzero(data, size);
#else
    // Запасний варіант: запис через volatile-вказівник не може бути усунутий
    // як dead store, бо компілятор зобов'язаний зберегти кожен доступ.
    volatile unsigned char* p = static_cast<volatile unsigned char*>(data);
    for (std::size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
#endif
}

void SecureClear(std::string& value) noexcept {
    if (!value.empty()) {
        SecureZero(&value[0], value.size());
    }
    value.clear();
    // `clear()` ємності не звільняє — без цього затерті байти лишилися б у
    // буфері, який контейнер продовжує тримати.
    std::string().swap(value);
}

void SecureClear(std::wstring& value) noexcept {
    if (!value.empty()) {
        // Затирати треба БАЙТИ, а не символи: розмір `wchar_t` платформозалежний
        // (2 на Windows, 4 на більшості POSIX), тож довжина рядка — не довжина
        // буфера.
        SecureZero(&value[0], value.size() * sizeof(wchar_t));
    }
    value.clear();
    std::wstring().swap(value);
}

void SecureClear(std::vector<std::uint8_t>& value) noexcept {
    if (!value.empty()) {
        SecureZero(value.data(), value.size());
    }
    value.clear();
    std::vector<std::uint8_t>().swap(value);
}

}  // namespace tamga::util
