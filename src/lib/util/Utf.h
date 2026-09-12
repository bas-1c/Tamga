#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace tamga::util {

std::wstring FromShortWchar(const char16_t* src, std::size_t len = 0);
std::u16string ToShortWchar(std::wstring_view src);
std::wstring FromUtf8(std::string_view src);
std::string ToUtf8(std::wstring_view src);
bool TryDecodeUtf8ToUtf16(std::string_view src, std::u16string& out);
bool TryEncodeUtf16ToUtf8(std::u16string_view src, std::string& out);

// ADR-027: винесено з анонімного namespace, бо копії цієї функції жили ще
// в `core/KeyParsers.cpp` і `util/Json.cpp`. Копія в KeyParsers не
// відхиляла сурогати (U+D800..U+DFFF) — тобто могла закодувати їх у
// 3-байтову послідовність і дати CESU-8 замість UTF-8. Живим дефектом це
// не було: єдиний викликач склеює сурогатні пари ДО виклику, тож поодинокі
// сурогати туди не доходили. Але безпечно воно було лише завдяки
// інваріанту викликача — рівно та конструкція, що дала С-06.
//
// Тут лишається строга версія: сурогати відхиляються.
bool AppendUtf8CodePoint(std::uint32_t code_point, std::string& out);

} // namespace tamga::util
