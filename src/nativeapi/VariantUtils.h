#pragma once

#include <string>
#include <vector>

#include <cstdint>

#include "types.h"
#include "IMemoryManager.h"

namespace tamga::util {

void SetBool(tVariant* var, bool value);
bool GetBool(const tVariant* var, bool& value);
bool GetInt32(const tVariant* var, std::int32_t& value);

bool SetWString(IMemoryManager* memory, tVariant* var, const std::wstring& value);

// П-11: відхиляє вхід, довжина якого перевищує спільну межу вхідних даних
// (`util::kMaxInputFileSize`), ДО будь-якої конверсії. Межа рахується в
// байтах UTF-16-корисного навантаження (`wstrLen * sizeof(WCHAR_T)`), тобто
// в тому самому вимірі, що й розмір файлу.
bool GetWString(const tVariant* var, std::wstring& value);

bool SetBlob(IMemoryManager* memory, tVariant* var, const std::vector<std::uint8_t>& value);

// П-11: відхиляє вхід, довший за `util::kMaxInputFileSize`, ДО копіювання.
bool GetBlob(const tVariant* var, std::vector<std::uint8_t>& value);

} // namespace tamga::util
