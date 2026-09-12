#pragma once
#include <cstdlib>
#include <filesystem>

namespace tamga_test {
// Явний локальний корінь для додаткового корпусу; за замовчуванням — public fixtures.
inline std::filesystem::path TestDataRoot() {
    const char* value = std::getenv("TAMGA_TEST_DATA_ROOT");
    if (value != nullptr && *value != '\0') return std::filesystem::u8path(value);
    return std::filesystem::path(TAMGA_TEST_SOURCE_DIR);
}
}  // namespace tamga_test
