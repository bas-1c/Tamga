#include "util/FileSystem.h"
#include "util/Utf.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

namespace {

const char* kDiia = "\xD0\x94\xD1\x96\xD1\x8F";
const char* kKalyna = "\xD0\x9A\xD0\xB0\xD0\xBB\xD0\xB8\xD0\xBD\xD0\xB0";
const char* kQualified = "\xD0\x9A\xD0\xB2\xD0\xB0\xD0\xBB\xD1\x96\xD1\x84\xD1\x96\xD0\xBA\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB9";
const char* kOleksandr = "\xD0\x9E\xD0\xBB\xD0\xB5\xD0\xBA\xD1\x81\xD0\xB0\xD0\xBD\xD0\xB4\xD1\x80";
const char* kKyiv = "\xD0\x9A\xD0\xB8\xD1\x97\xD0\xB2";

std::filesystem::path UnicodePath(const wchar_t* windows_value, const char* utf8_value) {
#if defined(_WIN32)
    (void)utf8_value;
    return std::filesystem::path(windows_value);
#else
    (void)windows_value;
    return std::filesystem::u8path(utf8_value);
#endif
}

bool Contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

bool ReadFile(const std::filesystem::path& path, std::vector<std::uint8_t>& data) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        return false;
    }
    data.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>{});
    return true;
}

bool ValidateUtfBoundaryRoundTrip() {
    const std::string utf8_text = std::string(kDiia) + " " + kKalyna + " " + kQualified + " " + kOleksandr + " " + kKyiv;
    const std::wstring wide_text = tamga::util::FromUtf8(utf8_text);
    if (wide_text.empty()) {
        std::cerr << "UTF-8 to UTF-16/WCHAR_T conversion returned an empty string\n";
        return false;
    }
    if (tamga::util::ToUtf8(wide_text) != utf8_text) {
        std::cerr << "UTF-8/UTF-16 roundtrip changed Ukrainian text\n";
        return false;
    }
    return true;
}

} // namespace

int main() {
    std::error_code ec;
    const auto root = std::filesystem::temp_directory_path() /
                      UnicodePath(L"Tamga-Калина-unicode-file-test", "Tamga-\xD0\x9A\xD0\xB0\xD0\xBB\xD0\xB8\xD0\xBD\xD0\xB0-unicode-file-test");
    const auto target = root / UnicodePath(L"Дія-Кваліфікований.bin", "\xD0\x94\xD1\x96\xD1\x8F-\xD0\x9A\xD0\xB2\xD0\xB0\xD0\xBB\xD1\x96\xD1\x84\xD1\x96\xD0\xBA\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB9.bin");
    const auto nested = root / UnicodePath(L"Олександр-Київ", "\xD0\x9E\xD0\xBB\xD0\xB5\xD0\xBA\xD1\x81\xD0\xB0\xD0\xBD\xD0\xB4\xD1\x80-\xD0\x9A\xD0\xB8\xD1\x97\xD0\xB2") /
                        UnicodePath(L"chainDebug.json", "chainDebug.json");
    auto temp = target;
    temp += ".tmp";

    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);
    if (ec) {
        std::cerr << "failed to create unicode test directory\n";
        return 1;
    }

    const std::string root_utf8 = root.u8string();
    const std::string target_utf8 = target.u8string();
    const std::string nested_parent_utf8 = nested.parent_path().u8string();
    if (!Contains(root_utf8, kKalyna) ||
        !Contains(target_utf8, kDiia) ||
        !Contains(target_utf8, kQualified) ||
        !Contains(nested_parent_utf8, kOleksandr) ||
        !Contains(nested_parent_utf8, kKyiv)) {
        std::cerr << "filesystem path UTF-8 conversion lost Ukrainian characters\n";
        std::filesystem::remove_all(root, ec);
        return 1;
    }

    if (!ValidateUtfBoundaryRoundTrip()) {
        std::filesystem::remove_all(root, ec);
        return 1;
    }

    const std::vector<std::uint8_t> first = {'o', 'k'};
    const std::vector<std::uint8_t> second = {'u', 'p', 'd', 'a', 't', 'e', 'd'};

    if (!tamga::util::WriteBinaryFileAtomic(target, first)) {
        std::cerr << "initial unicode atomic write failed\n";
        std::filesystem::remove_all(root, ec);
        return 1;
    }
    if (!tamga::util::WriteBinaryFileAtomic(target, second)) {
        std::cerr << "replacement unicode atomic write failed\n";
        std::filesystem::remove_all(root, ec);
        return 1;
    }

    std::vector<std::uint8_t> actual;
    if (!ReadFile(target, actual) || actual != second) {
        std::cerr << "unicode atomic write content mismatch\n";
        std::filesystem::remove_all(root, ec);
        return 1;
    }
    if (std::filesystem::exists(temp, ec)) {
        std::cerr << "unicode atomic write left a temp file behind\n";
        std::filesystem::remove_all(root, ec);
        return 1;
    }

    std::filesystem::remove_all(root, ec);
    return 0;
}
