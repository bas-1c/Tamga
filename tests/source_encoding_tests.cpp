// Н-12: гарантія однорідного кодування вихідних текстів.
//
// Аудит (oxalpha OXA-18) стверджував, що в `HttpClient.cpp`, `TspClient.cpp`
// та `TrustListSettings.h` лежать CP1251-«кракозябри». Перевірка байтів це
// НЕ підтвердила: усі три файли є валідним UTF-8 і були такими вже в
// початковому коміті `b624143`. Знахідка — артефакт читання файлів через
// CP1251-консоль, а не властивість репозиторію.
//
// Проте поруч є справжня залежність, і саме її стереже цей тест. У `src/`
// близько 388 рядків містять НЕ-ASCII усередині рядкових ЛІТЕРАЛІВ — це
// українські повідомлення, які бачить користувач 1С. Жоден файл не має BOM,
// тож єдиний механізм, який змушує MSVC читати їх як UTF-8, — прапорець
// `/utf-8` із `cmake/CompilerOptions.cmake`. Якщо новий таргет забудуть
// провести через `tamga_enable_project_compile_policy`, або якщо редактор
// збереже файл у CP1251, літерали мовчки поїдуть: збірка лишиться зеленою,
// а звіт користувачу прийде спотвореним.
//
// Тому перевіряються дві властивості:
//   1) кожен вихідний файл — строгий UTF-8 (ловить збереження в CP1251);
//   2) у жодному файлі немає подвійного кодування (U+00D0/U+00D1 перед
//      Latin-1 Supplement), яке лишається валідним UTF-8 і тому непомітне
//      для перевірки (1) — це рівно той дефект, який описував OXA-18.
//
// Приклади мохібаке тут навмисно НЕ наводяться буквально, а описуються
// через код-поінти: перша ж редакція цього файлу містила зразок у коментарі,
// і сторож справедливо позначив сам тест. Це, до речі, і є доказ, що
// перевірка (2) не вакуумна — вона спрацювала на реальному вмісті.
//
// Тест навмисно не має залежностей від cryptonite/xml і будується завжди.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

struct Failure {
    std::string path;
    std::string reason;
};

bool HasSourceExtension(const fs::path& path) {
    const std::string ext = path.extension().string();
    return ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".h" ||
           ext == ".hpp" || ext == ".ipp";
}

std::vector<std::uint8_t> ReadAllBytes(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(stream)),
                                     std::istreambuf_iterator<char>());
}

// Строгий декодер UTF-8: відкидає overlong-послідовності, сурогати та
// значення понад U+10FFFF. Пом'якшений декодер пропустив би CP1251-байти,
// що випадково склалися у формально правильну пару.
bool DecodeUtf8(const std::vector<std::uint8_t>& bytes,
                std::vector<std::uint32_t>& code_points,
                std::size_t& bad_offset) {
    const std::size_t size = bytes.size();
    std::size_t i = 0;
    while (i < size) {
        const std::uint8_t lead = bytes[i];
        std::uint32_t cp = 0;
        std::size_t extra = 0;
        std::uint32_t lower_bound = 0;

        if (lead < 0x80u) {
            cp = lead;
            extra = 0;
            lower_bound = 0;
        } else if ((lead & 0xE0u) == 0xC0u) {
            cp = lead & 0x1Fu;
            extra = 1;
            lower_bound = 0x80u;
        } else if ((lead & 0xF0u) == 0xE0u) {
            cp = lead & 0x0Fu;
            extra = 2;
            lower_bound = 0x800u;
        } else if ((lead & 0xF8u) == 0xF0u) {
            cp = lead & 0x07u;
            extra = 3;
            lower_bound = 0x10000u;
        } else {
            bad_offset = i;
            return false;
        }

        if (extra > 0 && i + extra >= size) {
            bad_offset = i;  // обірвана послідовність наприкінці файлу
            return false;
        }

        for (std::size_t k = 1; k <= extra; ++k) {
            const std::uint8_t cont = bytes[i + k];
            if ((cont & 0xC0u) != 0x80u) {
                bad_offset = i + k;
                return false;
            }
            cp = (cp << 6) | (cont & 0x3Fu);
        }

        if (extra > 0 && cp < lower_bound) {
            bad_offset = i;  // overlong
            return false;
        }
        if (cp >= 0xD800u && cp <= 0xDFFFu) {
            bad_offset = i;  // сурогат
            return false;
        }
        if (cp > 0x10FFFFu) {
            bad_offset = i;
            return false;
        }

        code_points.push_back(cp);
        i += extra + 1;
    }
    return true;
}

// Подвійне кодування: кирилиця, збережена як CP1251, прочитана як Latin-1 і
// вдруге закодована в UTF-8, дає ланцюжки виду U+00D0/U+00D1 + Latin-1
// Supplement. Причина в тому, що майже вся українська кирилиця в UTF-8
// починається з байтів 0xD0/0xD1, а вони ж у Latin-1 є літерами U+00D0/U+00D1.
// У справжньому українському тексті така пара не трапляється: після цих
// літер стоїть або ASCII, або нічого.
bool LooksLikeDoubleEncodedCyrillic(const std::vector<std::uint32_t>& cps,
                                    std::size_t& at) {
    for (std::size_t i = 0; i + 1 < cps.size(); ++i) {
        const std::uint32_t a = cps[i];
        const std::uint32_t b = cps[i + 1];
        const bool lead_is_moji = (a == 0x00D0u || a == 0x00D1u);
        const bool tail_is_latin1_supplement = (b >= 0x0080u && b <= 0x00FFu);
        if (lead_is_moji && tail_is_latin1_supplement) {
            at = i;
            return true;
        }
    }
    return false;
}

}  // namespace

int main() {
    const fs::path root(TAMGA_TEST_SOURCE_DIR);
    const char* scanned[] = {"src", "include", "tools", "tests"};

    std::vector<Failure> failures;
    std::size_t inspected = 0;
    std::size_t with_non_ascii = 0;

    for (const char* dir : scanned) {
        const fs::path base = root / dir;
        if (!fs::exists(base)) {
            std::cerr << "expected source directory is missing: " << base.string() << '\n';
            return 1;
        }
        for (const auto& entry : fs::recursive_directory_iterator(base)) {
            if (!entry.is_regular_file() || !HasSourceExtension(entry.path())) {
                continue;
            }
            const fs::path& path = entry.path();
            const std::string shown = fs::relative(path, root).generic_string();
            const std::vector<std::uint8_t> bytes = ReadAllBytes(path);
            ++inspected;

            if (bytes.size() >= 3 && bytes[0] == 0xEFu && bytes[1] == 0xBBu &&
                bytes[2] == 0xBFu) {
                // BOM сам собою нешкідливий, але робить механізм неоднорідним:
                // частина файлів покладалась би на BOM, частина — на /utf-8.
                failures.push_back(
                    {shown, "UTF-8 BOM: кодування задає /utf-8, BOM не використовується"});
                continue;
            }

            bool any_non_ascii = false;
            for (const std::uint8_t b : bytes) {
                if (b > 0x7Fu) {
                    any_non_ascii = true;
                    break;
                }
            }
            if (!any_non_ascii) {
                continue;
            }
            ++with_non_ascii;

            std::vector<std::uint32_t> cps;
            cps.reserve(bytes.size());
            std::size_t bad_offset = 0;
            if (!DecodeUtf8(bytes, cps, bad_offset)) {
                failures.push_back({shown,
                                    "не UTF-8 (ймовірно CP1251), перший хибний байт за зсувом " +
                                        std::to_string(bad_offset)});
                continue;
            }

            std::size_t at = 0;
            if (LooksLikeDoubleEncodedCyrillic(cps, at)) {
                failures.push_back({shown,
                                    "подвійне кодування CP1251->UTF-8 (мохібаке) біля символу " +
                                        std::to_string(at)});
            }
        }
    }

    if (inspected == 0) {
        std::cerr << "no source files were inspected; the scan is not doing its job\n";
        return 1;
    }
    if (with_non_ascii == 0) {
        std::cerr << "no file with non-ASCII content was found; the guard would pass "
                     "vacuously and prove nothing\n";
        return 1;
    }

    if (!failures.empty()) {
        std::cerr << "source encoding violations (" << failures.size() << "):\n";
        for (const Failure& failure : failures) {
            std::cerr << "  " << failure.path << ": " << failure.reason << '\n';
        }
        return 1;
    }

    std::cout << "source encoding OK: " << inspected << " files, " << with_non_ascii
              << " with non-ASCII content\n";
    return 0;
}
