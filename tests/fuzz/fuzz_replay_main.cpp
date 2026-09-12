// Standalone-драйвер для fuzz-цілей.
//
// Кожна ціль у цьому каталозі має канонічну сигнатуру libFuzzer
// (`LLVMFuzzerTestOneInput`), але libFuzzer доступний лише у Clang-збірці.
// Основний шлях проєкту — MSVC (див. README), а MSVC надає ASan без libFuzzer.
//
// Тому та сама ціль збирається у двох режимах:
//   * з Clang і -fsanitize=fuzzer — справжній фаззер, який ГЕНЕРУЄ входи;
//   * з цим драйвером — повтор корпусу, тобто регресійний прогін по вже
//     наявних файлах. Другий режим не шукає нових дефектів, зате запускається
//     у звичайному CI під ASan і сторожить, щоб уже знайдене не повернулося.
//
// Драйвер свідомо НЕ вважає жоден файл «своїм» за розширенням і згодовує цілі
// геть усе, що знайде: PDF, поданий у розбір ASN.1, — це коректний fuzz-випадок,
// а не помилка виклику. Виняток один — `.b64`: фікстури проєкту зберігаються
// в base64, тож вони декодуються, інакше ціль побачила б лише текст.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include "util/Base64.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

namespace {

bool ReadFile(const std::filesystem::path& path, std::vector<std::uint8_t>& out) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    return true;
}

// `.b64` розгортається у двійковий вигляд. Якщо декодування не вдалося — це не
// привід пропускати файл: згодовуємо його як є, зіпсований base64 теж вхід.
void FeedFile(const std::filesystem::path& path, std::size_t& fed) {
    std::vector<std::uint8_t> bytes;
    if (!ReadFile(path, bytes)) {
        std::fprintf(stderr, "fuzz-replay: cannot read %s\n", path.string().c_str());
        return;
    }
    if (path.extension() == ".b64") {
        std::vector<std::uint8_t> decoded;
        const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        if (tamga::util::Base64Decode(text, decoded) && !decoded.empty()) {
            bytes.swap(decoded);
        }
    }
    (void)LLVMFuzzerTestOneInput(bytes.data(), bytes.size());
    ++fed;
}

void FeedPath(const std::filesystem::path& path, std::size_t& fed) {
    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) {
        for (std::filesystem::recursive_directory_iterator it(path, ec), end; it != end;
             it.increment(ec)) {
            if (ec) {
                break;
            }
            if (it->is_regular_file(ec)) {
                FeedFile(it->path(), fed);
            }
        }
        return;
    }
    if (std::filesystem::is_regular_file(path, ec)) {
        FeedFile(path, fed);
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
                     "usage: %s <corpus-file-or-directory> [more...]\n"
                     "Replays every file through the fuzz target. Meant to run under a sanitizer.\n",
                     argv[0]);
        return 2;
    }

    // Порожній вхід — окремий випадок, який корпус зазвичай не містить, а
    // парсери на ньому регулярно падають.
    //
    // Вказівник НЕНУЛЬОВИЙ навмисно: libFuzzer теж передає валідний вказівник
    // при size == 0, і цілі мають бачити рівно ту саму форму виклику. Крім
    // того, `std::string(nullptr, 0)` формально є невизначеною поведінкою, тож
    // з nullptr драйвер сам став би джерелом дефекту.
    static const std::uint8_t kEmpty[1] = {0};
    (void)LLVMFuzzerTestOneInput(kEmpty, 0);

    std::size_t fed = 1;
    for (int i = 1; i < argc; ++i) {
        FeedPath(std::filesystem::path(argv[i]), fed);
    }

    std::printf("fuzz-replay: %zu input(s) replayed without a sanitizer report\n", fed);
    // Порожній корпус означав би тест, який нічого не перевіряє й лишається
    // зеленим — це рівно та пастка, через яку в цьому проєкті вже кілька разів
    // «зелені тести» насправді не виконували жодного коду.
    if (fed <= 1) {
        std::fprintf(stderr, "fuzz-replay: corpus is empty — nothing was exercised\n");
        return 1;
    }
    return 0;
}
