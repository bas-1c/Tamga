// В-04: спільна межа розміру недовіреного вхідного файла.
//
// Ліміт 64 MiB існував лише в `SessionHelpers.ipp` і діяв виключно на шляху
// `Session`. C ABI (`TamgaCApi.cpp`), CLI (`src/cli/main.cpp`) і NativeAPI
// `VerifyFile(xades/pades)` читали файл цілком через `istreambuf_iterator`
// без жодної перевірки розміру — тобто успадкували політику лише на папері.
// Для компоненти всередині процесу 1С керована ззовні OOM означає падіння
// всієї платформи.
//
// Тест перевіряє саму політику на межах limit-1 / limit / limit+1 і те, що
// ліміт тримається навіть тоді, коли розмір файла наперед невідомий.
//
// Коди виходу: 0 = поведінка коректна; 1 = регресія.

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "util/FileSystem.h"

namespace {

int g_failures = 0;

void Fail(const std::string& what) {
    std::cerr << "FAILED: " << what << "\n";
    ++g_failures;
}

struct TempFile {
    std::filesystem::path path;
    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
};

bool WriteBytes(const std::filesystem::path& path, const std::size_t count) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;
    if (count == 0) {
        return out.good();
    }
    const std::vector<char> chunk(count, 'x');
    out.write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    return out.good();
}

}  // namespace


// Обхід `src/lib` у пошуках цілофайлових читань повз ліміт.
void CheckNoUnboundedWholeFileReads() {
    const std::filesystem::path lib_root =
        std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "src" / "lib";

    std::error_code ec;
    if (!std::filesystem::exists(lib_root, ec)) {
        Fail("не знайдено src/lib — сторожа не може виконати свою роботу");
        return;
    }

    std::size_t inspected = 0;
    bool scanner_reads_content = false;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(lib_root)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const std::filesystem::path& path = entry.path();
        const std::string ext = path.extension().string();
        if (ext != ".cpp" && ext != ".h" && ext != ".hpp" && ext != ".ipp") {
            continue;
        }
        ++inspected;

        std::ifstream source(path, std::ios::binary);
        std::string line;
        std::size_t line_no = 0;
        while (std::getline(source, line)) {
            ++line_no;
            if (line.find("ReadBinaryFileLimited") != std::string::npos) {
                scanner_reads_content = true;
            }
            if (line.find("istreambuf_iterator") == std::string::npos) {
                continue;
            }
            // Коментарі описують саме цей дефект, тож згадка в них законна.
            const auto first = line.find_first_not_of(" \t");
            if (first != std::string::npos &&
                (line.compare(first, 2, "//") == 0 || line[first] == '*')) {
                continue;
            }
            Fail("цілофайлове читання повз ліміт: " + path.filename().string() +
                 ":" + std::to_string(line_no));
        }
    }

    if (inspected == 0) {
        Fail("не переглянуто жодного файлу — сторожа проходила б вакуумно");
    }
    if (!scanner_reads_content) {
        // Якщо сканер не побачив жодної згадки ReadBinaryFileLimited, він
        // читає не те або не туди — і мовчазний «успіх» нічого не вартий.
        Fail("сканер не знайшов ReadBinaryFileLimited у src/lib — перевірка недостовірна");
    }
}

int main() {
    const auto dir = std::filesystem::temp_directory_path();
    constexpr std::uintmax_t kLimit = 4096;

    struct Case {
        const char* name;
        std::size_t size;
        bool expect_ok;
    };
    const Case cases[] = {
        {"limit-1", static_cast<std::size_t>(kLimit) - 1, true},
        {"limit", static_cast<std::size_t>(kLimit), true},
        {"limit+1", static_cast<std::size_t>(kLimit) + 1, false},
    };

    for (const auto& c : cases) {
        const auto path = dir / (std::string("tamga-input-limit-") + c.name + ".bin");
        if (!WriteBytes(path, c.size)) {
            Fail(std::string("не вдалося підготувати файл для випадку ") + c.name);
            continue;
        }
        TempFile remover{path};

        std::vector<std::uint8_t> binary;
        std::string error;
        const bool ok_bin = tamga::util::ReadBinaryFileLimited(path, kLimit, binary, error);
        if (ok_bin != c.expect_ok) {
            Fail(std::string("двійкове читання, випадок ") + c.name + ": очікувалось " +
                 (c.expect_ok ? "успіх" : "відмову") + ", отримано протилежне");
        } else if (c.expect_ok && binary.size() != c.size) {
            Fail(std::string("двійкове читання, випадок ") + c.name + ": прочитано " +
                 std::to_string(binary.size()) + " замість " + std::to_string(c.size));
        } else if (!c.expect_ok) {
            if (!binary.empty()) {
                Fail("після відмови буфер має лишатися порожнім, а не нести частковий вміст");
            }
            if (error.empty()) {
                Fail("відмова має супроводжуватись повідомленням");
            }
        }

        std::string text;
        std::string text_error;
        const bool ok_txt = tamga::util::ReadTextFileLimited(path, kLimit, text, text_error);
        if (ok_txt != c.expect_ok) {
            Fail(std::string("текстове читання, випадок ") + c.name + ": політика розійшлася з двійковою");
        }
    }

    // Ліміт мусить триматися і тоді, коли `file_size` не спрацював як
    // підказка: перевірка на самому потоці — єдине, що лишається.
    {
        const auto path = dir / "tamga-input-limit-stream.bin";
        if (!WriteBytes(path, static_cast<std::size_t>(kLimit) * 4)) {
            Fail("не вдалося підготувати великий файл");
        } else {
            TempFile remover{path};
            std::vector<std::uint8_t> binary;
            std::string error;
            if (tamga::util::ReadBinaryFileLimited(path, kLimit, binary, error)) {
                Fail("файл, більший за ліміт у 4 рази, було прочитано");
            } else if (binary.size() > kLimit) {
                Fail("у пам'ять потрапило більше за ліміт до того, як читання зупинилось");
            }
        }
    }

    // O-01: місткість резервується один раз за перевіреним розміром файла.
    //
    // Читання йде порціями по 64 KiB, тому без резервування контейнер намацує
    // місткість геометричним ростом: проба з перехопленням `operator new` на
    // файлі 16 777 216 байтів рахувала 14 великих алокацій сумарно на
    // 50 822 274 байти. Файл тут навмисно більший за одну порцію — інакше
    // вставка одна і різниці не видно.
    {
        constexpr std::size_t kBig = 1024u * 1024u;
        const auto path = dir / "tamga-input-limit-reserve.bin";
        if (!WriteBytes(path, kBig)) {
            Fail("не вдалося підготувати файл для перевірки резервування");
        } else {
            TempFile remover{path};
            // Допуск на службові байти реалізації (напр. нуль-термінатор
            // рядка); геометричний ріст дав би ~1,5 розміру і не вліз би.
            const std::size_t kSlack = 4096;

            std::vector<std::uint8_t> binary;
            std::string error;
            if (!tamga::util::ReadBinaryFileLimited(path, kLimit * 1024, binary, error)) {
                Fail("двійкове читання файлу в межах ліміту не мало провалитись");
            } else if (binary.size() != kBig) {
                Fail("двійкове читання повернуло не весь файл");
            } else if (binary.capacity() > kBig + kSlack) {
                Fail("двійкове читання перевиділило місткість: " +
                     std::to_string(binary.capacity()) + " при розмірі " + std::to_string(kBig));
            }

            std::string text;
            std::string text_error;
            if (!tamga::util::ReadTextFileLimited(path, kLimit * 1024, text, text_error)) {
                Fail("текстове читання файлу в межах ліміту не мало провалитись");
            } else if (text.size() != kBig) {
                Fail("текстове читання повернуло не весь файл");
            } else if (text.capacity() > kBig + kSlack) {
                Fail("текстове читання перевиділило місткість: " +
                     std::to_string(text.capacity()) + " при розмірі " + std::to_string(kBig));
            }
        }
    }

    // Порожній файл: резервувати нічого, але читання лишається успішним.
    {
        const auto path = dir / "tamga-input-limit-empty.bin";
        if (!WriteBytes(path, 0)) {
            Fail("не вдалося підготувати порожній файл");
        } else {
            TempFile remover{path};
            std::vector<std::uint8_t> binary;
            std::string error;
            if (!tamga::util::ReadBinaryFileLimited(path, kLimit, binary, error)) {
                Fail("порожній файл має читатися успішно");
            } else if (!binary.empty()) {
                Fail("порожній файл дав непорожній буфер");
            }
        }
    }

    // Хвиля 8, п.2: сторожа КЛАСУ, а не окремого місця.
    //
    // Ліміт із цього тесту нічого не вартий, якщо код читає файл повз нього.
    // Саме так і було: дев'ять місць (`CrlCache`, `PolicyCache`,
    // `ValidationEngine`, `CertificateResolver`, `CaSettingsRegistry`,
    // `SessionHelpers`) тягнули файл цілком через `istreambuf_iterator`.
    //
    // Правило чітке й без винятків: `istreambuf_iterator` не має з'являтися
    // в `src/lib` ніде, крім самої реалізації `util/FileSystem.cpp`. Два
    // місця, що лишились на сирому `ifstream` (`AsicReader`, `SessionHelpers`
    // для вхідного документа), читають порціями з власною перевіркою розміру
    // й під це правило не підпадають.
    CheckNoUnboundedWholeFileReads();

    if (g_failures == 0) {
        std::cout << "Input size limit suite: OK\n";
        return EXIT_SUCCESS;
    }
    std::cerr << "input_limit_tests: " << g_failures << " failure(s)\n";
    return EXIT_FAILURE;
}
