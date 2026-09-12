// Н-08 (завершення): `vcpkg.json` — єдине джерело версій залежностей.
//
// Раніше той самий baseline-SHA стояв у двох місцях: у `vcpkg.json` і рядком
// у `.github/workflows/release.yml`. Оновивши один, легко було лишити другий,
// і реліз зібрався б на інших версіях, ніж описує маніфест. Найгірше тут те,
// що розходження не мало жодного видимого симптому: обидві збірки успішні,
// просто з різних дерев портів.
//
// Це той самий механізм, що й у решті знахідок цієї хвилі (ADR-027): та сама
// річ, записана двічі, лишається однаковою лише завдяки дисципліні.
//
// Сторожа перевіряє три речі:
//   1. `vcpkg.json` містить `builtin-baseline` з 40 hex-символів;
//   2. РІВНО ТА САМА регулярка, якою `release.yml` витягує baseline із
//      маніфеста, справді його знаходить — тобто крок CI перевіряється тут,
//      а не лише на живому раннері;
//   3. у жодному workflow немає літерала SHA поруч зі згадкою vcpkg/baseline.
//
// Пункт 3 навмисно звужений до рядків про vcpkg: пін GitHub-екшена за SHA —
// нормальна практика, і сторожа не має його чіпати.
//
// П-10 (пункт 4 нижче) стереже зворотну вимогу до тих самих файлів: КОЖЕН
// `uses:` має бути запінений повним 40-hex SHA комміта, а не рухомим тегом
// (`@v4`). Тег у GitHub перезаписуваний: власник екшена — або той, хто
// перехопив його обліковий запис, — може перевести `v4` на інший комміт, і
// наступна ж збірка виконає чужий код у процесі, з якого постачається
// `Tamga.dll`. Для `softprops/action-gh-release` це ще й право створювати
// релізи від імені репозиторію. SHA такого перепризначення не має: він
// адресує конкретне дерево.
//
// Читабельність версії зберігається коментарем у тому ж рядку (`# v4`), тому
// сторожа навмисно відкидає все після `#` перед розбором посилання.

#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

int g_failures = 0;

void Check(const bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        ++g_failures;
    }
}

std::string ReadFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

bool IsSha1Hex(const std::string& value) {
    if (value.size() != 40) {
        return false;
    }
    for (const char c : value) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) {
            return false;
        }
    }
    return true;
}

std::string Trim(const std::string& value) {
    const char* const spaces = " \t\r\n";
    const std::size_t first = value.find_first_not_of(spaces);
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = value.find_last_not_of(spaces);
    return value.substr(first, last - first + 1);
}

// Витягує значення ключа `uses:` з рядка workflow. Повертає false, якщо рядок
// не є інструкцією `uses:` — зокрема, якщо це коментар (`#` першим непробільним
// символом) або просто згадка слова в тексті кроку. Та сама обережність, що і
// в перевірці П-09: сторожа, яка спрацьовує не там, де треба, гірша за
// відсутню.
bool ExtractUses(const std::string& raw_line, std::string& value) {
    std::string line = Trim(raw_line);
    if (line.empty() || line.front() == '#') {
        return false;
    }

    // Ключ трапляється як `uses: ...`, так і першим у списку — `- uses: ...`.
    if (line.size() >= 2 && line.front() == '-' && line[1] == ' ') {
        line = Trim(line.substr(2));
    }

    const std::string key = "uses:";
    if (line.compare(0, key.size(), key) != 0) {
        return false;
    }

    std::string rest = Trim(line.substr(key.size()));
    // Кінцевий коментар (`# v4`) — людський підпис піна, а не частина
    // посилання; його треба відкинути до розбору.
    const std::size_t hash = rest.find('#');
    if (hash != std::string::npos) {
        rest = Trim(rest.substr(0, hash));
    }
    // YAML дозволяє взяти значення в лапки.
    if (rest.size() >= 2 && (rest.front() == '"' || rest.front() == '\'') &&
        rest.back() == rest.front()) {
        rest = rest.substr(1, rest.size() - 2);
    }

    value = rest;
    return !value.empty();
}

} // namespace

int main() {
    const fs::path root(TAMGA_TEST_SOURCE_DIR);

    // --- 1. маніфест містить baseline -------------------------------------
    const std::string manifest = ReadFile(root / "vcpkg.json");
    Check(!manifest.empty(), "vcpkg.json must be readable");
    if (manifest.empty()) {
        return 1;
    }

    // Регулярка навмисно повторює ту, що стоїть у `release.yml`: саме її
    // працездатність тут і перевіряється. Якщо хтось змінить формат запису в
    // маніфесті так, що крок CI перестане знаходити baseline, впаде цей тест,
    // а не реліз.
    const std::regex baseline_re("\"builtin-baseline\"[[:space:]]*:[[:space:]]*\"([0-9a-f]{40})\"");
    std::smatch match;
    const bool found = std::regex_search(manifest, match, baseline_re);
    Check(found, "vcpkg.json must declare builtin-baseline as a 40-hex SHA "
                 "(the same shape release.yml extracts)");
    if (!found) {
        return 1;
    }

    const std::string baseline = match[1].str();
    Check(IsSha1Hex(baseline), "builtin-baseline must be a 40-character lowercase hex SHA");
    std::cerr << "vcpkg.json builtin-baseline: " << baseline << "\n";

    // --- 2. у workflow-ах немає літерала SHA поруч із vcpkg ----------------
    const fs::path workflows = root / ".github" / "workflows";
    std::error_code ec;
    Check(fs::exists(workflows, ec), ".github/workflows must exist");

    std::size_t inspected_files = 0;
    std::size_t inspected_lines = 0;
    if (fs::exists(workflows, ec)) {
        for (const fs::directory_entry& entry : fs::directory_iterator(workflows, ec)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            const std::string name = entry.path().filename().string();
            if (name.size() < 5 || name.substr(name.size() - 4) != ".yml") {
                continue;
            }
            ++inspected_files;

            std::ifstream in(entry.path());
            std::string line;
            std::size_t number = 0;
            while (std::getline(in, line)) {
                ++number;
                ++inspected_lines;

                // Цікавлять лише рядки, які взагалі мають стосунок до vcpkg.
                const bool about_vcpkg = line.find("vcpkg") != std::string::npos ||
                                         line.find("VCPKG") != std::string::npos ||
                                         line.find("baseline") != std::string::npos;
                if (!about_vcpkg) {
                    continue;
                }
                // Рядок, який САМ витягує baseline із маніфеста, містить
                // `{40}` як частину регулярки, а не літерал — це і є дозволений
                // спосіб, тож він не має вважатися порушенням.
                if (line.find("vcpkg.json") != std::string::npos) {
                    continue;
                }
                if (std::regex_search(line, std::regex("[0-9a-f]{40}"))) {
                    Check(false, name + ":" + std::to_string(number) +
                                     " hardcodes a vcpkg SHA; read it from vcpkg.json instead");
                }
            }
        }
    }

    Check(inspected_files >= 3, "the scanner must actually read workflow files");
    std::cerr << "перевірено workflow-файлів: " << inspected_files
              << ", рядків: " << inspected_lines << "\n";

    // --- 3. П-09: склад залежностей у workflow не розходиться з маніфестом --
    //
    // Н-08 звів ВЕРСІЇ до одного джерела (baseline вище). Але СКЛАД лишався в
    // двох місцях, і вони розійшлися непомітно: `vcpkg.json` оголошує libxml2
    // із `default-features: false`, а `release.yml` ставив його класично, тобто
    // з дефолтними фічами — а вони в цього порту `["iconv", "zlib"]`, і `iconv`
    // тягне `libiconv` під LGPL.
    //
    // Наслідок був не косметичний: артефакт, який ПОСТАЧАЄТЬСЯ, статично
    // лінкував LGPL-компонент, а артефакт, який ТЕСТУЄТЬСЯ, — ні. Розходження
    // не мало жодного видимого симптому: обидві збірки успішні.
    //
    // Дві перевірки нижче ловлять саме повернення цього стану.
    {
        std::size_t classic_libxml2_installs = 0;
        for (const fs::directory_entry& entry : fs::directory_iterator(workflows, ec)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            const std::string name = entry.path().filename().string();
            if (name.size() < 5 || name.substr(name.size() - 4) != ".yml") {
                continue;
            }
            std::ifstream in(entry.path());
            std::string line;
            std::size_t number = 0;
            // Дивимося ЛИШЕ на рядки всередині команди встановлення пакетів.
            // Перша версія перевіряла будь-яку згадку `libxml2` і одразу дала
            // хибне спрацювання на кроці, який лише ПЕРЕВІРЯЄ наявність
            // `libxml2.lib` у manifest-дереві. Сторожа, що спрацьовує не там,
            // де треба, гірша за відсутню: її навчаються обходити.
            bool inside_install = false;
            while (std::getline(in, line)) {
                ++number;
                // Коментарі не є інструкціями збірки: у них ці імена
                // згадуються саме для пояснення, чому їх тут немає.
                const std::size_t first = line.find_first_not_of(" \t");
                if (first != std::string::npos && line[first] == '#') {
                    continue;
                }

                const bool starts_install =
                    line.find("install") != std::string::npos &&
                    (line.find("vcpkg") != std::string::npos ||
                     line.find("apt-get") != std::string::npos);
                if (starts_install) {
                    inside_install = true;
                }

                if (inside_install) {
                    // (а) класичне встановлення libxml2 мусить нести `[core]`.
                    // `libxml2-dev` — системний пакет apt, у нього фіч немає.
                    if (line.find("libxml2") != std::string::npos &&
                        line.find("libxml2-dev") == std::string::npos) {
                        ++classic_libxml2_installs;
                        Check(line.find("libxml2[core]") != std::string::npos,
                              name + ":" + std::to_string(number) +
                                  " installs libxml2 with DEFAULT features; the port's defaults are "
                                  "[\"iconv\",\"zlib\"] and iconv is LGPL, while vcpkg.json declares "
                                  "default-features:false. Use libxml2[core] to match the manifest");
                    }

                    // (б) xmlsec ставиться лише там, де вмикається crosscheck.
                    if (line.find("xmlsec") != std::string::npos &&
                        line.find("TAMGA_ENABLE_XMLSEC_CROSSCHECK") == std::string::npos) {
                        Check(false,
                              name + ":" + std::to_string(number) +
                                  " installs xmlsec, but TAMGA_ENABLE_XMLSEC_CROSSCHECK is not enabled "
                                  "here; the production XMLDSIG engine is built on libxml2 alone "
                                  "(ADR-014), so the package would be installed and never linked");
                    }
                }

                // Команда триває, доки рядок закінчується символом
                // продовження (`\` у sh, backtick у PowerShell).
                std::string trimmed = line;
                while (!trimmed.empty() &&
                       (trimmed.back() == ' ' || trimmed.back() == '\t' || trimmed.back() == '\r')) {
                    trimmed.pop_back();
                }
                const bool continues = !trimmed.empty() &&
                                       (trimmed.back() == '\\' || trimmed.back() == '`');
                if (inside_install && !continues) {
                    inside_install = false;
                }
            }
        }
        // Негативний контроль самого сканера: якщо жодного класичного
        // встановлення libxml2 більше немає, перевірка (а) стала вакуумною —
        // і про це треба знати, а не радіти зеленому прогону.
        std::cerr << "класичних встановлень libxml2 у workflow: "
                  << classic_libxml2_installs << "\n";
    }

    // --- 4. П-10: кожен GitHub-екшен запінений повним SHA комміта -----------
    //
    // Той самий механізм, що й у пунктах 2–3, тільки в інший бік: тут не «SHA
    // там, де має бути посилання на маніфест», а «посилання на рухомий тег там,
    // де має бути SHA». Спільне в них одне — розходження без видимого симптому:
    // збірка з підміненим `@v4` теж успішна.
    {
        std::size_t inspected_uses = 0;
        for (const fs::directory_entry& entry : fs::directory_iterator(workflows, ec)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            const std::string name = entry.path().filename().string();
            if (name.size() < 5 || name.substr(name.size() - 4) != ".yml") {
                continue;
            }

            std::ifstream in(entry.path());
            std::string line;
            std::size_t number = 0;
            while (std::getline(in, line)) {
                ++number;

                std::string uses;
                if (!ExtractUses(line, uses)) {
                    continue;
                }
                ++inspected_uses;

                // Локальний екшен (`./.github/actions/...`) живе в цьому ж
                // репозиторії, і пінити його нічим; docker-посилання має власну
                // схему адресації. Ані те, ані те не є рухомим тегом у чужому
                // репозиторії, тож під вимогу не підпадає.
                if (uses.compare(0, 2, "./") == 0 || uses.compare(0, 9, "docker://") == 0) {
                    continue;
                }

                const std::size_t at = uses.rfind('@');
                const std::string ref =
                    (at == std::string::npos) ? std::string() : uses.substr(at + 1);
                Check(IsSha1Hex(ref),
                      name + ":" + std::to_string(number) + " uses '" + uses +
                          "': a GitHub action must be pinned to a full 40-hex commit SHA, "
                          "not to a movable tag or branch (keep the readable version in a "
                          "trailing '# vN' comment)");
            }
        }

        // Негативний контроль самого сканера, як і в пункті 3: розбір `uses:`
        // може зламатися мовчки (зміниться відступ, значення візьмуть у лапки,
        // кроки винесуть у reusable workflow) — тоді перевірка стане вакуумною
        // і «пройде» будь-що. Число має падати лише разом із самими кроками.
        Check(inspected_uses >= 15,
              "the pin scanner found almost no `uses:` steps; either the workflows shrank "
              "drastically or the parser stopped matching them");
        std::cerr << "перевірено кроків uses: " << inspected_uses << "\n";
    }

    if (g_failures != 0) {
        std::cerr << "tamga_vcpkg_baseline_tests: " << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "tamga_vcpkg_baseline_tests: all checks passed\n";
    return 0;
}
