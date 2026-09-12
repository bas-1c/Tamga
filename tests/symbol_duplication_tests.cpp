// Сторожа МЕХАНІЗМУ, яким у цьому дереві заводяться копії.
//
// Чотири попередні сторожі били по конкретних патернах: кодування джерел,
// цілофайлові читання, побудова вердиктів, розбір довжини DER. Кожна закривала
// свій випадок — і жодна не заважала з'явитися наступному. Історія цієї сесії
// це показала прямо:
//
//   С-06  — парсер довжини DER у семи копіях; чотири звели, три лишились
//           непоміченими, бо той пошук не охоплював `.ipp`;
//   С-19  — перевірка строку дії TSA лише в одному з двох валідаторів;
//   вердикти звіту — вісім пар функцій, синхронних лише завдяки дисципліні;
//   EscapeJson — три копії;
//   ExtractJsonString — дві копії, і вони РОЗХОДИЛИСЬ (`\uXXXX`);
//   SHA-256 — реалізація, скопійована в `EvidenceStore.cpp` цілком.
//
// Спільна причина в усіх випадках одна: утиліта живе в анонімному namespace
// усередині `.cpp`/`.ipp`. Ззовні її не видно й використати неможливо, тож
// коли та сама потреба виникає в іншому модулі, єдиний доступний вихід —
// написати ще раз. Ніщо в дереві цього не помічало.
//
// Тест закриває саме це: він знаходить будь-яку функцію, визначену більш ніж
// в одному файлі, і звіряє з записаною базовою лінією.
//
//   * нова назва поза базовою лінією -> ПАДІННЯ (копія не з'явиться мовчки);
//   * назва в базовій лінії, якої вже немає в дереві -> ПАДІННЯ (базова лінія
//     мусить СКОРОЧУВАТИСЬ; інакше вона перетвориться на звалище).
//
// Друга умова робить із базової лінії храповик, а не список виправдань.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

int g_failures = 0;

void Fail(const std::string& what) {
    std::cerr << "FAIL: " << what << '\n';
    ++g_failures;
}

bool IsIdentifierChar(const char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_';
}

// Прибирає коментарі й вміст літералів, замінюючи їх пробілами: так позиції
// символів зберігаються, а хибних збігів у тексті й рядках не буде.
std::string StripCommentsAndLiterals(const std::string& source) {
    std::string out = source;
    const std::size_t n = out.size();
    std::size_t i = 0;
    while (i < n) {
        if (out[i] == '/' && i + 1 < n && out[i + 1] == '/') {
            while (i < n && out[i] != '\n') {
                out[i++] = ' ';
            }
            continue;
        }
        if (out[i] == '/' && i + 1 < n && out[i + 1] == '*') {
            out[i++] = ' ';
            out[i++] = ' ';
            while (i < n && !(out[i] == '*' && i + 1 < n && out[i + 1] == '/')) {
                if (out[i] != '\n') {
                    out[i] = ' ';
                }
                ++i;
            }
            if (i < n) {
                out[i++] = ' ';
            }
            if (i < n) {
                out[i++] = ' ';
            }
            continue;
        }
        if (out[i] == '"' || out[i] == '\'') {
            const char quote = out[i];
            out[i++] = ' ';
            while (i < n && out[i] != quote) {
                if (out[i] == '\\' && i + 1 < n) {
                    out[i++] = ' ';
                    if (i < n && out[i] != '\n') {
                        out[i] = ' ';
                    }
                    ++i;
                    continue;
                }
                if (out[i] != '\n') {
                    out[i] = ' ';
                }
                ++i;
            }
            if (i < n) {
                out[i++] = ' ';
            }
            continue;
        }
        ++i;
    }
    return out;
}

// Збирає імена функцій, ВИЗНАЧЕНИХ у файлі.
//
// Спосіб навмисно структурний, а не регексовий: йдемо текстом, рахуючи глибину
// дужок, і кожну `{` на НУЛЬОВІЙ глибині перевіряємо — чи стоїть перед нею
// `)`. На нульовій глибині це буває лише у визначенні функції: `namespace X {`,
// `struct X {`, `extern "C" {` дужки перед собою не мають, а `if (...) {` на
// нульовій глибині не трапляється.
std::set<std::string> CollectDefinitions(const std::string& raw) {
    const std::string text = StripCommentsAndLiterals(raw);
    std::set<std::string> names;
    int brace_depth = 0;
    // Глибина, на якій відкрилося тіло поточної функції; -1 — ми поза функцією.
    // Потрібно саме так: `namespace X {` і `class Y {` теж відкривають дужку,
    // тож просто «глибина 0» відкинула б геть усі визначення, бо вони лежать
    // усередині namespace. А відстеження тіла заразом відсіює лямбди —
    // вони завжди всередині функції.
    int function_body_depth = -1;

    for (std::size_t i = 0; i < text.size(); ++i) {
        const char ch = text[i];
        if (ch == '}') {
            if (brace_depth > 0) {
                --brace_depth;
            }
            if (function_body_depth >= 0 && brace_depth == function_body_depth) {
                function_body_depth = -1;
            }
            continue;
        }
        if (ch != '{') {
            continue;
        }
        const int depth_here = brace_depth++;
        if (function_body_depth >= 0) {
            continue;  // ми всередині тіла функції — це не нове визначення
        }

        // Крок назад: пропускаємо пробіли й кваліфікатори після `)`.
        std::size_t j = i;
        while (j > 0) {
            --j;
            while (j > 0 && std::isspace(static_cast<unsigned char>(text[j])) != 0) {
                --j;
            }
            // Хвостові кваліфікатори: const / noexcept / override / final.
            std::size_t word_end = j + 1;
            std::size_t word_start = j + 1;
            while (word_start > 0 && IsIdentifierChar(text[word_start - 1])) {
                --word_start;
            }
            const std::string word = text.substr(word_start, word_end - word_start);
            if (word == "const" || word == "noexcept" || word == "override" || word == "final") {
                if (word_start == 0) {
                    break;
                }
                j = word_start - 1;
                continue;
            }
            break;
        }
        if (text[j] != ')') {
            continue;  // не визначення функції
        }

        // Від `)` назад до відповідної `(`.
        int paren = 0;
        std::size_t k = j;
        bool matched = false;
        while (true) {
            if (text[k] == ')') {
                ++paren;
            } else if (text[k] == '(') {
                if (--paren == 0) {
                    matched = true;
                    break;
                }
            }
            if (k == 0) {
                break;
            }
            --k;
        }
        if (!matched || k == 0) {
            continue;
        }

        // Ім'я — ідентифікатор безпосередньо перед `(`.
        std::size_t name_end = k;
        while (name_end > 0 && std::isspace(static_cast<unsigned char>(text[name_end - 1])) != 0) {
            --name_end;
        }
        std::size_t name_start = name_end;
        while (name_start > 0 && IsIdentifierChar(text[name_start - 1])) {
            --name_start;
        }
        if (name_start == name_end) {
            continue;
        }
        // Кваліфікатори класу/namespace входять в ім'я: інакше `Foo::Build` і
        // `Bar::Build` виглядали б однією функцією, і сторожа сипала б хибними
        // спрацюваннями на методах різних класів.
        std::size_t qualified_start = name_start;
        while (qualified_start >= 2 && text[qualified_start - 1] == ':' &&
               text[qualified_start - 2] == ':') {
            std::size_t seg_end = qualified_start - 2;
            std::size_t seg_start = seg_end;
            while (seg_start > 0 && IsIdentifierChar(text[seg_start - 1])) {
                --seg_start;
            }
            if (seg_start == seg_end) {
                break;
            }
            qualified_start = seg_start;
        }
        const std::string name = text.substr(qualified_start, name_end - qualified_start);

        // Перед іменем має бути тип або кваліфікатор — інакше це виклик,
        // а не визначення. Порожньо перед ним буває лише в конструкторів.
        std::size_t before = qualified_start;
        while (before > 0 && std::isspace(static_cast<unsigned char>(text[before - 1])) != 0) {
            --before;
        }
        if (before == 0) {
            continue;
        }
        const char prev = text[before - 1];
        // `;` `}` `{` — конструктор/деструктор або початок блоку.
        // `,` та `:` — елемент списку ініціалізації конструктора
        //   (`Foo::Foo(...) : crypto_(...), impl_(...) {`), а не визначення.
        // `(` — виклик усередині виразу.
        if (prev == ';' || prev == '}' || prev == '{' || prev == ',' || prev == '(' ||
            prev == ':') {
            continue;
        }

        static const std::set<std::string> kKeywords = {
            "if", "for", "while", "switch", "return", "sizeof", "catch",
            "else", "do", "try", "namespace", "struct", "class", "enum",
            "union", "template", "operator"};
        if (kKeywords.count(name) != 0) {
            continue;
        }
        names.insert(name);
        function_body_depth = depth_here;
    }
    return names;
}

std::string Trim(const std::string& value) {
    const std::size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

} // namespace

int main() {
    const fs::path root(TAMGA_TEST_SOURCE_DIR);
    const fs::path lib_root = root / "src" / "lib";
    const fs::path baseline_path = root / "tests" / "duplicate_symbols.baseline";

    std::error_code ec;
    if (!fs::exists(lib_root, ec)) {
        std::cerr << "не знайдено src/lib\n";
        return 1;
    }

    std::map<std::string, std::set<std::string>> where;  // ім'я -> файли
    std::size_t inspected = 0;
    for (const auto& entry : fs::recursive_directory_iterator(lib_root)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const fs::path& path = entry.path();
        const std::string ext = path.extension().string();
        if (ext != ".cpp" && ext != ".h" && ext != ".hpp" && ext != ".ipp") {
            continue;
        }
        ++inspected;
        std::ifstream file(path, std::ios::binary);
        const std::string raw((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
        const std::string shown = fs::relative(path, root).generic_string();
        for (const std::string& name : CollectDefinitions(raw)) {
            where[name].insert(shown);
        }
    }

    if (inspected == 0) {
        std::cerr << "не переглянуто жодного файлу — сторожа вакуумна\n";
        return 1;
    }

    std::set<std::string> duplicated;
    for (const auto& [name, files] : where) {
        if (files.size() > 1) {
            duplicated.insert(name);
        }
    }

    // Базова лінія: рядки `ім'я  кількість  # причина`.
    //
    // Кількість фіксується навмисно. Без неї до вже відомого дубліката можна
    // було б тихо додати ТРЕТЮ копію — імʼя вже у списку, тест мовчить. Саме
    // так борг і росте непомітно.
    std::map<std::string, std::size_t> baseline;
    std::ifstream baseline_file(baseline_path, std::ios::binary);
    if (!baseline_file.is_open()) {
        std::cerr << "немає " << baseline_path.string() << "\n";
        return 1;
    }
    std::string line;
    while (std::getline(baseline_file, line)) {
        const std::size_t hash = line.find('#');
        const std::string payload = Trim(hash == std::string::npos ? line : line.substr(0, hash));
        if (payload.empty()) {
            continue;
        }
        std::istringstream fields(payload);
        std::string name;
        std::size_t count = 0;
        if (!(fields >> name >> count) || count < 2) {
            std::cerr << "не розібрано рядок базової лінії: " << payload << "\n";
            return 1;
        }
        baseline[name] = count;
    }

    if (baseline.empty()) {
        std::cerr << "базова лінія порожня — перевірка була б вакуумною\n";
        return 1;
    }

    for (const std::string& name : duplicated) {
        std::string files;
        for (const std::string& f : where[name]) {
            files += (files.empty() ? "" : ", ") + f;
        }
        const std::size_t actual = where[name].size();
        const auto known = baseline.find(name);
        if (known == baseline.end()) {
            Fail("нова копія: `" + name + "` визначено у " + std::to_string(actual) +
                 " файлах (" + files +
                 "). Винесіть спільну реалізацію (зазвичай у src/lib/util) замість "
                 "другої копії. Якщо збіг імен випадковий — додайте рядок у "
                 "tests/duplicate_symbols.baseline із поясненням.");
            continue;
        }
        if (actual != known->second) {
            Fail("`" + name + "`: у базовій лінії " + std::to_string(known->second) +
                 " копій, у дереві " + std::to_string(actual) + " (" + files + "). " +
                 (actual > known->second
                      ? std::string("Борг виріс — цього робити не можна.")
                      : std::string("Борг зменшився — оновіть число в базовій лінії.")));
        }
    }
    for (const auto& entry : baseline) {
        if (duplicated.count(entry.first) == 0) {
            Fail("застарілий запис базової лінії: `" + entry.first +
                 "` більше не дублюється — приберіть рядок із "
                 "tests/duplicate_symbols.baseline. Базова лінія мусить лише "
                 "скорочуватись.");
        }
    }

    if (g_failures != 0) {
        std::cerr << g_failures << " проблем(и) дублювання\n";
        return 1;
    }
    std::cout << "symbol duplication: OK (" << inspected << " файлів, "
              << where.size() << " імен, " << duplicated.size()
              << " відомих дублікатів у базовій лінії)\n";
    return 0;
}
