// Живі перевірки проти реальних сервісів ЦЗО (Хвиля 8, п.6).
//
// Правила, за якими ця сюїта написана, лежать у `docs/live-replay-suite-dod.md`.
// Три з них визначають кожен рядок нижче:
//
//   1. НЕДОСТУПНІСТЬ СЕРВІСУ — НЕ ПРОВАЛ. Тест перевіряє нашу поведінку, а не
//      аптайм ЦЗО. Якщо endpoint не відповів, повертаємо 77 (CTest покаже
//      "Skipped"), а не помилку. Провал резервується для випадку, коли сервіс
//      ВІДПОВІВ, а ми обробили відповідь неправильно.
//   2. ПРОПУСК МУСИТЬ БУТИ ВИДИМИМ. Код 77 і причина в stderr — щоб «зелений»
//      прогін не приховав, що мережі не було. Мовчазний успіх тут був би тією
//      самою брехнею, що й зелений ctest на старих бінарниках.
//   3. ПЕРЕВІРЯЮТЬСЯ ІНВАРІАНТИ, А НЕ ЧИСЛА. Асерт «85 якорів» зламався б
//      щойно ЦЗО оновить список — і сюїту почали б ігнорувати. Тому нижче
//      немає жодного очікуваного числа: лише властивості, які мусять
//      виконуватися для БУДЬ-ЯКОГО коректного стану довірчого списку.
//
// Ця ціль не входить у типовий набір: вона реєструється лише при
// `-DTAMGA_ENABLE_LIVE_POLICY_TESTS=ON`. Опція повернулася разом із тестами,
// які вона вмикає — доти вона була порожньою обіцянкою і її прибрали.

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#include "core/policy/TrustListSettings.h"
#include "core/policy/TrustListSync.h"

namespace fs = std::filesystem;

namespace {

constexpr int kSkip = 77;

int g_failures = 0;

void Check(const bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        ++g_failures;
    }
}

std::string ReadTextFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

std::size_t CountFiles(const fs::path& dir) {
    std::error_code ec;
    if (!fs::exists(dir, ec)) {
        return 0;
    }
    std::size_t count = 0;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (entry.is_regular_file()) {
            ++count;
        }
    }
    return count;
}

} // namespace

int main() {
    const fs::path work_dir =
        fs::temp_directory_path() / "tamga-live-policy-tests";
    std::error_code ec;
    fs::remove_all(work_dir, ec);
    fs::create_directories(work_dir, ec);
    if (ec) {
        std::cerr << "не вдалося створити робочий каталог: " << ec.message() << "\n";
        return 1;
    }

    tamga::core::TrustListSettings settings;
    std::cerr << "endpoint: " << settings.url << "\n";
    std::cerr << "timeout : " << settings.timeout_ms << " мс\n";

    tamga::core::policy::TrustListSync sync;
    const auto result = sync.Sync(work_dir.string(), settings);

    // Правило 1: сервіс не відповів -> ПРОПУСК, не провал.
    if (!result.succeeded) {
        std::cerr << "\nЦЗО недоступний або відповів помилкою — тест ПРОПУЩЕНО.\n"
                  << "  причина     : " << result.message << "\n"
                  << "  cache_status: " << result.cache_status << "\n"
                  << "\nЦе НЕ провал: сюїта перевіряє нашу поведінку, а не аптайм ЦЗО.\n"
                  << "Провал тут означав би, що сервіс відповів, а ми обробили відповідь\n"
                  << "неправильно. Див. docs/live-replay-suite-dod.md.\n";
        fs::remove_all(work_dir, ec);
        return kSkip;
    }

    std::cerr << "\nсинхронізація вдалася; перевіряємо інваріанти\n";

    // --- Інваріант 1: підпис списку перевірено, а не пропущено ---------------
    //
    // Найважливіший з усіх. Порожній або «не підтримується» статус означав би,
    // що ми взяли довірчі якорі з документа, справжність якого не встановлено.
    std::cerr << "  xmlSignatureStatus = " << result.xml_signature_status << "\n";
    Check(!result.xml_signature_status.empty(),
          "підпис TL: статус не має бути порожнім");
    Check(result.xml_signature_status != "not-checked",
          "підпис TL мусить бути перевірений, а не пропущений");
    Check(result.xml_signature_status != "failed",
          "підпис TL не має бути відхилений на справжньому списку ЦЗО — "
          "якщо це сталося, або змінився формат підпису, або зламався верифікатор");

    // --- Інваріант 2: якорі справді матеріалізувалися ------------------------
    //
    // Число навмисно не фіксується: воно змінюється щоразу, коли ЦЗО оновлює
    // список. Фіксується лише те, що їх БІЛЬШЕ НУЛЯ — інакше «успішна»
    // синхронізація дала б порожнє сховище довіри, і кожна подальша перевірка
    // мовчки провалювалася б у «немає якоря».
    const std::size_t anchors = CountFiles(work_dir / "trust-store");
    const std::size_t tsa_anchors = CountFiles(work_dir / "tsa-store");
    std::cerr << "  trust-store = " << anchors << " файлів, tsa-store = "
              << tsa_anchors << "\n";
    Check(anchors > 0, "успішна синхронізація мусить матеріалізувати хоча б один довірчий якір");
    Check(tsa_anchors > 0, "довірчий список ЦЗО мусить дати хоча б один TSA-якір");

    // --- Інваріант 3: метадані читаються і не суперечать сховищу -------------
    const std::string metadata = ReadTextFile(work_dir / "policy" / "trust-store-metadata.json");
    Check(!metadata.empty(), "метадані довірчого сховища мусять бути записані й читатися");
    Check(metadata.find("\"sourceUrl\"") != std::string::npos,
          "метадані мусять фіксувати, звідки взято список");
    Check(metadata.find("\"lastSync\"") != std::string::npos,
          "метадані мусять фіксувати час синхронізації");

    // --- Інваріант 4: адреси сервісів із TL не на відкритому HTTP -----------
    //
    // Перша версія цієї перевірки рахувала `http://` у ВСІХ метаданих і давала
    // 1196 попереджень — бо `serviceType` і `status` в ETSI TSL є URI-
    // ідентифікаторами, а не адресами. Перевірка, що спрацьовує завжди, гірша
    // за відсутню: її навчаються ігнорувати.
    //
    // Тепер дивимося рівно на три поля, які справді містять адреси. Станом на
    // 2026-08-28 у них немає жодного `http://`.
    std::size_t insecure_endpoints = 0;
    for (const char* key : {"\"crlUrls\":", "\"ocspUrls\":", "\"tspUrls\":"}) {
        std::size_t pos = 0;
        while ((pos = metadata.find(key, pos)) != std::string::npos) {
            const std::size_t open = metadata.find('[', pos);
            const std::size_t close = (open == std::string::npos)
                                          ? std::string::npos
                                          : metadata.find(']', open);
            if (open == std::string::npos || close == std::string::npos) {
                break;
            }
            const std::string span = metadata.substr(open, close - open);
            std::size_t at = 0;
            while ((at = span.find("http://", at)) != std::string::npos) {
                ++insecure_endpoints;
                at += 7;
            }
            pos = close;
        }
    }
    if (insecure_endpoints != 0) {
        // Свідомо НЕ провал: адресу публікує ЦЗО, і це не наша помилка.
        // Але побачити зміну треба — мовчки ковтати її не можна (правило 1
        // з DoD: провал резервується для випадку, коли ми обробили відповідь
        // неправильно).
        std::cerr << "  УВАГА: у crl/ocsp/tsp-адресах " << insecure_endpoints
                  << " разів трапився http:// — це зміна на боці ЦЗО\n";
    } else {
        std::cerr << "  усі crl/ocsp/tsp-адреси зі списку — https\n";
    }

    // --- Інваріант 5: повторна синхронізація не ламає сховище ----------------
    //
    // Друга поспіль синхронізація — типовий сценарій у 1С (кожен запуск
    // компоненти). Вона мусить лишити сховище щонайменше не гіршим.
    const auto second = sync.Sync(work_dir.string(), settings);
    Check(second.succeeded || second.used_cache,
          "повторна синхронізація мусить або вдатися, або спертися на кеш");
    const std::size_t anchors_after = CountFiles(work_dir / "trust-store");
    Check(anchors_after >= anchors,
          "повторна синхронізація не має зменшувати кількість довірчих якорів");

    fs::remove_all(work_dir, ec);

    if (g_failures != 0) {
        std::cerr << "\nlive_policy_tests: " << g_failures << " failure(s)\n";
        return 1;
    }
    std::cout << "live_policy_tests: усі інваріанти виконано\n";
    return 0;
}
