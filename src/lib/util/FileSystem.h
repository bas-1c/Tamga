#pragma once

#include <filesystem>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace tamga::util {

// В-04: спільна межа розміру недовіреного вхідного файла.
//
// Ліміт 64 MiB існував лише в `SessionHelpers.ipp` і застосовувався виключно
// на шляху `Session`. C ABI, CLI та NativeAPI `VerifyFile(xades/pades)` читали
// файл цілком через `istreambuf_iterator` без жодної перевірки розміру, тобто
// успадкували політику лише на папері. Для компоненти, що працює всередині
// процесу 1С, керована ззовні OOM — це падіння всієї платформи.
inline constexpr std::uintmax_t kMaxInputFileSize = 64ULL * 1024ULL * 1024ULL;

// Хвиля 8, п.2: межі для читання файлів, які проєкт створює сам у `workDir`.
//
// До консолідації дев'ять місць читали такі файли сирим `std::ifstream` через
// `istreambuf_iterator` — тобто цілком і без жодного обмеження розміру.
//
// Числа тут не вигадані. Кешовані артефакти (CRL, TL XML, JSON стану, реєстр
// КНЕДП) потрапляють у `workDir` виключно через `HttpClient`, який уже
// обмежує відповідь 64 MiB (`kMaxHttpResponseSize`). Тому читання з диска
// просто успадковує ту саму межу: файл, більший за неї, не міг з'явитися там
// нашим шляхом, і читати його цілком у пам'ять немає підстав.
inline constexpr std::uintmax_t kMaxCachedArtifactSize = 64ULL * 1024ULL * 1024ULL;

// Окремий сертифікат або PEM-бандл із trust-store. DER-сертифікат — це
// одиниці кілобайтів, тож 4 MiB залишає запас у три порядки і все ще вміщує
// бандл на тисячі сертифікатів.
//
// Пропуск файлу за розміром тут fail-closed: відсутній trust anchor означає,
// що ланцюг не побудується, а не що перевірка мовчки пройде.
inline constexpr std::uintmax_t kMaxCertificateFileSize = 4ULL * 1024ULL * 1024ULL;

// ADR-027: шлях у UTF-8. Жили ТРИ тотожні копії — у CertificateResolver,
// PolicyCache і ValidationEngine.
std::string PathToUtf8(const std::filesystem::path& path);

// Той самий шлях із доданим суфіксом (напр. ".tmp").
std::filesystem::path PathWithSuffix(std::filesystem::path path, const char* suffix);

// П-12: чому запис вихідного файлу централізований і атомарний.
//
// `WriteBinaryFileAtomic` існував і раніше, але користувався ним лише
// `RawSignFile`. Решта вихідних шляхів — три в `SessionAsicOps.ipp`, три в
// `src/cli/main.cpp`, два в `src/lib/core/TamgaCApi.cpp` — писали напряму
// `std::ofstream ... trunc`. `trunc` обнуляє ціль ДО того, як з'явиться хоч
// один байт нового вмісту, тож будь-яка невдача посередині (немає місця,
// зникла мережева шара, процес убито) лишає на місці цінного підписаного
// контейнера порожній або усічений файл. Для інструмента, який заміщує
// підписані документи, це найгірший з можливих станів: помилку видно не
// одразу, а при наступній перевірці.
//
// СЕМАНТИКА ПЕРЕЗАПИСУ — визначена тут ОДИН раз для всіх вихідних шляхів:
//
//   * запис завжди ЗАМІЩУЄ наявний файл цілком і атомарно (заміна імені);
//   * читач цільового шляху бачить або старий вміст, або повний новий —
//     проміжного стану немає;
//   * при невдачі ціль лишається недоторканою, а тимчасовий файл прибирається;
//   * політику «не перезаписувати наявний файл» реалізує ВИКЛИКАЧ до виклику
//     (напр. `settings.allow_overwrite` у `SessionAsicOps.ipp`). Це рішення
//     політики, а не властивість запису, і змішувати їх тут не можна: writer
//     не знає, чи заміщення дозволене.
//
// Тимчасовий файл створюється в ТОМУ САМОМУ каталозі, що й ціль, з унікальним
// іменем. Каталог той самий тому, що заміна імені атомарна лише в межах тому.
// Ім'я унікальне тому, що фіксований `<target>.tmp` робив два процеси, які
// пишуть ту саму ціль, суперниками за ОДИН тимчасовий файл: перший `remove`
// зносив чужий напівзаписаний файл, а `rename` міг перенести чужі байти під
// нашим іменем.
enum class AtomicWriteStatus {
    Ok,
    // Ціль непридатна: неможливо створити каталог або тимчасовий файл поруч
    // із нею. З погляду виклику це помилка АРГУМЕНТА.
    TargetUnusable,
    // Запис або заміна імені зірвалися. Ціль при цьому не зачеплена.
    WriteFailed,
};

struct AtomicWriteResult {
    AtomicWriteStatus status{AtomicWriteStatus::Ok};
    std::string message;

    explicit operator bool() const noexcept { return status == AtomicWriteStatus::Ok; }
};

// Базова операція. Розрізнення статусів потрібне тому, що `Session` віддає
// різні `ErrorCode` для непридатного шляху і для зірваного запису; без нього
// консолідація вісьмох місць запису мовчки погіршила б діагностику.
AtomicWriteResult WriteBytesAtomic(const std::filesystem::path& final_path,
                                   const void* data,
                                   std::size_t size);

bool WriteBinaryFileAtomic(const std::filesystem::path& final_path, const std::vector<std::uint8_t>& data);
bool WriteTextFileAtomic(const std::filesystem::path& final_path, const std::string& text);

// Читає файл цілком, але не більше `max_size` байтів.
//
// Розмір перевіряється ДО читання (`file_size`), а потім ще раз за фактом —
// файл міг вирости між stat і read. Повертає false і заповнює
// `error_message`, якщо шлях недоступний або ліміт перевищено; `out` при
// невдачі порожній.
//
// O-01: для звичайного файла перевірений розмір використовується ще й як
// місткість `out` — вона резервується один раз. Це властивість реалізації,
// а не контракту: прикладний код не має будувати логіку на `capacity()`
// (`tests/input_limit_tests.cpp` перевіряє її навмисно, як white-box-сторожа
// проти повернення перевиділення), а потокова перевірка ліміту лишається
// чинною незалежно від резервування.
bool ReadBinaryFileLimited(const std::filesystem::path& path,
                           std::uintmax_t max_size,
                           std::vector<std::uint8_t>& out,
                           std::string& error_message);

// Те саме для текстового вмісту (байти читаються без трансляції).
bool ReadTextFileLimited(const std::filesystem::path& path,
                         std::uintmax_t max_size,
                         std::string& out,
                         std::string& error_message);

} // namespace tamga::util
