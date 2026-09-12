#pragma once

// Хвиля 8, п.5: JSON-шар як окрема одиниця трансляції.
//
// До винесення цей код жив ВСЕРЕДИНІ моноліту `Session`: 313 рядків парсера
// в анонімному namespace `SessionHelpers.ipp`, який текстово включається в
// `Session.cpp` разом із рештою 6300 рядків. Він не мав ані заголовка, ані
// власних тестів, і його не можна було використати ззовні — тому поруч виросли
// ще дві незалежні копії JSON-логіки:
//
//   * `policy/UserReportBuilder.cpp` — власний `EscapeJson`, побайтово
//     тотожний тому, що в `SessionHelpers`;
//   * `policy/PolicyCache.cpp` — власний `ExtractJsonString`/`ExtractJsonBool`,
//     і от вони тотожними НЕ були.
//
// Розбіжність предметна: парсер `PolicyCache` не декодував `\uXXXX`. Його
// `default`-гілка штовхала в результат літеру `u`, після чого чотири
// шістнадцяткові цифри копіювались як звичайний текст. Той самий файл
// `state.json`, прочитаний двома парсерами одного продукту, давав різні
// значення. Записує ці файли сама Tamga через `EscapeJson`, який для будь-якого
// символу < 0x20 емітує саме `\u00XX` — тобто round-trip псував дані.
//
// Тепер парсер один, і він той, що коректно декодує escape-послідовності
// в UTF-8.

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace tamga::util {

// Екранує рядок для вставки в JSON-літерал. Символи < 0x20 виводяться як
// `\u00XX`; байти >= 0x20 (зокрема UTF-8 кирилиця) проходять без змін.
std::string EscapeJson(const std::string& value);

// "true"/"false" для JSON. Копії жили в `core/Session.h` і
// `policy/UserReportBuilder.cpp`.
const char* BoolJson(bool value);

// Знаходить member `key` на верхньому рівні об'єкта й повертає його значення.
// `ExtractJsonString` декодує `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`
// і `\uXXXX` (включно з сурогатними парами) у UTF-8.
//
// `std::nullopt` означає «немає такого member або значення не того типу» —
// це не помилка розбору, а відсутність факту.
//
// Вкладеність обмежена: документ глибший за 100 рівнів (рівень 1 — зовнішній
// об'єкт) відхиляється цілком, і обидві функції повертають `std::nullopt`.
// Причина — B-05: пропуск невідомих member-ів рекурсивний, і без ліміту
// вкладеність недовіреного вводу лягала на машинний стек (20000 рівнів,
// ~40 КБ вводу → STATUS_STACK_OVERFLOW у процесі-хості 1С). Легітимні входи —
// дескриптор `LoadKey` і метадані кешу політик — мають глибину одиниць.
std::optional<std::string> ExtractJsonString(const std::string& json, const std::string& key);
std::optional<bool> ExtractJsonBool(const std::string& json, const std::string& key);

// Те саме, але для вкладеного шляху: `{"diagnostics","flags","signatureValid"}`.
// Кожен елемент шляху, крім останнього, має бути об'єктом. Порожній шлях —
// `std::nullopt`. Ліміт вкладеності діє так само.
//
// O-03: потрібне тим, хто читає технічний звіт перевірки — там факти лежать
// у секціях (`diagnostics.flags`, `revocation.revocationStatus`), і без
// шляху єдиною альтернативою був пошук підрядка в тексті JSON.
std::optional<std::string> ExtractJsonStringPath(const std::string& json,
                                                 const std::vector<std::string>& path);
std::optional<bool> ExtractJsonBoolPath(const std::string& json,
                                        const std::vector<std::string>& path);

// ── Спільні примітиви розбору (O-03) ─────────────────────────────────────────
// Винесені назовні, щоб поруч не виростала ЩЕ ОДНА копія сканера. Саме так
// зʼявився дефект Q-05: `core/net/CaSettingsRegistry.cpp` мав власний
// мінімальний сканер, який декодував `\uXXXX` без склеювання сурогатних пар
// (тобто видавав CESU-8) і ігнорував результат зчитування токенів.
//
// Усі три працюють з `offset` як з курсором: при успіху він стоїть одразу за
// спожитим фрагментом, при невдачі його значення не визначене.

// Пропускає пробільні символи JSON.
void SkipJsonWhitespace(const std::string& json, std::size_t& offset);

// Розбирає рядковий токен, що починається на `json[offset] == '"'`.
// Декодує `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t` і `\uXXXX` разом із
// сурогатними парами; результат — коректний UTF-8. Відхиляє неспарені
// сурогати, невідомі escape-послідовності, сирі керівні байти < 0x20 і
// незавершений рядок.
bool ParseJsonString(const std::string& json, std::size_t& offset, std::string& out);

// Пропускає одне JSON-значення БУДЬ-ЯКОГО типу, перевіряючи його синтаксис
// цілком. `enclosing_depth` — скільки композитів уже відкрито над цим
// значенням (0 — значення на верхньому рівні документа). Повертає false, коли
// значення синтаксично некоректне, обірване або перевищує ліміт вкладеності.
bool SkipJsonValue(const std::string& json, std::size_t& offset, std::size_t enclosing_depth);

} // namespace tamga::util
