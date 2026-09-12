#include "core/net/CaSettingsRegistry.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>

#include "core/HttpClient.h"
#include "util/FileSystem.h"
#include "util/Json.h"

namespace tamga::core::net {
namespace {

constexpr char kCacheFileName[] = "CAs.json";

// Метадані кешу лежать ПОРУЧ, а не в самому `CAs.json`: той файл — дослівне
// тіло відповіді сервера, і дописувати в нього свої поля означало б зберігати
// не те, що прийшло. Звірка з тілом однаково неможлива — воно не несе ані
// джерела, ані часу завантаження.
constexpr char kCacheMetaFileName[] = "CAs.source";

// Доба. Реєстр КНЕДП змінюється рідко — переїзд адрес чи поява нового
// надавача трапляються не щодня, — але «рідко» не означає «ніколи», а саме
// так поводився кеш без TTL.
constexpr std::int64_t kCacheTtlSeconds = 24 * 60 * 60;

std::filesystem::path CacheMetadataPath(const std::filesystem::path& cache) {
    return cache.parent_path() / kCacheMetaFileName;
}

// Формат навмисно найпростіший: перший рядок — джерело, другий — час запису
// у секундах Unix. Це внутрішній файл, який читає лише цей модуль; JSON тут
// додав би залежність від парсера заради двох полів.
void WriteCacheMetadata(const std::filesystem::path& meta_path, const std::string& source) {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    const std::string text = source + "\n" + std::to_string(now) + "\n";
    (void)tamga::util::WriteBinaryFileAtomic(
        meta_path, std::vector<std::uint8_t>(text.begin(), text.end()));
}

// Кеш придатний лише коли метадані є, джерело збігається і вік у межах TTL.
// Будь-яка невизначеність — відсутній файл, нерозбірливий вміст, час із
// майбутнього — трактується як «непридатний»: це лише призводить до
// перезавантаження, тоді як помилка в інший бік лишила б застарілий реєстр
// назавжди.
bool IsCacheFresh(const std::filesystem::path& meta_path, const std::string& source) {
    std::string text;
    std::string read_error;
    if (!util::ReadTextFileLimited(meta_path, util::kMaxCachedArtifactSize, text, read_error)) {
        return false;
    }
    const auto first_newline = text.find('\n');
    if (first_newline == std::string::npos) {
        return false;
    }
    if (text.substr(0, first_newline) != source) {
        return false;
    }
    const std::string timestamp_text = text.substr(first_newline + 1);
    errno = 0;
    char* end = nullptr;
    const long long written_at = std::strtoll(timestamp_text.c_str(), &end, 10);
    if (errno != 0 || end == timestamp_text.c_str() || written_at <= 0) {
        return false;
    }
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    if (written_at > now) {
        return false;  // час із майбутнього: годинник переставили, кеш не довіряємо
    }
    return (now - written_at) <= kCacheTtlSeconds;
}

// ── Розбір `CAs.json` поверх спільних примітивів `util/Json` ─────────────────
// Q-05 / O-03. Раніше тут жив власний мінімальний сканер, і обидві його
// відмінності від спільного парсера виявилися дефектами:
//
//   * результати `Take('}')`, `Take(']')` і частини `ReadString` не
//     перевірялися, тож обірваний документ приймався як повний. Проба
//     `[{"address":"ca.example"` — без закриття обʼєкта Й масиву — давала
//     `true` і один придатний запис, який далі міг потрапити в кеш;
//   * `\uXXXX` декодувався без склеювання сурогатних пар: `😀`
//     (U+1F600) ставав двома трибайтовими послідовностями (CESU-8,
//     `ED A0 BD ED B8 80`) замість одного символу `F0 9F 98 80`. Розбір казав
//     «успіх», а `TryDecodeUtf8ToUtf16` потім відхиляв такий CN як невалідний
//     UTF-8.
//
// Тепер токени читає `util::ParseJsonString` (сурогатні пари, відмова на
// сирих керівних байтах), а межі значень визначає `util::SkipJsonValue`, який
// перевіряє синтаксис ЦІЛКОМ і має спільний ліміт вкладеності (B-05).
//
// Політика «биті записи пропускаємо» лишилася, але тепер вона означає рівно
// те, що каже: запис пропускається ЛИШЕ після того, як його межі надійно
// встановлено структурним скануванням. Документ, у якому межі встановити
// неможливо (обрив, зайві дані), відхиляється цілком — це не «один битий
// запис», це невідомо скільки записів.

// Рівень вкладеності елемента масиву: сам масив — рівень 1.
constexpr std::size_t kArrayElementEnclosingDepth = 1;
// Значення member-а всередині елемента-обʼєкта: відкриті масив і обʼєкт.
constexpr std::size_t kEntryMemberEnclosingDepth = 2;

// Чи лишилися після розібраного документа непробільні байти. Зайвий «хвіст» —
// ознака того, що прочитано не той документ, який надіслали.
bool AtDocumentEnd(const std::string& text, std::size_t offset) {
    util::SkipJsonWhitespace(text, offset);
    return offset >= text.size();
}

// Розбирає ОДИН елемент масиву, межі якого вже перевірено ззовні.
// `false` означає «запис непридатний» — і тільки це, бо вийти за `end` тут
// уже неможливо.
bool ParseEntry(const std::string& text, const std::size_t begin, CaSettingsEntry& entry,
                std::string& ocsp_address, std::string& ocsp_port, std::string& cmp_address,
                std::string& tsp_address, std::string& tsp_port) {
    std::size_t pos = begin;
    util::SkipJsonWhitespace(text, pos);
    if (pos >= text.size() || text[pos] != '{') {
        return false;  // елемент масиву не є обʼєктом
    }
    ++pos;
    util::SkipJsonWhitespace(text, pos);
    if (pos < text.size() && text[pos] == '}') {
        return false;  // порожній обʼєкт — без `address` він усе одно непридатний
    }

    // Читає рядкове значення в `out`; значення іншого типу пропускається, а
    // поле лишається порожнім — далі його відсутність вирішує долю запису.
    const auto read_string_member = [&text, &pos](std::string& out) {
        util::SkipJsonWhitespace(text, pos);
        if (pos < text.size() && text[pos] == '"') {
            return util::ParseJsonString(text, pos, out);
        }
        return util::SkipJsonValue(text, pos, kEntryMemberEnclosingDepth);
    };

    while (true) {
        std::string key;
        if (!util::ParseJsonString(text, pos, key)) {
            return false;
        }
        util::SkipJsonWhitespace(text, pos);
        if (pos >= text.size() || text[pos] != ':') {
            return false;
        }
        ++pos;
        util::SkipJsonWhitespace(text, pos);

        if (key == "issuerCNs" && pos < text.size() && text[pos] == '[') {
            ++pos;
            util::SkipJsonWhitespace(text, pos);
            if (pos < text.size() && text[pos] == ']') {
                ++pos;
            } else {
                while (true) {
                    std::string cn;
                    if (!util::ParseJsonString(text, pos, cn)) {
                        return false;
                    }
                    entry.issuer_cns.push_back(std::move(cn));
                    util::SkipJsonWhitespace(text, pos);
                    if (pos < text.size() && text[pos] == ',') {
                        ++pos;
                        util::SkipJsonWhitespace(text, pos);
                        continue;
                    }
                    if (pos < text.size() && text[pos] == ']') {
                        ++pos;
                        break;
                    }
                    return false;
                }
            }
        } else if (key == "address") {
            if (!read_string_member(entry.address)) return false;
        } else if (key == "codeEDRPOU") {
            if (!read_string_member(entry.edrpou)) return false;
        } else if (key == "ocspAccessPointAddress") {
            if (!read_string_member(ocsp_address)) return false;
        } else if (key == "ocspAccessPointPort") {
            if (!read_string_member(ocsp_port)) return false;
        } else if (key == "cmpAddress") {
            if (!read_string_member(cmp_address)) return false;
        } else if (key == "tspAddress") {
            if (!read_string_member(tsp_address)) return false;
        } else if (key == "tspAddressPort") {
            if (!read_string_member(tsp_port)) return false;
        } else if (key == "directAccess") {
            entry.direct_access = text.compare(pos, 4, "true") == 0;
            if (!util::SkipJsonValue(text, pos, kEntryMemberEnclosingDepth)) return false;
        } else {
            if (!util::SkipJsonValue(text, pos, kEntryMemberEnclosingDepth)) return false;
        }

        util::SkipJsonWhitespace(text, pos);
        if (pos < text.size() && text[pos] == ',') {
            ++pos;
            util::SkipJsonWhitespace(text, pos);
            continue;
        }
        if (pos < text.size() && text[pos] == '}') {
            return true;
        }
        return false;
    }
}

std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

// "ca.tax.gov.ua" + "80" + типовий шлях -> "http://ca.tax.gov.ua/services/ocsp/"
// "ca.gp.gov.ua/cmp" -> шлях уже в адресі, свій не додаємо.
// Порт 80 у URL не пишемо; нетиповий (43222 у деяких КНЕДП) — пишемо.
std::string BuildUrl(const std::string& address, const std::string& port,
                     const char* default_path) {
    if (address.empty()) {
        return {};
    }
    if (address.compare(0, 7, "http://") == 0 || address.compare(0, 8, "https://") == 0) {
        return address;
    }

    const auto slash = address.find('/');
    const std::string host = (slash == std::string::npos) ? address : address.substr(0, slash);
    const std::string path = (slash == std::string::npos) ? std::string() : address.substr(slash);

    std::string url = "http://" + host;
    if (!port.empty() && port != "80") {
        url += ":" + port;
    }
    if (!path.empty()) {
        url += path;
    } else if (default_path != nullptr) {
        url += default_path;
    }
    return url;
}

}  // namespace

const char* CaSettingsRegistry::DefaultUrl() {
    // Перевірено 2026-09-02: `/download/CAs.json` віддає 404, чинна адреса —
    // `/download/certificates/CAs.json` (200, 33 записи). Довірчий список
    // `/download/tl/TL-UA-EC.xml` при цьому лишився на місці (200).
    return "https://czo.gov.ua/download/certificates/CAs.json";
}

bool CaSettingsRegistry::ParseJson(const std::string& json,
                                   std::vector<CaSettingsEntry>& out,
                                   std::string& error_message) {
    out.clear();
    // Fail-closed: за будь-якої відмови викликач не має отримати «половину
    // реєстру» — інакше частковий результат виглядав би як повний.
    const auto fail = [&out, &error_message](const char* message) {
        out.clear();
        error_message = message;
        return false;
    };

    std::size_t pos = 0;
    util::SkipJsonWhitespace(json, pos);
    if (pos >= json.size() || json[pos] != '[') {
        return fail("CAs.json: expected a top-level array");
    }
    ++pos;
    util::SkipJsonWhitespace(json, pos);
    if (pos < json.size() && json[pos] == ']') {
        ++pos;
        if (!AtDocumentEnd(json, pos)) {
            return fail("CAs.json: trailing data after the top-level array");
        }
        error_message.clear();
        return true;
    }

    while (true) {
        // Спершу МЕЖІ, потім вміст. Структурне сканування підтверджує, що
        // елемент завершений і синтаксично коректний; лише після цього має
        // сенс рішення «цей запис пропускаємо».
        const std::size_t element_start = pos;
        std::size_t element_end = pos;
        if (!util::SkipJsonValue(json, element_end, kArrayElementEnclosingDepth)) {
            return fail("CAs.json: malformed or truncated array element");
        }

        CaSettingsEntry entry;
        std::string ocsp_address;
        std::string ocsp_port;
        std::string cmp_address;
        std::string tsp_address;
        std::string tsp_port;
        const bool entry_ok = ParseEntry(json, element_start, entry, ocsp_address, ocsp_port,
                                         cmp_address, tsp_address, tsp_port);

        // Непридатні записи пропускаємо: реєстр із 32 придатних КНЕДП
        // корисніший за повну відмову через один запис без `address`.
        if (entry_ok && !entry.address.empty()) {
            entry.ocsp_url = BuildUrl(ocsp_address, ocsp_port, "/services/ocsp/");
            entry.cmp_url  = BuildUrl(cmp_address, std::string(), "/services/cmp/");
            entry.tsp_url  = BuildUrl(tsp_address, tsp_port, "/services/tsp/");
            out.push_back(std::move(entry));
        }

        pos = element_end;
        util::SkipJsonWhitespace(json, pos);
        if (pos < json.size() && json[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos < json.size() && json[pos] == ']') {
            ++pos;
            break;
        }
        return fail("CAs.json: unterminated top-level array");
    }

    if (!AtDocumentEnd(json, pos)) {
        return fail("CAs.json: trailing data after the top-level array");
    }
    if (out.empty()) {
        return fail("CAs.json: no usable CA entries");
    }
    error_message.clear();
    return true;
}

bool CaSettingsRegistry::Load(const std::string& work_dir,
                              const bool offline,
                              const std::string& url,
                              const std::int32_t timeout_ms,
                              std::vector<CaSettingsEntry>& out,
                              std::string& error_message) {
    out.clear();

    const std::string source = url.empty() ? DefaultUrl() : url;

    // Кеш більше не вічний. Доти будь-який розбірний `CAs.json` повертався
    // одразу — до перевірки `offline`, без TTL і без звірки з джерелом. Тобто
    // переїзд адрес КНЕДП або зміна `url` не впливали на вже наповнений кеш, а
    // онлайн-режим ніколи не оновлював реєстр, поки файл існував і парсився.
    std::filesystem::path cache;
    std::vector<CaSettingsEntry> cached_entries;
    bool cache_parsed = false;
    bool cache_usable = false;
    if (!work_dir.empty()) {
        cache = std::filesystem::u8path(work_dir) / kCacheFileName;
        std::string text;
        std::string read_error;
        if (util::ReadTextFileLimited(cache, util::kMaxCachedArtifactSize, text, read_error) &&
            !text.empty()) {
            std::string parse_error;
            cache_parsed = ParseJson(text, cached_entries, parse_error);
        }
        if (cache_parsed) {
            cache_usable = IsCacheFresh(CacheMetadataPath(cache), source);
        }
    }

    // Офлайн: придатність за TTL і джерелом не перевіряється — альтернативи
    // однаково немає, тож використовується будь-який розбірний кеш.
    if (offline) {
        if (cache_parsed) {
            out = std::move(cached_entries);
            return true;
        }
        error_message = "CA registry is not cached and offline mode forbids the download";
        return false;
    }

    if (cache_usable) {
        out = std::move(cached_entries);
        return true;
    }
    const auto response = HttpClient::Get(source, "application/json", timeout_ms);
    const bool http_ok = response.succeeded && response.status_code >= 200 &&
                         response.status_code < 300;

    std::string download_error;
    if (http_ok) {
        const auto& body = response.body;
        const std::string text(body.begin(), body.end());
        if (ParseJson(text, out, download_error)) {
            // Кешуємо лише те, що вже успішно розібрано — інакше в кеш
            // потрапляло б сміття. Метадані пишемо ПІСЛЯ тіла: якщо процес
            // урветься між двома записами, наступний запуск побачить кеш без
            // метаданих і вважатиме його непридатним, тобто перезавантажить.
            // Зворотний порядок дав би метадані, що описують чуже тіло.
            if (!cache.empty()) {
                std::error_code ec;
                std::filesystem::create_directories(cache.parent_path(), ec);
                if (tamga::util::WriteBinaryFileAtomic(
                        cache, std::vector<std::uint8_t>(text.begin(), text.end()))) {
                    WriteCacheMetadata(CacheMetadataPath(cache), source);
                }
            }
            return true;
        }
    } else {
        download_error = "CA registry download failed (status " +
                         std::to_string(response.status_code) + ")";
    }

    // Довантаження не вдалося. Непридатний кеш кращий за повну відмову:
    // застарілий реєстр дає лише АДРЕСИ, а придатність самого сертифіката
    // однаково вирішує fail-closed звірка з відкритим ключем у
    // `CertificateResolver`. Тобто прострочений кеш не може нічого
    // «підтвердити» — він може лише підказати, куди сходити.
    if (cache_parsed) {
        out = std::move(cached_entries);
        return true;
    }

    out.clear();
    error_message = download_error;
    return false;
}

const CaSettingsEntry* CaSettingsRegistry::Find(const std::vector<CaSettingsEntry>& entries,
                                                const std::string& hint) {
    if (hint.empty()) {
        return nullptr;
    }
    const std::string needle = ToLowerAscii(hint);

    // ЄДРПОУ — найточніша ознака, тому перший прохід саме за ним.
    for (const auto& entry : entries) {
        if (!entry.edrpou.empty() && entry.edrpou == hint) {
            return &entry;
        }
    }
    for (const auto& entry : entries) {
        if (!entry.address.empty() && ToLowerAscii(entry.address) == needle) {
            return &entry;
        }
    }
    for (const auto& entry : entries) {
        for (const auto& cn : entry.issuer_cns) {
            if (ToLowerAscii(cn).find(needle) != std::string::npos) {
                return &entry;
            }
        }
    }
    return nullptr;
}

}  // namespace tamga::core::net
