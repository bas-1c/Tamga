// Реалізація перенесена з анонімного простору імен `HttpClient.cpp` дослівно.

#include "core/net/HttpMessageSyntax.h"

#include "core/net/HttpAccessPolicy.h"

#include <cctype>
#include <sstream>
#include <string>

namespace tamga::core::net {

std::string ResponseHeaderValue(const std::string& headers, const std::string& requested_name) {
    const std::string name = LowerAscii(requested_name);
    std::istringstream stream(headers);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto colon = line.find(':');
        if (colon == std::string::npos || LowerAscii(line.substr(0U, colon)) != name) continue;
        std::size_t begin = colon + 1U;
        while (begin < line.size() && std::isspace(static_cast<unsigned char>(line[begin])) != 0) ++begin;
        std::size_t end = line.size();
        while (end > begin && std::isspace(static_cast<unsigned char>(line[end - 1U])) != 0) --end;
        return line.substr(begin, end - begin);
    }
    return {};
}

namespace {

// RFC 3986 §5.2.4 remove_dot_segments. Без нього `..` у відносному `Location`
// лишався б у шляху текстом і давав адресу, якої на сервері немає.
std::string RemoveDotSegments(std::string input) {
    std::string output;
    while (!input.empty()) {
        if (input.rfind("../", 0U) == 0U) {
            input.erase(0U, 3U);
        } else if (input.rfind("./", 0U) == 0U) {
            input.erase(0U, 2U);
        } else if (input.rfind("/./", 0U) == 0U) {
            input.replace(0U, 3U, "/");
        } else if (input == "/.") {
            input = "/";
        } else if (input.rfind("/../", 0U) == 0U || input == "/..") {
            if (input == "/..") {
                input = "/";
            } else {
                input.replace(0U, 4U, "/");
            }
            const auto slash = output.rfind('/');
            output.erase(slash == std::string::npos ? 0U : slash);
        } else if (input == "." || input == "..") {
            input.clear();
        } else {
            const auto next = input.find('/', input.front() == '/' ? 1U : 0U);
            output.append(input, 0U, next);
            input.erase(0U, next);
            if (next == std::string::npos) break;
        }
    }
    return output;
}

// Ділить посилання на шлях і «хвіст» (`?query` та/або `#fragment`).
void SplitRefPath(const std::string& ref, std::string& path, std::string& suffix) {
    const auto cut = ref.find_first_of("?#");
    path = ref.substr(0U, cut);
    suffix = cut == std::string::npos ? std::string{} : ref.substr(cut);
}

}  // namespace

// Розвʼязання відносного посилання за RFC 3986 §5.3 в обсязі, потрібному для
// `Location`. Попередня реалізація знала лише два випадки — абсолютний URI і
// шлях від кореня, — а решту зводила до «дописати до каталогу бази». Через це
// B-07: `//cdn.example/new` перетворювався на
// `https://origin.example//cdn.example/new`, а `?new=2` — на
// `https://origin.example/a/?new=2` замість `.../a/file?new=2`. Обходу
// перевірки призначення тут не було (ціль усе одно проходить `CheckDestination`,
// а помилка тримала запит на тому самому origin), але частина законних
// редиректів просто не відпрацьовувала.
std::string ResolveHttpRedirectUrl(const std::string& base, const std::string& location) {
    if (location.empty()) return {};

    // Абсолютний URI повертається як є: судити його — справа `CheckDestination`.
    const std::string lowered = LowerAscii(location);
    if (lowered.rfind("http://", 0U) == 0U || lowered.rfind("https://", 0U) == 0U) return location;

    const auto scheme_end = base.find("://");
    if (scheme_end == std::string::npos || scheme_end == 0U) return {};
    const auto authority_begin = scheme_end + 3U;
    const auto authority_end = base.find_first_of("/?#", authority_begin);
    if (authority_end == authority_begin) return {};  // порожня authority
    const std::string scheme = base.substr(0U, scheme_end);
    const std::string origin = base.substr(0U, authority_end);

    // Шлях і query бази — окремо, бо кожна форма посилання бере з бази своє.
    std::string base_path;
    std::string base_query;
    if (authority_end != std::string::npos) {
        const std::string rest = base.substr(authority_end);
        const auto fragment = rest.find('#');
        const std::string rest_no_fragment = rest.substr(0U, fragment);
        const auto query = rest_no_fragment.find('?');
        base_path = rest_no_fragment.substr(0U, query);
        if (query != std::string::npos) base_query = rest_no_fragment.substr(query);
    }
    if (base_path.empty()) base_path = "/";

    // Protocol-relative: успадковується лише схема, authority береться з
    // посилання. Саме цей випадок стара реалізація перетворювала на шлях.
    if (location.rfind("//", 0U) == 0U) {
        std::string path;
        std::string suffix;
        SplitRefPath(location.substr(2U), path, suffix);
        const auto slash = path.find('/');
        const std::string authority = path.substr(0U, slash);
        if (authority.empty()) return {};
        const std::string ref_path = slash == std::string::npos ? std::string{} : path.substr(slash);
        return scheme + "://" + authority + RemoveDotSegments(ref_path) + suffix;
    }

    // Тільки фрагмент: база лишається цілком, змінюється лише фрагмент.
    if (location.front() == '#') return origin + base_path + base_query + location;

    // Тільки query: шлях бази зберігається ПОВНІСТЮ, а не обрізається до
    // каталогу — саме тут стара реалізація губила останній сегмент.
    if (location.front() == '?') return origin + base_path + location;

    std::string ref_path;
    std::string suffix;
    SplitRefPath(location, ref_path, suffix);

    // Шлях від кореня.
    if (location.front() == '/') return origin + RemoveDotSegments(ref_path) + suffix;

    // Відносний шлях: merge(base, ref) за RFC 3986 §5.2.3 — до останнього
    // слеша шляху бази включно.
    const auto slash = base_path.rfind('/');
    const std::string merged =
        (slash == std::string::npos ? std::string{"/"} : base_path.substr(0U, slash + 1U)) + ref_path;
    return origin + RemoveDotSegments(merged) + suffix;
}

bool IsRedirectStatus(const long status) {
    return status == 301L || status == 302L || status == 303L || status == 307L || status == 308L;
}

// Приймає за значенням і забирає тіло переміщенням: копія тут була б другим

}  // namespace tamga::core::net
