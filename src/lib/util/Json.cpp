#include "util/Json.h"
#include "util/Utf.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>

namespace tamga::util {
namespace {
// B-05 (аудит opus-2026-09-08, Q-01 стороннього аудиту 2026-09-04):
// `SkipJsonComposite` і `SkipJsonValue` викликали одна одну без жодного
// лічильника глибини. Вкладеність недовіреного JSON лягала один-в-один на
// машинний стек, тож 20000 рівнів (усього ~40 КБ вводу — на три порядки менше
// за ліміт вводу в 64 МіБ) валили процес-хост 1С через STATUS_STACK_OVERFLOW
// (0xC00000FD). Обмеження РОЗМІРУ вводу від цього не рятує: коштує один байт
// за рівень.
//
// Обраний спосіб — явна перевірка глибини ПЕРЕД рекурсивним входом, а не
// збільшення стека і не переписування на ітерацію. Причина: з цим лімітом
// глибина рекурсії обмежена константою, тобто споживання стека стає
// детермінованим і мізерним (сотня кадрів). Ітеративний варіант (як
// `ForEachElement` у `xml/XmlCore.h`) потрібен там, де ГЛИБОКИЙ ввід
// легітимний і його треба розібрати; тут глибокий ввід легітимним не буває,
// і правильна відповідь на нього — відмова, а не розбір.
//
// Значення ліміту. Реальні входи цього парсера — плаский JSON-дескриптор
// `LoadKey` (`{"path":...,"password":...}`) і метадані кешу політик; їхня
// глибина — одиниці рівнів. Сто рівнів дає запас у десятки разів над усім, що
// продукує й читає сама Tamga, і водночас утримує рекурсію в межах сотні
// кадрів. Рівень 1 — це сам зовнішній об'єкт.
constexpr std::size_t kMaxJsonNestingDepth = 100;

// ADR-027: копія прибрана — реалізація одна, в `util/Utf`.
using tamga::util::AppendUtf8CodePoint;

bool ParseJsonHexQuad(const std::string& json, std::size_t& offset, std::uint32_t& value) {
    value = 0;
    if (offset + 4 > json.size()) {
        return false;
    }

    for (std::size_t i = 0; i < 4; ++i) {
        const char ch = json[offset++];
        value <<= 4U;
        if (ch >= '0' && ch <= '9') {
            value |= static_cast<std::uint32_t>(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            value |= static_cast<std::uint32_t>(10 + (ch - 'a'));
        } else if (ch >= 'A' && ch <= 'F') {
            value |= static_cast<std::uint32_t>(10 + (ch - 'A'));
        } else {
            return false;
        }
    }

    return true;
}

}  // namespace

void SkipJsonWhitespace(const std::string& json, std::size_t& offset) {
    while (offset < json.size() && std::isspace(static_cast<unsigned char>(json[offset])) != 0) {
        ++offset;
    }
}

bool ParseJsonString(const std::string& json, std::size_t& offset, std::string& out) {
    if (offset >= json.size() || json[offset] != '"') {
        return false;
    }
    ++offset;
    out.clear();

    while (offset < json.size()) {
        const char ch = json[offset++];
        if (ch == '"') {
            return true;
        }
        if (static_cast<unsigned char>(ch) < 0x20U) {
            return false;
        }
        if (ch != '\\') {
            out.push_back(ch);
            continue;
        }
        if (offset >= json.size()) {
            return false;
        }

        const char escaped = json[offset++];
        switch (escaped) {
            case '"':
            case '\\':
            case '/':
                out.push_back(escaped);
                break;
            case 'b':
                out.push_back('\b');
                break;
            case 'f':
                out.push_back('\f');
                break;
            case 'n':
                out.push_back('\n');
                break;
            case 'r':
                out.push_back('\r');
                break;
            case 't':
                out.push_back('\t');
                break;
            case 'u': {
                std::uint32_t code_point = 0;
                if (!ParseJsonHexQuad(json, offset, code_point)) {
                    return false;
                }

                if (code_point >= 0xD800U && code_point <= 0xDBFFU) {
                    if (offset + 6 > json.size() || json[offset] != '\\' || json[offset + 1] != 'u') {
                        return false;
                    }
                    offset += 2;
                    std::uint32_t trail = 0;
                    if (!ParseJsonHexQuad(json, offset, trail) || trail < 0xDC00U || trail > 0xDFFFU) {
                        return false;
                    }
                    code_point = 0x10000U + ((code_point - 0xD800U) << 10U) + (trail - 0xDC00U);
                }

                if (!AppendUtf8CodePoint(code_point, out)) {
                    return false;
                }
                break;
            }
            default:
                return false;
        }
    }

    return false;
}

namespace {

// `depth` — рівень самого композита: 1 для зовнішнього об'єкта документа.
bool SkipJsonComposite(const std::string& json, std::size_t& offset, char open, char close,
                       std::size_t depth);

bool SkipJsonNumberToken(const std::string& json, std::size_t& offset) {
    const std::size_t start = offset;
    if (offset < json.size() && json[offset] == '-') {
        ++offset;
    }

    if (offset >= json.size()) {
        return false;
    }
    if (json[offset] == '0') {
        ++offset;
    } else {
        if (!std::isdigit(static_cast<unsigned char>(json[offset]))) {
            return false;
        }
        while (offset < json.size() && std::isdigit(static_cast<unsigned char>(json[offset])) != 0) {
            ++offset;
        }
    }

    if (offset < json.size() && json[offset] == '.') {
        ++offset;
        if (offset >= json.size() || !std::isdigit(static_cast<unsigned char>(json[offset]))) {
            return false;
        }
        while (offset < json.size() && std::isdigit(static_cast<unsigned char>(json[offset])) != 0) {
            ++offset;
        }
    }

    if (offset < json.size() && (json[offset] == 'e' || json[offset] == 'E')) {
        ++offset;
        if (offset < json.size() && (json[offset] == '+' || json[offset] == '-')) {
            ++offset;
        }
        if (offset >= json.size() || !std::isdigit(static_cast<unsigned char>(json[offset]))) {
            return false;
        }
        while (offset < json.size() && std::isdigit(static_cast<unsigned char>(json[offset])) != 0) {
            ++offset;
        }
    }

    return offset > start;
}

bool SkipJsonLiteralToken(const std::string& json, std::size_t& offset, const char* literal) {
    const std::size_t literal_len = std::char_traits<char>::length(literal);
    if (json.compare(offset, literal_len, literal) != 0) {
        return false;
    }
    offset += literal_len;
    return true;
}

}  // namespace

bool SkipJsonValue(const std::string& json, std::size_t& offset, const std::size_t enclosing_depth) {
    SkipJsonWhitespace(json, offset);
    if (offset >= json.size()) {
        return false;
    }

    const char ch = json[offset];
    if (ch == '"') {
        std::string ignored;
        return ParseJsonString(json, offset, ignored);
    }
    if (ch == '{') {
        return SkipJsonComposite(json, offset, '{', '}', enclosing_depth + 1);
    }
    if (ch == '[') {
        return SkipJsonComposite(json, offset, '[', ']', enclosing_depth + 1);
    }
    if (ch == 't') {
        return SkipJsonLiteralToken(json, offset, "true");
    }
    if (ch == 'f') {
        return SkipJsonLiteralToken(json, offset, "false");
    }
    if (ch == 'n') {
        return SkipJsonLiteralToken(json, offset, "null");
    }
    return SkipJsonNumberToken(json, offset);
}

namespace {

// `depth` — рівень самого цього композита: 1 для зовнішнього об'єкта документа.
bool SkipJsonComposite(const std::string& json, std::size_t& offset, const char open, const char close,
                       const std::size_t depth) {
    // Fail-closed: перевищення ліміту — відмова розбору, а не тихе усічення.
    // Мовчазне усічення тут означало б, що частина дескриптора прочитана, а
    // частина — ні, і виклик пішов би далі з половиною даних.
    if (depth > kMaxJsonNestingDepth) {
        return false;
    }
    if (offset >= json.size() || json[offset] != open) {
        return false;
    }
    ++offset;
    SkipJsonWhitespace(json, offset);
    if (offset < json.size() && json[offset] == close) {
        ++offset;
        return true;
    }

    while (offset < json.size()) {
        if (open == '{') {
            std::string ignored_key;
            if (!ParseJsonString(json, offset, ignored_key)) {
                return false;
            }
            SkipJsonWhitespace(json, offset);
            if (offset >= json.size() || json[offset] != ':') {
                return false;
            }
            ++offset;
            SkipJsonWhitespace(json, offset);
        }

        if (!SkipJsonValue(json, offset, depth)) {
            return false;
        }
        SkipJsonWhitespace(json, offset);
        if (offset >= json.size()) {
            return false;
        }
        if (json[offset] == close) {
            ++offset;
            return true;
        }
        if (json[offset] != ',') {
            return false;
        }
        ++offset;
        SkipJsonWhitespace(json, offset);
    }

    return false;
}

// `object_offset` — позиція `{` об'єкта, у якому шукаємо. `depth` — рівень
// цього об'єкта (1 для зовнішнього об'єкта документа): значення його member-ів
// мають рівно стільки відкритих композитів над собою.
bool FindJsonMemberValue(const std::string& json, const std::string& key,
                         const std::size_t object_offset, const std::size_t depth,
                         std::size_t& value_offset) {
    std::size_t offset = object_offset;
    SkipJsonWhitespace(json, offset);
    if (offset >= json.size() || json[offset] != '{') {
        return false;
    }
    ++offset;
    SkipJsonWhitespace(json, offset);
    if (offset < json.size() && json[offset] == '}') {
        return false;
    }

    while (offset < json.size()) {
        std::string current_key;
        if (!ParseJsonString(json, offset, current_key)) {
            return false;
        }
        SkipJsonWhitespace(json, offset);
        if (offset >= json.size() || json[offset] != ':') {
            return false;
        }
        ++offset;
        SkipJsonWhitespace(json, offset);

        if (current_key == key) {
            value_offset = offset;
            return true;
        }

        // Об'єкт відкритий тут же, вручну, тож над значеннями його member-ів
        // відкрито рівно `depth` композитів.
        if (!SkipJsonValue(json, offset, depth)) {
            return false;
        }
        SkipJsonWhitespace(json, offset);
        if (offset >= json.size()) {
            return false;
        }
        if (json[offset] == '}') {
            return false;
        }
        if (json[offset] != ',') {
            return false;
        }
        ++offset;
        SkipJsonWhitespace(json, offset);
    }

    return false;
}

// Спускається шляхом ключів: кожен крок, крім останнього, має бути об'єктом.
bool FindJsonPathValue(const std::string& json, const std::vector<std::string>& path,
                       std::size_t& value_offset) {
    if (path.empty()) {
        return false;
    }
    std::size_t offset = 0;
    for (std::size_t i = 0; i < path.size(); ++i) {
        std::size_t next = 0;
        if (!FindJsonMemberValue(json, path[i], offset, i + 1, next)) {
            return false;
        }
        offset = next;
    }
    value_offset = offset;
    return true;
}

// Спільне для `ExtractJsonBool` і `ExtractJsonBoolPath`: значення має бути
// саме літералом `true`/`false`, а не префіксом чогось іншого.
std::optional<bool> ReadBoolAt(const std::string& json, const std::size_t value_offset) {
    const auto is_value_terminator = [&json](const std::size_t offset) {
        return offset >= json.size() || json[offset] == ',' || json[offset] == '}' ||
               json[offset] == ']' ||
               std::isspace(static_cast<unsigned char>(json[offset])) != 0;
    };
    if (json.compare(value_offset, 4, "true") == 0 && is_value_terminator(value_offset + 4)) {
        return true;
    }
    if (json.compare(value_offset, 5, "false") == 0 && is_value_terminator(value_offset + 5)) {
        return false;
    }
    return std::nullopt;
}
}  // namespace
std::string EscapeJson(const std::string& value) {
    std::ostringstream stream;
    for (const unsigned char ch : value) {
        switch (ch) {
            case '\\': stream << "\\\\"; break;
            case '"': stream << "\\\""; break;
            case '\n': stream << "\\n"; break;
            case '\r': stream << "\\r"; break;
            case '\t': stream << "\\t"; break;
            case '\b': stream << "\\b"; break;
            case '\f': stream << "\\f"; break;
            default:
                if (ch < 0x20U) {
                    stream << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(ch) << std::dec;
                } else {
                    stream << static_cast<char>(ch);
                }
                break;
        }
    }
    return stream.str();
}
std::optional<std::string> ExtractJsonString(const std::string& json, const std::string& key) {
    return ExtractJsonStringPath(json, {key});
}

std::optional<bool> ExtractJsonBool(const std::string& json, const std::string& key) {
    return ExtractJsonBoolPath(json, {key});
}

std::optional<std::string> ExtractJsonStringPath(const std::string& json,
                                                 const std::vector<std::string>& path) {
    std::size_t value_offset = 0;
    if (!FindJsonPathValue(json, path, value_offset)) {
        return std::nullopt;
    }
    std::string out;
    if (!ParseJsonString(json, value_offset, out)) {
        return std::nullopt;
    }
    return out;
}

std::optional<bool> ExtractJsonBoolPath(const std::string& json,
                                        const std::vector<std::string>& path) {
    std::size_t value_offset = 0;
    if (!FindJsonPathValue(json, path, value_offset)) {
        return std::nullopt;
    }
    return ReadBoolAt(json, value_offset);
}

const char* BoolJson(const bool value) {
    return value ? "true" : "false";
}

}  // namespace tamga::util
