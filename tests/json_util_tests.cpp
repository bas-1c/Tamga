// Хвиля 8, п.5: JSON-шар винесено з моноліту Session у `util/Json`.
//
// До винесення в дереві жили ТРИ реалізації JSON-логіки:
//   * `SessionHelpers.ipp` — повноцінний парсер (313 рядків) в анонімному
//     namespace всередині одиниці трансляції на 6300 рядків;
//   * `UserReportBuilder.cpp` — власний `EscapeJson`, побайтово тотожний;
//   * `PolicyCache.cpp` — власні `ExtractJsonString`/`ExtractJsonBool`,
//     і от вони тотожними НЕ були.
//
// Головне, що перевіряє цей тест, — саме ту розбіжність. Парсер `PolicyCache`
// не декодував `\uXXXX`: його default-гілка штовхала в результат літеру `u`,
// після чого чотири шістнадцяткові цифри копіювались як звичайний текст.
// Оскільки ці ж файли (`state.json`, метадані trust-store) Tamga пише сама
// через `EscapeJson`, який для будь-якого символу < 0x20 емітує рівно `\u00XX`,
// round-trip псував значення: записали одне — прочитали інше.
//
// Тест містить негативний контроль: він відтворює стару гілку буквально й
// показує, що на тих самих даних вона давала інший результат. Без цього
// неможливо стверджувати, що консолідація щось виправила, а не лише
// перемістила код.

#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

#include "core/net/CaSettingsRegistry.h"
#include "util/Json.h"
#include "util/Utf.h"

namespace {

int g_failures = 0;

void Fail(const std::string& what) {
    std::cerr << "FAIL: " << what << '\n';
    ++g_failures;
}

void ExpectEq(const std::string& actual, const std::string& expected, const std::string& what) {
    if (actual != expected) {
        Fail(what + ": очікували \"" + expected + "\", отримали \"" + actual + "\"");
    }
}

// Стара гілка PolicyCache, відтворена буквально — для негативного контролю.
std::string LegacyPolicyCacheExtract(const std::string& json, const std::string& key) {
    const std::string marker = "\"" + key + "\":\"";
    const std::size_t start = json.find(marker);
    if (start == std::string::npos) {
        return "<not-found>";
    }
    std::string value;
    bool escaped = false;
    for (std::size_t i = start + marker.size(); i < json.size(); ++i) {
        const char ch = json[i];
        if (escaped) {
            switch (ch) {
                case '"': value.push_back('"'); break;
                case '\\': value.push_back('\\'); break;
                case '/': value.push_back('/'); break;
                case 'b': value.push_back('\b'); break;
                case 'f': value.push_back('\f'); break;
                case 'n': value.push_back('\n'); break;
                case 'r': value.push_back('\r'); break;
                case 't': value.push_back('\t'); break;
                default: value.push_back(ch); break;  // ← сюди потрапляло 'u'
            }
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') {
            return value;
        }
        value.push_back(ch);
    }
    return "<unterminated>";
}

void TestUnicodeEscapeIsDecoded() {
    // `A` — латинська 'A'.
    const std::string json = "{\"etag\":\"a\\u0041b\"}";
    const auto value = tamga::util::ExtractJsonString(json, "etag");
    if (!value) {
        Fail("ExtractJsonString не знайшов etag");
        return;
    }
    ExpectEq(*value, "aAb", "\\u0041 має декодуватись у 'A'");

    // Негативний контроль: стара гілка давала інше.
    const std::string legacy = LegacyPolicyCacheExtract(json, "etag");
    if (legacy == *value) {
        Fail("негативний контроль: стара гілка мала дати ІНШИЙ результат — "
             "інакше тест не доводить, що дефект був реальним");
    } else {
        std::cout << "  негативний контроль: стара гілка давала \"" << legacy
                  << "\" замість \"" << *value << "\"\n";
    }
}

void TestControlCharacterRoundTrip() {
    // Саме цей шлях і ламався: EscapeJson пише ``, а старий парсер
    // читав це як літерал.
    const std::string original = std::string("v1") + '\x01' + "v2";
    const std::string escaped = tamga::util::EscapeJson(original);
    if (escaped.find("\\u0001") == std::string::npos) {
        Fail("EscapeJson мусить емітувати \\u0001 для символу 0x01, отримали: " + escaped);
        return;
    }

    const std::string json = "{\"etag\":\"" + escaped + "\"}";
    const auto value = tamga::util::ExtractJsonString(json, "etag");
    if (!value) {
        Fail("round-trip: значення не прочиталось");
        return;
    }
    ExpectEq(*value, original, "round-trip EscapeJson -> ExtractJsonString");

    const std::string legacy = LegacyPolicyCacheExtract(json, "etag");
    if (legacy == original) {
        Fail("негативний контроль: старий парсер мав зіпсувати round-trip");
    }
}

void TestSurrogatePair() {
    // U+1F512 (🔒) у вигляді сурогатної пари.
    const std::string json = "{\"k\":\"\\uD83D\\uDD12\"}";
    const auto value = tamga::util::ExtractJsonString(json, "k");
    if (!value) {
        Fail("сурогатна пара: значення не прочиталось");
        return;
    }
    const std::string expected = "\xF0\x9F\x94\x92";
    ExpectEq(*value, expected, "сурогатна пара має стати 4-байтовим UTF-8");
}

void TestPlainEscapes() {
    const std::string json = "{\"k\":\"a\\\"b\\\\c\\nd\\te\"}";
    const auto value = tamga::util::ExtractJsonString(json, "k");
    if (!value) {
        Fail("прості escape: значення не прочиталось");
        return;
    }
    ExpectEq(*value, "a\"b\\c\nd\te", "прості escape-послідовності");
}

void TestCyrillicPassesThrough() {
    // Кирилиця в UTF-8 не має екрануватись — інакше українські повідомлення
    // звіту роздувалися б у \uXXXX без потреби.
    const std::string original = "Підпис дійсний";
    const std::string escaped = tamga::util::EscapeJson(original);
    ExpectEq(escaped, original, "UTF-8 кирилиця проходить без екранування");
}

void TestBoolAndMissing() {
    const std::string json = "{\"a\":true,\"b\":false,\"c\":\"x\"}";
    const auto a = tamga::util::ExtractJsonBool(json, "a");
    const auto b = tamga::util::ExtractJsonBool(json, "b");
    if (!a || *a != true) {
        Fail("ExtractJsonBool: a має бути true");
    }
    if (!b || *b != false) {
        Fail("ExtractJsonBool: b має бути false");
    }
    if (tamga::util::ExtractJsonBool(json, "c")) {
        Fail("ExtractJsonBool: рядкове значення не є bool");
    }
    if (tamga::util::ExtractJsonString(json, "missing")) {
        Fail("відсутній ключ має давати nullopt");
    }
}

void TestNestedKeyIsNotMatched() {
    // Ключ усередині вкладеного об'єкта не має підхоплюватись як верхній.
    const std::string json = "{\"outer\":{\"etag\":\"inner\"},\"etag\":\"top\"}";
    const auto value = tamga::util::ExtractJsonString(json, "etag");
    if (!value) {
        Fail("вкладеність: значення не прочиталось");
        return;
    }
    ExpectEq(*value, "top", "має братися member верхнього рівня");
}

// --- B-05: ліміт вкладеності ---------------------------------------------
//
// `SkipJsonComposite` і `SkipJsonValue` викликали одна одну без лічильника
// глибини, тож вкладеність недовіреного JSON лягала на машинний стек. Сторонній
// аудит (Q-01, 2026-09-04) відтворив падіння процесу на 20000 рівнях — це лише
// ~40 КБ вводу, тобто на три порядки менше за ліміт вводу в 64 МіБ; обмеження
// РОЗМІРУ від цього класу вводу не захищає в принципі.
//
// Скіп невідомих member-ів — єдиний шлях у цю рекурсію, тому всі три перевірки
// будують документ вигляду {"deep":<вкладене>,"k":"v"} і читають саме "k":
// щоб до нього дійти, парсер мусить пройти повз "deep". Значення "k" на виході
// означає «пропуск відпрацював», `nullopt` — «розбір відхилено».

// Документ загальної глибини `total_depth`, де рівень 1 — зовнішній об'єкт.
std::string MakeNestedJson(const std::size_t total_depth) {
    std::string json = "{\"deep\":";
    for (std::size_t i = 1; i < total_depth; ++i) {
        json += '[';
    }
    json += '1';
    for (std::size_t i = 1; i < total_depth; ++i) {
        json += ']';
    }
    json += ",\"k\":\"v\"}";
    return json;
}

void TestNestingAtLimitIsAccepted() {
    // Рівно на межі (100 рівнів разом із зовнішнім об'єктом) — ще валідно.
    const auto value = tamga::util::ExtractJsonString(MakeNestedJson(100), "k");
    if (!value) {
        Fail("глибина 100 (рівно ліміт) має розбиратись");
        return;
    }
    ExpectEq(*value, "v", "глибина на межі ліміту");
}

void TestNestingOverLimitIsRejected() {
    // На один рівень глибше — відмова, а не тихе усічення.
    if (tamga::util::ExtractJsonString(MakeNestedJson(101), "k")) {
        Fail("глибина 101 (ліміт + 1) мала бути відхилена");
    }
    // Той самий шлях для bool: {"deep":...,"b":true}.
    std::string json = MakeNestedJson(101);
    const std::size_t tail = json.rfind(",\"k\":\"v\"}");
    json.replace(tail, std::string::npos, ",\"b\":true}");
    if (tamga::util::ExtractJsonBool(json, "b")) {
        Fail("ExtractJsonBool: глибина 101 мала бути відхилена");
    }
}

void TestPathologicalNestingDoesNotCrash() {
    // Відтворення Q-01: 20000 рівнів, ~40 КБ. До виправлення цей рядок валив
    // процес зі STATUS_STACK_OVERFLOW (0xC00000FD) — тест не доходив до
    // наступного рядка взагалі. Доказ виправлення тут двоскладовий: функція
    // повернула false І процес живий, щоб про це повідомити.
    const std::string json = MakeNestedJson(20000);
    if (json.size() > 128 * 1024) {
        Fail("ввід репро мав лишитись малим — саме в цьому суть знахідки");
    }
    if (tamga::util::ExtractJsonString(json, "k")) {
        Fail("глибина 20000 мала бути відхилена");
    }
    std::cout << "  глибина 20000 (" << json.size()
              << " Б) відхилена без падіння процесу\n";
}

// ── Q-05: реєстр КНЕДП більше не приймає обірваний документ ─────────────────
// `core/net/CaSettingsRegistry` мав ВЛАСНИЙ мінімальний сканер — четверту
// копію JSON-логіки в дереві. Дві його відмінності від спільного парсера були
// дефектами, і обидві відтворені нижче буквально.

std::string ParseCaRegistry(const std::string& json, std::size_t& entries, std::string& error) {
    std::vector<tamga::core::net::CaSettingsEntry> out;
    const bool ok = tamga::core::net::CaSettingsRegistry::ParseJson(json, out, error);
    entries = out.size();
    return ok ? "true" : "false";
}

void ExpectRegistryRejects(const std::string& json, const std::string& what) {
    std::size_t entries = 0;
    std::string error;
    if (ParseCaRegistry(json, entries, error) != "false") {
        Fail(what + ": розбір повернув true (" + std::to_string(entries) + " запис(ів))");
    }
}

void TestCaRegistryRejectsTruncatedDocument() {
    // Проба з Q-05: ані обʼєкт, ані масив не закриті. До виправлення це
    // давало `true` і ОДИН придатний запис, який далі міг потрапити в кеш
    // `<work_dir>/CAs.json` як повний реєстр КНЕДП.
    ExpectRegistryRejects("[{\"address\":\"ca.example\"",
                          "обірвано після рядкового значення");
    ExpectRegistryRejects("[{\"address\":\"ca.example\"}",
                          "обірвано після закриття обʼєкта (масив не закритий)");
    ExpectRegistryRejects("[{\"address\":\"a\",", "обірвано після коми");
    ExpectRegistryRejects("[{\"address\"", "обірвано після ключа");
    ExpectRegistryRejects("[{\"address\":", "обірвано після двокрапки");
    ExpectRegistryRejects("[{\"issuerCNs\":[\"a\"", "обірвано всередині масиву CN");
    ExpectRegistryRejects("[{\"address\":\"a\",\"port\":80", "обірвано після числа");
    ExpectRegistryRejects("[{\"address\":\"a\",\"directAccess\":true",
                          "обірвано після літерала");
    ExpectRegistryRejects("[{\"address\":\"a\",\"nested\":{\"x\":1}",
                          "обірвано після вкладеного обʼєкта");
    ExpectRegistryRejects("[{\"address\":tru}]", "неповний літерал як значення");

    // Зайві дані після масиву означають, що прочитано не той документ.
    ExpectRegistryRejects("[{\"address\":\"ca.example\"}] xyz", "сміття після масиву");
    ExpectRegistryRejects("[{\"address\":\"ca.example\"}]{\"a\":1}", "другий документ після масиву");
    ExpectRegistryRejects("[] junk", "сміття після порожнього масиву");

    // Контроль: цілий документ і далі приймається, а завершений, але
    // непридатний запис — і далі лише пропускається.
    std::size_t entries = 0;
    std::string error;
    if (ParseCaRegistry("[{\"address\":\"ca.example\"}]", entries, error) != "true" || entries != 1) {
        Fail("цілий документ мав лишитись придатним");
    }
    if (ParseCaRegistry("[{\"noAddress\":\"x\"},{\"address\":\"ca.example\"}]", entries, error) !=
            "true" ||
        entries != 1) {
        Fail("запис без address мав бути пропущений, а не завалити документ");
    }
}

void TestCaRegistryJoinsSurrogatePairs() {
    // U+1F600: до виправлення власний сканер видавав CESU-8 —
    // ED A0 BD ED B8 80 замість F0 9F 98 80. `ParseJson` при цьому казав
    // «успіх», а `TryDecodeUtf8ToUtf16` потім відхиляв такий CN.
    std::vector<tamga::core::net::CaSettingsEntry> out;
    std::string error;
    const std::string json =
        "[{\"address\":\"a\",\"issuerCNs\":[\"\\uD83D\\uDE00\"]}]";
    if (!tamga::core::net::CaSettingsRegistry::ParseJson(json, out, error) || out.size() != 1 ||
        out[0].issuer_cns.size() != 1) {
        Fail("валідна сурогатна пара мала розібратись: " + error);
        return;
    }
    ExpectEq(out[0].issuer_cns[0], "\xF0\x9F\x98\x80",
             "сурогатна пара має склеїтись в один code point");

    std::u16string utf16;
    if (!tamga::util::TryDecodeUtf8ToUtf16(out[0].issuer_cns[0], utf16)) {
        Fail("результат мав бути валідним UTF-8 — саме на цьому CN відпадав далі");
    }

    // Самотні сурогати — відмова, а не CESU-8.
    ExpectRegistryRejects("[{\"address\":\"a\",\"issuerCNs\":[\"\\uD83D\"]}]",
                          "самотній старший сурогат");
    ExpectRegistryRejects("[{\"address\":\"a\",\"issuerCNs\":[\"\\uDE00\"]}]",
                          "самотній молодший сурогат");
    ExpectRegistryRejects("[{\"address\":\"a\",\"issuerCNs\":[\"\\uD83Dx\"]}]",
                          "старший сурогат без пари");
}

void TestJsonPathExtraction() {
    // O-03: без шляху єдиним способом дістати факт із секції звіту був пошук
    // підрядка в тексті JSON.
    const std::string json =
        "{\"summary\":{\"status\":\"invalid\"},"
        "\"diagnostics\":{\"errorCode\":\"None\",\"flags\":{\"signatureValid\":false,"
        "\"trustValid\":true}}}";
    const auto status = tamga::util::ExtractJsonStringPath(json, {"summary", "status"});
    if (!status || *status != "invalid") {
        Fail("шлях summary.status не знайдено");
    }
    const auto signature_valid =
        tamga::util::ExtractJsonBoolPath(json, {"diagnostics", "flags", "signatureValid"});
    if (!signature_valid || *signature_valid) {
        Fail("шлях diagnostics.flags.signatureValid мав дати false");
    }
    const auto trust_valid =
        tamga::util::ExtractJsonBoolPath(json, {"diagnostics", "flags", "trustValid"});
    if (!trust_valid || !*trust_valid) {
        Fail("шлях diagnostics.flags.trustValid мав дати true");
    }
    // Той самий ключ на верхньому рівні відсутній — шлях не має «провалюватись»
    // у вкладені секції сам собою.
    if (tamga::util::ExtractJsonBool(json, "signatureValid")) {
        Fail("вкладений ключ не має знаходитись пошуком по верхньому рівню");
    }
    if (tamga::util::ExtractJsonStringPath(json, {})) {
        Fail("порожній шлях мав дати nullopt");
    }
    if (tamga::util::ExtractJsonStringPath(json, {"summary", "status", "deeper"})) {
        Fail("шлях крізь рядкове значення мав дати nullopt");
    }
}

} // namespace

int main() {
    TestUnicodeEscapeIsDecoded();
    TestControlCharacterRoundTrip();
    TestSurrogatePair();
    TestPlainEscapes();
    TestCyrillicPassesThrough();
    TestBoolAndMissing();
    TestNestedKeyIsNotMatched();
    TestNestingAtLimitIsAccepted();
    TestNestingOverLimitIsRejected();
    TestPathologicalNestingDoesNotCrash();
    TestCaRegistryRejectsTruncatedDocument();
    TestCaRegistryJoinsSurrogatePairs();
    TestJsonPathExtraction();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "json util: OK\n";
    return 0;
}
