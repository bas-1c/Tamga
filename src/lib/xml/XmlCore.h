#pragma once

// Тонкий спільний шар над libxml2 для парсерів ЯДРА (ADR-030).
//
// Навіщо він існує. До ADR-030 у дереві було ТРИ способи читати XML: libxml2
// (лише коли `TAMGA_ENABLE_XML_SIGNATURES=ON`), саморобний сканер підрядків у
// `core/policy/TrustListParser.cpp` і другий саморобний сканер у
// `asic/AsicContainers.cpp`. Обидва сканери існували тому, що базова
// конфігурація не мала libxml2. Наслідок був структурний, а не косметичний:
// найчутливіший до довіри формат (довірчий список ЦЗО) розбирався найслабшим
// інструментом, а виправлення того самого класу помилки (С-21 — межа тега без
// урахування лапок) дійшло лише до ОДНОГО зі сканерів-близнюків.
//
// libxml2 тепер безумовна залежність ядра, тож обидва сканери прибрано, а
// `TAMGA_ENABLE_XML_SIGNATURES` лишився прапорцем ПІДСИСТЕМИ ПІДПИСУ
// (XMLDSIG/XAdES), а не парсера.
//
// Межа з `xmldsig/detail/XmlDocUtil.h`: той заголовок обслуговує підпис
// (C14N, XPath, збереження пробілів) і компілюється лише під
// `TAMGA_XML_SIGNATURES_ENABLED`. Цей — безумовний і навмисно вужчий: розбір
// недовіреного XML у read-only режимі без канонікалізації.

#include <algorithm>
#include <cstddef>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <libxml/parser.h>
#include <libxml/tree.h>

namespace tamga::xml {

// Межа розміру вхідного XML. Збігається з `util::kMaxInputFileSize` (64 МіБ)
// свідомо: XML сюди потрапляє або з файлу, або з HTTP-відповіді, і другої межі
// для того самого вводу заводити не треба. Дублювати `#include` заради однієї
// константи не варто — цей заголовок навмисно не тягне решту util.
inline constexpr std::size_t kMaxXmlBytes = 64ULL * 1024ULL * 1024ULL;

static_assert(kMaxXmlBytes <= static_cast<std::size_t>(std::numeric_limits<int>::max()),
              "kMaxXmlBytes мусить влазити в int: xmlReadMemory приймає довжину як int, "
              "і мовчазне звуження дало б розбір ЧАСТИНИ документа з успішним результатом");

struct DocDeleter {
    void operator()(xmlDoc* doc) const noexcept {
        if (doc != nullptr) {
            xmlFreeDoc(doc);
        }
    }
};
using DocPtr = std::unique_ptr<xmlDoc, DocDeleter>;

// Одноразова ініціалізація libxml2. `xmlReadMemory` ініціалізує парсер ліниво,
// і в старих версіях libxml2 ця лінива ініціалізація не була потокобезпечною.
// Локальна статика в C++11 ініціалізується рівно один раз і потокобезпечно —
// цього достатньо, щоб гонки не було незалежно від версії бібліотеки.
inline void EnsureParserInitialized() {
    static const bool initialized = [] {
        xmlInitParser();
        return true;
    }();
    (void)initialized;
}

// Розбір недовіреного XML із hardening проти XXE та вичерпання ресурсів.
//
// ІМ'Я ЗБІГАЄТЬСЯ з `xmldsig::detail::ParseHardened` — і це справжнє
// дублювання, зафіксоване в `tests/duplicate_symbols.baseline`, а не збіг.
// Звести їх в одну реалізацію не вийшло тому, що `xmldsig/detail/XmlDocUtil.h`
// правиться в іншій паралельній гілці (П-13). Після її злиття той заголовок
// має включити цей і викинути свою копію — рядок у baseline тоді зникає.
//
// Що саме вимкнено і чому:
//   * XML_PARSE_NONET     — жодних мережевих звернень парсера (SSRF);
//   * XML_PARSE_NOENT НЕ задано — внутрішні сутності НЕ підставляються, тож
//     entity-expansion (billion laughs) не має де розгорнутися;
//   * XML_PARSE_DTDLOAD/DTDATTR/DTDVALID НЕ задані — зовнішній DTD не
//     завантажується;
//   * XML_PARSE_HUGE НЕ задано — лишаються ВБУДОВАНІ межі libxml2, зокрема
//     максимальна глибина вкладення (`xmlParserMaxDepth`, 256) і межі довжини
//     імен/текстових вузлів. Саме тому окремої перевірки глибини тут немає:
//     вона робиться парсером, а не після нього;
//   * XML_PARSE_NOERROR/NOWARNING — діагностика libxml2 не друкується у stderr
//     процесу-хоста 1С; недовірений ввід не має керувати виводом компоненти;
//   * документ із DTD (внутрішнім чи зовнішнім) відхиляється повністю: ані
//     довірчий список, ані ASiC-манфест його не потребують, а лишати
//     DTD-підмножину означає лишати поверхню entity-expansion на дрібних полях.
//
// Повертає порожній DocPtr і заповнює `error` при невдачі.
inline DocPtr ParseHardened(const std::string& xml, std::string& error) {
    EnsureParserInitialized();

    if (xml.empty()) {
        error = "XML порожній";
        return DocPtr{};
    }
    if (xml.size() > kMaxXmlBytes) {
        error = "XML завеликий для розбору: розмір перевищує межу " +
                std::to_string(kMaxXmlBytes) + " байт";
        return DocPtr{};
    }

    const int options = XML_PARSE_NONET | XML_PARSE_NODICT | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    xmlDoc* doc = xmlReadMemory(xml.data(),
                                static_cast<int>(xml.size()),
                                "in-memory.xml",
                                nullptr,
                                options);
    if (doc == nullptr) {
        error = "Не вдалося розпарсити XML (некоректний документ або заблоковані небезпечні конструкції)";
        return DocPtr{};
    }
    if (doc->intSubset != nullptr || doc->extSubset != nullptr) {
        xmlFreeDoc(doc);
        error = "XML містить DTD, що заборонено";
        return DocPtr{};
    }
    return DocPtr{doc};
}

// Кореневий елемент документа (може бути nullptr для порожнього документа).
inline const xmlNode* RootElement(const DocPtr& doc) {
    return doc ? xmlDocGetRootElement(doc.get()) : nullptr;
}

// Чи є вузол елементом із заданою ЛОКАЛЬНОЮ назвою та (за потреби) у заданому
// namespace.
//
// Предикат навмисно ОДИН, а не пара «назва» + «namespace». С-17 у цьому дереві
// був саме про те, що зіставлення за самою локальною назвою пропускає елемент
// із ЧУЖОГО namespace там, де вирішується, що взагалі є підписом. Коли
// перевірка namespace — окрема функція, її легко забути викликати. Тут її
// доводиться згадати в кожному місці виклику: `ns_uri == nullptr` означає
// «namespace свідомо не перевіряємо» і це видно в коді.
//
// `node->name` у libxml2 — саме локальна частина; префікс живе окремо в
// `node->ns`. Некоректне ім'я з двома двокрапками («evil:tsl:X509Certificate»)
// libxml2 не вважає QName і лишає в `node->name` ЦІЛКОМ, разом з двокрапками,
// тож із очікуваною локальною назвою воно не збігається. Це та сама сувора
// семантика, яку ADR-027 задав для `util::LocalName`, але тепер її забезпечує
// сам парсер, а не наше порівняння рядків.
inline bool MatchesElement(const xmlNode* node, const char* local_name, const char* ns_uri) {
    if (node == nullptr || node->type != XML_ELEMENT_NODE) {
        return false;
    }
    if (xmlStrcmp(node->name, reinterpret_cast<const xmlChar*>(local_name)) != 0) {
        return false;
    }
    if (ns_uri == nullptr) {
        return true;
    }
    if (node->ns == nullptr || node->ns->href == nullptr) {
        return false;
    }
    return xmlStrcmp(node->ns->href, reinterpret_cast<const xmlChar*>(ns_uri)) == 0;
}

// Текстовий вміст піддерева з уже розкодованими символьними посиланнями.
inline std::string NodeContent(const xmlNode* node) {
    if (node == nullptr) {
        return {};
    }
    xmlChar* content = xmlNodeGetContent(node);
    if (content == nullptr) {
        return {};
    }
    std::string result(reinterpret_cast<const char*>(content));
    xmlFree(content);
    return result;
}

// Значення атрибута БЕЗ namespace (`URI="..."`, а не `x:URI="..."`).
// Саме так атрибути оголошені в схемах, які ми читаємо: ETSI TS 102 918
// (ASiC-манфест) і ETSI TS 119 612 (TL) задають їх unqualified.
inline bool GetAttribute(const xmlNode* node, const char* name, std::string& out_value) {
    if (node == nullptr || node->type != XML_ELEMENT_NODE) {
        return false;
    }
    xmlChar* value = xmlGetNoNsProp(node, reinterpret_cast<const xmlChar*>(name));
    if (value == nullptr) {
        return false;
    }
    out_value.assign(reinterpret_cast<const char*>(value));
    xmlFree(value);
    return true;
}

// Обхід піддерева `root` (включно з ним самим) у порядку документа.
//
// Обхід ІТЕРАТИВНИЙ свідомо. Рекурсивний варіант перетворив би глибоко
// вкладений документ на переповнення стека — тобто на падіння процесу 1С від
// недовіреного вводу. Межу глибини тримає парсер (див. ParseHardened), але
// покладатися на неї як на ЄДИНИЙ запобіжник тут не варто.
template <typename Visitor>
inline void ForEachElement(const xmlNode* root, Visitor&& visit) {
    if (root == nullptr) {
        return;
    }
    std::vector<const xmlNode*> pending{root};
    while (!pending.empty()) {
        const xmlNode* node = pending.back();
        pending.pop_back();
        if (node->type == XML_ELEMENT_NODE) {
            visit(node);
        }
        const std::size_t first_child = pending.size();
        for (const xmlNode* child = node->children; child != nullptr; child = child->next) {
            if (child->type == XML_ELEMENT_NODE) {
                pending.push_back(child);
            }
        }
        // Діти лягли у стек у прямому порядку, а знімаються з кінця — тож
        // перевертаємо саме щойно додану ділянку, щоб зберегти порядок документа.
        std::reverse(pending.begin() + static_cast<std::ptrdiff_t>(first_child), pending.end());
    }
}

} // namespace tamga::xml
