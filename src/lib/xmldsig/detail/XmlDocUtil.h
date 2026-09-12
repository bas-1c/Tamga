#pragma once

// Внутрішні утиліти libxml2 для XMLDSIG-компонентів. Включається лише у gated
// .cpp (TAMGA_ENABLE_XML_SIGNATURES); типи libxml2 свідомо не протікають у
// публічні заголовки модуля.
#if defined(TAMGA_XML_SIGNATURES_ENABLED)

#include <cstddef>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/c14n.h>

#include "xml/XmlCore.h"

namespace tamga::xmldsig::detail {

// ADR-030 передбачав це зведення: доки libxml2 був опційним, XMLDSIG мусив
// нести власну копію розбору, бо `xml/XmlCore.h` існував лише в частині
// конфігурацій. Тепер libxml2 безумовний, і копія стала простим дублюванням —
// рядок `ParseHardened` зникає з `tests/duplicate_symbols.baseline`.
using XmlDocDeleter = tamga::xml::DocDeleter;
using XmlDocPtr = tamga::xml::DocPtr;

struct XmlXPathObjDeleter {
    void operator()(xmlXPathObjectPtr obj) const noexcept {
        if (obj != nullptr) {
            xmlXPathFreeObject(obj);
        }
    }
};
using XmlXPathObjPtr = std::unique_ptr<xmlXPathObject, XmlXPathObjDeleter>;

struct XmlXPathCtxDeleter {
    void operator()(xmlXPathContextPtr ctx) const noexcept {
        if (ctx != nullptr) {
            xmlXPathFreeContext(ctx);
        }
    }
};
using XmlXPathCtxPtr = std::unique_ptr<xmlXPathContext, XmlXPathCtxDeleter>;

// Розбір із hardening проти XXE/SSRF живе в `xml/XmlCore.h` — одна реалізація
// на весь проєкт. Що саме вимкнено і чому — у коментарі там.
//
// Дві навмисні зміни поведінки порівняно з копією, що тут була:
//
//  1. Межа розміру — 64 МіБ (`xml::kMaxXmlBytes`) замість INT_MAX. Це та сама
//     межа, що вже діяла для файлового шляху, і вона закриває залишок П-11:
//     прямий BLOB із 1С був обмежений лише 2 ГіБ, тобто «контрольована
//     відмова» наставала після спроби виділити пам'ять під документ.
//  2. Діагностика libxml2 більше не друкується у stderr процесу-хоста 1С
//     (`XML_PARSE_NOERROR|NOWARNING`): недовірений ввід не має керувати
//     виводом компоненти.
//
// Перевірка П-11 щодо звуження `size_t` -> `int` не втрачена: у `XmlCore.h`
// вона зроблена сильніше — `static_assert` на самій константі, тож помилку
// видно на компіляції, а не на конкретному вході.
using tamga::xml::ParseHardened;

// Простір імен XMLDSIG.
inline const char* DsigNamespace() {
    return "http://www.w3.org/2000/09/xmldsig#";
}

// Чи є вузол елементом із заданою локальною назвою (без урахування префікса).
inline bool IsElementNamed(const xmlNode* node, const char* local_name) {
    return node != nullptr && node->type == XML_ELEMENT_NODE &&
           xmlStrcmp(node->name, reinterpret_cast<const xmlChar*>(local_name)) == 0;
}

// С-17: чи оголошений вузол саме в заданому namespace.
inline bool IsElementInNamespace(const xmlNode* node, const char* ns_uri) {
    if (node == nullptr || node->type != XML_ELEMENT_NODE) {
        return false;
    }
    if (node->ns == nullptr || node->ns->href == nullptr) {
        return false;
    }
    return xmlStrcmp(node->ns->href, reinterpret_cast<const xmlChar*>(ns_uri)) == 0;
}

// С-17: пара (namespace XMLDSIG, локальна назва).
//
// Розпізнавання за самою локальною назвою означає, що елемент `Signature` у
// ЧУЖОМУ namespace вважається підписом. Це не доведений exploit, але вихід за
// межі профілю XMLDSIG у місці, яке вирішує, ЩО взагалі є підписом, — не те,
// на що можна покладатися. Застосовано насамперед до збирача верхнього рівня.
inline bool IsDsigElementNamed(const xmlNode* node, const char* local_name) {
    return IsElementNamed(node, local_name) && IsElementInNamespace(node, DsigNamespace());
}

// П-13: ЯВНИЙ allowlist просторів імен XAdES.
//
// Це не «будь-який namespace, аби локальне ім'я збіглося». Для КЛАСИФІКАЦІЇ
// (`format_profile`, поля LTV-доказів у звіті для 1С) ширше трактування не
// робить перевірку суворішою — воно дозволяє вузлу з ЧУЖОГО namespace
// визначити, який профіль ми покажемо викликачу.
//
// Склад списку:
//   * `.../01903/v1.3.2#` — єдиний namespace, який ГЕНЕРУЄ `XadesBuilder` і
//     який реально трапляється в усіх XAdES-фікстурах репозиторію
//     (Дія ASiC-E/ASiC-S, DSS enveloping, TL-UA-EC);
//   * `.../01903/v1.4.1#` — нормативне місце `ArchiveTimeStamp` і
//     `TimeStampValidationData` за ETSI TS 101 903 V1.4.1; зовнішні
//     валідатори (ETSI DSS) кладуть архівну мітку саме туди. Фікстури з ним
//     у репозиторії немає — його присутність у списку розширює лише
//     РОЗПІЗНАВАННЯ, і навіть тоді профіль `XAdES-A` вимагає ФАКТИЧНО
//     підтвердженого токена (HI-04), а не самої наявності елемента.
// Старіші (v1.1.1, v1.2.2) свідомо НЕ додані: у репозиторії немає ні коду,
// ні фікстур, які б їх створювали або читали.
inline bool IsXadesNamespaceUri(const xmlChar* href) {
    if (href == nullptr) {
        return false;
    }
    static const char* const kAllowed[] = {
        "http://uri.etsi.org/01903/v1.3.2#",
        "http://uri.etsi.org/01903/v1.4.1#",
    };
    for (const char* uri : kAllowed) {
        if (xmlStrcmp(href, reinterpret_cast<const xmlChar*>(uri)) == 0) {
            return true;
        }
    }
    return false;
}

// Чи є вузол елементом XAdES із заданою локальною назвою (namespace — лише з
// allowlist вище).
inline bool IsXadesElementNamed(const xmlNode* node, const char* local_name) {
    if (!IsElementNamed(node, local_name)) {
        return false;
    }
    return node->ns != nullptr && IsXadesNamespaceUri(node->ns->href);
}

// Предикат «вузол відповідає локальній назві» — параметр пошукових хелперів
// нижче. Дозволені значення: IsElementNamed (будь-який namespace — для
// пошуку заради ВІДХИЛЕННЯ), IsDsigElementNamed, IsXadesElementNamed.
using ElementMatcher = bool (*)(const xmlNode*, const char*);

// Ті самі обходи, що FindFirstElement/FindFirstElementInSubtree/
// CountElementsInSubtree, але з явним namespace-предикатом. Семантика обходу
// збігається один-в-один (див. попередження до FindFirstElement про
// сиблінгів), змінюється лише умова збігу.
inline xmlNodePtr FindFirstElementBy(xmlNodePtr root, const char* local_name, ElementMatcher match) {
    for (xmlNodePtr node = root; node != nullptr; node = node->next) {
        if (match(node, local_name)) {
            return node;
        }
        if (node->children != nullptr) {
            if (xmlNodePtr found = FindFirstElementBy(node->children, local_name, match)) {
                return found;
            }
        }
    }
    return nullptr;
}

inline xmlNodePtr FindFirstElementInSubtreeBy(xmlNodePtr node, const char* local_name, ElementMatcher match) {
    if (node == nullptr) {
        return nullptr;
    }
    if (match(node, local_name)) {
        return node;
    }
    return node->children ? FindFirstElementBy(node->children, local_name, match) : nullptr;
}

inline int CountElementsInSubtreeBy(xmlNodePtr node, const char* local_name, ElementMatcher match) {
    if (node == nullptr) {
        return 0;
    }
    int count = match(node, local_name) ? 1 : 0;
    for (xmlNodePtr child = node->children; child != nullptr; child = child->next) {
        count += CountElementsInSubtreeBy(child, local_name, match);
    }
    return count;
}

// Зручні обгортки для двох нормативних просторів імен.
inline xmlNodePtr FindFirstDsigElement(xmlNodePtr root, const char* local_name) {
    return FindFirstElementBy(root, local_name, IsDsigElementNamed);
}
inline xmlNodePtr FindFirstDsigElementInSubtree(xmlNodePtr node, const char* local_name) {
    return FindFirstElementInSubtreeBy(node, local_name, IsDsigElementNamed);
}
inline xmlNodePtr FindFirstXadesElement(xmlNodePtr root, const char* local_name) {
    return FindFirstElementBy(root, local_name, IsXadesElementNamed);
}
inline xmlNodePtr FindFirstXadesElementInSubtree(xmlNodePtr node, const char* local_name) {
    return FindFirstElementInSubtreeBy(node, local_name, IsXadesElementNamed);
}
inline int CountXadesElementsInSubtree(xmlNodePtr node, const char* local_name) {
    return CountElementsInSubtreeBy(node, local_name, IsXadesElementNamed);
}

// П-13: XPath-скоуп для signature_position_1based-го ВЕРХНЬОРІВНЕВОГО
// ds:Signature.
//
// Раніше скоуп був `(//*[local-name()='Signature'])[N]` — суто за локальною
// назвою, тоді як список підписів (CollectTopLevelSignatureNodes) збирається
// namespace-aware. Через цю розбіжність `<evil:Signature>` перед справжнім
// ds:Signature зсував нумерацію, і C14N ds:SignedInfo бралася з ЧУЖОГО
// елемента: SignatureValue звірявся з копією SignedInfo, а дайджести
// перевірялися за справжнім (підміненим) SignedInfo. Тут звуження не
// послаблює перевірку, а прибирає розбіжність між двома нумераціями.
inline std::string DsigSignatureScopeXPath(int signature_position_1based) {
    return std::string("(//*[local-name()='Signature' and namespace-uri()='") + DsigNamespace() +
           "'])[" + std::to_string(signature_position_1based) + "]";
}

// УВАГА: попри назву, ця функція обходить НЕ ЛИШЕ нащадків `root`, а й усіх
// його НАСТУПНИХ СИБЛІНГІВ (через `node = node->next` у зовнішньому циклі).
// Якщо `root` — конкретний елемент (напр. один ds:Signature серед кількох) і
// шуканого local_name немає в його ВЛАСНОМУ піддереві, пошук "просочується" в
// сусідні елементи (інший ds:Signature тощо) і може повернути елемент, що
// belongs НЕ до `root`. Для пошуку, СТРОГО обмеженого власним піддеревом
// одного вузла (напр. XAdES-пошуки в межах конкретного ds:Signature, WP-2),
// використовуйте FindFirstElementInSubtree нижче, а не цю функцію напряму з
// `root` = сам вузол-межа. Тут `root` призначений як "перший вузол списку,
// який треба обійти разом з усіма наступними" (напр. `node->children` або
// корінь документа) — саме так і слід її викликати.
inline xmlNodePtr FindFirstElement(xmlNodePtr root, const char* local_name) {
    for (xmlNodePtr node = root; node != nullptr; node = node->next) {
        if (IsElementNamed(node, local_name)) {
            return node;
        }
        if (node->children != nullptr) {
            if (xmlNodePtr found = FindFirstElement(node->children, local_name)) {
                return found;
            }
        }
    }
    return nullptr;
}

// Шукає ПЕРШИЙ елемент local_name СТРОГО у піддереві node (сам node + його
// нащадки, БЕЗ сусідів по дереву) — на відміну від FindFirstElement(node, ...),
// який (як описано вище) також обходить node->next. Аналогічно
// CountElementsInSubtree нижче: потрібно для пошуків, прив'язаних до ОДНОГО
// конкретного ds:Signature серед кількох (WP-2) — інакше пошук міг би
// "просочитись" у сусідній ds:Signature і повернути ЙОГО елемент (напр.
// X509Certificate/SignedProperties іншого підпису), якщо шуканий елемент
// відсутній у власному піддереві node.
inline xmlNodePtr FindFirstElementInSubtree(xmlNodePtr node, const char* local_name) {
    if (node == nullptr) {
        return nullptr;
    }
    if (IsElementNamed(node, local_name)) {
        return node;
    }
    return node->children ? FindFirstElement(node->children, local_name) : nullptr;
}

// Значення атрибута як std::string ("" якщо відсутній).
inline std::string GetAttr(xmlNodePtr node, const char* name) {
    xmlChar* value = xmlGetProp(node, reinterpret_cast<const xmlChar*>(name));
    if (value == nullptr) {
        return std::string{};
    }
    std::string result(reinterpret_cast<const char*>(value));
    xmlFree(value);
    return result;
}

// Чи має node атрибут (будь-якого регістру з Id/ID/id) зі значенням value.
inline bool HasIdAttr(xmlNodePtr node, const std::string& value) {
    for (const char* name : {"Id", "ID", "id"}) {
        xmlChar* attr = xmlGetProp(node, reinterpret_cast<const xmlChar*>(name));
        if (attr != nullptr) {
            const bool match = value == reinterpret_cast<const char*>(attr);
            xmlFree(attr);
            if (match) {
                return true;
            }
        }
    }
    return false;
}

// Рекурсивно шукає елемент із атрибутом Id/ID/id == id.
inline xmlNodePtr FindElementById(xmlNodePtr root, const std::string& id) {
    for (xmlNodePtr node = root; node != nullptr; node = node->next) {
        if (node->type == XML_ELEMENT_NODE && HasIdAttr(node, id)) {
            return node;
        }
        if (node->children != nullptr) {
            if (xmlNodePtr found = FindElementById(node->children, id)) {
                return found;
            }
        }
    }
    return nullptr;
}

// Рекурсивно рахує елементи із заданою локальною назвою у піддереві (WP-1:
// для перевірки унікальності складових підпису — захист від XSW).
inline int CountElementsByLocalName(xmlNodePtr root, const char* local_name) {
    int count = 0;
    for (xmlNodePtr node = root; node != nullptr; node = node->next) {
        if (IsElementNamed(node, local_name)) {
            ++count;
        }
        if (node->children != nullptr) {
            count += CountElementsByLocalName(node->children, local_name);
        }
    }
    return count;
}

// Рахує елементи із заданою локальною назвою СТРОГО у піддереві node (сам
// node + його нащадки, БЕЗ сусідів по дереву) — на відміну від
// CountElementsByLocalName, який також обходить node->next. Потрібно, щоб
// перевірити структуру ОДНОГО конкретного ds:Signature (WP-2: підтримка
// кількох ds:Signature в одному документі), не рахуючи елементи інших,
// сусідніх ds:Signature.
inline int CountElementsInSubtree(xmlNodePtr node, const char* local_name) {
    if (node == nullptr) {
        return 0;
    }
    int count = IsElementNamed(node, local_name) ? 1 : 0;
    for (xmlNodePtr child = node->children; child != nullptr; child = child->next) {
        count += CountElementsInSubtree(child, local_name);
    }
    return count;
}

// Збирає ВЕРХНЬОРІВНЕВІ ds:Signature (тобто ті, що не є нащадками іншого
// ds:Signature) у порядку документа. nested_found=true, якщо десь усередині
// одного ds:Signature знайдено ще один — такий документ відхиляється
// цілком (класичний вектор wrapping через вкладений підмінений підпис),
// незалежно від підтримки кількох підписів (WP-2).
inline void CollectTopLevelSignatureNodes(xmlNodePtr node, std::vector<xmlNodePtr>& out,
                                          bool& nested_found) {
    for (xmlNodePtr n = node; n != nullptr; n = n->next) {
        // С-17: підписом вважається лише елемент у namespace XMLDSIG.
        // Вкладеність нижче навмисно перевіряється за локальною назвою: там
        // ширше трактування робить перевірку СУВОРІШОЮ (більше документів
        // відхиляється як wrapping), тож fail-closed зберігається.
        if (IsDsigElementNamed(n, "Signature")) {
            out.push_back(n);
            if (FindFirstElement(n->children, "Signature") != nullptr) {
                nested_found = true;
            }
            continue;  // не заглиблюємось у вже зареєстрований Signature
        }
        if (n->children != nullptr) {
            CollectTopLevelSignatureNodes(n->children, out, nested_found);
        }
    }
}

// Рекурсивно рахує елементи з атрибутом Id/ID/id == id (WP-1: дублікати ID для
// referenced-фрагмента мають відхилятися).
inline int CountElementsById(xmlNodePtr root, const std::string& id) {
    int count = 0;
    for (xmlNodePtr node = root; node != nullptr; node = node->next) {
        if (node->type == XML_ELEMENT_NODE && HasIdAttr(node, id)) {
            ++count;
        }
        if (node->children != nullptr) {
            count += CountElementsById(node->children, id);
        }
    }
    return count;
}

// Серіалізує вузол (із піддеревом) у рядок.
//
// Вузол копіюється у тимчасовий документ ПЕРЕД серіалізацією, і це не
// оптимізація, а виправлення. `xmlNodeDump` не виносить оголошення
// просторів імен, УСПАДКОВАНІ від предків: фрагмент, узятий з-під кореня,
// виходив із префіксом, якого в ньому не оголошено, і повторний розбір
// падав із «Namespace prefix ds on Object is not defined».
//
// Знайдено диференційною звіркою проти ETSI DSS: через це ми відхиляли
// коректний XAdES із packaging=ENVELOPING, де `ds:Reference` вказує на
// `ds:Object` того самого документа. Українські контейнери цього не
// показували — там посилання ведуть на записи контейнера.
//
// `xmlDocCopyNode` додає оголошення лише тоді, коли його немає в копії,
// тож для фрагментів, які вже несуть свій xmlns, результат не змінюється.
inline std::string SerializeNode(xmlDocPtr doc, xmlNodePtr node) {
    xmlBufferPtr buffer = xmlBufferCreate();
    if (buffer == nullptr) {
        return std::string{};
    }
    xmlDocPtr scratch = xmlNewDoc(BAD_CAST "1.0");
    xmlNodePtr copy = scratch == nullptr ? nullptr : xmlDocCopyNode(node, scratch, 1);
    const int written = copy != nullptr
                            ? xmlNodeDump(buffer, scratch, copy, 0, 0)
                            : xmlNodeDump(buffer, doc, node, 0, 0);
    std::string result;
    const xmlChar* content = xmlBufferContent(buffer);
    if (written >= 0 && content != nullptr) {
        result.assign(reinterpret_cast<const char*>(content),
                      static_cast<std::size_t>(xmlBufferLength(buffer)));
    }
    xmlBufferFree(buffer);
    if (scratch != nullptr) {
        xmlFreeDoc(scratch);
    }
    return result;
}

// Зіставляє канонічний C14N-URI з (libxml2 mode, with_comments).
inline bool C14nUriToMode(const std::string& uri, int& mode, int& with_comments) {
    if (uri == "http://www.w3.org/TR/2001/REC-xml-c14n-20010315") {
        mode = XML_C14N_1_0; with_comments = 0; return true;
    }
    if (uri == "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments") {
        mode = XML_C14N_1_0; with_comments = 1; return true;
    }
    if (uri == "http://www.w3.org/2001/10/xml-exc-c14n#") {
        mode = XML_C14N_EXCLUSIVE_1_0; with_comments = 0; return true;
    }
    if (uri == "http://www.w3.org/2001/10/xml-exc-c14n#WithComments") {
        mode = XML_C14N_EXCLUSIVE_1_0; with_comments = 1; return true;
    }
    return false;
}

// Канонікалізує піддерево першого елемента із заданою локальною назвою у межах
// документа, зберігаючи namespace-контекст (node-set включає namespace-вузли —
// це критично, інакше xmlns губиться). Розраховано на єдиний такий елемент
// (один підпис); підтримку кількох підписів додамо у наступних фазах.
inline bool CanonicalizeSubtreeByLocalName(xmlDocPtr doc,
                                           const char* local_name,
                                           int mode,
                                           int with_comments,
                                           std::string& out,
                                           std::string& error) {
    const std::string name(local_name);
    const std::string base = "//*[local-name()='" + name + "']";
    const std::string xpath =
        "(" + base + " | " + base + "//node() | " + base + "//@* | " +
        base + "/descendant-or-self::*/namespace::*)";

    XmlXPathCtxPtr ctx{xmlXPathNewContext(doc)};
    if (!ctx) {
        error = "Не вдалося створити XPath-контекст для канонікалізації піддерева";
        return false;
    }
    XmlXPathObjPtr obj{xmlXPathEvalExpression(
        reinterpret_cast<const xmlChar*>(xpath.c_str()), ctx.get())};
    if (!obj || obj->nodesetval == nullptr || obj->nodesetval->nodeNr == 0) {
        error = std::string("Не знайдено елемент для канонікалізації: ") + name;
        return false;
    }

    xmlChar* result = nullptr;
    const int len = xmlC14NDocDumpMemory(doc, obj->nodesetval, mode, nullptr, with_comments, &result);
    if (len < 0 || result == nullptr) {
        if (result != nullptr) {
            xmlFree(result);
        }
        error = std::string("Помилка канонікалізації піддерева: ") + name;
        return false;
    }
    out.assign(reinterpret_cast<const char*>(result), static_cast<std::size_t>(len));
    xmlFree(result);
    return true;
}

// Канонікалізує піддерево ВСІХ елементів local_name, що є нащадками САМЕ
// signature_position_1based-го (1-based, порядок документа) верхньорівневого
// ds:Signature — WP-2 (кілька ds:Signature в одному документі). Без
// обмеження до "першого" збігу: деякі XAdES-елементи (напр.
// SignatureTimeStamp/SigAndRefsTimeStamp для co-timestamping кількома TSA)
// легітимно можуть повторюватись у межах ОДНОГО підпису, і TBS архівної
// мітки часу має покривати ВСІ їх входження, а не лише перше. Для
// елементів, гарантовано унікальних структурно (SignedInfo/SignedProperties
// тощо, перевірених викликачем через CountElementsInSubtree == 1),
// поведінка ідентична — nodeset із рівно одним збігом.
inline bool CanonicalizeSubtreeWithinSignature(xmlDocPtr doc,
                                               int signature_position_1based,
                                               const char* local_name,
                                               int mode,
                                               int with_comments,
                                               std::string& out,
                                               std::string& error) {
    const std::string name(local_name);
    // П-13: скоуп namespace-aware — див. DsigSignatureScopeXPath.
    const std::string scope = DsigSignatureScopeXPath(signature_position_1based);
    const std::string base = scope + "//*[local-name()='" + name + "']";
    const std::string xpath =
        "(" + base + " | " + base + "//node() | " + base + "//@* | " +
        base + "/descendant-or-self::*/namespace::*)";

    XmlXPathCtxPtr ctx{xmlXPathNewContext(doc)};
    if (!ctx) {
        error = "Не вдалося створити XPath-контекст для канонікалізації піддерева";
        return false;
    }
    XmlXPathObjPtr obj{xmlXPathEvalExpression(
        reinterpret_cast<const xmlChar*>(xpath.c_str()), ctx.get())};
    if (!obj || obj->nodesetval == nullptr || obj->nodesetval->nodeNr == 0) {
        error = std::string("Не знайдено елемент для канонікалізації в межах підпису #") +
                std::to_string(signature_position_1based) + ": " + name;
        return false;
    }

    xmlChar* result = nullptr;
    const int len = xmlC14NDocDumpMemory(doc, obj->nodesetval, mode, nullptr, with_comments, &result);
    if (len < 0 || result == nullptr) {
        if (result != nullptr) {
            xmlFree(result);
        }
        error = std::string("Помилка канонікалізації піддерева в межах підпису: ") + name;
        return false;
    }
    out.assign(reinterpret_cast<const char*>(result), static_cast<std::size_t>(len));
    xmlFree(result);
    return true;
}

// ETSI EN 319 132-1 §5.5.2.3 крок 6 (архівна мітка часу XAdES, not-distributed
// case): канонікалізує ВСІ ds:Object, що є прямими нащадками
// signature_position_1based-го ds:Signature, КРІМ того(-их), що містить(ять)
// xades:QualifyingProperties -- це виключення прямо вимагає стандарт (сам
// QualifyingProperties/SignedProperties вже покритий кроком 1, через
// ds:Reference на SignedProperties; повторне включення дало б розбіжність із
// зовнішніми валідаторами). Порожній out БЕЗ помилки, якщо відповідних
// ds:Object немає -- типовий випадок для Tamga: єдиний ds:Object завжди
// містить QualifyingProperties.
inline bool CanonicalizeNonQualifyingObjectsWithinSignature(xmlDocPtr doc,
                                                            int signature_position_1based,
                                                            int mode,
                                                            int with_comments,
                                                            std::string& out,
                                                            std::string& error) {
    out.clear();
    // П-13: скоуп namespace-aware — див. DsigSignatureScopeXPath.
    const std::string scope = DsigSignatureScopeXPath(signature_position_1based);
    const std::string base =
        scope + "/*[local-name()='Object'][not(.//*[local-name()='QualifyingProperties'])]";
    const std::string xpath =
        "(" + base + " | " + base + "//node() | " + base + "//@* | " +
        base + "/descendant-or-self::*/namespace::*)";

    XmlXPathCtxPtr ctx{xmlXPathNewContext(doc)};
    if (!ctx) {
        error = "Не вдалося створити XPath-контекст для канонікалізації ds:Object";
        return false;
    }
    XmlXPathObjPtr obj{xmlXPathEvalExpression(
        reinterpret_cast<const xmlChar*>(xpath.c_str()), ctx.get())};
    if (!obj || obj->nodesetval == nullptr || obj->nodesetval->nodeNr == 0) {
        return true;  // немає ds:Object поза QualifyingProperties -- не помилка
    }

    xmlChar* result = nullptr;
    const int len = xmlC14NDocDumpMemory(doc, obj->nodesetval, mode, nullptr, with_comments, &result);
    if (len < 0 || result == nullptr) {
        if (result != nullptr) {
            xmlFree(result);
        }
        error = "Помилка канонікалізації ds:Object (виключаючи QualifyingProperties)";
        return false;
    }
    out.assign(reinterpret_cast<const char*>(result), static_cast<std::size_t>(len));
    xmlFree(result);
    return true;
}

// Канонікалізує піддерево елемента із атрибутом Id/ID/id == id, зберігаючи
// namespace-контекст відносно ОРИГІНАЛЬНОГО документа (node-set включає
// namespace-вузли предків — без цього губляться xmlns, успадковані від
// елементів вище за дерево, що дає невірний канонічний вигляд для
// ds:Reference URI="#...": такий вузол НЕ можна серіалізувати окремим
// рядком і перепарсити — він має канонікалізуватись прямо в контексті doc.
inline bool CanonicalizeSubtreeById(xmlDocPtr doc,
                                     const std::string& id,
                                     int mode,
                                     int with_comments,
                                     std::string& out,
                                     std::string& error) {
    if (id.empty() || id.find('\'') != std::string::npos) {
        error = "Некоректний ідентифікатор для XPath-пошуку елемента";
        return false;
    }
    const std::string base = "//*[@Id='" + id + "' or @ID='" + id + "' or @id='" + id + "']";
    const std::string xpath =
        "(" + base + " | " + base + "//node() | " + base + "//@* | " +
        base + "/descendant-or-self::*/namespace::*)";

    XmlXPathCtxPtr ctx{xmlXPathNewContext(doc)};
    if (!ctx) {
        error = "Не вдалося створити XPath-контекст для канонікалізації піддерева";
        return false;
    }
    XmlXPathObjPtr obj{xmlXPathEvalExpression(
        reinterpret_cast<const xmlChar*>(xpath.c_str()), ctx.get())};
    if (!obj || obj->nodesetval == nullptr || obj->nodesetval->nodeNr == 0) {
        error = "Не знайдено елемент з Id=" + id + " для канонікалізації";
        return false;
    }

    xmlChar* result = nullptr;
    const int len = xmlC14NDocDumpMemory(doc, obj->nodesetval, mode, nullptr, with_comments, &result);
    if (len < 0 || result == nullptr) {
        if (result != nullptr) {
            xmlFree(result);
        }
        error = "Помилка канонікалізації елемента з Id=" + id;
        return false;
    }
    out.assign(reinterpret_cast<const char*>(result), static_cast<std::size_t>(len));
    xmlFree(result);
    return true;
}

// Конкатенує C14N перших елементів із заданими локальними назвами (у вказаному
// порядку), пропускаючи відсутні. Використовується для TBS міток часу XAdES-X/A.
inline bool ConcatCanonical(xmlDocPtr doc,
                            const std::vector<std::string>& local_names,
                            int mode,
                            int with_comments,
                            std::string& out,
                            std::string& error) {
    out.clear();
    for (const std::string& name : local_names) {
        if (FindFirstElement(xmlDocGetRootElement(doc), name.c_str()) == nullptr) {
            continue;  // елемент відсутній — пропускаємо
        }
        std::string piece;
        if (!CanonicalizeSubtreeByLocalName(doc, name.c_str(), mode, with_comments, piece, error)) {
            return false;
        }
        out += piece;
    }
    return true;
}

// WP-2: те саме, але кожен елемент шукається/канонікалізується СТРОГО в
// межах signature_position_1based-го (1-based, порядок документа)
// верхньорівневого ds:Signature — для XAdES TBS (SigAndRefsTimeStamp/
// ArchiveTimeStamp) у документах із кількома підписами. Наявність елемента
// перевіряється через CountElementsInSubtree (сам підпис + нащадки, без
// сусідніх ds:Signature), а не глобальний пошук по документу.
inline bool ConcatCanonicalWithinSignature(xmlDocPtr doc,
                                           int signature_position_1based,
                                           xmlNodePtr signature_node,
                                           const std::vector<std::string>& local_names,
                                           int mode,
                                           int with_comments,
                                           std::string& out,
                                           std::string& error) {
    out.clear();
    for (const std::string& name : local_names) {
        if (CountElementsInSubtree(signature_node, name.c_str()) == 0) {
            continue;  // елемент відсутній у межах цього підпису — пропускаємо
        }
        std::string piece;
        if (!CanonicalizeSubtreeWithinSignature(doc, signature_position_1based, name.c_str(), mode, with_comments,
                                                piece, error)) {
            return false;
        }
        out += piece;
    }
    return true;
}

}  // namespace tamga::xmldsig::detail

#endif  // TAMGA_XML_SIGNATURES_ENABLED
