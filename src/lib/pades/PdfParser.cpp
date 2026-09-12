#include "pades/PdfParser.h"

#if defined(TAMGA_PDF_SIGNATURES_ENABLED)

#include <algorithm>
#include <exception>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <qpdf/QPDF.hh>

namespace tamga::pades {

bool PdfParser::IsValidPdf(const std::vector<std::uint8_t>& pdf, std::string& error_message) {
    if (pdf.empty()) {
        error_message = "Порожній PDF";
        return false;
    }
    try {
        QPDF qpdf;
        qpdf.processMemoryFile("in-memory.pdf",
                               reinterpret_cast<const char*>(pdf.data()),
                               pdf.size());
        return true;
    } catch (const std::exception& e) {
        error_message = e.what();
        return false;
    } catch (...) {
        error_message = "невідома помилка qpdf";
        return false;
    }
}

namespace {

void ExtractStreamArray(QPDFObjectHandle dict, const char* key,
                        std::vector<std::vector<std::uint8_t>>& out) {
    if (!dict.hasKey(key)) return;
    QPDFObjectHandle arr = dict.getKey(key);
    if (!arr.isArray()) return;
    const int n = arr.getArrayNItems();
    for (int i = 0; i < n; ++i) {
        QPDFObjectHandle item = arr.getArrayItem(i);
        if (!item.isStream()) continue;
        std::shared_ptr<Buffer> data = item.getStreamData();
        if (!data || data->getSize() == 0) continue;
        out.emplace_back(data->getBuffer(), data->getBuffer() + data->getSize());
    }
}

}  // namespace

bool PdfParser::ParseDss(const std::vector<std::uint8_t>& pdf,
                        std::vector<std::vector<std::uint8_t>>& certificates_der,
                        std::vector<std::vector<std::uint8_t>>& ocsp_responses_der,
                        std::vector<std::vector<std::uint8_t>>& crls_der) {
    certificates_der.clear();
    ocsp_responses_der.clear();
    crls_der.clear();
    if (pdf.empty()) return false;
    try {
        QPDF qpdf;
        qpdf.processMemoryFile("in-memory.pdf",
                               reinterpret_cast<const char*>(pdf.data()),
                               pdf.size());
        QPDFObjectHandle root = qpdf.getRoot();
        if (!root.hasKey("/DSS")) return false;
        QPDFObjectHandle dss = root.getKey("/DSS");
        if (!dss.isDictionary()) return false;
        ExtractStreamArray(dss, "/Certs", certificates_der);
        ExtractStreamArray(dss, "/OCSPs", ocsp_responses_der);
        ExtractStreamArray(dss, "/CRLs", crls_der);
        return true;
    } catch (const std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

std::vector<PdfSignatureDictionary> PdfParser::ExtractSignatureFields(
    const std::vector<std::uint8_t>& pdf) {
    std::vector<PdfSignatureDictionary> result;
    if (pdf.empty()) return result;
    try {
        QPDF qpdf;
        qpdf.processMemoryFile("in-memory.pdf",
                               reinterpret_cast<const char*>(pdf.data()), pdf.size());

        // Сканування всіх обʼєктів на наявність словників підпису:
        // /SubFilter + /ByteRange (4 елементи) + /Contents (рядок).
        // Надійніше за обхід AcroForm/Fields: охоплює DocTimeStamp-поля з
        // інкрементальних оновлень, що не зареєстровані у AcroForm /Fields.
        for (auto& obj : qpdf.getAllObjects()) {
            if (!obj.isDictionary()) continue;
            if (!obj.hasKey("/SubFilter") || !obj.hasKey("/ByteRange") ||
                !obj.hasKey("/Contents"))
                continue;

            PdfSignatureDictionary sd;

            if (obj.getKey("/SubFilter").isName()) {
                const std::string sf = obj.getKey("/SubFilter").getName();
                sd.sub_filter = (sf.size() > 1) ? sf.substr(1) : sf;
            }

            QPDFObjectHandle br = obj.getKey("/ByteRange");
            if (br.isArray() && br.getArrayNItems() == 4) {
                sd.byte_range.offset1 =
                    static_cast<std::uint64_t>(br.getArrayItem(0).getIntValue());
                sd.byte_range.length1 =
                    static_cast<std::uint64_t>(br.getArrayItem(1).getIntValue());
                sd.byte_range.offset2 =
                    static_cast<std::uint64_t>(br.getArrayItem(2).getIntValue());
                sd.byte_range.length2 =
                    static_cast<std::uint64_t>(br.getArrayItem(3).getIntValue());
            }

            // getStringValue() декодує hex-рядок /Contents у двійкові байти.
            // NUL-паддінг /Contents обрізає викликач через DerLength.
            if (obj.getKey("/Contents").isString()) {
                const std::string raw = obj.getKey("/Contents").getStringValue();
                sd.signature.assign(raw.begin(), raw.end());
            }

            if (!sd.signature.empty() && sd.byte_range.length1 > 0) {
                result.push_back(std::move(sd));
            }
        }

        // Стабільний порядок: сортування за offset2 (позиція після /Contents
        // у файлі) — перший підпис (основний) має найменший offset2.
        std::sort(result.begin(), result.end(),
                  [](const PdfSignatureDictionary& a, const PdfSignatureDictionary& b) {
                      return a.byte_range.offset2 < b.byte_range.offset2;
                  });
    } catch (const std::exception&) {
        return result;
    } catch (...) {
        return result;
    }
    return result;
}

namespace {

// Межі обходу. Вхід недовірений, а граф обʼєктів PDF може бути циклічним і
// довільно глибоким, тож обхід обмежений і за глибиною, і за обсягом.
constexpr int kMaxFingerprintDepth = 12;
constexpr std::size_t kMaxFingerprintBytes = 64u * 1024u * 1024u;

void AppendStreamBytes(QPDFObjectHandle obj, std::vector<std::uint8_t>& out) {
    if (!obj.isStream()) return;
    try {
        std::shared_ptr<Buffer> data = obj.getStreamData();
        if (data && data->getSize() > 0) {
            out.insert(out.end(), data->getBuffer(), data->getBuffer() + data->getSize());
        }
    } catch (const std::exception&) {
        // Потік із непідтримуваним фільтром: беремо сирі байти. Для порівняння
        // «до/після» важлива стабільність представлення, а не декодованість.
        try {
            std::shared_ptr<Buffer> raw = obj.getRawStreamData();
            if (raw && raw->getSize() > 0) {
                out.insert(out.end(), raw->getBuffer(), raw->getBuffer() + raw->getSize());
            }
        } catch (...) {
            out.push_back(0xFF);  // маркер нечитабельного потоку
        }
    }
}

// Рекурсивний відбиток довільного піддерева обʼєктів.
//
// Навіщо він потрібен. Попередня версія відбитка сторінки хешувала лише потоки
// /Contents і анотації. Але /Contents — це ІНСТРУКЦІЇ малювання (`/Im0 Do`), а
// не те, ЧИМ малюють: саме зображення лежить у /Resources /XObject окремим
// обʼєктом. Інкрементальне оновлення, що перевизначає цей обʼєкт, лишає
// /Contents побайтово тим самим — і документ, який бачить читач, змінюється,
// а відбиток ні. Аудит 2026-08-29 відтворив це на справжній фікстурі Дії:
// 267 дописаних байтів підмінювали повносторінковий скан, і звіт підробленого
// файлу відрізнявся від звіту оригіналу РІВНО одним полем — documentSize.
//
// Тому /Resources обходиться цілком і рекурсивно: словники (ключі відсортовані
// — `getKeys()` повертає `std::set`, тож обхід детермінований), масиви,
// потоки (словник + байти) і скаляри через `unparse()`.
//
// Маркери обриву ('#' глибина, '@' цикл) навмисно потрапляють у відбиток:
// якщо обхід обірвався, це має бути частиною порівняння, а не мовчазним
// пропуском — інакше два різні документи з обірваним обходом дали б однаковий
// відбиток.
void AppendObjectFingerprint(QPDFObjectHandle obj,
                             std::vector<std::uint8_t>& out,
                             std::set<std::pair<int, int>>& visited,
                             const int depth) {
    if (out.size() > kMaxFingerprintBytes) return;
    if (depth > kMaxFingerprintDepth) {
        out.push_back('#');
        return;
    }
    if (obj.isIndirect()) {
        const std::pair<int, int> id{obj.getObjectID(), obj.getGeneration()};
        if (!visited.insert(id).second) {
            out.push_back('@');
            return;
        }
    }
    if (obj.isStream()) {
        AppendObjectFingerprint(obj.getDict(), out, visited, depth + 1);
        out.push_back('~');
        AppendStreamBytes(obj, out);
        return;
    }
    if (obj.isDictionary()) {
        out.push_back('<');
        for (const auto& key : obj.getKeys()) {
            out.insert(out.end(), key.begin(), key.end());
            out.push_back(':');
            AppendObjectFingerprint(obj.getKey(key), out, visited, depth + 1);
            out.push_back(';');
        }
        out.push_back('>');
        return;
    }
    if (obj.isArray()) {
        out.push_back('[');
        const int n = obj.getArrayNItems();
        for (int i = 0; i < n; ++i) {
            AppendObjectFingerprint(obj.getArrayItem(i), out, visited, depth + 1);
            out.push_back(',');
        }
        out.push_back(']');
        return;
    }
    const std::string text = obj.unparse();
    out.insert(out.end(), text.begin(), text.end());
}

void AppendKeyFingerprint(QPDFObjectHandle dict, const char* key,
                          std::vector<std::uint8_t>& out,
                          std::set<std::pair<int, int>>& visited) {
    if (!dict.hasKey(key)) {
        out.push_back('-');
        return;
    }
    AppendObjectFingerprint(dict.getKey(key), out, visited, 0);
}

// Байти, за якими читач бачить сторінку: геометрія сторінки, декодовані потоки
// /Contents, ПОВНЕ піддерево /Resources і анотації (підтип + потік вигляду).
//
// `/Parent` навмисно НЕ обходиться: він веде вгору по дереву сторінок і
// втягнув би у відбиток однієї сторінки вміст усіх інших. Відбитки сторінок
// порівнюються поелементно, тож кожна сторінка й так перевіряється своїм.
void AppendPageFingerprint(QPDFObjectHandle page, std::vector<std::uint8_t>& out) {
    if (!page.isDictionary()) return;

    // Геометрія: /CropBox або /Rotate можуть приховати підписаний вміст, не
    // торкаючись жодного потоку.
    std::set<std::pair<int, int>> geometry_visited;
    for (const char* key : {"/MediaBox", "/CropBox", "/Rotate", "/UserUnit"}) {
        AppendKeyFingerprint(page, key, out, geometry_visited);
        out.push_back(';');
    }
    out.push_back('|');

    if (page.hasKey("/Contents")) {
        QPDFObjectHandle contents = page.getKey("/Contents");
        if (contents.isArray()) {
            const int n = contents.getArrayNItems();
            for (int i = 0; i < n; ++i) {
                AppendStreamBytes(contents.getArrayItem(i), out);
            }
        } else {
            AppendStreamBytes(contents, out);
        }
    }
    out.push_back('|');

    // /Resources цілком: зображення, шрифти, форми, патерни, градієнти й стани
    // графіки. Саме сюди веде посилання з /Contents.
    {
        std::set<std::pair<int, int>> resources_visited;
        AppendKeyFingerprint(page, "/Resources", out, resources_visited);
    }
    out.push_back('|');

    if (page.hasKey("/Annots")) {
        QPDFObjectHandle annots = page.getKey("/Annots");
        if (annots.isArray()) {
            const int n = annots.getArrayNItems();
            for (int i = 0; i < n; ++i) {
                QPDFObjectHandle a = annots.getArrayItem(i);
                if (!a.isDictionary()) continue;
                if (a.hasKey("/Subtype") && a.getKey("/Subtype").isName()) {
                    const std::string sub = a.getKey("/Subtype").getName();
                    out.insert(out.end(), sub.begin(), sub.end());
                }
                if (a.hasKey("/AP")) {
                    QPDFObjectHandle ap = a.getKey("/AP");
                    if (ap.isDictionary() && ap.hasKey("/N")) {
                        AppendStreamBytes(ap.getKey("/N"), out);
                    }
                }
                out.push_back(';');
            }
        }
    }
    out.push_back('\n');
}

// Відбиток документних властивостей, що впливають на видимий результат, але не
// належать жодній сторінці. Наразі це /OCProperties: перемикання видимості
// шару приховує або показує підписаний вміст, не торкаючись ані /Contents, ані
// /Resources. Каталог цілком тут НЕ хешується навмисно — саме до нього
// легітимно додається /DSS у PAdES-LT, і це не є модифікацією документа.
void AppendDocumentFingerprint(QPDF& qpdf, std::vector<std::uint8_t>& out) {
    std::set<std::pair<int, int>> visited;
    AppendKeyFingerprint(qpdf.getRoot(), "/OCProperties", out, visited);
    out.push_back('\n');
}

// Відбитки всіх сторінок документа плюс документний відбиток. Порожній вектор
// -> документ не вдалося розібрати (викликач трактує це fail-closed).
bool CollectPageFingerprints(const char* name, const char* data, std::size_t size,
                             std::vector<std::vector<std::uint8_t>>& out,
                             std::vector<std::uint8_t>& document_out,
                             std::string& error) {
    try {
        QPDF qpdf;
        qpdf.processMemoryFile(name, data, size);
        for (auto& page : qpdf.getAllPages()) {
            std::vector<std::uint8_t> fp;
            AppendPageFingerprint(page, fp);
            out.push_back(std::move(fp));
        }
        AppendDocumentFingerprint(qpdf, document_out);
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    } catch (...) {
        error = "невідома помилка qpdf";
        return false;
    }
}

}  // namespace

bool PdfParser::ComparePageContentWithSignedRevision(const std::vector<std::uint8_t>& pdf,
                                                     const std::size_t signed_prefix_size,
                                                     bool& content_changed,
                                                     std::string& detail) {
    content_changed = false;
    detail.clear();
    if (signed_prefix_size == 0 || signed_prefix_size > pdf.size()) {
        detail = "некоректний розмір підписаної ревізії";
        return false;
    }

    const char* base = reinterpret_cast<const char*>(pdf.data());

    std::vector<std::vector<std::uint8_t>> signed_pages;
    std::vector<std::uint8_t> signed_document;
    std::string signed_error;
    if (!CollectPageFingerprints("signed-revision.pdf", base, signed_prefix_size, signed_pages,
                                 signed_document, signed_error)) {
        // Префікс не є самодостатнім PDF. За інкрементальної моделі це
        // означає, що «хвіст» не є коректним інкрементальним оновленням.
        detail = "підписана ревізія не розбирається окремо: " + signed_error;
        return false;
    }

    std::vector<std::vector<std::uint8_t>> current_pages;
    std::vector<std::uint8_t> current_document;
    std::string current_error;
    if (!CollectPageFingerprints("current.pdf", base, pdf.size(), current_pages,
                                 current_document, current_error)) {
        detail = "поточний документ не розбирається: " + current_error;
        return false;
    }

    if (signed_document != current_document) {
        content_changed = true;
        detail = "документні властивості видимості (/OCProperties) змінено після підписання";
        return true;
    }

    if (signed_pages.size() != current_pages.size()) {
        content_changed = true;
        detail = "кількість сторінок змінено після підписання: було " +
                 std::to_string(signed_pages.size()) + ", стало " +
                 std::to_string(current_pages.size());
        return true;
    }

    for (std::size_t i = 0; i < signed_pages.size(); ++i) {
        if (signed_pages[i] != current_pages[i]) {
            content_changed = true;
            detail = "вміст сторінки " + std::to_string(i + 1) + " змінено після підписання";
            return true;
        }
    }

    detail = "вміст сторінок не змінювався";
    return true;
}

}  // namespace tamga::pades

#endif  // TAMGA_PDF_SIGNATURES_ENABLED
