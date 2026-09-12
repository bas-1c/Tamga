#include "pades/PadesBuilder.h"

#if defined(TAMGA_PDF_SIGNATURES_ENABLED)

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <exception>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <iterator>
#include <utility>
#include <vector>

#include <qpdf/QPDF.hh>
#include <qpdf/QPDFObjectHandle.hh>

#include "core/CryptoniteAdapter.h"
#include "core/policy/Sha256Helper.h"
#include "pades/PdfByteRange.h"

namespace tamga::pades {

namespace {

constexpr std::size_t kContentsHexLen = 16384;  // 8192 байти під CMS/токен DER
constexpr std::size_t kByteRangeSlotLen = 80;  // Чотири десяткові uint64 та роздільники.

struct IncrementalObject {
    QPDFObjGen object;
    std::string body;
};

struct RevisionLayout {
    std::string bytes;
    std::size_t byte_range_open{0};
    std::size_t byte_range_close{0};
    std::size_t contents_lt{0};
    std::size_t contents_gt{0};
    std::size_t startxref{0};
};

std::string HexUpper(const std::vector<std::uint8_t>& data) {
    static const char* d = "0123456789ABCDEF";
    std::string out;
    out.reserve(data.size() * 2);
    for (std::uint8_t b : data) {
        out.push_back(d[(b >> 4) & 0xF]);
        out.push_back(d[b & 0xF]);
    }
    return out;
}

std::string PdfUtf8String(const std::string& value) {
    // qpdf handles PDFDocEncoding/UTF-16BE escaping and parentheses safely.
    return QPDFObjectHandle::newUnicodeString(value).unparse();
}

std::string Ref(const QPDFObjectHandle& object) {
    return object.unparse();
}

QPDFObjectHandle NewIndirect(QPDF& qpdf) {
    return qpdf.makeIndirectObject(QPDFObjectHandle::newNull());
}

std::string StreamObj(const std::vector<std::uint8_t>& bytes) {
    std::string body(bytes.begin(), bytes.end());
    return "<</Length " + std::to_string(body.size()) + ">>\nstream\n" + body +
           "\nendstream";
}

std::string SigDictBody(const char* type, const char* sub_filter, const std::string& extra) {
    return std::string("<</Type/") + type +
           "/Filter/Adobe.PPKLite/SubFilter/" + sub_filter +
           "/ByteRange [" + std::string(kByteRangeSlotLen - 2, ' ') + "]/Contents <" +
           std::string(kContentsHexLen, '0') + ">" + extra + ">>";
}

std::string WidgetBody(const std::string& field_name, const QPDFObjectHandle& signature,
                       const QPDFObjectHandle& page, const std::string& pdf_date) {
    return "<</Type/Annot/Subtype/Widget/FT/Sig/T " + PdfUtf8String(field_name) +
           "/Rect[0 0 50 50]/F 132/V " + Ref(signature) +
           (page.isIndirect() ? "/P " + Ref(page) : "") +
           "/M " + PdfUtf8String(pdf_date) + ">>";
}

std::string CatalogBody(const std::map<std::string, QPDFObjectHandle>& source,
                        const QPDFObjectHandle& acroform,
                        const QPDFObjectHandle& dss) {
    auto catalog = source;
    // QPDFObjectHandle::newDictionary не зберігає непрямий null-placeholder,
    // якщо його безпосередньо передати як значення верхнього рівня. Ці два
    // посилання поточної revision серіалізуємо явно, зберігаючи всі інші ключі
    // Catalog на рівні object graph.
    catalog.erase("/AcroForm");
    if (dss.isIndirect()) catalog.erase("/DSS");
    std::string body = QPDFObjectHandle::newDictionary(catalog).unparse();
    const std::size_t close = body.rfind(">>");
    if (close == std::string::npos) return body;
    body.insert(close, " /AcroForm " + Ref(acroform));
    if (dss.isIndirect()) body.insert(close, " /DSS " + Ref(dss));
    return body;
}

bool IsPdfHeader(const std::vector<std::uint8_t>& pdf) {
    // PDF допускає короткий двійковий префікс перед заголовком (до перших
    // 1024 байтів). Повну синтаксичну перевірку все одно виконує qpdf.
    const std::size_t limit = std::min<std::size_t>(pdf.size(), 1024);
    for (std::size_t offset = 0; offset + 5 <= limit; ++offset) {
        if (std::memcmp(pdf.data() + offset, "%PDF-", 5) == 0) return true;
    }
    return false;
}

bool ParseLastStartXref(const std::vector<std::uint8_t>& pdf, std::uint64_t& value) {
    const std::string bytes(pdf.begin(), pdf.end());
    const std::size_t marker = bytes.rfind("startxref");
    if (marker == std::string::npos) return false;

    std::size_t pos = marker + std::strlen("startxref");
    while (pos < bytes.size() && std::isspace(static_cast<unsigned char>(bytes[pos]))) ++pos;
    if (pos >= bytes.size() || !std::isdigit(static_cast<unsigned char>(bytes[pos]))) return false;

    std::uint64_t parsed = 0;
    while (pos < bytes.size() && std::isdigit(static_cast<unsigned char>(bytes[pos]))) {
        const unsigned digit = static_cast<unsigned>(bytes[pos] - '0');
        if (parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) return false;
        parsed = parsed * 10 + digit;
        ++pos;
    }
    value = parsed;
    return true;
}

std::vector<QPDFObjectHandle> GetArrayItems(QPDFObjectHandle dictionary, const char* key) {
    if (!dictionary.isDictionary() || !dictionary.hasKey(key)) return {};
    QPDFObjectHandle array = dictionary.getKey(key);
    if (!array.isArray()) return {};
    return array.getArrayAsVector();
}

std::set<std::string> ExistingFieldNames(const std::vector<QPDFObjectHandle>& fields) {
    std::set<std::string> names;
    for (const auto& field : fields) {
        if (!field.isDictionary() || !field.hasKey("/T")) continue;
        const auto name = field.getKey("/T");
        if (name.isString()) names.insert(name.getStringValue());
    }
    return names;
}

std::string UniqueFieldName(const std::set<std::string>& existing, std::string base) {
    if (base.empty()) base = "Signature1";
    if (!existing.count(base)) return base;
    for (unsigned int suffix = 2;; ++suffix) {
        const std::string candidate = base + "-" + std::to_string(suffix);
        if (!existing.count(candidate)) return candidate;
    }
}

struct XrefEntry {
    std::size_t offset;
    int generation;
};

void AppendXrefSubsections(std::string& revision,
                           const std::map<int, XrefEntry>& offsets) {
    revision += "xref\n";
    auto it = offsets.begin();
    while (it != offsets.end()) {
        const int first = it->first;
        int last = first;
        auto end = std::next(it);
        while (end != offsets.end() && end->first == last + 1) {
            last = end->first;
            ++end;
        }

        revision += std::to_string(first) + " " + std::to_string(last - first + 1) + "\n";
        for (int id = first; id <= last; ++id) {
            const auto offset = offsets.find(id);
            char line[64];
            std::snprintf(line, sizeof(line), "%010zu %05d n \n",
                          offset->second.offset, offset->second.generation);
            revision += line;
        }
        it = end;
    }
}

RevisionLayout AssembleRevision(std::size_t base_offset,
                                 std::uint64_t previous_startxref,
                                 const std::vector<IncrementalObject>& input_objects,
                                 const QPDFObjectHandle& root,
                                 const QPDFObjGen& signature_object,
                                 std::map<std::string, QPDFObjectHandle>& trailer) {
    std::vector<IncrementalObject> objects = input_objects;
    std::sort(objects.begin(), objects.end(), [](const IncrementalObject& lhs,
                                                const IncrementalObject& rhs) {
        return lhs.object < rhs.object;
    });

    RevisionLayout layout;
    std::map<int, XrefEntry> offsets;
    int max_object_id = root.getObjectID();
    for (const auto& object : objects) {
        const std::size_t object_offset = base_offset + layout.bytes.size();
        offsets.emplace(object.object.getObj(), XrefEntry{object_offset, object.object.getGen()});
        max_object_id = std::max(max_object_id, object.object.getObj());
        layout.bytes += std::to_string(object.object.getObj()) + " " +
                        std::to_string(object.object.getGen()) + " obj\n";
        const std::size_t body_offset = layout.bytes.size();
        layout.bytes += object.body + "\nendobj\n";

        if (object.object == signature_object) {
            const std::size_t br = layout.bytes.find("/ByteRange [", body_offset);
            const std::size_t contents = layout.bytes.find("/Contents <", body_offset);
            if (br != std::string::npos) {
                const std::size_t open = layout.bytes.find('[', br);
                const std::size_t close = layout.bytes.find(']', open);
                layout.byte_range_open = base_offset + open;
                layout.byte_range_close = base_offset + close;
            }
            if (contents != std::string::npos) {
                const std::size_t lt = layout.bytes.find('<', contents);
                const std::size_t gt = layout.bytes.find('>', lt);
                layout.contents_lt = base_offset + lt;
                layout.contents_gt = base_offset + gt;
            }
        }
    }

    const std::size_t xref_offset = base_offset + layout.bytes.size();
    AppendXrefSubsections(layout.bytes, offsets);

    // Перехід із xref-stream до таблиці не переносить транспортні ключі потоку.
    // Решту трейлера (зокрема /Info та власні ключі) зберігаємо між ревізіями.
    for (const char* key : {"/Type", "/W", "/Index", "/Length", "/Filter",
                            "/DecodeParms", "/DL", "/XRefStm"}) {
        trailer.erase(key);
    }
    const auto old_size = trailer.find("/Size");
    const long long size = old_size != trailer.end() && old_size->second.isInteger()
                               ? old_size->second.getIntValue() : 0;
    trailer["/Size"] = QPDFObjectHandle::newInteger(
        std::max(size, static_cast<long long>(max_object_id) + 1));
    trailer["/Root"] = root;
    trailer["/Prev"] = QPDFObjectHandle::newInteger(static_cast<long long>(previous_startxref));

    // Перший ID ідентифікує документ, другий — саме це інкрементальне оновлення.
    // Це ідентифікатори PDF, а не геші для перевірки підпису.
    const std::string id_material = QPDFObjectHandle::newDictionary(trailer).unparse() +
                                    std::to_string(base_offset) + layout.bytes;
    const auto digest = tamga::core::policy::Sha256(
        std::vector<std::uint8_t>(id_material.begin(), id_material.end()));
    const auto revision_id = QPDFObjectHandle::newString(
        std::string(reinterpret_cast<const char*>(digest.data()), 16));
    QPDFObjectHandle document_id = revision_id;
    const auto old_id = trailer.find("/ID");
    if (old_id != trailer.end() && old_id->second.isArray() &&
        old_id->second.getArrayNItems() > 0 && old_id->second.getArrayItem(0).isString()) {
        document_id = old_id->second.getArrayItem(0);
    }
    trailer["/ID"] = QPDFObjectHandle::newArray({document_id, revision_id});
    layout.bytes += "trailer\n" + QPDFObjectHandle::newDictionary(trailer).unparse() +
                    "\nstartxref\n" + std::to_string(xref_offset) + "\n%%EOF\n";
    layout.startxref = xref_offset;
    return layout;
}

// Записує реальні значення ByteRange у плейсхолдер (позиції мають бути
// абсолютними зсувами у всьому PDF, а не відносними до incremental revision).
bool WriteByteRange(std::vector<std::uint8_t>& pdf, std::size_t open, std::size_t close,
                    const ByteRange& br, std::string& error) {
    if (open >= pdf.size() || close >= pdf.size() || close < open) {
        error = "Некоректні позиції ByteRange у PDF revision";
        return false;
    }
    std::string field = "[ 0 " + std::to_string(br.length1) + " " +
                        std::to_string(br.offset2) + " " + std::to_string(br.length2);
    const std::size_t slot_size = close - open + 1;
    if (field.size() + 2 > slot_size) {
        error = "Значення ByteRange не вміщуються у плейсхолдер";
        return false;
    }
    field.append(slot_size - field.size() - 1, ' ');
    field.push_back(']');
    std::copy(field.begin(), field.end(), pdf.begin() + open);
    return true;
}

bool WriteContentsHex(std::vector<std::uint8_t>& pdf, std::size_t lt, std::size_t gt,
                      const std::vector<std::uint8_t>& der, std::string& error) {
    if (lt >= pdf.size() || gt >= pdf.size() || gt <= lt) {
        error = "Некоректні позиції /Contents у PDF revision";
        return false;
    }
    const std::string hex = HexUpper(der);
    if (hex.size() > (gt - lt - 1)) {
        error = "DER не вміщується у /Contents плейсхолдер";
        return false;
    }
    std::copy(hex.begin(), hex.end(), pdf.begin() + lt + 1);
    return true;
}

}  // namespace

PadesBuilder::PadesBuilder(tamga::core::CryptoniteAdapter& crypto, tamga::core::TspClient& tsp)
    : crypto_(crypto), tsp_(tsp) {}

bool PadesBuilder::SignPdf(const PadesParameters& params,
                           const std::vector<std::uint8_t>& document_content,
                           const tamga::core::SigningKey& signing_key,
                           std::vector<std::uint8_t>& signed_pdf_out,
                           std::string& error_message) {
    signed_pdf_out.clear();
    const int level = static_cast<int>(params.profile);
    const bool want_t = level >= static_cast<int>(PadesProfile::T);
    const bool want_lt = level >= static_cast<int>(PadesProfile::LT);
    const bool want_lta = level >= static_cast<int>(PadesProfile::LTA);
    PadesValidationEvidence evidence{params.certificate_chain, params.crls, params.ocsp_responses};
    auto merge_evidence = [](PadesValidationEvidence& target,
                             const PadesValidationEvidence& incoming) {
        bool changed = false;
        auto merge = [&changed](auto& to, const auto& from) {
            for (const auto& blob : from) {
                if (!blob.empty() && std::find(to.begin(), to.end(), blob) == to.end()) {
                    to.push_back(blob);
                    changed = true;
                }
            }
        };
        merge(target.certificate_chain, incoming.certificate_chain);
        merge(target.crls, incoming.crls);
        merge(target.ocsp_responses, incoming.ocsp_responses);
        return changed;
    };

    if (want_t && !params.timestamp_provider) {
        error_message = "Профіль PAdES-T+ потребує timestamp_provider";
        return false;
    }
    if (!IsPdfHeader(document_content)) {
        error_message = "SignPdf очікує повний PDF-документ із заголовком %PDF-";
        return false;
    }

    QPDF qpdf;
    try {
        qpdf.processMemoryFile("input.pdf",
                               reinterpret_cast<const char*>(document_content.data()),
                               document_content.size());
    } catch (const std::exception& e) {
        error_message = std::string("Не вдалося розібрати вхідний PDF: ") + e.what();
        return false;
    } catch (...) {
        error_message = "Не вдалося розібрати вхідний PDF";
        return false;
    }
    if (qpdf.isEncrypted()) {
        error_message = "Підписання зашифрованого PDF без пароля не підтримується";
        return false;
    }

    const QPDFObjectHandle original_root = qpdf.getRoot();
    if (!original_root.isDictionary() || !original_root.isIndirect()) {
        error_message = "PDF не має коректного непрямого Catalog";
        return false;
    }
    auto trailer = qpdf.getTrailer().getDictAsMap();
    QPDFObjectHandle first_page;
    try {
        const auto& pages = qpdf.getAllPages();
        if (!pages.empty()) first_page = pages.front();
    } catch (const std::exception& e) {
        error_message = std::string("Не вдалося розібрати дерево сторінок PDF: ") + e.what();
        return false;
    }
    std::uint64_t previous_startxref = 0;
    if (!ParseLastStartXref(document_content, previous_startxref)) {
        error_message = "PDF не має коректного startxref для incremental update";
        return false;
    }

    std::map<std::string, QPDFObjectHandle> acroform_map;
    std::vector<QPDFObjectHandle> fields;
    if (original_root.hasKey("/AcroForm")) {
        const QPDFObjectHandle original_acroform = original_root.getKey("/AcroForm");
        if (!original_acroform.isDictionary()) {
            error_message = "PDF має некоректний /AcroForm dictionary";
            return false;
        }
        acroform_map = original_acroform.getDictAsMap();
        if (original_acroform.hasKey("/Fields")) {
            const QPDFObjectHandle existing_fields = original_acroform.getKey("/Fields");
            if (!existing_fields.isArray()) {
                error_message = "PDF має некоректний /AcroForm/Fields array";
                return false;
            }
            fields = existing_fields.getArrayAsVector();
        }
    }
    if (!acroform_map.count("/SigFlags")) {
        acroform_map["/SigFlags"] = QPDFObjectHandle::newInteger(3);
    }
    const std::set<std::string> existing_field_names = ExistingFieldNames(fields);
    const std::string main_field_name = UniqueFieldName(existing_field_names, params.field_name);

    std::map<std::string, QPDFObjectHandle> catalog_map = original_root.getDictAsMap();
    std::vector<IncrementalObject> main_objects;
    QPDFObjectHandle dss_ref;
    auto add_object = [&main_objects](const QPDFObjectHandle& object, std::string body) {
        main_objects.push_back({object.getObjGen(), std::move(body)});
    };

    if (level < static_cast<int>(PadesProfile::B) || level > static_cast<int>(PadesProfile::LTA)) {
        error_message = "Невідомий профіль PAdES";
        return false;
    }

    const QPDFObjectHandle signature_ref = NewIndirect(qpdf);
    const QPDFObjectHandle widget_ref = NewIndirect(qpdf);
    const QPDFObjectHandle acroform_ref = NewIndirect(qpdf);
    // ISO 32000-1, 7.5.6: оновлений Catalog зберігає номер і покоління об'єкта.
    const QPDFObjectHandle catalog_ref = original_root;

    fields.push_back(widget_ref);
    acroform_map["/Fields"] = QPDFObjectHandle::newArray(fields);
    const long long old_sig_flags = acroform_map["/SigFlags"].isInteger()
                                        ? acroform_map["/SigFlags"].getIntValue()
                                        : 0;
    acroform_map["/SigFlags"] = QPDFObjectHandle::newInteger(old_sig_flags | 3);

    // Заявлений час підпису PAdES міститься в PDF-словнику, а не лише в CMS.
    const std::time_t now = std::time(nullptr);
    std::tm utc{};
#ifdef _WIN32
    if (gmtime_s(&utc, &now) != 0) {
#else
    if (gmtime_r(&now, &utc) == nullptr) {
#endif
        error_message = "Не вдалося визначити час підпису PDF";
        return false;
    }
    char pdf_date[40];
    if (std::strftime(pdf_date, sizeof(pdf_date), "D:%Y%m%d%H%M%S+00'00'", &utc) == 0) {
        error_message = "Не вдалося сформувати дату підпису PDF";
        return false;
    }
    std::string sig_extra = "/M " + PdfUtf8String(pdf_date);
    sig_extra += "/Reason " + PdfUtf8String(params.reason);
    if (!params.location.empty()) sig_extra += "/Location " + PdfUtf8String(params.location);

    // PAdES містить CAdES/CMS-підпис, тому словник підпису має явно
    // оголошувати ETSI-профіль. `adbe.pkcs7.detached` описує загальний
    // PKCS#7-підпис і відхиляється валідатором Дії для PAdES-B-*.
    add_object(signature_ref, SigDictBody("Sig", "ETSI.CAdES.detached", sig_extra));
    add_object(widget_ref, WidgetBody(main_field_name, signature_ref, first_page, pdf_date));
    add_object(acroform_ref, QPDFObjectHandle::newDictionary(acroform_map).unparse());
    add_object(catalog_ref, CatalogBody(catalog_map, acroform_ref, dss_ref));

    std::vector<std::uint8_t> pdf = document_content;
    if (pdf.empty() || (pdf.back() != '\n' && pdf.back() != '\r')) pdf.push_back('\n');

    const RevisionLayout main_revision = AssembleRevision(pdf.size(), previous_startxref,
                                                          main_objects, catalog_ref,
                                                          signature_ref.getObjGen(), trailer);
    if (main_revision.contents_lt == 0 || main_revision.contents_gt <= main_revision.contents_lt ||
        main_revision.byte_range_close <= main_revision.byte_range_open) {
        error_message = "Не знайдено плейсхолдери PAdES у main incremental revision";
        return false;
    }
    pdf.insert(pdf.end(), main_revision.bytes.begin(), main_revision.bytes.end());

    const ByteRange main_range = PdfByteRange::Compute(main_revision.contents_lt,
                                                       main_revision.contents_gt, pdf.size());
    if (!WriteByteRange(pdf, main_revision.byte_range_open, main_revision.byte_range_close,
                        main_range, error_message)) {
        return false;
    }
    const std::vector<std::uint8_t> main_signed_bytes =
        PdfByteRange::ExtractSignedBytes(pdf, main_range);
    std::vector<std::uint8_t> cms;
    if (!tamga::core::CryptoniteAdapter::SignPadesDetached(
            signing_key.use_pkcs12, signing_key.key_material, signing_key.certificate_der,
            signing_key.password, main_signed_bytes, cms, error_message)) {
        return false;
    }
    if (want_t) {
        std::vector<std::uint8_t> sigval;
        if (!tamga::core::CryptoniteAdapter::GetSignatureValue(cms, sigval, error_message)) {
            return false;
        }
        std::vector<std::uint8_t> token;
        if (!params.timestamp_provider(sigval, token, error_message)) return false;
        if (want_lt && params.timestamp_evidence_provider) {
            PadesValidationEvidence actual;
            if (!params.timestamp_evidence_provider(token, sigval, actual, error_message)) return false;
            merge_evidence(evidence, actual);
        }
        std::vector<std::uint8_t> cms_t;
        if (!tamga::core::CryptoniteAdapter::AppendTspToken(cms, token, cms_t, error_message)) {
            return false;
        }
        cms = std::move(cms_t);
    }
    if (!WriteContentsHex(pdf, main_revision.contents_lt, main_revision.contents_gt, cms,
                          error_message)) {
        return false;
    }

    previous_startxref = main_revision.startxref;
    QPDFObjectHandle current_acroform_ref = acroform_ref;
    auto append_dss_revision = [&]() -> bool {
        // DSS додаємо лише після завершення CMS: ByteRange підпису не змінюється.
        std::vector<IncrementalObject> dss_objects;
        std::map<std::string, QPDFObjectHandle> dss_map;
        if (original_root.hasKey("/DSS")) {
            const QPDFObjectHandle original_dss = original_root.getKey("/DSS");
            if (!original_dss.isDictionary()) {
                error_message = "PDF має некоректний /DSS dictionary";
                return false;
            }
            dss_map = original_dss.getDictAsMap();
        }
        dss_map["/Type"] = QPDFObjectHandle::newName("/DSS");
        auto append_dss_streams = [&](const char* key,
                                     const std::vector<std::vector<std::uint8_t>>& blobs) {
            std::vector<QPDFObjectHandle> handles;
            if (original_root.hasKey("/DSS")) {
                handles = GetArrayItems(original_root.getKey("/DSS"), key);
            }
            for (const auto& blob : blobs) {
                if (blob.empty()) continue;
                const QPDFObjectHandle stream = NewIndirect(qpdf);
                handles.push_back(stream);
                dss_objects.push_back({stream.getObjGen(), StreamObj(blob)});
            }
            if (!handles.empty()) dss_map[key] = QPDFObjectHandle::newArray(handles);
        };
        append_dss_streams("/Certs", evidence.certificate_chain);
        append_dss_streams("/CRLs", evidence.crls);
        append_dss_streams("/OCSPs", evidence.ocsp_responses);
        dss_ref = NewIndirect(qpdf);
        dss_objects.push_back({dss_ref.getObjGen(),
                               QPDFObjectHandle::newDictionary(dss_map).unparse()});
        dss_objects.push_back({original_root.getObjGen(),
                               CatalogBody(catalog_map, current_acroform_ref, dss_ref)});
        const RevisionLayout dss_revision = AssembleRevision(
            pdf.size(), previous_startxref, dss_objects, original_root, QPDFObjGen(), trailer);
        pdf.insert(pdf.end(), dss_revision.bytes.begin(), dss_revision.bytes.end());
        previous_startxref = dss_revision.startxref;
        return true;
    };
    if (want_lt && !append_dss_revision()) return false;

    if (want_lta) {
        std::set<std::string> timestamp_names = existing_field_names;
        timestamp_names.insert(main_field_name);
        // Фактичний DocTimeStamp інколи змінює TSA/ланцюг. Нові докази
        // додаються наступною DSS-ревізією і захищаються новою міткою; старі
        // ревізії незмінні. Нескінченне оновлення доказів відхиляємо.
        constexpr unsigned kMaxEvidenceRenewals = 3;
        for (unsigned renewal = 0; ; ++renewal) {
        // LTA timestamp є окремою revision і тому не змінює ByteRange основного підпису.
        const QPDFObjectHandle timestamp_signature_ref = NewIndirect(qpdf);
        const QPDFObjectHandle timestamp_widget_ref = NewIndirect(qpdf);
        const QPDFObjectHandle timestamp_acroform_ref = NewIndirect(qpdf);
        const QPDFObjectHandle timestamp_catalog_ref = original_root;

        std::vector<QPDFObjectHandle> timestamp_fields = fields;
        const std::string timestamp_field_name = UniqueFieldName(timestamp_names, "TimeStamp1");
        timestamp_names.insert(timestamp_field_name);
        timestamp_fields.push_back(timestamp_widget_ref);

        std::map<std::string, QPDFObjectHandle> timestamp_acroform_map = acroform_map;
        timestamp_acroform_map["/Fields"] = QPDFObjectHandle::newArray(timestamp_fields);
        std::map<std::string, QPDFObjectHandle> timestamp_catalog_map = catalog_map;

        std::vector<IncrementalObject> timestamp_objects;
        timestamp_objects.push_back({timestamp_signature_ref.getObjGen(),
                                     SigDictBody("DocTimeStamp", "ETSI.RFC3161", "")});
        timestamp_objects.push_back({timestamp_widget_ref.getObjGen(),
                                     WidgetBody(timestamp_field_name, timestamp_signature_ref,
                                                first_page, pdf_date)});
        timestamp_objects.push_back({timestamp_acroform_ref.getObjGen(),
                                     QPDFObjectHandle::newDictionary(timestamp_acroform_map).unparse()});
        timestamp_objects.push_back({timestamp_catalog_ref.getObjGen(),
                                     CatalogBody(timestamp_catalog_map, timestamp_acroform_ref,
                                                 dss_ref)});

        const RevisionLayout timestamp_revision =
            AssembleRevision(pdf.size(), previous_startxref, timestamp_objects,
                             timestamp_catalog_ref, timestamp_signature_ref.getObjGen(), trailer);
        if (timestamp_revision.contents_lt == 0 ||
            timestamp_revision.contents_gt <= timestamp_revision.contents_lt ||
            timestamp_revision.byte_range_close <= timestamp_revision.byte_range_open) {
            error_message = "Не знайдено плейсхолдери PAdES DocTimeStamp";
            return false;
        }
        pdf.insert(pdf.end(), timestamp_revision.bytes.begin(), timestamp_revision.bytes.end());

        const ByteRange timestamp_range = PdfByteRange::Compute(
            timestamp_revision.contents_lt, timestamp_revision.contents_gt, pdf.size());
        if (!WriteByteRange(pdf, timestamp_revision.byte_range_open,
                            timestamp_revision.byte_range_close, timestamp_range, error_message)) {
            return false;
        }
        const std::vector<std::uint8_t> timestamp_signed_bytes =
            PdfByteRange::ExtractSignedBytes(pdf, timestamp_range);
        std::vector<std::uint8_t> token;
        if (!params.timestamp_provider(timestamp_signed_bytes, token, error_message)) return false;
        if (!WriteContentsHex(pdf, timestamp_revision.contents_lt, timestamp_revision.contents_gt,
                              token, error_message)) {
            return false;
        }
        previous_startxref = timestamp_revision.startxref;
        current_acroform_ref = timestamp_acroform_ref;
        fields = std::move(timestamp_fields);
        bool needs_renewal = false;
        if (params.timestamp_evidence_provider) {
            PadesValidationEvidence actual;
            if (!params.timestamp_evidence_provider(token, timestamp_signed_bytes, actual,
                                                    error_message)) return false;
            needs_renewal = merge_evidence(evidence, actual);
        }
        if (!needs_renewal) break;
        if (renewal == kMaxEvidenceRenewals) {
            error_message = "Докази TSA не стабілізувалися після трьох оновлень PAdES-LTA";
            return false;
        }
        if (!append_dss_revision()) return false;
        }
    }

    signed_pdf_out = std::move(pdf);
    return true;
}

}  // namespace tamga::pades

#endif  // TAMGA_PDF_SIGNATURES_ENABLED
