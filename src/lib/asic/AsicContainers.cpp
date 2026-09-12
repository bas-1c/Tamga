#include "asic/AsicContainers.h"
#include "asic/AsicWriter.h"
#include "asic/AsicReader.h"
#include "xml/XmlCore.h"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <utility>

// ADR-030: ASiC-манфест розбирається libxml2, а не власним сканером підрядків.
//
// Що прибрано разом зі сканером і де тепер живе та сама гарантія:
//   * `FindTagByLocalName` — ручний пропуск `</...>`, `<?...?>`, `<!--...-->`,
//     `<![CDATA[...]]>`, `<!...>`. Тепер це робить парсер: закоментований
//     `<SigReference URI="fake">` взагалі не є елементом.
//   * `ExtractAttribute` — межа тега з урахуванням лапок (С-21). Саме тут жив
//     дефект, який у двійнику (`core/policy/TrustListParser.cpp`) лишався
//     невиправленим: `xml.find('>')` обрізав тег на `>` усередині значення
//     атрибута. Регресійний тест лишається (`RunGreaterThanInsideAttributeTest`).
//   * `UnescapeXmlEntities` + `AppendUtf8FromCodePoint` — ручне розкодування
//     `&amp;`/`&#38;`/`&#x2D;` у значеннях атрибутів (С-21). libxml2 розкодовує
//     символьні посилання сам; регресійні тести на числові та іменовані entity
//     лишаються (`RunNumericEntityValueTest`, `RunEntityEscapedValueTest`).
//   * `FindNamespaceUri` + `TagPrefix` — ручне розв'язання префікса. Тепер
//     namespace бере `node->ns->href` за правилами області видимості XML.
//
// `EscapeXmlAttribute` (ME-07) лишається: манфест ми ще й ГЕНЕРУЄМО, а
// libxml2-сериалізатор сюди не заводимо — байтовий вигляд згенерованого
// манфеста є частиною контракту round-trip.

namespace tamga::asic {

namespace {

// WP-7 (HI-01): ASiC manifest namespace (ETSI TS 102 918 / EN 319 162-1).
constexpr const char* kAsicManifestNamespace = "http://uri.etsi.org/02918/v1.2.1#";
constexpr const char* kXmlDsigNamespace = "http://www.w3.org/2000/09/xmldsig#";

// ME-07: екранує значення XML-атрибута. URI/MimeType, з яких будується
// генерований ASiC manifest, походять від імен файлів контейнера і можуть
// легітимно містити '&', лапки чи не-ASCII символи — без екранування вони
// зробили б згенерований XML невалідним або семантично неоднозначним.
// Симетрична пара до розкодування, яке тепер робить libxml2 при розборі, тож
// round-trip лишається byte-точним.
std::string EscapeXmlAttribute(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (const char ch : text) {
        switch (ch) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += ch;       break;
        }
    }
    return out;
}

}  // namespace

std::string GetMimeTypeFromFilename(const std::string& filename) {
    auto pos = filename.find_last_of('.');
    if (pos == std::string::npos) return "application/octet-stream";
    std::string ext = filename.substr(pos + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (ext == "pdf") return "application/pdf";
    if (ext == "xml") return "text/xml";
    if (ext == "txt") return "text/plain";
    if (ext == "png") return "image/png";
    if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
    if (ext == "zip") return "application/zip";
    return "application/octet-stream";
}

std::string GenerateAsicManifestXml(const std::string& sig_uri, const std::vector<AsicDataObjectRef>& data_refs) {
    // Розкладка за `en_31916201v010101.xsd` (ETSI EN 319 162-1):
    //
    //   ASiCManifestType ::= sequence { SigReference, DataObjectReference+ }
    //   SigReferenceType ::= лише атрибути URI/MimeType, без дітей
    //   DataObjectReferenceType ::= sequence { ds:DigestMethod, ds:DigestValue }
    //
    // До 2026-09-03 тут писалася власна розкладка: `DataObjectReference`
    // вкладався ВСЕРЕДИНУ `SigReference` і не мав жодного дайджесту. Наш
    // власний читач її розумів, тому дефект не проявлявся, поки контейнер не
    // потрапив до стороннього валідатора: сервіс Дії відхиляв такий файл ще на
    // розборі маніфесту («пошкоджені дані чи невірний формат»).
    std::ostringstream xml;
    xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        << "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\""
        << " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""
        << " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n"
        << "  <asic:SigReference URI=\"" << EscapeXmlAttribute(sig_uri)
        << "\" MimeType=\"application/x-pkcs7-signature\"/>\n";

    for (const auto& ref : data_refs) {
        xml << "  <asic:DataObjectReference URI=\"" << EscapeXmlAttribute(ref.uri) << "\"";
        if (!ref.mime_type.empty()) {
            xml << " MimeType=\"" << EscapeXmlAttribute(ref.mime_type) << "\"";
        }
        xml << ">\n"
            << "    <ds:DigestMethod Algorithm=\"" << EscapeXmlAttribute(ref.digest_uri) << "\"/>\n"
            // Base64 не містить символів, які треба екранувати, але проганяємо
            // через ту саму функцію: значення приходить ззовні генератора.
            << "    <ds:DigestValue>" << EscapeXmlAttribute(ref.digest_base64) << "</ds:DigestValue>\n"
            << "  </asic:DataObjectReference>\n";
    }

    xml << "</asic:ASiCManifest>";
    return xml.str();
}

// WP-7 (HI-01): манфест зіставляється за ЛОКАЛЬНОЮ назвою елемента
// (namespace-префікс довільний, у т.ч. default namespace), а namespace-URI
// кореневого `SigReference` звіряється з канонічним ASiC namespace — інакше
// маніфест відхиляється як такий, що НЕ відповідає ETSI TS 102 918/EN 319
// 162-1, навіть якщо локальні назви тегів збіглися випадково.
//
// ADR-030: розбір робить libxml2. Лапки (обидва варіанти), `>` усередині
// значення атрибута (С-21), символьні та іменовані entity, коментарі й CDATA —
// усе це тепер поведінка парсера, а не наших циклів по рядку.
//
// Порядок пошуку збережено навмисно: `DataObjectReference` збираються в
// ПОРЯДКУ ДОКУМЕНТА ПІСЛЯ першого `SigReference`, а не лише серед його дітей.
// За ETSI EN 319 162-1 вони — сусіди `SigReference` під спільним коренем
// `ASiCManifest`, і саме так їх тепер пише генератор. Вкладену розкладку
// (її Tamga писала до 2026-09-03) читач приймає далі, щоб раніше створені
// контейнери лишалися читабельними.
bool ParseAsicManifestXml(const std::string& xml, std::string& out_sig_uri, std::vector<AsicDataObjectRef>& out_data_refs) {
    out_data_refs.clear();
    out_sig_uri.clear();

    std::string parse_error;
    const auto doc = tamga::xml::ParseHardened(xml, parse_error);
    const xmlNode* root = tamga::xml::RootElement(doc);
    if (root == nullptr) {
        return false;
    }

    const xmlNode* sig_node = nullptr;
    std::vector<const xmlNode*> data_nodes;
    tamga::xml::ForEachElement(root, [&](const xmlNode* node) {
        if (sig_node == nullptr) {
            // namespace тут свідомо НЕ перевіряємо: беремо ПЕРШИЙ SigReference
            // у документі, а вже потім вимагаємо від нього канонічний ASiC
            // namespace. Інакше манфест із чужим namespace «пропускався» б до
            // наступного, схожого на потрібний, елемента.
            if (tamga::xml::MatchesElement(node, "SigReference", nullptr)) {
                sig_node = node;
            }
            return;
        }
        // А-05: namespace перевіряється ТУТ, а не покладається на побічний
        // ефект правила «рівно один data-обʼєкт» нижче за стеком.
        //
        // Доти захист працював випадково: чужий `<evil:DataObjectReference>`
        // збирався нарівні з канонічним, робив список довшим за один — і
        // контейнер відхилявся перевіркою кількості в `SessionAsicOps.ipp`.
        // Тобто відхиляла його перевірка, для цього не призначена. Щойно
        // правило «рівно один» послаблять (наприклад, під multi-file ASiC-E),
        // чужий елемент почав би визначати покриття, і причина була б
        // неочевидною. Тепер елемент із чужого namespace просто не існує для
        // читача — так само, як для `SigReference` нижче.
        if (tamga::xml::MatchesElement(node, "DataObjectReference", kAsicManifestNamespace)) {
            data_nodes.push_back(node);
        }
    });

    if (sig_node == nullptr) {
        return false;
    }
    if (!tamga::xml::MatchesElement(sig_node, "SigReference", kAsicManifestNamespace)) {
        return false;
    }
    if (!tamga::xml::GetAttribute(sig_node, "URI", out_sig_uri)) {
        return false;
    }

    for (const xmlNode* node : data_nodes) {
        std::string d_uri;
        if (!tamga::xml::GetAttribute(node, "URI", d_uri)) {
            // Збережено поведінку до ADR-030: `DataObjectReference` без
            // обов'язкового URI обриває список, а не мовчки пропускається.
            break;
        }
        std::string d_mime;
        tamga::xml::GetAttribute(node, "MimeType", d_mime);  // необов'язковий атрибут

        // Дайджест обов'язковий за схемою, але порожній у контейнерах, які
        // Tamga писала до 2026-09-03. Читач лишається сумісним із ними; чи
        // приймати такий контейнер, вирішує перевірка вище за стеком.
        std::string digest_uri;
        std::string digest_value;
        tamga::xml::ForEachElement(node, [&](const xmlNode* child) {
            if (child == node) {
                return;
            }
            if (tamga::xml::MatchesElement(child, "DigestMethod", kXmlDsigNamespace)) {
                tamga::xml::GetAttribute(child, "Algorithm", digest_uri);
            } else if (tamga::xml::MatchesElement(child, "DigestValue", kXmlDsigNamespace)) {
                digest_value = tamga::xml::NodeContent(child);
            }
        });

        out_data_refs.push_back({d_uri, d_mime, digest_uri, digest_value});
    }

    return !out_sig_uri.empty() && !out_data_refs.empty();
}

std::string GenerateOdfManifestXml(const std::vector<std::pair<std::string, std::string>>& entries) {
    // Розкладка збігається з тим, що віддає Дія: один рядок без відступів,
    // кореневий запис "/" із mime-типом самого контейнера, далі документи.
    std::ostringstream xml;
    xml << "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\" ?>"
        << "<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\">"
        << "<manifest:file-entry manifest:full-path=\"/\""
        << " manifest:media-type=\"application/vnd.etsi.asic-e+zip\"/>";
    for (const auto& entry : entries) {
        xml << "<manifest:file-entry manifest:full-path=\"" << EscapeXmlAttribute(entry.first)
            << "\" manifest:media-type=\"" << EscapeXmlAttribute(entry.second) << "\"/>";
    }
    xml << "</manifest:manifest>";
    return xml.str();
}

namespace {

// Спільна валідація для обох XAdES-пакувальників.
bool ValidateXadesContent(const AsicXadesContent& content, const char* profile, std::string& error_message) {
    if (content.filename.empty() || content.file_data.empty()) {
        error_message = std::string(profile) + " requires a non-empty document name and data";
        return false;
    }
    if (content.signature_documents.empty()) {
        error_message = std::string(profile) + " requires at least one XAdES signature";
        return false;
    }
    for (const auto& doc : content.signature_documents) {
        if (doc.empty()) {
            error_message = std::string(profile) + " received an empty XAdES signature document";
            return false;
        }
    }
    return true;
}

std::vector<std::uint8_t> ToBytes(const std::string& text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

}  // namespace

bool AsicXadesContainer::PackS(const AsicXadesContent& content,
                               std::vector<std::uint8_t>& out_container,
                               std::string& error_message) {
    if (!ValidateXadesContent(content, "ASiC-S", error_message)) {
        return false;
    }
    // EN 319 162-1 §5.2: ASiC-S несе рівно один підпис, тож ім'я файла підпису
    // не нумерується, а ODF-маніфесту в цьому профілі немає взагалі.
    if (content.signature_documents.size() != 1) {
        error_message = "ASiC-S allows exactly one signature, got " +
                        std::to_string(content.signature_documents.size());
        return false;
    }

    AsicWriter writer(AsicType::AsicS);
    if (!writer.AddFile(content.filename, content.file_data, true)) {
        error_message = "Failed to add document to ASiC-S container";
        return false;
    }
    if (!writer.AddFile("META-INF/signatures.xml", ToBytes(content.signature_documents.front()), true)) {
        error_message = "Failed to add XAdES signature to ASiC-S container";
        return false;
    }
    return writer.Finalize(out_container, error_message);
}

bool AsicXadesContainer::PackE(const AsicXadesContent& content,
                               std::vector<std::uint8_t>& out_container,
                               std::string& error_message) {
    if (!ValidateXadesContent(content, "ASiC-E", error_message)) {
        return false;
    }

    AsicWriter writer(AsicType::AsicE);
    if (!writer.AddFile(content.filename, content.file_data, true)) {
        error_message = "Failed to add document to ASiC-E container";
        return false;
    }

    const std::string manifest_xml = GenerateOdfManifestXml(
        {{content.filename, GetMimeTypeFromFilename(content.filename)}});
    if (!writer.AddFile("META-INF/manifest.xml", ToBytes(manifest_xml), true)) {
        error_message = "Failed to add ODF manifest to ASiC-E container";
        return false;
    }

    for (std::size_t i = 0; i < content.signature_documents.size(); ++i) {
        std::ostringstream name;
        name << "META-INF/signatures" << std::setfill('0') << std::setw(3) << (i + 1) << ".xml";
        if (!writer.AddFile(name.str(), ToBytes(content.signature_documents[i]), true)) {
            error_message = "Failed to add XAdES signature to ASiC-E container: " + name.str();
            return false;
        }
    }
    return writer.Finalize(out_container, error_message);
}

bool AsicSContainer::Pack(const AsicSContent& content, std::vector<std::uint8_t>& out_container, std::string& error_message) {
    if (content.filename.empty() || content.file_data.empty()) {
        error_message = "ASiC-S requires a non-empty document name and data";
        return false;
    }
    if (content.signature_data.empty()) {
        error_message = "ASiC-S requires a non-empty CAdES signature";
        return false;
    }
    if (!content.timestamp_data.empty()) {
        error_message = "ASiC-S CAdES must not carry META-INF/timestamp.tst beside "
                        "META-INF/signature.p7s; the timestamp belongs inside CAdES";
        return false;
    }
    
    AsicWriter writer(AsicType::AsicS);
    if (!writer.AddFile(content.filename, content.file_data, true)) {
        error_message = "Failed to add document to ASiC-S container";
        return false;
    }
    
    // ETSI EN 319 162-1: для ASiC-S з CAdES файл підпису зветься
    // `META-INF/signature.p7s` в ОДНИНІ. Множина (`signatures`) — це назва для
    // XAdES (`META-INF/signatures.xml`). До 2026-09-03 тут писалося
    // `signatures.p7s`, тобто гібрид, якого немає в стандарті.
    // Підтверджено довідковою реалізацією ETSI DSS: `ASiCUtils.SIGNATURE_P7S`.
    if (!writer.AddFile("META-INF/signature.p7s", content.signature_data, false)) {
        error_message = "Failed to add signature to ASiC-S container";
        return false;
    }
    
    return writer.Finalize(out_container, error_message);
}

bool AsicSContainer::Unpack(const std::vector<std::uint8_t>& container, AsicSContent& out_content, std::string& error_message) {
    AsicReader reader;
    if (!reader.LoadFromBuffer(container, error_message)) {
        return false;
    }
    
    std::string mimetype;
    if (!reader.GetMimetype(mimetype) || mimetype != "application/vnd.etsi.asic-s+zip") {
        error_message = "Invalid or missing mimetype in ASiC-S container: " + mimetype;
        return false;
    }
    
    std::vector<AsicFileEntry> entries;
    if (!reader.GetFiles(entries, error_message)) {
        return false;
    }
    
    out_content = AsicSContent{};
    // Р-1: ASiC-S за ETSI TS 102 918 §5.2 містить РІВНО ОДИН підписаний обʼєкт.
    //
    // Доти цей цикл робив `out_content.filename = entry.name` для кожного
    // документа, тобто кожен наступний ПЕРЕЗАПИСУВАВ попередній: лишався
    // останній за порядком у ZIP, підпис перевірявся проти нього, а решта
    // вмісту не була покрита жодним підписом і ніде не згадувалась. Наслідок
    // залежав від порядку записів: якщо підписаний документ ішов останнім,
    // контейнер приймався як валідний РАЗОМ із чужим файлом усередині.
    //
    // Це той самий клас, що К-01/E і П-03 — непокритий вміст їде з валідним
    // підписом. Тому тут fail-closed, а не «беремо перший».
    std::size_t data_object_count = 0;
    std::string extra_data_object;
    for (const auto& entry : entries) {
        if (entry.name == "mimetype") continue;

        if (entry.name == "META-INF/signatures.p7s" || entry.name == "META-INF/signature.p7s") {
            out_content.signature_data = entry.data;
        } else if (entry.name == "META-INF/timestamp.tst") {
            out_content.timestamp_data = entry.data;
        } else if (entry.name.rfind("META-INF/", 0) == 0) {
            continue;
        } else {
            ++data_object_count;
            if (data_object_count == 1) {
                out_content.filename = entry.name;
                out_content.file_data = entry.data;
            } else if (extra_data_object.empty()) {
                extra_data_object = entry.name;
            }
        }
    }

    if (data_object_count > 1) {
        error_message = "ASiC-S container must contain exactly one data object (ETSI TS 102 918), "
                        "found " + std::to_string(data_object_count) + ": '" +
                        out_content.filename + "', '" + extra_data_object + "'";
        return false;
    }

    // ETSI EN 319 162-1 §4.3.3.2: META-INF контейнера ASiC-S несе АБО підпис
    // (`signature.p7s`), АБО позначку часу (`timestamp.tst`) — це два різні
    // профілі, а не рівні одного. Наявність обох не має визначеного сенсу:
    // невідомо, що саме штампує токен і в якому стосунку він до підпису.
    //
    // Tamga сама створювала такі контейнери до 2026-09-03 (мітка часу лягала і
    // всередину CAdES, і окремим entry), і сторонні валідатори відхиляли їх на
    // розборі. Читач приймав їх мовчки, тож дефект не було видно з наших
    // власних перевірок. Тепер — fail-closed з обох боків.
    if (!out_content.signature_data.empty() && !out_content.timestamp_data.empty()) {
        error_message = "ASiC-S container carries both META-INF/signature.p7s and "
                        "META-INF/timestamp.tst; ETSI EN 319 162-1 clause 4.3.3.2 allows only one "
                        "of them (a CAdES-T timestamp belongs inside the signature)";
        return false;
    }
    if (out_content.filename.empty() || out_content.file_data.empty()) {
        error_message = "ASiC-S container does not contain original document";
        return false;
    }
    if (out_content.signature_data.empty()) {
        error_message = "ASiC-S container does not contain signature";
        return false;
    }
    
    return true;
}

bool AsicEContainer::Pack(const AsicEContent& content, std::vector<std::uint8_t>& out_container, std::string& error_message) {
    if (content.files.empty()) {
        error_message = "ASiC-E requires at least one document";
        return false;
    }
    if (content.signatures.empty()) {
        error_message = "ASiC-E requires at least one signature";
        return false;
    }
    
    AsicWriter writer(AsicType::AsicE);
    for (const auto& f : content.files) {
        if (!writer.AddFile(f.filename, f.data, true)) {
            error_message = "Failed to add file to ASiC-E: " + f.filename;
            return false;
        }
    }
    
    for (const auto& s : content.signatures) {
        // Маніфест має прийти ГОТОВИМ: у ASiC-E CAdES підпис обчислюється саме
        // над ним, тож зібрати його тут, уже після підпису, означало б підписати
        // не те. Порожній `manifest_xml` — помилка виклику, а не привід
        // згенерувати маніфест без дайджестів (саме так контейнер і виходив
        // невалідним до 2026-09-03).
        if (s.manifest_xml.empty()) {
            error_message = "ASiC-E signature entry has no manifest: the manifest must be built "
                            "and signed before packing (" + s.sig_filename + ")";
            return false;
        }
        const std::string& manifest_xml = s.manifest_xml;

        std::vector<std::uint8_t> manifest_data(manifest_xml.begin(), manifest_xml.end());
        // Еталонні контейнери Дії записують пару у порядку
        // `ASiCManifestNNN.xml` -> `signatureNNN.p7s` і стискають обидва
        // metadata-entry. Порядок не змінює семантику ZIP, але прибирає
        // непотрібну відмінність для суворого парсера Дії.
        if (!writer.AddFile(s.manifest_filename, manifest_data, true)) {
            error_message = "Failed to add manifest to ASiC-E: " + s.manifest_filename;
            return false;
        }
        if (!writer.AddFile(s.sig_filename, s.signature_data, true)) {
            error_message = "Failed to add signature to ASiC-E: " + s.sig_filename;
            return false;
        }
    }
    
    if (!content.timestamp_data.empty()) {
        if (!writer.AddFile("META-INF/timestamp.tst", content.timestamp_data, false)) {
            error_message = "Failed to add timestamp to ASiC-E container";
            return false;
        }
    }
    
    return writer.Finalize(out_container, error_message);
}

bool AsicEContainer::Unpack(const std::vector<std::uint8_t>& container, AsicEContent& out_content, std::string& error_message) {
    AsicReader reader;
    if (!reader.LoadFromBuffer(container, error_message)) {
        return false;
    }
    
    std::string mimetype;
    if (!reader.GetMimetype(mimetype) || mimetype != "application/vnd.etsi.asic-e+zip") {
        error_message = "Invalid or missing mimetype in ASiC-E container: " + mimetype;
        return false;
    }
    
    std::vector<AsicFileEntry> entries;
    if (!reader.GetFiles(entries, error_message)) {
        return false;
    }
    
    out_content = AsicEContent{};
    
    std::vector<AsicFileEntry> files_temp;
    std::vector<AsicFileEntry> sigs_temp;
    std::vector<AsicFileEntry> manifests_temp;
    
    for (const auto& entry : entries) {
        if (entry.name == "mimetype") continue;
        
        if (entry.name == "META-INF/timestamp.tst") {
            out_content.timestamp_data = entry.data;
        } else if (entry.name.rfind("META-INF/ASiCManifest", 0) == 0) {
            manifests_temp.push_back(entry);
        } else if (entry.name.rfind("META-INF/", 0) == 0) {
            sigs_temp.push_back(entry);
        } else {
            files_temp.push_back(entry);
        }
    }
    
    for (const auto& manifest : manifests_temp) {
        std::string xml(manifest.data.begin(), manifest.data.end());
        std::string sig_uri;
        std::vector<AsicDataObjectRef> data_refs;
        if (ParseAsicManifestXml(xml, sig_uri, data_refs)) {
            std::vector<std::uint8_t> sig_data;
            for (const auto& s : sigs_temp) {
                if (s.name == sig_uri) {
                    sig_data = s.data;
                    break;
                }
            }
            if (sig_data.empty()) {
                std::string alt_sig = sig_uri.rfind("META-INF/", 0) == 0 ? sig_uri : "META-INF/" + sig_uri;
                for (const auto& s : sigs_temp) {
                    if (s.name == alt_sig) {
                        sig_data = s.data;
                        break;
                    }
                }
            }
            
            AsicEContent::SignatureEntry se;
            se.sig_filename = sig_uri;
            se.signature_data = sig_data;
            se.manifest_filename = manifest.name;
            se.manifest_xml = xml;
            out_content.signatures.push_back(se);
        }
    }
    
    if (out_content.signatures.empty() && !sigs_temp.empty()) {
        for (const auto& s : sigs_temp) {
            AsicEContent::SignatureEntry se;
            se.sig_filename = s.name;
            se.signature_data = s.data;
            out_content.signatures.push_back(se);
        }
    }
    
    for (const auto& f : files_temp) {
        out_content.files.push_back({f.name, f.data});
    }
    
    if (out_content.files.empty()) {
        error_message = "ASiC-E container does not contain any document files";
        return false;
    }
    if (out_content.signatures.empty()) {
        error_message = "ASiC-E container does not contain any signatures";
        return false;
    }
    
    return true;
}

bool AsicEContainer::AddSignature(const std::vector<std::uint8_t>& container,
                                 const std::vector<std::uint8_t>& signature_data,
                                 const std::string& sig_filename,
                                 const std::string& manifest_filename,
                                 const std::string& manifest_xml,
                                 std::vector<std::uint8_t>& out_container,
                                 std::string& error_message) {
    AsicEContent content;
    if (!Unpack(container, content, error_message)) {
        return false;
    }
    
    for (const auto& s : content.signatures) {
        if (s.sig_filename == sig_filename || s.sig_filename == "META-INF/" + sig_filename) {
            error_message = "Signature with name " + sig_filename + " already exists in container";
            return false;
        }
    }
    
    AsicEContent::SignatureEntry se;
    se.sig_filename = sig_filename.rfind("META-INF/", 0) == 0 ? sig_filename : "META-INF/" + sig_filename;
    se.signature_data = signature_data;
    se.manifest_filename = manifest_filename.rfind("META-INF/", 0) == 0 ? manifest_filename : "META-INF/" + manifest_filename;
    se.manifest_xml = manifest_xml;
    
    content.signatures.push_back(se);
    return Pack(content, out_container, error_message);
}

} // namespace tamga::asic
