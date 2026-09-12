#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <utility>

namespace tamga::asic {

struct AsicSContent {
    std::string filename;
    std::vector<std::uint8_t> file_data;
    std::vector<std::uint8_t> signature_data;
    std::vector<std::uint8_t> timestamp_data; // optional
};

struct AsicEContent {
    struct FileEntry {
        std::string filename;
        std::vector<std::uint8_t> data;
    };
    std::vector<FileEntry> files;
    
    struct SignatureEntry {
        std::string sig_filename;
        std::vector<std::uint8_t> signature_data;
        std::string manifest_filename;
        std::string manifest_xml;
    };
    std::vector<SignatureEntry> signatures;
    
    std::vector<std::uint8_t> timestamp_data; // optional
};

class AsicSContainer final {
public:
    static bool Pack(const AsicSContent& content, std::vector<std::uint8_t>& out_container, std::string& error_message);
    static bool Unpack(const std::vector<std::uint8_t>& container, AsicSContent& out_content, std::string& error_message);
};

class AsicEContainer final {
public:
    static bool Pack(const AsicEContent& content, std::vector<std::uint8_t>& out_container, std::string& error_message);
    static bool Unpack(const std::vector<std::uint8_t>& container, AsicEContent& out_content, std::string& error_message);
    static bool AddSignature(const std::vector<std::uint8_t>& container,
                             const std::vector<std::uint8_t>& signature_data,
                             const std::string& sig_filename,
                             const std::string& manifest_filename,
                             const std::string& manifest_xml,
                             std::vector<std::uint8_t>& out_container,
                             std::string& error_message);
};

// Один `DataObjectReference` маніфесту ASiC-E.
//
// `digest_uri` і `digest_base64` за схемою ETSI EN 319 162-1 ОБОВ'ЯЗКОВІ:
// саме вони зв'язують дані з підписом. До 2026-09-03 генератор Tamga їх не
// писав узагалі, тож сторонні валідатори (зокрема сервіс Дії) відхиляли
// контейнер ще на розборі маніфесту.
struct AsicDataObjectRef {
    std::string uri;
    std::string mime_type;
    std::string digest_uri;     // напр. http://www.w3.org/2001/04/xmldsig-more#gost34311
    std::string digest_base64;  // порожній лише в контейнерах старого формату

    friend bool operator==(const AsicDataObjectRef& lhs, const AsicDataObjectRef& rhs) {
        return lhs.uri == rhs.uri && lhs.mime_type == rhs.mime_type &&
               lhs.digest_uri == rhs.digest_uri && lhs.digest_base64 == rhs.digest_base64;
    }
    friend bool operator!=(const AsicDataObjectRef& lhs, const AsicDataObjectRef& rhs) {
        return !(lhs == rhs);
    }
};

// Один підписаний документ у XAdES-розкладці ASiC.
//
// У досліджених еталонах Дії ця розкладка зберігає підпис у
// `META-INF/signatures*.xml`. ETSI EN 319 162-1 дозволяє також CAdES-розкладку;
// обидва варіанти мають окремі шляхи створення та перевірки.
struct AsicXadesContent {
    std::string filename;                 // ім'я документа всередині контейнера
    std::vector<std::uint8_t> file_data;
    // Кожен елемент — цілий документ `asic:XAdESSignatures`. ASiC-S допускає
    // рівно один підпис, ASiC-E — кілька.
    std::vector<std::string> signature_documents;
};

class AsicXadesContainer final {
public:
    // ASiC-S: `mimetype`, документ, `META-INF/signatures.xml` (однина, без
    // нумерації і без ODF-маніфесту — EN 319 162-1 §5.2).
    static bool PackS(const AsicXadesContent& content,
                      std::vector<std::uint8_t>& out_container,
                      std::string& error_message);

    // ASiC-E: `mimetype`, документ, `META-INF/manifest.xml` (ODF) і
    // `META-INF/signatures001.xml`, `...002.xml` — тобто те, що віддає Дія.
    static bool PackE(const AsicXadesContent& content,
                      std::vector<std::uint8_t>& out_container,
                      std::string& error_message);
};

// Helper utilities
std::string GetMimeTypeFromFilename(const std::string& filename);

// OASIS ODF-маніфест `META-INF/manifest.xml` для ASiC-E XAdES: кореневий запис
// `/` з mime-типом контейнера плюс по запису на кожен документ. Це НЕ
// `ASiCManifest.xml` — той належить CAdES-розкладці й несе дайджести, тоді як
// цей лише перелічує вміст.
std::string GenerateOdfManifestXml(const std::vector<std::pair<std::string, std::string>>& entries);

// Формує маніфест за схемою `en_31916201v010101.xsd`:
//
//   ASiCManifest
//     SigReference           (порожній елемент, лише атрибути)
//     DataObjectReference+   (кожен із ds:DigestMethod і ds:DigestValue)
//
// `SigReference` і `DataObjectReference` — СУСІДИ в `xsd:sequence`, а не
// вкладені один в одного.
std::string GenerateAsicManifestXml(const std::string& sig_uri, const std::vector<AsicDataObjectRef>& data_refs);

// Читає маніфест. Приймає і канонічну розкладку, і історичну «вкладену», яку
// Tamga писала до 2026-09-03: контейнери, підписані старими версіями, мають
// лишатися читабельними. Порожні `digest_*` означають саме такий старий
// маніфест.
bool ParseAsicManifestXml(const std::string& xml, std::string& out_sig_uri, std::vector<AsicDataObjectRef>& out_data_refs);

} // namespace tamga::asic
