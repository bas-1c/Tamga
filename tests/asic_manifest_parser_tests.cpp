// WP-7 (HI-01) regression suite — ASiC manifest parsing hardening.
//
// tamga::asic::ParseAsicManifestXml previously matched only a hardcoded
// `<asic:SigReference`/`<asic:DataObjectReference` tag spelling and
// double-quoted `URI="..."` attributes. That gives a false negative for any
// other legitimate namespace prefix (or default namespace), single-quoted
// attributes, or XML-escaped attribute values, and a false positive for a
// document that merely reuses the same local tag names under an unrelated
// namespace. This suite exercises all of those cases directly against the
// pure parsing function, а також ZIP-розкладку публічних XAdES-пакувальників
// (без криптографії).
//
// Returns: 0 = all checks passed; 1 = regression.

#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "asic/AsicContainers.h"
#include "asic/AsicReader.h"

namespace {

bool Require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        return false;
    }
    return true;
}

std::uint16_t ReadLe16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(bytes[offset]) |
           (static_cast<std::uint16_t>(bytes[offset + 1]) << 8u);
}

std::uint32_t ReadLe32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8u) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16u) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24u);
}

bool VerifyDiiaCompatibleLocalHeaders(const std::vector<std::uint8_t>& zip,
                                      const char* profile,
                                      std::uint32_t expected_mimetype_crc) {
    const auto fail = [profile](const std::string& message) {
        std::cerr << "FAILED [" << profile << "]: " << message << '\n';
        return false;
    };
    if (zip.size() < 22) {
        return fail("ZIP is shorter than EOCD");
    }

    std::size_t eocd = zip.size();
    for (std::size_t pos = zip.size() - 22;; --pos) {
        if (ReadLe32(zip, pos) == 0x06054B50u) {
            eocd = pos;
            break;
        }
        if (pos == 0) {
            break;
        }
    }
    if (eocd == zip.size()) {
        return fail("EOCD was not found");
    }

    const auto entry_count = ReadLe16(zip, eocd + 10);
    std::size_t central_offset = ReadLe32(zip, eocd + 16);
    bool saw_mimetype = false;
    bool saw_deflated_metadata = false;

    for (std::uint16_t index = 0; index < entry_count; ++index) {
        if (central_offset + 46 > zip.size() || ReadLe32(zip, central_offset) != 0x02014B50u) {
            return fail("central-directory entry is malformed");
        }
        const auto method = ReadLe16(zip, central_offset + 10);
        const auto crc = ReadLe32(zip, central_offset + 16);
        const auto compressed_size = ReadLe32(zip, central_offset + 20);
        const auto uncompressed_size = ReadLe32(zip, central_offset + 24);
        const auto name_length = ReadLe16(zip, central_offset + 28);
        const auto extra_length = ReadLe16(zip, central_offset + 30);
        const auto comment_length = ReadLe16(zip, central_offset + 32);
        const auto local_offset = static_cast<std::size_t>(ReadLe32(zip, central_offset + 42));
        if (central_offset + 46u + name_length + extra_length + comment_length > zip.size()) {
            return fail("central-directory entry exceeds archive bounds");
        }
        const std::string name(reinterpret_cast<const char*>(zip.data() + central_offset + 46), name_length);

        if (local_offset + 30 > zip.size() || ReadLe32(zip, local_offset) != 0x04034B50u) {
            return fail("local-file header is malformed for " + name);
        }
        const auto local_flags = ReadLe16(zip, local_offset + 6);
        const auto local_method = ReadLe16(zip, local_offset + 8);
        const auto local_crc = ReadLe32(zip, local_offset + 14);
        const auto local_compressed_size = ReadLe32(zip, local_offset + 18);
        const auto local_uncompressed_size = ReadLe32(zip, local_offset + 22);

        if (method == 0) {
            if ((local_flags & 0x0008u) != 0) {
                return fail("stored entry uses a data descriptor: " + name);
            }
            if (local_method != method || local_crc != crc ||
                local_compressed_size != compressed_size ||
                local_uncompressed_size != uncompressed_size) {
                return fail("stored entry lacks final CRC/sizes in its local header: " + name);
            }
        }
        if (name.rfind("META-INF/", 0) == 0) {
            saw_deflated_metadata = saw_deflated_metadata || method == 8;
            if ((local_flags & 0x0008u) != 0 || local_method != method ||
                local_crc != crc || local_compressed_size != compressed_size ||
                local_uncompressed_size != uncompressed_size) {
                return fail("META-INF entry lacks final CRC/sizes in its local header: " + name);
            }
        }

        if (name == "mimetype") {
            saw_mimetype = true;
            if (local_offset != 0 || method != 0 || ReadLe16(zip, local_offset + 28) != 0 ||
                uncompressed_size != 31 || crc != expected_mimetype_crc) {
                return fail("mimetype does not satisfy the ETSI first-entry invariant");
            }
        }

        central_offset += 46u + name_length + extra_length + comment_length;
    }

    return Require(saw_mimetype, std::string(profile) + ": mimetype entry must exist") &&
           Require(saw_deflated_metadata,
                   std::string(profile) + ": META-INF XML must match Diia DEFLATE layout");
}

bool RunXadesZipLocalHeaderInteropTest() {
    tamga::asic::AsicXadesContent content;
    content.filename = "document.pdf";
    content.file_data.assign(512, static_cast<std::uint8_t>('A'));
    content.signature_documents = {
        "<?xml version=\"1.0\"?><asic:XAdESSignatures "
        "xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\"/>"
    };

    std::vector<std::uint8_t> asics;
    std::string error;
    if (!Require(tamga::asic::AsicXadesContainer::PackS(content, asics, error),
                 "ASiC-S XAdES packing must succeed")) {
        std::cerr << error << '\n';
        return false;
    }
    if (!VerifyDiiaCompatibleLocalHeaders(asics, "ASiC-S", 0xAA5943A8u)) {
        return false;
    }

    std::vector<std::uint8_t> asice;
    if (!Require(tamga::asic::AsicXadesContainer::PackE(content, asice, error),
                 "ASiC-E XAdES packing must succeed")) {
        std::cerr << error << '\n';
        return false;
    }
    return VerifyDiiaCompatibleLocalHeaders(asice, "ASiC-E", 0x45F9218Au);
}

bool RunCadesZipLayoutInteropTest() {
    tamga::asic::AsicEContent content;
    content.files.push_back({"document.pdf", std::vector<std::uint8_t>(512, 'A')});

    tamga::asic::AsicEContent::SignatureEntry signature;
    signature.sig_filename = "META-INF/signature001.p7s";
    signature.signature_data.assign(512, static_cast<std::uint8_t>('B'));
    signature.manifest_filename = "META-INF/ASiCManifest001.xml";
    signature.manifest_xml = tamga::asic::GenerateAsicManifestXml(
        signature.sig_filename,
        {{"document.pdf", "application/pdf",
          "http://www.w3.org/2001/04/xmlenc#dstu7564-256", "YWJjZGVm"}});
    content.signatures.push_back(signature);

    std::vector<std::uint8_t> asice;
    std::string error;
    if (!Require(tamga::asic::AsicEContainer::Pack(content, asice, error),
                 "ASiC-E CAdES packing must succeed")) {
        std::cerr << error << '\n';
        return false;
    }
    if (!VerifyDiiaCompatibleLocalHeaders(asice, "ASiC-E CAdES", 0x45F9218Au)) {
        return false;
    }

    tamga::asic::AsicReader reader;
    std::vector<tamga::asic::AsicFileEntry> entries;
    if (!Require(reader.LoadFromBuffer(asice, error) && reader.GetFiles(entries, error),
                 "ASiC-E CAdES container must be readable")) {
        std::cerr << error << '\n';
        return false;
    }
    const std::vector<std::string> expected_names{
        "mimetype", "document.pdf", "META-INF/ASiCManifest001.xml",
        "META-INF/signature001.p7s"};
    if (!Require(entries.size() == expected_names.size(),
                 "ASiC-E CAdES must contain exactly the Diia-profile entries")) {
        return false;
    }
    for (std::size_t i = 0; i < expected_names.size(); ++i) {
        if (!Require(entries[i].name == expected_names[i],
                     "ASiC-E CAdES entry order must be payload, manifest, signature")) {
            return false;
        }
    }
    const std::string manifest(entries[2].data.begin(), entries[2].data.end());
    return Require(manifest.find("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"") !=
                       std::string::npos,
                   "ASiC-E CAdES manifest must declare xsi like the Diia reference") &&
           Require(manifest.find("URI=\"META-INF/signature001.p7s\" "
                                 "MimeType=\"application/x-pkcs7-signature\"") !=
                       std::string::npos,
                   "ASiC-E CAdES SigReference must target the numbered signature") &&
           Require(manifest.find("http://www.w3.org/2001/04/xmlenc#dstu7564-256") !=
                       std::string::npos,
                   "ASiC-E CAdES DataObjectReference must declare Kupyna-256");
}

bool RunRoundTripTest() {
    // Digest-поля порожні свідомо: перевіряється round-trip маніфеста старого
    // формату, без DigestMethod/DigestValue. Записані явно, бо GCC із
    // `-Wextra -Werror` відхиляє агрегатну ініціалізацію з пропущеними членами.
    const std::vector<tamga::asic::AsicDataObjectRef> refs = {
        {"document.pdf", "application/pdf", /*digest_uri=*/"", /*digest_base64=*/""},
        {"data.xml", "text/xml", /*digest_uri=*/"", /*digest_base64=*/""},
    };
    const std::string xml = tamga::asic::GenerateAsicManifestXml("META-INF/signature1.p7s", refs);

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> parsed_refs;
    if (!Require(tamga::asic::ParseAsicManifestXml(xml, sig_uri, parsed_refs), "Round-trip manifest must parse")) {
        return false;
    }
    if (!Require(sig_uri == "META-INF/signature1.p7s", "Round-trip sig_uri must match")) {
        return false;
    }
    return Require(parsed_refs == refs, "Round-trip data refs must match");
}

bool RunAlternatePrefixTest() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<a:ASiCManifest xmlns:a=\"http://uri.etsi.org/02918/v1.2.1#\">\n"
        "  <a:SigReference URI=\"META-INF/signature1.p7s\" MimeType=\"application/pkcs7-signature\">\n"
        "    <a:DataObjectReference URI=\"document.pdf\" MimeType=\"application/pdf\"/>\n"
        "  </a:SigReference>\n"
        "</a:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    if (!Require(tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs),
                 "Manifest with a non-'asic' namespace prefix must still parse")) {
        return false;
    }
    return Require(sig_uri == "META-INF/signature1.p7s", "sig_uri must match with alternate prefix");
}

bool RunDefaultNamespaceTest() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<ASiCManifest xmlns=\"http://uri.etsi.org/02918/v1.2.1#\">\n"
        "  <SigReference URI=\"META-INF/signature1.p7s\">\n"
        "    <DataObjectReference URI=\"document.pdf\" MimeType=\"application/pdf\"/>\n"
        "  </SigReference>\n"
        "</ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    if (!Require(tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs),
                 "Manifest using the default (unprefixed) namespace must still parse")) {
        return false;
    }
    return Require(sig_uri == "META-INF/signature1.p7s", "sig_uri must match with default namespace");
}

bool RunSingleQuotedAttributesTest() {
    const std::string xml =
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<asic:ASiCManifest xmlns:asic='http://uri.etsi.org/02918/v1.2.1#'>\n"
        "  <asic:SigReference URI='META-INF/signature1.p7s'>\n"
        "    <asic:DataObjectReference URI='document.pdf' MimeType='application/pdf'/>\n"
        "  </asic:SigReference>\n"
        "</asic:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    if (!Require(tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs),
                 "Manifest with single-quoted attributes must still parse")) {
        return false;
    }
    return Require(sig_uri == "META-INF/signature1.p7s", "sig_uri must match with single-quoted attributes");
}

// С-21: '>' усередині значення атрибута — валідний XML. Раніше межа тега
// шукалася як xml.find('>'), тож тег обрізався достроково і атрибути після
// такого значення губилися. Це вирішує, який data-object вважається
// підписаним, тож розбіжність із канонічним парсером тут не нешкідлива.
bool RunGreaterThanInsideAttributeTest() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\">\n"
        "  <asic:SigReference URI=\"META-INF/signature1.p7s\">\n"
        "    <asic:DataObjectReference URI=\"a>b.pdf\" MimeType=\"application/pdf\"/>\n"
        "  </asic:SigReference>\n"
        "</asic:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    if (!Require(tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs),
                 "Manifest with '>' inside an attribute value must parse")) {
        return false;
    }
    if (!Require(refs.size() == 1 && refs[0].uri == "a>b.pdf" &&
                     refs[0].mime_type == "application/pdf",
                 "attributes after a '>' inside a quoted value must still be read")) {
        std::cerr << "got: " << (refs.empty() ? "<none>" : refs[0].uri) << '\n';
        return false;
    }
    return true;
}

// С-21: числові entity раніше лишалися сирим текстом, тож URI у числовій
// формі не збігався з іменем файлу в контейнері.
bool RunNumericEntityValueTest() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\">\n"
        "  <asic:SigReference URI=\"META-INF/signature1.p7s\">\n"
        "    <asic:DataObjectReference URI=\"file&#38;name&#x2D;1.pdf\" MimeType=\"application/pdf\"/>\n"
        "  </asic:SigReference>\n"
        "</asic:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    if (!Require(tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs),
                 "Manifest with numeric entities must parse")) {
        return false;
    }
    if (!Require(refs.size() == 1 && refs[0].uri == "file&name-1.pdf",
                 "numeric entities must be decoded")) {
        std::cerr << "got: " << (refs.empty() ? "<none>" : refs[0].uri) << '\n';
        return false;
    }
    return true;
}

bool RunEntityEscapedValueTest() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\">\n"
        "  <asic:SigReference URI=\"META-INF/signature1.p7s\">\n"
        "    <asic:DataObjectReference URI=\"file&amp;name.pdf\" MimeType=\"application/pdf\"/>\n"
        "  </asic:SigReference>\n"
        "</asic:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    if (!Require(tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs),
                 "Manifest with an XML-escaped attribute value must parse")) {
        return false;
    }
    if (!Require(refs.size() == 1 && refs[0].uri == "file&name.pdf",
                 "Escaped '&amp;' in DataObjectReference URI must be decoded to '&'")) {
        std::cerr << "got: " << (refs.empty() ? "<none>" : refs[0].uri) << '\n';
        return false;
    }
    return true;
}

// ME-07: GenerateAsicManifestXml previously interpolated URI/MimeType values
// (which come from container filenames) straight into XML attributes without
// escaping. A filename containing '&', a raw '"' or non-ASCII characters
// produced a malformed or ambiguous manifest -- a literal '"' in particular
// terminates the attribute value early and corrupts the surrounding markup.
bool RunGeneratedManifestEscapesSpecialCharactersTest() {
    const std::string original_uri = "рахунок & акт \"фінал\".pdf";
    // Тут перевіряється екранування URI, а не дайджести — поля порожні свідомо.
    const std::vector<tamga::asic::AsicDataObjectRef> refs = {
        {original_uri, "application/pdf", /*digest_uri=*/"", /*digest_base64=*/""},
    };
    const std::string xml = tamga::asic::GenerateAsicManifestXml("META-INF/signature1.p7s", refs);

    if (!Require(xml.find("акт \"фінал\"") == std::string::npos,
                 "Generated manifest must not embed a raw unescaped '\"' inside an attribute value")) {
        return false;
    }

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> parsed_refs;
    if (!Require(tamga::asic::ParseAsicManifestXml(xml, sig_uri, parsed_refs),
                 "Generated manifest with special characters in the filename must still parse")) {
        return false;
    }
    return Require(parsed_refs.size() == 1 && parsed_refs[0].uri == original_uri,
                   "Round-tripped URI with '&', '\"' and non-ASCII characters must match the original exactly");
}

bool RunWrongNamespaceRejectedTest() {
    // Тег-назви ЗБІГАЮТЬСЯ з очікуваними ("asic:SigReference"), але префікс
    // прив'язаний до ІНШОГО namespace -- це не легітимний ASiC manifest,
    // хоч би що там локально називалося так само.
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<asic:ASiCManifest xmlns:asic=\"http://example.com/not-asic#\">\n"
        "  <asic:SigReference URI=\"META-INF/signature1.p7s\">\n"
        "    <asic:DataObjectReference URI=\"document.pdf\" MimeType=\"application/pdf\"/>\n"
        "  </asic:SigReference>\n"
        "</asic:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    return Require(!tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs),
                   "Manifest whose 'asic' prefix is bound to a foreign namespace must be rejected");
}

bool RunMissingNamespaceDeclarationRejectedTest() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<asic:ASiCManifest>\n"
        "  <asic:SigReference URI=\"META-INF/signature1.p7s\">\n"
        "    <asic:DataObjectReference URI=\"document.pdf\" MimeType=\"application/pdf\"/>\n"
        "  </asic:SigReference>\n"
        "</asic:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    return Require(!tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs),
                   "Manifest with no xmlns:asic declaration at all must be rejected");
}

// Гарантує, що закоментований (fake) SigReference НЕ приймається за
// активний елемент, а реальний, наступний за ним, парситься коректно.
bool RunCommentBypassRejectedTest() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\">\n"
        "  <!-- <asic:SigReference URI=\"fake-signature.p7s\">\n"
        "         <asic:DataObjectReference URI=\"fake-document.pdf\"/>\n"
        "       </asic:SigReference> -->\n"
        "  <asic:SigReference URI=\"META-INF/signature1.p7s\">\n"
        "    <asic:DataObjectReference URI=\"document.pdf\" MimeType=\"application/pdf\"/>\n"
        "  </asic:SigReference>\n"
        "</asic:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    if (!Require(tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs),
                 "Manifest with a commented-out SigReference must still parse the real one")) {
        return false;
    }
    if (!Require(sig_uri == "META-INF/signature1.p7s",
                 "Must parse the real signature URI, not the commented-out fake one")) {
        return false;
    }
    return Require(refs.size() == 1 && refs[0].uri == "document.pdf",
                   "Must parse the real data reference, not the commented-out fake one");
}

// Якщо ЄДИНИЙ SigReference закоментований (немає жодного активного), манфест
// має бути відхилений, а не хибно "успішно" розібраний з фейковими даними.
bool RunCommentedOnlySigReferenceRejectedTest() {
    const std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\">\n"
        "  <!-- <asic:SigReference URI=\"fake-signature.p7s\">\n"
        "         <asic:DataObjectReference URI=\"fake-document.pdf\"/>\n"
        "       </asic:SigReference> -->\n"
        "</asic:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    return Require(!tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs),
                   "Manifest with only a commented-out SigReference must be rejected");
}

// ADR-030: XXE. Манфест приходить із недовіреного ZIP-контейнера, тож DTD і
// зовнішні сутності мають бути закриті ПОВНІСТЮ.
bool RunDtdAndExternalEntityRejectedTest() {
    const std::string external_entity =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE ASiCManifest [\n"
        "  <!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">\n"
        "]>\n"
        "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\">\n"
        "  <asic:SigReference URI=\"META-INF/signature1.p7s\">\n"
        "    <asic:DataObjectReference URI=\"&xxe;\" MimeType=\"application/pdf\"/>\n"
        "  </asic:SigReference>\n"
        "</asic:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    if (!Require(!tamga::asic::ParseAsicManifestXml(external_entity, sig_uri, refs),
                 "Manifest declaring an external entity must be rejected outright")) {
        return false;
    }
    return Require(refs.empty() && sig_uri.empty(),
                   "Nothing may be extracted from a rejected DTD-bearing manifest");
}

// ADR-030: глибоке вкладення не має ставати переповненням стека. Межу тримає
// сам парсер (XML_PARSE_HUGE не задано), а обхід дерева в XmlCore —
// ітеративний. Тест доводить, що вхід відхиляється або розбирається, але
// процес не падає.
bool RunDeeplyNestedManifestDoesNotCrashTest() {
    const std::size_t depth = 5000;
    std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\">\n";
    for (std::size_t i = 0; i < depth; ++i) {
        xml += "<asic:Nested>";
    }
    xml += "<asic:SigReference URI=\"META-INF/signature1.p7s\">"
           "<asic:DataObjectReference URI=\"document.pdf\"/>"
           "</asic:SigReference>";
    for (std::size_t i = 0; i < depth; ++i) {
        xml += "</asic:Nested>";
    }
    xml += "\n</asic:ASiCManifest>";

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> refs;
    // Результат тут не є контрактом — контракт у тому, що виклик ПОВЕРТАЄТЬСЯ.
    (void)tamga::asic::ParseAsicManifestXml(xml, sig_uri, refs);
    return Require(true, "Deeply nested manifest must return instead of overflowing the stack");
}

}  // namespace

// Регресія 2026-09-03: генератор писав власну розкладку — `DataObjectReference`
// ВСЕРЕДИНІ `SigReference` і без жодного дайджесту. Наш читач її розумів, тому
// дефект не проявлявся, поки контейнер не потрапив до стороннього валідатора:
// сервіс Дії відхиляв такий ASiC-E ще на розборі маніфесту.
//
// Тест закріплює форму за `en_31916201v010101.xsd`:
//   ASiCManifestType ::= sequence { SigReference, DataObjectReference+ }
//   SigReferenceType ::= лише атрибути, без дітей
//   DataObjectReferenceType ::= sequence { ds:DigestMethod, ds:DigestValue }
bool RunGeneratedManifestMatchesEtsiSchemaTest() {
    const std::vector<tamga::asic::AsicDataObjectRef> refs = {
        {"document.pdf", "application/pdf",
         "http://www.w3.org/2001/04/xmldsig-more#gost34311", "YWJjZGVm"},
    };
    const std::string xml = tamga::asic::GenerateAsicManifestXml("META-INF/signature.p7s", refs);

    // `SigReference` — порожній елемент. Відкритий тег із дітьми означав би
    // повернення старої, невалідної розкладки.
    if (!Require(xml.find("<asic:SigReference URI=\"META-INF/signature.p7s\" "
                          "MimeType=\"application/x-pkcs7-signature\"/>") != std::string::npos,
                 "SigReference must be an empty element")) {
        std::cerr << xml << "\n";
        return false;
    }
    if (!Require(xml.find("</asic:SigReference>") == std::string::npos,
                 "SigReference must not wrap DataObjectReference")) {
        return false;
    }
    if (!Require(xml.find("<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/"
                          "xmldsig-more#gost34311\"/>") != std::string::npos,
                 "DataObjectReference must carry ds:DigestMethod")) {
        return false;
    }
    if (!Require(xml.find("<ds:DigestValue>YWJjZGVm</ds:DigestValue>") != std::string::npos,
                 "DataObjectReference must carry ds:DigestValue")) {
        return false;
    }

    // Round-trip: дайджест має читатися назад без втрат.
    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> parsed;
    if (!Require(tamga::asic::ParseAsicManifestXml(xml, sig_uri, parsed) && parsed.size() == 1,
                 "Schema-conforming manifest must parse back")) {
        return false;
    }
    return Require(parsed[0] == refs[0], "Digest must survive the round-trip");
}

int main() {
    bool ok = true;
    ok = RunXadesZipLocalHeaderInteropTest() && ok;
    ok = RunCadesZipLayoutInteropTest() && ok;
    ok = RunRoundTripTest() && ok;
    ok = RunGeneratedManifestMatchesEtsiSchemaTest() && ok;
    ok = RunAlternatePrefixTest() && ok;
    ok = RunDefaultNamespaceTest() && ok;
    ok = RunSingleQuotedAttributesTest() && ok;
    ok = RunEntityEscapedValueTest() && ok;
    ok = RunGreaterThanInsideAttributeTest() && ok;
    ok = RunNumericEntityValueTest() && ok;
    ok = RunGeneratedManifestEscapesSpecialCharactersTest() && ok;
    ok = RunWrongNamespaceRejectedTest() && ok;
    ok = RunMissingNamespaceDeclarationRejectedTest() && ok;
    ok = RunCommentBypassRejectedTest() && ok;
    ok = RunCommentedOnlySigReferenceRejectedTest() && ok;
    ok = RunDtdAndExternalEntityRejectedTest() && ok;
    ok = RunDeeplyNestedManifestDoesNotCrashTest() && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
