#include "support/FixturePaths.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "types.h"
#include "IMemoryManager.h"
#include "asic/AsicReader.h"
#include "asic/AsicWriter.h"
#include "asic/AsicContainers.h"
#include "miniz.h"
#include "core/Errors.h"
#include "core/HttpClient.h"
#include "core/KeyParsers.h"
#include "core/net/CaSettingsRegistry.h"
#include "core/net/CertificateFetcher.h"
#include "core/net/CertificateResolver.h"
#include "core/Session.h"
#include "tamga/tamga_c_api.h"
#include "core/TspClient.h"
#include "core/policy/AiaIssuerFetcher.h"
#include "core/policy/CertificateChainValidator.h"
#include "core/policy/CrlValidator.h"
#include "core/policy/CrlCache.h"
#include "core/policy/ImprintDigest.h"
#include "core/policy/OcspValidator.h"
#include "core/policy/PolicyCache.h"
#include "core/policy/TimestampValidator.h"
#include "core/policy/TlXmlSigCheck.h"
#include "core/policy/TrustListParser.h"
#include "core/policy/TrustListSettings.h"
#include "core/policy/TrustListSync.h"
#include "core/policy/Sha256Helper.h"
#include "core/policy/UserReportBuilder.h"
#include "core/session/VerifySummary.h"
#include "core/validation/EvidenceStore.h"
#include "core/validation/PathEngine.h"
#include "core/validation/PolicyResolver.h"
#include "core/validation/SigningTimeResolver.h"
#include "core/validation/ValidationReportJson.h"
#include "core/validation/ValidationReportProjection.h"
#include "core/validation/TrustServiceEvaluator.h"
#include "core/validation/RevocationEngine.h"
#include "core/validation/TimestampEngine.h"
#include "core/validation/ValidationEngine.h"
#include "core/CryptoniteAdapter.h"
#include "core/policy/ImprintDigest.h"
#include "nativeapi/TamgaAddIn.h"
#include "util/AsicUri.h"
#include "util/Base64.h"
#include "util/Utf.h"
#include "nativeapi/VariantUtils.h"

// Phase 0 (ADR 012): стаб-заголовки форматних підсистем XMLDSIG/XAdES/PAdES.
// Включення тут дає compile-smoke у проєктному тулчейні — заголовки мають
// парситися й бути взаємно консистентними, поки .cpp зʼявляться у фазах 1-6.
#include "core/SignatureRequest.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/XmlTransformEngine.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSecContext.h"
#include "xmldsig/XmlSignatureBuilder.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xades/XadesTypes.h"
#include "xades/XadesBuilder.h"
#include "xades/XadesVerifier.h"
#include "pades/PdfTypes.h"
#include "pades/PdfParser.h"
#include "pades/PdfByteRange.h"
#include "pades/PadesBuilder.h"
#include "pades/PadesVerifier.h"

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "aid.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "cert_engine.h"
#include "certificate_request_engine.h"
#include "crl.h"
#include "crl_engine.h"
#include "cryptonite_manager.h"
#include "digest_adapter.h"
#include "dstu4145.h"
#include "dstu7564.h"
#include "ext.h"
#include "gost28147.h"
#include "oids.h"
#include "ocsp_response.h"
#include "ocsp_response_engine.h"
#include "pkcs12.h"
#include "pkcs8.h"
#include "sign_adapter.h"
#include "spki.h"
#include "verify_adapter.h"
#include "content_info.h"
#include "signed_data.h"
#include "CertificateSerialNumber.h"
#include "RevokedCertificate.h"
#include "TSTInfo.h"
#include "signed_data_engine.h"
#include "signer_info_engine.h"
#include "signer_info.h"
#include "CertificateSet.h"
#include "SignerIdentifier.h"
#include "pkix_utils.h"
#include "tsp_request.h"
#include "tsp_response.h"
#include "tsp_request_engine.h"
#include "tsp_response_engine.h"
#include "adapters_map.h"
#include "DigestAlgorithmIdentifiers.h"
#include "MessageImprint.h"
#include "AlgorithmIdentifier.h"
#if defined(_WIN32)
#include "dirent_internal.h"
#endif
}
#endif

#include "support/TestSupport.h"

// Хвиля 8, п.5: шар підтримки тестів, винесений із моноліту
// `tamga_tests.cpp`. Включення успадковані від нього без змін: це
// тестова інфраструктура, і звужувати їх окремим кроком безпечніше,
// ніж разом із переносом.
namespace tamga_tests {


int g_failures = 0;

// С-16: пропущений тест раніше просто друкував [SKIP] і мовчки повертався —
// CTest бачив Passed. Механізму, який зафіксував би ЗРОСТАННЯ кількості
// пропусків, не існувало, тож втрата фікстури або зміна умови тихо вимкнула б
// будь-який із перевіряних шляхів, а сюїта лишалася б зеленою. Саме від цього
// застерігає skill репозиторію: зелений CTest сам по собі не є доказом.
//
// Baseline — кількість пропусків, яка вважається відомою і прийнятною. Її
// перевищення робить прогін невдалим: не тому, що пропуск — помилка, а тому,
// що НЕПОМІЧЕНИЙ пропуск нею стає.
//
// Значення — це ФАКТИЧНИЙ максимум по конфігураціях, виміряний, а не кількість
// місць виклику RecordSkip (їх 41 — таке значення робило б гейт декоративним):
//   конфігурація постачання — 1 (відсутня фікстура rahunok.pdf.sig);
//   базова (без XML/PDF)    — 1;
//   діагностична vendor=OFF — 6 (сюїти, що вимагають cryptonite).
// Підвищувати це число можна лише свідомо й разом із поясненням, ЯКИЙ шлях
// перестав виконуватись.
int g_skips = 0;
// kExpectedMaxSkips визначено в TestSupport.h (inline constexpr).

void RecordSkip(const std::string& reason) {
    ++g_skips;
    std::cerr << "  [SKIP] " << reason << "\n";
}

bool Contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

bool IsValidJson(const std::string& input) {
    class Parser final {
    public:
        explicit Parser(const std::string& text) : text_(text) {}

        bool Parse() {
            SkipWhitespace();
            if (!ParseValue()) {
                return false;
            }
            SkipWhitespace();
            return pos_ == text_.size();
        }

    private:
        void SkipWhitespace() {
            while (pos_ < text_.size()) {
                const char ch = text_[pos_];
                if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
                    break;
                }
                ++pos_;
            }
        }

        bool Consume(const char expected) {
            SkipWhitespace();
            if (pos_ >= text_.size() || text_[pos_] != expected) {
                return false;
            }
            ++pos_;
            return true;
        }

        bool ParseValue() {
            SkipWhitespace();
            if (pos_ >= text_.size()) {
                return false;
            }
            switch (text_[pos_]) {
                case '{': return ParseObject();
                case '[': return ParseArray();
                case '"': return ParseString();
                case 't': return ParseLiteral("true");
                case 'f': return ParseLiteral("false");
                case 'n': return ParseLiteral("null");
                default: return ParseNumber();
            }
        }

        bool ParseObject() {
            if (!Consume('{')) {
                return false;
            }
            SkipWhitespace();
            if (pos_ < text_.size() && text_[pos_] == '}') {
                ++pos_;
                return true;
            }
            while (true) {
                SkipWhitespace();
                if (!ParseString() || !Consume(':') || !ParseValue()) {
                    return false;
                }
                SkipWhitespace();
                if (pos_ < text_.size() && text_[pos_] == '}') {
                    ++pos_;
                    return true;
                }
                if (!Consume(',')) {
                    return false;
                }
            }
        }

        bool ParseArray() {
            if (!Consume('[')) {
                return false;
            }
            SkipWhitespace();
            if (pos_ < text_.size() && text_[pos_] == ']') {
                ++pos_;
                return true;
            }
            while (true) {
                if (!ParseValue()) {
                    return false;
                }
                SkipWhitespace();
                if (pos_ < text_.size() && text_[pos_] == ']') {
                    ++pos_;
                    return true;
                }
                if (!Consume(',')) {
                    return false;
                }
            }
        }

        bool ParseString() {
            if (pos_ >= text_.size() || text_[pos_] != '"') {
                return false;
            }
            ++pos_;
            while (pos_ < text_.size()) {
                const unsigned char ch = static_cast<unsigned char>(text_[pos_++]);
                if (ch == '"') {
                    return true;
                }
                if (ch < 0x20U) {
                    return false;
                }
                if (ch != '\\') {
                    continue;
                }
                if (pos_ >= text_.size()) {
                    return false;
                }
                const char escaped = text_[pos_++];
                if (std::string("\"\\/bfnrt").find(escaped) != std::string::npos) {
                    continue;
                }
                if (escaped != 'u' || pos_ + 4U > text_.size()) {
                    return false;
                }
                for (std::size_t i = 0; i < 4U; ++i) {
                    if (!std::isxdigit(static_cast<unsigned char>(text_[pos_++]))) {
                        return false;
                    }
                }
            }
            return false;
        }

        bool ParseLiteral(const char* literal) {
            const std::size_t length = std::char_traits<char>::length(literal);
            if (text_.compare(pos_, length, literal) != 0) {
                return false;
            }
            pos_ += length;
            return true;
        }

        bool ParseNumber() {
            if (pos_ < text_.size() && text_[pos_] == '-') {
                ++pos_;
            }
            if (pos_ >= text_.size()) {
                return false;
            }
            if (text_[pos_] == '0') {
                ++pos_;
            } else if (IsDigitOneToNine(text_[pos_])) {
                do {
                    ++pos_;
                } while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_])));
            } else {
                return false;
            }
            if (pos_ < text_.size() && text_[pos_] == '.') {
                ++pos_;
                if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
                    return false;
                }
                do {
                    ++pos_;
                } while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_])));
            }
            if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
                ++pos_;
                if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) {
                    ++pos_;
                }
                if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
                    return false;
                }
                do {
                    ++pos_;
                } while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_])));
            }
            return true;
        }

        static bool IsDigitOneToNine(const char ch) {
            return ch >= '1' && ch <= '9';
        }

        const std::string& text_;
        std::size_t pos_{0};
    };

    return Parser(input).Parse();
}

std::filesystem::path FixturePath(const std::string& relative_path) {
    return tamga_test::TestDataRoot() / "tests" / "fixtures" / relative_path;
}

std::vector<std::uint8_t> ReadBinaryFixture(const std::filesystem::path& path) {
    const auto resolved_path = path.is_relative() && !std::filesystem::exists(path) ? FixturePath(path.string()) : path;
    std::ifstream input(resolved_path, std::ios::binary);
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

// struct TestTlvView визначено в TestSupport.h.

bool ParseTestDerLength(const std::vector<std::uint8_t>& data, std::size_t& offset, std::size_t& length) {
    if (offset >= data.size()) {
        return false;
    }

    const auto first = data[offset++];
    if ((first & 0x80U) == 0) {
        length = first;
        return true;
    }

    const std::size_t count = first & 0x7FU;
    if (count == 0 || count > sizeof(std::size_t) || offset + count > data.size()) {
        return false;
    }

    length = 0;
    for (std::size_t i = 0; i < count; ++i) {
        length = (length << 8U) | data[offset++];
    }
    return true;
}

bool ParseTestTlvAt(const std::vector<std::uint8_t>& data, std::size_t offset, TestTlvView& out) {
    if (offset >= data.size()) {
        return false;
    }

    out.tag = data[offset++];
    out.value_offset = offset;

    std::size_t value_length = 0;
    if (!ParseTestDerLength(data, out.value_offset, value_length)) {
        return false;
    }
    if (out.value_offset > data.size() || value_length > data.size() - out.value_offset) {
        return false;
    }

    out.value_length = value_length;
    out.next_offset = out.value_offset + out.value_length;
    return true;
}

std::string HexForTest(const std::uint8_t* data, const std::size_t size) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i) {
        stream << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return stream.str();
}

std::string ExtractDerCertificateSerialHexForTest(const std::vector<std::uint8_t>& certificate_der) {
    TestTlvView outer{};
    TestTlvView tbs{};
    if (!ParseTestTlvAt(certificate_der, 0, outer) || outer.tag != 0x30 ||
        !ParseTestTlvAt(certificate_der, outer.value_offset, tbs) || tbs.tag != 0x30) {
        return {};
    }

    std::size_t offset = tbs.value_offset;
    TestTlvView node{};
    if (!ParseTestTlvAt(certificate_der, offset, node)) {
        return {};
    }
    if (node.tag == 0xA0) {
        offset = node.next_offset;
    }

    TestTlvView serial{};
    if (!ParseTestTlvAt(certificate_der, offset, serial) || serial.tag != 0x02) {
        return {};
    }
    return HexForTest(&certificate_der[serial.value_offset], serial.value_length);
}

std::filesystem::path MakeTemporaryFixturePath(const std::string& suffix) {
    static std::atomic<unsigned long long> counter{0};
    static const unsigned int process_nonce = std::random_device{}();

    std::ostringstream name;
    name << "tamga-" << process_nonce << "-" << counter.fetch_add(1, std::memory_order_relaxed) << suffix;
    return std::filesystem::temp_directory_path() / name.str();
}

bool WriteBinaryFile(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return out.good();
}

// Мінімальний, але справжній PDF для PAdES tests. Текст зберігається в
// content stream як PDF-коментар, щоб mutation-тест міг змінити байт уже
// підписаного документа без залежності від шрифтів або qpdf writer.
std::vector<std::uint8_t> MakeMinimalPdf(const std::string& marker) {
    std::string safe_marker;
    safe_marker.reserve(marker.size());
    for (const char ch : marker) {
        safe_marker += (ch == '\r' || ch == '\n') ? ' ' : ch;
    }
    const std::string content = "q\n% " + safe_marker + "\nQ\n";
    const std::vector<std::string> objects = {
        "<</Type/Catalog/Pages 2 0 R>>",
        "<</Type/Pages/Kids[3 0 R]/Count 1>>",
        "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>",
        "<</Length " + std::to_string(content.size()) + ">>\nstream\n" + content +
            "endstream",
    };

    std::string pdf = "%PDF-1.7\n%\xE2\xE3\xCF\xD3\n";
    std::vector<std::size_t> offsets;
    for (std::size_t i = 0; i < objects.size(); ++i) {
        offsets.push_back(pdf.size());
        pdf += std::to_string(i + 1) + " 0 obj\n" + objects[i] + "\nendobj\n";
    }
    const std::size_t xref = pdf.size();
    pdf += "xref\n0 5\n0000000000 65535 f \n";
    // Без snprintf свідомо: `vendor/cryptonite/src/asn1/c/asn_system.h` під MSVC
    // робить `#define snprintf _snprintf`, тож у цій TU (вона тягне заголовки
    // cryptonite) `std::snprintf` перетворюється на `std::_snprintf` і збірка
    // падає з C2039. `sprintf_s` тут стояв саме тому, але він MSVC-only й ламав
    // Linux. Потік із <iomanip> дає той самий 10-значний запис xref без макроса
    // і однаково працює на обох платформах.
    for (const auto offset : offsets) {
        std::ostringstream line;
        line << std::setw(10) << std::setfill('0') << offset << " 00000 n \n";
        pdf += line.str();
    }
    pdf += "trailer\n<</Size 5/Root 1 0 R>>\nstartxref\n" + std::to_string(xref) +
           "\n%%EOF\n";
    return std::vector<std::uint8_t>(pdf.begin(), pdf.end());
}

// WP-13: тестові string-level хелпери для ArchiveTimeStamp token-swap
// регресії -- витягують/підміняють base64 EncapsulatedTimeStamp САМЕ
// всередині xades:ArchiveTimeStamp (останній EncapsulatedTimeStamp у
// документі: за builder-порядком SignatureTimeStamp -> SigAndRefsTimeStamp ->
// ArchiveTimeStamp), без повного XML-парсингу.
std::string ExtractArchiveTimeStampTokenForTest(const std::string& signed_xml) {
    const auto archive_pos = signed_xml.find("ArchiveTimeStamp");
    if (archive_pos == std::string::npos) {
        return {};
    }
    const std::string enc_open = "EncapsulatedTimeStamp>";
    const auto enc_open_pos = signed_xml.find(enc_open, archive_pos);
    if (enc_open_pos == std::string::npos) {
        return {};
    }
    const auto value_start = enc_open_pos + enc_open.size();
    const auto value_end = signed_xml.find('<', value_start);
    if (value_end == std::string::npos) {
        return {};
    }
    return signed_xml.substr(value_start, value_end - value_start);
}

std::string ReplaceArchiveTimeStampTokenForTest(const std::string& signed_xml, const std::string& new_token_b64) {
    const auto archive_pos = signed_xml.find("ArchiveTimeStamp");
    if (archive_pos == std::string::npos) {
        return signed_xml;
    }
    const std::string enc_open = "EncapsulatedTimeStamp>";
    const auto enc_open_pos = signed_xml.find(enc_open, archive_pos);
    if (enc_open_pos == std::string::npos) {
        return signed_xml;
    }
    const auto value_start = enc_open_pos + enc_open.size();
    const auto value_end = signed_xml.find('<', value_start);
    if (value_end == std::string::npos) {
        return signed_xml;
    }
    std::string out = signed_xml;
    out.replace(value_start, value_end - value_start, new_token_b64);
    return out;
}

// ME-01: видаляє ds:KeyInfo/X509Certificate з уже підписаного XML, лишаючи
// xades:SignedProperties недоторканими — симулює підпис, що структурно є
// XAdES (має SignedProperties), але не містить вбудованого сертифіката.
std::string StripX509CertificateForTest(const std::string& signed_xml) {
    // Тег серіалізується з префіксом "ds:" (див. DEBUG-перевірку під час
    // розробки ME-01 тесту) — на відміну від xades:-елементів, для яких
    // деінде в тестах використовується без-префіксний пошук.
    const std::string open_tag = "<ds:X509Certificate>";
    const auto open_pos = signed_xml.find(open_tag);
    if (open_pos == std::string::npos) {
        return signed_xml;
    }
    const std::string close_tag = "</ds:X509Certificate>";
    const auto close_pos = signed_xml.find(close_tag, open_pos);
    if (close_pos == std::string::npos) {
        return signed_xml;
    }
    std::string out = signed_xml;
    out.erase(open_pos, close_pos + close_tag.size() - open_pos);
    return out;
}

std::string ExtractPemCertificatePayloadForTest(const std::vector<std::uint8_t>& pem_blob) {
    const std::string pem(pem_blob.begin(), pem_blob.end());
    const std::string begin_marker = "-----BEGIN CERTIFICATE-----";
    const std::string end_marker = "-----END CERTIFICATE-----";
    const std::size_t begin = pem.find(begin_marker);
    const std::size_t end = pem.find(end_marker);
    if (begin == std::string::npos || end == std::string::npos || end <= begin) {
        return {};
    }

    std::string payload = pem.substr(begin + begin_marker.size(), end - begin - begin_marker.size());
    payload.erase(std::remove_if(payload.begin(), payload.end(), [](const unsigned char ch) {
        return std::isspace(ch) != 0;
    }), payload.end());
    return payload;
}

std::vector<std::uint8_t> BuildTrustListXmlForTest(const std::string& service_type,
                                                   const std::string& status,
                                                   const std::vector<std::uint8_t>& custom_cert_der) {
    const auto pki_dir = std::filesystem::path(TAMGA_TEST_SOURCE_DIR) / "vendor" / "cryptonite" /
                         "src" / "pkixUtest" / "resources" / "pkiExample_DSTU4145_M257_PB";
    std::string cert_payload;
    if (!custom_cert_der.empty()) {
        cert_payload = tamga::util::Base64Encode(custom_cert_der);
    } else {
        const auto root_der = ReadBinaryFixture(pki_dir / "root_certificate.cer");
        if (!root_der.empty()) {
            cert_payload = tamga::util::Base64Encode(root_der);
        } else {
            const auto cert_pem = ReadBinaryFixture(FixturePath("pki/cert.pem"));
            cert_payload = ExtractPemCertificatePayloadForTest(cert_pem);
        }
    }
    std::ostringstream xml;
    xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        << "<TrustServiceStatusList>"
        << "<TrustServiceProvider>"
        << "<TSPInformation><TSPName><Name>КНЕДП Тест</Name></TSPName></TSPInformation>"
        << "<TSPServices><TSPService><ServiceInformation>"
        << "<ServiceTypeIdentifier>" << service_type << "</ServiceTypeIdentifier>"
        << "<ServiceStatus>" << status << "</ServiceStatus>"
        << "<ServiceDigitalIdentity><DigitalId>"
        << "<X509SubjectName>CN=Tamga Test,O=Tamga,C=UA</X509SubjectName>"
        << "<X509Certificate>" << cert_payload << "</X509Certificate>"
        << "</DigitalId></ServiceDigitalIdentity>"
        << "<ServiceSupplyPoints><ServiceSupplyPoint>https://example.test/tsp</ServiceSupplyPoint></ServiceSupplyPoints>"
        << "<CRL>https://example.test/test.crl</CRL>"
        << "<OCSP>https://example.test/ocsp</OCSP>"
        << "<TSP>https://example.test/tsp</TSP>"
        << "</ServiceInformation></TSPService></TSPServices>"
        << "</TrustServiceProvider>"
        << "</TrustServiceStatusList>";
    const std::string text = xml.str();
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

std::vector<std::uint8_t> BuildGrantedCaTrustListXmlForTest(
    const std::vector<std::uint8_t>& custom_cert_der) {
    return BuildTrustListXmlForTest("http://czo.gov.ua/TrstSvc/Svctype/CA/QC",
                                    "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted",
                                    custom_cert_der);
}

std::size_t CountCerFilesForTest(const std::filesystem::path& dir) {
    std::error_code ec;
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!ec && entry.path().extension() == ".cer") {
            ++count;
        }
    }
    return count;
}

long FindMethod(tamga::nativeapi::TamgaAddIn& addin, const std::wstring& name) {
    const std::u16string short_name = tamga::util::ToShortWchar(name);
    return addin.FindMethod(short_name.c_str());
}

bool CallNoArgs(tamga::nativeapi::TamgaAddIn& addin, const long method, tVariant& ret) {
    return addin.CallAsFunc(method, &ret, nullptr, 0);
}

std::string EscapeJson(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8U);
    for (const unsigned char ch : value) {
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(static_cast<char>(ch)); break;
        }
    }
    return out;
}

bool PrepareInitializedSession(tamga::core::Session& session) {
    tamga::core::Settings settings;
    settings.offline_mode = true;
    settings.work_dir = FixturePath(".").string();
    return session.SetSettings(settings) && session.Initialize();
}

void ExpectTrue(const bool condition, const char* message) {
    if (!condition) {
        ++g_failures;
        std::cerr << "FAILED: " << message << '\n';
    }
}

void ExpectFalse(const bool condition, const char* message) {
    ExpectTrue(!condition, message);
}

void ExpectContains(const std::string& haystack, const std::string& needle, const char* message) {
    if (!Contains(haystack, needle)) {
        ++g_failures;
        std::cerr << "FAILED: " << message << "\nExpected to find: " << needle << "\nIn: " << haystack << '\n';
    }
}

void ExpectContainsValue(const std::vector<std::string>& values, const std::string& expected, const char* message) {
    if (std::find(values.begin(), values.end(), expected) == values.end()) {
        ++g_failures;
        std::cerr << "FAILED: " << message << "\nExpected value: " << expected << '\n';
    }
}

void ExpectNotContainsValue(const std::vector<std::string>& values, const std::string& unexpected, const char* message) {
    if (std::find(values.begin(), values.end(), unexpected) != values.end()) {
        ++g_failures;
        std::cerr << "FAILED: " << message << "\nUnexpected value: " << unexpected << '\n';
    }
}

void ExpectValidJson(const std::string& json, const char* message) {
    if (!IsValidJson(json)) {
        ++g_failures;
        std::cerr << "FAILED: " << message << "\nInvalid JSON: " << json << '\n';
    }
}

void ExpectInvalidJson(const std::string& json, const char* message) {
    if (IsValidJson(json)) {
        ++g_failures;
        std::cerr << "FAILED: " << message << "\nUnexpected valid JSON: " << json << '\n';
    }
}

void ExpectSessionTrue(tamga::core::Session& session, const bool condition, const char* message) {
    if (!condition) {
        ++g_failures;
        std::cerr << "FAILED: " << message << "\nLastError: " << session.GetLastError().message << '\n';
    }
}

void ExpectSummary(const tamga::core::VerifyReport& report,
                   const char* expected,
                   const char* message) {
    const std::string actual = tamga::core::ComputeVerifySummary(report);
    if (actual != expected) {
        ++g_failures;
        std::cerr << "FAILED: " << message
                  << "\nExpected summary: " << expected
                  << "\nActual summary:   " << actual << '\n';
    }
}

void ExpectPolicyDecision(const tamga::core::VerifyReport& report,
                          const bool expected_valid,
                          const char* expected_level,
                          const char* expected_summary,
                          const char* message) {
    const auto actual = tamga::core::ComputeVerifyPolicyDecision(report);
    if (actual.valid != expected_valid ||
        actual.level != expected_level ||
        actual.summary != expected_summary) {
        ++g_failures;
        std::cerr << "FAILED: " << message
                  << "\nExpected policyDecision.valid: " << (expected_valid ? "true" : "false")
                  << "\nActual policyDecision.valid:   " << (actual.valid ? "true" : "false")
                  << "\nExpected policyDecision.level: " << expected_level
                  << "\nActual policyDecision.level:   " << actual.level
                  << "\nExpected policyDecision.summary: " << expected_summary
                  << "\nActual policyDecision.summary:   " << actual.summary << '\n';
    }
}

void ExpectDefaultString(tamga::nativeapi::TamgaAddIn& addin,
                         long method,
                         long param,
                         const std::wstring& expected,
                         const char* message) {
    tVariant value{};
    ExpectTrue(addin.GetParamDefValue(method, param, &value), message);
    std::wstring actual;
    ExpectTrue(tamga::util::GetWString(&value, actual) && actual == expected, message);
}

void ExpectDefaultInt32(tamga::nativeapi::TamgaAddIn& addin,
                        long method,
                        long param,
                        std::int32_t expected,
                        const char* message) {
    tVariant value{};
    ExpectTrue(addin.GetParamDefValue(method, param, &value), message);
    ExpectTrue(TV_VT(&value) == VTYPE_I4 && value.lVal == expected, message);
}

void ExpectDefaultBool(tamga::nativeapi::TamgaAddIn& addin,
                       long method,
                       long param,
                       bool expected,
                       const char* message) {
    tVariant value{};
    ExpectTrue(addin.GetParamDefValue(method, param, &value), message);
    bool actual = !expected;
    ExpectTrue(tamga::util::GetBool(&value, actual) && actual == expected, message);
}

// Ці фікстури потребують cryptonite: у діагностичній збірці vendor=OFF
// їх немає, як і тестів, що ними користуються.
#if TAMGA_CRYPTONITE_ENABLED
// ПД-01: спільна реалізація фікстури. `with_timestamping_eku` додає до
// самопідписаного сертифіката розширення extendedKeyUsage з
// id-kp-timeStamping (1.3.6.1.5.5.7.3.8). Без нього канонічний
// `validation::TimestampEngine` ЗАКОННО відмовляє будь-якій мітці
// (TimestampEngine.cpp:213-217), тож фікстура без EKU не дає перевірити
// щасливий шлях «доказ дійшов до рушія і рушій його підтвердив» — вона
// зупиняється на EKU раніше, ніж на будь-чому іншому.
DstuFixture GenerateDstuFixtureImpl(bool with_timestamping_eku) {
    DstuFixture result;

    Dstu4145Ctx* ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    Gost28147Ctx* cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    if (ec_params == nullptr || cipher_params == nullptr) {
        dstu4145_free(ec_params);
        gost28147_free(cipher_params);
        return result;
    }

    AlgorithmIdentifier_t* aid = nullptr;
    ByteArray* aid_ba = nullptr;
    Pkcs12Ctx* storage = nullptr;
    SignAdapter* sa = nullptr;
    DigestAdapter* da = nullptr;
    VerifyAdapter* va = nullptr;
    CertificateRequestEngine* creq_eng = nullptr;
    CertificationRequest_t* cert_req = nullptr;
    CertificateEngine* cert_eng = nullptr;
    Certificate_t* cert = nullptr;
    ByteArray* cert_encoded = nullptr;
    ByteArray* storage_body = nullptr;
    Extension_t* key_usage_ext = nullptr;
    Extension_t* eku_ext = nullptr;
    OBJECT_IDENTIFIER_t* eku_oid = nullptr;
    Extensions_t* extensions = nullptr;
    SubjectPublicKeyInfo_t* spki = nullptr;
    int rc = 0;

    rc = aid_create_dstu4145(ec_params, cipher_params, true, &aid);
    if (rc != 0) goto cleanup;

    rc = aid_encode(aid, &aid_ba);
    if (rc != 0) goto cleanup;

    rc = pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, "test", 1024, &storage);
    if (rc != 0) goto cleanup;

    rc = pkcs12_generate_key(storage, aid_ba);
    if (rc != 0) goto cleanup;

    rc = pkcs12_store_key(storage, "signer", "test", 1024);
    if (rc != 0) goto cleanup;

    rc = pkcs12_select_key(storage, "signer", "test");
    if (rc != 0) goto cleanup;

    rc = pkcs12_get_sign_adapter(storage, &sa);
    if (rc != 0) goto cleanup;

    rc = pkcs12_get_verify_adapter(storage, &va);
    if (rc != 0) goto cleanup;

    rc = va->get_pub_key(va, &spki);
    if (rc != 0) goto cleanup;

    rc = digest_adapter_init_by_aid(&spki->algorithm, &da);
    if (rc != 0) goto cleanup;

    rc = ecert_request_alloc(sa, &creq_eng);
    if (rc != 0) goto cleanup;

    rc = ecert_request_set_subj_name(creq_eng, "{CN=Tamga Test}{O=Tamga}{C=UA}");
    if (rc != 0) goto cleanup;

    rc = ecert_request_generate(creq_eng, &cert_req);
    if (rc != 0) goto cleanup;

    rc = ext_create_key_usage(true,
        static_cast<KeyUsageBits>(KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_KEY_CERTSIGN),
        &key_usage_ext);
    if (rc != 0) goto cleanup;

    extensions = static_cast<Extensions_t*>(calloc(1, sizeof(Extensions_t)));
    if (extensions == nullptr) goto cleanup;
    rc = ASN_SEQUENCE_ADD(&extensions->list, key_usage_ext);
    if (rc != 0) goto cleanup;
    key_usage_ext = nullptr; // ownership transferred to extensions

    if (with_timestamping_eku) {
        static const long kTimestampingOidNumbers[] = {1, 3, 6, 1, 5, 5, 7, 3, 8};
        OidNumbers numbers{const_cast<long*>(kTimestampingOidNumbers),
                           sizeof(kTimestampingOidNumbers) / sizeof(kTimestampingOidNumbers[0])};
        rc = pkix_create_oid(&numbers, &eku_oid);
        if (rc != 0) goto cleanup;

        OBJECT_IDENTIFIER_t* eku_oids[1] = {eku_oid};
        rc = ext_create_ext_key_usage(false, eku_oids, 1, &eku_ext);
        if (rc != 0) goto cleanup;

        rc = ASN_SEQUENCE_ADD(&extensions->list, eku_ext);
        if (rc != 0) goto cleanup;
        eku_ext = nullptr; // ownership transferred to extensions
    }

    rc = ecert_alloc(sa, da, true, &cert_eng);
    if (rc != 0) goto cleanup;

    {
        const unsigned char serial_bytes[] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14
        };
        ByteArray* serial_ba = ba_alloc_from_uint8(serial_bytes, sizeof(serial_bytes));
        time_t not_before = std::time(nullptr) - 86400;
        time_t not_after = not_before + 365 * 86400;

        rc = ecert_generate(cert_eng, cert_req, 2, serial_ba, &not_before, &not_after, extensions, &cert);
        ba_free(serial_ba);
    }
    if (rc != 0) goto cleanup;

    rc = cert_encode(cert, &cert_encoded);
    if (rc != 0) goto cleanup;

    {
        const ByteArray* certs[2] = {cert_encoded, nullptr};
        rc = pkcs12_set_certificates(storage, certs);
    }
    if (rc != 0) goto cleanup;

    rc = pkcs12_encode(storage, &storage_body);
    if (rc != 0) goto cleanup;

    result.pkcs12_blob.assign(ba_get_buf(storage_body), ba_get_buf(storage_body) + ba_get_len(storage_body));
    result.cert_der.assign(ba_get_buf(cert_encoded), ba_get_buf(cert_encoded) + ba_get_len(cert_encoded));
    result.valid = true;

cleanup:
    ba_free(storage_body);
    ba_free(cert_encoded);
    cert_free(cert);
    ecert_free(cert_eng);
    if (extensions != nullptr) {
        ASN_FREE_CONTENT_STATIC(get_Extensions_desc(), extensions);
        free(extensions);
    }
    if (key_usage_ext != nullptr) {
        ASN_FREE(get_Extension_desc(), key_usage_ext);
    }
    if (eku_ext != nullptr) {
        ASN_FREE(get_Extension_desc(), eku_ext);
    }
    if (eku_oid != nullptr) {
        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), eku_oid);
    }
    ecert_request_free(creq_eng);
    if (cert_req != nullptr) {
        ASN_FREE(get_CertificationRequest_desc(), cert_req);
    }
    spki_free(spki);
    digest_adapter_free(da);
    verify_adapter_free(va);
    sign_adapter_free(sa);
    pkcs12_free(storage);
    ba_free(aid_ba);
    aid_free(aid);
    gost28147_free(cipher_params);
    dstu4145_free(ec_params);
    return result;
}

DstuFixture GenerateDstuFixture() {
    return GenerateDstuFixtureImpl(/*with_timestamping_eku=*/false);
}

// ПД-01: фікстура mock-TSA з EKU id-kp-timeStamping. Потрібна саме тестам
// міток часу: без цього розширення TimestampEngine відмовляє ще до перевірки
// ланцюга й відкликання, тож «мітка дійшла до канонічного рушія» неможливо
// відрізнити від «мітка дійшла, але рушій її не підтвердив».
DstuFixture GenerateDstuTsaFixture() {
    return GenerateDstuFixtureImpl(/*with_timestamping_eku=*/true);
}

namespace {

// PKCS12 може містити кілька сертифікатів того самого ключа. Фікстура
// явно задає потрібний сертифікат, тому не беремо перший старий CertBag.
int BindFixtureCertificate(const DstuFixture& fixture, SignAdapter* signer, Certificate_t** certificate) {
    ByteArray* der = ba_alloc_from_uint8(fixture.cert_der.data(), fixture.cert_der.size());
    *certificate = cert_alloc();
    if (!der || !*certificate) {
        ba_free(der);
        return RET_INVALID_PARAM;
    }
    const int rc = cert_decode(*certificate, der);
    ba_free(der);
    return rc == RET_OK ? signer->set_cert(signer, *certificate) : rc;
}

} // namespace

// Мок-TSA: мінтить RFC3161 timestamp-токен над tbs (GOST34311 imprint),
// підписаний ключем DSTU-фікстури, з вбудованим сертифікатом (cert_req=true).
bool MockTsaTimestamp(const DstuFixture& fixture,
                      const std::vector<std::uint8_t>& tbs,
                      std::vector<std::uint8_t>& token_out,
                      std::string& error) {
    token_out.clear();
    tamga::core::ImprintResult imprint;
    if (!tamga::core::ComputeImprint(tamga::core::ImprintDigest::Gost34311, tbs, imprint, error)) {
        return false;
    }

    Pkcs12Ctx* storage = nullptr;
    SignAdapter* sa = nullptr;
    DigestAdapter* da = nullptr;
    Certificate_t* tsa_cert = nullptr;
    TimeStampReq_t* req = nullptr;
    MessageImprint_t* mi = nullptr;
    DigestAlgorithmIdentifiers_t* aids = nullptr;
    INTEGER_t* sn = nullptr;
    AdaptersMap* map = nullptr;
    TimeStampResp_t* resp = nullptr;
    ContentInfo_t* ts_token = nullptr;
    ByteArray* p12_ba = nullptr;
    ByteArray* hash_ba = nullptr;
    ByteArray* req_der = nullptr;
    ByteArray* token_ba = nullptr;
    AlgorithmIdentifier_t* aid_copy = nullptr;
    bool ok = false;
    int rc = 0;

    p12_ba = ba_alloc_from_uint8(fixture.pkcs12_blob.data(), fixture.pkcs12_blob.size());
    if (p12_ba == nullptr) { error = "p12 byte array"; goto done; }
    rc = pkcs12_decode("Tamga", p12_ba, "test", &storage);
    if (rc != 0 || storage == nullptr) { error = "pkcs12_decode"; goto done; }
    rc = pkcs12_select_key(storage, nullptr, "test");
    if (rc != 0) { error = "pkcs12_select_key"; goto done; }
    rc = pkcs12_get_sign_adapter(storage, &sa);
    if (rc != 0 || sa == nullptr) { error = "pkcs12_get_sign_adapter"; goto done; }
    rc = BindFixtureCertificate(fixture, sa, &tsa_cert);
    if (rc != 0 || tsa_cert == nullptr) { error = "sign_adapter get_cert"; goto done; }
    rc = digest_adapter_init_by_cert(tsa_cert, &da);
    if (rc != 0 || da == nullptr) { error = "digest_adapter_init_by_cert"; goto done; }

    hash_ba = ba_alloc_from_uint8(imprint.hash.data(), imprint.hash.size());
    rc = etspreq_generate_from_gost34311(hash_ba, "1.2.804.2.1.1.1.2.3.1", true, &req);
    if (rc != 0 || req == nullptr) { error = "etspreq_generate"; goto done; }
    rc = tsreq_encode(req, &req_der);
    if (rc != 0 || req_der == nullptr) { error = "tsreq_encode"; goto done; }

    rc = tsreq_get_message(req, &mi);
    if (rc != 0 || mi == nullptr) { error = "tsreq_get_message"; goto done; }
    aids = static_cast<DigestAlgorithmIdentifiers_t*>(calloc(1, sizeof(DigestAlgorithmIdentifiers_t)));
    aid_copy = static_cast<AlgorithmIdentifier_t*>(
        asn_copy_with_alloc(&AlgorithmIdentifier_desc, &mi->hashAlgorithm));
    if (aids == nullptr || aid_copy == nullptr) { error = "digest aids"; goto done; }
    ASN_SEQUENCE_ADD(&aids->list, aid_copy);
    aid_copy = nullptr;  // ownership transferred to aids

    rc = asn_create_integer_from_long(1, &sn);
    if (rc != 0 || sn == nullptr) { error = "serial"; goto done; }

    map = adapters_map_alloc();
    rc = adapters_map_add(map, da, sa);
    if (rc != 0) { error = "adapters_map_add"; goto done; }
    da = nullptr;  // ownership transferred to map
    sa = nullptr;

    {
        time_t now = std::time(nullptr);
        rc = etspresp_generate(map, req_der, sn, aids, &now, &resp);
        if (rc != 0 || resp == nullptr) { error = "etspresp_generate rc=" + std::to_string(rc); goto done; }
    }
    rc = tsresp_get_ts_token(resp, &ts_token);
    if (rc != 0 || ts_token == nullptr) { error = "tsresp_get_ts_token"; goto done; }
    rc = cinfo_encode(ts_token, &token_ba);
    if (rc != 0 || token_ba == nullptr) { error = "cinfo_encode"; goto done; }
    token_out.assign(ba_get_buf(token_ba), ba_get_buf(token_ba) + ba_get_len(token_ba));
    ok = true;

done:
    ba_free(p12_ba);
    ba_free(hash_ba);
    ba_free(req_der);
    ba_free(token_ba);
    if (ts_token != nullptr) cinfo_free(ts_token);
    if (resp != nullptr) tsresp_free(resp);
    if (sn != nullptr) ASN_FREE(&INTEGER_desc, sn);
    if (aids != nullptr) ASN_FREE(&DigestAlgorithmIdentifiers_desc, aids);
    if (aid_copy != nullptr) ASN_FREE(&AlgorithmIdentifier_desc, aid_copy);
    if (req != nullptr) tsreq_free(req);
    if (tsa_cert != nullptr) cert_free(tsa_cert);
    if (map != nullptr) {
        adapters_map_free(map);  // також звільняє da/sa
    } else {
        if (da != nullptr) digest_adapter_free(da);
        if (sa != nullptr) sign_adapter_free(sa);
    }
    if (storage != nullptr) pkcs12_free(storage);
    return ok;
}

// LO-01: генерує справжній, коректно підписаний "порожній" CRL (без жодного
// відкликаного сертифіката), виданий і підписаний тим самим self-signed
// ключем/сертифікатом фікстури (KEY_CERTSIGN у GenerateDstuFixture дозволяє
// йому виступати власним CRL-issuer). На відміну від решти CRL-тестів у цьому
// файлі (які або читають вже готовий фікстурний .crl, або навмисно пишуть
// зіпсовані байти), це єдиний спосіб отримати СПРАВЖНІЙ, engine-згенерований
// CRL "з нуля" без попереднього CRL-файлу як стартової точки:
// ecrl_generate_diff_next_update/ecrl_generate_next_update НЕ вимагають
// ctx->clist (на відміну від голого ecrl_generate) — досить SignAdapter/
// VerifyAdapter, побудованих з того самого self-signed сертифіката.
bool GenerateGoodCrlForTest(const DstuFixture& fixture, std::vector<std::uint8_t>& crl_der_out, std::string& error) {
    crl_der_out.clear();
    Pkcs12Ctx* storage = nullptr;
    SignAdapter* sa = nullptr;
    VerifyAdapter* va = nullptr;
    Certificate_t* issuer_cert = nullptr;
    CrlEngine* engine = nullptr;
    CertificateList_t* crl = nullptr;
    ByteArray* p12_ba = nullptr;
    ByteArray* crl_ba = nullptr;
    bool ok = false;
    int rc = 0;

    p12_ba = ba_alloc_from_uint8(fixture.pkcs12_blob.data(), fixture.pkcs12_blob.size());
    if (p12_ba == nullptr) { error = "p12 byte array"; goto done; }
    rc = pkcs12_decode("Tamga", p12_ba, "test", &storage);
    if (rc != 0 || storage == nullptr) { error = "pkcs12_decode"; goto done; }
    rc = pkcs12_select_key(storage, nullptr, "test");
    if (rc != 0) { error = "pkcs12_select_key"; goto done; }
    rc = pkcs12_get_sign_adapter(storage, &sa);
    if (rc != 0 || sa == nullptr) { error = "pkcs12_get_sign_adapter"; goto done; }
    rc = BindFixtureCertificate(fixture, sa, &issuer_cert);
    if (rc != 0 || issuer_cert == nullptr) { error = "sign_adapter get_cert"; goto done; }
    rc = verify_adapter_init_by_cert(issuer_cert, &va);
    if (rc != 0 || va == nullptr) { error = "verify_adapter_init_by_cert"; goto done; }

    rc = ecrl_alloc(nullptr, sa, va, nullptr, "tamga-test-crl", CRL_FULL, "LO-01 good CRL fixture", &engine);
    if (rc != 0 || engine == nullptr) { error = "ecrl_alloc rc=" + std::to_string(rc); goto done; }

    // Жодного ecrl_add_revoked_cert -- порожній список відкликаних; 30 днів
    // до nextUpdate, з запасом понад validity-вікно тестових сертифікатів.
    rc = ecrl_generate_diff_next_update(engine, 60 * 60 * 24 * 30, &crl);
    if (rc != 0 || crl == nullptr) { error = "ecrl_generate_diff_next_update rc=" + std::to_string(rc); goto done; }

    rc = crl_encode(crl, &crl_ba);
    if (rc != 0 || crl_ba == nullptr) { error = "crl_encode rc=" + std::to_string(rc); goto done; }
    crl_der_out.assign(ba_get_buf(crl_ba), ba_get_buf(crl_ba) + ba_get_len(crl_ba));
    ok = true;

done:
    ba_free(p12_ba);
    ba_free(crl_ba);
    if (crl != nullptr) crl_free(crl);
    if (engine != nullptr) ecrl_free(engine);
    if (va != nullptr) verify_adapter_free(va);
    if (issuer_cert != nullptr) cert_free(issuer_cert);
    if (sa != nullptr) sign_adapter_free(sa);
    if (storage != nullptr) pkcs12_free(storage);
    return ok;
}

// Готує пару «PKCS#8 ключ + його сертифікат» із PEM-фікстур. Повертає false,
// якщо фікстури недоступні або збірка без cryptonite.
bool LoadResolverKeyPair(std::vector<std::uint8_t>& key_container,
                         std::vector<std::uint8_t>& cert_der,
                         std::string& password) {
#if TAMGA_CRYPTONITE_ENABLED
    // Справжня ДСТУ 4145 пара: PKCS#12-контейнер і сертифікат, що йому відповідає.
    // PEM-фікстури pki/*.pem для цього не годяться — cryptonite їх не декодує
    // (rc=539), бо це не ДСТУ/ГОСТ-матеріал.
    auto fixture = GenerateDstuFixture();
    if (!fixture.valid || fixture.pkcs12_blob.empty() || fixture.cert_der.empty()) {
        return false;
    }
    key_container = fixture.pkcs12_blob;
    cert_der = fixture.cert_der;
    password = "test";
    return true;
#else
    (void)key_container;
    (void)cert_der;
    (void)password;
    return false;
#endif
}
#endif  // TAMGA_CRYPTONITE_ENABLED

// B-3: набір налаштувань для тестів, що перевіряють ТРАНСПОРТ/КЕШ TL, а не підпис
// списку. Фікстури TL у цих тестах не підписані, а дефолт (PreferAvailable) у
// збірці з XMLDSIG-рушієм їх коректно відхилив би. Опт-аут тут ЯВНИЙ, щоб не
// сховати зміну дефолту; саму захисну поведінку перевіряє окремий тест.
tamga::core::TrustListSettings MechanicsOnlyTrustListSettings() {
    tamga::core::TrustListSettings settings;
    settings.xml_signature_policy = tamga::core::TrustListSettings::XmlSignaturePolicy::Disabled;
    return settings;
}

std::vector<std::uint8_t> BuildSyntheticAiaDerForTest(const std::string& url) {
    std::vector<std::uint8_t> aia;
    const std::vector<std::uint8_t> ca_issuers_oid = {0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02};
    aia.push_back(0x30);
    aia.push_back(static_cast<std::uint8_t>(ca_issuers_oid.size() + 2U + url.size()));
    aia.insert(aia.end(), ca_issuers_oid.begin(), ca_issuers_oid.end());
    aia.push_back(0x86);
    aia.push_back(static_cast<std::uint8_t>(url.size()));
    aia.insert(aia.end(), url.begin(), url.end());

    std::vector<std::uint8_t> cert_like;
    const std::vector<std::uint8_t> aia_ext_oid = {0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01};
    cert_like.push_back(0x30);
    cert_like.push_back(static_cast<std::uint8_t>(aia_ext_oid.size() + 2U + aia.size()));
    cert_like.insert(cert_like.end(), aia_ext_oid.begin(), aia_ext_oid.end());
    cert_like.push_back(0x04);
    cert_like.push_back(static_cast<std::uint8_t>(aia.size()));
    cert_like.insert(cert_like.end(), aia.begin(), aia.end());
    return cert_like;
}

#if TAMGA_CRYPTONITE_ENABLED
DstuPkcs8Fixture GenerateDstuPkcs8Fixture() {
    DstuPkcs8Fixture result;

    Dstu4145Ctx* ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    Gost28147Ctx* cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    if (ec_params == nullptr || cipher_params == nullptr) {
        dstu4145_free(ec_params);
        gost28147_free(cipher_params);
        return result;
    }

    AlgorithmIdentifier_t* aid = nullptr;
    PrivateKeyInfo_t* pkey = nullptr;
    SignAdapter* sa = nullptr;
    VerifyAdapter* va = nullptr;
    SubjectPublicKeyInfo_t* spki = nullptr;
    DigestAdapter* da = nullptr;
    CertificateRequestEngine* creq_eng = nullptr;
    CertificationRequest_t* cert_req = nullptr;
    Extension_t* key_usage_ext = nullptr;
    Extensions_t* extensions = nullptr;
    CertificateEngine* cert_eng = nullptr;
    Certificate_t* cert = nullptr;
    ByteArray* cert_encoded = nullptr;
    ByteArray* pkcs8_encoded = nullptr;

    int rc = aid_create_dstu4145(ec_params, cipher_params, true, &aid);
    if (rc != 0) goto cleanup;

    rc = pkcs8_generate(aid, &pkey);
    if (rc != 0) goto cleanup;

    rc = pkcs8_get_sign_adapter(pkey, nullptr, &sa);
    if (rc != 0) goto cleanup;

    rc = pkcs8_get_verify_adapter(pkey, &va);
    if (rc != 0) goto cleanup;

    rc = va->get_pub_key(va, &spki);
    if (rc != 0) goto cleanup;

    rc = digest_adapter_init_by_aid(&spki->algorithm, &da);
    if (rc != 0) goto cleanup;

    rc = ecert_request_alloc(sa, &creq_eng);
    if (rc != 0) goto cleanup;

    rc = ecert_request_set_subj_name(creq_eng, "{CN=Tamga PKCS8 Test}{O=Tamga}{C=UA}");
    if (rc != 0) goto cleanup;

    rc = ecert_request_generate(creq_eng, &cert_req);
    if (rc != 0) goto cleanup;

    rc = ext_create_key_usage(true,
        static_cast<KeyUsageBits>(KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_KEY_CERTSIGN),
        &key_usage_ext);
    if (rc != 0) goto cleanup;

    extensions = static_cast<Extensions_t*>(calloc(1, sizeof(Extensions_t)));
    if (extensions == nullptr) goto cleanup;
    rc = ASN_SEQUENCE_ADD(&extensions->list, key_usage_ext);
    if (rc != 0) goto cleanup;
    key_usage_ext = nullptr;

    rc = ecert_alloc(sa, da, true, &cert_eng);
    if (rc != 0) goto cleanup;

    {
        const unsigned char serial_bytes[] = {
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
            0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34
        };
        ByteArray* serial_ba = ba_alloc_from_uint8(serial_bytes, sizeof(serial_bytes));
        time_t not_before = std::time(nullptr) - 86400;
        time_t not_after = not_before + 365 * 86400;
        rc = ecert_generate(cert_eng, cert_req, 2, serial_ba, &not_before, &not_after, extensions, &cert);
        ba_free(serial_ba);
    }
    if (rc != 0) goto cleanup;

    rc = cert_encode(cert, &cert_encoded);
    if (rc != 0) goto cleanup;

    rc = pkcs8_encode(pkey, &pkcs8_encoded);
    if (rc != 0) goto cleanup;

    result.pkcs8_der.assign(ba_get_buf(pkcs8_encoded), ba_get_buf(pkcs8_encoded) + ba_get_len(pkcs8_encoded));
    result.cert_der.assign(ba_get_buf(cert_encoded), ba_get_buf(cert_encoded) + ba_get_len(cert_encoded));
    result.valid = true;

cleanup:
    ba_free(pkcs8_encoded);
    ba_free(cert_encoded);
    cert_free(cert);
    ecert_free(cert_eng);
    if (extensions != nullptr) {
        ASN_FREE_CONTENT_STATIC(get_Extensions_desc(), extensions);
        free(extensions);
    }
    if (key_usage_ext != nullptr) {
        ASN_FREE(get_Extension_desc(), key_usage_ext);
    }
    ecert_request_free(creq_eng);
    if (cert_req != nullptr) {
        ASN_FREE(get_CertificationRequest_desc(), cert_req);
    }
    spki_free(spki);
    digest_adapter_free(da);
    verify_adapter_free(va);
    sign_adapter_free(sa);
    pkcs8_free(pkey);
    aid_free(aid);
    gost28147_free(cipher_params);
    dstu4145_free(ec_params);
    return result;
}

std::vector<std::uint8_t> CreateTstInfoDer(const std::vector<std::uint8_t>& imprint_hash, const std::string& gen_time_str,
                                           const std::string& hash_algorithm_oid) {
    TSTInfo_t* tst = (TSTInfo_t*)calloc(1, sizeof(TSTInfo_t));
    if (tst == nullptr) {
        return {};
    }
    asn_long2INTEGER(&tst->version, 1);

    pkix_set_oid(oids_get_oid_numbers_by_id(OID_DATA_ID), &tst->policy);

    // ME-05: параметризовано (раніше — хардкод, і з помилковою OID-строкою
    // "...2.1.2.1" замість коректної Kupyna-256 "...2.2.1", яку маскував
    // тепер прибраний "compatibility" fallback у ValidateTimestampToken —
    // без нього тест падав на неправильному статусі помилки замість
    // очікуваного untrusted/expired). Дефолт лишається коректним Kupyna-256
    // OID; тест на саму ME-05-регресію передає свідомо нерозпізнаний OID.
    OidNumbers* kupyna_oid = oids_get_oid_numbers_by_str(hash_algorithm_oid.c_str());
    if (kupyna_oid) {
        pkix_set_oid(kupyna_oid, &tst->messageImprint.hashAlgorithm.algorithm);
        oids_oid_numbers_free(kupyna_oid);
    }
    
    ByteArray* hash_ba = ba_alloc_from_uint8(imprint_hash.data(), imprint_hash.size());
    OCTET_STRING_fromBuf(&tst->messageImprint.hashedMessage, (const char*)ba_get_buf(hash_ba), static_cast<int>(ba_get_len(hash_ba)));
    ba_free(hash_ba);

    asn_long2INTEGER(&tst->serialNumber, 1);

    OCTET_STRING_fromBuf(&tst->genTime, gen_time_str.data(), static_cast<int>(gen_time_str.size()));

    ByteArray* encoded = nullptr;
    asn_encode_ba(&TSTInfo_desc, tst, &encoded);
    
    std::vector<std::uint8_t> der(ba_get_buf(encoded), ba_get_buf(encoded) + ba_get_len(encoded));
    
    ba_free(encoded);
    ASN_FREE(&TSTInfo_desc, tst);
    return der;
}

bool GenerateMockTspToken(const std::vector<std::uint8_t>& key_material,
                          const std::vector<std::uint8_t>& certificate_der,
                          const std::vector<std::uint8_t>& tst_info_der,
                          std::vector<std::uint8_t>& out_token_der) {
    ByteArray* data_ba = nullptr;
    DigestAdapter* digest_adapter = nullptr;
    SignAdapter* sign_adapter = nullptr;
    SignerInfoEngine* signer_engine = nullptr;
    SignedDataEngine* signed_data_engine = nullptr;
    SignedData_t* signed_data = nullptr;
    ContentInfo_t* content_info = nullptr;
    ByteArray* encoded = nullptr;
    Certificate_t* signer_certificate = nullptr;
    OidNumbers* tst_oid = nullptr;
    Pkcs12Ctx* storage = nullptr;
    int rc = RET_OK;
    bool success = false;

    data_ba = ba_alloc_from_uint8(tst_info_der.data(), tst_info_der.size());
    if (data_ba == nullptr) goto cleanup;

    {
        ByteArray* p12_ba = ba_alloc_from_uint8(key_material.data(), key_material.size());
        rc = pkcs12_decode("Tamga", p12_ba, "test", &storage);
        ba_free(p12_ba);
    }
    if (rc != RET_OK) goto cleanup;

    rc = pkcs12_select_key(storage, "signer", "test");
    if (rc != RET_OK) goto cleanup;

    rc = pkcs12_get_sign_adapter(storage, &sign_adapter);
    if (rc != RET_OK) goto cleanup;

    {
        ByteArray* cert_ba = ba_alloc_from_uint8(certificate_der.data(), certificate_der.size());
        signer_certificate = cert_alloc();
        rc = cert_decode(signer_certificate, cert_ba);
        ba_free(cert_ba);
    }
    if (rc != RET_OK) goto cleanup;

    rc = sign_adapter->set_cert(sign_adapter, signer_certificate);
    if (rc != RET_OK) goto cleanup;

    rc = digest_adapter_init_by_cert(signer_certificate, &digest_adapter);
    if (rc != RET_OK) {
        rc = digest_adapter_init_default(&digest_adapter);
    }
    if (rc != RET_OK) goto cleanup;

    rc = esigner_info_alloc(sign_adapter, digest_adapter, digest_adapter, &signer_engine);
    if (rc != RET_OK) goto cleanup;

    tst_oid = oids_get_oid_numbers_by_str("1.2.840.113549.1.9.16.1.4");
    if (tst_oid == nullptr) goto cleanup;

    rc = esigned_data_alloc(signer_engine, &signed_data_engine);
    if (rc != RET_OK) goto cleanup;

    rc = esigned_data_set_data(signed_data_engine, tst_oid, data_ba, true);
    if (rc != RET_OK) goto cleanup;

    rc = esigned_data_add_cert(signed_data_engine, signer_certificate);
    if (rc != RET_OK) goto cleanup;

    rc = esigned_data_generate(signed_data_engine, &signed_data);
    if (rc != RET_OK) goto cleanup;

    content_info = cinfo_alloc();
    if (content_info == nullptr) goto cleanup;

    rc = cinfo_init_by_signed_data(content_info, signed_data);
    if (rc != RET_OK) goto cleanup;
    signed_data = nullptr;

    rc = cinfo_encode(content_info, &encoded);
    if (rc != RET_OK || encoded == nullptr) goto cleanup;

    {
        const std::uint8_t* buf = ba_get_buf(encoded);
        const size_t len = ba_get_len(encoded);
        if (buf != nullptr && len > 0) {
            out_token_der.assign(buf, buf + len);
            success = true;
        }
    }

cleanup:
    cinfo_free(content_info);
    sdata_free(signed_data);
    if (signed_data_engine != nullptr) {
        esigned_data_free(signed_data_engine);
    } else {
        esigner_info_free(signer_engine);
    }
    digest_adapter_free(digest_adapter);
    sign_adapter_free(sign_adapter);
    cert_free(signer_certificate);
    if (tst_oid) oids_oid_numbers_free(tst_oid);
    ba_free(encoded);
    ba_free(data_ba);
    if (storage) pkcs12_free(storage);
    return success;
}
#endif  // TAMGA_CRYPTONITE_ENABLED

} // namespace tamga_tests
