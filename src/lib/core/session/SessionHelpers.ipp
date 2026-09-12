#include "core/Session.h"

#include <algorithm>
#include <atomic>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <iostream>

#include "core/CryptoniteAdapter.h"
#include "core/cryptonite/Names.h"
#include "core/net/CertificateResolver.h"
#include "core/HttpClient.h"
#include "asic/AsicContainers.h"
#include "asic/AsicReader.h"
#include "core/TspClient.h"
#include "core/KeyParsers.h"
#include "util/Der.h"
#include "util/Hex.h"
#include "util/Json.h"
#include "util/X509Name.h"
#include "core/policy/AiaIssuerFetcher.h"
#include "core/policy/CertificateChainValidator.h"
#include "core/policy/CrlValidator.h"
#include "core/policy/OcspValidator.h"
#include "core/policy/TimestampValidator.h"
#include "core/policy/VerifyChecks.h"
#include "core/policy/VerifyReportJson.h"
#include "core/policy/ImprintDigest.h"
#include "core/policy/PolicyCache.h"
#include "core/session/VerifyReportCommit.h"
#include "core/session/VerifySummary.h"
#include "core/validation/ValidationEngine.h"
#include "core/validation/ValidationReportProjection.h"
#include "util/AsicUri.h"
#include "util/Base64.h"
#include "util/FileSystem.h"
#include "util/SecureZero.h"
#if defined(TAMGA_XML_SIGNATURES_ENABLED)
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xmldsig/XmlTransformEngine.h"
#include "xades/XadesVerifier.h"
#endif

#ifndef TAMGA_LIBCURL_ENABLED
#define TAMGA_LIBCURL_ENABLED 0
#endif

// HTTP доступний якщо є libcurl або WinHTTP (Windows-вбудований)
#if TAMGA_LIBCURL_ENABLED
#define TAMGA_HTTP_ENABLED 1
#elif defined(_WIN32)
#define TAMGA_HTTP_ENABLED 1  // WinHTTP
#else
#define TAMGA_HTTP_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "byte_array.h"
#include "cert.h"
#include "crl.h"
#include "oids.h"
#include "OBJECT_IDENTIFIER.h"
#include "TBSCertificate.h"
#include "cryptonite_manager.h"
#include "dstu7564.h"
}
#endif

namespace tamga::core {

namespace {
bool StartsWith(const std::vector<std::uint8_t>& data, const std::initializer_list<std::uint8_t>& prefix) {
    if (data.size() < prefix.size()) {
        return false;
    }
    return std::equal(prefix.begin(), prefix.end(), data.begin());
}

// Визначає алгоритм імпринту для TSP із пріоритетом:
//   1. Явно налаштований OID у TspSettings.imprint_digest_oid
//   2. Авто-визначення із digestAlgorithm підписанта у CMS-блоці cms_for_detect
//   3. Kupyna-256 як запасний варіант (зворотна сумісність)
bool ResolveTspImprint(const TspSettings& tsp,
                       const std::vector<std::uint8_t>& data_to_stamp,
                       const std::vector<std::uint8_t>& cms_for_detect,
                       ImprintResult& out,
                       std::string& error_message) {
    ImprintDigest resolved_alg = ImprintDigest::Kupyna256;

    // Пріоритет 1: явно налаштований OID
    if (!tsp.imprint_digest_oid.empty() && tsp.imprint_digest_oid != "auto") {
        auto alg_opt = ImprintFromDigestOid(tsp.imprint_digest_oid);
        if (alg_opt.has_value()) {
            resolved_alg = alg_opt.value();
        } else {
            error_message = "ResolveTspImprint: configured imprint digest OID '" + tsp.imprint_digest_oid + "' is unsupported";
            return false;
        }
    }
    // Пріоритет 2: авто-визначення із digestAlgorithm CMS
    else if (!cms_for_detect.empty()) {
        std::string signer_digest_oid;
        std::string extract_err;
        if (CryptoniteAdapter::GetSignerDigestAlgorithmOid(cms_for_detect, signer_digest_oid, extract_err)) {
            auto alg_opt = ImprintFromDigestOid(signer_digest_oid);
            if (alg_opt.has_value()) {
                resolved_alg = alg_opt.value();
            }
            // Якщо OID не розпізнано — fallback до Kupyna256
        }
        // Якщо витяг не вдався — fallback до Kupyna256
    }
    // Пріоритет 3: Kupyna256 вже встановлено як resolved_alg

    return ComputeImprint(resolved_alg, data_to_stamp, out, error_message);
}


bool IsLikelyPem(const std::vector<std::uint8_t>& data) {
    static constexpr char kPemPrefix[] = "-----BEGIN ";
    if (data.size() < sizeof(kPemPrefix) - 1) {
        return false;
    }

    for (std::size_t i = 0; i < sizeof(kPemPrefix) - 1; ++i) {
        if (static_cast<char>(data[i]) != kPemPrefix[i]) {
            return false;
        }
    }
    return true;
}

constexpr char kCryptoniteRequiredMessage[] =
    "Signing and verification require a build with TAMGA_ENABLE_VENDOR_CRYPTONITE=ON";



// Хвиля 8, п.2: єдина реалізація DER-парсера — в `util/Der`.
using tamga::util::ParseTlvAt;
using tamga::util::TlvView;

bool IsPkcs12Der(const std::vector<std::uint8_t>& der_data) {
    TlvView outer{};
    if (!ParseTlvAt(der_data, 0, outer) || outer.tag != 0x30) {
        return false;
    }

    TlvView version{};
    if (!ParseTlvAt(der_data, outer.value_offset, version) || version.tag != 0x02) {
        return false;
    }

    TlvView auth_safe{};
    if (!ParseTlvAt(der_data, version.next_offset, auth_safe) || auth_safe.tag != 0x30) {
        return false;
    }

    TlvView content_type{};
    return ParseTlvAt(der_data, auth_safe.value_offset, content_type) && content_type.tag == 0x06;
}



bool IsValidTimeout(const std::int32_t timeout_ms) {
    return timeout_ms > 0 && timeout_ms <= 300000;
}

bool IsLikelyUrl(const std::string& value) {
    return value.rfind("http://", 0) == 0 || value.rfind("https://", 0) == 0 || value.rfind("ldap://", 0) == 0;
}

constexpr std::uintmax_t kMaxInputFileSize = 64U * 1024U * 1024U;

// Хвиля 8, п.5: JSON-шар винесено в `util/Json` — 313 рядків парсера
// більше не живуть усередині моноліту Session. Короткі імена лишаються,
// щоб не чіпати сотні місць виклику.
using tamga::util::EscapeJson;

// ADR-027: розбір і форматування X.509-імен над сирим DER винесені в
// `util/X509Name`; шістнадцяткове кодування — в `util/Hex`. Короткі імена
// лишаються, щоб не чіпати наявні місця виклику.
using tamga::util::EscapeRfc4514;
using tamga::util::ExtractDerStringValue;
using tamga::util::FormatRdnSequence;
using tamga::util::HexEncode;
using tamga::util::LookupOidShortName;
using tamga::util::OidToString;










#if TAMGA_CRYPTONITE_ENABLED
// ADR-027: тут лежала друга реалізація FormatNameRfc4514 — переписаний
// `cryptonite/Names.cpp`. Вона відрізнялася від оригіналу таблицею OID:
// знала стандартні атрибути X.500, але не знала українських DRFO і EDRPOU,
// тож ДРФО у звіті виглядало як `1.2.804.2.1.1.1.11.1.4=#<hex>`.
// Таблиці обʼєднані в `util::LookupOidShortName`, а форматування
// ASN.1-структури лишилося одне — у cryptonite.
using cryptonite_detail::FormatNameRfc4514;
#endif


// ADR-033: `ApplyFormatTimestampVerdict`, `ApplyEntryTimestampVerdict` і
// `BuildVerifyMessage` переїхали у `core/session/VerifyReportCommit.{h,cpp}`.
// Тут вони жили в анонімному namespace, тобто були недосяжні для прямого
// тесту: перевірити правило В-03 можна було лише через повний Verify* із
// ключем, файлом і мережею. Тепер це чисті функції над `VerifyReport`.

[[maybe_unused]] void WriteTspTraceBinary(const char* name, const std::vector<std::uint8_t>& data) {
    const char* dir = std::getenv("TAMGA_TSP_TRACE_DIR");
    if (dir == nullptr || dir[0] == '\0') {
        return;
    }

    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::u8path(dir), ec);
    const std::filesystem::path path = std::filesystem::u8path(dir) / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return;
    }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

// ComputeVerifySummary lives in core/session/VerifySummary.{h,cpp} so that its visibility
// does not depend on the .ipp inclusion order inside Session.cpp, and so that unit tests
// can exercise every branch of the summary directly without going through the full Session.

#if TAMGA_CRYPTONITE_ENABLED
void CollectCertificatesFromDirectory(const std::filesystem::path& dir_path,
                                      std::vector<std::vector<std::uint8_t>>& certificates) {
    std::error_code ec;
    if (!std::filesystem::exists(dir_path, ec) || !std::filesystem::is_directory(dir_path, ec)) {
        return;
    }

    for (const auto& entry : std::filesystem::directory_iterator(dir_path, ec)) {
        if (ec || !entry.is_regular_file(ec)) {
            continue;
        }
        std::vector<std::uint8_t> file_data;
        std::string read_error;
        if (!util::ReadBinaryFileLimited(entry.path(), util::kMaxCertificateFileSize, file_data,
                                         read_error)) {
            continue;
        }
        if (file_data.empty()) {
            continue;
        }

        if (IsLikelyPem(file_data)) {
            std::vector<PemDerLoader::PemBlock> blocks;
            std::string error_message;
            PemDerLoader::LoadOptions options;
            options.strict_mode = false;
            if (PemDerLoader::LoadAll(file_data, blocks, error_message, options)) {
                for (auto& block : blocks) {
                    if (block.type.find("CERTIFICATE") != std::string::npos && !block.der_payload.empty()) {
                        certificates.push_back(std::move(block.der_payload));
                    }
                }
            }
        } else {
            certificates.push_back(std::move(file_data));
        }
    }
}

void CollectTrustAnchors(const std::string& work_dir, std::vector<std::vector<std::uint8_t>>& anchors) {
    anchors.clear();
    if (work_dir.empty()) {
        return;
    }
    CollectCertificatesFromDirectory(std::filesystem::u8path(work_dir) / "trust-store", anchors);
}

void CollectHistoricalTrustAnchors(const std::string& work_dir, std::vector<std::vector<std::uint8_t>>& anchors) {
    anchors.clear();
    if (work_dir.empty()) {
        return;
    }
    CollectCertificatesFromDirectory(std::filesystem::u8path(work_dir) / "historical-trust-store", anchors);
}

void CollectIntermediateCertificates(const std::string& work_dir,
                                     std::vector<std::vector<std::uint8_t>>& intermediates) {
    intermediates.clear();
    if (work_dir.empty()) {
        return;
    }
    CollectCertificatesFromDirectory(std::filesystem::u8path(work_dir) / "intermediate-store", intermediates);
}

// WP-11: раніше AIA (Authority Information Access) issuer fallback жив лише
// у legacy ApplyTrustPipelineStatus (CMS/CAdES). Винесено як format-agnostic
// pre-step перед ValidationEngine::Validate — доповнює embedded_certificates_der
// відсутніми проміжними сертифікатами, коли поточний ланцюг Untrusted/Incomplete
// із наявним (непорожнім) trust-store, замість того, щоб дублювати retry-логіку
// всередині самого ValidationEngine. Trust/revocation decision й надалі
// походить ЛИШЕ з ValidationEngine — це лише збагачення вхідних кандидатів.
std::vector<std::vector<std::uint8_t>> EnrichWithAiaIssuersIfNeeded(
    const std::string& work_dir,
    std::int32_t timeout_ms,
    bool network_enabled,
    const std::vector<std::uint8_t>& signer_certificate_der,
    std::vector<std::vector<std::uint8_t>> embedded_certificates_der) {
    if (!network_enabled || work_dir.empty() || signer_certificate_der.empty()) {
        return embedded_certificates_der;
    }
    std::vector<std::vector<std::uint8_t>> current_trust_anchors;
    CollectTrustAnchors(work_dir, current_trust_anchors);
    if (current_trust_anchors.empty()) {
        return embedded_certificates_der;
    }
    std::vector<std::vector<std::uint8_t>> intermediate_certs;
    CollectIntermediateCertificates(work_dir, intermediate_certs);

    policy::CertificateChainInput probe;
    probe.signer_certificate_der = signer_certificate_der;
    probe.embedded_certificates_der = embedded_certificates_der;
    probe.intermediate_certificates_der = intermediate_certs;
    probe.trust_anchors_der = current_trust_anchors;
    const auto probe_result = policy::CertificateChainValidator{}.Validate(probe);
    if (probe_result.status != policy::ChainStatus::Untrusted &&
        probe_result.status != policy::ChainStatus::Incomplete) {
        return embedded_certificates_der;
    }

    policy::AiaIssuerFetchInput aia_input;
    aia_input.network_enabled = network_enabled;
    aia_input.work_dir = work_dir;
    aia_input.timeout_ms = timeout_ms > 0 ? timeout_ms : 10000;
    aia_input.seed_certificates_der.push_back(signer_certificate_der);
    aia_input.seed_certificates_der.insert(aia_input.seed_certificates_der.end(),
                                           embedded_certificates_der.begin(), embedded_certificates_der.end());
    aia_input.seed_certificates_der.insert(aia_input.seed_certificates_der.end(),
                                           intermediate_certs.begin(), intermediate_certs.end());
    const auto aia_result = policy::AiaIssuerFetcher{}.FetchMissingIssuers(aia_input);
    embedded_certificates_der.insert(embedded_certificates_der.end(),
                                     aia_result.certificates_der.begin(), aia_result.certificates_der.end());
    return embedded_certificates_der;
}

void CollectTsaAnchors(const std::string& work_dir, std::vector<std::vector<std::uint8_t>>& anchors) {
    anchors.clear();
    if (work_dir.empty()) {
        return;
    }
    CollectCertificatesFromDirectory(std::filesystem::u8path(work_dir) / "tsa-store", anchors);
}

void CollectHistoricalTsaAnchors(const std::string& work_dir, std::vector<std::vector<std::uint8_t>>& anchors) {
    anchors.clear();
    if (work_dir.empty()) {
        return;
    }
    CollectCertificatesFromDirectory(std::filesystem::u8path(work_dir) / "historical-tsa-store", anchors);
}

#endif

/**
 * WP-11 (HI-06): тонкий адаптер над чистою `ProjectVerifyReport` — весь
 * canonical trust/revocation/certificate-time/timestamp мапінг живе лише там
 * (single source of truth), тут лише копіюються ці поля у вже частково
 * заповнений (форматно-специфічними полями: operation/policy/containerType/
 * signatureFormat/formatProfile/ltvValid) `report`. Формат-специфічні поля
 * НЕ чіпаються — саме вони й лишаються "мутацією", а не подвійним джерелом
 * істини для trust/revocation/timestamp (яке усунено).
 */
[[maybe_unused]] void ApplyValidationEngineReport(const validation::ValidationReport& ve_report,
                                 VerifyReport& report) {
    const VerifyReport projected = ProjectVerifyReport(ve_report);

    report.signer_certificate_present = projected.signer_certificate_present;
    report.certificate_time_valid = projected.certificate_time_valid;
    report.validation_time_source = projected.validation_time_source;

    report.chain_checked = projected.chain_checked;
    report.chain_valid = projected.chain_valid;
    report.chain_debug = projected.chain_debug;

    report.trust_checked = projected.trust_checked;
    report.trust_valid = projected.trust_valid;
    report.trust_status = projected.trust_status;
    report.trust_reason = projected.trust_reason;
    report.trust_mode = projected.trust_mode;
    report.historical_trust_used = projected.historical_trust_used;
    report.historical_anchor_subject = projected.historical_anchor_subject;
    report.historical_anchor_serial = projected.historical_anchor_serial;

    report.trust_list_checked = projected.trust_list_checked;
    report.trust_list_cache_status = projected.trust_list_cache_status;
    report.trust_list_source = projected.trust_list_source;

    report.revocation_checked = projected.revocation_checked;
    report.ocsp_checked = projected.ocsp_checked;
    report.revocation_status = projected.revocation_status;

    report.timestamp_checked = projected.timestamp_checked;
    report.timestamp_valid = projected.timestamp_valid;
    report.tsp_checked = projected.tsp_checked;
    report.timestamp_status = projected.timestamp_status;
    report.timestamp_details = projected.timestamp_details;

    report.error_code = projected.error_code;
    if (!projected.message.empty()) {
        report.message = projected.message;
    }
}

// Адаптери над `util::ExtractJson*`: зберігають форму `bool + out`, якою
// користуються наявні місця виклику, але самої логіки більше не містять.
bool TryExtractJsonString(const std::string& json, const std::string& key, std::string& out) {
    const auto value = tamga::util::ExtractJsonString(json, key);
    if (!value) {
        return false;
    }
    out = *value;
    return true;
}

bool TryExtractJsonBool(const std::string& json, const std::string& key, bool& out) {
    const auto value = tamga::util::ExtractJsonBool(json, key);
    if (!value) {
        return false;
    }
    out = *value;
    return true;
}

// Hardening: усі шляхи від викликача трактуються як UTF-8 і йдуть у
// std::filesystem::u8path. На невалідному UTF-8 (типовий випадок — хост передав
// рядок у системному ANSI-кодуванні) u8path на MSVC не повертає помилку, а
// призводить до аварійного завершення процесу (0xC0000409). Для бібліотеки, яку
// вантажить 1С, це неприпустимо: некоректний вхід мусить давати чисту помилку, а
// не вбивати процес хоста. Тому валідуємо кодування ДО побудови path.
bool IsValidUtf8Path(const std::string& path) {
    // Свідомо локальна перевірка без проміжного UTF-16 буфера: тут потрібно лише
    // відхилити невалідний ввід до побудови std::filesystem::path.
    const auto* bytes = reinterpret_cast<const unsigned char*>(path.data());
    const std::size_t size = path.size();
    for (std::size_t i = 0; i < size;) {
        const unsigned char lead = bytes[i];
        std::size_t extra = 0;
        unsigned int code = 0;
        if (lead < 0x80U) {
            ++i;
            continue;
        }
        if ((lead & 0xE0U) == 0xC0U) { extra = 1; code = lead & 0x1FU; }
        else if ((lead & 0xF0U) == 0xE0U) { extra = 2; code = lead & 0x0FU; }
        else if ((lead & 0xF8U) == 0xF0U) { extra = 3; code = lead & 0x07U; }
        else { return false; }  // 0x80-0xBF як lead, або 0xF8+ — невалідно

        if (i + extra >= size) {
            return false;  // обірвана послідовність у кінці рядка
        }
        for (std::size_t k = 1; k <= extra; ++k) {
            const unsigned char cont = bytes[i + k];
            if ((cont & 0xC0U) != 0x80U) {
                return false;
            }
            code = (code << 6) | (cont & 0x3FU);
        }
        // Overlong, surrogate half і поза-Unicode послідовності також відкидаємо:
        // вони не можуть з'явитися у коректному UTF-8 шляху.
        if ((extra == 1 && code < 0x80U) ||
            (extra == 2 && code < 0x800U) ||
            (extra == 3 && code < 0x10000U) ||
            (code >= 0xD800U && code <= 0xDFFFU) ||
            code > 0x10FFFFU) {
            return false;
        }
        i += extra + 1;
    }
    return true;
}

// Контракт (Q-02): за порожнього `settings.base_path` відносний шлях лишається
// ВІДНОСНИМ і розвʼязується проти поточного каталогу процесу. Це навмисно:
// результат цієї функції потрапляє і в повідомлення про помилки, і у звіти
// перевірки, тож примусове перетворення на абсолютний шлях змінило б
// спостережуваний вивід усіх файлових операцій (вхід, вихід, ASiC, XML, PDF).
//
// Наслідок для викликачів: той, кому потрібен КАТАЛОГ файлу (наприклад,
// sidecar-пошук сертифіката поруч із ключем), не має права вважати порожній
// `parent_path()` за «каталогу немає» — це «каталог поточний». Див.
// `CollectSidecarCandidates` у `core/net/CertificateResolver.cpp`.
std::string ResolveFilePath(const std::string& path, const FileStoreSettings& settings) {
    if (path.empty()) {
        return {};
    }
    if (!IsValidUtf8Path(path) || (!settings.base_path.empty() && !IsValidUtf8Path(settings.base_path))) {
        // Порожній результат тлумачиться викликачами як «шлях недоступний» і
        // перетворюється на ErrorCode::InvalidArgument нижче по стеку.
        return {};
    }

    const std::filesystem::path input = std::filesystem::u8path(path);
    if (input.is_absolute() || settings.base_path.empty()) {
        return input.lexically_normal().u8string();
    }

    return (std::filesystem::u8path(settings.base_path) / input).lexically_normal().u8string();
}

// ADR-027: читання файлу більше не реалізується тут.
//
// Ця функція мала власне тіло — перевірку розміру, відкриття, читання
// шматками — тобто повторювала `util::ReadBinaryFileLimited` з точністю до
// формулювань. Своїм у неї було рівно двоє: перевірка, що шлях є валідним
// UTF-8 (fail-clean замість аварії процесу-хоста 1С), і МІТКА в повідомленні
// про помилку, за якою читач звіту розуміє, який саме файл не прочитався.
//
// Обидві ці речі й лишилися. Все інше делегується.
bool ReadBinaryFile(const std::string& path,
                    const std::string& label,
                    std::vector<std::uint8_t>& out,
                    std::string& error_message) {
    if (path.empty() || !IsValidUtf8Path(path)) {
        // Див. IsValidUtf8Path: fail-clean замість аварії процесу-хоста.
        error_message = label + " path is not valid UTF-8";
        return false;
    }

    std::string reason;
    if (!tamga::util::ReadBinaryFileLimited(std::filesystem::u8path(path),
                                            kMaxInputFileSize, out, reason)) {
        out.clear();
        // Мітка попереду, причина позаду: інтегратор має бачити І що саме не
        // прочиталося, І чому.
        error_message = label + ": " + reason;
        return false;
    }
    return true;
}

bool ParseX509Time(const std::string& text, std::tm& out_tm) {
    auto all_digits = [](const std::string& v, const std::size_t from, const std::size_t len) {
        if (from + len > v.size()) return false;
        for (std::size_t i = from; i < from + len; ++i) {
            if (!std::isdigit(static_cast<unsigned char>(v[i]))) return false;
        }
        return true;
    };

    std::tm tm{};
    if (text.size() == 13 && text.back() == 'Z') { // YYMMDDhhmmssZ
        if (!(all_digits(text, 0, 12))) return false;
        tm.tm_year = std::stoi(text.substr(0, 2));
        tm.tm_year += (tm.tm_year >= 50 ? 0 : 100);
        tm.tm_mon = std::stoi(text.substr(2, 2)) - 1;
        tm.tm_mday = std::stoi(text.substr(4, 2));
        tm.tm_hour = std::stoi(text.substr(6, 2));
        tm.tm_min = std::stoi(text.substr(8, 2));
        tm.tm_sec = std::stoi(text.substr(10, 2));
        out_tm = tm;
        return true;
    }
    if (text.size() == 15 && text.back() == 'Z') { // YYYYMMDDhhmmssZ
        if (!(all_digits(text, 0, 14))) return false;
        tm.tm_year = std::stoi(text.substr(0, 4)) - 1900;
        tm.tm_mon = std::stoi(text.substr(4, 2)) - 1;
        tm.tm_mday = std::stoi(text.substr(6, 2));
        tm.tm_hour = std::stoi(text.substr(8, 2));
        tm.tm_min = std::stoi(text.substr(10, 2));
        tm.tm_sec = std::stoi(text.substr(12, 2));
        out_tm = tm;
        return true;
    }
    return false;
}

#if defined(_WIN32)
time_t TimegmPortable(std::tm* t) {
    return _mkgmtime(t);
}
#else
time_t TimegmPortable(std::tm* t) {
    return timegm(t);
}
#endif

bool ParseValidityWindow(const std::vector<std::uint8_t>& cert_data,
                         std::string& not_before,
                         std::string& not_after,
                         bool& valid_now,
                         time_t& not_before_ts,
                         time_t& not_after_ts) {
    TlvView outer{};
    if (!ParseTlvAt(cert_data, 0, outer) || outer.tag != 0x30) {
        return false;
    }

    TlvView tbs{};
    if (!ParseTlvAt(cert_data, outer.value_offset, tbs) || tbs.tag != 0x30) {
        return false;
    }

    std::size_t offset = tbs.value_offset;
    TlvView node{};

    if (!ParseTlvAt(cert_data, offset, node)) {
        return false;
    }
    if (node.tag == 0xA0) {
        offset = node.next_offset;
    }

    for (int i = 0; i < 3; ++i) {
        if (!ParseTlvAt(cert_data, offset, node)) {
            return false;
        }
        offset = node.next_offset;
    }

    TlvView validity{};
    if (!ParseTlvAt(cert_data, offset, validity) || validity.tag != 0x30) {
        return false;
    }
    TlvView not_before_tlv{};
    TlvView not_after_tlv{};
    if (!ParseTlvAt(cert_data, validity.value_offset, not_before_tlv)) {
        return false;
    }
    if (!ParseTlvAt(cert_data, not_before_tlv.next_offset, not_after_tlv)) {
        return false;
    }
    if (!((not_before_tlv.tag == 0x17 || not_before_tlv.tag == 0x18) &&
          (not_after_tlv.tag == 0x17 || not_after_tlv.tag == 0x18))) {
        return false;
    }

    not_before.assign(reinterpret_cast<const char*>(&cert_data[not_before_tlv.value_offset]), not_before_tlv.value_length);
    not_after.assign(reinterpret_cast<const char*>(&cert_data[not_after_tlv.value_offset]), not_after_tlv.value_length);

    std::tm from_tm{};
    std::tm to_tm{};
    if (!ParseX509Time(not_before, from_tm) || !ParseX509Time(not_after, to_tm)) {
        return false;
    }

    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    const auto from = TimegmPortable(&from_tm);
    const auto to = TimegmPortable(&to_tm);
    valid_now = now >= from && now <= to;
    // ME-08: not_before_ts/not_after_ts винесені окремо (не лише рядки), щоб
    // GetCertificateInfo міг перевірити валідність на ДОВІЛЬНИЙ момент часу
    // (validAt), а не лише "зараз" -- уніфіковано з cryptonite-шляхом, де ці
    // самі time_t доступні напряму через cert_get_not_before/cert_get_not_after.
    not_before_ts = from;
    not_after_ts = to;
    return true;
}

std::string ExtractExtensionHex(const std::vector<std::uint8_t>& cert_data,
                                const std::array<std::uint8_t, 3>& oid_bytes,
                                const bool unwrap_inner_octet_string) {
    for (std::size_t i = 0; i + 5 < cert_data.size(); ++i) {
        if (cert_data[i] != 0x06 || cert_data[i + 1] != 0x03 || cert_data[i + 2] != oid_bytes[0] ||
            cert_data[i + 3] != oid_bytes[1] || cert_data[i + 4] != oid_bytes[2]) {
            continue;
        }

        std::size_t cursor = i + 5;
        TlvView maybe_critical{};
        if (!ParseTlvAt(cert_data, cursor, maybe_critical)) {
            continue;
        }
        if (maybe_critical.tag == 0x01) {
            cursor = maybe_critical.next_offset;
        }

        TlvView extn_value{};
        if (!ParseTlvAt(cert_data, cursor, extn_value) || extn_value.tag != 0x04) {
            continue;
        }

        const auto* value_ptr = &cert_data[extn_value.value_offset];
        std::size_t value_len = extn_value.value_length;
        if (unwrap_inner_octet_string) {
            TlvView inner{};
            if (!ParseTlvAt(cert_data, extn_value.value_offset, inner) || inner.tag != 0x04) {
                continue;
            }
            value_ptr = &cert_data[inner.value_offset];
            value_len = inner.value_length;
        } else {
            TlvView bit_string{};
            if (ParseTlvAt(cert_data, extn_value.value_offset, bit_string) && bit_string.tag == 0x03 && bit_string.value_length > 0) {
                value_ptr = &cert_data[bit_string.value_offset + 1];
                value_len = bit_string.value_length - 1;
            }
        }
        return HexEncode(value_ptr, value_len);
    }
    return {};
}

[[maybe_unused]] std::string FormatUnixTimeUtc(const time_t value) {
    std::tm utc_tm{};
#if defined(_WIN32)
    if (gmtime_s(&utc_tm, &value) != 0) {
        return {};
    }
#else
    if (gmtime_r(&value, &utc_tm) == nullptr) {
        return {};
    }
#endif

    std::ostringstream out;
    out << std::setfill('0') << std::setw(4) << (utc_tm.tm_year + 1900) << '-'
        << std::setw(2) << (utc_tm.tm_mon + 1) << '-'
        << std::setw(2) << utc_tm.tm_mday << 'T'
        << std::setw(2) << utc_tm.tm_hour << ':'
        << std::setw(2) << utc_tm.tm_min << ':'
        << std::setw(2) << utc_tm.tm_sec << 'Z';
    return out.str();
}

#if TAMGA_CRYPTONITE_ENABLED
std::string ExtractCertExtensionHex(const Certificate_t* cert,
                                    const OidId oid_id,
                                    const bool unwrap_inner_octet_string) {
    const OidNumbers* oid = oids_get_oid_numbers_by_id(oid_id);
    if (oid == nullptr) {
        return {};
    }

    ByteArray* ext_value = nullptr;
    if (cert_get_ext_value(cert, oid, &ext_value) != RET_OK || ext_value == nullptr) {
        ba_free(ext_value);
        return {};
    }

    std::string result = HexEncode(ba_get_buf(ext_value), ba_get_len(ext_value));
    if (unwrap_inner_octet_string) {
        const std::vector<std::uint8_t> ext(ba_get_buf(ext_value), ba_get_buf(ext_value) + ba_get_len(ext_value));
        TlvView inner{};
        if (ParseTlvAt(ext, 0, inner) && inner.tag == 0x04 && inner.value_offset + inner.value_length <= ext.size()) {
            result = HexEncode(ext.data() + static_cast<std::ptrdiff_t>(inner.value_offset), inner.value_length);
        }
    }

    ba_free(ext_value);
    return result;
}
#endif
} // namespace
