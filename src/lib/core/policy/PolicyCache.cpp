#include "core/policy/PolicyCache.h"
#include "util/Hex.h"

#include "core/CryptoniteAdapter.h"
#include "core/cryptonite/CertUtil.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <sstream>
#include <system_error>
#include "util/FileSystem.h"
#include "util/Json.h"
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "BasicConstraints.h"
#include "KeyUsage.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "oids.h"
}
#endif

namespace tamga::core::policy {

// ADR-027: копія прибрана — одна реалізація в `util/Hex`.
using tamga::util::HexFromUInt64;
namespace {

std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8U);
    for (const unsigned char ch : value) {
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20U) {
                    std::ostringstream escaped;
                    escaped << "\\u";
                    constexpr char kHex[] = "0123456789abcdef";
                    escaped << "00" << kHex[(ch >> 4U) & 0x0FU] << kHex[ch & 0x0FU];
                    out += escaped.str();
                } else {
                    out.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    return out;
}

// ADR-027: копія прибрана — одна реалізація в `util/FileSystem`.
using tamga::util::PathToUtf8;

// ADR-027: копія прибрана — одна реалізація в `util/FileSystem`.
using tamga::util::PathWithSuffix;

std::filesystem::path TempPathFor(const std::filesystem::path& path) {
    return PathWithSuffix(path, ".tmp");
}

std::filesystem::path BackupPathFor(const std::filesystem::path& path) {
    return PathWithSuffix(path, ".bak");
}

bool ReplaceFileWithTemp(const std::filesystem::path& temp_path, const std::filesystem::path& final_path) {
#ifdef _WIN32
    return MoveFileExW(temp_path.wstring().c_str(),
                       final_path.wstring().c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    std::error_code ec;
    std::filesystem::rename(temp_path, final_path, ec);
    return !ec;
#endif
}

bool MoveFilePath(const std::filesystem::path& from, const std::filesystem::path& to) {
#ifdef _WIN32
    return MoveFileExW(from.wstring().c_str(),
                       to.wstring().c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    std::error_code ec;
    std::filesystem::rename(from, to, ec);
    return !ec;
#endif
}

bool StageBinaryFile(const std::filesystem::path& temp_path, const std::vector<std::uint8_t>& data) {
    std::error_code ec;
    std::filesystem::remove(temp_path, ec);

    std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        std::filesystem::remove(temp_path, ec);
        return false;
    }
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    const bool write_ok = out.good();
    out.close();
    if (!write_ok || !out.good()) {
        std::filesystem::remove(temp_path, ec);
        return false;
    }

    return true;
}

std::vector<std::uint8_t> BuildStateJson(const PolicyCacheState& state) {
    std::ostringstream json;
    json << "{"
         << "\"sourceUrl\":\"" << JsonEscape(state.source_url) << "\","
         << "\"cacheStatus\":\"" << JsonEscape(state.cache_status) << "\","
         << "\"lastSync\":\"" << JsonEscape(state.last_sync) << "\","
         << "\"etag\":\"" << JsonEscape(state.etag) << "\","
         << "\"lastModified\":\"" << JsonEscape(state.last_modified) << "\","
         << "\"updateSucceeded\":" << (state.update_succeeded ? "true" : "false")
         << "}\n";
    const std::string text = json.str();
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

void WriteJsonStringArray(std::ostringstream& json, const std::vector<std::string>& values) {
    json << "[";
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            json << ",";
        }
        json << "\"" << JsonEscape(values[i]) << "\"";
    }
    json << "]";
}

[[maybe_unused]] bool EndsWith(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool IsGrantedService(const TrustListServiceRecord& service) {
    return service.status == "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted" ||
           service.status == "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted" ||
           service.status == "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel" ||
           service.status == "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";
}

struct CertificateMaterializationDecision {
    bool granted{false};
    bool is_ca{false};
    bool key_cert_sign{false};
    bool materialize{false};
    std::string target{"skip"};
    std::string reason{"not evaluated"};
};

#if TAMGA_CRYPTONITE_ENABLED
bool DecodeCertificateForPolicy(const std::vector<std::uint8_t>& der, Certificate_t** out_certificate) {
    *out_certificate = nullptr;
    if (der.empty()) {
        return false;
    }
    ByteArray* ba = ba_alloc_from_uint8(der.data(), der.size());
    Certificate_t* cert = cert_alloc();
    if (ba == nullptr || cert == nullptr) {
        ba_free(ba);
        cert_free(cert);
        return false;
    }
    const int rc = cert_decode(cert, ba);
    ba_free(ba);
    if (rc != RET_OK) {
        cert_free(cert);
        return false;
    }
    *out_certificate = cert;
    return true;
}

bool CertificateHasCaBasicConstraint(const Certificate_t* cert) {
    if (cert == nullptr) {
        return false;
    }
    ByteArray* ext = nullptr;
    const auto* oid = oids_get_oid_numbers_by_id(OID_BASIC_CONSTRAINTS_EXTENSION_ID);
    if (oid == nullptr || cert_get_ext_value(cert, oid, &ext) != RET_OK || ext == nullptr) {
        ba_free(ext);
        return false;
    }
    auto* basic_constraints = static_cast<BasicConstraints_t*>(
        asn_decode_with_alloc(get_BasicConstraints_desc(), ba_get_buf(ext), ba_get_len(ext)));
    ba_free(ext);
    if (basic_constraints == nullptr) {
        return false;
    }
    const bool is_ca = basic_constraints->cA != nullptr && *basic_constraints->cA != 0;
    ASN_FREE(get_BasicConstraints_desc(), basic_constraints);
    return is_ca;
}

// Відсутнє розширення keyUsage означає «обмежень немає». Сам розбір — у
// `cryptonite_detail::CertificateAllowsKeyUsage` (одна копія на проєкт).
bool CertificateHasKeyCertSign(const Certificate_t* cert) {
    return tamga::core::cryptonite_detail::CertificateAllowsKeyUsage(cert, KeyUsage_keyCertSign);
}
#endif

CertificateMaterializationDecision ClassifyMaterializationCandidate(
    const TrustListServiceRecord& service,
    const std::vector<std::uint8_t>& certificate,
    bool is_historical) {
    CertificateMaterializationDecision decision;
    decision.granted = IsGrantedService(service);
    if (!decision.granted) {
        decision.reason = "service status is not granted";
        return decision;
    }

#if TAMGA_CRYPTONITE_ENABLED
    Certificate_t* cert = nullptr;
    if (!DecodeCertificateForPolicy(certificate, &cert)) {
        decision.reason = "certificate cannot be decoded";
        return decision;
    }
    decision.is_ca = CertificateHasCaBasicConstraint(cert);
    decision.key_cert_sign = CertificateHasKeyCertSign(cert);
    cert_free(cert);
#else
    (void)certificate;
    decision.reason = "cryptonite disabled; CA/keyCertSign cannot be evaluated";
    return decision;
#endif

    // TSA endpoint certificates (MR-TSA/QTST, National-TSA/QTST) — не є CA,
    // але є прямими trust anchors для TSA chain validation через TL direct-match модель.
    const bool is_tsa_service =
        (service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/MR-TSA/QTST" ||
         service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/National-TSA/QTST");
    if (is_tsa_service) {
        decision.materialize = true;
        decision.target = is_historical ? "historical-tsa-store" : "tsa-store";
        decision.reason = "granted TSA endpoint certificate from trust list";
        return decision;
    }

    if (!decision.is_ca) {
        decision.reason = "basicConstraints CA is false or missing";
        return decision;
    }

    // NationalRootCA-QC — кореневий CA, materialize як trust anchor
    const bool is_ca_service = (service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/CA/QC" ||
                                service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/MR-CA/QC" ||
                                service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/NationalRootCA-QC");

    if (!decision.key_cert_sign && !is_ca_service) {
        decision.reason = "keyUsage keyCertSign is false or missing";
        return decision;
    }

    decision.materialize = true;
    decision.target = is_historical ? "historical-trust-store" : "trust-store";
    if (!decision.key_cert_sign) {
        decision.reason = "granted CA certificate from trust list (keyCertSign is 0/missing but service type is CA)";
    } else {
        decision.reason = "granted CA certificate with keyCertSign";
    }
    return decision;
}


// ADR-027: копія прибрана — спільна реалізація в `util/Hex.h`.
using tamga::util::StableDerHash;

std::string SanitizeToken(std::string value) {
    value.erase(std::remove_if(value.begin(), value.end(), [](const unsigned char ch) {
        return std::isalnum(ch) == 0 && ch != '-' && ch != '_';
    }), value.end());
    return value;
}

std::string UniqueFileName(const std::string& base_name, std::set<std::string>& used_names) {
    std::string candidate = base_name + ".cer";
    std::size_t index = 2U;
    while (used_names.find(candidate) != used_names.end()) {
        candidate = base_name + "-" + std::to_string(index++) + ".cer";
    }
    used_names.insert(candidate);
    return candidate;
}

struct TrustStoreMetadataRecord {
    std::string provider_name;
    std::string service_type;
    std::string status;
    std::string xml_subject_name;
    std::string file_name;
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string metadata_error;
    bool materialized_trust_anchor{false};
    bool granted{false};
    bool is_ca{false};
    bool key_cert_sign{false};
    std::string target{"skip"};
    std::string materialization_reason;
    std::string source_tl;
    TrustListEndpoints endpoints;
};

std::vector<TrustStoreMetadataRecord> BuildTrustStoreMetadataRecords(const std::vector<PolicyCacheEntry>& entries) {
    std::vector<TrustStoreMetadataRecord> records;
    std::set<std::string> active_used_names;
    std::set<std::string> historical_used_names;

    for (const auto& entry : entries) {
        for (const auto& service : entry.parsed.services) {
            for (const auto& certificate : service.certificates) {
                const auto decision = ClassifyMaterializationCandidate(service, certificate, entry.is_historical);
                TrustStoreMetadataRecord record;
                record.provider_name = service.provider_name;
                record.service_type = service.service_type;
                record.status = service.status;
                record.xml_subject_name = service.subject_name;
                record.materialized_trust_anchor = decision.materialize;
                record.granted = decision.granted;
                record.is_ca = decision.is_ca;
                record.key_cert_sign = decision.key_cert_sign;
                record.target = decision.target;
                record.materialization_reason = decision.reason;
                record.source_tl = entry.filename;
                record.endpoints = service.endpoints;

                tamga::core::CertificateMetadata metadata;
                std::string error_message;
                if (tamga::core::CryptoniteAdapter::ExtractCertificateMetadata(certificate, metadata, error_message)) {
                    record.subject = metadata.subject;
                    record.issuer = metadata.issuer;
                    record.serial = metadata.serial_number_hex;
                } else {
                    record.subject = service.subject_name;
                    record.metadata_error = error_message;
                }

                if (decision.materialize) {
                    const std::string base_token = !record.serial.empty()
                        ? "serial-" + SanitizeToken(record.serial)
                        : "hash-" + StableDerHash(certificate);
                    if (entry.is_historical) {
                        record.file_name = UniqueFileName(base_token, historical_used_names);
                    } else {
                        record.file_name = UniqueFileName(base_token, active_used_names);
                    }
                }

                records.push_back(std::move(record));
            }
        }
    }

    return records;
}

std::vector<std::uint8_t> BuildTrustStoreMetadataJson(const PolicyCacheState& state,
                                                      std::size_t service_count,
                                                      const std::vector<TrustStoreMetadataRecord>& records) {
    std::ostringstream json;
    json << "{"
         << "\"sourceUrl\":\"" << JsonEscape(state.source_url) << "\","
         << "\"lastSync\":\"" << JsonEscape(state.last_sync) << "\","
         << "\"serviceCount\":" << service_count << ","
         << "\"records\":[";
    for (std::size_t i = 0; i < records.size(); ++i) {
        const auto& record = records[i];
        if (i > 0) {
            json << ",";
        }
        json << "{"
             << "\"providerName\":\"" << JsonEscape(record.provider_name) << "\","
             << "\"serviceType\":\"" << JsonEscape(record.service_type) << "\","
             << "\"status\":\"" << JsonEscape(record.status) << "\","
             << "\"sourceTl\":\"" << JsonEscape(record.source_tl) << "\","
             << "\"materializedTrustAnchor\":" << (record.materialized_trust_anchor ? "true" : "false") << ","
             << "\"granted\":" << (record.granted ? "true" : "false") << ","
             << "\"isCa\":" << (record.is_ca ? "true" : "false") << ","
             << "\"keyCertSign\":" << (record.key_cert_sign ? "true" : "false") << ","
             << "\"target\":\"" << JsonEscape(record.target) << "\","
             << "\"materializationReason\":\"" << JsonEscape(record.materialization_reason) << "\","
             << "\"fileName\":\"" << JsonEscape(record.file_name) << "\","
             << "\"issuer\":\"" << JsonEscape(record.issuer) << "\","
             << "\"subject\":\"" << JsonEscape(record.subject.empty() ? record.xml_subject_name : record.subject) << "\","
             << "\"serial\":\"" << JsonEscape(record.serial) << "\","
             << "\"metadataError\":\"" << JsonEscape(record.metadata_error) << "\","
             << "\"crlUrls\":";
        WriteJsonStringArray(json, record.endpoints.crl_urls);
        json << ",\"ocspUrls\":";
        WriteJsonStringArray(json, record.endpoints.ocsp_urls);
        json << ",\"tspUrls\":";
        WriteJsonStringArray(json, record.endpoints.tsp_urls);
        json << "}";
    }
    json << "]}\n";
    const std::string text = json.str();
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

// Хвиля 8, п.5: власні розбирачі прибрані. Тутешній `ExtractJsonString`
// НЕ декодував `\uXXXX`: default-гілка штовхала літеру `u`, а чотири
// шістнадцяткові цифри копіювались як текст. Оскільки ці ж файли Tamga
// сама й пише через EscapeJson (який для символів < 0x20 емітує саме
// `\u00XX`), round-trip псував значення. Тепер парсер спільний.
using tamga::util::ExtractJsonBool;
using tamga::util::ExtractJsonString;


// ME-06 (повний фікс): наступні два хелпери читають масиви, записані
// BuildTrustStoreMetadataJson — "records":[{...},...] і, всередині кожного
// запису, "tspUrls":[...]. Формат самоконтрольований (пишеться лише цим же
// файлом), тому цільовий, а не загальний JSON-парсер — коректно враховує
// вкладені лапки/дужки в рядкових значеннях (URL тощо), але не претендує на
// повну RFC 8259-грамотність.
std::vector<std::string> ExtractJsonObjectArray(const std::string& json, const std::string& key) {
    std::vector<std::string> objects;
    const std::string marker = "\"" + key + "\":[";
    const std::size_t start = json.find(marker);
    if (start == std::string::npos) {
        return objects;
    }

    std::size_t pos = start + marker.size();
    while (pos < json.size()) {
        while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
            ++pos;
        }
        if (pos < json.size() && json[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos >= json.size() || json[pos] != '{') {
            break;
        }

        const std::size_t obj_start = pos;
        int depth = 0;
        bool in_string = false;
        bool escaped = false;
        for (; pos < json.size(); ++pos) {
            const char ch = json[pos];
            if (in_string) {
                if (escaped) {
                    escaped = false;
                } else if (ch == '\\') {
                    escaped = true;
                } else if (ch == '"') {
                    in_string = false;
                }
                continue;
            }
            if (ch == '"') {
                in_string = true;
            } else if (ch == '{') {
                ++depth;
            } else if (ch == '}') {
                --depth;
                if (depth == 0) {
                    ++pos;
                    break;
                }
            }
        }
        if (depth != 0) {
            break;  // malformed/truncated -- stop rather than misparse
        }
        objects.push_back(json.substr(obj_start, pos - obj_start));
    }
    return objects;
}

std::vector<std::string> ExtractJsonStringArray(const std::string& json, const std::string& key) {
    std::vector<std::string> values;
    const std::string marker = "\"" + key + "\":[";
    const std::size_t start = json.find(marker);
    if (start == std::string::npos) {
        return values;
    }

    std::size_t pos = start + marker.size();
    while (pos < json.size()) {
        while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
            ++pos;
        }
        if (pos < json.size() && json[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos >= json.size() || json[pos] != '"') {
            break;
        }

        std::string value;
        bool escaped = false;
        ++pos;
        for (; pos < json.size(); ++pos) {
            const char ch = json[pos];
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
                    default: value.push_back(ch); break;
                }
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '"') {
                ++pos;
                break;
            }
            value.push_back(ch);
        }
        values.push_back(std::move(value));
    }
    return values;
}

bool ExistingFileHasContent(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec) && std::filesystem::file_size(path, ec) > 0U && !ec;
}

bool ExistingDirectory(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::is_directory(path, ec) && !ec;
}

} // namespace

PolicyCache::PolicyCache(const std::string& work_dir) : work_dir_(std::filesystem::u8path(work_dir)) {}

PolicyCache::PolicyCache(std::filesystem::path work_dir) : work_dir_(std::move(work_dir)) {}

bool PolicyCache::EnsureLayout(std::string& error_message) const {
    const std::array<std::filesystem::path, 6> dirs = {
        TrustListPath().parent_path(),
        TrustStoreDir(),
        HistoricalTrustStoreDir(),
        IntermediateStoreDir(),
        CrlStoreDir(),
        PolicyDir(),
    };

    for (const auto& dir : dirs) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) {
            error_message = "Failed to create policy cache directory: " + PathToUtf8(dir) + ": " + ec.message();
            return false;
        }
    }

    error_message.clear();
    return true;
}

bool PolicyCache::WriteTrustList(const std::vector<std::uint8_t>& xml, const PolicyCacheState& state) const {
    std::string error_message;
    if (!EnsureLayout(error_message)) {
        return false;
    }

    const std::filesystem::path xml_path = TrustListPath();
    const std::filesystem::path state_path = StatePath();
    const std::filesystem::path xml_temp_path = TempPathFor(xml_path);
    const std::filesystem::path state_temp_path = TempPathFor(state_path);
    const std::filesystem::path xml_backup_path = BackupPathFor(xml_path);
    const std::filesystem::path state_backup_path = BackupPathFor(state_path);

    std::error_code ec;
    std::filesystem::remove(xml_backup_path, ec);
    std::filesystem::remove(state_backup_path, ec);

    if (!StageBinaryFile(xml_temp_path, xml) ||
        !StageBinaryFile(state_temp_path, BuildStateJson(state))) {
        std::filesystem::remove(xml_temp_path, ec);
        std::filesystem::remove(state_temp_path, ec);
        return false;
    }

    const bool had_xml = ExistingFileHasContent(xml_path);
    const bool had_state = ExistingFileHasContent(state_path);
    if (had_xml && !MoveFilePath(xml_path, xml_backup_path)) {
        std::filesystem::remove(xml_temp_path, ec);
        std::filesystem::remove(state_temp_path, ec);
        return false;
    }
    if (had_state && !MoveFilePath(state_path, state_backup_path)) {
        if (had_xml) {
            MoveFilePath(xml_backup_path, xml_path);
        }
        std::filesystem::remove(xml_temp_path, ec);
        std::filesystem::remove(state_temp_path, ec);
        return false;
    }

    bool ok = ReplaceFileWithTemp(xml_temp_path, xml_path) &&
              ReplaceFileWithTemp(state_temp_path, state_path);
    if (!ok) {
        std::filesystem::remove(xml_path, ec);
        std::filesystem::remove(state_path, ec);
        if (had_xml) {
            MoveFilePath(xml_backup_path, xml_path);
        }
        if (had_state) {
            MoveFilePath(state_backup_path, state_path);
        }
        std::filesystem::remove(xml_temp_path, ec);
        std::filesystem::remove(state_temp_path, ec);
        return false;
    }

    std::filesystem::remove(xml_backup_path, ec);
    std::filesystem::remove(state_backup_path, ec);
    return true;
}

bool PolicyCache::WriteTrustListMaterialized(const std::vector<std::uint8_t>& xml,
                                             const PolicyCacheState& state,
                                             const TrustListParseResult& parsed) const {
    PolicyCacheEntry entry;
    entry.filename = "TL-UA-EC.xml";
    entry.xml = xml;
    entry.parsed = parsed;
    entry.is_historical = false;
    return WriteTrustListsMaterialized({entry}, state);
}

bool PolicyCache::WriteTrustListsMaterialized(const std::vector<PolicyCacheEntry>& entries,
                                              const PolicyCacheState& state) const {
    std::string error_message;
    if (!EnsureLayout(error_message)) {
        return false;
    }

    const auto records = BuildTrustStoreMetadataRecords(entries);
    std::size_t total_service_count = 0;
    for (const auto& entry : entries) {
        total_service_count += entry.parsed.services.size();
    }

    std::error_code ec;
    const std::filesystem::path state_path = StatePath();
    const std::filesystem::path metadata_path = TrustStoreMetadataPath();
    const std::filesystem::path trust_store_path = TrustStoreDir();
    const std::filesystem::path historical_trust_store_path = HistoricalTrustStoreDir();
    const std::filesystem::path tsa_store_path = work_dir_ / "tsa-store";
    const std::filesystem::path historical_tsa_store_path = work_dir_ / "historical-tsa-store";

    const std::filesystem::path state_temp_path = TempPathFor(state_path);
    const std::filesystem::path metadata_temp_path = TempPathFor(metadata_path);
    const std::filesystem::path trust_store_temp_path = TempPathFor(trust_store_path);
    const std::filesystem::path historical_trust_store_temp_path = TempPathFor(historical_trust_store_path);
    const std::filesystem::path tsa_store_temp_path = TempPathFor(tsa_store_path);
    const std::filesystem::path historical_tsa_store_temp_path = TempPathFor(historical_tsa_store_path);

    const std::filesystem::path state_backup_path = BackupPathFor(state_path);
    const std::filesystem::path metadata_backup_path = BackupPathFor(metadata_path);
    const std::filesystem::path trust_store_backup_path = BackupPathFor(trust_store_path);
    const std::filesystem::path historical_trust_store_backup_path = BackupPathFor(historical_trust_store_path);
    const std::filesystem::path tsa_store_backup_path = BackupPathFor(tsa_store_path);
    const std::filesystem::path historical_tsa_store_backup_path = BackupPathFor(historical_tsa_store_path);

    // Clean backups & temps
    std::filesystem::remove(state_backup_path, ec);
    std::filesystem::remove(metadata_backup_path, ec);
    std::filesystem::remove_all(trust_store_backup_path, ec);
    std::filesystem::remove_all(historical_trust_store_backup_path, ec);
    std::filesystem::remove_all(tsa_store_backup_path, ec);
    std::filesystem::remove_all(historical_tsa_store_backup_path, ec);

    std::filesystem::remove(state_temp_path, ec);
    std::filesystem::remove(metadata_temp_path, ec);
    std::filesystem::remove_all(trust_store_temp_path, ec);
    std::filesystem::remove_all(historical_trust_store_temp_path, ec);
    std::filesystem::remove_all(tsa_store_temp_path, ec);
    std::filesystem::remove_all(historical_tsa_store_temp_path, ec);

    std::vector<std::filesystem::path> xml_paths;
    xml_paths.reserve(entries.size());
    for (const auto& entry : entries) {
        const std::filesystem::path xml_path = TrustListPath(entry.filename);
        std::filesystem::remove(BackupPathFor(xml_path), ec);
        std::filesystem::remove(TempPathFor(xml_path), ec);
        xml_paths.push_back(xml_path);
    }

    // Stage XML files
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (!StageBinaryFile(TempPathFor(xml_paths[i]), entries[i].xml)) {
            for (const auto& p : xml_paths) {
                std::filesystem::remove(TempPathFor(p), ec);
            }
            return false;
        }
    }

    // Stage state & metadata
    if (!StageBinaryFile(state_temp_path, BuildStateJson(state)) ||
        !StageBinaryFile(metadata_temp_path, BuildTrustStoreMetadataJson(state, total_service_count, records))) {
        for (const auto& p : xml_paths) {
            std::filesystem::remove(TempPathFor(p), ec);
        }
        std::filesystem::remove(state_temp_path, ec);
        std::filesystem::remove(metadata_temp_path, ec);
        return false;
    }

    // Create temp directories for stores
    std::filesystem::create_directories(trust_store_temp_path, ec);
    std::filesystem::create_directories(historical_trust_store_temp_path, ec);
    std::filesystem::create_directories(tsa_store_temp_path, ec);
    std::filesystem::create_directories(historical_tsa_store_temp_path, ec);
    if (ec) {
        for (const auto& p : xml_paths) {
            std::filesystem::remove(TempPathFor(p), ec);
        }
        std::filesystem::remove(state_temp_path, ec);
        std::filesystem::remove(metadata_temp_path, ec);
        std::filesystem::remove_all(trust_store_temp_path, ec);
        std::filesystem::remove_all(historical_trust_store_temp_path, ec);
        std::filesystem::remove_all(tsa_store_temp_path, ec);
        std::filesystem::remove_all(historical_tsa_store_temp_path, ec);
        return false;
    }

    // Stage certificates
    std::size_t record_index = 0;
    for (const auto& entry : entries) {
        for (const auto& service : entry.parsed.services) {
            for (const auto& certificate : service.certificates) {
                const auto& record = records[record_index++];
                if (!record.materialized_trust_anchor || record.file_name.empty()) {
                    continue;
                }
                std::filesystem::path store_temp_path;
                if (record.target == "trust-store") {
                    store_temp_path = trust_store_temp_path;
                } else if (record.target == "historical-trust-store") {
                    store_temp_path = historical_trust_store_temp_path;
                } else if (record.target == "tsa-store") {
                    store_temp_path = tsa_store_temp_path;
                } else if (record.target == "historical-tsa-store") {
                    store_temp_path = historical_tsa_store_temp_path;
                } else {
                    continue;
                }
                const std::filesystem::path cert_path = store_temp_path / record.file_name;
                if (!StageBinaryFile(cert_path, certificate)) {
                    for (const auto& p : xml_paths) {
                        std::filesystem::remove(TempPathFor(p), ec);
                    }
                    std::filesystem::remove(state_temp_path, ec);
                    std::filesystem::remove(metadata_temp_path, ec);
                    std::filesystem::remove_all(trust_store_temp_path, ec);
                    std::filesystem::remove_all(historical_trust_store_temp_path, ec);
                    std::filesystem::remove_all(tsa_store_temp_path, ec);
                    std::filesystem::remove_all(historical_tsa_store_temp_path, ec);
                    return false;
                }
            }
        }
    }

    // Backup current files
    std::vector<std::filesystem::path> backed_xmls;
    backed_xmls.reserve(xml_paths.size());
    for (const auto& xml_p : xml_paths) {
        if (ExistingFileHasContent(xml_p)) {
            if (!MoveFilePath(xml_p, BackupPathFor(xml_p))) {
                for (const auto& b : backed_xmls) {
                    MoveFilePath(BackupPathFor(b), b);
                }
                for (const auto& p : xml_paths) {
                    std::filesystem::remove(TempPathFor(p), ec);
                }
                std::filesystem::remove(state_temp_path, ec);
                std::filesystem::remove(metadata_temp_path, ec);
                std::filesystem::remove_all(trust_store_temp_path, ec);
                std::filesystem::remove_all(historical_trust_store_temp_path, ec);
                return false;
            }
            backed_xmls.push_back(xml_p);
        }
    }

    bool backed_state = false;
    if (ExistingFileHasContent(state_path)) {
        if (!MoveFilePath(state_path, state_backup_path)) {
            for (const auto& b : backed_xmls) {
                MoveFilePath(BackupPathFor(b), b);
            }
            for (const auto& p : xml_paths) {
                std::filesystem::remove(TempPathFor(p), ec);
            }
            std::filesystem::remove(state_temp_path, ec);
            std::filesystem::remove(metadata_temp_path, ec);
            std::filesystem::remove_all(trust_store_temp_path, ec);
            std::filesystem::remove_all(historical_trust_store_temp_path, ec);
            return false;
        }
        backed_state = true;
    }

    bool backed_metadata = false;
    if (ExistingFileHasContent(metadata_path)) {
        if (!MoveFilePath(metadata_path, metadata_backup_path)) {
            if (backed_state) {
                MoveFilePath(state_backup_path, state_path);
            }
            for (const auto& b : backed_xmls) {
                MoveFilePath(BackupPathFor(b), b);
            }
            for (const auto& p : xml_paths) {
                std::filesystem::remove(TempPathFor(p), ec);
            }
            std::filesystem::remove(state_temp_path, ec);
            std::filesystem::remove(metadata_temp_path, ec);
            std::filesystem::remove_all(trust_store_temp_path, ec);
            std::filesystem::remove_all(historical_trust_store_temp_path, ec);
            return false;
        }
        backed_metadata = true;
    }

    bool backed_trust_store = false;
    if (ExistingDirectory(trust_store_path)) {
        if (!MoveFilePath(trust_store_path, trust_store_backup_path)) {
            if (backed_metadata) {
                MoveFilePath(metadata_backup_path, metadata_path);
            }
            if (backed_state) {
                MoveFilePath(state_backup_path, state_path);
            }
            for (const auto& b : backed_xmls) {
                MoveFilePath(BackupPathFor(b), b);
            }
            for (const auto& p : xml_paths) {
                std::filesystem::remove(TempPathFor(p), ec);
            }
            std::filesystem::remove(state_temp_path, ec);
            std::filesystem::remove(metadata_temp_path, ec);
            std::filesystem::remove_all(trust_store_temp_path, ec);
            std::filesystem::remove_all(historical_trust_store_temp_path, ec);
            return false;
        }
        backed_trust_store = true;
    }

    bool backed_historical_trust_store = false;
    if (ExistingDirectory(historical_trust_store_path)) {
        if (!MoveFilePath(historical_trust_store_path, historical_trust_store_backup_path)) {
            if (backed_trust_store) {
                MoveFilePath(trust_store_backup_path, trust_store_path);
            }
            if (backed_metadata) {
                MoveFilePath(metadata_backup_path, metadata_path);
            }
            if (backed_state) {
                MoveFilePath(state_backup_path, state_path);
            }
            for (const auto& b : backed_xmls) {
                MoveFilePath(BackupPathFor(b), b);
            }
            for (const auto& p : xml_paths) {
                std::filesystem::remove(TempPathFor(p), ec);
            }
            std::filesystem::remove(state_temp_path, ec);
            std::filesystem::remove(metadata_temp_path, ec);
            std::filesystem::remove_all(trust_store_temp_path, ec);
            std::filesystem::remove_all(historical_trust_store_temp_path, ec);
            return false;
        }
        backed_historical_trust_store = true;
    }

    bool backed_tsa_store = false;
    if (ExistingDirectory(tsa_store_path)) {
        if (!MoveFilePath(tsa_store_path, tsa_store_backup_path)) {
            if (backed_historical_trust_store) {
                MoveFilePath(historical_trust_store_backup_path, historical_trust_store_path);
            }
            if (backed_trust_store) {
                MoveFilePath(trust_store_backup_path, trust_store_path);
            }
            if (backed_metadata) {
                MoveFilePath(metadata_backup_path, metadata_path);
            }
            if (backed_state) {
                MoveFilePath(state_backup_path, state_path);
            }
            for (const auto& b : backed_xmls) {
                MoveFilePath(BackupPathFor(b), b);
            }
            for (const auto& p : xml_paths) {
                std::filesystem::remove(TempPathFor(p), ec);
            }
            std::filesystem::remove(state_temp_path, ec);
            std::filesystem::remove(metadata_temp_path, ec);
            std::filesystem::remove_all(trust_store_temp_path, ec);
            std::filesystem::remove_all(historical_trust_store_temp_path, ec);
            std::filesystem::remove_all(tsa_store_temp_path, ec);
            std::filesystem::remove_all(historical_tsa_store_temp_path, ec);
            return false;
        }
        backed_tsa_store = true;
    }

    bool backed_historical_tsa_store = false;
    if (ExistingDirectory(historical_tsa_store_path)) {
        if (!MoveFilePath(historical_tsa_store_path, historical_tsa_store_backup_path)) {
            if (backed_tsa_store) {
                MoveFilePath(tsa_store_backup_path, tsa_store_path);
            }
            if (backed_historical_trust_store) {
                MoveFilePath(historical_trust_store_backup_path, historical_trust_store_path);
            }
            if (backed_trust_store) {
                MoveFilePath(trust_store_backup_path, trust_store_path);
            }
            if (backed_metadata) {
                MoveFilePath(metadata_backup_path, metadata_path);
            }
            if (backed_state) {
                MoveFilePath(state_backup_path, state_path);
            }
            for (const auto& b : backed_xmls) {
                MoveFilePath(BackupPathFor(b), b);
            }
            for (const auto& p : xml_paths) {
                std::filesystem::remove(TempPathFor(p), ec);
            }
            std::filesystem::remove(state_temp_path, ec);
            std::filesystem::remove(metadata_temp_path, ec);
            std::filesystem::remove_all(trust_store_temp_path, ec);
            std::filesystem::remove_all(historical_trust_store_temp_path, ec);
            std::filesystem::remove_all(tsa_store_temp_path, ec);
            std::filesystem::remove_all(historical_tsa_store_temp_path, ec);
            return false;
        }
        backed_historical_tsa_store = true;
    }

    // Move temps to final
    bool ok = true;
    for (std::size_t i = 0; i < xml_paths.size(); ++i) {
        ok = ok && ReplaceFileWithTemp(TempPathFor(xml_paths[i]), xml_paths[i]);
    }
    ok = ok && ReplaceFileWithTemp(state_temp_path, state_path);
    ok = ok && ReplaceFileWithTemp(metadata_temp_path, metadata_path);
    ok = ok && MoveFilePath(trust_store_temp_path, trust_store_path);
    ok = ok && MoveFilePath(historical_trust_store_temp_path, historical_trust_store_path);
    ok = ok && MoveFilePath(tsa_store_temp_path, tsa_store_path);
    ok = ok && MoveFilePath(historical_tsa_store_temp_path, historical_tsa_store_path);

    if (!ok) {
        std::filesystem::remove(state_path, ec);
        std::filesystem::remove(metadata_path, ec);
        std::filesystem::remove_all(trust_store_path, ec);
        std::filesystem::remove_all(historical_trust_store_path, ec);
        std::filesystem::remove_all(tsa_store_path, ec);
        std::filesystem::remove_all(historical_tsa_store_path, ec);
        for (const auto& xml_p : xml_paths) {
            std::filesystem::remove(xml_p, ec);
        }

        if (backed_historical_tsa_store) {
            MoveFilePath(historical_tsa_store_backup_path, historical_tsa_store_path);
        }
        if (backed_tsa_store) {
            MoveFilePath(tsa_store_backup_path, tsa_store_path);
        }
        if (backed_historical_trust_store) {
            MoveFilePath(historical_trust_store_backup_path, historical_trust_store_path);
        }
        if (backed_trust_store) {
            MoveFilePath(trust_store_backup_path, trust_store_path);
        }
        if (backed_metadata) {
            MoveFilePath(metadata_backup_path, metadata_path);
        }
        if (backed_state) {
            MoveFilePath(state_backup_path, state_path);
        }
        for (const auto& b : backed_xmls) {
            MoveFilePath(BackupPathFor(b), b);
        }

        for (const auto& p : xml_paths) {
            std::filesystem::remove(TempPathFor(p), ec);
        }
        std::filesystem::remove(state_temp_path, ec);
        std::filesystem::remove(metadata_temp_path, ec);
        std::filesystem::remove_all(trust_store_temp_path, ec);
        std::filesystem::remove_all(historical_trust_store_temp_path, ec);
        std::filesystem::remove_all(tsa_store_temp_path, ec);
        std::filesystem::remove_all(historical_tsa_store_temp_path, ec);
        return false;
    }

    // Clean backups & temps
    for (const auto& xml_p : xml_paths) {
        std::filesystem::remove(BackupPathFor(xml_p), ec);
        std::filesystem::remove(TempPathFor(xml_p), ec);
    }
    std::filesystem::remove(state_backup_path, ec);
    std::filesystem::remove(metadata_backup_path, ec);
    std::filesystem::remove_all(trust_store_backup_path, ec);
    std::filesystem::remove_all(historical_trust_store_backup_path, ec);
    std::filesystem::remove_all(tsa_store_backup_path, ec);
    std::filesystem::remove_all(historical_tsa_store_backup_path, ec);

    std::filesystem::remove(state_temp_path, ec);
    std::filesystem::remove(metadata_temp_path, ec);
    std::filesystem::remove_all(trust_store_temp_path, ec);
    std::filesystem::remove_all(historical_trust_store_temp_path, ec);
    std::filesystem::remove_all(tsa_store_temp_path, ec);
    std::filesystem::remove_all(historical_tsa_store_temp_path, ec);

    return true;
}

bool PolicyCache::ReadState(PolicyCacheState& state) const {
    std::string json;
    std::string read_error;
    if (!util::ReadTextFileLimited(StatePath(), util::kMaxCachedArtifactSize, json, read_error)) {
        return false;
    }
    const auto source_url = ExtractJsonString(json, "sourceUrl");
    const auto cache_status = ExtractJsonString(json, "cacheStatus");
    const auto last_sync = ExtractJsonString(json, "lastSync");
    const auto update_succeeded = ExtractJsonBool(json, "updateSucceeded");
    const auto etag = ExtractJsonString(json, "etag");
    const auto last_modified = ExtractJsonString(json, "lastModified");
    if (!source_url || !cache_status || !last_sync || !update_succeeded ||
        cache_status->empty() || last_sync->empty() || !ExistingFileHasContent(TrustListPath())) {
        return false;
    }

    state.source_url = *source_url;
    state.cache_status = *cache_status;
    state.last_sync = *last_sync;
    state.update_succeeded = *update_succeeded;
    if (etag) {
        state.etag = *etag;
    }
    if (last_modified) {
        state.last_modified = *last_modified;
    }
    return true;
}

std::string PolicyCache::ResolveGrantedTspUrl() const {
    std::string json;
    std::string read_error;
    if (!util::ReadTextFileLimited(TrustStoreMetadataPath(), util::kMaxCachedArtifactSize, json,
                                   read_error)) {
        return {};
    }

    for (const std::string& record : ExtractJsonObjectArray(json, "records")) {
        const auto service_type = ExtractJsonString(record, "serviceType");
        const bool is_tsa_service = service_type.has_value() &&
            (*service_type == "http://czo.gov.ua/TrstSvc/Svctype/MR-TSA/QTST" ||
             *service_type == "http://czo.gov.ua/TrstSvc/Svctype/National-TSA/QTST");
        if (!is_tsa_service) {
            continue;
        }
        const auto granted = ExtractJsonBool(record, "granted");
        if (!granted.has_value() || !*granted) {
            continue;
        }
        const auto tsp_urls = ExtractJsonStringArray(record, "tspUrls");
        if (!tsp_urls.empty() && !tsp_urls.front().empty()) {
            return tsp_urls.front();
        }
    }
    return {};
}

std::filesystem::path PolicyCache::TrustListPath() const {
    return TrustListPath("TL-UA-EC.xml");
}

std::filesystem::path PolicyCache::TrustListPath(const std::string& filename) const {
    return work_dir_ / "trust-list" / filename;
}

std::filesystem::path PolicyCache::StatePath() const {
    return work_dir_ / "trust-list" / "state.json";
}

std::filesystem::path PolicyCache::TrustStoreMetadataPath() const {
    return PolicyDir() / "trust-store-metadata.json";
}

std::filesystem::path PolicyCache::TrustStoreDir() const {
    return work_dir_ / "trust-store";
}

std::filesystem::path PolicyCache::HistoricalTrustStoreDir() const {
    return work_dir_ / "historical-trust-store";
}

std::filesystem::path PolicyCache::IntermediateStoreDir() const {
    return work_dir_ / "intermediate-store";
}

std::filesystem::path PolicyCache::CrlStoreDir() const {
    return work_dir_ / "crl-store";
}

std::filesystem::path PolicyCache::PolicyDir() const {
    return work_dir_ / "policy";
}

} // namespace tamga::core::policy
