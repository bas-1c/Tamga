#include "core/policy/TrustListSync.h"

#include "core/HttpClient.h"
#include "core/policy/PolicyCache.h"
#include "core/policy/Sha256Helper.h"
#include "core/policy/TlXmlSigCheck.h"
#include "core/cryptonite/CertUtil.h"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <fstream>

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
namespace {

std::string UtcNowIsoString() {
    const std::time_t now = std::time(nullptr);
    std::tm utc_tm{};
#ifdef _WIN32
    if (gmtime_s(&utc_tm, &now) != 0) {
        return {};
    }
#else
    if (gmtime_r(&now, &utc_tm) == nullptr) {
        return {};
    }
#endif

    std::ostringstream out;
    out << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

// ADR-027: копія прибрана — спільна реалізація в `core/HttpClient.h`.
using tamga::core::IsHttpSuccess;

bool HasMaterializableTrustAnchor(const TrustListParseResult& parsed, bool is_historical) {
    (void)is_historical;
    for (const auto& service : parsed.services) {
        const bool granted =
            service.status == "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/granted" ||
            service.status == "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted" ||
            service.status == "http://czo.gov.ua/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel" ||
            service.status == "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";
        if (!granted) {
            continue;
        }
#if TAMGA_CRYPTONITE_ENABLED
        for (const auto& certificate_der : service.certificates) {
            ByteArray* ba = certificate_der.empty()
                ? nullptr
                : ba_alloc_from_uint8(certificate_der.data(), certificate_der.size());
            Certificate_t* cert = cert_alloc();
            if (ba == nullptr || cert == nullptr || cert_decode(cert, ba) != RET_OK) {
                ba_free(ba);
                cert_free(cert);
                continue;
            }
            ba_free(ba);

            ByteArray* basic_constraints_ext = nullptr;
            bool is_ca = false;
            if (cert_get_ext_value(cert,
                                   oids_get_oid_numbers_by_id(OID_BASIC_CONSTRAINTS_EXTENSION_ID),
                                   &basic_constraints_ext) == RET_OK &&
                basic_constraints_ext != nullptr) {
                auto* basic_constraints = static_cast<BasicConstraints_t*>(
                    asn_decode_with_alloc(get_BasicConstraints_desc(),
                                          ba_get_buf(basic_constraints_ext),
                                          ba_get_len(basic_constraints_ext)));
                is_ca = basic_constraints != nullptr &&
                        basic_constraints->cA != nullptr &&
                        *basic_constraints->cA != 0;
                ASN_FREE(get_BasicConstraints_desc(), basic_constraints);
            }
            ba_free(basic_constraints_ext);

            // Відсутнє розширення keyUsage = обмежень немає; розбір — одна
            // копія на проєкт (`cryptonite_detail::CertificateAllowsKeyUsage`).
            const bool key_cert_sign =
                tamga::core::cryptonite_detail::CertificateAllowsKeyUsage(cert, KeyUsage_keyCertSign);
            cert_free(cert);

            const bool is_ca_service = (service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/CA/QC" ||
                                        service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/MR-CA/QC" ||
                                        service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/NationalRootCA-QC");
            const bool is_tsa_service = (service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/TSA/QTST" ||
                                         service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/MR-TSA/QTST" ||
                                         service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/National-TSA/QTST" ||
                                         service.service_type == "http://czo.gov.ua/TrstSvc/Svctype/MR-TSA/QTST");

            if (is_tsa_service || (is_ca && (key_cert_sign || is_ca_service))) {
                return true;
            }
        }
#else
        (void)service;
        (void)is_historical;
#endif
    }
    return false;
}

std::string ExtractHeaderValue(const std::string& headers, const std::string& name) {
    std::string lower_headers = headers;
    std::transform(lower_headers.begin(), lower_headers.end(), lower_headers.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    size_t pos = lower_headers.find(lower_name + ":");
    if (pos == std::string::npos) {
        return "";
    }
    size_t val_start = pos + lower_name.size() + 1;
    while (val_start < headers.size() && std::isspace(static_cast<unsigned char>(headers[val_start])) != 0 && headers[val_start] != '\r' && headers[val_start] != '\n') {
        val_start++;
    }
    size_t val_end = headers.find_first_of("\r\n", val_start);
    if (val_end == std::string::npos) {
        val_end = headers.size();
    }
    return headers.substr(val_start, val_end - val_start);
}

std::string ExtractSha256(const std::string& sha2_content) {
    std::string hex;
    for (char c : sha2_content) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            hex.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        } else if (!hex.empty() && hex.size() == 64) {
            break;
        } else {
            hex.clear();
        }
    }
    if (hex.size() == 64) {
        return hex;
    }
    return "";
}

std::string ExtractListIssueDateTime(const std::string& xml) {
    size_t pos = xml.find("<ListIssueDateTime>");
    if (pos == std::string::npos) {
        return "";
    }
    size_t end_pos = xml.find("</ListIssueDateTime>", pos);
    if (end_pos == std::string::npos) {
        return "";
    }
    size_t start = pos + std::string("<ListIssueDateTime>").size();
    return xml.substr(start, end_pos - start);
}

void ArchiveMonthlySnapshot(const std::filesystem::path& work_dir, const std::string& filename, const std::vector<std::uint8_t>& xml_data) {
    if (filename != "TL-UA-EC.xml") {
        return;
    }
    std::string xml(xml_data.begin(), xml_data.end());
    std::string issue_date = ExtractListIssueDateTime(xml);
    std::string yyyy_mm;
    if (issue_date.size() >= 7 && std::isdigit(issue_date[0]) && std::isdigit(issue_date[1]) &&
        std::isdigit(issue_date[2]) && std::isdigit(issue_date[3]) && issue_date[4] == '-' &&
        std::isdigit(issue_date[5]) && std::isdigit(issue_date[6])) {
        yyyy_mm = issue_date.substr(0, 7);
    } else {
        const std::time_t now = std::time(nullptr);
        std::tm utc_tm{};
#ifdef _WIN32
        if (gmtime_s(&utc_tm, &now) == 0) {
#else
        if (gmtime_r(&now, &utc_tm) != nullptr) {
#endif
            std::ostringstream os;
            os << std::setw(4) << std::setfill('0') << (utc_tm.tm_year + 1900)
               << '-' << std::setw(2) << std::setfill('0') << (utc_tm.tm_mon + 1);
            yyyy_mm = os.str();
        }
    }

    if (!yyyy_mm.empty()) {
        std::error_code ec;
        std::filesystem::path history_dir = work_dir / "trust-list" / "history";
        std::filesystem::create_directories(history_dir, ec);
        std::filesystem::path history_file = history_dir / ("TL-UA-EC-" + yyyy_mm + ".xml");

        std::ofstream out(history_file, std::ios::binary | std::ios::trunc);
        if (out.is_open()) {
            out.write(reinterpret_cast<const char*>(xml_data.data()), xml_data.size());
        }
    }
}

struct TrustListInfo {
    std::string url;
    std::string filename;
    bool is_historical;
};

std::vector<TrustListInfo> ResolveTrustLists(const std::string& configured_url) {
    std::vector<TrustListInfo> lists;
    if (configured_url.find("TL-UA-EC.xml") != std::string::npos) {
        size_t pos = configured_url.find("TL-UA-EC.xml");
        std::string base = configured_url.substr(0, pos);
        lists.push_back({base + "TL-UA.xml", "TL-UA.xml", false});
        lists.push_back({base + "TL-UA-DSTU.xml", "TL-UA-DSTU.xml", true});
        lists.push_back({base + "TL-UA-EC.xml", "TL-UA-EC.xml", false});
    } else if (configured_url.find("TL-UA.xml") != std::string::npos) {
        size_t pos = configured_url.find("TL-UA.xml");
        std::string base = configured_url.substr(0, pos);
        lists.push_back({base + "TL-UA.xml", "TL-UA.xml", false});
        lists.push_back({base + "TL-UA-DSTU.xml", "TL-UA-DSTU.xml", true});
        lists.push_back({base + "TL-UA-EC.xml", "TL-UA-EC.xml", false});
    } else if (configured_url.find("TL-UA-DSTU.xml") != std::string::npos) {
        size_t pos = configured_url.find("TL-UA-DSTU.xml");
        std::string base = configured_url.substr(0, pos);
        lists.push_back({base + "TL-UA.xml", "TL-UA.xml", false});
        lists.push_back({base + "TL-UA-DSTU.xml", "TL-UA-DSTU.xml", true});
        lists.push_back({base + "TL-UA-EC.xml", "TL-UA-EC.xml", false});
    } else {
        lists.push_back({configured_url, "TL-UA-EC.xml", false});
    }
    return lists;
}

TrustListSyncResult FailureResult(const TrustListSyncResult& base, const PolicyCache& cache, std::string message) {
    TrustListSyncResult result = base;
    result.succeeded = false;
    result.message = std::move(message);

    PolicyCacheState cached_state;
    if (cache.ReadState(cached_state)) {
        result.used_cache = true;
        result.cache_status = cached_state.cache_status.empty() ? "stale" : cached_state.cache_status;
        result.last_sync = cached_state.last_sync;
        return result;
    }

    result.used_cache = false;
    result.cache_status = "unavailable";
    return result;
}

} // namespace

TrustListSyncResult TrustListSync::Sync(const std::string& work_dir, const TrustListSettings& settings) const {
    TrustListSyncResult result;
    result.source_url = settings.url;
    result.last_sync = UtcNowIsoString();
    PolicyCache cache(work_dir);

    if (result.source_url.empty()) {
        return FailureResult(result, cache, "Trust list URL is empty");
    }
    if (!settings.allow_https_bootstrap) {
        return FailureResult(result, cache, "HTTPS trust list bootstrap is disabled");
    }

    const auto lists_to_sync = ResolveTrustLists(settings.url);
    std::vector<PolicyCacheEntry> entries;
    entries.reserve(lists_to_sync.size());

    std::string main_etag;
    std::string main_last_modified;

    for (const auto& info : lists_to_sync) {
        const auto response = tamga::core::HttpClient::Get(info.url,
                                                          "application/xml",
                                                          settings.timeout_ms);
        if (!IsHttpSuccess(response)) {
            std::ostringstream message;
            message << "Trust list download failed for " << info.url;
            if (response.status_code != 0) {
                message << ": HTTP " << response.status_code;
            }
            if (!response.message.empty()) {
                message << ": " << response.message;
            }
            return FailureResult(result, cache, message.str());
        }

        // Fetch SHA-256 hash file
        std::string sha2_url = info.url;
        size_t xml_ext_pos = sha2_url.rfind(".xml");
        if (xml_ext_pos != std::string::npos) {
            sha2_url.replace(xml_ext_pos, 4, ".sha2");
        } else {
            sha2_url += ".sha2";
        }

        const auto sha2_response = tamga::core::HttpClient::Get(sha2_url,
                                                               "text/plain",
                                                               settings.timeout_ms);
        if (!IsHttpSuccess(sha2_response)) {
            std::ostringstream message;
            message << "Trust list SHA-256 download failed for " << sha2_url;
            if (sha2_response.status_code != 0) {
                message << ": HTTP " << sha2_response.status_code;
            }
            return FailureResult(result, cache, message.str());
        }

        // Verify SHA-256 integrity
        std::string computed_hash = LowerHex(Sha256(response.body));
        std::string expected_hash = ExtractSha256(std::string(sha2_response.body.begin(), sha2_response.body.end()));
        if (expected_hash.empty() || computed_hash != expected_hash) {
            return FailureResult(result, cache, "SHA-256 integrity check failed for " + info.url + " (expected: " + expected_hash + ", got: " + computed_hash + ")");
        }

        // S-002 / B-3: TL XML signature verification (ETSI TS 119 612 §5.7).
        //
        // Previously `not_supported` (build without the XMLDSIG engine) fell through
        // this block as if verification had succeeded — a fail-open path: the caller
        // could not distinguish "signature verified" from "signature never checked".
        // Verification requested but impossible is now a hard failure, and the
        // outcome is always recorded in result.xml_signature_status.
        using XmlSigPolicy = TrustListSettings::XmlSignaturePolicy;
        if (settings.xml_signature_policy == XmlSigPolicy::Disabled) {
            result.xml_signature_status = "not-verified-disabled";
        } else {
            const std::string xml_str(response.body.begin(), response.body.end());
            const auto sig_check = VerifyTlXmlSignature(xml_str, settings.xml_signer_cert_der);
            if (sig_check.not_supported) {
                // The old code fell through here as if verification had succeeded.
                // Require -> abort; PreferAvailable -> continue, but say so explicitly.
                result.xml_signature_status = "not-verified-unsupported";
                if (settings.xml_signature_policy == XmlSigPolicy::Require) {
                    return FailureResult(result, cache,
                        "TL XML signature verification is required but this build has no XMLDSIG "
                        "engine (rebuild with TAMGA_ENABLE_XML_SIGNATURES=ON, or relax "
                        "xml_signature_policy): " + info.url);
                }
            } else if (!sig_check.succeeded) {
                // A verification that ran and rejected the document is always fatal,
                // regardless of policy — that is a real signature failure, not a gap.
                result.xml_signature_status = "failed";
                return FailureResult(result, cache,
                    "TL XML signature verification failed for " + info.url + ": " + sig_check.error);
            } else {
                result.xml_signature_status = settings.xml_signer_cert_der.empty()
                                                  ? "verified-self-consistent"
                                                  : "verified-pinned";
            }
        }

        TrustListParser parser;
        auto parsed = parser.Parse(std::string(response.body.begin(), response.body.end()));
        if (!parsed.ok) {
            return FailureResult(result, cache, "Failed to parse trust list: " + parsed.message);
        }

        if (!HasMaterializableTrustAnchor(parsed, info.is_historical)) {
            return FailureResult(result, cache, "Trust list does not contain granted CA certificates: " + info.url);
        }

        // Save ETag & Last-Modified for the main/first URL
        if (info.filename == "TL-UA-EC.xml" || main_etag.empty()) {
            main_etag = ExtractHeaderValue(response.response_headers, "ETag");
            main_last_modified = ExtractHeaderValue(response.response_headers, "Last-Modified");
        }

        PolicyCacheEntry entry;
        entry.filename = info.filename;
        entry.xml = response.body;
        entry.parsed = std::move(parsed);
        entry.is_historical = info.is_historical;
        entries.push_back(std::move(entry));
    }

    PolicyCacheState state;
    state.source_url = result.source_url;
    state.cache_status = "fresh";
    state.last_sync = result.last_sync;
    state.update_succeeded = true;
    state.etag = main_etag;
    state.last_modified = main_last_modified;

    if (!cache.WriteTrustListsMaterialized(entries, state)) {
        return FailureResult(result, cache, "Failed to write trust lists cache");
    }

    // Archive monthly snapshots for TL-UA-EC
    for (const auto& entry : entries) {
        ArchiveMonthlySnapshot(std::filesystem::path(std::filesystem::u8path(work_dir)), entry.filename, entry.xml);
    }

    // Populate combined parsed results for output
    result.parsed.ok = true;
    result.parsed.message = "All trust lists synchronized and parsed";
    for (const auto& entry : entries) {
        result.parsed.certificates.insert(result.parsed.certificates.end(),
                                          entry.parsed.certificates.begin(),
                                          entry.parsed.certificates.end());
        result.parsed.services.insert(result.parsed.services.end(),
                                      entry.parsed.services.begin(),
                                      entry.parsed.services.end());
        result.parsed.endpoints.crl_urls.insert(result.parsed.endpoints.crl_urls.end(),
                                                entry.parsed.endpoints.crl_urls.begin(),
                                                entry.parsed.endpoints.crl_urls.end());
        result.parsed.endpoints.ocsp_urls.insert(result.parsed.endpoints.ocsp_urls.end(),
                                                 entry.parsed.endpoints.ocsp_urls.begin(),
                                                 entry.parsed.endpoints.ocsp_urls.end());
        result.parsed.endpoints.tsp_urls.insert(result.parsed.endpoints.tsp_urls.end(),
                                                entry.parsed.endpoints.tsp_urls.begin(),
                                                entry.parsed.endpoints.tsp_urls.end());
    }

    result.succeeded = true;
    result.used_cache = false;
    result.cache_status = "fresh";
    result.message = "Trust lists synchronized";
    return result;
}

} // namespace tamga::core::policy
