#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::core::policy {

struct AiaIssuerFetchInput {
    bool network_enabled{false};
    std::string work_dir;
    std::int32_t timeout_ms{10000};
    std::size_t max_depth{6};
    std::size_t max_urls{16};
    std::size_t max_retries{2};
    std::vector<std::vector<std::uint8_t>> seed_certificates_der;
};

struct AiaIssuerFetchResult {
    bool attempted{false};
    std::size_t downloaded_count{0};
    std::size_t cached_count{0};
    std::string message;
    std::string debug_log;
    std::vector<std::vector<std::uint8_t>> certificates_der;
};

class AiaIssuerFetcher final {
public:
    AiaIssuerFetchResult FetchMissingIssuers(const AiaIssuerFetchInput& input) const;

    static std::vector<std::string> ExtractCaIssuersUrls(const std::vector<std::uint8_t>& certificate_der);
    static std::vector<std::vector<std::uint8_t>> ParseDownloadedCertificates(
        const std::vector<std::uint8_t>& body,
        std::string& error_message);
};

} // namespace tamga::core::policy
