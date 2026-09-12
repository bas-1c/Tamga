#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::core::policy {

struct TrustListEndpoints {
    std::vector<std::string> crl_urls;
    std::vector<std::string> ocsp_urls;
    std::vector<std::string> tsp_urls;
};

struct TrustListServiceRecord {
    std::string provider_name;
    std::string service_type;
    std::string status;
    std::string subject_name;
    std::vector<std::vector<std::uint8_t>> certificates;
    TrustListEndpoints endpoints;
};

struct TrustListParseResult {
    bool ok{false};
    std::string message;
    std::vector<std::vector<std::uint8_t>> certificates;
    TrustListEndpoints endpoints;
    std::vector<TrustListServiceRecord> services;
};

class TrustListParser final {
public:
    TrustListParseResult Parse(const std::string& xml) const;
};

} // namespace tamga::core::policy
