#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::core {

class TspClient final {
public:
    static bool GetTimestamp(const std::vector<std::uint8_t>& hashed_data,
                             const std::string& hash_alg_oid,
                             const std::string& tsp_server_url,
                             std::int32_t timeout_ms,
                             const std::string& policy_oid,
                             std::vector<std::uint8_t>& out_timestamp_token,
                             std::string& error_message);
};

} // namespace tamga::core
