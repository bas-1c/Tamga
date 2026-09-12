#pragma once

#include <string>
#include <vector>
#include <filesystem>

namespace tamga::core::validation {

struct TrustServiceDecision {
    bool checked{false};
    bool service_trusted{false};
    std::string service_type;
    std::string status;
    std::string snapshot_evidence_id;
    std::vector<std::string> limitations;
};

class TrustServiceEvaluator final {
public:
    static std::filesystem::path SelectSnapshot(
        const std::string& work_dir,
        const std::string& trust_list_reference_time,
        bool strict_current_tl);

    TrustServiceDecision Evaluate(
        const std::vector<std::uint8_t>& certificate_der,
        const std::string& trust_list_xml,
        const std::string& snapshot_evidence_id) const;
};

} // namespace tamga::core::validation
