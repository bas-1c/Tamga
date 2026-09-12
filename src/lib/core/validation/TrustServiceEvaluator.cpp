#include "core/validation/TrustServiceEvaluator.h"
#include "core/policy/TrustListParser.h"
#include <filesystem>
#include <algorithm>
#include <cctype>

namespace tamga::core::validation {

std::filesystem::path TrustServiceEvaluator::SelectSnapshot(
    const std::string& work_dir,
    const std::string& trust_list_reference_time,
    bool strict_current_tl) 
{
    const std::filesystem::path work_path = std::filesystem::u8path(work_dir);
    const auto current_tl = work_path / "trust-list" / "TL-UA-EC.xml";
    if (trust_list_reference_time.empty() || strict_current_tl) {
        return current_tl;
    }
    
    if (trust_list_reference_time.size() < 7) {
        return current_tl;
    }
    
    std::string ref_ym = trust_list_reference_time.substr(0, 7); // "YYYY-MM"
    std::filesystem::path history_dir = work_path / "trust-list" / "history";
    
    std::error_code ec;
    if (!std::filesystem::exists(history_dir, ec) || !std::filesystem::is_directory(history_dir, ec)) {
        return current_tl;
    }
    
    std::string best_ym;
    std::filesystem::path best_path;
    std::string earliest_ym;
    std::filesystem::path earliest_path;
    
    for (const auto& entry : std::filesystem::directory_iterator(history_dir, ec)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        std::string filename = entry.path().filename().u8string();
        if (filename.size() == 20 && 
            filename.compare(0, 9, "TL-UA-EC-") == 0 && 
            filename.compare(16, 4, ".xml") == 0) {
            
            std::string file_ym = filename.substr(9, 7); // "YYYY-MM"
            if (file_ym[4] == '-' && 
                std::isdigit(static_cast<unsigned char>(file_ym[0])) && 
                std::isdigit(static_cast<unsigned char>(file_ym[1])) && 
                std::isdigit(static_cast<unsigned char>(file_ym[2])) && 
                std::isdigit(static_cast<unsigned char>(file_ym[3])) && 
                std::isdigit(static_cast<unsigned char>(file_ym[5])) && 
                std::isdigit(static_cast<unsigned char>(file_ym[6]))) {
                
                if (earliest_ym.empty() || file_ym < earliest_ym) {
                    earliest_ym = file_ym;
                    earliest_path = entry.path();
                }
                
                if (file_ym <= ref_ym) {
                    if (best_ym.empty() || file_ym > best_ym) {
                        best_ym = file_ym;
                        best_path = entry.path();
                    }
                }
            }
        }
    }
    
    if (!best_path.empty()) {
        return best_path;
    }
    if (!earliest_path.empty()) {
        return earliest_path;
    }
    return current_tl;
}

TrustServiceDecision TrustServiceEvaluator::Evaluate(
    const std::vector<std::uint8_t>& certificate_der,
    const std::string& trust_list_xml,
    const std::string& snapshot_evidence_id) const 
{
    TrustServiceDecision decision;
    decision.checked = true;
    decision.snapshot_evidence_id = snapshot_evidence_id;

    if (certificate_der.empty()) {
        decision.service_trusted = false;
        decision.limitations.push_back("empty certificate provided");
        return decision;
    }

    tamga::core::policy::TrustListParser parser;
    const auto parse_result = parser.Parse(trust_list_xml);
    if (!parse_result.ok) {
        decision.service_trusted = false;
        decision.limitations.push_back("failed to parse trust list: " + parse_result.message);
        return decision;
    }

    for (const auto& service : parse_result.services) {
        for (const auto& cert : service.certificates) {
            if (cert == certificate_der) {
                decision.service_type = service.service_type;
                decision.status = service.status;
                
                if (service.status.find("/granted") != std::string::npos) {
                    decision.service_trusted = true;
                } else {
                    decision.service_trusted = false;
                    decision.limitations.push_back("service status is not granted: " + service.status);
                }
                return decision;
            }
        }
    }

    decision.service_trusted = false;
    decision.limitations.push_back("service record not found in trust list");
    return decision;
}

} // namespace tamga::core::validation
