#include "core/policy/PolicyDecision.h"

#include "core/Session.h"

namespace tamga::core::policy {

void ApplyPolicyDecision(const PolicyValidationResult& policy_result, VerifyReport& report) {
    report.trust_checked = policy_result.trust_checked;
    report.trust_valid = policy_result.trust_valid;
    report.revocation_checked = policy_result.revocation_checked;
    report.ocsp_checked = policy_result.ocsp_checked;
    report.tsp_checked = policy_result.tsp_checked;
    report.timestamp_checked = policy_result.timestamp_checked;
    report.timestamp_valid = policy_result.timestamp_valid;
    report.chain_checked = policy_result.chain_checked;
    report.chain_valid = policy_result.chain_valid;
    report.policy = policy_result.policy;
    report.trust_status = policy_result.trust_status;
    report.revocation_status = policy_result.revocation_status_text;
    if (!policy_result.message.empty()) {
        report.message = policy_result.message;
    }
}

} // namespace tamga::core::policy
