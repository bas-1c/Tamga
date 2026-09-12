#pragma once

#include "core/policy/PolicyTypes.h"

namespace tamga::core {
struct VerifyReport;
}

namespace tamga::core::policy {

void ApplyPolicyDecision(const PolicyValidationResult& policy_result, VerifyReport& report);

} // namespace tamga::core::policy
