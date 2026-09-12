#include "core/validation/PolicyResolver.h"

#include <filesystem>
#include <string>

namespace tamga::core::validation {
namespace {

bool IsKnownProfile(const ValidationProfile profile) {
    return profile == ValidationProfile::Strict ||
           profile == ValidationProfile::Compatibility ||
           profile == ValidationProfile::UkraineLegal ||
           profile == ValidationProfile::Offline ||
           profile == ValidationProfile::Forensic;
}

bool IsKnownLevel(const ValidationLevel level) {
    return level == ValidationLevel::Basic ||
           level == ValidationLevel::Standard ||
           level == ValidationLevel::Extended ||
           level == ValidationLevel::Forensic;
}

bool IsStandardOrHigher(const ValidationLevel level) {
    return level == ValidationLevel::Standard ||
           level == ValidationLevel::Extended ||
           level == ValidationLevel::Forensic;
}

bool IsExtendedOrHigher(const ValidationLevel level) {
    return level == ValidationLevel::Extended ||
           level == ValidationLevel::Forensic;
}

std::string PathToUtf8String(const std::filesystem::path& path) {
    const auto utf8 = path.u8string();
#if defined(__cpp_char8_t)
    return std::string(reinterpret_cast<const char*>(utf8.data()), utf8.size());
#else
    return utf8;
#endif
}

void ResolveWorkDirPaths(const std::string& work_dir, ValidationPlan& plan) {
    if (work_dir.empty()) {
        return;
    }

    const std::filesystem::path work_dir_path = std::filesystem::u8path(work_dir);
    plan.trust_store_path = PathToUtf8String(work_dir_path / "trust-store");
    plan.historical_trust_store_path = PathToUtf8String(work_dir_path / "historical-trust-store");
}

} // namespace

ResolvedValidationPolicy PolicyResolver::Resolve(const ValidationContext& context) const {
    ResolvedValidationPolicy resolved;

    ResolveWorkDirPaths(context.work_dir, resolved.plan);

    if (!IsKnownProfile(context.profile) || !IsKnownLevel(context.level)) {
        resolved.plan.network_allowed = false;
        resolved.policy.revocation_hard_fail = true;
        return resolved;
    }

    resolved.plan.network_allowed = !context.offline;

    switch (context.profile) {
        case ValidationProfile::Strict:
            resolved.policy.trust_anchor_policy = TrustAnchorPolicy::CurrentTLOnly;
            resolved.policy.revocation_hard_fail = IsStandardOrHigher(context.level);
            break;

        case ValidationProfile::Compatibility:
            resolved.policy.trust_anchor_policy = TrustAnchorPolicy::ExplicitLegacyAnchorBundle;
            resolved.policy.allow_historical_trust = true;
            resolved.policy.revocation_hard_fail = IsExtendedOrHigher(context.level);
            break;

        case ValidationProfile::UkraineLegal:
            resolved.policy.trust_anchor_policy = TrustAnchorPolicy::HistoricalAtSigningTime;
            resolved.policy.allow_historical_trust = true;
            resolved.policy.revocation_hard_fail = IsStandardOrHigher(context.level);
            resolved.policy.require_trusted_signing_time = IsExtendedOrHigher(context.level);
            resolved.policy.require_service_level_trust = IsExtendedOrHigher(context.level);
            break;

        case ValidationProfile::Offline:
            resolved.policy.trust_anchor_policy = TrustAnchorPolicy::CustomTrustStore;
            resolved.policy.revocation_hard_fail = IsStandardOrHigher(context.level);
            resolved.plan.network_allowed = false;
            break;

        case ValidationProfile::Forensic:
            resolved.policy.trust_anchor_policy = TrustAnchorPolicy::ForensicAllPossible;
            resolved.policy.revocation_hard_fail = IsStandardOrHigher(context.level);
            resolved.policy.forensic_diagnostics = true;
            break;
    }

    return resolved;
}

} // namespace tamga::core::validation
