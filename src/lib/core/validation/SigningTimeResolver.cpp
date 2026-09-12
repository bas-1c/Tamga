#include "core/validation/SigningTimeResolver.h"
#include "util/Vectors.h"

#include <algorithm>
#include <string>

namespace tamga::core::validation {
namespace {

constexpr char kRfc3161TimestampNotCryptographicallyValid[] = "rfc3161-timestamp-not-cryptographically-valid";
constexpr char kRfc3161TimestampNotTrusted[] = "rfc3161-timestamp-not-trusted";
constexpr char kRfc3161TimestampTimeUnavailable[] = "rfc3161-timestamp-time-unavailable";
constexpr char kClaimedSigningTimeNotCryptographicallyProven[] = "claimed-signing-time-not-cryptographically-proven";
constexpr char kVerificationTimeFallbackUsed[] = "verification-time-fallback-used";
constexpr char kSigningTimeDerivedFromVerificationTime[] = "signing-time-derived-from-verification-time";
constexpr char kSigningTimeUnavailable[] = "signing-time-unavailable";
constexpr char kTrustedSigningTimeRequired[] = "trusted-signing-time-required";

// ADR-027: копія прибрана — шаблон живе в `util/Vectors.h`.
using tamga::util::AppendAll;

std::string WithEvidenceId(const char* code, const std::string& evidence_id) {
    if (evidence_id.empty()) {
        return code;
    }
    return std::string(code) + ":" + evidence_id;
}

void ApplyTrustedTimeRequirement(SigningTimeResolution& resolution, const ValidationPolicy& policy) {
    if (policy.require_trusted_signing_time && !resolution.trusted_time) {
        resolution.limitations.push_back(kTrustedSigningTimeRequired);
    }
}

void CollectSkippedRfc3161Diagnostics(const std::vector<SigningTimeCandidate>& candidates,
                                      SigningTimeResolution& resolution) {
    for (const auto& candidate : candidates) {
        if (candidate.source != SigningTimeSource::Rfc3161Timestamp) {
            continue;
        }

        if (!candidate.cryptographically_valid) {
            resolution.warnings.push_back(WithEvidenceId(kRfc3161TimestampNotCryptographicallyValid,
                                                         candidate.evidence_id));
        }
        if (!candidate.trusted) {
            resolution.limitations.push_back(WithEvidenceId(kRfc3161TimestampNotTrusted, candidate.evidence_id));
        }
        if (candidate.time.empty()) {
            resolution.limitations.push_back(WithEvidenceId(kRfc3161TimestampTimeUnavailable, candidate.evidence_id));
        }
        AppendAll(resolution.warnings, candidate.warnings);
    }
}

} // namespace

SigningTimeResolution SigningTimeResolver::Resolve(const std::vector<SigningTimeCandidate>& candidates,
                                                   const ValidationContext& context,
                                                   const ValidationPolicy& policy) const {
    const auto trusted_timestamp = std::find_if(candidates.begin(), candidates.end(), [](const auto& candidate) {
        return candidate.source == SigningTimeSource::Rfc3161Timestamp &&
               candidate.cryptographically_valid &&
               candidate.trusted &&
               !candidate.time.empty();
    });
    if (trusted_timestamp != candidates.end()) {
        SigningTimeResolution resolution;
        resolution.signature_evaluation_time = trusted_timestamp->time;
        resolution.source = SigningTimeSource::Rfc3161Timestamp;
        resolution.confidence = SigningTimeConfidence::Trusted;
        resolution.evidence_id = trusted_timestamp->evidence_id;
        AppendAll(resolution.warnings, trusted_timestamp->warnings);
        resolution.trusted_time = true;
        return resolution;
    }

    SigningTimeResolution resolution;
    CollectSkippedRfc3161Diagnostics(candidates, resolution);

    const auto claimed_time = std::find_if(candidates.begin(), candidates.end(), [](const auto& candidate) {
        return candidate.source == SigningTimeSource::ClaimedSigningTime && !candidate.time.empty();
    });
    if (claimed_time != candidates.end()) {
        resolution.signature_evaluation_time = claimed_time->time;
        resolution.source = SigningTimeSource::ClaimedSigningTime;
        resolution.confidence = SigningTimeConfidence::Claimed;
        resolution.evidence_id = claimed_time->evidence_id;
        resolution.trusted_time = false;
        AppendAll(resolution.warnings, claimed_time->warnings);
        if (!claimed_time->cryptographically_valid) {
            resolution.warnings.push_back(kClaimedSigningTimeNotCryptographicallyProven);
        }
        ApplyTrustedTimeRequirement(resolution, policy);
        return resolution;
    }

    if (!context.verification_time.empty()) {
        resolution.signature_evaluation_time = context.verification_time;
        resolution.source = SigningTimeSource::VerificationTimeFallback;
        resolution.confidence = SigningTimeConfidence::Fallback;
        resolution.trusted_time = false;
        resolution.warnings.push_back(kVerificationTimeFallbackUsed);
        resolution.limitations.push_back(kSigningTimeDerivedFromVerificationTime);
        ApplyTrustedTimeRequirement(resolution, policy);
        return resolution;
    }

    resolution.limitations.push_back(kSigningTimeUnavailable);
    ApplyTrustedTimeRequirement(resolution, policy);
    return resolution;
}

} // namespace tamga::core::validation
