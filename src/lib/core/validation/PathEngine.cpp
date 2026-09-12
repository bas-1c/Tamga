#include "core/validation/PathEngine.h"

#include "core/policy/CertificateChainValidator.h"

#include <utility>

namespace tamga::core::validation {
namespace {

PathCandidate MakeCandidate(const PathBuilderInput& input,
                            std::string candidate_id,
                            std::string trust_anchor_source,
                            std::vector<std::vector<std::uint8_t>> trust_anchors,
                            const bool uses_historical_trust) {
    PathCandidate candidate;
    candidate.candidate_id = std::move(candidate_id);
    candidate.trust_anchor_source = std::move(trust_anchor_source);
    candidate.signer_certificate_der = input.signer_certificate_der;
    candidate.embedded_certificates_der = input.embedded_certificates_der;
    candidate.intermediate_certificates_der = input.intermediate_store_certificates_der;
    candidate.aia_certificates_der = input.aia_certificates_der;
    candidate.trust_anchors_der = std::move(trust_anchors);
    candidate.uses_historical_trust = uses_historical_trust;
    candidate.validation_time = input.validation_time;
    return candidate;
}

void AddCurrentCandidate(std::vector<PathCandidate>& candidates,
                         const PathBuilderInput& input,
                         const char* candidate_id,
                         const char* trust_anchor_source) {
    candidates.push_back(MakeCandidate(input,
                                       candidate_id,
                                       trust_anchor_source,
                                       input.current_trust_anchors_der,
                                       false));
}

void AddHistoricalCandidateIfAllowed(std::vector<PathCandidate>& candidates,
                                     const PathBuilderInput& input,
                                     const char* candidate_id) {
    if (input.policy.allow_historical_trust && !input.historical_trust_anchors_der.empty()) {
        candidates.push_back(MakeCandidate(input,
                                           candidate_id,
                                           "historical-tl",
                                           input.historical_trust_anchors_der,
                                           true));
    }
}

bool IsAuthoritativeCandidateAllowed(const PathValidationResult& result,
                                     const ValidationPolicy& policy) {
    return !result.uses_historical_trust || policy.allow_historical_trust;
}

} // namespace

std::vector<PathCandidate> PathBuilder::Build(const PathBuilderInput& input) const {
    std::vector<PathCandidate> candidates;

    switch (input.policy.trust_anchor_policy) {
        case TrustAnchorPolicy::CurrentTLOnly:
            AddCurrentCandidate(candidates, input, "current-tl", "current-tl");
            break;
        case TrustAnchorPolicy::ExplicitLegacyAnchorBundle:
            AddCurrentCandidate(candidates, input, "current-tl", "current-tl");
            AddHistoricalCandidateIfAllowed(candidates, input, "historical-tl");
            break;
        case TrustAnchorPolicy::HistoricalAtSigningTime:
            AddCurrentCandidate(candidates, input, "current-tl", "current-tl");
            AddHistoricalCandidateIfAllowed(candidates, input, "historical-tl");
            break;
        case TrustAnchorPolicy::CustomTrustStore:
            candidates.push_back(MakeCandidate(input,
                                               "custom-trust-store",
                                               "custom-trust-store",
                                               input.custom_trust_anchors_der,
                                               false));
            break;
        case TrustAnchorPolicy::PinnedAnchors:
            candidates.push_back(MakeCandidate(input,
                                               "pinned-anchors",
                                               "pinned-anchors",
                                               input.pinned_trust_anchors_der,
                                               false));
            break;
        case TrustAnchorPolicy::ForensicAllPossible:
            if (!input.current_trust_anchors_der.empty() || input.historical_trust_anchors_der.empty()) {
                AddCurrentCandidate(candidates, input, "forensic-current-tl", "current-tl");
            }
            if (!input.historical_trust_anchors_der.empty()) {
                candidates.push_back(MakeCandidate(input,
                                                   "forensic-historical-tl",
                                                   "historical-tl",
                                                   input.historical_trust_anchors_der,
                                                   true));
            }
            break;
    }

    return candidates;
}

PathValidationResult PathValidator::Validate(const PathCandidate& candidate) const {
    policy::CertificateChainInput input;
    input.signer_certificate_der = candidate.signer_certificate_der;
    input.embedded_certificates_der = candidate.embedded_certificates_der;
    input.intermediate_certificates_der = candidate.intermediate_certificates_der;
    input.aia_certificates_der = candidate.aia_certificates_der;
    input.trust_anchors_der = candidate.trust_anchors_der;
    input.trust_anchor_source = candidate.trust_anchor_source;
    input.validation_time = candidate.validation_time;

    const auto chain = policy::CertificateChainValidator{}.Validate(input);

    PathValidationResult result;
    result.candidate_id = candidate.candidate_id;
    result.trust_anchor_source = candidate.trust_anchor_source;
    result.attempted = true;
    result.checked = chain.checked;
    result.trusted = chain.trusted;
    result.chain_valid = chain.chain_valid;
    result.signer_certificate_time_valid = chain.signer_certificate_time_valid;
    result.status = chain.status;
    result.message = chain.message;
    result.chain_debug = chain.chain_debug;
    result.issuer_certificate_der = chain.issuer_certificate_der;
    result.signer_issuer_certificate_der = chain.signer_issuer_certificate_der;
    result.uses_historical_trust = candidate.uses_historical_trust;
    return result;
}

PathSelection PathSelector::Select(const std::vector<PathValidationResult>& results,
                                   const ValidationPolicy& policy) const {
    PathSelection selection;
    if (results.empty()) {
        selection.reason = "no-candidates";
        return selection;
    }

    for (std::size_t i = 0; i < results.size(); ++i) {
        if (results[i].trusted && IsAuthoritativeCandidateAllowed(results[i], policy)) {
            selection.selected_index = i;
            selection.selected_result = results[i];
            selection.reason = "trusted-candidate";
            return selection;
        }
    }

    for (std::size_t i = 0; i < results.size(); ++i) {
        if (IsAuthoritativeCandidateAllowed(results[i], policy)) {
            selection.selected_index = i;
            selection.selected_result = results[i];
            selection.reason = "fallback-untrusted-candidate";
            return selection;
        }
    }

    selection.reason = "no-authoritative-candidate";
    return selection;
}

} // namespace tamga::core::validation
