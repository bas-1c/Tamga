#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "core/policy/PolicyTypes.h"
#include "core/validation/ValidationTypes.h"

namespace tamga::core::validation {

struct PathBuilderInput {
    std::vector<std::uint8_t> signer_certificate_der;
    std::vector<std::vector<std::uint8_t>> embedded_certificates_der;
    std::vector<std::vector<std::uint8_t>> intermediate_store_certificates_der;
    std::vector<std::vector<std::uint8_t>> aia_certificates_der;
    std::vector<std::vector<std::uint8_t>> current_trust_anchors_der;
    std::vector<std::vector<std::uint8_t>> historical_trust_anchors_der;
    std::vector<std::vector<std::uint8_t>> custom_trust_anchors_der;
    std::vector<std::vector<std::uint8_t>> pinned_trust_anchors_der;
    ValidationPolicy policy;
    std::string validation_time;
};

struct PathCandidate {
    std::string candidate_id;
    std::string trust_anchor_source;
    std::vector<std::uint8_t> signer_certificate_der;
    std::vector<std::vector<std::uint8_t>> embedded_certificates_der;
    std::vector<std::vector<std::uint8_t>> intermediate_certificates_der;
    std::vector<std::vector<std::uint8_t>> aia_certificates_der;
    std::vector<std::vector<std::uint8_t>> trust_anchors_der;
    bool uses_historical_trust{false};
    std::string validation_time;
};

struct PathValidationResult {
    std::string candidate_id;
    std::string trust_anchor_source;
    bool attempted{false};
    bool checked{false};
    bool trusted{false};
    bool chain_valid{false};
    // WP-3 (canonical certificateTimeValid, CR-02): чи власна валідність
    // сертифіката підписанта (notBefore/notAfter) підтверджена на validation_time,
    // незалежно від довіри до якоря.
    bool signer_certificate_time_valid{false};
    policy::ChainStatus status{policy::ChainStatus::NotChecked};
    std::string message;
    std::string chain_debug;
    std::vector<std::uint8_t> issuer_certificate_der;
    std::vector<std::uint8_t> signer_issuer_certificate_der;
    bool uses_historical_trust{false};
};

struct PathSelection {
    static constexpr std::size_t npos = static_cast<std::size_t>(-1);

    std::size_t selected_index{npos};
    PathValidationResult selected_result;
    std::string reason{"no-candidates"};
};

class PathBuilder final {
public:
    std::vector<PathCandidate> Build(const PathBuilderInput& input) const;
};

class PathValidator final {
public:
    PathValidationResult Validate(const PathCandidate& candidate) const;
};

class PathSelector final {
public:
    PathSelection Select(const std::vector<PathValidationResult>& results,
                         const ValidationPolicy& policy) const;
};

} // namespace tamga::core::validation
