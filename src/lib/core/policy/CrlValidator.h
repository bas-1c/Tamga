#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/policy/PolicyTypes.h"

namespace tamga::core::policy {

struct CrlValidationInput {
    std::vector<std::uint8_t> signer_certificate_der;
    std::vector<std::uint8_t> issuer_certificate_der;
    std::vector<std::vector<std::uint8_t>> crls_der;
    std::string validation_time;
};

struct CrlValidationResult {
    bool checked{false};
    bool revoked{false};
    RevocationStatus status{RevocationStatus::NotChecked};
    std::string message;
    std::string crl_evidence_id;
    time_t revocation_time{0};
};

class CrlValidator final {
public:
    CrlValidationResult Validate(const CrlValidationInput& input) const;
};

} // namespace tamga::core::policy
