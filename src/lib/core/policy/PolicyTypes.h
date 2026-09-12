#pragma once

#include <string>

namespace tamga::core::policy {

enum class ChainStatus {
    NotChecked,
    Trusted,
    Untrusted,
    Incomplete,
    Expired,
    InvalidSignature,
    SignerMissing,
};

enum class RevocationStatus {
    NotChecked,
    Good,
    Revoked,
    Unknown,
    Stale,
    Invalid,
    ResponderUnavailable,
};

enum class TimestampStatus {
    NotChecked,
    Missing,
    Valid,
    InvalidImprint,
    InvalidSignature,
    UntrustedTsa,
    TsaExpired,
    Unsupported,
};

struct PolicyValidationResult {
    bool trust_checked{false};
    bool trust_valid{false};
    bool revocation_checked{false};
    bool ocsp_checked{false};
    bool tsp_checked{false};
    bool timestamp_checked{false};
    bool timestamp_valid{false};
    bool chain_checked{false};
    bool chain_valid{false};
    ChainStatus chain_status{ChainStatus::NotChecked};
    RevocationStatus revocation_status{RevocationStatus::NotChecked};
    TimestampStatus timestamp_status{TimestampStatus::NotChecked};
    std::string trust_status{"not-implemented"};
    std::string revocation_status_text{"not-checked"};
    std::string policy{"crypto-integrity-only"};
    std::string message;
};

} // namespace tamga::core::policy
