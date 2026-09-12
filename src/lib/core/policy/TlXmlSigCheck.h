#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::core::policy {

struct TlXmlSigCheckResult {
    bool succeeded{false};      // true = verification ran and signature is cryptographically valid
    bool not_supported{false};  // true = build lacks TAMGA_XML_SIGNATURES_ENABLED; check skipped
    std::string error;
};

// Verifies the ds:Signature embedded in a Trust List XML string.
// If pinned_cert_der is non-empty, the signer certificate in ds:KeyInfo must
// match it exactly (DER byte comparison) before the cryptographic check runs.
// Returns not_supported=true (not an error) when built without TAMGA_ENABLE_XML_SIGNATURES.
TlXmlSigCheckResult VerifyTlXmlSignature(
    const std::string& xml,
    const std::vector<std::uint8_t>& pinned_cert_der);

}  // namespace tamga::core::policy
