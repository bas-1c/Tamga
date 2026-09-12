#pragma once

#include <string>

#include "core/CryptoniteAdapter.h"
#include "core/Session.h"

namespace tamga::core::policy {

struct UserReportInput {
    VerifyReport verify_report;
    std::string container_type;
    std::string signature_format;
    CertificateMetadata signer_metadata;
};

class UserReportBuilder final {
public:
    std::string Build(const UserReportInput& input) const;
};

} // namespace tamga::core::policy
