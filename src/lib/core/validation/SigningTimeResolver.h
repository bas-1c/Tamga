#pragma once

#include "core/validation/ValidationTypes.h"

#include <vector>

namespace tamga::core::validation {

class SigningTimeResolver final {
public:
    SigningTimeResolution Resolve(const std::vector<SigningTimeCandidate>& candidates,
                                  const ValidationContext& context,
                                  const ValidationPolicy& policy) const;
};

} // namespace tamga::core::validation
