#pragma once

#include "core/validation/ValidationTypes.h"

namespace tamga::core::validation {

class PolicyResolver final {
public:
    ResolvedValidationPolicy Resolve(const ValidationContext& context) const;
};

} // namespace tamga::core::validation
