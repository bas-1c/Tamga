#include "core/validation/ValidationReportJson.h"

namespace tamga::core::validation {

const char* ToString(const ValidationProfile value) {
    switch (value) {
        case ValidationProfile::Strict: return "strict";
        case ValidationProfile::Compatibility: return "compatibility";
        case ValidationProfile::UkraineLegal: return "ukraine-legal";
        case ValidationProfile::Offline: return "offline";
        case ValidationProfile::Forensic: return "forensic";
    }
    return "unknown";
}

const char* ToString(const ValidationLevel value) {
    switch (value) {
        case ValidationLevel::Basic: return "basic";
        case ValidationLevel::Standard: return "standard";
        case ValidationLevel::Extended: return "extended";
        case ValidationLevel::Forensic: return "forensic";
    }
    return "unknown";
}

const char* ToString(const OverallStatus value) {
    switch (value) {
        case OverallStatus::Valid: return "valid";
        case OverallStatus::IntegrityOnly: return "integrity-only";
        case OverallStatus::Indeterminate: return "indeterminate";
        case OverallStatus::Invalid: return "invalid";
    }
    return "unknown";
}

} // namespace tamga::core::validation
