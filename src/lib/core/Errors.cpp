#include "core/Errors.h"

namespace tamga::core {

const char* ToString(const ErrorCode code) {
    switch (code) {
        case ErrorCode::None: return "OK";
        case ErrorCode::NotInitialized: return "Session is not initialized";
        case ErrorCode::SettingsRequired: return "Settings must be configured";
        case ErrorCode::KeyNotLoaded: return "Private key is not loaded";
        case ErrorCode::InvalidArgument: return "Invalid argument";
        case ErrorCode::InternalError: return "Internal error";
        case ErrorCode::NotSupported: return "Operation is not supported";
        case ErrorCode::GuiNotAvailable: return "GUI methods are unavailable in this build";
        case ErrorCode::TrustValidationFailed: return "Trust validation failed";
        case ErrorCode::RevocationCheckFailed: return "Certificate revocation check failed";
        case ErrorCode::OnlineServiceUnavailable: return "Online validation service is unavailable";
        case ErrorCode::TimestampValidationFailed: return "Timestamp validation failed";
        case ErrorCode::PolicyValidationFailed: return "Verification policy validation failed";
        default: return "Unknown error";
    }
}

} // namespace tamga::core
