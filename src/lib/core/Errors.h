#pragma once

#include <string>

namespace tamga::core {

enum class ErrorCode {
    None = 0,
    NotInitialized,
    SettingsRequired,
    KeyNotLoaded,
    InvalidArgument,
    InternalError,
    NotSupported,
    GuiNotAvailable,
    TrustValidationFailed,
    RevocationCheckFailed,
    OnlineServiceUnavailable,
    TimestampValidationFailed,
    PolicyValidationFailed,
};

struct LastError {
    ErrorCode code{ErrorCode::None};
    std::string message;
};

const char* ToString(ErrorCode code);

} // namespace tamga::core
