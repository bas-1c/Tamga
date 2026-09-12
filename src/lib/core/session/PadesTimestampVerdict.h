#pragma once

#include "core/session/VerifyReportCommit.h"

namespace tamga::core::pades_detail {

// Єдина фінальна точка PAdES-коміту: спочатку форматний запобіжник,
// потім канонічні деталі лише за його успіху. Окремий наступний виклик
// ApplyTimestampDetailsVerdict помилково скасовував форматну відмову.
inline void ApplyPadesTimestampVerdict(VerifyReport& report, bool format_valid, bool canonical_full) {
    ApplyFormatTimestampVerdict(report, format_valid, canonical_full);
}

} // namespace tamga::core::pades_detail
