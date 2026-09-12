#pragma once

#include <string>

#include "core/Session.h"
#include "core/Errors.h"
#include "core/policy/TimestampValidator.h"

namespace tamga::core {

struct VerifyPolicyDecision {
    bool valid{false};
    std::string level{"integrity-only"};
    std::string summary;
};

// Formalized verify-policy summary: collapses the multi-field VerifyReport into a single
// stable status string for 1C clients. The values are a fixed enumeration and must stay in
// sync with docs/component-methods.md "GetReport".
//
// The helper is declared in an internal header (instead of living in the anonymous
// namespace of a single translation unit) so that visibility does not depend on the
//
// The helper is declared in an internal header (instead of living in the anonymous
// namespace of a single translation unit) so that visibility does not depend on the
// .ipp inclusion order inside Session.cpp, and so that unit tests can exercise every
// branch of the summary directly.
std::string ComputeVerifySummary(const VerifyReport& report);
VerifyPolicyDecision ComputeVerifyPolicyDecision(const VerifyReport& report);
bool CanOnlineServiceOutageOverrideTrustStatus(const VerifyReport& report, bool has_policy_failure);
ErrorCode TrustFailureErrorCode(const VerifyReport& report);
// Хвиля 8, п.3: єдине місце, де провал мітки часу понижує довіру.
//
// Раніше поруч жив `ApplyTimestampValidationResultToVerifyReport`, який мапив
// результат мертвого `policy::TimestampValidator` і при цьому втілював СТАРІШУ,
// м'якшу політику (статус `Unsupported` довіру не скидав). Продакшн ним не
// користувався жодного разу — його тримали живим лише тести, тобто той самий
// дефект, що С-16: тест доводив властивість, якої продукт не має.
//
// Гейт `report.trust_valid` тут — не оптимізація, а інваріант: провал мітки
// часу НЕ має перекривати вже зафіксовану причину недовіри (наприклад
// `certificate-revoked`), інакше звіт назве відкликаний сертифікат проблемою
// мітки часу.
void ApplyTimestampFailureToTrust(VerifyReport& report);

} // namespace tamga::core
