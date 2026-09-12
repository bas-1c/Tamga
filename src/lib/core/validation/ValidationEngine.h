#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/validation/EvidenceStore.h"
#include "core/validation/PathEngine.h"
#include "core/validation/PolicyResolver.h"
#include "core/validation/RevocationEngine.h"
#include "core/validation/SigningTimeResolver.h"
#include "core/validation/TimestampEngine.h"
#include "core/validation/TrustServiceEvaluator.h"
#include "core/validation/ValidationTypes.h"

namespace tamga::core::validation {

/**
 * Зведений звіт валідації, що об'єднує рішення (ValidationDecision),
 * трасування шляху сертифіката і склад доказового пакету (EvidenceStore).
 *
 * Використовується для передачі повного результату оркестратора до сесійного
 * рівня (SessionCryptoOps) та подальшої проєкції в legacy-поля VerifyReport.
 */
struct ValidationReport {
    ValidationDecision decision;

    // Вибраний шлях довіри
    PathSelection path_selection;

    // Результат оцінки сервісу в списку довіри
    TrustServiceDecision trust_service;

    // Результат перевірки відкликання підписанта (Signer)
    RevocationEngineResult signer_revocation;

    // Результат валідації мітки часу (якщо присутня)
    TimestampEngineResult timestamp;
    bool timestamp_attempted{false};

    // Розв'язаний момент підпису
    SigningTimeResolution signing_time_resolution;

    // Весь доказовий пакет
    EvidenceStore evidence;
};

/**
 * Головний оркестратор повного production-grade validation pipeline
 * для CMS/CAdES підписів, сумісного з українською PKI (TL-UA, КНЕДП).
 *
 * Послідовність кроків:
 *  1. PolicyResolver → ValidationPolicy + ValidationPlan
 *  2. EvidenceStore: реєстрація сирого підпису/даних
 *  3. SigningTimeResolver (попередній): збір кандидатів часу
 *  4. PathEngine: побудова та вибір ланцюжка довіри
 *  5. TrustServiceEvaluator: оцінка запису КНЕДП у TL-UA
 *  6. RevocationEngine: перевірка відкликання підписанта
 *  7. TimestampEngine: повна валідація RFC3161 мітки (якщо вимагається)
 *  8. SigningTimeResolver (фінальний): вибір trusted/evaluation time
 *  9. Синтез ValidationDecision (overallStatus, summary, because, warnings, limitations)
 */
class ValidationEngine final {
public:
    /**
     * Запускає повний validation pipeline.
     *
     * @param context  Контекст валідації (профіль, рівень, режим, work_dir)
     * @param signer_certificate_der  DER-байти сертифіката підписанта
     * @param embedded_certificates_der  Вбудовані в CMS проміжні сертифікати
     * @return  Повний ValidationReport із рішенням і доказами
     */
    ValidationReport Validate(const ValidationContext& context,
                              const std::vector<std::uint8_t>& signer_certificate_der,
                              const std::vector<std::vector<std::uint8_t>>& embedded_certificates_der) const;
};

} // namespace tamga::core::validation
