#pragma once

// Хвиля 8, п.1: ЄДИНЕ джерело вердиктів для обох звітів (ADR-026).
//
// Проєкт віддає два JSON зі схемою `2.0`:
//   * `GetUserReport()` — `policy::UserReportBuilder`, для показу користувачу;
//   * `GetReport()` — технічний звіт, збирається в `SessionCertificateOps.ipp`.
//
// Донедавна кожен із них мав ВЛАСНУ копію логіки вердиктів: вісім пар
// `XxxCheck` / `XxxCheckForV2` плюс п'ять пар допоміжних предикатів. Копії були
// тотожні рядок у рядок — але лише тому, що К-01, В-03 і HI-02 щоразу
// виправляли обидві вручну. Достатньо було один раз забути другу, і два звіти
// про той самий підпис почали б суперечити один одному.
//
// Це не гіпотеза: рівно так поводився С-06 (guard у одній копії парсера з
// чотирьох) і С-19 (перевірка строку дії TSA лише в одному з двох валідаторів).
//
// Тепер логіка вердикту тут одна. Звіти лишаються двома проєкціями: вони
// свідомо емітують різні ДОДАТКОВІ поля (користувацький — дані підписувача,
// технічний — `validatedProfile`, `qualifyingPropertiesPresent`), але
// `status`/`code` кожного блоку беруть із цього модуля.

#include <string>

#include "core/Session.h"

namespace tamga::core::policy {

// Вердикт одного блоку звіту. `status` — одне з
// `valid` / `invalid` / `warning` / `skipped` / `unavailable` / `unknown`.
struct VerifyCheck final {
    const char* status;
    const char* code;
};

// --- канонічні предикати ---------------------------------------------------
//
// Кожен із них колись був «оптимістичним здогадом» і зводився до канонічного
// поля звіту (WP-3/CR-02, ME-02). Функції збережені як іменовані точки, щоб
// причина була видима на місці використання, а не розчинялася в полі.
bool EffectiveCertificateTimeValid(const VerifyReport& report);
bool EffectiveOcspChecked(const VerifyReport& report);
bool EffectiveRevocationChecked(const VerifyReport& report);
const std::string& ValidationTimeSource(const VerifyReport& report);

bool HasPolicyWarning(const VerifyReport& report);
const char* FirstPolicyWarningCode(const VerifyReport& report);

// --- вердикти блоків -------------------------------------------------------
VerifyCheck SummaryCheck(const VerifyReport& report);
VerifyCheck SignatureCheck(const VerifyReport& report);
VerifyCheck CertificateCheck(const VerifyReport& report);
VerifyCheck TrustCheck(const VerifyReport& report);
VerifyCheck RevocationCheck(const VerifyReport& report);
VerifyCheck TimestampCheck(const VerifyReport& report);
VerifyCheck LtvCheck(const VerifyReport& report);
bool LtvFullyValidated(const VerifyReport& report);
VerifyCheck PolicyCheck(const VerifyReport& report);

} // namespace tamga::core::policy
