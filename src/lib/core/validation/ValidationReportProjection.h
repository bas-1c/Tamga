#pragma once

#include "core/Session.h"  // tamga::core::VerifyReport

// WP-0 (заморожений контракт) — для WP-3/WP-11/WP-17.
//
// Канонічним джерелом істини є tamga::core::validation::ValidationReport
// (оркестратор у ValidationEngine.h). legacy VerifyReport і user-report мають
// генеруватися ДЕТЕРМІНОВАНОЮ ПРОЄКЦІЄЮ без мутацій, усуваючи подвійну мутацію
// звіту двома pipeline (HI-06). Тут заморожено лише підпис
// проєкції; реалізація — WP-11.

namespace tamga::core::validation {
struct ValidationReport;
struct TimestampEngineResult;
}  // namespace tamga::core::validation

namespace tamga::core {

// Детермінована проєкція canonical ValidationReport у legacy VerifyReport.
// Чиста функція без побічних ефектів; signature_crypto_valid обовʼязково
// надходить усередині ValidationReport, а не хардкодиться (Opus M2).
VerifyReport ProjectVerifyReport(const validation::ValidationReport& report);

TimestampEntry ProjectTimestampResult(const validation::TimestampEngineResult& result);

}  // namespace tamga::core
