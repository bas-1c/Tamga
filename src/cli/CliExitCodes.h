#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "core/Errors.h"
#include "util/Json.h"

namespace tamga::cli {

inline constexpr std::string_view kMissingCertificateMessagePrefix =
    "Не знайдено відкритий сертифікат для закритого ключа";

inline int SignFailureExitCode(const core::ErrorCode code, const std::string_view message) {
    const bool missing_certificate =
        message.find(kMissingCertificateMessagePrefix) != std::string_view::npos;
    if (code == core::ErrorCode::KeyNotLoaded || missing_certificate) {
        return 2;
    }
    if (code == core::ErrorCode::OnlineServiceUnavailable) {
        return 3;
    }
    return 1;
}

// ── Типізовані факти технічного звіту ───────────────────────────────────────
// O-03. Раніше код виходу обирався пошуком підрядків у тексті звіту
// (`report.find("\"signatureValid\":false")` і ще девʼять таких рядків). Це
// крихко з двох причин одразу: (1) будь-яка зміна форматування чи назви поля
// тихо змінювала код виходу — без помилки збірки й без падіння тесту;
// (2) пошук не розрізняв секцій, тож збіг у геть іншій частині звіту
// (наприклад у per-signature масиві) рахувався так само, як у зведенні.
//
// Тепер факти читаються за ЯВНИМ шляхом у документі через спільний парсер
// `util/Json`, а рішення ухвалюється над типізованою структурою. Значення
// кодів виходу (0..7) не змінилися — змінилося лише те, звідки вони беруться.
struct VerifyReportFacts {
    std::optional<bool> signature_valid;
    std::optional<bool> container_coverage_complete;
    std::optional<bool> certificate_time_valid;
    std::optional<bool> trust_valid;
    std::optional<bool> timestamp_valid;
    // `revocation.revocationStatus`: "valid" / "good" / "revoked" / "unknown"…
    std::string revocation_status;
    // Секційні `status` зведення/сертифіката/довіри. Порівнюються з
    // `certificate-expired` і `certificate-revoked` — рівно ті два літерали,
    // які шукав попередній код.
    std::string summary_status;
    std::string certificate_status;
    std::string trust_status;
};

inline VerifyReportFacts ReadVerifyReportFacts(const std::string& report_json) {
    VerifyReportFacts facts;
    const auto flag = [&report_json](const char* name) {
        return util::ExtractJsonBoolPath(report_json, {"diagnostics", "flags", name});
    };
    facts.signature_valid = flag("signatureValid");
    facts.trust_valid = flag("trustValid");
    facts.timestamp_valid = flag("timestampValid");
    facts.certificate_time_valid = flag("certificateTimeValid");
    facts.container_coverage_complete = flag("containerCoverageComplete");

    const auto text = [&report_json](const char* section, const char* name) {
        return util::ExtractJsonStringPath(report_json, {section, name}).value_or(std::string());
    };
    facts.revocation_status = text("revocation", "revocationStatus");
    facts.summary_status = text("summary", "status");
    facts.certificate_status = text("certificate", "status");
    facts.trust_status = text("trust", "status");
    return facts;
}

inline bool IsExplicitlyFalse(const std::optional<bool>& value) {
    return value.has_value() && !*value;
}

// Код виходу для перевірки, що НЕ дала повністю валідного підпису.
// Порядок гілок відтворює попередню поведінку один-в-один.
inline int VerificationFailureExitCode(const core::ErrorCode code, const VerifyReportFacts& facts) {
    if (code == core::ErrorCode::KeyNotLoaded) {
        return 2;
    }
    if (code == core::ErrorCode::OnlineServiceUnavailable) {
        return 3;
    }
    if (code == core::ErrorCode::RevocationCheckFailed) {
        return 6;
    }

    if (IsExplicitlyFalse(facts.signature_valid)) {
        return 4;
    }
    // К-01: документ, змінений після підписання, — це відмова у прийнятті
    // підпису, а не проблема довіри. Без цієї гілки він потрапляв би у
    // загальний `return 7` (Policy Invalid) і був би невідрізнимий від
    // порожнього trust-store чи недоступного OCSP.
    if (IsExplicitlyFalse(facts.container_coverage_complete)) {
        return 4;
    }
    if (IsExplicitlyFalse(facts.certificate_time_valid)) {
        return 5;
    }
    const auto section_status_is = [&facts](const char* expected) {
        return facts.summary_status == expected || facts.certificate_status == expected ||
               facts.trust_status == expected;
    };
    if (section_status_is("certificate-expired")) {
        return 5;
    }
    if (facts.revocation_status == "revoked" || section_status_is("certificate-revoked")) {
        return 6;
    }
    // Решта — Policy Invalid; окремої гілки для `trustValid`/`timestampValid`
    // не потрібно, бо вона й раніше вела в те саме значення.
    return 7;
}

}  // namespace tamga::cli
