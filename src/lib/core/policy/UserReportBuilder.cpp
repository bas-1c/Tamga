#include "core/policy/UserReportBuilder.h"

#include <sstream>
#include <utility>

#include "core/policy/VerifyChecks.h"
#include "core/policy/VerifyReportJson.h"
#include "core/session/VerifyReportCommit.h"
#include "core/session/VerifySummary.h"
#include "util/Json.h"

namespace tamga::core {

void Session::RefreshUserReport(std::string container_type, std::string signature_format) {
    policy::UserReportInput input;
    input.verify_report = last_verify_report_;
    input.container_type = std::move(container_type);
    input.signature_format = std::move(signature_format);
    input.signer_metadata = last_signer_metadata_;
    last_user_report_json_ = policy::UserReportBuilder{}.Build(input);
}

void Session::RefreshUserReportForCurrentOperation() {
    // ADR-033: таблиця «операція -> (тип контейнера, формат підпису)» живе у
    // шарі коміту звіту (`core/session/VerifyReportCommit`), а не в анонімному
    // namespace цього файлу — інакше її не можна перевірити без Session.
    const VerifyReportFormatLabels format = UserReportFormatForOperation(last_verify_report_.operation);
    RefreshUserReport(format.container_type, format.signature_format);
}

} // namespace tamga::core

namespace tamga::core::policy {

// Хвиля 8, п.1 (залишок): розмітка JSON більше не живе тут. І вердикти
// (`VerifyChecks`, ADR-026), і форма секцій (`VerifyReportJson`) спільні з
// технічним звітом. Тут лишилося тільки те, чим цей звіт справді
// відрізняється: двомовні повідомлення, дані підписувача і підстановка
// формату, виведеного з імені операції.
std::string UserReportBuilder::Build(const UserReportInput& input) const {
    const VerifyReport& r = input.verify_report;

    FormatFallbacks fallbacks;
    fallbacks.signature_format = input.signature_format;
    fallbacks.container_type = input.container_type;

    constexpr MessageStyle kStyle = MessageStyle::Bilingual;

    std::ostringstream json;
    json << "{\"schemaVersion\":\"2.2\",";

    WriteSummarySection(json, r, kStyle);
    WriteSignatureSection(json, r, fallbacks, SignatureSectionExtras{}, kStyle);

    CertificateSectionExtras certificate_extras;
    certificate_extras.signer_metadata = &input.signer_metadata;
    WriteCertificateSection(json, r, certificate_extras, kStyle);

    WriteTrustSection(json, r, kStyle);
    WriteRevocationSection(json, r, kStyle);
    WriteTimestampSection(json, r, kStyle);
    WriteLtvSection(json, r, kStyle);
    WritePolicySection(json, r, kStyle);

    WriteDiagnosticsPrefix(json, r, fallbacks);
    json << ",";
    WriteDiagnosticsFlagsPrefix(json, r);
    json << ",\"ltvValid\":" << tamga::util::BoolJson(r.ltv_valid)
         << "}}";

    json << "}";
    return json.str();
}

} // namespace tamga::core::policy
