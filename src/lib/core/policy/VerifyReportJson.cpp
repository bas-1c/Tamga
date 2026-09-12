#include "core/policy/VerifyReportJson.h"

#include <utility>

#include "core/session/VerifySummary.h"
#include "util/Json.h"

namespace tamga::core::policy {
namespace {

using tamga::util::BoolJson;
using tamga::util::EscapeJson;

void WriteMessage(std::ostringstream& json, const std::string& code) {
    const auto message = MessageForCode(code);
    json << ",\"message\":{\"en\":\"" << EscapeJson(message.first) << "\",\"uk\":\""
         << EscapeJson(message.second) << "\"}";
}

void WriteWarning(std::ostringstream& json, const char* code, bool& first, const MessageStyle style) {
    if (!first) json << ",";
    first = false;
    json << "{\"code\":\"" << code << "\"";
    if (style == MessageStyle::Bilingual) {
        WriteMessage(json, code);
    }
    json << "}";
}

void WriteStringOrNull(std::ostringstream& json, const std::string& value) {
    if (value.empty()) {
        json << "null";
    } else {
        json << "\"" << EscapeJson(value) << "\"";
    }
}

// Порожнє значення у звіті означає «нема чого показати» — тоді підставляємо
// те, що вивела операція. Технічний звіт передає порожній fallback, тож
// результат для нього не змінюється.
const std::string& OrFallback(const std::string& value, const std::string& fallback) {
    return value.empty() ? fallback : value;
}

} // namespace

const char* ErrorCodeName(const ErrorCode code) {
    switch (code) {
        case ErrorCode::None: return "None";
        case ErrorCode::NotInitialized: return "NotInitialized";
        case ErrorCode::SettingsRequired: return "SettingsRequired";
        case ErrorCode::KeyNotLoaded: return "KeyNotLoaded";
        case ErrorCode::InvalidArgument: return "InvalidArgument";
        case ErrorCode::InternalError: return "InternalError";
        case ErrorCode::NotSupported: return "NotSupported";
        case ErrorCode::GuiNotAvailable: return "GuiNotAvailable";
        case ErrorCode::TrustValidationFailed: return "TrustValidationFailed";
        case ErrorCode::RevocationCheckFailed: return "RevocationCheckFailed";
        case ErrorCode::OnlineServiceUnavailable: return "OnlineServiceUnavailable";
        case ErrorCode::TimestampValidationFailed: return "TimestampValidationFailed";
        case ErrorCode::PolicyValidationFailed: return "PolicyValidationFailed";
        default: return "Unknown";
    }
}

std::pair<const char*, const char*> MessageForCode(const std::string& code) {
    if (code == "SIGNATURE_VALID") return {"Electronic signature is valid.", "Електронний підпис дійсний."};
    if (code == "SIGNATURE_VALID_WITH_WARNINGS") return {"Electronic signature is valid with warnings.", "Електронний підпис дійсний із попередженнями."};
    if (code == "SIGNATURE_INTEGRITY_ONLY") return {"Signature integrity is confirmed, but full policy validation is incomplete.", "Цілісність підпису підтверджено, але повна перевірка політики не завершена."};
    if (code == "SIGNATURE_CRYPTOGRAPHICALLY_VALID") return {"Signature is cryptographically valid.", "Криптографічну цілісність підпису підтверджено."};
    if (code == "SIGNATURE_CRYPTOGRAPHICALLY_INVALID" || code == "SIGNATURE_INVALID") return {"Signature cryptographic validation failed.", "Криптографічну перевірку підпису не пройдено."};
    if (code == "CONTAINER_COVERAGE_INCOMPLETE") return {"Signature does not cover the whole document: part of the content is unsigned.", "Підпис не покриває весь документ: частина вмісту не підписана."};
    // ADR-029: формулювання навмисно каже, що робити далі. «Не вдалося
    // завершити» провокувало повтор спроби, а поламаний контейнер від повтору
    // кращим не стане — його треба отримати заново від відправника.
    if (code == "CONTAINER_MALFORMED") return {"Container structure is malformed and cannot be processed; request a new copy from the sender.", "Структура контейнера пошкоджена й не може бути опрацьована; запросіть у відправника новий примірник."};
    if (code == "VERIFICATION_EXECUTION_FAILED") return {"Signature verification could not be completed.", "Перевірку підпису не вдалося завершити."};
    if (code == "NOT_EXECUTED") return {"Signature verification has not been executed yet.", "Перевірку підпису ще не виконано."};
    if (code == "CERTIFICATE_VALID_AT_VALIDATION_TIME") return {"Signer certificate is valid at the selected validation time.", "Сертифікат підписувача дійсний на обраний час перевірки."};
    if (code == "CERTIFICATE_INVALID_AT_VALIDATION_TIME") return {"Signer certificate is not valid at the selected validation time.", "Сертифікат підписувача недійсний на обраний час перевірки."};
    if (code == "SIGNER_CERTIFICATE_MISSING") return {"Signer certificate is not available in the signature evidence.", "Сертифікат підписувача відсутній у даних підпису."};
    if (code == "TRUST_VALID") return {"Certificate chain is trusted.", "Ланцюг сертифікатів довірений."};
    if (code == "TRUST_VALID_HISTORICAL") return {"Certificate chain is trusted using historical trust evidence.", "Ланцюг сертифікатів довірений за історичними даними довіри."};
    if (code == "TRUST_INVALID") return {"Certificate chain is not trusted.", "Ланцюг сертифікатів не є довіреним."};
    if (code == "TRUST_NOT_CHECKED") return {"Trust validation was not performed.", "Перевірку довіри не виконано."};
    if (code == "REVOCATION_VALID") return {"Certificate revocation status is valid.", "Статус відкликання сертифіката підтверджено як дійсний."};
    if (code == "CERTIFICATE_REVOKED") return {"Signer certificate is revoked.", "Сертифікат підписувача відкликано."};
    // П-02: код повертає `RevocationCheck` і (з 2026-08-29) `SummaryCheck`, але
    // рядка для нього тут не було — спрацьовував fallback «Перевірку не
    // виконано або вона не застосовується». Тобто повідомлення казало
    // протилежне до факту: перевірку виконано, і дані виявилися некоректними.
    if (code == "REVOCATION_INVALID") return {"Revocation data is invalid.", "Дані про відкликання некоректні."};
    if (code == "REVOCATION_UNAVAILABLE") return {"Revocation service is temporarily unavailable.", "Сервіс перевірки відкликання тимчасово недоступний."};
    if (code == "REVOCATION_UNKNOWN") return {"Certificate revocation status is unknown.", "Статус відкликання сертифіката невідомий."};
    if (code == "TIMESTAMP_VALID") return {"Trusted timestamp is valid.", "Довірена позначка часу дійсна."};
    if (code == "TIMESTAMP_NOT_FULLY_VALIDATED") return {"Timestamp evidence is present but not fully validated.", "Позначка часу наявна, але не повністю перевірена."};
    if (code == "TIMESTAMP_INVALID") return {"Timestamp validation failed.", "Перевірку позначки часу не пройдено."};
    if (code == "TIMESTAMP_NOT_CHECKED") return {"Timestamp validation was not performed.", "Перевірку позначки часу не виконано."};
    if (code == "LTV_VALID") return {"Long-term validation evidence is valid.", "Дані довготривалої перевірки дійсні."};
    if (code == "LTV_EVIDENCE_UNAVAILABLE") return {"Long-term validation evidence is unavailable or incomplete.", "Дані довготривалої перевірки недоступні або неповні."};
    if (code == "POLICY_VALID") return {"Validation policy requirements are satisfied.", "Вимоги політики перевірки виконано."};
    if (code == "HISTORICAL_TRUST_USED") return {"Historical trust evidence was used.", "Використано історичні дані довіри."};
    if (code == "ONLINE_SERVICE_UNAVAILABLE") return {"One or more online validation services are unavailable.", "Один або кілька онлайн-сервісів перевірки недоступні."};
    if (code == "REVOCATION_STATUS_UNKNOWN") return {"Revocation status could not be confirmed completely.", "Статус відкликання не вдалося підтвердити повністю."};
    if (code == "POLICY_INVALID") return {"Validation policy requirements are not satisfied.", "Вимоги політики перевірки не виконано."};
    return {"Check was not performed or is not applicable.", "Перевірку не виконано або вона не застосовується."};
}

void WriteCheckFields(std::ostringstream& json, const VerifyCheck& check, const MessageStyle style) {
    json << "\"status\":\"" << check.status << "\",\"code\":\"" << check.code << "\"";
    if (style == MessageStyle::Bilingual) {
        WriteMessage(json, check.code);
    }
}

void WriteSummarySection(std::ostringstream& json, const VerifyReport& report, const MessageStyle style) {
    json << "\"summary\":{";
    WriteCheckFields(json, SummaryCheck(report), style);
    json << ",\"summaryCode\":\"" << EscapeJson(ComputeVerifySummary(report)) << "\"},";
}

void WriteSignatureSection(std::ostringstream& json, const VerifyReport& report,
                           const FormatFallbacks& fallbacks, const SignatureSectionExtras& extras,
                           const MessageStyle style) {
    json << "\"signature\":{";
    WriteCheckFields(json, SignatureCheck(report), style);
    json << ",\"format\":\"" << EscapeJson(OrFallback(report.signature_format, fallbacks.signature_format)) << "\""
         << ",\"profile\":\"" << EscapeJson(report.format_profile) << "\"";
    if (extras.validated_profile != nullptr) {
        json << ",\"validatedProfile\":\"" << EscapeJson(*extras.validated_profile) << "\"";
    }
    json << ",\"coverageStatus\":\"" << EscapeJson(report.coverage_status) << "\""
         << ",\"containerType\":\"" << EscapeJson(OrFallback(report.container_type, fallbacks.container_type)) << "\"},";
}

void WriteCertificateSection(std::ostringstream& json, const VerifyReport& report,
                             const CertificateSectionExtras& extras, const MessageStyle style) {
    json << "\"certificate\":{";
    WriteCheckFields(json, CertificateCheck(report), style);
    json << ",\"validationTimeSource\":\"" << ValidationTimeSource(report) << "\""
         << ",\"present\":" << BoolJson(report.signer_certificate_present);
    if (extras.qualifying_properties_present != nullptr) {
        // ME-01: окремий структурний факт — наявність XAdES SignedProperties/
        // QualifyingProperties, НЕ те саме, що "present" вище (KeyInfo/
        // X509Certificate). Завжди false для CMS/CAdES/PAdES-операцій.
        json << ",\"qualifyingPropertiesPresent\":" << BoolJson(*extras.qualifying_properties_present);
    }
    json << ",\"timeValid\":" << BoolJson(EffectiveCertificateTimeValid(report))
         << ",\"chain\":{\"checked\":" << BoolJson(report.chain_checked)
         << ",\"valid\":" << BoolJson(report.chain_valid) << "}";
    if (extras.signer_metadata != nullptr) {
        const CertificateMetadata& m = *extras.signer_metadata;
        json << ",\"subject\":";
        WriteStringOrNull(json, m.common_name);
        json << ",\"issuer\":";
        WriteStringOrNull(json, m.issuer);
        json << ",\"serialNumber\":";
        WriteStringOrNull(json, m.serial_number_hex);
        json << ",\"organization\":";
        WriteStringOrNull(json, m.organization);
        json << ",\"country\":";
        WriteStringOrNull(json, m.country);
    }
    json << "},";
}

void WriteTrustSection(std::ostringstream& json, const VerifyReport& report, const MessageStyle style) {
    json << "\"trust\":{";
    WriteCheckFields(json, TrustCheck(report), style);
    json << ",\"checked\":" << BoolJson(report.trust_checked)
         << ",\"valid\":" << BoolJson(report.trust_valid)
         << ",\"mode\":\"" << EscapeJson(report.trust_mode) << "\""
         << ",\"reason\":\"" << EscapeJson(report.trust_reason) << "\""
         << ",\"trustStatus\":\"" << EscapeJson(report.trust_status) << "\""
         << ",\"historicalTrustUsed\":" << BoolJson(report.historical_trust_used)
         << ",\"historicalAnchor\":{\"subject\":\"" << EscapeJson(report.historical_anchor_subject)
         << "\",\"serial\":\"" << EscapeJson(report.historical_anchor_serial) << "\"}},";
}

void WriteRevocationSection(std::ostringstream& json, const VerifyReport& report, const MessageStyle style) {
    const bool ocsp_checked = EffectiveOcspChecked(report);
    json << "\"revocation\":{";
    WriteCheckFields(json, RevocationCheck(report), style);
    json << ",\"checked\":" << BoolJson(EffectiveRevocationChecked(report))
         << ",\"ocspChecked\":" << BoolJson(ocsp_checked)
         << ",\"crlChecked\":" << BoolJson(report.revocation_checked && !ocsp_checked)
         // ME-02: структурна наявність XAdES RevocationValues, окремо від
         // canonical checked/ocspChecked вище (див. VerifyReport::revocation_evidence_present).
         << ",\"evidencePresent\":" << BoolJson(report.revocation_evidence_present)
         << ",\"revocationStatus\":\"" << EscapeJson(report.revocation_status) << "\"},";
}

void WriteTimestampDetails(std::ostringstream& json, const std::vector<TimestampEntry>& details) {
    const auto write_strings = [&json](const char* name, const std::vector<std::string>& values) {
        json << ",\"" << name << "\":[";
        bool first = true;
        for (const auto& value : values) {
            if (!first) json << ',';
            first = false;
            json << '"' << EscapeJson(value) << '"';
        }
        json << ']';
    };
    json << '[';
    bool first = true;
    for (const auto& detail : details) {
        if (!first) json << ',';
        first = false;
        const char* state = detail.status == "timestamp-valid" ? "valid" :
                            detail.status == "timestamp-invalid" ? "invalid" : "unavailable";
        json << "{\"signatureIndex\":" << detail.signature_index
             << ",\"kind\":\"" << EscapeJson(detail.kind) << '"'
             << ",\"signedRevisionEnd\":" << detail.signed_revision_end
             << ",\"status\":\"" << state << '"'
             << ",\"timestampStatus\":\"" << EscapeJson(detail.status) << '"'
             << ",\"valid\":" << BoolJson(detail.valid && detail.status == "timestamp-valid")
             << ",\"policyAcceptable\":" << BoolJson(detail.policy_acceptable)
             << ",\"cryptoValid\":" << BoolJson(detail.crypto_valid)
             << ",\"genTimeValid\":" << BoolJson(detail.gen_time_valid)
             << ",\"certificateTimeValid\":" << BoolJson(detail.certificate_time_valid)
             << ",\"ekuValid\":" << BoolJson(detail.eku_valid)
             << ",\"trustValid\":" << BoolJson(detail.trust_valid)
             << ",\"revocationChecked\":" << BoolJson(detail.revocation_checked)
             << ",\"ocspAttempted\":" << BoolJson(detail.ocsp_attempted)
             << ",\"crlAttempted\":" << BoolJson(detail.crl_attempted)
             << ",\"historicalTrustUsed\":" << BoolJson(detail.historical_trust_used)
             << ",\"genTime\":\"" << EscapeJson(detail.gen_time) << '"'
             << ",\"validationTime\":\"" << EscapeJson(detail.validation_time) << '"'
             << ",\"reasonCode\":\"" << EscapeJson(detail.reason_code) << '"'
             << ",\"trustSource\":\"" << EscapeJson(detail.trust_source) << '"'
             << ",\"tsaSubject\":\"" << EscapeJson(detail.tsa_subject) << '"'
             << ",\"tsaIssuer\":\"" << EscapeJson(detail.tsa_issuer) << '"'
             << ",\"tsaSerial\":\"" << EscapeJson(detail.tsa_serial) << '"'
             << ",\"tsaFingerprintSha256\":\"" << EscapeJson(detail.tsa_fingerprint_sha256) << '"'
             << ",\"revocationStatus\":\"" << EscapeJson(detail.revocation_status) << '"';
        write_strings("because", detail.because);
        write_strings("warnings", detail.warnings);
        write_strings("limitations", detail.limitations);
        write_strings("evidenceIds", detail.evidence_ids);
        json << '}';
    }
    json << ']';
}

void WriteTimestampSection(std::ostringstream& json, const VerifyReport& report, const MessageStyle style) {
    json << "\"timestamp\":{";
    WriteCheckFields(json, TimestampCheck(report), style);
    json << ",\"checked\":" << BoolJson(report.timestamp_checked)
         << ",\"tspChecked\":" << BoolJson(report.tsp_checked)
         << ",\"timestampStatus\":\"" << EscapeJson(report.timestamp_status) << "\",\"details\":";
    WriteTimestampDetails(json, report.timestamp_details);
    json << "},";
}

void WriteLtvSection(std::ostringstream& json, const VerifyReport& report, const MessageStyle style) {
    json << "\"ltv\":{";
    WriteCheckFields(json, LtvCheck(report), style);
    // HI-02: "valid" лишається старим структурним ltv_valid (без зміни
    // поведінки/контракту); evidenceBound/evidenceValidated — нові поля з
    // деталізацією (див. коментар при VerifyReport::ltv_evidence_bound/
    // ltv_evidence_validated у Session.h).
    json << ",\"valid\":" << BoolJson(report.ltv_valid)
         << ",\"evidenceBound\":" << BoolJson(report.ltv_evidence_bound)
         << ",\"evidenceValidated\":" << BoolJson(report.ltv_evidence_validated)
         << ",\"fullyValidated\":" << BoolJson(LtvFullyValidated(report))
         << ",\"fullValidationState\":\"" << LtvCheck(report).status << "\"},";
}

void WritePolicySection(std::ostringstream& json, const VerifyReport& report, const MessageStyle style) {
    json << "\"policy\":{";
    WriteCheckFields(json, PolicyCheck(report), style);
    json << ",\"level\":\"" << EscapeJson(ComputeVerifyPolicyDecision(report).level) << "\",";

    bool first = true;
    json << "\"warnings\":[";
    if (report.historical_trust_used) WriteWarning(json, "HISTORICAL_TRUST_USED", first, style);
    if (report.trust_status == "timestamp-not-fully-validated" || report.timestamp_status == "timestamp-partial") {
        WriteWarning(json, "TIMESTAMP_NOT_FULLY_VALIDATED", first, style);
    }
    if (report.trust_status == "ocsp-responder-unavailable" || report.trust_status == "tsp-responder-unavailable") {
        WriteWarning(json, "ONLINE_SERVICE_UNAVAILABLE", first, style);
    }
    if (EffectiveRevocationChecked(report) && report.revocation_status != "valid" &&
        report.revocation_status != "good" && report.revocation_status != "revoked" &&
        report.revocation_status != "invalid") {
        WriteWarning(json, "REVOCATION_STATUS_UNKNOWN", first, style);
    }
    json << "]";

    json << "},";
}

void WriteDiagnosticsPrefix(std::ostringstream& json, const VerifyReport& report,
                            const FormatFallbacks& fallbacks) {
    json << "\"diagnostics\":{"
         << "\"operation\":\"" << EscapeJson(report.operation) << "\""
         << ",\"format\":\"" << EscapeJson(OrFallback(report.signature_format, fallbacks.signature_format)) << "\""
         << ",\"profile\":\"" << EscapeJson(report.format_profile) << "\""
         << ",\"containerType\":\"" << EscapeJson(OrFallback(report.container_type, fallbacks.container_type)) << "\""
         << ",\"errorCode\":\"" << EscapeJson(ErrorCodeName(report.error_code)) << "\"";
}

void WriteDiagnosticsFlagsPrefix(std::ostringstream& json, const VerifyReport& report) {
    json << "\"flags\":{"
         << "\"hasResult\":" << BoolJson(report.has_result)
         << ",\"executionSucceeded\":" << BoolJson(report.execution_succeeded)
         << ",\"signatureValid\":" << BoolJson(report.signature_valid)
         << ",\"trustChecked\":" << BoolJson(report.trust_checked)
         << ",\"trustValid\":" << BoolJson(report.trust_valid)
         << ",\"revocationChecked\":" << BoolJson(EffectiveRevocationChecked(report))
         << ",\"ocspChecked\":" << BoolJson(EffectiveOcspChecked(report))
         << ",\"tspChecked\":" << BoolJson(report.tsp_checked)
         << ",\"timestampChecked\":" << BoolJson(report.timestamp_checked)
         << ",\"timestampValid\":" << BoolJson(report.timestamp_valid);
}

} // namespace tamga::core::policy
