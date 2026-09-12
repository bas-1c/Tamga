#include "core/session/VerifySummary.h"

namespace tamga::core {

bool CanOnlineServiceOutageOverrideTrustStatus(const VerifyReport& report, const bool has_policy_failure) {
    if (has_policy_failure) {
        return false;
    }
    if (report.trust_status == "timestamp-not-fully-validated") {
        return false;
    }
    return !(report.trust_checked && !report.trust_valid);
}

ErrorCode TrustFailureErrorCode(const VerifyReport& report) {
    if (report.trust_status == "certificate-revoked" ||
        report.trust_status == "revocation-check-invalid" ||
        report.trust_status == "ocsp-response-invalid") {
        return ErrorCode::RevocationCheckFailed;
    }
    if (report.trust_status == "ocsp-responder-unavailable" ||
        report.trust_status == "tsp-responder-unavailable") {
        return ErrorCode::OnlineServiceUnavailable;
    }
    if (report.trust_status == "timestamp-invalid") {
        return ErrorCode::TimestampValidationFailed;
    }
    return ErrorCode::TrustValidationFailed;
}

VerifyPolicyDecision ComputeVerifyPolicyDecision(const VerifyReport& report) {
    const std::string summary = ComputeVerifySummary(report);
    const bool policy_base_valid = report.has_result &&
        report.execution_succeeded &&
        report.signature_valid &&
        report.trust_checked &&
        report.trust_valid &&
        report.revocation_checked &&
        (report.revocation_status == "good" || report.revocation_status == "valid");

    if (!policy_base_valid || report.trust_status == "timestamp-invalid" || report.timestamp_status == "timestamp-invalid") {
        return {false, "integrity-only", summary};
    }
    for (const auto& detail : report.timestamp_details) {
        if (!detail.valid && !detail.policy_acceptable) {
            return {false, "integrity-only", "integrity-but-timestamp-not-fully-validated"};
        }
    }
    if (report.trust_status == "timestamp-not-fully-validated") {
        return {false, "integrity-only", "integrity-but-timestamp-not-fully-validated"};
    }
    if (report.trust_status == "ocsp-responder-unavailable" ||
        report.trust_status == "tsp-responder-unavailable") {
        return {false, "integrity-only", summary};
    }
    if (report.timestamp_checked && report.timestamp_valid) {
        return {true, "cades-t", summary};
    }
    return {true, "bes", summary};
}

void ApplyTimestampFailureToTrust(VerifyReport& report) {
    if (!report.trust_valid) {
        // Довіри вже немає, і причина в ній зафіксована точніша за нашу.
        return;
    }
    report.trust_valid = false;
    report.trust_status = "timestamp-invalid";
    report.error_code = ErrorCode::TimestampValidationFailed;
}

std::string ComputeVerifySummary(const VerifyReport& report) {
    if (!report.has_result) {
        return "not-executed";
    }
    if (!report.execution_succeeded) {
        return "execution-failed";
    }
    // ADR-029: див. коментар у `SummaryCheck`. Перевіряється перед підписом,
    // бо до підпису справа не дійшла — контейнер не розібрався.
    if (report.container_malformed) {
        return "container-malformed";
    }
    if (!report.signature_valid) {
        return "integrity-failed";
    }
    // signature_valid == true from here on: crypto-integrity is confirmed.
    // К-01: криптографічна цілісність підпису НЕ означає, що підписом
    // покрито весь документ. Якщо частина вмісту не підписана, підсумок має
    // говорити саме про це, а не про «цілісність без довіри» — інакше
    // документ із дописаним вмістом отримує той самий summaryCode, що й
    // недоторканий.
    if (!report.container_coverage_complete) {
        return "content-not-fully-signed";
    }
    if (report.trust_checked && report.trust_valid &&
        report.revocation_checked && report.revocation_status == "temporarily-unavailable") {
        return "integrity-but-revocation-unknown";
    }
    if (report.trust_status == "ocsp-responder-unavailable" ||
        report.trust_status == "tsp-responder-unavailable") {
        return "integrity-but-online-service-unavailable";
    }
    if (report.trust_status == "timestamp-not-fully-validated" || report.timestamp_status == "timestamp-partial") {
        return "integrity-but-timestamp-not-fully-validated";
    }
    if (report.signature_valid && report.timestamp_checked && !report.timestamp_valid &&
        (report.trust_status == "timestamp-invalid" || report.timestamp_status == "timestamp-invalid")) {
        return "integrity-but-timestamp-invalid";
    }
    if (report.signature_valid && report.trust_checked && report.trust_valid &&
        report.revocation_checked && report.revocation_status == "unknown") {
        return "integrity-but-revocation-unknown";
    }
    if (report.signature_valid && report.trust_checked && report.trust_valid &&
        report.revocation_checked && (report.revocation_status == "good" || report.revocation_status == "valid") &&
        report.timestamp_checked && report.timestamp_valid) {
        return "integrity-trust-revocation-and-timestamp";
    }
    if (!report.trust_checked) {
        return "integrity-only";
    }
    if (!report.trust_valid) {
        if (report.trust_status == "certificate-revoked") {
            return "integrity-but-revoked";
        }
        if (report.trust_status == "certificate-time-invalid" ||
            report.trust_status == "certificate-chain-time-invalid") {
            return "integrity-but-certificate-expired";
        }
        if (report.trust_status == "certificate-chain-incomplete" ||
            report.trust_status == "certificate-chain-cycle" ||
            report.trust_status == "signer-certificate-missing" ||
            report.trust_status == "legacy-anchor-not-in-current-tl") {
            return "integrity-but-chain-incomplete";
        }
        if (report.trust_status == "trust-store-empty" ||
            report.trust_status == "no-trust-store-configured") {
            return "integrity-without-trust-store";
        }
        if (report.trust_status == "revocation-check-invalid" ||
            report.trust_status == "ocsp-response-invalid") {
            return "integrity-but-revocation-check-invalid";
        }
        return "integrity-but-untrusted-chain";
    }
    // trust_valid == true
    // Online-service outages (OCSP/TSP probe failures) can coexist with a trusted anchor:
    // ApplyTrustPipelineStatus keeps trust_valid=true when the chain was previously validated
    // but sets trust_status to the corresponding *-unavailable value. Surface that explicitly
    // so 1C clients see the availability gap instead of a misleading "integrity-and-trust".
    if (report.revocation_checked && (report.revocation_status == "good" || report.revocation_status == "valid")) {
        return "integrity-trust-and-revocation";
    }
    return "integrity-and-trust";
}

} // namespace tamga::core
