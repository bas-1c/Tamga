#include "core/session/VerifyReportCommit.h"

#include <atomic>
#include <utility>

#include "core/session/VerifyReportOwnership.h"

namespace tamga::core {
namespace {

// Спільне тіло дописування діагностичної примітки. Різниця між контейнерною
// і XAdES-міткою — рівно один префікс, і тепер вона видима як параметр, а не
// як друга копія функції.
void AppendVerifyReportNote(VerifyReport& report, const char* prefix, const std::string& message) {
    if (message.empty()) {
        return;
    }
    if (!report.message.empty()) {
        report.message += "; ";
    }
    report.message += prefix;
    report.message += message;
}

} // namespace

VerifyReport MakeClearedVerifyReport() {
    VerifyReport report{};
    report.policy = "crypto-integrity-only";
    report.trust_status = "not-implemented";
    report.revocation_status = "not-checked";
    return report;
}

void CommitVerifyOutcome(VerifyReport& report, VerifyOutcome outcome) {
    report.has_result = true;
    report.execution_succeeded = outcome.execution_succeeded;
    report.signature_valid = outcome.signature_valid;
    report.operation = std::move(outcome.operation);
    if (report.operation == "VerifyFileAsicEXades") {
        report.container_type = "ASiC-E";
        report.signature_format = "XAdES";
        report.format_profile = "XAdES";
    }
    report.error_code = outcome.error_code;
    report.message = BuildVerifyMessage(outcome.execution_succeeded,
                                        outcome.signature_valid,
                                        std::move(outcome.message));
}

std::string BuildVerifyMessage(const bool execution_succeeded, const bool signature_valid, std::string message) {
    if (!message.empty()) {
        return message;
    }
    if (execution_succeeded && signature_valid) {
        // С-08: раніше тут стояло "Trust validation is not implemented" —
        // твердження, яке перестало відповідати дійсності: trust validation
        // реалізована (validation/PathEngine, TrustServiceEvaluator,
        // RevocationEngine, policy/CertificateChainValidator, локальний
        // trust-store, OCSP/CRL).
        //
        // Повідомлення потрапляло у VerifyReport::message і далі в GetReport()
        // та GetError() для КОЖНОЇ успішної перевірки без власного тексту, тож
        // інтегратор 1С робив протилежний правильному висновок і ігнорував
        // наявний policyDecision. Це той самий клас помилки, від якого
        // застерігає AGENTS.md:41, лише в зворотний бік — applying надто
        // СЛАБКЕ формулювання замість надто сильного.
        //
        // Знахідку зафіксовано ще в аудиті 2026-08-20 і не виправлено; це
        // рецидив, а не нова знахідка.
        return "Signature integrity verified. See policyDecision for the trust verdict.";
    }
    if (execution_succeeded) {
        return "Signature integrity check completed with a negative result.";
    }
    return {};
}

void ApplyFormatTimestampVerdict(VerifyReport& report, const bool crypto_valid,
                                 const bool canonical_full) {
    if (!crypto_valid) {
        report.timestamp_valid = false;
        report.timestamp_status = "timestamp-invalid";
        return;
    }
    if (!report.timestamp_details.empty()) {
        ApplyTimestampDetailsVerdict(report);
        return;
    }
    if (canonical_full) {
        report.timestamp_valid = true;
        report.timestamp_status = "timestamp-valid";
        return;
    }
    report.timestamp_valid = false;
    report.timestamp_status = "timestamp-partial";
}

void ApplyTimestampDetailsVerdict(VerifyReport& report) {
    if (report.timestamp_details.empty()) {
        return;
    }
    bool all_valid = true;
    bool any_invalid = false;
    for (const auto& detail : report.timestamp_details) {
        all_valid = all_valid && detail.valid && detail.status == "timestamp-valid";
        any_invalid = any_invalid || detail.status == "timestamp-invalid";
    }
    report.timestamp_checked = true;
    report.tsp_checked = true;
    report.timestamp_valid = all_valid && !any_invalid;
    report.timestamp_status = any_invalid ? "timestamp-invalid" :
                              (report.timestamp_valid ? "timestamp-valid" : "timestamp-partial");
}

void ApplyEntryTimestampVerdict(SignatureEntry& entry, const bool crypto_valid) {
    if (!crypto_valid) {
        entry.timestamp_valid = false;
        entry.timestamp_status = "timestamp-invalid";
        return;
    }
    entry.timestamp_valid = false;
    entry.timestamp_status = "timestamp-partial";
}

void AppendContainerTimestampMessage(VerifyReport& report, const std::string& message) {
    AppendVerifyReportNote(report, "ASiC container timestamp: ", message);
}

void AppendXadesTimestampMessage(VerifyReport& report, const std::string& message) {
    AppendVerifyReportNote(report, "XAdES timestamp policy: ", message);
}

VerifyReportFormatLabels UserReportFormatForOperation(const std::string& operation) {
    if (operation == "VerifyData" || operation == "VerifyDataBase64" || operation == "VerifyFile" || operation == "RawVerifyFile") {
        return {"CAdES detached", "cms-detached"};
    }
    if (operation == "VerifyDataInternal" || operation == "VerifyDataInternalBase64" ||
        operation == "VerifyDataInternalStr" || operation == "VerifyDataInternalBase64Str") {
        return {"CAdES attached", "cms-attached"};
    }
    if (operation == "VerifyFileAsicS") return {"ASiC-S", "asic-s"};
    if (operation == "VerifyFileAsicE") return {"ASiC-E", "asic-e"};
    if (operation == "VerifyFileAsicEXades") return {"ASiC-E", "XAdES"};
    return {"unknown", "unknown"};
}

namespace {

// Н-04: глобально унікальний лічильник епох звіту.
//
// Глобальний, а не по-сесійний, навмисно: інакше два різні Session могли б
// видати однакове число, і доуточнення від одного помилково збіглося б з
// епохою іншого. Атомарний, бо сесії живуть у різних потоках.
std::atomic<std::uint64_t> g_verify_report_epoch{0};

// Епоха останнього коміту, виконаного САМЕ ЦИМ потоком. Порівняння з
// `epoch_` відповідає на єдине потрібне питання: чи звіт у сесії — усе ще
// той, який закомітив цей потік, чи його вже замінив паралельний Verify*.
thread_local std::uint64_t t_last_verify_commit_epoch = 0;

} // namespace

void VerifyReportOwnership::MarkCommitted() {
    const std::uint64_t epoch = ++g_verify_report_epoch;
    epoch_ = epoch;
    t_last_verify_commit_epoch = epoch;
}

bool VerifyReportOwnership::StillOwnedByThisThread() const {
    return epoch_ != 0 && epoch_ == t_last_verify_commit_epoch;
}

} // namespace tamga::core
