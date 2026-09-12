#include "core/validation/ValidationReportProjection.h"

#include "core/session/VerifySummary.h"
#include "core/session/VerifyReportCommit.h"
#include "core/policy/Sha256Helper.h"
#include "core/validation/ValidationEngine.h"

namespace tamga::core {

namespace {

bool HasSignerCertificateEvidence(const validation::ValidationReport& ve_report) {
    for (const auto& [id, record] : ve_report.evidence.GetAllRecords()) {
        (void)id;
        if (record.type == "signer-certificate") {
            return true;
        }
    }
    return false;
}

const char* CanonicalRevocationStatusString(policy::RevocationStatus status) {
    switch (status) {
        case policy::RevocationStatus::Good:                return "valid";
        case policy::RevocationStatus::Revoked:             return "revoked";
        case policy::RevocationStatus::Invalid:             return "invalid";
        case policy::RevocationStatus::ResponderUnavailable: return "temporarily-unavailable";
        case policy::RevocationStatus::Stale:               return "stale";
        case policy::RevocationStatus::NotChecked:          return "not-checked";
        case policy::RevocationStatus::Unknown:
        default:                                            return "unknown";
    }
}

// WP-3 (canonical certificateTimeValid, CR-02): відображає канонічне джерело
// часу оцінки (`SigningTimeResolution`) на рядковий словник
// (trustedTimestamp/signingTime/currentTime/unknown) — чесне відображення
// того часу, який справді пішов у X.509 notBefore/notAfter перевірку
// сертифіката підписанта, а не здогад за непов'язаними прапорцями.
const char* CanonicalValidationTimeSource(const validation::SigningTimeResolution& resolution,
                                          bool signer_certificate_present) {
    if (!signer_certificate_present) {
        return "unknown";
    }
    switch (resolution.source) {
        case validation::SigningTimeSource::Rfc3161Timestamp:
            return resolution.trusted_time ? "trustedTimestamp" : "signingTime";
        case validation::SigningTimeSource::ClaimedSigningTime:
            return "signingTime";
        case validation::SigningTimeSource::VerificationTimeFallback:
        case validation::SigningTimeSource::Unavailable:
        default:
            return "currentTime";
    }
}

} // namespace

TimestampEntry ProjectTimestampResult(const validation::TimestampEngineResult& result) {
    TimestampEntry entry;
    entry.valid = result.valid;
    entry.policy_acceptable = result.policy_acceptable;
    entry.crypto_valid = result.crypto_valid;
    entry.gen_time_valid = result.gen_time_valid;
    entry.certificate_time_valid = result.certificate_time_valid;
    entry.eku_valid = result.eku_valid;
    entry.trust_valid = result.trust_valid;
    entry.revocation_checked = result.revocation_checked;
    entry.historical_trust_used = result.historical_trust_used;
    entry.ocsp_attempted = result.ocsp_attempted;
    entry.crl_attempted = result.crl_attempted;
    entry.gen_time = result.gen_time;
    entry.validation_time = result.validation_time;
    entry.reason_code = result.reason_code;
    entry.trust_source = result.trust_source;
    entry.revocation_status = CanonicalRevocationStatusString(result.revocation_status);
    entry.because = result.because;
    entry.warnings = result.warnings;
    entry.limitations = result.limitations;
    entry.evidence_ids = result.evidence_ids;
    switch (result.status) {
        case policy::TimestampStatus::Valid: entry.status = "timestamp-valid"; break;
        case policy::TimestampStatus::Missing:
        case policy::TimestampStatus::NotChecked: entry.status = "timestamp-not-validated"; break;
        case policy::TimestampStatus::InvalidImprint:
        case policy::TimestampStatus::InvalidSignature:
        case policy::TimestampStatus::Unsupported: entry.status = "timestamp-invalid"; break;
        default: entry.status = "timestamp-partial"; break;
    }
    // Відсутній доказ і доведена відмова політики — різні результати.
    if (result.reason_code == "TSA_REVOKED" || result.reason_code == "TSA_EKU_INVALID" ||
        result.reason_code == "TIMESTAMP_TIME_INVALID" || result.reason_code == "TSA_CERTIFICATE_TIME_INVALID" ||
        result.reason_code == "TSA_CHAIN_TIME_INVALID") {
        entry.status = "timestamp-invalid";
    }
    if (result.reason_code == "TSA_CERTIFICATE_MISSING") entry.status = "timestamp-partial";
    if (!result.tsa_certificate_der.empty()) {
        entry.tsa_fingerprint_sha256 = policy::LowerHex(policy::Sha256(result.tsa_certificate_der));
        CertificateMetadata metadata;
        std::string error;
        if (CryptoniteAdapter::ExtractCertificateMetadata(result.tsa_certificate_der, metadata, error)) {
            entry.tsa_subject = metadata.subject;
            entry.tsa_issuer = metadata.issuer;
            entry.tsa_serial = metadata.serial_number_hex;
        }
    }
    return entry;
}

// WP-11 (HI-06): детермінована проєкція canonical ValidationReport у legacy
// VerifyReport. Раніше цю саму роботу робив ApplyValidationEngineReport, що
// МУТУВАВ вже частково заповнений (іншим, legacy trust-пайплайном) VerifyReport&
// — два незалежні джерела правди могли залишити суміш полів із різних
// моделей (HI-06). Ця функція не приймає і не
// повертає жодного зовнішнього стану: увесь VerifyReport будується наново,
// виключно з полів ValidationReport.
VerifyReport ProjectVerifyReport(const validation::ValidationReport& ve_report) {
    using namespace tamga::core::validation;

    VerifyReport report;
    const ValidationDecision& decision = ve_report.decision;
    const bool signer_certificate_present = HasSignerCertificateEvidence(ve_report);

    report.signature_valid = decision.signature_valid;
    report.signer_certificate_present = signer_certificate_present;

    // Ланцюг довіри із PathSelection.
    const bool path_selected = ve_report.path_selection.selected_index != PathSelection::npos;
    const bool path_trusted = path_selected && ve_report.path_selection.selected_result.trusted;
    report.chain_checked = path_selected;
    report.chain_valid = path_trusted;
    report.chain_debug = ve_report.path_selection.selected_result.chain_debug;

    // WP-3 (CR-02): канонічний certificateTimeValid — реальна X.509
    // notBefore/notAfter перевірка сертифіката підписанта на фактично
    // використаному evaluation_time, незалежно від того, чи ланцюг дійшов до
    // довіреного якоря.
    report.certificate_time_valid = path_selected &&
                                    ve_report.path_selection.selected_result.signer_certificate_time_valid;
    report.validation_time_source = CanonicalValidationTimeSource(ve_report.signing_time_resolution,
                                                                  signer_certificate_present);

    report.trust_checked = true;
    report.trust_valid = decision.trust_valid;

    // Статус відкликання — єдине джерело: RevocationEngine (не спадщина з
    // попередньої мутації того самого VerifyReport).
    //
    // V-02: `checked` означає, що перевірку СПРАВДІ виконано, а не що рушій
    // викликали. Раніше тут стояло `!because.empty()`, але `because` отримує
    // рядок ролі завжди (`RevocationEngine.cpp:31`), навіть коли немає ні
    // OCSP-URL, ні CRL — і звіт заявляв `checked:true` при `not-checked`.
    // Фактичні прапорці спроб уже існують і заповнюються самим рушієм.
    report.revocation_checked = ve_report.signer_revocation.ocsp_attempted ||
                                ve_report.signer_revocation.crl_attempted;
    report.ocsp_checked = ve_report.signer_revocation.ocsp_attempted;
    report.revocation_status = CanonicalRevocationStatusString(ve_report.signer_revocation.revocation_status);

    // V-01: ЕФЕКТИВНИЙ вердикт відкликання, а не сирий enum.
    //
    // `RevocationEngine` свідомо повертає `overall_status = Valid`, якщо
    // сертифікат відкликано ПІСЛЯ моменту оцінки підпису
    // (`RevocationEngine.cpp:179-183`): підпис, створений до відкликання,
    // лишається дійсним — це прямо передбачено ETSI EN 319 102-1 і є типовим
    // сценарієм (сертифікат відкликають через рік після договору).
    //
    // Раніше проєкція гілкувалася за сирим `revocation_status == Revoked` і
    // безумовно скидала `trust_valid`, тобто ПЕРЕКРИВАЛА правильне рішення
    // канонічного рушія. Наслідком був юридично значущий хибний негатив:
    // історично валідний підпис звітувався як недійсний.
    const bool revocation_defeats_trust =
        ve_report.signer_revocation.overall_status != OverallStatus::Valid;

    const bool uses_historical = path_trusted && ve_report.path_selection.selected_result.uses_historical_trust;
    report.historical_trust_used = uses_historical;
    report.trust_mode = uses_historical ? "historical" : "strict";
    if (uses_historical) {
        const auto& hist_res = ve_report.path_selection.selected_result;
        if (!hist_res.signer_issuer_certificate_der.empty()) {
            report.historical_anchor_subject = hist_res.trust_anchor_source;
        }
    }

    if (ve_report.trust_service.checked) {
        report.trust_list_checked = true;
        report.trust_list_cache_status = "snapshot";
        if (!ve_report.trust_service.snapshot_evidence_id.empty()) {
            report.trust_list_source = ve_report.trust_service.snapshot_evidence_id;
        }
    }

    report.trust_status = decision.trust_status;
    report.trust_reason = decision.trust_reason;

    // V-01: обидві гілки застосовуються ЛИШЕ коли відкликання справді
    // знецінює довіру. Якщо канонічний рушій визнав стан валідним (відкликання
    // сталося після моменту оцінки підпису), публічний звіт не має права
    // перетворювати це на помилку — інакше два звіти на тих самих даних дають
    // протилежні вердикти.
    if (revocation_defeats_trust &&
        ve_report.signer_revocation.revocation_status == policy::RevocationStatus::Invalid) {
        report.trust_valid = false;
        report.trust_status = "revocation-check-invalid";
        report.error_code = ErrorCode::RevocationCheckFailed;
        if (!ve_report.signer_revocation.because.empty()) {
            report.message = ve_report.signer_revocation.because.front();
        }
    } else if (revocation_defeats_trust &&
               ve_report.signer_revocation.revocation_status == policy::RevocationStatus::Revoked) {
        report.trust_valid = false;
        report.trust_status = "certificate-revoked";
        report.error_code = ErrorCode::RevocationCheckFailed;
        report.message = "Certificate is revoked by CRL policy.";
    } else if (ve_report.signer_revocation.revocation_status == policy::RevocationStatus::Revoked) {
        // Відкликано, але вже ПІСЛЯ моменту оцінки підпису. Вердикт лишається
        // валідним; факт відкликання не приховуємо — він іде як попередження,
        // щоб користувач бачив повну картину.
        if (!ve_report.signer_revocation.warnings.empty()) {
            report.message = ve_report.signer_revocation.warnings.front();
        } else if (!ve_report.signer_revocation.because.empty()) {
            report.message = ve_report.signer_revocation.because.front();
        }
    }

    // Мітка часу.
    if (ve_report.timestamp_attempted) {
        report.timestamp_details.push_back(ProjectTimestampResult(ve_report.timestamp));
        report.timestamp_checked = true;
        report.timestamp_valid = ve_report.timestamp.valid;
        report.tsp_checked = true;
        switch (ve_report.timestamp.status) {
            case policy::TimestampStatus::Valid:
                report.timestamp_status = "timestamp-valid";
                break;
            case policy::TimestampStatus::InvalidImprint:
            case policy::TimestampStatus::InvalidSignature:
            case policy::TimestampStatus::Unsupported:
                // Криптографічно пошкоджений або нерозбірливий токен — це не
                // «частково перевірено». Інакше CAdES маскує підміну імпринта
                // чи підпису TSA як звичайну відсутність trust-матеріалу.
                report.timestamp_status = "timestamp-invalid";
                break;
            case policy::TimestampStatus::UntrustedTsa:
            case policy::TimestampStatus::TsaExpired:
                // Сам токен криптографічно коректний, але повного policy-
                // вердикту щодо TSA немає.
                report.timestamp_status = "timestamp-partial";
                break;
            case policy::TimestampStatus::NotChecked:
            case policy::TimestampStatus::Missing:
                report.timestamp_status = "timestamp-not-validated";
                break;
        }
        ApplyTimestampDetailsVerdict(report);
    } else {
        report.timestamp_status = "timestamp-not-validated";
    }

    // error_code із ValidationDecision. На відміну від колишнього
    // ApplyValidationEngineReport тут немає "legacy вже встановив специфічний
    // код" — report свіжий, тож достатньо перевірити, що жодна з гілок вище
    // (revocation Invalid/Revoked) ще не виставила власний специфічний код.
    switch (decision.overall_status) {
        case OverallStatus::Valid:
        case OverallStatus::IntegrityOnly:
            break;
        case OverallStatus::Indeterminate:
            if (!decision.trust_valid && report.error_code == ErrorCode::None) {
                report.error_code = TrustFailureErrorCode(report);
            }
            break;
        case OverallStatus::Invalid:
            if (report.revocation_status == "revoked") {
                report.error_code = ErrorCode::RevocationCheckFailed;
            } else if (report.error_code == ErrorCode::None) {
                report.error_code = ErrorCode::InvalidArgument;
            }
            break;
    }

    return report;
}

} // namespace tamga::core
