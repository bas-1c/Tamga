// ValidationEngine.cpp — повний оркестратор pipeline валідації КЕП/CMS/CAdES
// Milestone 9: ValidationEngine Integration
// Сумісний з українською PKI (TL-UA, КНЕДП, ЦЗО, НБУ).

#include "core/validation/ValidationEngine.h"
#include "util/Vectors.h"

#include "core/policy/PolicyTypes.h"
#include "core/policy/CrlCache.h"
#include "util/FileSystem.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace tamga::core::validation {
namespace {



// ─────────────────────────────────────────────────────────────────────────────
// Допоміжні функції завантаження сертифікатів із файлової системи
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Зчитує всі DER-файли (*.cer, *.crt, *.der) із директорії.
 */
void LoadCertificatesFromDir(const std::filesystem::path& dir,
                             std::vector<std::vector<std::uint8_t>>& certs) {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec) || !std::filesystem::is_directory(dir, ec)) {
        return;
    }
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec || !entry.is_regular_file(ec)) {
            continue;
        }
        const auto& path = entry.path();
        const std::filesystem::path ext = path.extension();
        if (ext != std::filesystem::path(".cer") &&
            ext != std::filesystem::path(".crt") &&
            ext != std::filesystem::path(".der")) {
            continue;
        }
        std::vector<std::uint8_t> data;
        std::string read_error;
        if (!util::ReadBinaryFileLimited(path, util::kMaxCertificateFileSize, data, read_error)) {
            continue;
        }
        if (!data.empty()) {
            certs.push_back(std::move(data));
        }
    }
}

/**
 * Зчитує вміст XML-файлу списку довіри.
 */
std::string ReadTrustListXml(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return {};
    }
    std::string xml;
    std::string read_error;
    if (!util::ReadTextFileLimited(path, util::kMaxCachedArtifactSize, xml, read_error)) {
        return {};
    }
    return xml;
}

/**
 * Перетворює std::filesystem::path → UTF-8 рядок (C++17/C++20-сумісно).
 */
// ADR-027: копія прибрана — одна реалізація в `util/FileSystem`.
using tamga::util::PathToUtf8;

/**
 * V-03: СТАБІЛЬНИЙ ідентифікатор знімка довірчого списку — без локального шляху.
 *
 * Раніше сюди йшов `PathToUtf8(snapshot_path)`, тобто АБСОЛЮТНИЙ шлях до
 * `work_dir/trust-list/...`, і він серіалізувався у публічний звіт як
 * `diagnostics.trustList.source`. Наслідком був витік топології машини (диск,
 * імʼя користувача, структура каталогів) у документ, який 1С може передавати
 * далі, а сам звіт ставав недетермінованим: той самий підпис на двох машинах
 * давав різні звіти.
 *
 * Ідентифікатор будується відносно `work_dir` і несе рівно ту інформацію, яка
 * має значення для перевірки: який саме знімок узято — поточний чи історичний.
 */
std::string StableSnapshotId(const std::filesystem::path& snapshot_path,
                             const std::string& work_dir) {
    std::error_code ec;
    const std::filesystem::path work_path = std::filesystem::u8path(work_dir);
    const std::filesystem::path relative = std::filesystem::relative(snapshot_path, work_path, ec);
    if (ec || relative.empty()) {
        return "unknown";
    }

    // Очікувані форми: "trust-list/TL-UA-EC.xml" і "trust-list/history/<файл>".
    // generic_u8string() дає '/' на всіх платформах, тож ідентифікатор однаковий
    // і на Windows, і на Linux.
    const auto generic = relative.generic_u8string();
#if defined(__cpp_char8_t)
    const std::string rel(reinterpret_cast<const char*>(generic.data()), generic.size());
#else
    const std::string rel = generic;
#endif
    if (rel.rfind("..", 0) == 0) {
        // Знімок поза work_dir — шлях не розкриваємо в жодному разі.
        return "unknown";
    }
    const std::string history_prefix = "trust-list/history/";
    if (rel.rfind(history_prefix, 0) == 0) {
        return "history/" + rel.substr(history_prefix.size());
    }
    if (rel.rfind("trust-list/", 0) == 0) {
        return "current";
    }
    return "unknown";
}

// ─────────────────────────────────────────────────────────────────────────────
// Синтез ValidationDecision із результатів усіх етапів
// ─────────────────────────────────────────────────────────────────────────────

// ADR-027: копія прибрана — шаблон живе в `util/Vectors.h`.
using tamga::util::AppendAll;

/**
 * Маппінг статусу відкликання → рядок для legacy VerifyReport.
 */
[[maybe_unused]] const char* RevocationStatusToString(policy::RevocationStatus status) {
    switch (status) {
        case policy::RevocationStatus::Good:                return "good";
        case policy::RevocationStatus::Revoked:             return "revoked";
        case policy::RevocationStatus::Unknown:             return "unknown";
        case policy::RevocationStatus::Invalid:             return "invalid";
        case policy::RevocationStatus::Stale:               return "stale";
        case policy::RevocationStatus::ResponderUnavailable: return "temporarily-unavailable";
        case policy::RevocationStatus::NotChecked:          return "not-checked";
    }
    return "not-checked";
}

/**
 * Синтезує фінальне ValidationDecision із результатів усіх підетапів.
 *
 * Правила:
 *  - Якщо підпис кріптографічно не валідний → Invalid
 *  - Якщо сертифікат відкликано → Invalid
 *  - Якщо trust_valid=false при strict-профілі → Indeterminate
 *  - Якщо revocation indeterminate + hard_fail → Indeterminate
 *  - Якщо рівень Basic → IntegrityOnly (без trust/revocation)
 *  - Якщо всі перевірки пройшли → Valid
 */
ValidationDecision SynthesizeDecision(
    bool signature_crypto_valid,
    const PathSelection& path_selection,
    const std::vector<PathValidationResult>& path_results,
    const TrustServiceDecision& trust_service,
    const RevocationEngineResult& signer_revocation,
    const TimestampEngineResult& timestamp,
    bool timestamp_attempted,
    const SigningTimeResolution& signing_time,
    const ValidationPolicy& policy,
    const ValidationContext& context) {

    ValidationDecision decision;
    decision.signature_valid = signature_crypto_valid;
    decision.trusted_signing_time = signing_time.trusted_time ? signing_time.signature_evaluation_time : "";
    decision.signature_evaluation_time = signing_time.signature_evaluation_time;

    // Базовий рівень: перевіряємо лише цілісність підпису
    if (context.level == ValidationLevel::Basic) {
        decision.level_reached = ValidationLevel::Basic;
        if (!signature_crypto_valid) {
            decision.overall_status = OverallStatus::Invalid;
            decision.summary = "invalid";
            decision.because.push_back("Криптографічна перевірка підпису не пройшла.");
            return decision;
        }
        decision.overall_status = OverallStatus::IntegrityOnly;
        decision.summary = "integrity-only";
        decision.because.push_back("Рівень Basic: перевірена лише цілісність підпису.");
        return decision;
    }

    // Підпис невалідний — завжди Invalid незалежно від рівня
    if (!signature_crypto_valid) {
        decision.overall_status = OverallStatus::Invalid;
        decision.summary = "invalid";
        decision.because.push_back("Криптографічна перевірка підпису не пройшла.");
        return decision;
    }

    // Сертифікат відкликано — Invalid
    if (signer_revocation.revocation_status == policy::RevocationStatus::Revoked &&
        signer_revocation.overall_status == OverallStatus::Invalid) {
        decision.overall_status = OverallStatus::Invalid;
        decision.summary = "invalid";
        decision.because.push_back("Сертифікат підписанта відкликано.");
        AppendAll(decision.because, signer_revocation.because);
        return decision;
    }

    // Оцінка trust_valid із вибраного шляху довіри
    const bool path_trusted = path_selection.selected_index != PathSelection::npos &&
                              path_selection.selected_result.trusted;
    const bool uses_historical = path_trusted && path_selection.selected_result.uses_historical_trust;

    // Якщо trust_service checked — додатково враховуємо рівень сервісу
    const bool service_level_ok = !policy.require_service_level_trust || trust_service.service_trusted;

    decision.trust_valid = path_trusted && service_level_ok;

    // Шукаємо, чи є успішний historical шлях у strict режимі
    bool has_historical_trust_match = false;
    for (const auto& res : path_results) {
        if (res.candidate_id == "historical-tl" && res.trusted) {
            has_historical_trust_match = true;
            break;
        }
    }

    // Розраховуємо trust_status та trust_reason
    if (decision.trust_valid) {
        decision.trust_status = "trusted-anchor-validated";
        decision.trust_reason = uses_historical
            ? "historical-tl-anchor: " + path_selection.selected_result.trust_anchor_source
            : "current-tl-anchor";
    } else {
        if (has_historical_trust_match) {
            decision.trust_status = "legacy-anchor-not-in-current-tl";
            decision.trust_reason = "legacy-anchor-not-in-current-tl";
        } else if (path_selection.selected_result.status == policy::ChainStatus::Incomplete) {
            decision.trust_status = "certificate-chain-incomplete";
            decision.trust_reason = "legacy-anchor-not-in-current-tl";
        } else if (path_selection.selected_result.status == policy::ChainStatus::Expired) {
            decision.trust_status = "certificate-chain-time-invalid";
            decision.trust_reason = "expired-chain";
        } else if (path_selection.selected_result.status == policy::ChainStatus::InvalidSignature) {
            decision.trust_status = "certificate-chain-invalid";
            decision.trust_reason = "invalid-chain-signature";
        } else if (path_selection.selected_result.status == policy::ChainStatus::Untrusted) {
            if (path_selection.selected_result.message.find("empty") != std::string::npos) {
                decision.trust_status = "trust-store-empty";
                decision.trust_reason = "legacy-anchor-not-in-current-tl";
            } else {
                decision.trust_status = "untrusted-chain";
                decision.trust_reason = "current-tl-anchor-mismatch";
            }
        } else {
            decision.trust_status = "untrusted-chain";
            decision.trust_reason = "no-trusted-path";
        }
    }

    // При strict-профілі + не-довіреному ланцюжку — Indeterminate
    if (!decision.trust_valid && context.profile == ValidationProfile::Strict) {
        decision.overall_status = OverallStatus::Indeterminate;
        decision.summary = "indeterminate";
        decision.because.push_back("Ланцюжок довіри не вдалося вибудувати до поточного кореня (Strict-профіль).");
        AppendAll(decision.limitations, path_selection.selected_result.message.empty()
                      ? std::vector<std::string>{"no-trusted-path"}
                      : std::vector<std::string>{path_selection.selected_result.message});
        AppendAll(decision.warnings, signing_time.warnings);
        AppendAll(decision.limitations, signing_time.limitations);
        return decision;
    }

    // Відкликання indeterminate + hard fail → Indeterminate
    if (signer_revocation.overall_status == OverallStatus::Indeterminate &&
        policy.revocation_hard_fail) {
        decision.overall_status = OverallStatus::Indeterminate;
        decision.summary = "indeterminate";
        decision.because.push_back("Статус відкликання сертифіката не встановлено (hard-fail).");
        AppendAll(decision.because, signer_revocation.because);
        AppendAll(decision.warnings, signer_revocation.warnings);
        AppendAll(decision.limitations, signer_revocation.limitations);
        AppendAll(decision.warnings, signing_time.warnings);
        AppendAll(decision.limitations, signing_time.limitations);
        return decision;
    }

    // Мітка часу невалідна при вимозі — Indeterminate
    if (timestamp_attempted && !timestamp.valid &&
        policy.require_trusted_signing_time) {
        decision.overall_status = OverallStatus::Indeterminate;
        decision.summary = "indeterminate";
        decision.because.push_back("Мітка часу RFC3161 не пройшла перевірку, але вимагається довірений час підпису.");
        AppendAll(decision.because, timestamp.because);
        AppendAll(decision.warnings, timestamp.warnings);
        AppendAll(decision.limitations, timestamp.limitations);
        return decision;
    }

    // Trusted signing time
    if (signing_time.trusted_time) {
        decision.because.push_back("Довірений час підпису підтверджено RFC3161 міткою.");
    } else if (!signing_time.signature_evaluation_time.empty()) {
        decision.warnings.push_back("Час підпису не підтверджено криптографічно — використано fallback/claimed.");
    }

    // Підсумовуємо досягнутий рівень
    if (context.level >= ValidationLevel::Extended) {
        decision.level_reached = decision.trust_valid ? ValidationLevel::Extended : ValidationLevel::Standard;
    } else {
        decision.level_reached = ValidationLevel::Standard;
    }

    // Кваліфікована валідність: trust + service_level + trusted_time
    decision.qualified_valid = decision.trust_valid && signing_time.trusted_time;

    // LTV: наявність доказів (revocation + timestamp)
    decision.ltv_valid = IsLongTermValidationValid(decision.trust_valid,
                                                   signer_revocation.revocation_status,
                                                   timestamp_attempted,
                                                   timestamp.valid);

    // Фінальний статус
    if (decision.trust_valid) {
        decision.overall_status = OverallStatus::Valid;
        decision.summary = uses_historical ? "valid-historical-trust" : "valid";
        if (uses_historical) {
            decision.because.push_back("Ланцюжок довіри вибудований через архівний список довіри (historical-tl).");
            decision.warnings.push_back("historical-trust-used");
        } else {
            decision.because.push_back("Ланцюжок довіри вибудований через поточний список довіри.");
        }
    } else {
        // trust не вдалося, але не strict — Indeterminate
        decision.overall_status = OverallStatus::Indeterminate;
        decision.summary = "indeterminate";
        decision.because.push_back("Не вдалося встановити довіру до ланцюжка сертифікатів.");
    }

    AppendAll(decision.because, signer_revocation.because);
    AppendAll(decision.warnings, signer_revocation.warnings);
    AppendAll(decision.limitations, signer_revocation.limitations);
    AppendAll(decision.warnings, signing_time.warnings);
    AppendAll(decision.limitations, signing_time.limitations);
    if (timestamp_attempted) {
        AppendAll(decision.warnings, timestamp.warnings);
        AppendAll(decision.limitations, timestamp.limitations);
    }

    return decision;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// ValidationEngine::Validate — головний оркестратор
// ─────────────────────────────────────────────────────────────────────────────

ValidationReport ValidationEngine::Validate(
    const ValidationContext& context,
    const std::vector<std::uint8_t>& signer_certificate_der,
    const std::vector<std::vector<std::uint8_t>>& embedded_certificates_der) const {

    ValidationReport report;

    // ── Крок 1: PolicyResolver ───────────────────────────────────────────────
    const PolicyResolver policy_resolver;
    const ResolvedValidationPolicy resolved = policy_resolver.Resolve(context);
    const ValidationPolicy& policy = resolved.policy;
    const ValidationPlan& plan = resolved.plan;

    // ── Крок 2: EvidenceStore — реєстрація вхідних даних ────────────────────
    EvidenceStore& evidence = report.evidence;
    if (!signer_certificate_der.empty()) {
        evidence.PutRawEvidence("signer-certificate", signer_certificate_der, "cms-embedded");
    }
    for (const auto& cert : embedded_certificates_der) {
        if (!cert.empty()) {
            evidence.PutRawEvidence("embedded-certificate", cert, "cms-embedded");
        }
    }

    // ── Крок 3: Завантаження якорів довіри із файлової системи ──────────────
    std::vector<std::vector<std::uint8_t>> current_trust_anchors;
    std::vector<std::vector<std::uint8_t>> historical_trust_anchors;
    std::vector<std::vector<std::uint8_t>> intermediate_store_certs;
    std::vector<std::vector<std::uint8_t>> tsa_trust_anchors;
    std::vector<std::vector<std::uint8_t>> historical_tsa_trust_anchors;

    if (!context.work_dir.empty()) {
        const std::filesystem::path work_path = std::filesystem::u8path(context.work_dir);
        LoadCertificatesFromDir(work_path / "trust-store", current_trust_anchors);
        LoadCertificatesFromDir(work_path / "historical-trust-store", historical_trust_anchors);
        LoadCertificatesFromDir(work_path / "intermediate-store", intermediate_store_certs);
        // TSA endpoint certs із tsa-store (TL direct-match, ETSI TSL model)
        LoadCertificatesFromDir(work_path / "tsa-store", tsa_trust_anchors);
        LoadCertificatesFromDir(work_path / "historical-tsa-store", historical_tsa_trust_anchors);
    }

    // ── Крок 4: SigningTimeResolver (попередній) — fallback-кандидати часу ───
    std::vector<SigningTimeCandidate> time_candidates;

    if (!context.verification_time.empty()) {
        SigningTimeCandidate fallback_candidate;
        fallback_candidate.source = SigningTimeSource::VerificationTimeFallback;
        fallback_candidate.time = context.verification_time;
        fallback_candidate.cryptographically_valid = false;
        fallback_candidate.trusted = false;
        time_candidates.push_back(std::move(fallback_candidate));
    }

    // WP-10 (H4/ME-03): claimed signingTime як кандидат best-signature-time —
    // не криптографічно доведений, але вищий за current-time fallback. Дозволяє
    // оцінювати сертифікат/відкликання на заявлений час підпису (архівні
    // підписи: сертифікат прострочений «зараз», але був чинним на момент підпису).
    if (!context.claimed_signing_time.empty()) {
        SigningTimeCandidate claimed_candidate;
        claimed_candidate.source = SigningTimeSource::ClaimedSigningTime;
        claimed_candidate.time = context.claimed_signing_time;
        claimed_candidate.cryptographically_valid = false;
        claimed_candidate.trusted = false;
        time_candidates.push_back(std::move(claimed_candidate));
    }

    const SigningTimeResolver signing_time_resolver;
    const SigningTimeResolution provisional_time =
        signing_time_resolver.Resolve(time_candidates, context, policy);

    // ── Крок 5: TimestampEngine — RFC3161 мітка часу ────────────────────────
    // ETSI EN 319 102-1 вимагає оцінювати сертифікат/довіру на best signature
    // time. Тому timestamp має бути перевірений до signer path/revocation.
    report.timestamp_attempted = false;
    if (!context.cms_der.empty()) {
        TimestampEngineInput ts_input;
        ts_input.cms_der = context.cms_der;
        ts_input.validation_time = provisional_time.signature_evaluation_time;
        ts_input.policy = policy;
        ts_input.plan = plan;
        ts_input.current_trust_anchors_der = current_trust_anchors;
        ts_input.tsa_trust_anchors_der = tsa_trust_anchors;
        ts_input.historical_trust_anchors_der = historical_trust_anchors;
        ts_input.historical_tsa_trust_anchors_der = historical_tsa_trust_anchors;
        ts_input.intermediate_store_certificates_der = intermediate_store_certs;
        // ПД-01: вбудовані сертифікати (для PAdES-LT/LTA це /DSS/Certs) — пул
        // кандидатів на сертифікат підписанта TSA, якщо його немає в самому
        // токені. Лише джерело кандидатів; звірка SignerIdentifier і перевірка
        // підпису токена лишаються обов'язковими.
        ts_input.additional_tsa_candidate_certificates_der = embedded_certificates_der;
        ts_input.embedded_crls_der = context.embedded_revocation_crl_der;
        ts_input.embedded_ocsp_responses_der = context.embedded_revocation_ocsp_der;
        ts_input.profile = context.profile;
        ts_input.level = context.level;

        report.timestamp = TimestampEngine{}.Validate(ts_input);
        if (report.timestamp.status != policy::TimestampStatus::Missing) {
            report.timestamp_attempted = true;
        }
    }

    // ── Крок 6: SigningTimeResolver (фінальний) ──────────────────────────────
    std::vector<SigningTimeCandidate> final_candidates;
    std::string trusted_timestamp_time;
    if (report.timestamp_attempted && report.timestamp.valid &&
        NormalizeTimestampTime(report.timestamp.gen_time, trusted_timestamp_time)) {
        SigningTimeCandidate tsp_candidate;
        tsp_candidate.source = SigningTimeSource::Rfc3161Timestamp;
        tsp_candidate.time = std::move(trusted_timestamp_time);
        tsp_candidate.cryptographically_valid = true;
        tsp_candidate.trusted = true;
        if (!report.timestamp.evidence_ids.empty()) {
            tsp_candidate.evidence_id = report.timestamp.evidence_ids.front();
        }
        final_candidates.push_back(std::move(tsp_candidate));
    }
    final_candidates.insert(final_candidates.end(), time_candidates.begin(), time_candidates.end());

    report.signing_time_resolution = signing_time_resolver.Resolve(final_candidates, context, policy);
    const std::string evaluation_time = report.signing_time_resolution.signature_evaluation_time;

    // ── Крок 7: PathEngine — побудова і вибір ланцюжка довіри ───────────────
    PathBuilderInput path_input;
    path_input.signer_certificate_der = signer_certificate_der;
    path_input.embedded_certificates_der = embedded_certificates_der;
    path_input.intermediate_store_certificates_der = intermediate_store_certs;
    path_input.current_trust_anchors_der = current_trust_anchors;
    path_input.historical_trust_anchors_der = historical_trust_anchors;
    path_input.policy = policy;
    path_input.validation_time = evaluation_time;

    const PathBuilder path_builder;
    const PathValidator path_validator;
    const PathSelector path_selector;

    const auto candidates = path_builder.Build(path_input);
    std::vector<PathValidationResult> path_results;
    path_results.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        path_results.push_back(path_validator.Validate(candidate));
    }
    report.path_selection = path_selector.Select(path_results, policy);

    // ── Крок 8: TrustServiceEvaluator — оцінка запису КНЕДП у TL-UA ─────────
    const bool strict_current_tl = (policy.trust_anchor_policy == TrustAnchorPolicy::CurrentTLOnly);
    const std::filesystem::path snapshot_path =
        TrustServiceEvaluator::SelectSnapshot(context.work_dir, evaluation_time, strict_current_tl);
    const std::string trust_list_xml = ReadTrustListXml(snapshot_path);
    const std::string snapshot_id = StableSnapshotId(snapshot_path, context.work_dir);

    if (!trust_list_xml.empty() && !signer_certificate_der.empty()) {
        report.trust_service = TrustServiceEvaluator{}.Evaluate(
            signer_certificate_der, trust_list_xml, snapshot_id);
    }

    // ── Крок 9: RevocationEngine — перевірка відкликання підписанта ──────────
    std::vector<std::uint8_t> issuer_cert_der;
    if (report.path_selection.selected_index != PathSelection::npos) {
        issuer_cert_der = report.path_selection.selected_result.signer_issuer_certificate_der;
    }

    if (plan.network_allowed && !context.work_dir.empty()) {
        policy::DownloadAndCacheCrlsForCert(signer_certificate_der, context.work_dir, plan.timeout_ms);
        if (!issuer_cert_der.empty()) {
            policy::DownloadAndCacheCrlsForCert(issuer_cert_der, context.work_dir, plan.timeout_ms);
        }
    }

    std::vector<std::vector<std::uint8_t>> crls;
    policy::LoadCrlsFromWorkDir(context.work_dir, crls);
    // WP-5 (ME-07): додаємо XAdES-вбудовані CRL (RevocationValues) до
    // локального/кешованого набору — Дія B-LT доводить відкликання власними
    // embedded-доказами, без мережевого доступу.
    crls.insert(crls.end(), context.embedded_revocation_crl_der.begin(),
                context.embedded_revocation_crl_der.end());

    RevocationEngineInput rev_input;
    rev_input.certificate_der = signer_certificate_der;
    rev_input.issuer_certificate_der = issuer_cert_der;
    rev_input.role = CertificateRole::Signer;
    rev_input.validation_time = evaluation_time;
    rev_input.network_allowed = plan.network_allowed;
    rev_input.revocation_hard_fail = policy.revocation_hard_fail;
    rev_input.crls_der = crls;
    rev_input.embedded_ocsp_responses_der = context.embedded_revocation_ocsp_der;
    // WP-11: жива OCSP-перевірка signer-сертифіката (раніше — лише в legacy
    // trust-пайплайні CMS/CAdES; тепер єдиний шлях через ValidationEngine).
    rev_input.ocsp_url = context.ocsp_url;

    if (!signer_certificate_der.empty()) {
        report.signer_revocation = RevocationEngine{}.Validate(rev_input);
        for (const auto& eid : report.signer_revocation.evidence_ids) {
            evidence.PutDerivedEvidence("revocation-evidence", {{"id", eid}});
        }
    } else {
        report.signer_revocation.overall_status = OverallStatus::Indeterminate;
        report.signer_revocation.because.push_back("Сертифікат підписанта відсутній — перевірка відкликання неможлива.");
    }

    // ── Крок 10: Синтез ValidationDecision ──────────────────────────────────
    // F-04: криптографічний вердикт беремо з контексту, а не приймаємо за true.
    // Фактична перевірка (CryptoniteAdapter / XmlSignatureVerifier / PadesVerifier)
    // відбувається у викликача до входу сюди; ValidationEngine відповідає за
    // ланцюг, довіру, відкликання і час, але НЕ за саму криптографію — і тому не
    // має права підставляти за неї «валідно».
    report.decision = SynthesizeDecision(
        context.signature_crypto_valid,
        report.path_selection,
        path_results,
        report.trust_service,
        report.signer_revocation,
        report.timestamp,
        report.timestamp_attempted,
        report.signing_time_resolution,
        policy,
        context);

    // Причина має бути видимою у звіті, а не лише в булевому вердикті: інакше
    // «підпис невалідний» без пояснення виглядає як збій ланцюга чи довіри.
    if (!context.signature_crypto_valid) {
        report.decision.because.push_back(
            "Криптографічна перевірка підпису не підтверджена викликачем "
            "(ValidationContext.signature_crypto_valid=false).");
    }

    return report;
}

} // namespace tamga::core::validation
