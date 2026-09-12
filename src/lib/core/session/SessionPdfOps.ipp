#include <ctime>
#include <sstream>
// Session-оркестрація PAdES (підпис PDF) поверх pades-builder/verifier.
// Доступно лише у збірці з TAMGA_ENABLE_PDF_SIGNATURES; інакше — NotSupported.

#if defined(TAMGA_PDF_SIGNATURES_ENABLED)
#include "pades/PadesBuilder.h"
#include "pades/PadesVerifier.h"
// А-07: матеріал валідації для /DSS профілів LT/LTA — через наявний кеш CRL,
// а не через другу реалізацію завантаження.
#include "core/policy/CrlCache.h"
#include "core/policy/CrlValidator.h"
#include "core/policy/OcspValidator.h"
#include "core/policy/TimestampValidator.h"
#include "core/validation/TimestampEngine.h"
#include "core/session/PadesEvidenceCollection.h"
#include "core/session/PadesTimestampVerdict.h"
#endif

namespace tamga::core {

namespace {
[[maybe_unused]] const char* kPadesDisabledMessage =
    "PAdES support requires building with TAMGA_ENABLE_PDF_SIGNATURES";

#if defined(TAMGA_PDF_SIGNATURES_ENABLED)
// А-07: розбір назви профілю. Приймаються і повні назви ("pades-lt"), і
// короткі ("lt") — так само, як `SignXml` приймає "xades-t".
//
// Регістр не важливий: 1С-конфігурації передають рядок як є, і відмова через
// велику літеру була б відмовою заради букви, а не заради безпеки.
bool ParsePadesProfileName(const std::string& text, tamga::pades::PadesProfile& out) {
    std::string key;
    key.reserve(text.size());
    for (const unsigned char ch : text) {
        key.push_back(static_cast<char>(std::tolower(ch)));
    }
    if (key.empty() || key == "b" || key == "pades-b") {
        out = tamga::pades::PadesProfile::B;
        return true;
    }
    if (key == "t" || key == "pades-t") {
        out = tamga::pades::PadesProfile::T;
        return true;
    }
    if (key == "lt" || key == "pades-lt") {
        out = tamga::pades::PadesProfile::LT;
        return true;
    }
    if (key == "lta" || key == "pades-lta") {
        out = tamga::pades::PadesProfile::LTA;
        return true;
    }
    return false;
}

void AppendPadesEvidence(std::vector<std::vector<std::uint8_t>>& pool,
                         const std::vector<std::uint8_t>& value) {
    if (!value.empty() && std::find(pool.begin(), pool.end(), value) == pool.end()) pool.push_back(value);
}

} // namespace
namespace pades_detail {

// Це збір і прив'язка доказів, не trust-policy: якір довіри визначається
// лише канонічним рушієм перевірки. Кожен issuer звіряється криптографічно.
bool CollectPadesCertificateEvidence(
    const std::vector<std::uint8_t>& certificate,
    const std::vector<std::vector<std::uint8_t>>& candidates,
    const std::vector<std::vector<std::uint8_t>>& ca_anchors,
    const std::string& work_dir, bool offline, const OcspSettings& ocsp_settings,
    const std::string& validation_time, tamga::pades::PadesValidationEvidence& evidence,
    std::string& error) {
    error.clear();
    std::time_t parsed_time{};
    if (!validation_time.empty() && !policy::ParseIso8601Time(validation_time, parsed_time)) {
        error = "Некоректний момент перевірки доказів PAdES-LT";
        return false;
    }
    auto current = certificate;
    std::vector<std::vector<std::uint8_t>> visited;
    for (unsigned depth = 0; depth < 32; ++depth) {
        if (current.empty()) break;
        AppendPadesEvidence(evidence.certificate_chain, current);
        if (std::find(visited.begin(), visited.end(), current) != visited.end()) break;
        visited.push_back(current);
        // Довірений CA-якір може бути проміжним, не самопідписаним.
        // Над-якоревий шлях не потрібен для пакування доказів. Лист (TSA
        // або підписувач) завжди проходить перевірку відкликання нижче.
        if (depth != 0 && std::find(ca_anchors.begin(), ca_anchors.end(), current) != ca_anchors.end()) {
            return true;
        }
        const auto issuer = validation::FindVerifiedTsaIssuer(current, candidates);
        if (issuer.empty()) {
            error = "Не знайдено криптографічно підтвердженого видавця для доказів PAdES-LT";
            return false;
        }
        AppendPadesEvidence(evidence.certificate_chain, issuer);
        if (issuer == current && depth != 0) {
            return true;
        }
        policy::OcspValidationInput ocsp_input;
        ocsp_input.signer_certificate_der = current;
        ocsp_input.issuer_certificate_der = issuer;
        ocsp_input.validation_time = validation_time;
        ocsp_input.timeout_ms = ocsp_settings.timeout_ms;
        ocsp_input.use_nonce = ocsp_settings.use_nonce;
        bool good = false;
        // Повторний токен не обходить перевірку свіжості. Придатна кешована
        // відповідь перевіряється без мережі й не змінює DSS новими байтами.
        for (const auto& response : evidence.ocsp_responses) {
            if (response.empty()) continue;
            ocsp_input.response_der = response;
            const auto ocsp = policy::OcspValidator{}.Validate(ocsp_input);
            if (ocsp.status == policy::RevocationStatus::Revoked) {
                error = "Сертифікат доказів PAdES-LT відкликано за вбудованим OCSP";
                return false;
            }
            good = good || (ocsp.status == policy::RevocationStatus::Good && !ocsp.response_der.empty());
        }

        if (!good && !evidence.crls.empty()) {
            policy::CrlValidationInput crl_input;
            crl_input.signer_certificate_der = current;
            crl_input.issuer_certificate_der = issuer;
            crl_input.validation_time = validation_time;
            crl_input.crls_der = evidence.crls;
            auto crl = policy::CrlValidator{}.Validate(crl_input);
            if (crl.status == policy::RevocationStatus::Revoked) {
                error = "Сертифікат доказів PAdES-LT відкликано";
                return false;
            }
            good = crl.status == policy::RevocationStatus::Good;
        }

        // Пріоритет OCSP над багатомегабайтними CRL при онлайн-зборі (PAdES-LT/LTA).
        if (!good && !offline) {
            ocsp_input.response_der.clear();
            ocsp_input.url = validation::ResolveTsaOcspUrl(current, issuer, work_dir);
            if (ocsp_input.url.empty()) ocsp_input.url = ocsp_settings.url;
            if (!ocsp_input.url.empty()) {
                const auto ocsp = policy::OcspValidator{}.Validate(ocsp_input);
                if (ocsp.status == policy::RevocationStatus::Revoked) {
                    error = "Сертифікат доказів PAdES-LT відкликано за OCSP";
                    return false;
                }
                good = ocsp.status == policy::RevocationStatus::Good && !ocsp.response_der.empty();
                if (good) AppendPadesEvidence(evidence.ocsp_responses, ocsp.response_der);
            }
        }

        // Якщо OCSP недоступний/не підтверджено: перевіряємо валідний відповідний CRL.
        if (!good) {
            if (!offline) {
                policy::DownloadAndCacheCrlsForCert(current, work_dir, ocsp_settings.timeout_ms);
            }
            std::vector<std::vector<std::uint8_t>> matching_crls;
            policy::LoadMatchingCrlsFromWorkDir(work_dir, {current}, matching_crls);
            if (!matching_crls.empty()) {
                policy::CrlValidationInput crl_input;
                crl_input.signer_certificate_der = current;
                crl_input.issuer_certificate_der = issuer;
                crl_input.validation_time = validation_time;
                crl_input.crls_der = matching_crls;
                auto crl = policy::CrlValidator{}.Validate(crl_input);
                if (crl.status == policy::RevocationStatus::Revoked) {
                    error = "Сертифікат доказів PAdES-LT відкликано";
                    return false;
                }
                if (crl.status == policy::RevocationStatus::Good) {
                    good = true;
                    for (const auto& der : matching_crls) {
                        AppendPadesEvidence(evidence.crls, der);
                    }
                }
            }
        }

        if (!good) {
            error = "Немає підтверджених CRL/OCSP для сертифіката доказів PAdES-LT";
            return false;
        }
        if (issuer == current) return true;
        current = issuer;
    }
    error = "Циклічний або надмірно довгий ланцюг доказів PAdES-LT";
    return false;
}
} // namespace pades_detail
namespace {
#endif
}  // namespace

bool Session::SignPdf(const std::vector<std::uint8_t>& document_content,
                      std::vector<std::uint8_t>& signed_pdf_out) {
    // Історична двоаргументна форма: профіль B, як і до А-07.
    return SignPdf(document_content, std::string{}, signed_pdf_out);
}

bool Session::SignPdf(const std::vector<std::uint8_t>& document_content,
                      const std::string& pades_profile,
                      std::vector<std::uint8_t>& signed_pdf_out) {
    signed_pdf_out.clear();
#if defined(TAMGA_PDF_SIGNATURES_ENABLED)
    tamga::pades::PadesProfile profile = tamga::pades::PadesProfile::B;
    if (!ParsePadesProfileName(pades_profile, profile)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::NotSupported,
                 "SignPdf: непідтримуваний профіль \"" + pades_profile +
                 "\"; очікується \"pades-b\", \"pades-t\", \"pades-lt\" або \"pades-lta\"");
        return false;
    }
    const int level = static_cast<int>(profile);
    const bool needs_timestamp = level >= static_cast<int>(tamga::pades::PadesProfile::T);
    const bool needs_dss = level >= static_cast<int>(tamga::pades::PadesProfile::LT);

    // Звуження critical section — той самий патерн, що в SignXml для XAdES-T:
    // мітка часу і довантаження CRL ходять у мережу, і тримати на цей час
    // mutex_ означало б блокувати всю сесію на час чужого таймауту.
    tamga::core::SigningKey key;
    TspSettings tsp_settings;
    OcspSettings ocsp_settings;
    bool offline_mode = true;
    std::string work_dir;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        if (!is_private_key_loaded_) {
            SetError(ErrorCode::KeyNotLoaded, ToString(ErrorCode::KeyNotLoaded));
            return false;
        }
        key.use_pkcs12 = (loaded_key_format_ == KeyFormat::Pkcs12);
        key.key_material = loaded_key_material_;
        key.certificate_der = loaded_certificate_;
        key.password = loaded_key_password_;
        tsp_settings = tsp_settings_;
        ocsp_settings = ocsp_settings_;
        offline_mode = settings_.offline_mode;
        work_dir = settings_.work_dir;
    }

    if (key.certificate_der.empty()) {
        std::string cert_error;
        std::vector<std::uint8_t> signer_cert;
        if (CryptoniteAdapter::ExtractSignerCertificate(key.use_pkcs12, key.key_material,
                                                        key.certificate_der, key.password,
                                                        signer_cert, cert_error)) {
            key.certificate_der = std::move(signer_cert);
        }
    }

    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::pades::PadesBuilder builder(crypto, tsp);
    tamga::pades::PadesParameters params;
    params.profile = profile;

    if (needs_timestamp) {
        std::string tsp_url = tsp_settings.url;
        if (tsp_url.empty()) {
            tsp_url = ResolveDefaultTspUrlCombined(key.certificate_der, work_dir);
        }
        if (tsp_url.empty() || offline_mode) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::OnlineServiceUnavailable,
                     "PAdES-T і вище потребують адреси TSP і онлайн-режиму; "
                     "скористайтеся ConfigureTsp() і Configure(offline=false)");
            return false;
        }
        const TspSettings captured_tsp = tsp_settings;
        const std::string captured_url = std::move(tsp_url);
        // Той самий провайдер, що для XAdES-T: одна реалізація політики міток
        // часу на обидва формати (ADR-026).
        params.timestamp_provider = [captured_tsp, captured_url](
            const std::vector<std::uint8_t>& tbs,
            std::vector<std::uint8_t>& token,
            std::string& error) -> bool {
            ImprintResult imprint;
            if (!ResolveTspImprint(captured_tsp, tbs, {}, imprint, error)) return false;
            return TspClient::GetTimestamp(imprint.hash, imprint.digest_oid, captured_url,
                                           captured_tsp.timeout_ms, captured_tsp.policy_oid,
                                           token, error);
        };
    }

    if (needs_dss) {
        // Матеріал валідації для /DSS. Сертифікати — з довірчого сховища й
        // проміжних; CRL — через наявний кеш (мережа лише коли онлайн).
        //
        // Історичні якорі теж потрібні тут: ЦЗО переносить сертифікат служби
        // QTSP у historical-trust-store, щойно видає нову діючу серію, навіть
        // якщо стара серія (яка й підписала конкретний ключ підписувача) ще в
        // межах власного строку дії. Без цього PAdES-LT відхиляв би доказ
        // цілком легітимного, ще дійсного видавця — той самий випадок, що
        // ASiC-шлях (SessionAsicOps.ipp) уже враховує через
        // CollectHistoricalTrustAnchors/CollectHistoricalTsaAnchors.
        std::vector<std::vector<std::uint8_t>> anchors;
        std::vector<std::vector<std::uint8_t>> intermediates;
        CollectTrustAnchors(work_dir, anchors);
        {
            std::vector<std::vector<std::uint8_t>> historical_anchors;
            CollectHistoricalTrustAnchors(work_dir, historical_anchors);
            for (const auto& cert : historical_anchors) AppendPadesEvidence(anchors, cert);
        }
        CollectIntermediateCertificates(work_dir, intermediates);

        tamga::core::policy::CertificateChainInput chain_input;
        chain_input.signer_certificate_der = key.certificate_der;
        chain_input.intermediate_certificates_der = intermediates;
        chain_input.trust_anchors_der = anchors;
        const auto chain = tamga::core::policy::CertificateChainValidator{}.Validate(chain_input);

        if (!key.certificate_der.empty()) {
            params.certificate_chain.push_back(key.certificate_der);
        }
        if (!chain.signer_issuer_certificate_der.empty()) {
            params.certificate_chain.push_back(chain.signer_issuer_certificate_der);
        }
        if (!chain.issuer_certificate_der.empty() &&
            chain.issuer_certificate_der != chain.signer_issuer_certificate_der) {
            params.certificate_chain.push_back(chain.issuer_certificate_der);
        }

        // CRL не є єдиним джерелом: збір нижче також підтримує OCSP.
        if (params.certificate_chain.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::OnlineServiceUnavailable,
                     "PAdES-LT потребує сертифіката підписувача для збору доказів /DSS");
            return false;
        }
        std::vector<std::vector<std::uint8_t>> candidates = intermediates;
        for (const auto& cert : anchors) AppendPadesEvidence(candidates, cert);
        std::vector<std::vector<std::uint8_t>> tsa_certificates;
        CollectTsaAnchors(work_dir, tsa_certificates);
        {
            std::vector<std::vector<std::uint8_t>> historical_tsa_certificates;
            CollectHistoricalTsaAnchors(work_dir, historical_tsa_certificates);
            for (const auto& cert : historical_tsa_certificates) AppendPadesEvidence(tsa_certificates, cert);
        }
        for (const auto& cert : tsa_certificates) AppendPadesEvidence(candidates, cert);
        for (const auto& cert : params.certificate_chain) AppendPadesEvidence(candidates, cert);
        tamga::pades::PadesValidationEvidence evidence{
            params.certificate_chain, params.crls, params.ocsp_responses};
        std::string evidence_error;
        if (!pades_detail::CollectPadesCertificateEvidence(key.certificate_der, candidates, anchors,
                work_dir, offline_mode, ocsp_settings, {}, evidence, evidence_error)) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::OnlineServiceUnavailable, std::move(evidence_error));
            return false;
        }
        params.certificate_chain = evidence.certificate_chain;
        params.crls = evidence.crls;
        params.ocsp_responses = evidence.ocsp_responses;
        // Кеш належить лише цій операції. На кожен фактичний genTime докази
        // перевіряються заново, але придатні CRL/OCSP не завантажуються вдруге.
        params.timestamp_evidence_provider =
            [candidates = std::move(candidates), evidence = std::move(evidence),
             anchors, work_dir, offline_mode, ocsp_settings](
                const std::vector<std::uint8_t>& token, const std::vector<std::uint8_t>& tbs,
                tamga::pades::PadesValidationEvidence& output, std::string& error) mutable {
                const auto timestamp = policy::ValidateTimestampToken(token, tbs, candidates);
                if (!timestamp.valid) {
                    error = "Не можна збирати докази непідтвердженого токена TSA: " + timestamp.message;
                    return false;
                }
                std::string timestamp_time;
                if (!validation::NormalizeTimestampTime(timestamp.gen_time, timestamp_time)) {
                    error = "Некоректний genTime токена TSA для збору доказів PAdES-LT";
                    return false;
                }
                for (const auto& cert : timestamp.embedded_certificates_der) {
                    AppendPadesEvidence(candidates, cert);
                }
                AppendPadesEvidence(candidates, timestamp.tsa_certificate_der);
                if (!pades_detail::CollectPadesCertificateEvidence(timestamp.tsa_certificate_der,
                        candidates, anchors, work_dir, offline_mode, ocsp_settings,
                        timestamp_time, evidence, error)) return false;
                output = evidence;
                return true;
            };
    }

    std::string error_message;
    if (!builder.SignPdf(params, document_content, key, signed_pdf_out, error_message)) {
        signed_pdf_out.clear();
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError, std::move(error_message));
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearError();
    }
    return true;
#else
    (void)document_content;
    (void)pades_profile;
    std::lock_guard<std::mutex> lock(mutex_);
    SetError(ErrorCode::NotSupported, kPadesDisabledMessage);
    return false;
#endif
}

bool Session::VerifyPdf(const std::vector<std::uint8_t>& pdf, bool& is_valid) {
    is_valid = false;

    // Q-001 (звуження critical section): той самий патерн, що вже застосований
    // у VerifyXml (WP-17), VerifyData/VerifyDataInternal (ME-04) і
    // VerifyFileAsicEXades (PR #39) — mutex_ тримається лише для (1) початкової
    // перевірки стану + знімка Settings і (2) фінального коміту результату;
    // PAdES-парсинг і мережевий trust/revocation-pipeline (RunFormatTrustValidationOn)
    // працюють над ЛОКАЛЬНИМ Settings/VerifyReport, без lock_guard.
    Settings local_settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        local_settings = settings_;
    }
#if defined(TAMGA_PDF_SIGNATURES_ENABLED)
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::pades::PadesVerifier verifier(crypto, tsp);
    tamga::pades::PadesVerificationResult result;
    std::string error_message;
    if (!verifier.VerifyPdf(pdf, result, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError, std::move(error_message));
        return false;
    }
    // К-01: документ-рівнева відповідь ураховує покриття. `signature_valid`
    // нижче лишається СУТО криптографічною цілісністю CMS (для файла з
    // дописаним суфіксом CMS справді цілий) — цього вимагає AGENTS.md, який
    // забороняє видавати криптоперевірку за ширший вердикт. Але на питання
    // «чи валідно підписаний ЦЕЙ файл» відповідь має бути «ні», якщо частина
    // файла не покрита жодним підписом.
    is_valid = result.signature_valid && result.coverage_complete;

    // Phase 7: форматний звіт PAdES.
    auto profile_name = [](tamga::pades::PadesProfile p) -> const char* {
        switch (p) {
            case tamga::pades::PadesProfile::B: return "PAdES-B";
            case tamga::pades::PadesProfile::T: return "PAdES-T";
            case tamga::pades::PadesProfile::LT: return "PAdES-LT";
            case tamga::pades::PadesProfile::LTA: return "PAdES-LTA";
        }
        return "PAdES";
    };
    VerifyReport report;
    report.has_result = true;
    report.execution_succeeded = true;
    report.signature_valid = result.signature_valid;
    report.signature_format = "PAdES";
    report.format_profile = profile_name(result.detected_profile);
    report.signer_certificate_present = result.signature_count > 0;
    const int plevel = static_cast<int>(result.detected_profile);
    if (plevel >= static_cast<int>(tamga::pades::PadesProfile::T)) {
        report.timestamp_checked = true;
        // В-03: до trust-валідації канонічного вердикту ще немає, тож
        // крипто-результат подається як частковий.
        ApplyFormatTimestampVerdict(report, result.timestamps_valid, /*canonical_full=*/false);
    }
    report.ltv_valid = result.ltv_valid;
    // HI-02: PAdES не має окремого поняття "refs прив'язані до values"
    // (немає XAdES-подібних CompleteCertificateRefs/CompleteRevocationRefs) —
    // DSS-словник структурно або є, або немає, тож ltv_evidence_bound тут
    // збігається зі структурним ltv_valid (DSS присутній, /Certs непорожній
    // — тепер підтверджено фактичним парсингом обʼєктного графа qpdf, а не
    // наївним пошуком підрядків, див. PadesVerifier::VerifyPdf).
    report.ltv_evidence_bound = result.ltv_valid;
    // К-01: раніше поле лишалось типовим `true` (Session.h) на ВСЬОМУ
    // PDF-шляху — присвоєння було тільки в ASiC-шляху. Через це PAdES завжди
    // звітував повне покриття, навіть для файла з дописаними байтами.
    report.container_coverage_complete = result.coverage_complete;
    report.coverage_status = result.coverage_status;
    report.operation = "VerifyPdf";
    report.policy = "pades-format";
    // Діагностика PAdES. До цього `message` лишався порожнім навіть на відмові:
    // PadesVerifier збирав notes (ByteRange, помилки VerifyDetached, timestamp),
    // але вони нікуди не виводились, тож звіт казав "невалідний" без жодної
    // підказки — на відміну від XAdES-шляху, який друкує per-reference
    // expected/computed дайджести. Без цього діагностувати PAdES неможливо.
    {
        std::ostringstream diag;
        diag << "PAdES diagnostics: pdfWellFormed=" << (result.pdf_well_formed ? "true" : "false")
             << "; byteRangeValid=" << (result.byte_range_valid ? "true" : "false")
             << "; signatureCount=" << result.signature_count
             << "; profile=" << report.format_profile
             << "; timestampsValid=" << (result.timestamps_valid ? "true" : "false")
             << "; ltvStructural=" << (result.ltv_valid ? "true" : "false")
             << "; dssCerts=" << result.dss_certificates_der.size()
             << "; dssOcsp=" << result.dss_ocsp_responses_der.size()
             << "; dssCrls=" << result.dss_crls_der.size()
             << "; containerCoverageComplete=" << (result.coverage_complete ? "true" : "false")
             << "; coverageStatus=" << result.coverage_status
             << "; signedCoverageEnd=" << result.signed_coverage_end
             << "; documentSize=" << result.document_size;
        for (const auto& note : result.notes) {
            diag << "; " << note;
        }
        report.message = diag.str();
    }

    // Кожен CMS і весь DSS передаються канонічному рушію незалежно.
    // Перший підпис зберігає legacy верхньорівневі signer-поля; деталізація
    // всіх підписів і агрегація TSA не можуть бути представлені лише ним.
    bool canonical_signature_timestamp_full = true;
    std::vector<TimestampEntry> signature_timestamp_details;
    std::vector<SignatureEntry> signature_entries;
    for (std::size_t i = 0; i < result.main_signatures.size(); ++i) {
        const auto& evidence = result.main_signatures[i];
        VerifyReport signer_report;
        RunFormatTrustValidationOn(local_settings, evidence.signer_certificate_der, evidence.cms_der,
                                  result.dss_certificates_der, result.dss_ocsp_responses_der,
                                  result.dss_crls_der, evidence.signature_valid, signer_report);
        if (evidence.signature_timestamp_present) {
            canonical_signature_timestamp_full = canonical_signature_timestamp_full &&
                signer_report.timestamp_status == "timestamp-valid";
            if (signer_report.timestamp_details.empty()) {
                TimestampEntry missing;
                missing.status = "timestamp-partial";
                missing.reason_code = "timestamp-validation-unavailable";
                missing.limitations.push_back("Канонічний рушій не повернув результат мітки CMS");
                signer_report.timestamp_details.push_back(std::move(missing));
            }
            for (auto& detail : signer_report.timestamp_details) {
                detail.signature_index = static_cast<int>(i + 1);
                detail.kind = "signature";
                detail.signed_revision_end = evidence.signed_revision_end;
                signature_timestamp_details.push_back(detail);
            }
        }
        SignatureEntry entry;
        entry.index = static_cast<int>(i + 1);
        entry.signature_valid = evidence.signature_valid;
        entry.signer_certificate_present = !evidence.signer_certificate_der.empty();
        entry.format_profile = profile_name(result.detected_profile);
        entry.timestamp_checked = signer_report.timestamp_checked;
        entry.timestamp_valid = signer_report.timestamp_valid;
        entry.timestamp_status = signer_report.timestamp_status;
        entry.timestamp_details = signer_report.timestamp_details;
        entry.ltv_valid = result.ltv_valid;
        entry.ltv_evidence_bound = result.ltv_valid;
        entry.ltv_evidence_validated = result.ltv_valid && signer_report.trust_valid &&
            (signer_report.revocation_status == "valid" || signer_report.revocation_status == "good");
        entry.certificate_time_valid = signer_report.certificate_time_valid;
        entry.validation_time_source = signer_report.validation_time_source;
        entry.chain_checked = signer_report.chain_checked;
        entry.chain_valid = signer_report.chain_valid;
        entry.chain_debug = signer_report.chain_debug;
        entry.trust_checked = signer_report.trust_checked;
        entry.trust_valid = signer_report.trust_valid;
        entry.trust_status = signer_report.trust_status;
        entry.trust_mode = signer_report.trust_mode;
        entry.trust_reason = signer_report.trust_reason;
        entry.historical_trust_used = signer_report.historical_trust_used;
        entry.historical_anchor_subject = signer_report.historical_anchor_subject;
        entry.historical_anchor_serial = signer_report.historical_anchor_serial;
        entry.revocation_checked = signer_report.revocation_checked;
        entry.ocsp_checked = signer_report.ocsp_checked;
        entry.revocation_status = signer_report.revocation_status;
        entry.error_code = signer_report.error_code;
        entry.message = signer_report.message;
        signature_entries.push_back(std::move(entry));
        if (i == 0) {
            const std::string diagnostics = report.message;
            report = std::move(signer_report);
            if (!diagnostics.empty()) report.message = diagnostics + "; " + report.message;
        }
    }
    report.timestamp_details = std::move(signature_timestamp_details);
    report.signatures = std::move(signature_entries);
    report.has_result = true;
    report.execution_succeeded = true;
    report.signature_valid = result.signature_valid;
    report.operation = "VerifyPdf";

    // ПД-01: документна мітка часу (PAdES-LTA, поле SubFilter=ETSI.RFC3161) НЕ
    // є частиною CMS підпису, тож у `cms_der` її немає в принципі. Її доказ
    // подається в той самий канонічний рушій явно — через
    // `TryCanonicalTimestampVerdict` (SessionAsicOps.ipp), який заповнює
    // `TimestampEngineInput::explicit_timestamp_token_der` і
    // `explicit_timestamp_imprint_source`. Це той самий шлях, яким уже йдуть
    // контейнерні мітки ASiC і мітка XAdES: жодної другої реалізації політики
    // довіри до TSA тут не з'являється (ADR-026).
    bool canonical_document_timestamp_full = true;
    std::string canonical_timestamp_reason;
    const bool has_document_timestamp = !result.document_timestamp_tokens_der.empty();
    const std::vector<std::uint8_t> kNoImprintSource;
    for (std::size_t i = 0; i < result.document_timestamp_tokens_der.size(); ++i) {
        const auto& token = result.document_timestamp_tokens_der[i];
        const std::vector<std::uint8_t>& imprint_source =
            i < result.document_timestamp_imprint_sources.size()
                ? result.document_timestamp_imprint_sources[i]
                : kNoImprintSource;
        bool dts_valid = false;
        std::string dts_reason;
        TimestampEntry detail;
        // Fail-closed: якщо канонічний вердикт недосяжний (немає cryptonite чи
        // trust-матеріалу) або він негативний — повний статус НЕ видається.
        const bool canonical_available = TryCanonicalTimestampVerdict(
            local_settings, token, imprint_source, /*validation_time=*/std::string{}, dts_valid,
            dts_reason, result.dss_certificates_der, result.dss_ocsp_responses_der,
            result.dss_crls_der, &detail);
        detail.kind = "document";
        detail.signature_index = static_cast<int>(result.main_signatures.size() + i + 1);
        detail.signed_revision_end = i < result.document_timestamp_revision_ends.size()
            ? result.document_timestamp_revision_ends[i] : 0;
        if (!canonical_available) {
            detail.status = "timestamp-partial";
            detail.reason_code = "timestamp-validation-unavailable";
            detail.limitations.push_back("Відсутній придатний токен або джерело imprint DocTimeStamp");
        }
        if (detail.signed_revision_end == 0) {
            detail.valid = false;
            detail.crypto_valid = false;
            detail.status = "timestamp-invalid";
            detail.reason_code = "timestamp-byte-range-invalid";
            dts_valid = false;
        }
        report.timestamp_details.push_back(std::move(detail));
        if (!canonical_available || !dts_valid) {
            canonical_document_timestamp_full = false;
            if (canonical_timestamp_reason.empty() && !dts_reason.empty()) {
                canonical_timestamp_reason = dts_reason;
            }
        }
    }

    // ПД-01: повний вердикт лише тоді, коли (а) доказ мітки взагалі є і (б)
    // КОЖНА наявна мітка — і signature timestamp у CMS, і кожна документна —
    // пройшла канонічний рушій. Відсутність доказу не може дати "valid".
    const bool has_timestamp_evidence = result.signature_timestamp_present || has_document_timestamp;
    const bool canonical_timestamp_full =
        has_timestamp_evidence &&
        (!result.signature_timestamp_present || canonical_signature_timestamp_full) &&
        (!has_document_timestamp || canonical_document_timestamp_full);
    if (!canonical_timestamp_full && !canonical_timestamp_reason.empty()) {
        if (!report.message.empty()) {
            report.message += "; ";
        }
        report.message += "PAdES document timestamp: " + canonical_timestamp_reason;
    }

    report.signature_format = "PAdES";
    report.format_profile = profile_name(result.detected_profile);
    if (plevel >= static_cast<int>(tamga::pades::PadesProfile::T)) {
        report.timestamp_checked = true;
        report.tsp_checked = true;
        // В-03: канонічний вердикт, якщо TimestampEngine його встиг дати, не
        // понижуємо; але й не підвищуємо крипто-результат до "valid".
        pades_detail::ApplyPadesTimestampVerdict(report, result.timestamps_valid, canonical_timestamp_full);
    }
    report.ltv_valid = result.ltv_valid;
    report.ltv_evidence_bound = result.ltv_valid;
    // К-01: відновлюємо форматне поле після RunFormatTrustValidationOn — тим
    // самим прийомом, яким вище відновлюються timestamp/ltv поля.
    report.container_coverage_complete = result.coverage_complete;
    report.coverage_status = result.coverage_status;
    // HI-02: той самий вираз, що XAdES-шлях використовує для validated_profile
    // /ltv_evidence_validated — докази структурно присутні (bound) І
    // trust-ланцюг довірений (RunFormatTrustValidationOn вище) І відкликання
    // підтверджено.
    report.ltv_evidence_validated =
        report.ltv_evidence_bound && report.trust_valid &&
        (report.revocation_status == "valid" || report.revocation_status == "good");

    // Фінальний коміт: єдина ділянка, де це знову торкається спільного стану
    // Session, — короткий lock без жодного мережевого виклику під ним.
    // Q-003: RefreshUserReport оновлює кеш last_user_report_json_ (який читає
    // GetUserReport()) — раніше VerifyPdf його НЕ викликав, тож GetUserReport()
    // після VerifyPdf повертав звіт попередньої операції.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_verify_report_ = std::move(report);
        // Н-04: фіксуємо епоху цього коміту — доуточнення нижче застосується
        // лише якщо звіт усе ще належить цьому потоку.
        MarkVerifyReportCommittedLocked();
        RefreshUserReport("PDF", "PAdES");
        ClearError();
    }
    return true;
#else
    (void)pdf;
    std::lock_guard<std::mutex> lock(mutex_);
    SetError(ErrorCode::NotSupported, kPadesDisabledMessage);
    return false;
#endif
}

}  // namespace tamga::core
