#include "core/validation/RevocationEngine.h"

#include "core/policy/OcspValidator.h"
#include "core/policy/CrlValidator.h"
#include "core/policy/CertificateChainValidator.h"

#include <ctime>
#include <algorithm>

namespace tamga::core::validation {

namespace {

std::string RoleToString(CertificateRole role) {
    switch (role) {
        case CertificateRole::Signer: return "Signer";
        case CertificateRole::IntermediateCa: return "IntermediateCa";
        case CertificateRole::Tsa: return "Tsa";
        case CertificateRole::OcspResponder: return "OcspResponder";
        case CertificateRole::CrlIssuer: return "CrlIssuer";
    }
    return "Unknown";
}

int DiagnosticRank(const policy::RevocationStatus status) {
    switch (status) {
        case policy::RevocationStatus::Invalid: return 4;
        case policy::RevocationStatus::Stale: return 3;
        case policy::RevocationStatus::ResponderUnavailable: return 2;
        case policy::RevocationStatus::Unknown: return 1;
        default: return 0;
    }
}

void KeepMoreSpecificFailure(const policy::RevocationStatus status, const std::string& message,
                             policy::RevocationStatus& current, std::string& current_message) {
    if (DiagnosticRank(status) > DiagnosticRank(current)) {
        current = status;
        current_message = message;
    }
}

} // namespace

RevocationEngineResult RevocationEngine::Validate(const RevocationEngineInput& input) const {
    RevocationEngineResult result;

    // Додаємо роль сертифіката до причин для відстеження та тестування
    result.because.push_back("Роль сертифіката: " + RoleToString(input.role));

    if (input.certificate_der.empty()) {
        result.overall_status = OverallStatus::Indeterminate;
        result.revocation_status = policy::RevocationStatus::NotChecked;
        result.because.push_back("Помилка: сертифікат порожній.");
        return result;
    }

    time_t validation_time_sec = std::time(nullptr);
    if (!input.validation_time.empty()) {
        time_t parsed_time = 0;
        if (policy::ParseIso8601Time(input.validation_time, parsed_time)) {
            validation_time_sec = parsed_time;
        } else {
            result.warnings.push_back("Не вдалося розпарсити validation_time: " + input.validation_time);
        }
    }

    policy::RevocationStatus final_status = policy::RevocationStatus::NotChecked;
    time_t final_revocation_time = 0;
    std::string detail_message;

    // 1. Спробувати вбудовану/кешовану відповідь(і) OCSP. WP-5: XAdES
    // RevocationValues може нести кілька EncapsulatedOCSPValue (напр. окремо
    // для OCSP-responder сертифіката) — перебираємо усіх кандидатів і
    // зупиняємось на першому, що дає визначений good/revoked статус для саме
    // цього certificate_der/issuer_certificate_der (CertID-звірка усередині
    // OcspValidator відкидає відповіді для інших сертифікатів).
    std::vector<std::vector<std::uint8_t>> ocsp_candidates;
    if (!input.embedded_ocsp_response.empty()) {
        ocsp_candidates.push_back(input.embedded_ocsp_response);
    }
    for (const auto& candidate : input.embedded_ocsp_responses_der) {
        if (!candidate.empty()) {
            ocsp_candidates.push_back(candidate);
        }
    }
    for (const auto& response_der : ocsp_candidates) {
        policy::OcspValidationInput ocsp_input;
        ocsp_input.signer_certificate_der = input.certificate_der;
        ocsp_input.issuer_certificate_der = input.issuer_certificate_der;
        ocsp_input.response_der = response_der;
        ocsp_input.validation_time = input.validation_time;

        const auto ocsp_res = policy::OcspValidator{}.Validate(ocsp_input);
        result.ocsp_attempted = result.ocsp_attempted || ocsp_res.checked;
        if (!ocsp_res.request_evidence_id.empty()) {
            result.evidence_ids.push_back(ocsp_res.request_evidence_id);
        }
        if (!ocsp_res.response_evidence_id.empty()) {
            result.evidence_ids.push_back(ocsp_res.response_evidence_id);
        }

        if (ocsp_res.checked && (ocsp_res.status == policy::RevocationStatus::Good ||
                                 ocsp_res.status == policy::RevocationStatus::Revoked)) {
            final_status = ocsp_res.status;
            final_revocation_time = ocsp_res.revocation_time;
            detail_message = ocsp_res.message;
            result.because.push_back("Використано вбудовану відповідь OCSP.");
            break;
        } else {
            KeepMoreSpecificFailure(ocsp_res.status, ocsp_res.message, final_status, detail_message);
            result.warnings.push_back("Вбудована відповідь OCSP не дала результату: " + ocsp_res.message);
        }
    }

    // 2. Спробувати локальні CRL
    if (final_status != policy::RevocationStatus::Good &&
        final_status != policy::RevocationStatus::Revoked &&
        !input.crls_der.empty()) {
        
        policy::CrlValidationInput crl_input;
        crl_input.signer_certificate_der = input.certificate_der;
        crl_input.issuer_certificate_der = input.issuer_certificate_der;
        crl_input.crls_der = input.crls_der;
        crl_input.validation_time = input.validation_time;

        const auto crl_res = policy::CrlValidator{}.Validate(crl_input);
        result.crl_attempted = crl_res.checked;
        if (!crl_res.crl_evidence_id.empty()) {
            result.evidence_ids.push_back(crl_res.crl_evidence_id);
        }

        if (crl_res.checked && (crl_res.status == policy::RevocationStatus::Good ||
                                crl_res.status == policy::RevocationStatus::Revoked)) {
            final_status = crl_res.status;
            final_revocation_time = crl_res.revocation_time;
            detail_message = crl_res.message;
            result.because.push_back("Використано локальний CRL.");
        } else if (crl_res.checked &&
                   (crl_res.status == policy::RevocationStatus::Invalid ||
                    crl_res.status == policy::RevocationStatus::Stale)) {
            KeepMoreSpecificFailure(crl_res.status, crl_res.message, final_status, detail_message);
            result.because.push_back("Локальний CRL не дав чинного статусу: " + crl_res.message);
        } else {
            KeepMoreSpecificFailure(crl_res.status, crl_res.message, final_status, detail_message);
            result.warnings.push_back("Локальний CRL не дав результату: " + crl_res.message);
        }
    }

    // 3. Запит через мережу (OCSP)
    if (final_status != policy::RevocationStatus::Good &&
        final_status != policy::RevocationStatus::Revoked) {

        if (input.network_allowed && !input.ocsp_url.empty()) {
            policy::OcspValidationInput ocsp_input;
            ocsp_input.url = input.ocsp_url;
            ocsp_input.signer_certificate_der = input.certificate_der;
            ocsp_input.issuer_certificate_der = input.issuer_certificate_der;
            ocsp_input.validation_time = input.validation_time;

            const auto ocsp_res = policy::OcspValidator{}.Validate(ocsp_input);
            result.ocsp_attempted = result.ocsp_attempted || ocsp_res.checked;
            if (!ocsp_res.request_evidence_id.empty()) {
                result.evidence_ids.push_back(ocsp_res.request_evidence_id);
            }
            if (!ocsp_res.response_evidence_id.empty()) {
                result.evidence_ids.push_back(ocsp_res.response_evidence_id);
            }

            if (ocsp_res.checked && (ocsp_res.status == policy::RevocationStatus::Good ||
                                     ocsp_res.status == policy::RevocationStatus::Revoked)) {
                final_status = ocsp_res.status;
                final_revocation_time = ocsp_res.revocation_time;
                detail_message = ocsp_res.message;
                result.because.push_back("Отримано статус через мережевий OCSP.");
            } else {
                KeepMoreSpecificFailure(ocsp_res.status, ocsp_res.message, final_status, detail_message);
                result.warnings.push_back("Мережевий запит OCSP завершився статусом: " + detail_message);
            }
        } else {
            if (!input.network_allowed) {
                result.warnings.push_back("Мережевий доступ заборонено конфігурацією.");
            }
            if (input.ocsp_url.empty()) {
                result.warnings.push_back("Адресу OCSP не налаштовано.");
            }
        }
    }

    result.revocation_status = final_status;

    // Оцінка фінального статусу
    if (final_status == policy::RevocationStatus::Good) {
        result.overall_status = OverallStatus::Valid;
        result.because.push_back("Сертифікат не відкликано.");
    } else if (final_status == policy::RevocationStatus::Revoked) {
        // Перевіряємо час відкликання
        if (final_revocation_time != 0 && final_revocation_time > validation_time_sec) {
            // Відкликано після моменту оцінки підпису
            result.overall_status = OverallStatus::Valid;
            result.because.push_back("Сертифікат відкликано після моменту оцінки підпису (дійсний на момент підпису).");
            result.warnings.push_back("Сертифікат був відкликаний у часі: " + std::to_string(final_revocation_time));
        } else {
            // Відкликано до або в момент оцінки підпису
            result.overall_status = OverallStatus::Invalid;
            result.because.push_back("Сертифікат відкликано до моменту оцінки підпису.");
            if (final_revocation_time != 0) {
                result.because.push_back("Час відкликання: " + std::to_string(final_revocation_time));
            }
        }
    } else if (final_status == policy::RevocationStatus::Invalid) {
        // Некоректні дані відкликання — фіксуємо як помилку
        result.overall_status = OverallStatus::Indeterminate;
        result.because.push_back("Дані відкликання некоректні: " + detail_message);
        result.warnings.push_back("revocation-check-invalid");
    } else {
        // Невідомий/Неперевірений статус
        result.because.push_back("Не вдалося однозначно визначити статус відкликання: " + detail_message);
        if (input.revocation_hard_fail) {
            result.overall_status = OverallStatus::Indeterminate;
            result.warnings.push_back("Сувора політика відкликання (hard fail): статус невизначено.");
        } else {
            result.overall_status = OverallStatus::Indeterminate;
            result.limitations.push_back("М'яка політика відкликання (soft fail): статус не підтверджено.");
        }
    }

    result.revocation_time = final_revocation_time;
    return result;
}

} // namespace tamga::core::validation
