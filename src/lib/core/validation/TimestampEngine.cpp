#include "core/validation/TimestampEngine.h"
#include "core/policy/CertificateChainValidator.h"
#include "core/cryptonite/CertUtil.h"
#include "core/net/CaSettingsRegistry.h"

#include "core/CryptoniteAdapter.h"
#include "core/policy/EkuUtils.h"
#include "core/policy/TimestampValidator.h"
#include "core/validation/PathEngine.h"
#include "core/validation/RevocationEngine.h"
#include "core/policy/CrlCache.h"

#include <algorithm>
#include <cstring>
#include <vector>
#include <filesystem>
#include <ctime>

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "cert.h"
#include "byte_array.h"
#include "pkix_errors.h"
#include "oids.h"
#include "AuthorityInfoAccessSyntax.h"
}
#endif

namespace tamga::core::validation {

namespace {

// RFC3161 використовує UTC GeneralizedTime. Перевіряємо календар до
// передачі часу нижчим шарам, які історично мають fallback на поточний час.
bool ParseTimestampTime(const std::string& raw, std::string& iso) {
    iso.clear();
    if (raw.size() < 15 || raw.size() > 64 || raw.back() != 'Z') return false;
    for (std::size_t i = 0; i < 14; ++i) {
        if (raw[i] < '0' || raw[i] > '9') return false;
    }
    if (raw.size() != 15) {
        if (raw.size() < 17 || raw[14] != '.') return false;
        for (std::size_t i = 15; i + 1 < raw.size(); ++i) {
            if (raw[i] < '0' || raw[i] > '9') return false;
        }
    }
    const auto number = [&](std::size_t offset, std::size_t count) {
        int value = 0;
        for (std::size_t i = 0; i < count; ++i) value = value * 10 + raw[offset + i] - '0';
        return value;
    };
    const int year = number(0, 4), month = number(4, 2), day = number(6, 2);
    const int hour = number(8, 2), minute = number(10, 2), second = number(12, 2);
    if (year < 1970 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
    const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    const int days[] = {31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (day < 1 || day > days[month - 1]) return false;
    const std::string normalized = raw.substr(0, 4) + "-" + raw.substr(4, 2) + "-" + raw.substr(6, 2) +
        "T" + raw.substr(8, 2) + ":" + raw.substr(10, 2) + ":" + raw.substr(12, 2) + "Z";
    std::time_t parsed{};
    if (!policy::ParseIso8601Time(normalized, parsed)) return false;
    iso = normalized;
    return true;
}

using CertificatePool = std::vector<std::vector<std::uint8_t>>;

void AppendUnique(CertificatePool& output, const CertificatePool& values) {
    for (const auto& value : values) {
        if (!value.empty() && std::find(output.begin(), output.end(), value) == output.end()) output.push_back(value);
    }
}

#if TAMGA_CRYPTONITE_ENABLED
std::vector<std::uint8_t> FindVerifiedIssuerImpl(const std::vector<std::uint8_t>& tsa_der,
                                           const CertificatePool& candidates) {
    const auto tsa = cryptonite_detail::DecodeCertificateDer(tsa_der);
    if (!tsa) return {};
    // Якір endpoint не обов'язково є своїм видавцем. Навіть DER-збіг сам із
    // собою приймаємо тільки після перевірки issuer/subject і підпису X.509.
    std::size_t examined = 0;
    for (const auto& der : candidates) {
        if (++examined > 512) break;
        const auto issuer = cryptonite_detail::DecodeCertificateDer(der);
        if (issuer && asn_equals(&Name_desc, &tsa->tbsCertificate.issuer, &issuer->tbsCertificate.subject) &&
            cryptonite_detail::VerifyCertificateByIssuer(tsa.get(), issuer.get())) return der;
    }
    return {};
}

std::string ResolveTsaOcspUrlImpl(const std::vector<std::uint8_t>& tsa_der,
                              const std::vector<std::uint8_t>& issuer_der,
                              const std::string& work_dir) {
    const auto tsa = cryptonite_detail::DecodeCertificateDer(tsa_der);
    if (tsa) {
        ByteArray* raw = nullptr;
        if (cert_get_ext_value(tsa.get(), oids_get_oid_numbers_by_id(OID_AUTHORITY_INFO_ACCESS_EXTENSION_ID), &raw) == RET_OK && raw) {
            auto* aia = static_cast<AuthorityInfoAccessSyntax_t*>(
                asn_decode_with_alloc(&AuthorityInfoAccessSyntax_desc, ba_get_buf(raw), ba_get_len(raw)));
            ba_free(raw);
            std::string url;
            if (aia) {
                for (int i = 0; i < aia->list.count && url.empty(); ++i) {
                    const auto* entry = aia->list.array[i];
                    if (!entry || !pkix_check_oid_equal(&entry->accessMethod, oids_get_oid_numbers_by_id(OID_OCSP_OID_ID)) ||
                        entry->accessLocation.present != GeneralName_PR_uniformResourceIdentifier) continue;
                    const auto& uri = entry->accessLocation.choice.uniformResourceIdentifier;
                    if (uri.buf && uri.size > 0) {
                        std::string candidate(reinterpret_cast<const char*>(uri.buf), static_cast<std::size_t>(uri.size));
                        if (candidate.find('\0') == std::string::npos &&
                            (candidate.rfind("http://", 0) == 0 || candidate.rfind("https://", 0) == 0)) url = std::move(candidate);
                    }
                }
                ASN_FREE(&AuthorityInfoAccessSyntax_desc, aia);
            }
            if (!url.empty()) return url;
        } else {
            ba_free(raw);
        }
    }
    // Резервне джерело — лише вже кешований реєстр і CN перевіреного видавця.
    // Завантаження реєстру тут не запускається, а URL не створює довіри.
    CertificateMetadata metadata;
    std::string error;
    std::vector<net::CaSettingsEntry> providers;
    if (!work_dir.empty() && !issuer_der.empty() && !FindVerifiedIssuerImpl(tsa_der, {issuer_der}).empty() &&
        CryptoniteAdapter::ExtractCertificateMetadata(issuer_der, metadata, error) &&
        !metadata.common_name.empty() && net::CaSettingsRegistry::Load(work_dir, true, {}, 0, providers, error)) {
        const auto* provider = net::CaSettingsRegistry::Find(providers, metadata.common_name);
        if (provider) return provider->ocsp_url;
    }
    return {};
}
#endif

} // namespace

bool NormalizeTimestampTime(const std::string& raw, std::string& iso) {
    return ParseTimestampTime(raw, iso);
}

std::vector<std::uint8_t> FindVerifiedTsaIssuer(const std::vector<std::uint8_t>& tsa_der,
                                               const CertificatePool& candidates) {
#if TAMGA_CRYPTONITE_ENABLED
    return FindVerifiedIssuerImpl(tsa_der, candidates);
#else
    (void)tsa_der; (void)candidates;
    return {};
#endif
}

std::string ResolveTsaOcspUrl(const std::vector<std::uint8_t>& tsa_der,
                              const std::vector<std::uint8_t>& issuer_der,
                              const std::string& work_dir) {
#if TAMGA_CRYPTONITE_ENABLED
    return ResolveTsaOcspUrlImpl(tsa_der, issuer_der, work_dir);
#else
    (void)tsa_der; (void)issuer_der; (void)work_dir;
    return {};
#endif
}

TimestampEngineResult TimestampEngine::Validate(const TimestampEngineInput& input) const {
    TimestampEngineResult result;
    CertificatePool certificate_candidates = input.additional_tsa_candidate_certificates_der;
    AppendUnique(certificate_candidates, input.intermediate_store_certificates_der);
    AppendUnique(certificate_candidates, input.tsa_trust_anchors_der);
    AppendUnique(certificate_candidates, input.current_trust_anchors_der);
    AppendUnique(certificate_candidates, input.historical_tsa_trust_anchors_der);
    AppendUnique(certificate_candidates, input.historical_trust_anchors_der);
    AppendUnique(certificate_candidates, input.custom_trust_anchors_der);
    AppendUnique(certificate_candidates, input.pinned_trust_anchors_der);

    policy::TimestampValidationResult val_res;
    if (!input.explicit_timestamp_token_der.empty()) {
        if (input.explicit_timestamp_imprint_source.empty()) {
            result.status = policy::TimestampStatus::Unsupported;
            result.reason_code = "TIMESTAMP_IMPRINT_SOURCE_MISSING";
            result.because.push_back("Помилка: explicit timestamp imprint source порожній.");
            return result;
        }
        val_res = policy::ValidateTimestampToken(input.explicit_timestamp_token_der,
                                                 input.explicit_timestamp_imprint_source,
                                                 certificate_candidates);
    } else {
        if (input.cms_der.empty()) {
            result.status = policy::TimestampStatus::Unsupported;
            result.reason_code = "TIMESTAMP_FORMAT_INVALID";
            result.because.push_back("Помилка: CMS порожній.");
            return result;
        }

        std::vector<std::uint8_t> signature_value;
        std::string error_message;
        if (!tamga::core::CryptoniteAdapter::GetSignatureValue(input.cms_der, signature_value, error_message)) {
            result.status = policy::TimestampStatus::Unsupported;
            result.reason_code = "TIMESTAMP_SIGNATURE_VALUE_MISSING";
            result.because.push_back("Не вдалося вилучити значення підпису: " + error_message);
            return result;
        }

        auto ext_res = policy::ExtractTimestampToken(input.cms_der);
        if (!ext_res.success) {
            result.reason_code = ext_res.failure_code;
            if (ext_res.failure_code == "TIMESTAMP_MISSING") {
                result.status = policy::TimestampStatus::Missing;
            } else {
                result.status = policy::TimestampStatus::InvalidSignature;
            }
            result.because.push_back("Не вдалося вилучити мітку часу: " + ext_res.message);
            return result;
        }

        val_res = policy::ValidateTimestampToken(ext_res.token_der, signature_value,
                                                 certificate_candidates);
    }

    result.gen_time = val_res.gen_time;
    if (!val_res.valid) {
        result.reason_code = val_res.failure_code;
        if (val_res.failure_code == "TIMESTAMP_IMPRINT_MISMATCH") {
            result.status = policy::TimestampStatus::InvalidImprint;
        } else if (val_res.failure_code == "TIMESTAMP_IMPRINT_UNSUPPORTED" || val_res.failure_code == "TIMESTAMP_UNSUPPORTED") {
            result.status = policy::TimestampStatus::Unsupported;
        } else if (val_res.failure_code == "TSA_CERTIFICATE_MISSING") {
            result.status = policy::TimestampStatus::UntrustedTsa;
        } else {
            result.status = policy::TimestampStatus::InvalidSignature;
        }
        result.because.push_back("Криптографічна перевірка мітки часу завершилася помилкою: " + val_res.message);
        return result;
    }

    result.crypto_valid = true;
    result.tsa_certificate_der = val_res.tsa_certificate_der;
    result.gen_time_valid = NormalizeTimestampTime(val_res.gen_time, result.validation_time);
    if (!result.gen_time_valid) {
        result.status = policy::TimestampStatus::InvalidSignature;
        result.reason_code = "TIMESTAMP_TIME_INVALID";
        result.because.push_back("genTime мітки не є коректним UTC GeneralizedTime; поточний час не підставляється.");
        return result;
    }
    const auto& timestamp_validation_time = result.validation_time;
    result.certificate_time_valid = policy::IsCertificateValidAt(val_res.tsa_certificate_der, timestamp_validation_time);
    if (!result.certificate_time_valid) {
        result.status = policy::TimestampStatus::TsaExpired;
        result.reason_code = "TSA_CERTIFICATE_TIME_INVALID";
        result.because.push_back("Сертифікат TSA не є чинним на момент мітки часу.");
        return result;
    }

    // 1. TL direct-match (ETSI EN 319 102-1 §5.4):
    // Якщо TSA signer cert ідентичний за DER будь-му запису в tsa-store
    // (ServiceDigitalIdentity з TL), він довірений без побудови ланцюжка.
    const auto& tsa_signer_der = val_res.tsa_certificate_der;
    const auto& direct_tsa_anchors = input.tsa_trust_anchors_der;

    bool direct_matched = false;
    const bool use_tl_endpoints = input.policy.trust_anchor_policy != TrustAnchorPolicy::CustomTrustStore &&
        input.policy.trust_anchor_policy != TrustAnchorPolicy::PinnedAnchors;
    for (const auto& anchor_der : direct_tsa_anchors) {
        if (use_tl_endpoints && !anchor_der.empty() && anchor_der == tsa_signer_der) {
            direct_matched = true;
            result.trust_source = "current-tl";
            break;
        }
    }

    if (use_tl_endpoints && !direct_matched && input.policy.allow_historical_trust) {
        const auto& direct_hist_tsa = input.historical_tsa_trust_anchors_der;
        for (const auto& anchor_der : direct_hist_tsa) {
            if (!anchor_der.empty() && anchor_der == tsa_signer_der) {
                direct_matched = true;
                result.trust_source = "historical-tl";
                result.historical_trust_used = true;
                break;
            }
        }
    }
    if (direct_matched) {
        result.because.push_back("TSA сертифікат збігається з endpoint-сертифікатом у списку довіри (TL direct-match).");
    }

    // 2. Валідація ланцюжка сертифіката TSA.
    // Для побудови ланцюжка об'єднуємо TSA-якорі та CA-якорі з trust-store,
    // оскільки TSA-сертифікат може бути випущений одним із загальних довірених CA.
    std::vector<std::vector<std::uint8_t>> effective_tsa_anchors = input.tsa_trust_anchors_der;
    effective_tsa_anchors.insert(effective_tsa_anchors.end(),
                                 input.current_trust_anchors_der.begin(),
                                 input.current_trust_anchors_der.end());

    std::vector<std::vector<std::uint8_t>> effective_historical_tsa_anchors = input.historical_tsa_trust_anchors_der;
    effective_historical_tsa_anchors.insert(effective_historical_tsa_anchors.end(),
                                            input.historical_trust_anchors_der.begin(),
                                            input.historical_trust_anchors_der.end());

    PathBuilderInput path_input;
    path_input.signer_certificate_der = val_res.tsa_certificate_der;
    path_input.embedded_certificates_der = val_res.embedded_certificates_der;
    AppendUnique(path_input.embedded_certificates_der, input.additional_tsa_candidate_certificates_der);
    path_input.intermediate_store_certificates_der = input.intermediate_store_certificates_der;
    path_input.current_trust_anchors_der = effective_tsa_anchors;
    path_input.historical_trust_anchors_der = effective_historical_tsa_anchors;
    path_input.custom_trust_anchors_der = input.custom_trust_anchors_der;
    path_input.pinned_trust_anchors_der = input.pinned_trust_anchors_der;
    path_input.policy = input.policy;
    path_input.validation_time = timestamp_validation_time;

    PathBuilder builder;
    auto candidates = builder.Build(path_input);
    if (candidates.empty() && !direct_matched) {
        result.status = policy::TimestampStatus::UntrustedTsa;
        result.reason_code = "TSA_UNTRUSTED";
        result.because.push_back("Не вдалося побудувати ланцюжок для сертифіката TSA (немає кандидатів).");
        return result;
    }

    PathValidator validator;
    std::vector<PathValidationResult> path_results;
    for (const auto& candidate : candidates) {
        path_results.push_back(validator.Validate(candidate));
    }

    PathSelector selector;
    auto selection = selector.Select(path_results, input.policy);
    if (!direct_matched && selection.selected_result.status == policy::ChainStatus::Expired) {
        result.status = policy::TimestampStatus::TsaExpired;
        result.reason_code = "TSA_CHAIN_TIME_INVALID";
        result.because.push_back("Сертифікат TSA або один із сертифікатів ланцюжка протерміновано на момент мітки часу.");
        return result;
    }
    if (!direct_matched &&
        (selection.selected_index == PathSelection::npos || !selection.selected_result.trusted)) {
        auto chain_status = selection.selected_result.status;
        if (chain_status == policy::ChainStatus::Expired) {
            result.status = policy::TimestampStatus::TsaExpired;
            result.reason_code = "TSA_CHAIN_TIME_INVALID";
            result.because.push_back("Сертифікат TSA або один із сертифікатів ланцюжка протерміновано.");
        } else {
            result.status = policy::TimestampStatus::UntrustedTsa;
            result.reason_code = "TSA_UNTRUSTED";
            result.because.push_back("Сертифікат TSA не є довіреним: " + selection.selected_result.message);
        }
        return result;
    }

    result.trust_valid = true;
    if (!direct_matched) {
        result.trust_source = selection.selected_result.trust_anchor_source;
        result.historical_trust_used = selection.selected_result.uses_historical_trust;
    }
    if (result.historical_trust_used) result.warnings.push_back("TSA_HISTORICAL_TRUST_USED");

    // Право TSA на створення міток перевіряється незалежно від рівня policy.
    {
        bool has_eku = false;
#if TAMGA_CRYPTONITE_ENABLED
        ByteArray* cert_ba = ba_alloc_from_uint8(val_res.tsa_certificate_der.data(), val_res.tsa_certificate_der.size());
        if (cert_ba != nullptr) {
            Certificate_t* cert = cert_alloc();
            if (cert != nullptr) {
                if (cert_decode(cert, cert_ba) == RET_OK) {
                    has_eku = tamga::core::policy::HasTimestampingEku(cert);
                }
                cert_free(cert);
            }
            ba_free(cert_ba);
        }
#endif
        if (!has_eku) {
            result.status = policy::TimestampStatus::UntrustedTsa;
            result.reason_code = "TSA_EKU_INVALID";
            result.because.push_back("Сертифікат TSA не містить розширення EKU для Timestamping (1.3.6.1.5.5.7.3.8).");
            return result;
        }
        result.eku_valid = true;
    }

    CertificatePool issuer_candidates;
    if (!selection.selected_result.signer_issuer_certificate_der.empty())
        issuer_candidates.push_back(selection.selected_result.signer_issuer_certificate_der);
    AppendUnique(issuer_candidates, val_res.embedded_certificates_der);
    AppendUnique(issuer_candidates, certificate_candidates);
#if TAMGA_CRYPTONITE_ENABLED
    result.tsa_issuer_certificate_der = FindVerifiedTsaIssuer(tsa_signer_der, issuer_candidates);
#endif
    if (result.tsa_issuer_certificate_der.empty()) {
        result.status = policy::TimestampStatus::UntrustedTsa;
        result.reason_code = "TSA_ISSUER_MISSING";
        result.policy_acceptable = !input.policy.revocation_hard_fail && !input.policy.require_trusted_signing_time;
        result.because.push_back("Не знайдено криптографічно підтвердженого видавця TSA для перевірки відкликання.");
        return result;
    }

    std::string work_dir;
    if (!input.plan.trust_store_path.empty()) {
        work_dir = std::filesystem::u8path(input.plan.trust_store_path).parent_path().u8string();
    }

    // Перевірка статусу відкликання сертифіката TSA через RevocationEngine
    RevocationEngineInput rev_input;
    rev_input.certificate_der = val_res.tsa_certificate_der;
    rev_input.issuer_certificate_der = result.tsa_issuer_certificate_der;
    rev_input.role = CertificateRole::Tsa;
    rev_input.validation_time = timestamp_validation_time;
    // Спершу лише вбудовані та кешовані докази. Мережа є fallback, а не
    // побічним ефектом навіть за повністю достатнього DSS.
    rev_input.network_allowed = false;
    rev_input.revocation_hard_fail = input.policy.revocation_hard_fail;
    rev_input.crls_der = input.embedded_crls_der;
    rev_input.embedded_ocsp_responses_der = input.embedded_ocsp_responses_der;
#if TAMGA_CRYPTONITE_ENABLED
    rev_input.ocsp_url = ResolveTsaOcspUrl(tsa_signer_der, result.tsa_issuer_certificate_der, work_dir);
#endif

    if (!work_dir.empty()) {
        CertificatePool cached_crls;
        policy::LoadCrlsFromWorkDir(work_dir, cached_crls);
        AppendUnique(rev_input.crls_der, cached_crls);
    }

    RevocationEngine revocation_engine;
    auto rev_result = revocation_engine.Validate(rev_input);
    if (rev_result.overall_status == OverallStatus::Indeterminate && input.plan.network_allowed) {
        if (!work_dir.empty()) {
            policy::DownloadAndCacheCrlsForCert(val_res.tsa_certificate_der, work_dir, input.plan.timeout_ms);
            CertificatePool downloaded_crls;
            policy::LoadCrlsFromWorkDir(work_dir, downloaded_crls);
            AppendUnique(rev_input.crls_der, downloaded_crls);
        }
        rev_input.network_allowed = true;
        rev_result = revocation_engine.Validate(rev_input);
    }
    result.revocation_status = rev_result.revocation_status;
    result.ocsp_attempted = rev_result.ocsp_attempted;
    result.crl_attempted = rev_result.crl_attempted;
    result.revocation_checked = result.ocsp_attempted || result.crl_attempted;
    for (const auto& because_str : rev_result.because) {
        result.because.push_back(because_str);
    }
    for (const auto& warning_str : rev_result.warnings) {
        result.warnings.push_back(warning_str);
    }
    for (const auto& limitation_str : rev_result.limitations) {
        result.limitations.push_back(limitation_str);
    }
    for (const auto& evidence_id : rev_result.evidence_ids) {
        result.evidence_ids.push_back(evidence_id);
    }

    if (rev_result.overall_status == OverallStatus::Invalid) {
        result.status = policy::TimestampStatus::UntrustedTsa;
        result.reason_code = rev_result.revocation_status == policy::RevocationStatus::Revoked
            ? "TSA_REVOKED" : "TSA_REVOCATION_INVALID";
        result.because.push_back("Сертифікат TSA був відкликаний.");
        return result;
    } else if (rev_result.overall_status != OverallStatus::Valid) {
        result.status = policy::TimestampStatus::UntrustedTsa;
        switch (rev_result.revocation_status) {
            case policy::RevocationStatus::Stale: result.reason_code = "TSA_REVOCATION_STALE"; break;
            case policy::RevocationStatus::Invalid: result.reason_code = "TSA_REVOCATION_INVALID"; break;
            case policy::RevocationStatus::ResponderUnavailable: result.reason_code = "TSA_RESPONDER_UNAVAILABLE"; break;
            default: result.reason_code = "TSA_REVOCATION_UNKNOWN"; break;
        }
        result.policy_acceptable = !input.policy.revocation_hard_fail && !input.policy.require_trusted_signing_time;
        result.because.push_back("Статус відкликання TSA не підтверджено; м'яка policy не робить час довіреним.");
        return result;
    }

    result.valid = true;
    result.policy_acceptable = true;
    result.reason_code = "TIMESTAMP_VALID";
    result.status = policy::TimestampStatus::Valid;
    result.because.push_back("Мітка часу RFC3161 є валідною.");
    return result;
}

} // namespace tamga::core::validation
