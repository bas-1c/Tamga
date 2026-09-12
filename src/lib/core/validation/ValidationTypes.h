#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "core/policy/PolicyTypes.h"

namespace tamga::core::validation {

enum class ValidationProfile {
    Strict,
    Compatibility,
    UkraineLegal,
    Offline,
    Forensic,
};

enum class ValidationLevel {
    Basic,
    Standard,
    Extended,
    Forensic,
};

enum class TrustAnchorPolicy {
    CurrentTLOnly,
    HistoricalAtSigningTime,
    ExplicitLegacyAnchorBundle,
    PinnedAnchors,
    CustomTrustStore,
    ForensicAllPossible,
};

enum class OverallStatus {
    Valid,
    IntegrityOnly,
    Indeterminate,
    Invalid,
};

enum class SigningTimeSource {
    Unavailable,
    Rfc3161Timestamp,
    ClaimedSigningTime,
    VerificationTimeFallback,
};

enum class SigningTimeConfidence {
    Trusted,
    Claimed,
    Fallback,
    Unavailable,
};

struct ValidationContext {
    ValidationProfile profile{ValidationProfile::Strict};
    ValidationLevel level{ValidationLevel::Basic};
    std::string verification_time;
    bool offline{true};
    std::string work_dir;
    std::vector<std::uint8_t> cms_der;
    // WP-10: claimed signingTime (CMS signed attr / xades:SigningTime), ISO8601.
    // Не криптографічно доведений; подається як кандидат best-signature-time
    // (ETSI EN 319 102-1), нижчий за trusted timestamp, вищий за current-time.
    std::string claimed_signing_time;
    // WP-5 (ME-07): вбудовані XAdES RevocationValues (OCSP/CRL), типізовано
    // окремо, бо йдуть різними шляхами у RevocationEngine.
    std::vector<std::vector<std::uint8_t>> embedded_revocation_ocsp_der;
    std::vector<std::vector<std::uint8_t>> embedded_revocation_crl_der;
    // WP-11: адреса живого OCSP-респондера підписанта (CMS/CAdES `OcspSettings`
    // Session-рівня). ValidationEngine передає це у RevocationEngineInput.ocsp_url,
    // щоб онлайн-перевірка відкликання лишалась доступною після відмови від
    // окремого legacy trust-пайплайна (HI-06).
    std::string ocsp_url;
    // F-04: вердикт КРИПТОГРАФІЧНОЇ перевірки підпису, отриманий викликачем
    // (CryptoniteAdapter/XmlSignatureVerifier/PadesVerifier) ДО входу сюди.
    //
    // Раніше ValidationEngine припускав `true` константою: припущення було
    // істинним для наявних викликачів, але не перевірялося, тож будь-який новий
    // шлях, що забув би перевірити криптографію, отримав би VALID-вердикт від
    // руху ланцюга й відкликання. Тепер це явний вхід із fail-closed типовим
    // значенням: не заповнив — отримав INVALID, а не «валідно за замовчуванням».
    bool signature_crypto_valid{false};
};

struct ValidationPolicy {
    TrustAnchorPolicy trust_anchor_policy{TrustAnchorPolicy::CurrentTLOnly};
    bool revocation_hard_fail{false};
    bool require_trusted_signing_time{false};
    bool require_service_level_trust{false};
    bool allow_historical_trust{false};
    bool forensic_diagnostics{false};
};

struct ValidationPlan {
    bool network_allowed{false};
    // Вузькі рядки UTF-8: Windows-виклики мають відновлювати filesystem paths із семантикою, еквівалентною u8path.
    std::string trust_store_path;
    std::string historical_trust_store_path;
    // Лишається порожнім, доки етап довіри з урахуванням часу не вибере детермінований знімок із ValidationMoments.
    std::string selected_trust_snapshot_id;
    std::int32_t timeout_ms{10000};
};

struct ResolvedValidationPolicy {
    ValidationPolicy policy;
    ValidationPlan plan;
};

struct ValidationDecision {
    OverallStatus overall_status{OverallStatus::Indeterminate};
    bool signature_valid{false};
    bool trust_valid{false};
    bool qualified_valid{false};
    bool ltv_valid{false};
    std::string trusted_signing_time;
    std::string signature_evaluation_time;
    ValidationLevel level_reached{ValidationLevel::Basic};
    std::string summary{"not-executed"};
    std::string trust_status;
    std::string trust_reason;
    std::vector<std::string> because;
    std::vector<std::string> warnings;
    std::vector<std::string> limitations;
};

struct SigningTimeCandidate {
    SigningTimeCandidate() = default;

    SigningTimeCandidate(SigningTimeSource source_value,
                         std::string time_value,
                         std::string evidence_id_value,
                         bool cryptographically_valid_value = false,
                         bool trusted_value = false,
                         std::vector<std::string> warnings_value = {})
        : source(source_value),
          time(std::move(time_value)),
          evidence_id(std::move(evidence_id_value)),
          cryptographically_valid(cryptographically_valid_value),
          trusted(trusted_value),
          warnings(std::move(warnings_value)) {}

    SigningTimeSource source{SigningTimeSource::Unavailable};
    std::string time;
    std::string evidence_id;
    bool cryptographically_valid{false};
    bool trusted{false};
    std::vector<std::string> warnings;
};

struct SigningTimeResolution {
    // Заявлені та fallback-значення є лише опорними моментами оцінки. Не використовуй їх для historical TL/LTV trust,
    // коли trusted_time=false, якщо майбутня policy явно цього не дозволить; ValidationMoments формалізує контракт.
    std::string signature_evaluation_time;
    SigningTimeSource source{SigningTimeSource::Unavailable};
    SigningTimeConfidence confidence{SigningTimeConfidence::Unavailable};
    std::string evidence_id;
    std::vector<std::string> warnings;
    std::vector<std::string> limitations;
    bool trusted_time{false};
};

const char* ToString(ValidationProfile value);
const char* ToString(ValidationLevel value);
const char* ToString(OverallStatus value);

inline bool IsLongTermValidationValid(bool trust_valid,
                                      policy::RevocationStatus signer_revocation_status,
                                      bool timestamp_attempted,
                                      bool timestamp_valid) {
    return trust_valid &&
           signer_revocation_status == policy::RevocationStatus::Good &&
           timestamp_attempted &&
           timestamp_valid;
}

} // namespace tamga::core::validation
