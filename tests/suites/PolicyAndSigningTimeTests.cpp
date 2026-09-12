// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено — ctest не знає, скільки тестів
// мало бути.
// Політика валідації та визначення часу підпису.
//
// Група чисто логічна: працює над структурами, без файлів і мережі.
// Через це вона й переноситься першою з великого негейтованого пробігу.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "types.h"
#include "IMemoryManager.h"
#include "asic/AsicReader.h"
#include "asic/AsicWriter.h"
#include "asic/AsicContainers.h"
#include "miniz.h"
#include "core/Errors.h"
#include "core/HttpClient.h"
#include "core/KeyParsers.h"
#include "core/net/CaSettingsRegistry.h"
#include "core/net/CertificateFetcher.h"
#include "core/net/CertificateResolver.h"
#include "core/Session.h"
#include "tamga/tamga_c_api.h"
#include "core/TspClient.h"
#include "core/policy/AiaIssuerFetcher.h"
#include "core/policy/CertificateChainValidator.h"
#include "core/policy/CrlValidator.h"
#include "core/policy/CrlCache.h"
#include "core/policy/ImprintDigest.h"
#include "core/policy/OcspValidator.h"
#include "core/policy/PolicyCache.h"
#include "core/policy/TimestampValidator.h"
#include "core/policy/TlXmlSigCheck.h"
#include "core/policy/TrustListParser.h"
#include "core/policy/TrustListSettings.h"
#include "core/policy/TrustListSync.h"
#include "core/policy/Sha256Helper.h"
#include "core/policy/UserReportBuilder.h"
#include "core/session/VerifySummary.h"
#include "core/validation/EvidenceStore.h"
#include "core/validation/PathEngine.h"
#include "core/validation/PolicyResolver.h"
#include "core/validation/SigningTimeResolver.h"
#include "core/validation/ValidationReportJson.h"
#include "core/validation/ValidationReportProjection.h"
#include "core/validation/TrustServiceEvaluator.h"
#include "core/validation/RevocationEngine.h"
#include "core/validation/TimestampEngine.h"
#include "core/validation/ValidationEngine.h"
#include "core/CryptoniteAdapter.h"
#include "core/policy/ImprintDigest.h"
#include "nativeapi/TamgaAddIn.h"
#include "util/AsicUri.h"
#include "util/Base64.h"
#include "util/Utf.h"
#include "nativeapi/VariantUtils.h"

// Phase 0 (ADR 012): стаб-заголовки форматних підсистем XMLDSIG/XAdES/PAdES.
// Включення тут дає compile-smoke у проєктному тулчейні — заголовки мають
// парситися й бути взаємно консистентними, поки .cpp зʼявляться у фазах 1-6.
#include "core/SignatureRequest.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/XmlTransformEngine.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSecContext.h"
#include "xmldsig/XmlSignatureBuilder.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xades/XadesTypes.h"
#include "xades/XadesBuilder.h"
#include "xades/XadesVerifier.h"
#include "pades/PdfTypes.h"
#include "pades/PdfParser.h"
#include "pades/PdfByteRange.h"
#include "pades/PadesBuilder.h"
#include "pades/PadesVerifier.h"

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "aid.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "cert_engine.h"
#include "certificate_request_engine.h"
#include "crl.h"
#include "crl_engine.h"
#include "cryptonite_manager.h"
#include "digest_adapter.h"
#include "dstu4145.h"
#include "dstu7564.h"
#include "ext.h"
#include "gost28147.h"
#include "oids.h"
#include "ocsp_response.h"
#include "ocsp_response_engine.h"
#include "pkcs12.h"
#include "pkcs8.h"
#include "sign_adapter.h"
#include "spki.h"
#include "verify_adapter.h"
#include "content_info.h"
#include "signed_data.h"
#include "CertificateSerialNumber.h"
#include "RevokedCertificate.h"
#include "TSTInfo.h"
#include "signed_data_engine.h"
#include "signer_info_engine.h"
#include "signer_info.h"
#include "CertificateSet.h"
#include "SignerIdentifier.h"
#include "pkix_utils.h"
#include "tsp_request.h"
#include "tsp_response.h"
#include "tsp_request_engine.h"
#include "tsp_response_engine.h"
#include "adapters_map.h"
#include "DigestAlgorithmIdentifiers.h"
#include "MessageImprint.h"
#include "AlgorithmIdentifier.h"
#if defined(_WIN32)
#include "dirent_internal.h"
#endif
}
#endif

#include "support/TestSupport.h"
#include "suites/Suites.h"

using namespace tamga_tests;

void TestValidationDecisionStatusVocabulary() {
    using tamga::core::validation::OverallStatus;
    using tamga::core::validation::ValidationDecision;
    using tamga::core::validation::ValidationLevel;
    using tamga::core::validation::ValidationProfile;

    ValidationDecision decision;
    ExpectTrue(decision.overall_status == OverallStatus::Indeterminate,
               "Default ValidationDecision should be indeterminate");
    ExpectTrue(!decision.signature_valid,
               "Default ValidationDecision should not mark signature valid");
    ExpectTrue(decision.level_reached == ValidationLevel::Basic,
               "Default ValidationDecision should reach basic level");
    ExpectTrue(decision.summary == "not-executed",
               "Default ValidationDecision should summarize as not-executed");

    ExpectTrue(std::string(tamga::core::validation::ToString(OverallStatus::Valid)) == "valid",
               "OverallStatus::Valid should serialize as valid");
    ExpectTrue(std::string(tamga::core::validation::ToString(OverallStatus::IntegrityOnly)) == "integrity-only",
               "OverallStatus::IntegrityOnly should serialize as integrity-only");
    ExpectTrue(std::string(tamga::core::validation::ToString(OverallStatus::Indeterminate)) == "indeterminate",
               "OverallStatus::Indeterminate should serialize as indeterminate");
    ExpectTrue(std::string(tamga::core::validation::ToString(OverallStatus::Invalid)) == "invalid",
               "OverallStatus::Invalid should serialize as invalid");
    ExpectTrue(std::string(tamga::core::validation::ToString(ValidationProfile::Strict)) == "strict",
               "ValidationProfile::Strict should serialize as strict");
    ExpectTrue(std::string(tamga::core::validation::ToString(ValidationProfile::Compatibility)) == "compatibility",
               "ValidationProfile::Compatibility should serialize as compatibility");
    ExpectTrue(std::string(tamga::core::validation::ToString(ValidationProfile::UkraineLegal)) == "ukraine-legal",
               "ValidationProfile::UkraineLegal should serialize as ukraine-legal");
    ExpectTrue(std::string(tamga::core::validation::ToString(ValidationProfile::Offline)) == "offline",
               "ValidationProfile::Offline should serialize as offline");
    ExpectTrue(std::string(tamga::core::validation::ToString(ValidationProfile::Forensic)) == "forensic",
               "ValidationProfile::Forensic should serialize as forensic");
    ExpectTrue(std::string(tamga::core::validation::ToString(ValidationLevel::Basic)) == "basic",
               "ValidationLevel::Basic should serialize as basic");
    ExpectTrue(std::string(tamga::core::validation::ToString(ValidationLevel::Standard)) == "standard",
               "ValidationLevel::Standard should serialize as standard");
    ExpectTrue(std::string(tamga::core::validation::ToString(ValidationLevel::Extended)) == "extended",
               "ValidationLevel::Extended should serialize as extended");
    ExpectTrue(std::string(tamga::core::validation::ToString(ValidationLevel::Forensic)) == "forensic",
               "ValidationLevel::Forensic should serialize as forensic");
    ExpectTrue(std::string(tamga::core::validation::ToString(static_cast<ValidationProfile>(-1))) == "unknown",
               "Unknown ValidationProfile should serialize as unknown");
    ExpectTrue(std::string(tamga::core::validation::ToString(static_cast<ValidationLevel>(-1))) == "unknown",
               "Unknown ValidationLevel should serialize as unknown");
    ExpectTrue(std::string(tamga::core::validation::ToString(static_cast<OverallStatus>(-1))) == "unknown",
               "Unknown OverallStatus should serialize as unknown");
}

void TestValidationLtvRequiresTimestampEvidence() {
    using tamga::core::policy::RevocationStatus;
    using tamga::core::validation::IsLongTermValidationValid;

    ExpectFalse(IsLongTermValidationValid(true, RevocationStatus::Good, false, false),
                "LTV must not be valid without timestamp evidence");
    ExpectFalse(IsLongTermValidationValid(true, RevocationStatus::Good, true, false),
                "LTV must not be valid when timestamp validation failed");
    ExpectFalse(IsLongTermValidationValid(false, RevocationStatus::Good, true, true),
                "LTV must not be valid when trust validation failed");
    ExpectFalse(IsLongTermValidationValid(true, RevocationStatus::Unknown, true, true),
                "LTV must not be valid when revocation status is unknown");
    ExpectTrue(IsLongTermValidationValid(true, RevocationStatus::Good, true, true),
               "LTV should be valid only with trust, good revocation and valid timestamp");
}

void TestPolicyResolverStrictRules() {
    using tamga::core::validation::PolicyResolver;
    using tamga::core::validation::TrustAnchorPolicy;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationLevel;
    using tamga::core::validation::ValidationProfile;

    PolicyResolver resolver;

    ValidationContext basic;
    basic.profile = ValidationProfile::Strict;
    basic.level = ValidationLevel::Basic;
    const auto basic_resolved = resolver.Resolve(basic);
    ExpectTrue(basic_resolved.policy.trust_anchor_policy == TrustAnchorPolicy::CurrentTLOnly,
               "Strict Basic should use current TL anchors only");
    ExpectFalse(basic_resolved.policy.allow_historical_trust,
                "Strict Basic should not allow historical trust");
    ExpectFalse(basic_resolved.policy.revocation_hard_fail,
                "Strict Basic should not hard-fail revocation");

    for (const auto level : {ValidationLevel::Standard, ValidationLevel::Extended, ValidationLevel::Forensic}) {
        ValidationContext context;
        context.profile = ValidationProfile::Strict;
        context.level = level;
        const auto resolved = resolver.Resolve(context);
        ExpectTrue(resolved.policy.trust_anchor_policy == TrustAnchorPolicy::CurrentTLOnly,
                   "Strict Standard/Extended/Forensic should use current TL anchors only");
        ExpectTrue(resolved.policy.revocation_hard_fail,
                   "Strict Standard/Extended/Forensic should hard-fail revocation");
        ExpectFalse(resolved.policy.allow_historical_trust,
                    "Strict Standard/Extended/Forensic should not allow historical trust");
    }
}

void TestPolicyResolverCompatibilityRules() {
    using tamga::core::validation::PolicyResolver;
    using tamga::core::validation::TrustAnchorPolicy;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationLevel;
    using tamga::core::validation::ValidationProfile;

    PolicyResolver resolver;

    ValidationContext extended;
    extended.profile = ValidationProfile::Compatibility;
    extended.level = ValidationLevel::Extended;
    const auto extended_resolved = resolver.Resolve(extended);
    ExpectTrue(extended_resolved.policy.trust_anchor_policy == TrustAnchorPolicy::ExplicitLegacyAnchorBundle,
               "Compatibility Extended should use explicit legacy anchor bundle");
    ExpectTrue(extended_resolved.policy.allow_historical_trust,
               "Compatibility Extended should allow historical trust");
    ExpectTrue(extended_resolved.policy.revocation_hard_fail,
               "Compatibility Extended should hard-fail revocation");

    ValidationContext standard;
    standard.profile = ValidationProfile::Compatibility;
    standard.level = ValidationLevel::Standard;
    const auto standard_resolved = resolver.Resolve(standard);
    ExpectTrue(standard_resolved.policy.allow_historical_trust,
               "Compatibility Standard should allow historical trust");
    ExpectFalse(standard_resolved.policy.revocation_hard_fail,
                "Compatibility Standard should not hard-fail revocation");
}

void TestPolicyResolverUkraineLegalRules() {
    using tamga::core::validation::PolicyResolver;
    using tamga::core::validation::TrustAnchorPolicy;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationLevel;
    using tamga::core::validation::ValidationProfile;

    PolicyResolver resolver;

    ValidationContext standard;
    standard.profile = ValidationProfile::UkraineLegal;
    standard.level = ValidationLevel::Standard;
    const auto standard_resolved = resolver.Resolve(standard);
    ExpectTrue(standard_resolved.policy.trust_anchor_policy == TrustAnchorPolicy::HistoricalAtSigningTime,
               "UkraineLegal Standard should evaluate historical trust at signing time");
    ExpectTrue(standard_resolved.policy.allow_historical_trust,
               "UkraineLegal Standard should allow historical trust");
    ExpectTrue(standard_resolved.policy.revocation_hard_fail,
               "UkraineLegal Standard should hard-fail revocation");
    ExpectFalse(standard_resolved.policy.require_trusted_signing_time,
                "UkraineLegal Standard should not require trusted signing time");
    ExpectFalse(standard_resolved.policy.require_service_level_trust,
                "UkraineLegal Standard should not require service-level trust");

    for (const auto level : {ValidationLevel::Standard, ValidationLevel::Extended, ValidationLevel::Forensic}) {
        ValidationContext context;
        context.profile = ValidationProfile::UkraineLegal;
        context.level = level;
        const auto resolved = resolver.Resolve(context);
        ExpectTrue(resolved.policy.revocation_hard_fail,
                   "UkraineLegal Standard/Extended/Forensic should hard-fail revocation");
    }

    for (const auto level : {ValidationLevel::Extended, ValidationLevel::Forensic}) {
        ValidationContext context;
        context.profile = ValidationProfile::UkraineLegal;
        context.level = level;
        const auto resolved = resolver.Resolve(context);
        ExpectTrue(resolved.policy.require_trusted_signing_time,
                   "UkraineLegal Extended/Forensic should require trusted signing time");
        ExpectTrue(resolved.policy.require_service_level_trust,
                   "UkraineLegal Extended/Forensic should require service-level trust");
        ExpectTrue(resolved.plan.selected_trust_snapshot_id.empty(),
                   "UkraineLegal should not select a trust snapshot before time-aware trust resolution");
    }
}

void TestPolicyResolverOfflineAndForensicRules() {
    using tamga::core::validation::PolicyResolver;
    using tamga::core::validation::TrustAnchorPolicy;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationLevel;
    using tamga::core::validation::ValidationProfile;

    PolicyResolver resolver;

    ValidationContext offline;
    offline.profile = ValidationProfile::Offline;
    offline.level = ValidationLevel::Standard;
    offline.offline = false;
    const auto offline_resolved = resolver.Resolve(offline);
    ExpectFalse(offline_resolved.plan.network_allowed,
                "Offline profile should disable network even when runtime context is online");
    ExpectTrue(offline_resolved.policy.trust_anchor_policy == TrustAnchorPolicy::CustomTrustStore,
               "Offline profile should use custom trust store policy");
    ExpectTrue(offline_resolved.policy.revocation_hard_fail,
               "Offline Standard should hard-fail revocation");

    for (const auto level : {ValidationLevel::Standard, ValidationLevel::Extended, ValidationLevel::Forensic}) {
        ValidationContext context;
        context.profile = ValidationProfile::Offline;
        context.level = level;
        const auto resolved = resolver.Resolve(context);
        ExpectFalse(resolved.plan.network_allowed,
                    "Offline Standard/Extended/Forensic should disable network");
        ExpectTrue(resolved.policy.revocation_hard_fail,
                   "Offline Standard/Extended/Forensic should hard-fail revocation");
    }

    ValidationContext forensic;
    forensic.profile = ValidationProfile::Forensic;
    forensic.level = ValidationLevel::Forensic;
    forensic.offline = false;
    const auto forensic_resolved = resolver.Resolve(forensic);
    ExpectTrue(forensic_resolved.plan.network_allowed,
               "Forensic profile should follow runtime offline flag for network access");
    ExpectTrue(forensic_resolved.policy.trust_anchor_policy == TrustAnchorPolicy::ForensicAllPossible,
               "Forensic profile should use diagnostic all-possible anchor policy");
    ExpectTrue(forensic_resolved.policy.forensic_diagnostics,
               "Forensic profile should enable forensic diagnostics");
    ExpectFalse(forensic_resolved.policy.allow_historical_trust,
                "Forensic diagnostics should not relax trust by itself");
    ExpectTrue(forensic_resolved.policy.revocation_hard_fail,
               "Forensic level should hard-fail revocation");

    forensic.offline = true;
    const auto forensic_offline_resolved = resolver.Resolve(forensic);
    ExpectFalse(forensic_offline_resolved.plan.network_allowed,
                "Forensic profile should disable network when runtime context is offline");
}

void TestPolicyResolverWorkDirPaths() {
    using tamga::core::validation::PolicyResolver;
    using tamga::core::validation::ValidationContext;

    const auto work_dir = MakeTemporaryFixturePath(".policy-resolver");
    ValidationContext context;
    context.work_dir = work_dir.string();

    const auto resolved = PolicyResolver().Resolve(context);
    ExpectTrue(std::filesystem::path(resolved.plan.trust_store_path) == work_dir / "trust-store",
               "PolicyResolver should join workDir and trust-store using filesystem paths");
    ExpectTrue(std::filesystem::path(resolved.plan.historical_trust_store_path) ==
                   work_dir / "historical-trust-store",
               "PolicyResolver should join workDir and historical-trust-store using filesystem paths");

    const std::string cyrillic_work_dir = "relative-\xD0\xA2\xD0\xB0\xD0\xBC\xD0\xB3\xD0\xB0-policy";
    context.work_dir = cyrillic_work_dir;
    const auto cyrillic_resolved = PolicyResolver().Resolve(context);
    ExpectContains(cyrillic_resolved.plan.trust_store_path,
                   "\xD0\xA2\xD0\xB0\xD0\xBC\xD0\xB3\xD0\xB0-policy",
                   "PolicyResolver should preserve UTF-8 Cyrillic bytes in trust-store path");
    ExpectContains(cyrillic_resolved.plan.historical_trust_store_path,
                   "\xD0\xA2\xD0\xB0\xD0\xBC\xD0\xB3\xD0\xB0-policy",
                   "PolicyResolver should preserve UTF-8 Cyrillic bytes in historical trust-store path");
    ExpectTrue(cyrillic_resolved.plan.trust_store_path.size() >= std::string("trust-store").size() &&
                   cyrillic_resolved.plan.trust_store_path.compare(
                       cyrillic_resolved.plan.trust_store_path.size() - std::string("trust-store").size(),
                       std::string("trust-store").size(),
                       "trust-store") == 0,
               "PolicyResolver UTF-8 trust-store path should end with trust-store");
    ExpectTrue(cyrillic_resolved.plan.historical_trust_store_path.size() >=
                       std::string("historical-trust-store").size() &&
                   cyrillic_resolved.plan.historical_trust_store_path.compare(
                       cyrillic_resolved.plan.historical_trust_store_path.size() -
                           std::string("historical-trust-store").size(),
                       std::string("historical-trust-store").size(),
                       "historical-trust-store") == 0,
               "PolicyResolver UTF-8 historical trust-store path should end with historical-trust-store");
}

void TestPolicyResolverInvalidEnumsFailClosed() {
    using tamga::core::validation::PolicyResolver;
    using tamga::core::validation::TrustAnchorPolicy;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationLevel;
    using tamga::core::validation::ValidationProfile;

    ValidationContext invalid_profile;
    invalid_profile.profile = static_cast<ValidationProfile>(999);
    invalid_profile.level = ValidationLevel::Standard;
    invalid_profile.offline = false;
    const auto invalid_profile_resolved = PolicyResolver().Resolve(invalid_profile);
    ExpectFalse(invalid_profile_resolved.plan.network_allowed,
                "PolicyResolver should fail closed with network disabled for invalid profile");
    ExpectTrue(invalid_profile_resolved.policy.revocation_hard_fail,
               "PolicyResolver should fail closed with revocation hard-fail for invalid profile");
    ExpectTrue(invalid_profile_resolved.policy.trust_anchor_policy == TrustAnchorPolicy::CurrentTLOnly,
               "PolicyResolver should fail closed to current TL only for invalid profile");
    ExpectFalse(invalid_profile_resolved.policy.allow_historical_trust,
                "PolicyResolver should fail closed without historical trust for invalid profile");

    ValidationContext invalid_level;
    invalid_level.profile = ValidationProfile::Compatibility;
    invalid_level.level = static_cast<ValidationLevel>(999);
    invalid_level.offline = false;
    const auto invalid_level_resolved = PolicyResolver().Resolve(invalid_level);
    ExpectFalse(invalid_level_resolved.plan.network_allowed,
                "PolicyResolver should fail closed with network disabled for invalid level");
    ExpectTrue(invalid_level_resolved.policy.revocation_hard_fail,
               "PolicyResolver should fail closed with revocation hard-fail for invalid level");
    ExpectTrue(invalid_level_resolved.policy.trust_anchor_policy == TrustAnchorPolicy::CurrentTLOnly,
               "PolicyResolver should fail closed to current TL only for invalid level");
    ExpectFalse(invalid_level_resolved.policy.allow_historical_trust,
                "PolicyResolver should fail closed without historical trust for invalid level");
}

void TestSigningTimeResolverTrustedRfc3161Wins() {
    using tamga::core::validation::SigningTimeCandidate;
    using tamga::core::validation::SigningTimeConfidence;
    using tamga::core::validation::SigningTimeResolver;
    using tamga::core::validation::SigningTimeSource;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationPolicy;

    std::vector<SigningTimeCandidate> candidates;
    candidates.push_back({SigningTimeSource::ClaimedSigningTime, "2026-01-01T10:00:00Z", "claimed-1"});
    candidates.push_back({SigningTimeSource::Rfc3161Timestamp,
                          "2026-01-01T09:59:00Z",
                          "tsp-1",
                          true,
                          true,
                          {"timestamp-warning"}});
    candidates.push_back({SigningTimeSource::Rfc3161Timestamp,
                          "2026-01-01T09:58:00Z",
                          "tsp-later-invalid",
                          false,
                          false,
                          {"later-invalid-warning"}});
    ValidationContext context;
    context.verification_time = "2026-01-02T00:00:00Z";

    const auto resolved = SigningTimeResolver().Resolve(candidates, context, ValidationPolicy{});
    ExpectTrue(resolved.signature_evaluation_time == "2026-01-01T09:59:00Z",
               "Trusted RFC3161 timestamp should win over claimed and verification fallback");
    ExpectTrue(resolved.source == SigningTimeSource::Rfc3161Timestamp,
               "Trusted RFC3161 result should preserve source");
    ExpectTrue(resolved.confidence == SigningTimeConfidence::Trusted,
               "Trusted RFC3161 result should have trusted confidence");
    ExpectTrue(resolved.trusted_time, "Trusted RFC3161 result should mark time trusted");
    ExpectTrue(resolved.evidence_id == "tsp-1", "Trusted RFC3161 result should preserve evidence id");
    ExpectContainsValue(resolved.warnings, "timestamp-warning",
                        "Trusted RFC3161 result should propagate selected candidate warnings");
    ExpectTrue(resolved.warnings.size() == 1U,
               "Trusted RFC3161 result should not include diagnostics from later unrelated timestamps");
    ExpectTrue(resolved.limitations.empty(),
               "Trusted RFC3161 result should not include skip limitations from later unrelated timestamps");
    ExpectNotContainsValue(resolved.warnings,
                           "rfc3161-timestamp-not-cryptographically-valid:tsp-later-invalid",
                           "Trusted RFC3161 result should not include later invalid timestamp diagnostics");
    ExpectNotContainsValue(resolved.warnings, "later-invalid-warning",
                           "Trusted RFC3161 result should not include later candidate warnings");
}

void TestSigningTimeResolverSkipsInvalidRfc3161AndUsesClaimed() {
    using tamga::core::validation::SigningTimeCandidate;
    using tamga::core::validation::SigningTimeConfidence;
    using tamga::core::validation::SigningTimeResolver;
    using tamga::core::validation::SigningTimeSource;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationPolicy;

    std::vector<SigningTimeCandidate> candidates;
    candidates.push_back({SigningTimeSource::Rfc3161Timestamp, "2026-01-01T08:00:00Z", "tsp-invalid", false, false});
    candidates.push_back({SigningTimeSource::Rfc3161Timestamp, "2026-01-01T08:30:00Z", "tsp-untrusted", true, false});
    candidates.push_back({SigningTimeSource::ClaimedSigningTime, "2026-01-01T10:00:00Z", "claimed-1"});

    const auto resolved = SigningTimeResolver().Resolve(candidates, ValidationContext{}, ValidationPolicy{});
    ExpectTrue(resolved.signature_evaluation_time == "2026-01-01T10:00:00Z",
               "Resolver should use claimed signing time when RFC3161 candidates are not trusted");
    ExpectTrue(resolved.source == SigningTimeSource::ClaimedSigningTime,
               "Claimed result should preserve source");
    ExpectTrue(resolved.confidence == SigningTimeConfidence::Claimed,
               "Claimed result should have claimed confidence");
    ExpectFalse(resolved.trusted_time, "Claimed result should not mark time trusted");
    ExpectTrue(resolved.evidence_id == "claimed-1", "Claimed result should preserve evidence id");
    ExpectContainsValue(resolved.warnings, "rfc3161-timestamp-not-cryptographically-valid:tsp-invalid",
                        "Resolver should explain skipped invalid RFC3161 timestamp");
    ExpectContainsValue(resolved.limitations, "rfc3161-timestamp-not-trusted:tsp-untrusted",
                        "Resolver should explain skipped untrusted RFC3161 timestamp");
    ExpectContainsValue(resolved.warnings, "claimed-signing-time-not-cryptographically-proven",
                        "Unproven claimed signing time should add a warning");
}

void TestSigningTimeResolverSkipsEmptyTrustedRfc3161AndUsesClaimed() {
    using tamga::core::validation::SigningTimeCandidate;
    using tamga::core::validation::SigningTimeResolver;
    using tamga::core::validation::SigningTimeSource;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationPolicy;

    const std::vector<SigningTimeCandidate> candidates{
        {SigningTimeSource::Rfc3161Timestamp, "", "tsp-empty", true, true, {"empty-timestamp-warning"}},
        {SigningTimeSource::ClaimedSigningTime, "claimed-distinctive-time", "claimed-1", true}};

    const auto resolved = SigningTimeResolver().Resolve(candidates, ValidationContext{}, ValidationPolicy{});
    ExpectTrue(resolved.source == SigningTimeSource::ClaimedSigningTime,
               "Empty trusted RFC3161 timestamp should be skipped in favor of claimed time");
    ExpectTrue(resolved.signature_evaluation_time == "claimed-distinctive-time",
               "Claimed time should be used after empty trusted RFC3161 timestamp is skipped");
    ExpectContainsValue(resolved.limitations, "rfc3161-timestamp-time-unavailable:tsp-empty",
                        "Skipped empty RFC3161 timestamp should add time-unavailable diagnostic");
    ExpectContainsValue(resolved.warnings, "empty-timestamp-warning",
                        "Skipped RFC3161 timestamp warnings should be preserved when no timestamp is selected");
}

void TestSigningTimeResolverClaimedBeforeVerificationFallback() {
    using tamga::core::validation::SigningTimeCandidate;
    using tamga::core::validation::SigningTimeConfidence;
    using tamga::core::validation::SigningTimeResolver;
    using tamga::core::validation::SigningTimeSource;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationPolicy;

    std::vector<SigningTimeCandidate> candidates;
    candidates.push_back({SigningTimeSource::ClaimedSigningTime, "2026-02-03T04:05:06Z", "claimed-1", true});
    ValidationContext context;
    context.verification_time = "2026-02-04T00:00:00Z";

    const auto resolved = SigningTimeResolver().Resolve(candidates, context, ValidationPolicy{});
    ExpectTrue(resolved.signature_evaluation_time == "2026-02-03T04:05:06Z",
               "Claimed signing time should be selected before verification_time fallback");
    ExpectTrue(resolved.source == SigningTimeSource::ClaimedSigningTime,
               "Claimed-before-fallback result should preserve source");
    ExpectTrue(resolved.confidence == SigningTimeConfidence::Claimed,
               "Claimed-before-fallback result should have claimed confidence");
    ExpectFalse(resolved.trusted_time, "Claimed signing time should not be treated as trusted");
}

void TestSigningTimeResolverPreservesDateStringsExactly() {
    using tamga::core::validation::SigningTimeCandidate;
    using tamga::core::validation::SigningTimeResolver;
    using tamga::core::validation::SigningTimeSource;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationPolicy;

    const std::string distinctive_time = " raw signing time: 2026-06-15 01:02:03,123 +02 / not-normalized ";
    const std::vector<SigningTimeCandidate> candidates{
        {SigningTimeSource::ClaimedSigningTime, distinctive_time, "claimed-distinctive", true}};

    const auto resolved = SigningTimeResolver().Resolve(candidates, ValidationContext{}, ValidationPolicy{});
    ExpectTrue(resolved.signature_evaluation_time == distinctive_time,
               "SigningTimeResolver should preserve date strings exactly without parsing or normalization");
}

void TestSigningTimeResolverUsesVerificationFallback() {
    using tamga::core::validation::SigningTimeConfidence;
    using tamga::core::validation::SigningTimeResolver;
    using tamga::core::validation::SigningTimeSource;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationPolicy;

    ValidationContext context;
    context.verification_time = "2026-03-01T00:00:00Z";

    const auto resolved = SigningTimeResolver().Resolve({}, context, ValidationPolicy{});
    ExpectTrue(resolved.signature_evaluation_time == "2026-03-01T00:00:00Z",
               "Resolver should use verification_time when there are no candidates");
    ExpectTrue(resolved.source == SigningTimeSource::VerificationTimeFallback,
               "Fallback result should preserve source");
    ExpectTrue(resolved.confidence == SigningTimeConfidence::Fallback,
               "Fallback result should have fallback confidence");
    ExpectFalse(resolved.trusted_time, "Verification fallback should not mark time trusted");
    ExpectContainsValue(resolved.warnings, "verification-time-fallback-used",
                        "Verification fallback should add a warning");
    ExpectContainsValue(resolved.limitations, "signing-time-derived-from-verification-time",
                        "Verification fallback should document its limitation");
}

void TestSigningTimeResolverUnavailableWithoutFallback() {
    using tamga::core::validation::SigningTimeConfidence;
    using tamga::core::validation::SigningTimeResolver;
    using tamga::core::validation::SigningTimeSource;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationPolicy;

    const auto resolved = SigningTimeResolver().Resolve({}, ValidationContext{}, ValidationPolicy{});
    ExpectTrue(resolved.signature_evaluation_time.empty(),
               "Resolver should leave evaluation time empty when no evidence or fallback exists");
    ExpectTrue(resolved.confidence == SigningTimeConfidence::Unavailable,
               "Missing time should have unavailable confidence");
    ExpectTrue(resolved.source == SigningTimeSource::Unavailable,
               "Missing time should use explicit unavailable source");
    ExpectFalse(resolved.trusted_time, "Missing time should not be trusted");
    ExpectContainsValue(resolved.limitations, "signing-time-unavailable",
                        "Missing time should add unavailable limitation");
}

void TestSigningTimeResolverTrustedTimeRequirementAddsLimitation() {
    using tamga::core::validation::SigningTimeCandidate;
    using tamga::core::validation::SigningTimeResolver;
    using tamga::core::validation::SigningTimeSource;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationPolicy;

    ValidationPolicy policy;
    policy.require_trusted_signing_time = true;

    const std::vector<SigningTimeCandidate> claimed_candidates{
        {SigningTimeSource::ClaimedSigningTime, "2026-04-01T00:00:00Z", "claimed-1", true}};
    const auto claimed = SigningTimeResolver().Resolve(claimed_candidates, ValidationContext{}, policy);
    ExpectContainsValue(claimed.limitations, "trusted-signing-time-required",
                        "Trusted-time policy should limit claimed signing time");

    ValidationContext fallback_context;
    fallback_context.verification_time = "2026-04-02T00:00:00Z";
    const auto fallback = SigningTimeResolver().Resolve({}, fallback_context, policy);
    ExpectContainsValue(fallback.limitations, "trusted-signing-time-required",
                        "Trusted-time policy should limit verification fallback");
}

void TestSigningTimeResolverFirstTrustedRfc3161WinsDeterministically() {
    using tamga::core::validation::SigningTimeCandidate;
    using tamga::core::validation::SigningTimeResolver;
    using tamga::core::validation::SigningTimeSource;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationPolicy;

    const std::vector<SigningTimeCandidate> candidates{
        {SigningTimeSource::Rfc3161Timestamp, "2026-05-01T00:00:00Z", "tsp-first", true, true},
        {SigningTimeSource::Rfc3161Timestamp, "2026-05-01T00:01:00Z", "tsp-second", true, true}};

    const auto resolved = SigningTimeResolver().Resolve(candidates, ValidationContext{}, ValidationPolicy{});
    ExpectTrue(resolved.signature_evaluation_time == "2026-05-01T00:00:00Z",
               "Resolver should select first trusted RFC3161 timestamp deterministically");
    ExpectTrue(resolved.evidence_id == "tsp-first",
               "Resolver should preserve first trusted RFC3161 evidence id");
}

void TestSigningTimeResolverUsesManualPolicyWithoutProfileLevel() {
    using tamga::core::validation::SigningTimeCandidate;
    using tamga::core::validation::SigningTimeResolver;
    using tamga::core::validation::SigningTimeSource;
    using tamga::core::validation::ValidationContext;
    using tamga::core::validation::ValidationLevel;
    using tamga::core::validation::ValidationPolicy;
    using tamga::core::validation::ValidationProfile;

    ValidationContext context;
    context.profile = static_cast<ValidationProfile>(999);
    context.level = static_cast<ValidationLevel>(999);

    ValidationPolicy policy;
    policy.require_trusted_signing_time = true;

    const std::vector<SigningTimeCandidate> candidates{
        {SigningTimeSource::ClaimedSigningTime, "2026-06-01T00:00:00Z", "claimed-1", true}};
    const auto resolved = SigningTimeResolver().Resolve(candidates, context, policy);
    ExpectTrue(resolved.signature_evaluation_time == "2026-06-01T00:00:00Z",
               "Resolver should not require valid ValidationProfile/ValidationLevel when policy is provided manually");
    ExpectContainsValue(resolved.limitations, "trusted-signing-time-required",
                        "Resolver should apply manual policy directly");
}

// WP-10: claimed signingTime is extracted from the CMS signed attributes and fed
// to the validation engine as a best-signature-time candidate.
void TestClaimedSigningTimeExtraction() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture should generate for signing-time extraction");
    if (!fixture.valid) {
        return;
    }
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session init for signing-time extraction");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "Load key for signing-time extraction");
    const std::vector<std::uint8_t> data{'w', 'p', '1', '0'};
    std::vector<std::uint8_t> signature;
    ExpectSessionTrue(session, session.SignData(data, signature, tamga::core::TimestampMode::Disabled),
                      "SignData for signing-time extraction");

    std::string iso;
    ExpectTrue(tamga::core::CryptoniteAdapter::ExtractSigningTime(signature, iso),
               "ExtractSigningTime should read the signed signingTime attribute");
    ExpectTrue(iso.size() == 20 && iso[4] == '-' && iso[7] == '-' && iso[10] == 'T' &&
                   iso[13] == ':' && !iso.empty() && iso.back() == 'Z',
               "signingTime should be ISO8601 UTC (YYYY-MM-DDTHH:MM:SSZ)");
    ExpectTrue(iso.substr(0, 2) == "20", "signingTime year should be 20xx");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}
