// Хвиля 8, п.5: перша тематична група, винесена з тестового моноліту.
//
// Тести побудови та вибору шляху сертифіката (PathBuilder / PathSelector /
// PathValidator) — суцільний блок без умовної компіляції, тож переносяться
// одним шматком без змін у тілах.
//
// Інваріант, який робить такий перенос перевірним: список `Running <name>`,
// що друкує бінарник, мусить лишитися тим самим і в тому самому порядку.
// Саме він, а не зелений ctest, доводить, що жодного тесту не загублено.

#include "suites/Suites.h"

#include "support/TestSupport.h"

#include "core/policy/CertificateChainValidator.h"
#include "core/validation/PathEngine.h"
#include "core/validation/ValidationTypes.h"

#include <string>
#include <vector>

using namespace tamga_tests;
void TestPathBuilderCurrentTlOnlyIgnoresHistoricalAnchors() {
    using tamga::core::validation::PathBuilder;
    using tamga::core::validation::PathBuilderInput;
    using tamga::core::validation::TrustAnchorPolicy;

    PathBuilderInput input;
    input.signer_certificate_der = {0x01};
    input.current_trust_anchors_der = {{0x10}};
    input.historical_trust_anchors_der = {{0x20}};
    input.policy.trust_anchor_policy = TrustAnchorPolicy::CurrentTLOnly;
    input.policy.allow_historical_trust = true;

    const auto candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 1, "CurrentTLOnly should build exactly one path candidate");
    ExpectTrue(candidates[0].candidate_id == "current-tl", "CurrentTLOnly candidate id should be current-tl");
    ExpectTrue(candidates[0].trust_anchor_source == "current-tl",
               "CurrentTLOnly candidate should use current trust anchors");
    ExpectTrue(candidates[0].trust_anchors_der == input.current_trust_anchors_der,
               "CurrentTLOnly candidate must not mix historical anchors");
    ExpectFalse(candidates[0].uses_historical_trust,
                "CurrentTLOnly candidate should not be marked historical");
}

void TestPathBuilderCompatibilityBuildsCurrentThenHistoricalSeparately() {
    using tamga::core::validation::PathBuilder;
    using tamga::core::validation::PathBuilderInput;
    using tamga::core::validation::TrustAnchorPolicy;

    PathBuilderInput input;
    input.signer_certificate_der = {0x01};
    input.current_trust_anchors_der = {{0x10}};
    input.historical_trust_anchors_der = {{0x20}};
    input.policy.trust_anchor_policy = TrustAnchorPolicy::ExplicitLegacyAnchorBundle;
    input.policy.allow_historical_trust = true;

    const auto candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 2,
               "Compatibility policy should build current and historical candidates");
    ExpectTrue(candidates[0].candidate_id == "current-tl",
               "Compatibility policy should try current TL first");
    ExpectTrue(candidates[1].candidate_id == "historical-tl",
               "Compatibility policy should try historical TL second");
    ExpectTrue(candidates[0].trust_anchors_der == input.current_trust_anchors_der,
               "Current candidate should contain only current anchors");
    ExpectTrue(candidates[1].trust_anchors_der == input.historical_trust_anchors_der,
               "Historical candidate should contain only historical anchors");
    ExpectFalse(candidates[0].uses_historical_trust,
                "Current candidate should not be historical");
    ExpectTrue(candidates[1].uses_historical_trust,
               "Historical candidate should be explicitly marked historical");
}


void TestPathBuilderHistoricalAtSigningTimeRequiresAllowedHistoricalTrust() {
    using tamga::core::validation::PathBuilder;
    using tamga::core::validation::PathBuilderInput;
    using tamga::core::validation::TrustAnchorPolicy;

    PathBuilderInput input;
    input.signer_certificate_der = {0x01};
    input.current_trust_anchors_der = {{0x10}};
    input.historical_trust_anchors_der = {{0x20}};
    input.policy.trust_anchor_policy = TrustAnchorPolicy::HistoricalAtSigningTime;
    input.policy.allow_historical_trust = true;

    auto candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 2,
               "HistoricalAtSigningTime should build current and historical candidates when allowed");
    ExpectTrue(candidates[0].candidate_id == "current-tl",
               "HistoricalAtSigningTime should keep current diagnostics first");
    ExpectTrue(candidates[1].candidate_id == "historical-tl",
               "HistoricalAtSigningTime should build historical candidate second");
    ExpectTrue(candidates[1].trust_anchors_der == input.historical_trust_anchors_der,
               "HistoricalAtSigningTime historical candidate should use only historical anchors");

    input.policy.allow_historical_trust = false;
    candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 1,
               "HistoricalAtSigningTime must not build historical candidate when policy disallows it");
    ExpectTrue(candidates[0].candidate_id == "current-tl",
               "HistoricalAtSigningTime disallowed fallback should retain current candidate");

    input.policy.allow_historical_trust = true;
    input.historical_trust_anchors_der.clear();
    candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 1,
               "HistoricalAtSigningTime should not build empty historical candidate");
}

void TestPathBuilderCustomTrustStoreUsesExplicitAnchors() {
    using tamga::core::validation::PathBuilder;
    using tamga::core::validation::PathBuilderInput;
    using tamga::core::validation::TrustAnchorPolicy;

    PathBuilderInput input;
    input.signer_certificate_der = {0x01};
    input.current_trust_anchors_der = {{0x10}};
    input.custom_trust_anchors_der = {{0x30}};
    input.policy.trust_anchor_policy = TrustAnchorPolicy::CustomTrustStore;

    const auto candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 1, "CustomTrustStore should build one candidate");
    ExpectTrue(candidates[0].candidate_id == "custom-trust-store",
               "CustomTrustStore candidate should use stable custom identity");
    ExpectTrue(candidates[0].trust_anchor_source == "custom-trust-store",
               "CustomTrustStore candidate should expose custom source");
    ExpectTrue(candidates[0].trust_anchors_der == input.custom_trust_anchors_der,
               "CustomTrustStore must use explicit custom anchors instead of current anchors");
}

void TestPathBuilderCustomTrustStoreEmptyExplicitAnchorsDoNotUseCurrentTl() {
    using tamga::core::validation::PathBuilder;
    using tamga::core::validation::PathBuilderInput;
    using tamga::core::validation::TrustAnchorPolicy;

    PathBuilderInput input;
    input.signer_certificate_der = {0x01};
    input.current_trust_anchors_der = {{0x10}};
    input.policy.trust_anchor_policy = TrustAnchorPolicy::CustomTrustStore;

    const auto candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 1,
               "CustomTrustStore should keep a diagnostic candidate when explicit anchors are empty");
    ExpectTrue(candidates[0].candidate_id == "custom-trust-store",
               "CustomTrustStore empty-anchor candidate should preserve custom identity");
    ExpectTrue(candidates[0].trust_anchors_der.empty(),
               "CustomTrustStore empty explicit anchors must not inherit current TL anchors");
}

void TestPathBuilderPinnedAnchorsUsesExplicitAnchors() {
    using tamga::core::validation::PathBuilder;
    using tamga::core::validation::PathBuilderInput;
    using tamga::core::validation::TrustAnchorPolicy;

    PathBuilderInput input;
    input.signer_certificate_der = {0x01};
    input.current_trust_anchors_der = {{0x10}};
    input.pinned_trust_anchors_der = {{0x40}};
    input.policy.trust_anchor_policy = TrustAnchorPolicy::PinnedAnchors;

    const auto candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 1, "PinnedAnchors should build one candidate");
    ExpectTrue(candidates[0].candidate_id == "pinned-anchors",
               "PinnedAnchors candidate should use stable pinned identity");
    ExpectTrue(candidates[0].trust_anchor_source == "pinned-anchors",
               "PinnedAnchors candidate should expose pinned source");
    ExpectTrue(candidates[0].trust_anchors_der == input.pinned_trust_anchors_der,
               "PinnedAnchors must use explicit pinned anchors instead of current anchors");
}

void TestPathBuilderPinnedAnchorsEmptyExplicitAnchorsDoNotUseCurrentTl() {
    using tamga::core::validation::PathBuilder;
    using tamga::core::validation::PathBuilderInput;
    using tamga::core::validation::TrustAnchorPolicy;

    PathBuilderInput input;
    input.signer_certificate_der = {0x01};
    input.current_trust_anchors_der = {{0x10}};
    input.policy.trust_anchor_policy = TrustAnchorPolicy::PinnedAnchors;

    const auto candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 1,
               "PinnedAnchors should keep a diagnostic candidate when explicit anchors are empty");
    ExpectTrue(candidates[0].candidate_id == "pinned-anchors",
               "PinnedAnchors empty-anchor candidate should preserve pinned identity");
    ExpectTrue(candidates[0].trust_anchors_der.empty(),
               "PinnedAnchors empty explicit anchors must not inherit current TL anchors");
}

void TestPathBuilderKeepsAiaAsIssuerCandidatesOnly() {
    using tamga::core::validation::PathBuilder;
    using tamga::core::validation::PathBuilderInput;
    using tamga::core::validation::TrustAnchorPolicy;

    PathBuilderInput input;
    input.signer_certificate_der = {0x01};
    input.embedded_certificates_der = {{0x02}};
    input.intermediate_store_certificates_der = {{0x03}};
    input.aia_certificates_der = {{0x04}};
    input.current_trust_anchors_der = {{0x10}};
    input.policy.trust_anchor_policy = TrustAnchorPolicy::CurrentTLOnly;

    const auto candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 1, "AIA issuer test should build current candidate");
    ExpectTrue(candidates[0].embedded_certificates_der == input.embedded_certificates_der,
               "Path candidate should preserve embedded issuer certificates");
    ExpectTrue(candidates[0].intermediate_certificates_der == input.intermediate_store_certificates_der,
               "Path candidate should preserve intermediate-store issuer certificates");
    ExpectTrue(candidates[0].aia_certificates_der == input.aia_certificates_der,
               "Path candidate should preserve AIA issuer certificates");
    ExpectTrue(candidates[0].trust_anchors_der == input.current_trust_anchors_der,
               "AIA certificates must not be promoted into trust anchors");
}

void TestPathSelectorChoosesFirstTrustedResultDeterministically() {
    using tamga::core::policy::ChainStatus;
    using tamga::core::validation::PathSelector;
    using tamga::core::validation::PathValidationResult;
    using tamga::core::validation::ValidationPolicy;

    std::vector<PathValidationResult> results(3);
    results[0].candidate_id = "current-tl";
    results[0].trusted = false;
    results[0].status = ChainStatus::Untrusted;
    results[1].candidate_id = "custom-trust-store";
    results[1].trusted = true;
    results[1].status = ChainStatus::Trusted;
    results[2].candidate_id = "historical-tl";
    results[2].trusted = true;
    results[2].status = ChainStatus::Trusted;
    results[2].uses_historical_trust = true;

    const auto selection = PathSelector().Select(results, ValidationPolicy{});
    ExpectTrue(selection.selected_index == 1,
               "PathSelector should select the first trusted result in candidate order");
    ExpectTrue(selection.selected_result.candidate_id == "custom-trust-store",
               "PathSelector should preserve the selected result");
    ExpectTrue(selection.reason == "trusted-candidate",
               "PathSelector should explain trusted selection");
}

void TestPathSelectorDoesNotSelectHistoricalWhenPolicyDisallowsIt() {
    using tamga::core::policy::ChainStatus;
    using tamga::core::validation::PathSelector;
    using tamga::core::validation::PathValidationResult;
    using tamga::core::validation::ValidationPolicy;

    std::vector<PathValidationResult> results(2);
    results[0].candidate_id = "current-tl";
    results[0].trusted = false;
    results[0].status = ChainStatus::Untrusted;
    results[1].candidate_id = "historical-tl";
    results[1].trusted = true;
    results[1].status = ChainStatus::Trusted;
    results[1].uses_historical_trust = true;

    ValidationPolicy policy;
    policy.allow_historical_trust = false;

    const auto selection = PathSelector().Select(results, policy);
    ExpectTrue(selection.selected_index == 0,
               "Historical result must not become authoritative when policy disallows it");
    ExpectTrue(selection.selected_result.candidate_id == "current-tl",
               "Selector should fall back to the current result instead of historical trust");
    ExpectTrue(selection.reason == "fallback-untrusted-candidate",
               "Selector should explain fallback selection");
}

void TestPathSelectorFallsBackToFirstNonTrustedCurrentResult() {
    using tamga::core::policy::ChainStatus;
    using tamga::core::validation::PathSelector;
    using tamga::core::validation::PathValidationResult;
    using tamga::core::validation::ValidationPolicy;

    std::vector<PathValidationResult> results(2);
    results[0].candidate_id = "current-tl";
    results[0].trusted = false;
    results[0].status = ChainStatus::Incomplete;
    results[1].candidate_id = "historical-tl";
    results[1].trusted = false;
    results[1].status = ChainStatus::Untrusted;
    results[1].uses_historical_trust = true;

    const auto selection = PathSelector().Select(results, ValidationPolicy{});
    ExpectTrue(selection.selected_index == 0,
               "Selector should fall back to the first non-trusted current result");
    ExpectTrue(selection.selected_result.status == ChainStatus::Incomplete,
               "Fallback selection should preserve the original result status");
}

void TestPathValidatorDelegatesEmptySignerToCertificateChainValidator() {
    using tamga::core::validation::PathCandidate;
    using tamga::core::validation::PathValidator;

    PathCandidate candidate;
    candidate.candidate_id = "current-tl";
    candidate.trust_anchor_source = "current-tl";
    candidate.trust_anchors_der = {{0x30, 0x00}};
    candidate.uses_historical_trust = true;

    tamga::core::policy::CertificateChainInput direct_input;
    direct_input.trust_anchor_source = candidate.trust_anchor_source;
    direct_input.trust_anchors_der = candidate.trust_anchors_der;
    const auto direct = tamga::core::policy::CertificateChainValidator{}.Validate(direct_input);
    const auto wrapped = PathValidator().Validate(candidate);

    ExpectTrue(wrapped.candidate_id == candidate.candidate_id,
               "PathValidator should preserve candidate id");
    ExpectTrue(wrapped.trust_anchor_source == candidate.trust_anchor_source,
               "PathValidator should preserve trust anchor source");
    ExpectTrue(wrapped.attempted, "PathValidator should mark candidate validation as attempted");
    ExpectTrue(wrapped.checked == direct.checked,
               "PathValidator checked flag should match CertificateChainValidator");
    ExpectTrue(wrapped.trusted == direct.trusted,
               "PathValidator trusted flag should match CertificateChainValidator");
    ExpectTrue(wrapped.chain_valid == direct.chain_valid,
               "PathValidator chain_valid flag should match CertificateChainValidator");
    ExpectTrue(wrapped.status == direct.status,
               "PathValidator status should match CertificateChainValidator");
    ExpectTrue(wrapped.message == direct.message,
               "PathValidator message should match CertificateChainValidator");
    ExpectTrue(wrapped.chain_debug == direct.chain_debug,
               "PathValidator chain debug should match CertificateChainValidator");
    ExpectTrue(wrapped.issuer_certificate_der == direct.issuer_certificate_der,
               "PathValidator issuer certificate should match CertificateChainValidator");
    ExpectTrue(wrapped.signer_issuer_certificate_der == direct.signer_issuer_certificate_der,
               "PathValidator signer issuer certificate should match CertificateChainValidator");
    ExpectFalse(wrapped.trusted, "Empty signer should not produce trusted PathValidationResult");
    ExpectFalse(wrapped.chain_valid, "Empty signer should not produce valid chain result");
    ExpectFalse(wrapped.chain_debug.empty(), "Empty signer should produce chain debug diagnostics");
    ExpectTrue(wrapped.issuer_certificate_der.empty(),
               "Empty signer should not return an issuer certificate");
    ExpectTrue(wrapped.signer_issuer_certificate_der.empty(),
               "Empty signer should not return signer issuer certificate");
    ExpectTrue(wrapped.uses_historical_trust,
               "PathValidator should preserve candidate historical-trust flag");
}

void TestForensicPathCandidatesDoNotAuthorizeHistoricalUnlessAllowed() {
    using tamga::core::policy::ChainStatus;
    using tamga::core::validation::PathBuilder;
    using tamga::core::validation::PathBuilderInput;
    using tamga::core::validation::PathSelector;
    using tamga::core::validation::PathValidationResult;
    using tamga::core::validation::TrustAnchorPolicy;

    PathBuilderInput input;
    input.signer_certificate_der = {0x01};
    input.current_trust_anchors_der = {{0x10}};
    input.historical_trust_anchors_der = {{0x20}};
    input.policy.trust_anchor_policy = TrustAnchorPolicy::ForensicAllPossible;
    input.policy.allow_historical_trust = false;
    input.policy.forensic_diagnostics = true;

    const auto candidates = PathBuilder().Build(input);
    ExpectTrue(candidates.size() == 2,
               "ForensicAllPossible should build diagnostic current and historical candidates");
    ExpectTrue(candidates[0].candidate_id == "forensic-current-tl",
               "Forensic current candidate should have diagnostic identity");
    ExpectTrue(candidates[1].candidate_id == "forensic-historical-tl",
               "Forensic historical candidate should have diagnostic identity");
    ExpectTrue(candidates[0].trust_anchors_der == input.current_trust_anchors_der,
               "Forensic current candidate should not mix historical anchors");
    ExpectTrue(candidates[1].trust_anchors_der == input.historical_trust_anchors_der,
               "Forensic historical candidate should not mix current anchors");

    std::vector<PathValidationResult> results(2);
    results[0].candidate_id = candidates[0].candidate_id;
    results[0].trusted = false;
    results[0].status = ChainStatus::Untrusted;
    results[1].candidate_id = candidates[1].candidate_id;
    results[1].trusted = true;
    results[1].status = ChainStatus::Trusted;
    results[1].uses_historical_trust = true;

    const auto disallowed = PathSelector().Select(results, input.policy);
    ExpectTrue(disallowed.selected_index == 0,
               "Forensic selector must not authorize historical trust when policy disallows it");

    input.policy.allow_historical_trust = true;
    const auto allowed = PathSelector().Select(results, input.policy);
    ExpectTrue(allowed.selected_index == 1,
               "Forensic selector may authorize historical trust only when policy allows it");
}
