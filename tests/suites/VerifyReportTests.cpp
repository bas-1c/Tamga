#include "support/FixturePaths.h"
// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено — ctest не знає, скільки тестів
// мало бути.
// Підсумок перевірки, звіти й сховище доказів.
//
// Сюди входять тести, що закріплюють К-01 (неповне покриття), В-03
// (частковий статус мітки часу) і HI-02 (LTV вимагає підтверджених
// доказів) на рівні звіту.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <set>
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
#include "core/session/VerifyReportCommit.h"
#include "core/policy/VerifyReportJson.h"
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

void TestComputeVerifySummaryBranches() {
    using tamga::core::VerifyReport;

    // not-executed: has_result=false
    {
        VerifyReport r;
        ExpectSummary(r, "not-executed", "Fresh VerifyReport should summarize as not-executed");
    }

    // execution-failed: VerifyCms could not run (e.g. NotInitialized, InvalidArgument)
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = false;
        ExpectSummary(r, "execution-failed",
                      "Execution failure should summarize as execution-failed");
    }

    // integrity-failed: signature mismatch reported cleanly by the adapter
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = false;
        ExpectSummary(r, "integrity-failed",
                      "Signature mismatch should summarize as integrity-failed");
    }

    // integrity-only: crypto-integrity confirmed but trust pipeline disabled
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = false;
        ExpectSummary(r, "integrity-only",
                      "Integrity-only result should summarize as integrity-only");
    }

    // integrity-but-revoked
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = false;
        r.trust_status = "certificate-revoked";
        ExpectSummary(r, "integrity-but-revoked",
                      "Revoked certificate should summarize as integrity-but-revoked");
    }

    // integrity-but-certificate-expired
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = false;
        r.trust_status = "certificate-time-invalid";
        ExpectSummary(r, "integrity-but-certificate-expired",
                      "Expired certificate should summarize as integrity-but-certificate-expired");
    }

    // integrity-but-chain-incomplete
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = false;
        r.trust_status = "certificate-chain-incomplete";
        ExpectSummary(r, "integrity-but-chain-incomplete",
                      "Incomplete chain should summarize as integrity-but-chain-incomplete");
    }

    // integrity-without-trust-store
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = false;
        r.trust_status = "trust-store-empty";
        ExpectSummary(r, "integrity-without-trust-store",
                      "Empty trust-store should summarize as integrity-without-trust-store");
    }

    // integrity-but-online-service-unavailable — untrusted-chain branch: trust_valid=false
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = false;
        r.trust_status = "ocsp-responder-unavailable";
        ExpectSummary(r, "integrity-but-online-service-unavailable",
                      "OCSP unavailable without trust should summarize as integrity-but-online-service-unavailable");
    }

    // integrity-but-untrusted-chain (catch-all)
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = false;
        r.trust_status = "untrusted-anchor";
        ExpectSummary(r, "integrity-but-untrusted-chain",
                      "Unknown trust failure should summarize as integrity-but-untrusted-chain");
    }

    // integrity-but-revocation-check-invalid: trusted chain was found, but CRL/OCSP data was invalid.
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = false;
        r.trust_status = "revocation-check-invalid";
        r.revocation_checked = true;
        r.revocation_status = "invalid";
        ExpectSummary(r, "integrity-but-revocation-check-invalid",
                      "Invalid CRL data should not be summarized as an untrusted chain");
    }
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = false;
        r.trust_status = "ocsp-response-invalid";
        r.revocation_checked = true;
        r.revocation_status = "invalid";
        ExpectSummary(r, "integrity-but-revocation-check-invalid",
                      "Invalid OCSP data should not be summarized as an untrusted chain");
    }

    // REGRESSION: trusted-chain + OCSP probe down must surface as
    // integrity-but-online-service-unavailable. Previously this fell through to
    // "integrity-and-trust" because the OCSP/TSP check lived only inside the
    // !trust_valid branch, misclassifying online-service outages as full success.
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;  // chain was validated against the trust-store
        r.trust_status = "ocsp-responder-unavailable";  // but OCSP probe failed afterwards
        ExpectSummary(r, "integrity-but-online-service-unavailable",
                      "Trusted chain with OCSP down should summarize as integrity-but-online-service-unavailable (regression)");
    }

    // REGRESSION: same for TSP outage with a trusted chain
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;
        r.trust_status = "tsp-responder-unavailable";
        ExpectSummary(r, "integrity-but-online-service-unavailable",
                      "Trusted chain with TSP down should summarize as integrity-but-online-service-unavailable (regression)");
    }

    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;
        r.trust_status = "ocsp-responder-unavailable";
        r.revocation_checked = true;
        r.revocation_status = "good";
        r.timestamp_checked = true;
        r.timestamp_valid = true;
        ExpectSummary(r, "integrity-but-online-service-unavailable",
                      "Online outage should outrank good revocation and valid timestamp");
    }

    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;
        r.trust_status = "tsp-responder-unavailable";
        r.revocation_checked = true;
        r.revocation_status = "unknown";
        ExpectSummary(r, "integrity-but-online-service-unavailable",
                      "Online outage should outrank unknown revocation");
    }

    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;
        r.trust_status = "ocsp-responder-unavailable";
        r.revocation_checked = true;
        r.revocation_status = "temporarily-unavailable";
        ExpectSummary(r, "integrity-but-revocation-unknown",
                      "OCSP unavailable with temporarily unavailable revocation should summarize as revocation unknown");
    }

    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;
        r.trust_status = "tsp-responder-unavailable";
        r.revocation_checked = true;
        r.revocation_status = "good";
        ExpectSummary(r, "integrity-but-online-service-unavailable",
                      "TSP unavailable without revocation uncertainty should remain an online service outage");
    }

    // integrity-trust-and-revocation: fully trusted + OCSP answered with good
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;
        r.trust_status = "online-policy-services-available";
        r.revocation_checked = true;
        r.revocation_status = "good";
        ExpectSummary(r, "integrity-trust-and-revocation",
                      "Trusted chain with good revocation should summarize as integrity-trust-and-revocation");
    }

    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;
        r.revocation_checked = true;
        r.revocation_status = "good";
        r.timestamp_checked = true;
        r.timestamp_valid = true;
        r.trust_status = "policy-valid";
        ExpectSummary(r, "integrity-trust-revocation-and-timestamp",
                      "Trusted signature with good revocation and valid timestamp should summarize as full local policy");
    }
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;
        r.revocation_checked = true;
        r.revocation_status = "unknown";
        ExpectSummary(r, "integrity-but-revocation-unknown",
                      "Unknown revocation after trusted chain should be explicit");
    }
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.timestamp_checked = true;
        r.timestamp_valid = false;
        r.trust_status = "timestamp-invalid";
        ExpectSummary(r, "integrity-but-timestamp-invalid",
                      "Invalid timestamp should be explicit in summary");
    }
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;
        r.trust_status = "timestamp-not-fully-validated";
        r.timestamp_checked = true;
        r.timestamp_valid = false;
        ExpectSummary(r, "integrity-but-timestamp-not-fully-validated",
                      "Partial timestamp validation should be explicit even before revocation is confirmed");
    }

    // integrity-and-trust: chain trusted but no revocation confirmation performed
    {
        VerifyReport r;
        r.has_result = true;
        r.execution_succeeded = true;
        r.signature_valid = true;
        r.trust_checked = true;
        r.trust_valid = true;
        r.trust_status = "chain-trusted";
        ExpectSummary(r, "integrity-and-trust",
                      "Trusted chain without revocation data should summarize as integrity-and-trust");
    }
}

void TestTechnicalReportPolicyBlocks() {
    tamga::core::VerifyReport r;
    r.has_result = true;
    r.execution_succeeded = true;
    r.signature_valid = true;
    r.trust_list_checked = true;
    r.trust_list_cache_status = "fresh";
    r.trust_list_update_succeeded = true;
    r.trust_checked = true;
    r.trust_valid = true;
    r.revocation_checked = true;
    r.revocation_status = "temporarily-unavailable";
    r.timestamp_checked = true;
    r.timestamp_valid = true;
    ExpectSummary(r, "integrity-but-revocation-unknown",
                  "Hybrid signer revocation uncertainty should not summarize as full policy");

    tamga::core::VerifyReport bes_without_timestamp;
    bes_without_timestamp.has_result = true;
    bes_without_timestamp.execution_succeeded = true;
    bes_without_timestamp.signature_valid = true;
    bes_without_timestamp.trust_checked = true;
    bes_without_timestamp.trust_valid = true;
    bes_without_timestamp.revocation_checked = true;
    bes_without_timestamp.revocation_status = "good";
    bes_without_timestamp.trust_status = "trusted-anchor-validated";
    bes_without_timestamp.timestamp_checked = true;
    bes_without_timestamp.timestamp_valid = false;
    ExpectPolicyDecision(bes_without_timestamp,
                         true,
                         "bes",
                         "integrity-trust-and-revocation",
                         "Missing timestamp should remain valid for BES-level policy");

    tamga::core::VerifyReport cades_t = bes_without_timestamp;
    cades_t.timestamp_valid = true;
    ExpectPolicyDecision(cades_t,
                         true,
                         "cades-t",
                         "integrity-trust-revocation-and-timestamp",
                         "Valid timestamp should produce CAdES-T policy level");

    tamga::core::VerifyReport partial_timestamp;
    partial_timestamp.has_result = true;
    partial_timestamp.execution_succeeded = true;
    partial_timestamp.signature_valid = true;
    partial_timestamp.trust_checked = true;
    partial_timestamp.trust_valid = true;
    partial_timestamp.revocation_checked = true;
    partial_timestamp.revocation_status = "good";
    partial_timestamp.trust_status = "timestamp-not-fully-validated";
    partial_timestamp.timestamp_checked = true;
    partial_timestamp.timestamp_valid = false;
    ExpectPolicyDecision(partial_timestamp,
                         false,
                         "integrity-only",
                         "integrity-but-timestamp-not-fully-validated",
                         "Partially verified timestamp token must not become valid BES policy");

    tamga::core::VerifyReport tsp_unavailable;
    tsp_unavailable.has_result = true;
    tsp_unavailable.execution_succeeded = true;
    tsp_unavailable.signature_valid = true;
    tsp_unavailable.trust_checked = true;
    tsp_unavailable.trust_valid = true;
    tsp_unavailable.revocation_checked = true;
    tsp_unavailable.revocation_status = "good";
    tsp_unavailable.trust_status = "tsp-responder-unavailable";
    tsp_unavailable.timestamp_checked = true;
    tsp_unavailable.timestamp_valid = false;
    ExpectSummary(tsp_unavailable,
                  "integrity-but-online-service-unavailable",
                  "TSP unavailable should remain an online service summary");
    ExpectPolicyDecision(tsp_unavailable,
                         false,
                         "integrity-only",
                         "integrity-but-online-service-unavailable",
                         "TSP unavailable must not become valid BES policy");

    tamga::core::VerifyReport tsp_unavailable_without_timestamp_check = tsp_unavailable;
    tsp_unavailable_without_timestamp_check.timestamp_checked = false;
    tsp_unavailable_without_timestamp_check.timestamp_valid = false;
    ExpectPolicyDecision(tsp_unavailable_without_timestamp_check,
                         false,
                         "integrity-only",
                         "integrity-but-online-service-unavailable",
                         "Explicit TSP outage must not become valid BES policy even without timestamp flags");

    tamga::core::VerifyReport ocsp_unavailable = bes_without_timestamp;
    ocsp_unavailable.trust_status = "ocsp-responder-unavailable";
    ExpectSummary(ocsp_unavailable,
                  "integrity-but-online-service-unavailable",
                  "OCSP unavailable should remain an online service summary when revocation is otherwise good");
    ExpectPolicyDecision(ocsp_unavailable,
                         false,
                         "integrity-only",
                         "integrity-but-online-service-unavailable",
                         "Explicit OCSP outage must not become valid policy");

    tamga::core::Session session;
    std::string report;
    ExpectTrue(session.GetLastVerifyReport(report), "GetLastVerifyReport should expose technical report JSON");
    ExpectValidJson(report, "Technical report should remain valid JSON");
    ExpectContains(report, "\"policy\":{", "Technical report should include policyDecision block");
    ExpectContains(report, "\"level\":\"integrity-only\"",
                   "Technical report should default policyDecision to integrity-only when no verify result exists");
    ExpectContains(report, "\"trustList\"", "Technical report should include trustList block");
}

void TestUserReportPolicyDecisionAlignment() {
    tamga::core::VerifyReport r;
    r.has_result = true;
    r.execution_succeeded = true;
    r.signature_valid = true;
    r.trust_checked = true;
    r.trust_valid = true;
    r.revocation_checked = true;
    r.revocation_status = "good";
    r.trust_status = "tsp-responder-unavailable";
    r.timestamp_checked = true;
    r.timestamp_valid = false;
    r.operation = "VerifyData";

    const auto decision = tamga::core::ComputeVerifyPolicyDecision(r);
    ExpectFalse(decision.valid, "Technical policyDecision should reject TSP unavailable state");

    tamga::core::policy::UserReportInput input;
    input.verify_report = r;
    input.container_type = "CAdES detached";
    input.signature_format = "cms-detached";
    const std::string user_report = tamga::core::policy::UserReportBuilder{}.Build(input);

    ExpectValidJson(user_report, "User report policy alignment fixture should be valid JSON");
    ExpectContains(user_report,
                   "\"summaryCode\":\"integrity-but-online-service-unavailable\"",
                   "User report validity should align with technical policyDecision for TSP unavailable state");
}

void TestOnlineOutageDoesNotOverrideTrustFailureStatus() {
    tamga::core::VerifyReport revoked;
    revoked.trust_checked = true;
    revoked.trust_valid = false;
    revoked.trust_status = "certificate-revoked";
    revoked.error_code = tamga::core::ErrorCode::RevocationCheckFailed;
    ExpectFalse(tamga::core::CanOnlineServiceOutageOverrideTrustStatus(revoked, false),
                "TSP outage must not override certificate-revoked trust failure");

    tamga::core::VerifyReport ocsp_invalid;
    ocsp_invalid.trust_checked = true;
    ocsp_invalid.trust_valid = false;
    ocsp_invalid.trust_status = "ocsp-response-invalid";
    ocsp_invalid.error_code = tamga::core::ErrorCode::RevocationCheckFailed;
    ExpectFalse(tamga::core::CanOnlineServiceOutageOverrideTrustStatus(ocsp_invalid, false),
                "TSP outage must not override OCSP invalid trust failure");

    tamga::core::VerifyReport trusted;
    trusted.trust_checked = true;
    trusted.trust_valid = true;
    trusted.trust_status = "trusted-anchor-validated";
    ExpectTrue(tamga::core::CanOnlineServiceOutageOverrideTrustStatus(trusted, false),
               "TSP outage may update status when no trust failure exists");

    tamga::core::VerifyReport partial_timestamp;
    partial_timestamp.trust_checked = true;
    partial_timestamp.trust_valid = true;
    partial_timestamp.trust_status = "timestamp-not-fully-validated";
    partial_timestamp.timestamp_checked = true;
    partial_timestamp.timestamp_valid = false;
    ExpectFalse(tamga::core::CanOnlineServiceOutageOverrideTrustStatus(partial_timestamp, false),
                "TSP availability must not override partial timestamp validation status");
}

void TestTrustFailureErrorCodePreservesOcspInvalidAsRevocationFailure() {
    tamga::core::VerifyReport report;
    report.trust_checked = true;
    report.trust_valid = false;
    report.trust_status = "ocsp-response-invalid";
    report.revocation_checked = true;
    report.revocation_status = "invalid";

    ExpectTrue(tamga::core::TrustFailureErrorCode(report) == tamga::core::ErrorCode::RevocationCheckFailed,
               "OCSP invalid response should preserve RevocationCheckFailed error code");
}

void TestTrustFailureErrorCodePreservesTimestampInvalid() {
    tamga::core::VerifyReport report;
    report.trust_checked = true;
    report.trust_valid = false;
    report.trust_status = "timestamp-invalid";
    report.timestamp_checked = true;
    report.timestamp_valid = false;

    ExpectTrue(tamga::core::TrustFailureErrorCode(report) == tamga::core::ErrorCode::TimestampValidationFailed,
               "Invalid timestamp should preserve TimestampValidationFailed error code");
}

// Хвиля 8, п.3: раніше цей тест звався
// TestTimestampUnsupportedDoesNotBecomeInvalidTrustFailure і перевіряв, що
// статус Unsupported НЕ скидає довіру. Він доводив властивість мертвої функції
// ApplyTimestampValidationResultToVerifyReport, яку продакшн не викликав
// жодного разу, — тобто рівно дефект С-16.
//
// Живий шлях (ApplyXadesTimestampPolicyValidation) поводиться інакше й
// суворіше: якщо токен мітки часу Є, але не пройшов перевірку, довіра
// понижується. Відсутність токена до цього місця не доходить — там ранній
// return. Тому стару, м'якшу асерцію не збережено: вона описувала політику,
// якої продукт більше не має.
void TestTimestampFailureDowngradesTrust() {
    tamga::core::VerifyReport report;
    report.trust_checked = true;
    report.trust_valid = true;
    report.trust_status = "trusted-anchor-validated";
    report.error_code = tamga::core::ErrorCode::None;

    tamga::core::ApplyTimestampFailureToTrust(report);

    ExpectFalse(report.trust_valid, "Провал мітки часу мусить понизити довіру");
    ExpectTrue(report.trust_status == "timestamp-invalid",
               "Причина недовіри мусить називати саме мітку часу");
    ExpectTrue(report.error_code == tamga::core::ErrorCode::TimestampValidationFailed,
               "Код помилки мусить бути TimestampValidationFailed");
}

void TestTimestampInvalidDoesNotMaskExistingRevocationFailure() {
    tamga::core::VerifyReport report;
    report.trust_checked = true;
    report.trust_valid = false;
    report.trust_status = "certificate-revoked";
    report.error_code = tamga::core::ErrorCode::RevocationCheckFailed;
    report.revocation_checked = true;
    report.revocation_status = "revoked";

    // Це і є інваріант, заради якого гейт `report.trust_valid` існує:
    // провал мітки часу не має перекривати вже зафіксовану причину недовіри.
    // Покриття перенесено з мертвої функції на живу.
    tamga::core::ApplyTimestampFailureToTrust(report);

    ExpectTrue(report.trust_status == "certificate-revoked",
               "Invalid timestamp must not mask existing revoked trust status");
    ExpectTrue(report.error_code == tamga::core::ErrorCode::RevocationCheckFailed,
               "Invalid timestamp must not replace existing revocation error code");
    ExpectTrue(report.revocation_status == "revoked",
               "Invalid timestamp must not change revocation status");
}

void TestInitialVerifyReportState() {
    tamga::core::Session session;
    std::string json;
    ExpectTrue(session.GetLastVerifyReport(json), "GetLastVerifyReport should succeed before any verification");
    ExpectValidJson(json, "Initial verify report should be valid JSON");
    ExpectContains(json, "\"schemaVersion\":\"2.2\"", "GetLastVerifyReport should advertise v2.2 schema");
    ExpectContains(json, "\"hasResult\":false", "Initial verify report should indicate missing result");
    ExpectContains(json, "\"summaryCode\":\"not-executed\"", "Initial verify report should summarize as not-executed");
    ExpectContains(json, "\"trustStatus\":\"not-implemented\"", "Initial verify report should expose trust status");
    ExpectContains(json, "\"summary\":{", "Verify report should expose structured categories");
    ExpectContains(json, "\"signature\":{", "Verify report should expose cryptoIntegrity category");
    ExpectContains(json, "\"trust\":{", "Verify report should expose trust category");
    ExpectContains(json, "\"revocation\":{", "Verify report should expose revocation category");
    ExpectContains(json, "\"timestamp\":{", "Verify report should expose timestamp category");
    ExpectContains(json, "\"certificate\":{", "Verify report should expose certificate category");
    ExpectContains(json, "\"chain\":{", "Verify report should expose chain category");
    ExpectContains(json, "\"details\":[]", "Початковий звіт не вигадує перевірених міток");

    tamga::core::validation::TimestampEngineResult tsa_result;
    tsa_result.status = tamga::core::policy::TimestampStatus::UntrustedTsa;
    tsa_result.crypto_valid = true;
    tsa_result.policy_acceptable = true;
    tsa_result.reason_code = "TSA_REVOCATION_UNKNOWN";
    tsa_result.revocation_status = tamga::core::policy::RevocationStatus::Unknown;
    tsa_result.because = {"Немає відповіді \"OCSP\" для TSA"};
    auto partial = tamga::core::ProjectTimestampResult(tsa_result);
    partial.signature_index = 2;
    tamga::core::TimestampEntry good;
    good.signature_index = 1;
    good.valid = true;
    good.status = "timestamp-valid";
    tamga::core::VerifyReport report;
    report.has_result = true;
    report.execution_succeeded = true;
    report.timestamp_details = {good, partial};
    tamga::core::ApplyTimestampDetailsVerdict(report);
    ExpectTrue(!report.timestamp_valid && report.timestamp_status == "timestamp-partial",
               "Друга неповна TSA-перевірка не ховається за першою валідною міткою");
    std::ostringstream detail_json;
    detail_json << '{';
    tamga::core::policy::WriteTimestampSection(detail_json, report,
                                              tamga::core::policy::MessageStyle::None);
    detail_json << "\"end\":true}";
    ExpectValidJson(detail_json.str(), "Діагностика TSA коректно екранує повідомлення");
    ExpectContains(detail_json.str(), "\"reasonCode\":\"TSA_REVOCATION_UNKNOWN\"",
                   "Точна причина TSA потрапляє до звіту");
    ExpectContains(detail_json.str(), "\"policyAcceptable\":true",
                   "Прийнятність за soft-fail відокремлена від повної валідності");
    report.timestamp_details.back().status = "timestamp-invalid";
    tamga::core::ApplyFormatTimestampVerdict(report, true, true);
    ExpectTrue(report.timestamp_status == "timestamp-invalid", "Формат не підвищує канонічну відмову");
    std::reverse(report.timestamp_details.begin(), report.timestamp_details.end());
    tamga::core::ApplyTimestampDetailsVerdict(report);
    ExpectTrue(report.timestamp_status == "timestamp-invalid", "Результат не залежить від порядку міток");
    report.timestamp_details = {good, good};
    tamga::core::ApplyTimestampDetailsVerdict(report);
    ExpectTrue(report.timestamp_valid, "Повний статус вимагає валідності всіх міток");
    report.ltv_evidence_validated = true;
    tamga::core::SignatureEntry first_signer;
    first_signer.ltv_evidence_validated = true;
    report.signatures = {first_signer, {}};
    ExpectFalse(tamga::core::policy::LtvFullyValidated(report),
                "Повний LTV не підтверджується лише доказами першого підписувача");
    report.signatures.back().ltv_evidence_validated = true;
    ExpectTrue(tamga::core::policy::LtvFullyValidated(report), "Повний LTV враховує всі підписи");
    report.signature_valid = true;
    report.trust_checked = true;
    report.trust_valid = true;
    report.revocation_checked = true;
    report.revocation_status = "valid";
    report.timestamp_details = {partial};
    tamga::core::ApplyTimestampDetailsVerdict(report);
    ExpectTrue(tamga::core::ComputeVerifyPolicyDecision(report).valid,
               "Soft-fail може прийняти цілісність і довіру без повного TSA");
    report.timestamp_details.front().policy_acceptable = false;
    ExpectFalse(tamga::core::ComputeVerifyPolicyDecision(report).valid,
                "Hard-fail невідомого TSA статусу не губиться у форматному звіті");
    report.timestamp_details.front().status = "timestamp-invalid";
    report.timestamp_details.front().policy_acceptable = true;
    tamga::core::ApplyTimestampDetailsVerdict(report);
    ExpectFalse(tamga::core::ComputeVerifyPolicyDecision(report).valid,
                "Доведена невалідність мітки не приймається навіть за soft-fail");
}

void TestEvidenceStoreStableRawEvidenceIds() {
    tamga::core::validation::EvidenceStore store;
    const std::vector<std::uint8_t> same_bytes = {'a', 'b', 'c'};

    const std::string embedded_id = store.PutRawEvidence("certificate", same_bytes, "embedded");
    const std::string aia_id = store.PutRawEvidence("certificate", same_bytes, "aia");

    ExpectTrue(embedded_id == aia_id, "Raw evidence ID should be stable for identical bytes");
    ExpectTrue(embedded_id.rfind("sha256:", 0) == 0, "Raw evidence ID should use sha256 prefix");
    ExpectTrue(embedded_id == "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
               "Raw evidence ID should match SHA-256 known vector for abc");

    const tamga::core::validation::EvidenceRecord* record = store.Resolve(embedded_id);
    ExpectTrue(record != nullptr, "EvidenceStore should resolve stored raw evidence");
    if (record != nullptr) {
        ExpectTrue(record->type == "certificate", "Raw evidence should keep first stored type");
        ExpectTrue(record->source == "embedded", "Raw evidence should keep first stored source");
        ExpectTrue(record->bytes == same_bytes, "Raw evidence should keep first stored bytes");
    }

    ExpectTrue(store.PutRawEvidence("empty", {}, "test") ==
                   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               "Raw evidence ID should match SHA-256 known vector for empty input");
    ExpectTrue(store.PutRawEvidence("padding", std::vector<std::uint8_t>(55, static_cast<std::uint8_t>('a')), "test") ==
                   "sha256:9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
               "Raw evidence ID should match SHA-256 known vector for 55 ASCII a bytes");
    ExpectTrue(store.PutRawEvidence("padding", std::vector<std::uint8_t>(56, static_cast<std::uint8_t>('a')), "test") ==
                   "sha256:b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
               "Raw evidence ID should match SHA-256 known vector for 56 ASCII a bytes");
    ExpectTrue(store.PutRawEvidence("padding", std::vector<std::uint8_t>(57, static_cast<std::uint8_t>('a')), "test") ==
                   "sha256:f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6",
               "Raw evidence ID should match SHA-256 known vector for 57 ASCII a bytes");
    ExpectTrue(store.PutRawEvidence("padding", std::vector<std::uint8_t>(64, static_cast<std::uint8_t>('a')), "test") ==
                   "sha256:ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
               "Raw evidence ID should match SHA-256 known vector for 64 ASCII a bytes");
    ExpectTrue(store.PutRawEvidence("padding", std::vector<std::uint8_t>(100, static_cast<std::uint8_t>('a')), "test") ==
                   "sha256:2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e",
               "Raw evidence ID should match SHA-256 known vector for 100 ASCII a bytes");
}

void TestEvidenceStoreCanonicalDerivedEvidenceIds() {
    tamga::core::validation::EvidenceStore store;

    const std::string first = store.PutDerivedEvidence(
        "revocation-result",
        {{"status", "good"}, {"source", "ocsp"}});
    const std::string second = store.PutDerivedEvidence(
        "revocation-result",
        {{"source", "ocsp"}, {"status", "good"}});

    ExpectTrue(first == second, "Derived evidence ID should be stable for reversed fields");
    ExpectTrue(first.rfind("sha256:", 0) == 0, "Derived evidence ID should use sha256 prefix");
    ExpectTrue(first == "sha256:3cea8489306547230ec0ee8c286b02d8ba310305644f310e991fad2a84fdea68",
               "Derived evidence ID should match SHA-256 of canonical JSON computed via .NET SHA256");

    const tamga::core::validation::EvidenceRecord* record = store.Resolve(first);
    ExpectTrue(record != nullptr, "EvidenceStore should resolve stored derived evidence");
    if (record != nullptr) {
        ExpectTrue(record->type == "revocation-result", "Derived evidence should store type");
        ExpectTrue(record->source == "ocsp", "Derived evidence should expose source field");
        ExpectTrue(record->canonical_json ==
                       "{\"source\":\"ocsp\",\"status\":\"good\",\"type\":\"revocation-result\"}",
                   "Derived evidence should store canonical JSON with sorted keys");
    }
}

void TestEvidenceStoreEscapesDerivedEvidenceJson() {
    tamga::core::validation::EvidenceStore store;
    std::string escaped_value = "quote:\" backslash:\\ newline:\n tab:\t nul:";
    escaped_value.push_back('\0');
    escaped_value += "end";

    const std::string id = store.PutDerivedEvidence(
        "escaped",
        {{"status", escaped_value}, {"source", "unit"}});

    const tamga::core::validation::EvidenceRecord* record = store.Resolve(id);
    ExpectTrue(record != nullptr, "Escaped derived evidence should be stored");
    if (record != nullptr) {
        ExpectContains(record->canonical_json, "\\\"", "Canonical JSON should escape quotes");
        ExpectContains(record->canonical_json, "\\\\", "Canonical JSON should escape backslashes");
        ExpectContains(record->canonical_json, "\\n", "Canonical JSON should escape newlines");
        ExpectContains(record->canonical_json, "\\t", "Canonical JSON should escape tabs");
        ExpectContains(record->canonical_json, "\\u0000", "Canonical JSON should escape embedded NUL");
    }
}

void TestEvidenceStoreRejectsInvalidDerivedFields() {
    tamga::core::validation::EvidenceStore store;

    const std::string duplicate = store.PutDerivedEvidence(
        "revocation-result",
        {{"status", "good"}, {"status", "bad"}});
    ExpectTrue(duplicate.empty(), "Derived evidence should reject duplicate field keys");
    ExpectTrue(store.Resolve("") == nullptr, "EvidenceStore should not resolve empty rejected ID");

    const std::string reserved = store.PutDerivedEvidence(
        "revocation-result",
        {{"type", "spoof"}, {"status", "good"}});
    ExpectTrue(reserved.empty(), "Derived evidence should reject caller-supplied reserved type field");
    ExpectTrue(store.Resolve(reserved) == nullptr, "EvidenceStore should not store reserved type field evidence");
}

void TestUserReportInitialShape() {
    tamga::core::Session session;
    PrepareInitializedSession(session);
    std::string json;
    ExpectTrue(session.GetUserReport(json), "GetUserReport should return JSON");
    ExpectContains(json, "\"schemaVersion\":\"2.2\"", "User report should expose schema version 2.2");
    ExpectContains(json, "\"summary\":{", "User report should expose summary block");
    ExpectContains(json, "\"certificate\":{", "User report should expose certificate block");
}

void TestJsonValidatorRejectsMalformedInput() {
    ExpectInvalidJson("{\"a\" \"b\"}", "JSON validator should reject missing object key colon");
    ExpectInvalidJson("{foo}", "JSON validator should reject unquoted object keys");
    ExpectInvalidJson("{} trailing", "JSON validator should reject trailing garbage after root value");
}

namespace {

// Хвиля 8, п.1 (залишок): службові розбирачі для вартового нижче.
//
// Знаходить секцію `"name":{...}` і повертає її ВМІСТ без зовнішніх дужок.
// Сканер знає про рядки й екранування, тож дужка всередині значення його не
// збиває. Порожній рядок означає «секції немає».
std::string ExtractJsonSectionBody(const std::string& json, const std::string& name) {
    const std::string needle = "\"" + name + "\":{";
    const std::size_t start = json.find(needle);
    if (start == std::string::npos) {
        return {};
    }
    const std::size_t body_start = start + needle.size();
    int depth = 1;
    bool in_string = false;
    bool escaped = false;
    for (std::size_t i = body_start; i < json.size(); ++i) {
        const char c = json[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (in_string) {
            if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        if (c == '"') {
            in_string = true;
        } else if (c == '{' || c == '[') {
            ++depth;
        } else if (c == '}' || c == ']') {
            --depth;
            if (depth == 0) {
                return json.substr(body_start, i - body_start);
            }
        }
    }
    return {};
}

// Розкладає вміст секції на поля ВЕРХНЬОГО рівня. Поле `message` свідомо
// пропускається: воно є лише в користувацькому звіті, і це задокументована
// різниця, а не розходження форми.
std::vector<std::string> TopLevelJsonFields(const std::string& body) {
    std::vector<std::string> fields;
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    std::size_t begin = 0;
    for (std::size_t i = 0; i <= body.size(); ++i) {
        const bool at_end = (i == body.size());
        const char c = at_end ? ',' : body[i];
        if (!at_end) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (in_string) {
                if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    in_string = false;
                }
                continue;
            }
            if (c == '"') {
                in_string = true;
                continue;
            }
            if (c == '{' || c == '[') {
                ++depth;
                continue;
            }
            if (c == '}' || c == ']') {
                --depth;
                continue;
            }
        }
        if (c == ',' && depth == 0) {
            const std::string piece = body.substr(begin, i - begin);
            begin = i + 1;
            if (!piece.empty() && piece.rfind("\"message\":", 0) != 0) {
                fields.push_back(piece);
            }
        }
    }
    return fields;
}

} // namespace

// Хвиля 8, п.1 (залишок): ВАРТОВИЙ проти повторного розходження двох звітів.
//
// Форма секцій тепер одна (`core/policy/VerifyReportJson`), але ніщо не
// заважає комусь дописати поле прямо на місці виклику — в один звіт і забути
// про другий. Саме так з'явилися всі попередні копії.
//
// Тест бере ОДИН стан перевірки і вимагає, щоб секції, спільні за задумом,
// збігалися полем у поле і значенням у значення. `message` пропускається —
// це єдина свідома різниця.
//
// Негативний контроль виконано на знімку з семи реальних артефактів:
// перейменування одного поля у спільному модулі змінює ОБИДВА звіти
// (8 входжень), а дописування поля лише в один — валить цей тест.
void TestReportJsonSharedSectionsAgree() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture unavailable for shared report sections check");
        return;
    }

    tamga::core::Session session;
    PrepareInitializedSession(session);
    ExpectTrue(session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
               "Fixture key should load before shared report sections check");

    const std::vector<std::uint8_t> data{'s', 'h', 'a', 'r', 'e', 'd'};
    std::vector<std::uint8_t> signature;
    ExpectTrue(session.SignData(data, signature, tamga::core::TimestampMode::Disabled),
               "Signing should succeed before shared report sections check");
    bool is_valid = false;
    ExpectTrue(session.VerifyData(data, signature, is_valid),
               "VerifyData should populate both reports");

    std::string technical;
    std::string user;
    ExpectTrue(session.GetLastVerifyReport(technical), "Technical report should be readable");
    ExpectTrue(session.GetUserReport(user), "User report should be readable");

    // Секції, форма яких у двох звітах збігається повністю.
    for (const char* name : {"trust", "revocation", "timestamp", "ltv"}) {
        const std::vector<std::string> from_technical =
            TopLevelJsonFields(ExtractJsonSectionBody(technical, name));
        const std::vector<std::string> from_user =
            TopLevelJsonFields(ExtractJsonSectionBody(user, name));

        const std::string present =
            std::string("Section \"") + name + "\" must be present in the technical report";
        ExpectFalse(from_technical.empty(), present.c_str());

        const std::string agree =
            std::string("Section \"") + name + "\" must be identical in both reports (single emitter)";
        ExpectTrue(from_technical == from_user, agree.c_str());
    }

    // Секції, які свідомо мають РІЗНІ додаткові поля, все одно мусять
    // погоджуватися у вердикті: перші два поля — це завжди status і code.
    for (const char* name : {"summary", "signature", "certificate", "policy"}) {
        const std::vector<std::string> from_technical =
            TopLevelJsonFields(ExtractJsonSectionBody(technical, name));
        const std::vector<std::string> from_user =
            TopLevelJsonFields(ExtractJsonSectionBody(user, name));

        const std::string verdict =
            std::string("Section \"") + name + "\" must carry the same status/code in both reports";
        ExpectTrue(from_technical.size() >= 2 && from_user.size() >= 2 &&
                       from_technical[0] == from_user[0] && from_technical[1] == from_user[1],
                   verdict.c_str());
    }
#else
    RecordSkip("cryptonite disabled: shared report sections check needs a real verify");
#endif
}


namespace {

// ADR-028: витягує значення поля верхнього рівня зі списку `TopLevelJsonFields`.
// Порожній рядок — поля немає.
std::string FieldValue(const std::vector<std::string>& fields, const std::string& key) {
    const std::string prefix = "\"" + key + "\":";
    for (const std::string& f : fields) {
        if (f.rfind(prefix, 0) == 0) {
            return f.substr(prefix.size());
        }
    }
    return {};
}

// Будує набір станів звіту, які інакше довелося б ловити на реальних
// артефактах. Саме перелічення станів, а не сподівання, що фікстура влучить,
// робить цю сторожу здатною побачити суперечність.
std::vector<tamga::core::VerifyReport> ReportStatesForNamingInvariant() {
    using tamga::core::VerifyReport;
    std::vector<VerifyReport> states;

    // 1. Початковий стан: перевірку не виконували.
    states.push_back(VerifyReport{});

    // 2. XAdES із докази присутніми, але НЕ підтвердженими. Саме цей стан
    //    відвантажується для реальних артефактів Дії і дає блок, де
    //    "status":"unavailable" стоїть поруч із "valid":true.
    VerifyReport xades_partial;
    xades_partial.has_result = true;
    xades_partial.execution_succeeded = true;
    xades_partial.signature_valid = true;
    xades_partial.signature_format = "XAdES";
    xades_partial.ltv_valid = true;
    xades_partial.ltv_evidence_bound = true;
    xades_partial.ltv_evidence_validated = false;
    states.push_back(xades_partial);

    // 3. Те саме для PAdES.
    VerifyReport pades_partial = xades_partial;
    pades_partial.signature_format = "PAdES";
    states.push_back(pades_partial);

    // 4. Повністю підтверджений LTV: тут "valid":true законний.
    VerifyReport validated = xades_partial;
    validated.ltv_evidence_validated = true;
    validated.trust_checked = true;
    validated.trust_valid = true;
    validated.revocation_checked = true;
    validated.revocation_status = "valid";
    states.push_back(validated);

    // 5. Довіру перевірено і відхилено.
    VerifyReport untrusted;
    untrusted.has_result = true;
    untrusted.execution_succeeded = true;
    untrusted.signature_valid = true;
    untrusted.trust_checked = true;
    untrusted.trust_valid = false;
    untrusted.trust_status = "chain-not-trusted";
    states.push_back(untrusted);

    // 6. Неповне покриття контейнера (К-01).
    VerifyReport partial_coverage;
    partial_coverage.has_result = true;
    partial_coverage.execution_succeeded = true;
    partial_coverage.signature_valid = true;
    partial_coverage.container_coverage_complete = false;
    partial_coverage.coverage_status = "container-object-not-signed";
    states.push_back(partial_coverage);

    return states;
}

// Читає перелік записаних винятків. Ключ — `блок.поле`.
std::set<std::string> LoadReportSchemaExceptions(bool& loaded) {
    std::set<std::string> allowed;
    const std::filesystem::path path =
        tamga_test::TestDataRoot() / "tests" / "report_schema_exceptions.baseline";
    std::ifstream in(path);
    loaded = in.is_open();
    if (!loaded) {
        return allowed;
    }
    std::string line;
    while (std::getline(in, line)) {
        const std::size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos || line[first] == '#') {
            continue;
        }
        const std::size_t end = line.find_first_of(" \t", first);
        allowed.insert(line.substr(first, end == std::string::npos ? end : end - first));
    }
    return allowed;
}

} // namespace

// ADR-028: СТОРОЖА правила іменування фактів звіту.
//
// Правило: поле з іменем `valid` може бути `true` лише тоді, коли `status`
// свого блока дорівнює `valid`. Факт, слабший за «перевірено й дійсне», має
// називатися так, як він називається насправді.
//
// Порушення цього правила вже відвантажується: `ltv.valid` означає «докази
// структурно присутні» (HI-02), тож у звіті стоїть `"status":"unavailable"`
// поруч із `"valid":true`. Прибрати це у 2.x означало б зламати інтеграторів,
// тому воно записане у `tests/report_schema_exceptions.baseline` із версією,
// у якій зникне.
//
// Тест падає на будь-якому порушенні, якого в переліку немає: НОВЕ поле не
// може назватися `valid`, не будучи ним.
void TestReportFactNamingInvariant() {
    bool loaded = false;
    const std::set<std::string> allowed = LoadReportSchemaExceptions(loaded);
    ExpectTrue(loaded, "ADR-028: tests/report_schema_exceptions.baseline must be readable");

    static const char* const kBlocks[] = {"summary",    "signature", "certificate", "trust",
                                          "revocation", "timestamp", "ltv",         "policy"};

    std::set<std::string> seen_violations;
    std::size_t inspected = 0;

    for (const tamga::core::VerifyReport& state : ReportStatesForNamingInvariant()) {
        tamga::core::policy::UserReportInput input;
        input.verify_report = state;
        const std::string json = tamga::core::policy::UserReportBuilder{}.Build(input);

        for (const char* name : kBlocks) {
            const std::vector<std::string> fields =
                TopLevelJsonFields(ExtractJsonSectionBody(json, name));
            if (fields.empty()) {
                continue;
            }
            ++inspected;

            const std::string status = FieldValue(fields, "status");
            const std::string valid = FieldValue(fields, "valid");
            if (valid == "true" && status != "\"valid\"") {
                seen_violations.insert(std::string(name) + ".valid");
            }
        }
    }

    // Сторожа має бути НЕвакуумною: якщо блоки не розібралися, тест мовчки
    // проходив би на будь-якому звіті.
    ExpectTrue(inspected >= 24,
               "ADR-028: the scanner must actually inspect report blocks, not pass vacuously");

    // Стан, заради якого сторожа й написана, мусить бути відтворений — інакше
    // перелік винятків нічого не стереже.
    ExpectTrue(seen_violations.count("ltv.valid") == 1,
               "ADR-028: the known ltv.valid contradiction must be reproducible by construction");

    for (const std::string& violation : seen_violations) {
        if (allowed.count(violation) == 1) {
            continue;
        }
        const std::string message =
            "ADR-028: field \"" + violation +
            "\" is true while its block status is not \"valid\"; name it for what was established, "
            "or record it in tests/report_schema_exceptions.baseline with the version that removes it";
        ExpectTrue(false, message.c_str());
    }
}
