#include "core/policy/UserReportBuilder.h"

#include <iostream>
#include <string>

namespace {

const char* kKalyna = "\xD0\x9A\xD0\xB0\xD0\xBB\xD0\xB8\xD0\xBD\xD0\xB0";
const char* kQualified = "\xD0\x9A\xD0\xB2\xD0\xB0\xD0\xBB\xD1\x96\xD1\x84\xD1\x96\xD0\xBA\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB9";
const char* kOleksandr = "\xD0\x9E\xD0\xBB\xD0\xB5\xD0\xBA\xD1\x81\xD0\xB0\xD0\xBD\xD0\xB4\xD1\x80";
const char* kKyiv = "\xD0\x9A\xD0\xB8\xD1\x97\xD0\xB2";
const char* kUkMessage = "\xD0\x9A\xD1\x80\xD0\xB8\xD0\xBF\xD1\x82\xD0\xBE\xD0\xB3\xD1\x80\xD0\xB0\xD1\x84\xD1\x96\xD1\x87\xD0\xBD\xD1\x83 \xD1\x86\xD1\x96\xD0\xBB\xD1\x96\xD1\x81\xD0\xBD\xD1\x96\xD1\x81\xD1\x82\xD1\x8C \xD0\xBF\xD1\x96\xD0\xB4\xD0\xBF\xD0\xB8\xD1\x81\xD1\x83 \xD0\xBF\xD1\x96\xD0\xB4\xD1\x82\xD0\xB2\xD0\xB5\xD1\x80\xD0\xB4\xD0\xB6\xD0\xB5\xD0\xBD\xD0\xBE.";

bool Contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

} // namespace

int main() {
    tamga::core::VerifyReport report;
    report.has_result = true;
    report.execution_succeeded = true;
    report.signature_valid = true;
    report.trust_checked = true;
    report.trust_valid = true;
    report.revocation_checked = true;
    report.revocation_status = "valid";
    report.tsp_checked = true;
    report.timestamp_checked = true;
    report.timestamp_valid = true;
    report.chain_checked = true;
    report.chain_valid = true;
    report.signer_certificate_present = true;
    report.certificate_time_valid = true;
    report.container_type = "ASiC-E";
    report.signature_format = "XAdES";
    report.format_profile = "XAdES-B-LT";
    report.operation = "VerifyFileAsicEXades";
    report.policy = "xades-format";
    report.trust_status = "trusted-anchor-validated";
    report.trust_mode = "historical";
    report.historical_trust_used = true;
    report.trust_list_source = std::string("https://example.test/") + kKyiv + "/TL-UA-EC.xml";
    report.chain_debug = std::string("subject=") + kOleksandr + "; issuer=" + kQualified;

    tamga::core::policy::UserReportInput input;
    input.verify_report = report;
    input.container_type = "ASiC-E";
    input.signature_format = "XAdES";
    input.signer_metadata.common_name = kOleksandr;
    input.signer_metadata.organization = kKalyna;
    input.signer_metadata.country = "UA";
    input.signer_metadata.issuer = std::string("CN=") + kQualified + ",L=" + kKyiv + ",C=UA";
    input.signer_metadata.serial_number_hex = "010203";

    const std::string json = tamga::core::policy::UserReportBuilder{}.Build(input);
    if (json.empty() || !Contains(json, "\"schemaVersion\":\"2.2\"")) {
        std::cerr << "schema v2 Unicode report was not produced: " << json << '\n';
        return 1;
    }
    if (Contains(json, "\"verificationResult\"") || Contains(json, "\"version\":1")) {
        std::cerr << "schema v2 user report still contains legacy root fields: " << json << '\n';
        return 1;
    }
    if (Contains(json, "not-executed")) {
        std::cerr << "successful Unicode report was overwritten by fallback: " << json << '\n';
        return 1;
    }
    for (const std::string& needle : {std::string(kKalyna), std::string(kQualified), std::string(kOleksandr), std::string(kKyiv), std::string(kUkMessage), std::string("Signature is cryptographically valid.")}) {
        if (!Contains(json, needle)) {
            std::cerr << "Unicode report lost value: " << needle << "\nJSON: " << json << '\n';
            return 1;
        }
    }
    return 0;
}
