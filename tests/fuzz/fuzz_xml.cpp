// Fuzz-ціль: XMLDSIG/XAdES і довірчий список.
//
// Поверхня: libxml2 плюс власний рушій (ADR 014). Класи дефектів, за якими
// сюди й ходять, — XXE, entity-expansion, signature wrapping; проти двох
// останніх у сюїті вже є цілеспрямовані тести, і ця ціль їх не замінює, а
// доповнює довільними входами.

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "core/CryptoniteAdapter.h"
#include "core/policy/TrustListParser.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xmldsig/XmlTransformEngine.h"

namespace {

// XML-входи мають бути малими: expansion-атаки цікаві саме тим, що дають
// величезний вихід із крихітного входу, тож великий вхід нічого не додає.
constexpr std::size_t kMaxInput = 1u * 1024u * 1024u;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > kMaxInput) {
        return 0;
    }
    const std::string xml(reinterpret_cast<const char*>(data), size);

    {
        tamga::core::policy::TrustListParser parser;
        (void)parser.Parse(xml);
    }

    {
        tamga::xmldsig::XmlCanonicalizer canonicalizer;
        tamga::xmldsig::XmlTransformEngine transform_engine;
        tamga::xmldsig::XmlDigestEngine digest_engine;
        tamga::core::CryptoniteAdapter crypto;
        tamga::xmldsig::XmlSignatureVerifier verifier(canonicalizer, transform_engine,
                                                      digest_engine, crypto);

        const std::map<std::string, std::vector<std::uint8_t>> external_references;

        tamga::xmldsig::XmlSignatureVerificationResult result;
        std::string error;
        (void)verifier.Verify(xml, external_references, result, error);

        // VerifyAll — окремий шлях (WP-2, кілька ds:Signature в документі),
        // і саме він містить захист від wrapping, тож перевіряється теж.
        std::vector<tamga::xmldsig::XmlSignatureVerificationResult> results;
        std::string all_error;
        (void)verifier.VerifyAll(xml, external_references, results, all_error);
    }

    return 0;
}
