// WP-9: canonical UA DSTU/GOST/Kupyna algorithm registry (plan section 6, #8).
// Known URIs/OIDs map deterministically; unknown ones are rejected (no guessing).
// Pure logic — no libxml2/cryptonite needed.

#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>

#include "xmldsig/XmlAlgorithmRegistry.h"
#include "xmldsig/XmlDigestEngine.h"

namespace {

int g_failures = 0;

void Check(bool ok, const std::string& msg) {
    if (!ok) {
        std::cerr << "FAILED: " << msg << '\n';
        ++g_failures;
    }
}

}  // namespace

int main() {
    using tamga::xmldsig::AlgorithmRegistry;
    using tamga::xmldsig::DigestAlg;
    using tamga::xmldsig::SignatureAlg;

    // Digest URIs (including the Diia gost34311 digest and canonical Kupyna).
    Check(AlgorithmRegistry::MapDigestUri("http://www.w3.org/2001/04/xmlenc#gost34311") == DigestAlg::Gost34311,
          "gost34311 digest URI maps");
    Check(AlgorithmRegistry::MapDigestUri("http://www.w3.org/2001/04/xmlenc#sha256") == DigestAlg::Sha256,
          "sha256 digest URI maps");
    Check(AlgorithmRegistry::MapDigestUri("http://www.w3.org/2001/04/xmldsig-more#kupyna256") == DigestAlg::Kupyna256,
          "kupyna256 digest URI maps");
    Check(AlgorithmRegistry::MapDigestUri("http://example.com/unknown-digest") == std::nullopt,
          "unknown digest URI is rejected");
    Check(AlgorithmRegistry::MapDigestUri("http://www.w3.org/2000/09/xmldsig#sha1") == std::nullopt,
          "sha1 is not supported");

    // Signature URIs (Diia dstu4145-gost34311 must map).
    Check(AlgorithmRegistry::MapSignatureUri("http://www.w3.org/2001/04/xmldsig-more#dstu4145-gost34311") ==
              SignatureAlg::Dstu4145WithGost34311,
          "dstu4145-gost34311 signature URI maps (Diia)");
    Check(AlgorithmRegistry::MapSignatureUri("http://www.w3.org/2001/04/xmldsig-more#dstu4145-kupyna256") ==
              SignatureAlg::Dstu4145WithKupyna,
          "dstu4145-kupyna signature URI maps");
    Check(AlgorithmRegistry::MapSignatureUri("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") ==
              SignatureAlg::RsaSha256,
          "rsa-sha256 signature URI maps");
    Check(AlgorithmRegistry::MapSignatureUri("http://example.com/unknown-sig") == std::nullopt,
          "unknown signature URI is rejected");
    // A stray substring 'dstu' that is not dstu4145 must NOT be guessed.
    Check(AlgorithmRegistry::MapSignatureUri("http://example.com/mydstuThing") == std::nullopt,
          "loose 'dstu' substring is not accepted");

    // OIDs.
    Check(AlgorithmRegistry::MapOid("1.2.804.2.1.1.1.1.2.1") == DigestAlg::Gost34311, "gost34311 OID maps");
    Check(AlgorithmRegistry::MapOid("1.2.804.2.1.1.1.1.2.2.1") == DigestAlg::Kupyna256, "kupyna256 OID maps");
    Check(AlgorithmRegistry::MapOid("9.9.9") == std::nullopt, "unknown OID is rejected");

    // ToImprint bridge.
    Check(AlgorithmRegistry::ToImprint(DigestAlg::Kupyna256) == tamga::core::ImprintDigest::Kupyna256,
          "Kupyna256 maps to ImprintDigest");
    // С-07: дайджест задає сам URI підпису — потрібно рушію для rsa-sha384/512.
    Check(AlgorithmRegistry::ToImprint(SignatureAlg::RsaSha384) == tamga::core::ImprintDigest::Sha384,
          "rsa-sha384 signature URI implies SHA-384 imprint");
    Check(AlgorithmRegistry::MapSignatureUri("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") ==
              SignatureAlg::RsaSha512,
          "rsa-sha512 signature URI maps");

    // С-07: НАЙВАЖЛИВІШЕ — реєстр тепер справді використовується продакшн-
    // рушієм. Доти XmlSignatureVerifier лише включав його заголовок, а
    // розпізнавав алгоритми підрядками, тож ці твердження доводили властивість,
    // якої продукт не мав. Перевіряємо саме XmlDigestEngine, а не реєстр.
    Check(tamga::xmldsig::XmlDigestEngine::MapSignatureMethodUri(
              "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") ==
              tamga::core::ImprintDigest::Sha256,
          "engine maps a canonical rsa-sha256 URI");
    Check(tamga::xmldsig::XmlDigestEngine::MapSignatureMethodUri("urn:evil:kupyna:garbage") == std::nullopt,
          "engine must not accept an attacker-shaped URI containing 'kupyna'");
    Check(tamga::xmldsig::XmlDigestEngine::MapSignatureMethodUri("http://example.com/mydstu4145Thing") == std::nullopt,
          "engine must not accept a stray 'dstu4145' substring");
    Check(tamga::xmldsig::XmlDigestEngine::MapSignatureMethodUri("http://example.com/rsa-sha256-not-really") ==
              std::nullopt,
          "engine must not accept a URI whose tail merely contains a known name");

    if (g_failures == 0) {
        std::cout << "XmlAlgorithmRegistry: all mappings correct.\n";
        return EXIT_SUCCESS;
    }
    std::cout << g_failures << " registry mapping(s) failed.\n";
    return EXIT_FAILURE;
}
