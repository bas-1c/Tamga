#include "xmldsig/XmlAlgorithmRegistry.h"

#include <string>
#include <unordered_map>

// WP-9: канонічний реєстр підтримуваних DigestMethod/SignatureMethod URI та OID
// для українських DSTU 4145 / ГОСТ 34.311 / Kupyna і стандартних W3C-алгоритмів.
// Явний whitelist замість loose contains("dstu"): НЕВІДОМИЙ вхід -> std::nullopt
// (жодного fallback-«вгадування»).

namespace tamga::xmldsig {

// ADR-027: `UriTail` живе тут, а не в `XmlHelpers`, бо цей модуль збирається
// БЕЗУМОВНО (pure-logic реєстр алгоритмів), а `XmlHelpers` тягне libxml2.
// Копія в `XmlDigestEngine` прибрана — тіла збігалися.
std::string UriTail(const std::string& uri) {
    const auto pos = uri.find_last_of("#/:");
    return pos == std::string::npos ? uri : uri.substr(pos + 1);
}

namespace {

// Хвіст URI після останнього '#','/',':' — саме там стоїть ім'я алгоритму.

std::string ToLower(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return value;
}

}  // namespace

std::optional<DigestAlg> AlgorithmRegistry::MapDigestUri(const std::string& uri) {
    static const std::unordered_map<std::string, DigestAlg> kByTail = {
        {"sha256", DigestAlg::Sha256},
        {"sha384", DigestAlg::Sha384},
        {"sha512", DigestAlg::Sha512},
        {"gost34311", DigestAlg::Gost34311},
        {"kupyna256", DigestAlg::Kupyna256},
        {"kupyna-256", DigestAlg::Kupyna256},
        {"dstu7564-256", DigestAlg::Kupyna256},  // DSTU 7564 = Kupyna
    };
    const auto it = kByTail.find(ToLower(UriTail(uri)));
    return it == kByTail.end() ? std::nullopt : std::optional<DigestAlg>(it->second);
}

std::optional<SignatureAlg> AlgorithmRegistry::MapSignatureUri(const std::string& uri) {
    const std::string tail = ToLower(UriTail(uri));
    if (tail == "rsa-sha256") return SignatureAlg::RsaSha256;
    if (tail == "rsa-sha384") return SignatureAlg::RsaSha384;
    if (tail == "rsa-sha512") return SignatureAlg::RsaSha512;
    if (tail == "ecdsa-sha256") return SignatureAlg::EcdsaSha256;
    if (tail == "ecdsa-sha384") return SignatureAlg::EcdsaSha384;
    if (tail == "ecdsa-sha512") return SignatureAlg::EcdsaSha512;
    // С-07: ДСТУ 4145 розпізнається ТОЧНИМ переліком хвостів, а не
    // `tail.find("dstu4145")`. Підрядковий варіант приймав, наприклад,
    // `http://example.com/mydstu4145Thing` — тобто whitelist, заявлений як
    // «жодного вгадування», сам вгадував.
    //
    // Перелік звірений із реальними контейнерами Дії у фікстурах:
    //   dstu4145-dstu7564-256  (diia-asice-kupyna-2docs)
    //   dstu4145-gost34311     (diia-asice-gost-3docs)
    // Решта — написання, що трапляються в українських реалізаціях і вже
    // згадані в коді. Новий варіант треба ДОДАВАТИ сюди свідомо, а не
    // покладатися на те, що підрядок випадково збіжиться.
    static const std::unordered_map<std::string, SignatureAlg> kDstuByTail = {
        {"dstu4145-dstu7564-256", SignatureAlg::Dstu4145WithKupyna},
        {"dstu4145-kupyna", SignatureAlg::Dstu4145WithKupyna},
        {"dstu4145-kupyna256", SignatureAlg::Dstu4145WithKupyna},
        {"dstu4145-kupyna-256", SignatureAlg::Dstu4145WithKupyna},
        {"dstu4145-gost34311", SignatureAlg::Dstu4145WithGost34311},
        {"dstu4145", SignatureAlg::Dstu4145WithGost34311},
    };
    const auto dstu = kDstuByTail.find(tail);
    if (dstu != kDstuByTail.end()) {
        return dstu->second;
    }
    return std::nullopt;
}

std::optional<DigestAlg> AlgorithmRegistry::MapOid(const std::string& oid) {
    static const std::unordered_map<std::string, DigestAlg> kByOid = {
        {"2.16.840.1.101.3.4.2.1", DigestAlg::Sha256},
        {"2.16.840.1.101.3.4.2.2", DigestAlg::Sha384},
        {"2.16.840.1.101.3.4.2.3", DigestAlg::Sha512},
        {"1.2.804.2.1.1.1.1.2.1", DigestAlg::Gost34311},
        {"1.2.804.2.1.1.1.1.2.2.1", DigestAlg::Kupyna256},
    };
    const auto it = kByOid.find(oid);
    return it == kByOid.end() ? std::nullopt : std::optional<DigestAlg>(it->second);
}

std::optional<tamga::core::ImprintDigest> AlgorithmRegistry::ToImprint(DigestAlg alg) {
    switch (alg) {
        case DigestAlg::Sha256: return tamga::core::ImprintDigest::Sha256;
        case DigestAlg::Sha384: return tamga::core::ImprintDigest::Sha384;
        case DigestAlg::Sha512: return tamga::core::ImprintDigest::Sha512;
        case DigestAlg::Gost34311: return tamga::core::ImprintDigest::Gost34311;
        case DigestAlg::Kupyna256: return tamga::core::ImprintDigest::Kupyna256;
    }
    return std::nullopt;
}

// С-07: дайджест задає сам URI підпису — для rsa-sha384 його визначає підписний
// URI, а не сертифікат підписанта.
std::optional<tamga::core::ImprintDigest> AlgorithmRegistry::ToImprint(SignatureAlg alg) {
    switch (alg) {
        case SignatureAlg::RsaSha256:
        case SignatureAlg::EcdsaSha256:
            return tamga::core::ImprintDigest::Sha256;
        case SignatureAlg::RsaSha384:
        case SignatureAlg::EcdsaSha384:
            return tamga::core::ImprintDigest::Sha384;
        case SignatureAlg::RsaSha512:
        case SignatureAlg::EcdsaSha512:
            return tamga::core::ImprintDigest::Sha512;
        case SignatureAlg::Dstu4145WithGost34311:
            return tamga::core::ImprintDigest::Gost34311;
        case SignatureAlg::Dstu4145WithKupyna:
            return tamga::core::ImprintDigest::Kupyna256;
    }
    return std::nullopt;
}

}  // namespace tamga::xmldsig
