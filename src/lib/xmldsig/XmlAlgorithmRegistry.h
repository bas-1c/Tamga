#pragma once

#include <optional>
#include <string>

#include "core/policy/ImprintDigest.h"

// WP-0 (заморожений контракт) — для WP-6/WP-9.
//
// Єдиний реєстр канонічних DigestMethod/SignatureMethod URI та OID для
// українських DSTU 4145 / GOST 34.311 / Kupyna і стандартних W3C-алгоритмів.
// Замінює loose `contains("dstu")`-евристику (XmlDigestEngine TODO phase 3):
// НЕВІДОМИЙ URI/OID -> std::nullopt (жодного fallback-«вгадування»).
//
// Реалізація (whitelist + режими strict/ukraine-legal/compatibility) — WP-9.

namespace tamga::xmldsig {

// Хвіст URI після останнього `#`, `/` або `:`.
std::string UriTail(const std::string& uri);

enum class DigestAlg {
    Sha256,
    Sha384,
    Sha512,
    Gost34311,
    Kupyna256,
};

enum class SignatureAlg {
    RsaSha256,
    EcdsaSha256,
    Dstu4145WithGost34311,
    Dstu4145WithKupyna,
    // С-07: додано, бо продакшн-рушій ці URI підтримував, а реєстр — ні.
    // Саме через таку неповноту реєстр і не можна було просто підключити
    // замість loose-евристики: переведення на нього обірвало б перевірку
    // реального TL ЦЗО, підписаного rsa-sha384/512. Перелік append-only.
    RsaSha384,
    RsaSha512,
    EcdsaSha384,
    EcdsaSha512,
};

struct AlgorithmRegistry {
    // XMLDSIG/XAdES DigestMethod URI -> алгоритм. Невідомий -> nullopt.
    static std::optional<DigestAlg> MapDigestUri(const std::string& uri);

    // XMLDSIG/XAdES SignatureMethod URI -> алгоритм. Невідомий -> nullopt.
    static std::optional<SignatureAlg> MapSignatureUri(const std::string& uri);

    // OID (digest або signature) -> digest-алгоритм. Невідомий -> nullopt.
    static std::optional<DigestAlg> MapOid(const std::string& oid);

    // Місток до проєктного імпринту (Kupyna/GOST/SHA).
    static std::optional<tamga::core::ImprintDigest> ToImprint(DigestAlg alg);

    // С-07: дайджест, який задає САМ URI підпису. Потрібен рушію: для
    // rsa-sha384 дайджест визначає підписний URI, а не сертифікат.
    static std::optional<tamga::core::ImprintDigest> ToImprint(SignatureAlg alg);
};

}  // namespace tamga::xmldsig
