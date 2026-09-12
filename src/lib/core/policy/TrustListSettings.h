#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::core {

struct TrustListSettings {
    std::string url{"https://czo.gov.ua/download/tl/TL-UA-EC.xml"};
    std::int32_t timeout_ms{30000};
    std::int32_t cache_ttl_hours{24};
    bool allow_https_bootstrap{true};
    bool fail_if_cache_stale{false};
    // S-002 / B-3: TL XML signature verification policy (ETSI TS 119 612 §5.7).
    //
    // Replaces the former `bool verify_xml_signature{false}`. The bool had two
    // problems: (1) it defaulted to "do not verify", so the trust anchor of the
    // whole system rested on TLS alone; (2) when verification was requested in a
    // build without the XMLDSIG engine, `VerifyTlXmlSignature` answered
    // `not_supported` and the sync path *silently* treated that as success — a
    // fail-open path in which the caller could not distinguish "signature
    // verified" from "signature never checked".
    //
    // Deliberately NOT a compile-time-conditional default: TAMGA_XML_SIGNATURES_ENABLED
    // is a PRIVATE compile definition of the core targets, so making the default
    // depend on it would give this struct a different default initialiser inside
    // the library than in the NativeAPI/CLI translation units — an ODR hazard.
    // The engine-availability decision therefore lives in TrustListSync.cpp, which
    // is a single TU that does see the macro.
    //
    // If xml_signer_cert_der is non-empty, the certificate in ds:KeyInfo must match
    // it exactly (pinned-cert check) BEFORE the cryptographic verification runs.
    // When it is empty only mathematical self-consistency against the certificate
    // embedded in the very same XML is proven — that is NOT proof of origin and
    // does not stop substitution of the whole document. The sync result then
    // reports `verified-self-consistent`, never `verified-pinned`. Configure a
    // pinned CZO certificate to obtain a real trust anchor.
    enum class XmlSignaturePolicy {
        // Never verify. Sync reports `not-verified-disabled`.
        Disabled,
        // Verify whenever this build has the XMLDSIG engine; a verification failure is
        // fail-closed. If the engine is absent the sync still proceeds but reports
        // `not-verified-unsupported`, so the gap is explicit rather than silent.
        //
        // This IS the default now, and the reason is measured rather than assumed.
        // The real `https://czo.gov.ua/download/tl/TL-UA-EC.xml` is signed with
        // `xmldsig-more#rsa-sha256`. That used to be rejected outright, because
        // the PKIX verify adapter did not recognize RSA. Since ADR-015 (Windows CNG)
        // and ADR-022 (cryptonite PKIX VerifyAdapter), the verifier has full cross-platform
        // RSA-PKCS1 support (`core/RsaVerifier.h`), and
        // `tamga-interop-diag tl-sig tests/TL-UA-EC.xml` — a genuine CZO list —
        // reports VERIFIED.
        PreferAvailable,
        // Verification is mandatory: a failure OR a build without the engine both
        // abort the sync. Use this when the trust list must never be accepted unverified.
        Require,
    };
    // Дефолт `PreferAvailable` — підпис довірчого списку перевіряється завжди, коли
    // збірка має XMLDSIG-рушій. Раніше тут стояв `Disabled`, і причина була вимірена:
    // справжній TL ЦЗО підписаний RSA-SHA256. Після ADR-015 (Windows CNG) та ADR-022
    // (PKIX VerifyAdapter у cryptonite) це обмеження знято — перевірено на реальному
    // `tests/TL-UA-EC.xml` на Windows та Linux.
    //
    // `Require` свідомо НЕ дефолт: він обриває синхронізацію і в збірці без
    // XMLDSIG-рушія, тобто змінює поведінку залежно від опцій компіляції.
    //
    // Решта B-3 лишається в силі: перевірка, яку неможливо виконати, НЕ вважається
    // успішною (fail-open усунуто), а `TrustListSyncResult::xml_signature_status`
    // завжди явно каже, чи підпис перевірено і з якою силою — самоузгодженість
    // (`verified-self-consistent`) не є доказом походження, на відміну від
    // `verified-pinned` із закріпленим сертифікатом ЦЗО.
    XmlSignaturePolicy xml_signature_policy{XmlSignaturePolicy::PreferAvailable};
    std::vector<std::uint8_t> xml_signer_cert_der;
};

} // namespace tamga::core
