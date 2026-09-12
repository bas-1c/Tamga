#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/policy/ImprintDigest.h"

namespace tamga::xmldsig {

// Обчислює дайджест над канонікалізованими даними XMLDSIG/XAdES, делегуючи саме
// хешування до проєктної точки tamga::core::ComputeImprint (Kupyna/GOST/SHA),
// яка під капотом використовує cryptonite. Engine лише зіставляє XMLDSIG
// digest-URI з алгоритмом імпринту — власної криптографії не містить (ADR 012).
class XmlDigestEngine {
public:
    XmlDigestEngine() = default;

    // Обчислює дайджест для data за XMLDSIG/XAdES DigestMethod URI.
    // Повертає false і заповнює error_message, якщо URI невідомий або алгоритм
    // недоступний у поточній збірці (наприклад, cryptonite вимкнено).
    bool ComputeDigest(const std::vector<std::uint8_t>& data,
                       const std::string& algo_uri,
                       std::vector<std::uint8_t>& digest_out,
                       std::string& error_message);

    // Для ДСТУ/GOST/Kupyna DigestMethod, якщо XMLDSig містить embedded
    // X509Certificate, рахує digest через cryptonite adapter, ініціалізований
    // з цього сертифіката. SHA-алгоритми та випадки без сертифіката ідуть
    // звичайним ComputeDigest шляхом.
    bool ComputeDigestByCertificate(const std::vector<std::uint8_t>& data,
                                    const std::string& algo_uri,
                                    const std::vector<std::uint8_t>& certificate_der,
                                    std::vector<std::uint8_t>& digest_out,
                                    std::string& error_message);

    // Зіставляє XMLDSIG/XAdES DigestMethod URI з алгоритмом імпринту проєкту.
    // Невідомий URI -> std::nullopt. Підтримує як канонічні W3C-URI, так і
    // запасний шлях через tamga::core::ImprintFromDigestOid (приймає bare-імена
    // та OID-и: sha256, kupyna256, gost34311, 2.16.840.1.101.3.4.2.1 тощо).
    static std::optional<tamga::core::ImprintDigest> MapDigestUri(const std::string& algo_uri);

    // Зіставляє XMLDSIG/XAdES SignatureMethod URI з алгоритмом гешу, яким
    // обчислюється імпринт SignedInfo. Для ДСТУ URI -> ГОСТ 34.311; Купина для
    // kupyna-URI; інакше — запасний шлях через MapDigestUri. Невідомий ->
    // std::nullopt.
    static std::optional<tamga::core::ImprintDigest> MapSignatureMethodUri(const std::string& algo_uri);
};

}  // namespace tamga::xmldsig
