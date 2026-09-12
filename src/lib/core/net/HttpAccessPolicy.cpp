// Реалізація політики мережевого доступу. Код перенесено з анонімного
// простору імен `HttpClient.cpp` ДОСЛІВНО: рефакторинг, який дорогою міняє
// поведінку захисту від SSRF, — найгірший різновид рефакторингу, бо різницю
// нікому не видно. Змінилося рівно одне: резолвер більше не береться з
// глобальної змінної, а приходить параметром.

#include "core/net/HttpAccessPolicy.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <string>
#include <vector>

namespace tamga::core::net {

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

DestinationUrl ParseDestinationUrl(const std::string& url) {
    DestinationUrl parsed;
    if (url.empty() || url.find_first_of("\r\n\t ") != std::string::npos) {
        return parsed;
    }
    const auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        return parsed;
    }
    parsed.scheme = LowerAscii(url.substr(0, scheme_end));
    if (parsed.scheme != "http" && parsed.scheme != "https") {
        return parsed;
    }
    const auto authority_begin = scheme_end + 3U;
    const auto authority_end = url.find_first_of("/?#", authority_begin);
    const std::string authority = url.substr(
        authority_begin,
        authority_end == std::string::npos ? std::string::npos : authority_end - authority_begin);
    if (authority.empty() || authority.find('@') != std::string::npos ||
        authority.find('\\') != std::string::npos || authority.find('%') != std::string::npos) {
        return parsed;
    }

    std::string port;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string::npos || close == 1U) {
            return parsed;
        }
        parsed.host = authority.substr(1U, close - 1U);
        if (close + 1U < authority.size()) {
            if (authority[close + 1U] != ':') {
                return DestinationUrl{};
            }
            port = authority.substr(close + 2U);
            if (port.empty()) return DestinationUrl{};
        }
    } else {
        const auto colon = authority.rfind(':');
        if (colon != std::string::npos) {
            if (authority.find(':') != colon) {
                return DestinationUrl{};  // IPv6 literals must use brackets.
            }
            if (colon + 1U == authority.size()) {
                return DestinationUrl{};
            }
            parsed.host = authority.substr(0U, colon);
            port = authority.substr(colon + 1U);
        } else {
            parsed.host = authority;
        }
    }
    if (parsed.host.empty()) {
        return DestinationUrl{};
    }
    if (!port.empty()) {
        if (!std::all_of(port.begin(), port.end(), [](const unsigned char ch) { return std::isdigit(ch) != 0; })) {
            return DestinationUrl{};
        }
        errno = 0;
        char* end = nullptr;
        const unsigned long value = std::strtoul(port.c_str(), &end, 10);
        if (errno != 0 || end == nullptr || *end != '\0' || value == 0UL || value > 65535UL) {
            return DestinationUrl{};
        }
    }
    parsed.host = LowerAscii(parsed.host);
    if (!parsed.host.empty() && parsed.host.back() == '.') {
        parsed.host.pop_back();
    }
    parsed.valid = !parsed.host.empty();
    return parsed;
}

namespace {

bool IsBlockedIpv4(const std::uint32_t address) {
    const auto first = static_cast<std::uint8_t>(address >> 24U);
    const auto second = static_cast<std::uint8_t>(address >> 16U);
    const auto third = static_cast<std::uint8_t>(address >> 8U);
    if (first == 0U || first == 10U || first == 127U || first >= 224U) return true;
    if (first == 100U && second >= 64U && second <= 127U) return true;  // carrier-grade NAT
    if (first == 169U && second == 254U) return true;                   // link-local / metadata
    if (first == 172U && second >= 16U && second <= 31U) return true;
    if (first == 192U && second == 168U) return true;
    if (first == 192U && second == 0U && (third == 0U || third == 2U)) return true;
    if (first == 198U && (second == 18U || second == 19U)) return true;
    if (first == 198U && second == 51U && third == 100U) return true;
    if (first == 203U && second == 0U && third == 113U) return true;
    return false;
}

// Чотири байти в тому самому порядку, у якому їх чекає `IsBlockedIpv4`.
// Виділено, бо вкладена IPv4-адреса трапляється в IPv6 у чотирьох різних
// місцях (mapped, NAT64, 6to4), і кожне переписування цього зсуву — шанс
// помилитися на один байт.
std::uint32_t Ipv4FromBytes(const std::uint8_t* bytes) {
    return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
           (static_cast<std::uint32_t>(bytes[1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[2]) << 8U) |
           static_cast<std::uint32_t>(bytes[3]);
}

bool ParseLegacyIpv4(const std::string& text, std::uint32_t& out) {
    if (text.empty() || text.front() == '+' || text.front() == '-') return false;
    std::array<unsigned long long, 4> parts{};
    std::size_t count = 0;
    std::size_t begin = 0;
    while (begin <= text.size() && count < parts.size()) {
        const auto end_pos = text.find('.', begin);
        const std::string part = text.substr(begin, end_pos == std::string::npos ? std::string::npos : end_pos - begin);
        if (part.empty()) return false;
        errno = 0;
        char* end = nullptr;
        const unsigned long long value = std::strtoull(part.c_str(), &end, 0);
        if (errno != 0 || end == nullptr || *end != '\0') return false;
        parts[count++] = value;
        if (end_pos == std::string::npos) break;
        if (count == parts.size()) return false;
        begin = end_pos + 1U;
    }
    if (count == 0U || (begin <= text.size() && text.find('.', begin) != std::string::npos) || count > 4U) return false;
    std::uint64_t value = 0;
    switch (count) {
        case 1: if (parts[0] > 0xffffffffULL) return false; value = parts[0]; break;
        case 2: if (parts[0] > 0xffULL || parts[1] > 0xffffffULL) return false;
                value = (parts[0] << 24U) | parts[1]; break;
        case 3: if (parts[0] > 0xffULL || parts[1] > 0xffULL || parts[2] > 0xffffULL) return false;
                value = (parts[0] << 24U) | (parts[1] << 16U) | parts[2]; break;
        case 4: if (parts[0] > 0xffULL || parts[1] > 0xffULL || parts[2] > 0xffULL || parts[3] > 0xffULL) return false;
                value = (parts[0] << 24U) | (parts[1] << 16U) | (parts[2] << 8U) | parts[3]; break;
        default: return false;
    }
    out = static_cast<std::uint32_t>(value);
    return true;
}

}  // namespace

IpClassification ClassifyIpAddress(const std::string& text) {
    in_addr v4{};
    if (inet_pton(AF_INET, text.c_str(), &v4) == 1) {
        return IsBlockedIpv4(ntohl(v4.s_addr)) ? IpClassification::Blocked : IpClassification::Public;
    }
    std::uint32_t legacy_v4 = 0;
    if (ParseLegacyIpv4(text, legacy_v4)) {
        return IsBlockedIpv4(legacy_v4) ? IpClassification::Blocked : IpClassification::Public;
    }

    in6_addr v6{};
    if (inet_pton(AF_INET6, text.c_str(), &v6) != 1) {
        return IpClassification::NotAnIp;
    }
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&v6);
    const bool unspecified = std::all_of(bytes, bytes + 16, [](const std::uint8_t b) { return b == 0U; });
    if (unspecified) return IpClassification::Blocked;
    bool loopback = true;
    for (int i = 0; i < 15; ++i) loopback = loopback && bytes[i] == 0U;
    if (loopback && bytes[15] == 1U) return IpClassification::Blocked;
    const bool mapped_v4 = std::all_of(bytes, bytes + 10, [](const std::uint8_t b) { return b == 0U; }) &&
                           bytes[10] == 0xffU && bytes[11] == 0xffU;
    // `::ffff:0:0/96` — IPv4-mapped. Вкладена адреса судиться як IPv4:
    // `::ffff:127.0.0.1` — це 127.0.0.1, і нічого більше.
    if (mapped_v4) {
        return IsBlockedIpv4(Ipv4FromBytes(bytes + 12)) ? IpClassification::Blocked
                                                        : IpClassification::Public;
    }

    // `64:ff9b::/96` — well-known prefix NAT64 (RFC 6052): останні 32 біти є
    // справжньою IPv4-адресою призначення, тож судити треба саме її
    // (`64:ff9b::7f00:1` — це 127.0.0.1). Блокувати діапазон цілком не можна:
    // у мережі з DNS64/NAT64 це єдина форма, у якій IPv6-only клієнт бачить
    // публічний IPv4-сервіс ЦСК. Решта `64:ff9b::/32` — зокрема local-use
    // `64:ff9b:1::/48` (RFC 8215), де довжина префікса довільна, — лишається
    // заблокованою: позиція вкладеної IPv4 там не визначена однозначно, а
    // здогадка про неї була б гіршою за відмову.
    if (bytes[0] == 0x00U && bytes[1] == 0x64U && bytes[2] == 0xffU && bytes[3] == 0x9bU) {
        const bool well_known =
            std::all_of(bytes + 4, bytes + 12, [](const std::uint8_t b) { return b == 0U; });
        if (!well_known) return IpClassification::Blocked;
        return IsBlockedIpv4(Ipv4FromBytes(bytes + 12)) ? IpClassification::Blocked
                                                        : IpClassification::Public;
    }

    if ((bytes[0] & 0xfeU) == 0xfcU ||                            // unique-local fc00::/7
        (bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0x80U) ||     // link-local fe80::/10
        bytes[0] == 0xffU ||                                      // multicast ff00::/8
        // `2001::/23` — IETF Protocol Assignments із реєстру IANA
        // special-purpose: Teredo `2001::/32`, benchmarking `2001:2::/48`,
        // AMT `2001:3::/32`, ORCHIDv2 `2001:20::/28`. Teredo блокується цілим
        // діапазоном, а не за вкладеною IPv4, і це свідоме рішення: у
        // Teredo-адресі вкладених адрес ДВІ — сервера (біти 32-63) і клієнта
        // (біти 96-127, збережена інвертованою), — і жодна з них не є адресою
        // сервісу, до якого ми звертаємось. Розбирати одну з них означало б
        // видати часткову перевірку за повну.
        (bytes[0] == 0x20U && bytes[1] == 0x01U && (bytes[2] & 0xfeU) == 0x00U) ||
        // документаційні діапазони: `2001:db8::/32` і `3fff::/20` (RFC 9637)
        (bytes[0] == 0x20U && bytes[1] == 0x01U && bytes[2] == 0x0dU && bytes[3] == 0xb8U) ||
        (bytes[0] == 0x3fU && (bytes[1] & 0xf0U) == 0xf0U) ||
        // `2620:4f:8000::/48` — Direct Delegation AS112 Service (RFC 7534).
        (bytes[0] == 0x26U && bytes[1] == 0x20U && bytes[2] == 0x00U && bytes[3] == 0x4fU &&
         bytes[4] == 0x80U && bytes[5] == 0x00U)) {
        return IpClassification::Blocked;
    }

    // `2002::/16` — 6to4 (RFC 3056): біти 16-47 несуть IPv4-адресу шлюзу, тож
    // `2002:7f00:1::` — це 127.0.0.1, а `2002:5db8:d822::` — 93.184.216.34.
    // Діапазон не блокується цілком навмисно: 6to4 з публічною вкладеною
    // адресою маршрутизується законно, і рішення про нього ухвалює той самий
    // предикат, що й про чисту IPv4-адресу. Одна умова — одне місце.
    if (bytes[0] == 0x20U && bytes[1] == 0x02U) {
        return IsBlockedIpv4(Ipv4FromBytes(bytes + 2)) ? IpClassification::Blocked
                                                       : IpClassification::Public;
    }

    // Лишився глобальний unicast `2000::/3`: спеціальні діапазони всередині
    // нього перелічені вище поіменно, а все поза ним — зокрема deprecated
    // IPv4-compatible `::/96` і SRv6 SIDs `5f00::/16` — fail-closed.
    return (bytes[0] & 0xe0U) == 0x20U ? IpClassification::Public : IpClassification::Blocked;
}

bool IsBlockedHostname(const std::string& host) {
    if (host == "localhost" || host == "metadata" || host == "instance-data" ||
        host == "metadata.google.internal" || host == "metadata.azure.internal") {
        return true;
    }
    const auto has_suffix = [&host](const std::string& suffix) {
        return host.size() >= suffix.size() &&
               host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0;
    };
    return has_suffix(".localhost") || has_suffix(".local") || has_suffix(".internal") ||
           has_suffix(".lan") || has_suffix(".home");
}



HttpDestinationResult CheckDestination(const std::string& url,
                                       const HttpHostResolver& resolver,
                                       const bool treat_missing_resolver_as_allowed) {
    HttpDestinationResult result;
    const DestinationUrl parsed = ParseDestinationUrl(url);
    if (!parsed.valid) {
        result.message = "network destination denied: malformed or unsupported HTTP(S) URL";
        return result;
    }
    if (IsBlockedHostname(parsed.host)) {
        result.message = "network destination denied: local or metadata hostname";
        return result;
    }
    const IpClassification literal = ClassifyIpAddress(parsed.host);
    if (literal == IpClassification::Blocked) {
        result.message = "network destination denied: non-public IP address";
        return result;
    }
    if (literal == IpClassification::Public) {
        result.allowed = true;
        result.resolved_addresses.push_back(parsed.host);
        return result;
    }
    if (!std::all_of(parsed.host.begin(), parsed.host.end(), [](const unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '.' || ch == '-';
        })) {
        result.message = "network destination denied: invalid hostname";
        return result;
    }

    if (treat_missing_resolver_as_allowed && !resolver) {
        result.allowed = true;  // Детерміновані mock-тести не залежать від live DNS.
        return result;
    }
    result.resolved_addresses = resolver ? resolver(parsed.host) : std::vector<std::string>{};
    if (result.resolved_addresses.empty()) {
        result.message = "network destination denied: hostname did not resolve";
        return result;
    }
    for (const auto& address : result.resolved_addresses) {
        // П-08: та сама функція, що вирішує долю фактичної peer-адреси
        // зʼєднання. Дві точки застосування — один предикат.
        if (!tamga::core::detail::IsAllowedPublicAddress(address)) {
            result.allowed = false;
            result.message = "network destination denied: DNS returned a non-public address";
            return result;
        }
    }
    result.allowed = true;
    return result;
}

}  // namespace tamga::core::net

namespace tamga::core::detail {

// Визначення лишається під історичним іменем із `core/HttpClient.h`, але тіло
// живе тут — поруч із класифікатором, який воно і є. Одне визначення на весь
// проєкт: храповик дублювання нічого нового не побачить.
bool IsAllowedPublicAddress(const std::string& peer_address_text) {
    return net::ClassifyIpAddress(peer_address_text) == net::IpClassification::Public;
}

}  // namespace tamga::core::detail
