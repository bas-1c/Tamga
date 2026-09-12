#include "core/KeyParsers.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "util/Base64.h"
#include "util/Der.h"
#include "util/SecureZero.h"
#include "util/Utf.h"

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "byte_array.h"
#include "cryptonite_errors.h"
#include "dstu7564.h"
#include "dstu7624.h"
#include "gost28147.h"
#include "gost34_311.h"
}
#endif

namespace tamga::core {
namespace {

constexpr std::uint32_t kJksMagic = 0xFEEDFEEDU;
constexpr std::uint32_t kJksVersion1 = 1U;
constexpr std::uint32_t kJksVersion2 = 2U;
constexpr std::size_t kJksSaltLength = 20U;
constexpr std::size_t kJksDigestLength = 20U;
constexpr std::array<std::uint8_t, 10> kJksKeyProtectorOid = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x11, 0x01, 0x01,
};
constexpr char kJksWhitener[] = "Mighty Aphrodite";

// Хвиля 8, п.2: парсер DER більше не дублюється тут — єдина реалізація
// живе в `util/Der`. Саме дублювання й породило С-06: guard проти
// переповнення додали в одну копію з чотирьох.
using tamga::util::ParseTlvAt;
using tamga::util::TlvView;

std::uint32_t RotateLeft32Bits(const std::uint32_t value, const unsigned shift) {
    return (value << shift) | (value >> (32U - shift));
}

bool ReadU16(const std::vector<std::uint8_t>& data,
             std::size_t& offset,
             const std::size_t limit,
             std::uint16_t& out) {
    // С-06: без переповнення (див. ReadU32).
    if (offset > limit || limit - offset < 2) {
        return false;
    }

    out = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8U) |
                                     static_cast<std::uint16_t>(data[offset + 1]));
    offset += 2;
    return true;
}

bool ReadU32(const std::vector<std::uint8_t>& data,
             std::size_t& offset,
             const std::size_t limit,
             std::uint32_t& out) {
    // С-06: `offset + 4 > limit` переповнюється при offset біля SIZE_MAX.
    if (offset > limit || limit - offset < 4) {
        return false;
    }

    out = (static_cast<std::uint32_t>(data[offset]) << 24U) |
          (static_cast<std::uint32_t>(data[offset + 1]) << 16U) |
          (static_cast<std::uint32_t>(data[offset + 2]) << 8U) |
          static_cast<std::uint32_t>(data[offset + 3]);
    offset += 4;
    return true;
}

bool ReadU64(const std::vector<std::uint8_t>& data,
             std::size_t& offset,
             const std::size_t limit,
             std::uint64_t& out) {
    // С-06: без переповнення (див. ReadU32).
    if (offset > limit || limit - offset < 8) {
        return false;
    }

    out = 0;
    for (int i = 0; i < 8; ++i) {
        out = (out << 8U) | data[offset + static_cast<std::size_t>(i)];
    }
    offset += 8;
    return true;
}

bool ReadBytes(const std::vector<std::uint8_t>& data,
               std::size_t& offset,
               const std::size_t limit,
               const std::size_t length,
               std::vector<std::uint8_t>& out) {
    // С-06: той самий патерн переповнення, що й у ParseDerLength. Тут наслідок
    // прямий — нижче з offset і length будуються ітератори.
    if (offset > limit || length > limit - offset) {
        return false;
    }

    out.assign(data.begin() + static_cast<std::ptrdiff_t>(offset),
               data.begin() + static_cast<std::ptrdiff_t>(offset + length));
    offset += length;
    return true;
}

// ADR-027: копія прибрана. Вона не відхиляла сурогати, на відміну від
// `util::AppendUtf8CodePoint` — див. пояснення в `util/Utf.h`.
using tamga::util::AppendUtf8CodePoint;

// ADR-027: копія була побайтово тотожна `util::TryEncodeUtf16ToUtf8`.
using tamga::util::TryEncodeUtf16ToUtf8;

bool DecodeJavaModifiedUtf8(const std::uint8_t* data, const std::size_t length, std::u16string& out) {
    out.clear();
    out.reserve(length);

    std::size_t offset = 0;
    while (offset < length) {
        const auto lead = data[offset++];
        if ((lead & 0x80U) == 0) {
            if (lead == 0) {
                return false;
            }
            out.push_back(static_cast<char16_t>(lead));
            continue;
        }

        if ((lead & 0xE0U) == 0xC0U) {
            if (offset >= length) {
                return false;
            }
            const auto trail = data[offset++];
            if ((trail & 0xC0U) != 0x80U) {
                return false;
            }

            const std::uint16_t value =
                static_cast<std::uint16_t>(((lead & 0x1FU) << 6U) | (trail & 0x3FU));
            if (value == 0) {
                out.push_back(0);
                continue;
            }
            if (value < 0x80U) {
                return false;
            }
            out.push_back(static_cast<char16_t>(value));
            continue;
        }

        if ((lead & 0xF0U) == 0xE0U) {
            if (offset + 1 >= length) {
                return false;
            }
            const auto trail1 = data[offset++];
            const auto trail2 = data[offset++];
            if ((trail1 & 0xC0U) != 0x80U || (trail2 & 0xC0U) != 0x80U) {
                return false;
            }

            const std::uint16_t value = static_cast<std::uint16_t>(((lead & 0x0FU) << 12U) |
                                                                   ((trail1 & 0x3FU) << 6U) |
                                                                   (trail2 & 0x3FU));
            if (value < 0x800U) {
                return false;
            }
            out.push_back(static_cast<char16_t>(value));
            continue;
        }

        return false;
    }

    return true;
}

bool ReadModifiedUtf8(const std::vector<std::uint8_t>& data,
                      std::size_t& offset,
                      const std::size_t limit,
                      std::string& out) {
    std::uint16_t length = 0;
    // С-06: без переповнення — offset уже просунувся на 2 байти всередині ReadU16.
    if (!ReadU16(data, offset, limit, length) || offset > limit ||
        static_cast<std::size_t>(length) > limit - offset) {
        return false;
    }

    std::u16string decoded;
    if (!DecodeJavaModifiedUtf8(data.data() + offset, length, decoded) || !TryEncodeUtf16ToUtf8(decoded, out)) {
        return false;
    }
    offset += length;
    return true;
}

bool IsBase64Char(const char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '+' || ch == '/' || ch == '=';
}


std::array<std::uint8_t, 20> Sha1Digest(const std::uint8_t* data, const std::size_t size) {
    std::array<std::uint8_t, 20> digest{};
    std::uint32_t h0 = 0x67452301U;
    std::uint32_t h1 = 0xEFCDAB89U;
    std::uint32_t h2 = 0x98BADCFEU;
    std::uint32_t h3 = 0x10325476U;
    std::uint32_t h4 = 0xC3D2E1F0U;

    auto process_block = [&](const std::uint8_t* block) {
        std::uint32_t schedule[80]{};
        for (std::size_t i = 0; i < 16; ++i) {
            const std::size_t base = i * 4;
            schedule[i] = (static_cast<std::uint32_t>(block[base]) << 24U) |
                          (static_cast<std::uint32_t>(block[base + 1]) << 16U) |
                          (static_cast<std::uint32_t>(block[base + 2]) << 8U) |
                          static_cast<std::uint32_t>(block[base + 3]);
        }
        for (std::size_t i = 16; i < 80; ++i) {
            schedule[i] = RotateLeft32Bits(schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16], 1U);
        }

        std::uint32_t a = h0;
        std::uint32_t b = h1;
        std::uint32_t c = h2;
        std::uint32_t d = h3;
        std::uint32_t e = h4;

        for (std::size_t i = 0; i < 80; ++i) {
            std::uint32_t f = 0;
            std::uint32_t k = 0;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999U;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1U;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCU;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6U;
            }

            const std::uint32_t temp = RotateLeft32Bits(a, 5U) + f + e + k + schedule[i];
            e = d;
            d = c;
            c = RotateLeft32Bits(b, 30U);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    };

    const std::size_t full_blocks = size / 64U;
    for (std::size_t i = 0; i < full_blocks; ++i) {
        process_block(data + (i * 64U));
    }

    std::array<std::uint8_t, 128> tail{};
    const std::size_t remainder = size % 64U;
    if (remainder != 0) {
        std::memcpy(tail.data(), data + (full_blocks * 64U), remainder);
    }
    tail[remainder] = 0x80U;

    const std::uint64_t bit_length = static_cast<std::uint64_t>(size) * 8U;
    const bool needs_extra_block = remainder >= 56U;
    const std::size_t total_tail = needs_extra_block ? 128U : 64U;
    const std::size_t length_offset = total_tail - 8U;
    for (std::size_t i = 0; i < 8; ++i) {
        tail[length_offset + i] = static_cast<std::uint8_t>((bit_length >> ((7U - i) * 8U)) & 0xFFU);
    }

    process_block(tail.data());
    if (needs_extra_block) {
        process_block(tail.data() + 64U);
    }

    const std::uint32_t words[5] = {h0, h1, h2, h3, h4};
    for (std::size_t i = 0; i < 5; ++i) {
        digest[i * 4] = static_cast<std::uint8_t>((words[i] >> 24U) & 0xFFU);
        digest[i * 4 + 1] = static_cast<std::uint8_t>((words[i] >> 16U) & 0xFFU);
        digest[i * 4 + 2] = static_cast<std::uint8_t>((words[i] >> 8U) & 0xFFU);
        digest[i * 4 + 3] = static_cast<std::uint8_t>(words[i] & 0xFFU);
    }
    return digest;
}

std::array<std::uint8_t, 20> Sha1Digest(const std::vector<std::uint8_t>& data) {
    return Sha1Digest(data.data(), data.size());
}

bool ToJksPasswordBytes(const std::string& password, std::vector<std::uint8_t>& out) {
    out.clear();
    if (password.empty()) {
        return true;
    }

    std::u16string password_utf16;
    if (!util::TryDecodeUtf8ToUtf16(password, password_utf16)) {
        return false;
    }

    out.reserve(password_utf16.size() * 2U);
    for (const char16_t ch : password_utf16) {
        out.push_back(static_cast<std::uint8_t>((static_cast<std::uint16_t>(ch) >> 8U) & 0xFFU));
        out.push_back(static_cast<std::uint8_t>(static_cast<std::uint16_t>(ch) & 0xFFU));
    }
    return true;
}

std::string NormalizeJksAlias(std::string alias) {
    std::u16string utf16;
    if (util::TryDecodeUtf8ToUtf16(alias, utf16)) {
        auto to_lower_utf16 = [](const char16_t ch) -> char16_t {
            if (ch >= u'A' && ch <= u'Z') {
                return static_cast<char16_t>(ch - u'A' + u'a');
            }
            if (ch >= u'\u0410' && ch <= u'\u042F') {
                return static_cast<char16_t>(ch + 0x20U);
            }

            switch (ch) {
                case u'\u0401': return u'\u0451'; // Ё
                case u'\u0404': return u'\u0454'; // Є
                case u'\u0406': return u'\u0456'; // І
                case u'\u0407': return u'\u0457'; // Ї
                case u'\u0490': return u'\u0491'; // Ґ
                default: return ch;
            }
        };

        for (char16_t& ch : utf16) {
            ch = to_lower_utf16(ch);
        }

        std::string lowered_utf8;
        if (util::TryEncodeUtf16ToUtf8(utf16, lowered_utf8)) {
            return lowered_utf8;
        }
    }

    for (char& ch : alias) {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte >= 'A' && byte <= 'Z') {
            ch = static_cast<char>(byte - 'A' + 'a');
        }
    }
    return alias;
}

bool VerifyJksIntegrity(const std::vector<std::uint8_t>& input,
                        const std::size_t body_size,
                        const std::string& store_password,
                        std::string& error_message) {
    if (store_password.empty()) {
        return true;
    }
    if (input.size() < body_size + kJksDigestLength) {
        error_message = "JKS integrity trailer is truncated";
        return false;
    }

    std::vector<std::uint8_t> digest_input;
    if (!ToJksPasswordBytes(store_password, digest_input)) {
        error_message = "JKS store password is not valid UTF-8";
        return false;
    }
    digest_input.reserve(digest_input.size() + (sizeof(kJksWhitener) - 1U) + body_size);
    digest_input.insert(digest_input.end(), kJksWhitener, kJksWhitener + sizeof(kJksWhitener) - 1U);
    digest_input.insert(digest_input.end(), input.begin(), input.begin() + static_cast<std::ptrdiff_t>(body_size));

    const auto computed = Sha1Digest(digest_input);
    const auto actual_begin = input.begin() + static_cast<std::ptrdiff_t>(body_size);
    if (!std::equal(computed.begin(), computed.end(), actual_begin)) {
        error_message = "JKS keystore password is incorrect or the store was tampered with";
        return false;
    }

    return true;
}

bool ExtractJksEncryptedPayload(const std::vector<std::uint8_t>& protected_private_key,
                                std::vector<std::uint8_t>& encrypted_payload,
                                std::string& error_message) {
    TlvView outer{};
    if (!ParseTlvAt(protected_private_key, 0, protected_private_key.size(), outer) || outer.tag != 0x30 ||
        outer.next_offset != protected_private_key.size()) {
        error_message = "JKS private key entry is not valid EncryptedPrivateKeyInfo";
        return false;
    }

    TlvView algorithm{};
    if (!ParseTlvAt(protected_private_key, outer.value_offset, outer.next_offset, algorithm) || algorithm.tag != 0x30) {
        error_message = "JKS private key entry has invalid encryption algorithm metadata";
        return false;
    }

    TlvView algorithm_oid{};
    if (!ParseTlvAt(protected_private_key, algorithm.value_offset, algorithm.next_offset, algorithm_oid) ||
        algorithm_oid.tag != 0x06) {
        error_message = "JKS private key entry does not contain encryption OID";
        return false;
    }
    if (algorithm_oid.value_length != kJksKeyProtectorOid.size() ||
        !std::equal(kJksKeyProtectorOid.begin(),
                    kJksKeyProtectorOid.end(),
                    protected_private_key.begin() + static_cast<std::ptrdiff_t>(algorithm_oid.value_offset))) {
        error_message = "JKS private key entry uses unsupported protection algorithm";
        return false;
    }

    TlvView encrypted_data{};
    if (!ParseTlvAt(protected_private_key, algorithm.next_offset, outer.next_offset, encrypted_data) ||
        encrypted_data.tag != 0x04 || encrypted_data.next_offset != outer.next_offset) {
        error_message = "JKS private key entry has invalid encrypted payload";
        return false;
    }

    encrypted_payload.assign(
        protected_private_key.begin() + static_cast<std::ptrdiff_t>(encrypted_data.value_offset),
        protected_private_key.begin() + static_cast<std::ptrdiff_t>(encrypted_data.next_offset));
    return true;
}

bool RecoverJksPrivateKey(const std::vector<std::uint8_t>& protected_private_key,
                          const std::string& key_password,
                          std::vector<std::uint8_t>& private_key_pkcs8,
                          std::string& error_message) {
    if (key_password.empty()) {
        error_message = "JKS private key entry requires non-empty key password";
        return false;
    }

    std::vector<std::uint8_t> encrypted_payload;
    if (!ExtractJksEncryptedPayload(protected_private_key, encrypted_payload, error_message)) {
        return false;
    }
    if (encrypted_payload.size() < kJksSaltLength + kJksDigestLength) {
        error_message = "JKS private key entry payload is too short";
        return false;
    }

    const std::size_t encrypted_key_length = encrypted_payload.size() - kJksSaltLength - kJksDigestLength;
    const auto encrypted_key_begin = encrypted_payload.begin() + static_cast<std::ptrdiff_t>(kJksSaltLength);
    const auto integrity_begin = encrypted_key_begin + static_cast<std::ptrdiff_t>(encrypted_key_length);

    std::vector<std::uint8_t> password_bytes;
    if (!ToJksPasswordBytes(key_password, password_bytes)) {
        error_message = "JKS private key password is not valid UTF-8";
        return false;
    }
    std::vector<std::uint8_t> xor_key;
    xor_key.reserve(encrypted_key_length);

    std::vector<std::uint8_t> previous_digest(encrypted_payload.begin(),
                                              encrypted_payload.begin() + static_cast<std::ptrdiff_t>(kJksSaltLength));
    while (xor_key.size() < encrypted_key_length) {
        std::vector<std::uint8_t> round_input = password_bytes;
        round_input.insert(round_input.end(), previous_digest.begin(), previous_digest.end());
        const auto digest = Sha1Digest(round_input);

        const std::size_t remaining = encrypted_key_length - xor_key.size();
        const std::size_t chunk = std::min<std::size_t>(digest.size(), remaining);
        xor_key.insert(xor_key.end(), digest.begin(), digest.begin() + static_cast<std::ptrdiff_t>(chunk));
        previous_digest.assign(digest.begin(), digest.end());
    }

    private_key_pkcs8.resize(encrypted_key_length);
    for (std::size_t i = 0; i < encrypted_key_length; ++i) {
        private_key_pkcs8[i] = encrypted_payload[kJksSaltLength + i] ^ xor_key[i];
    }

    std::vector<std::uint8_t> digest_input = password_bytes;
    digest_input.insert(digest_input.end(), private_key_pkcs8.begin(), private_key_pkcs8.end());
    const auto computed = Sha1Digest(digest_input);
    if (!std::equal(computed.begin(), computed.end(), integrity_begin)) {
        error_message = "JKS private key password is incorrect";
        private_key_pkcs8.clear();
        return false;
    }

    return true;
}

} // namespace

bool PemDerLoader::Load(const std::vector<std::uint8_t>& input,
                        std::vector<std::uint8_t>& der_payload,
                        std::string& type,
                        std::string& error_message) {
    std::vector<PemBlock> blocks;
    if (!LoadAll(input, blocks, error_message, LoadOptions{})) {
        return false;
    }

    const auto key_it = std::find_if(blocks.begin(), blocks.end(), [](const PemBlock& block) {
        return block.type.find("PRIVATE KEY") != std::string::npos || block.type == "DER";
    });
    if (key_it == blocks.end()) {
        error_message = "PEM/DER does not contain PRIVATE KEY block";
        return false;
    }

    der_payload = key_it->der_payload;
    type = key_it->type;
    return true;
}

bool PemDerLoader::LoadAll(const std::vector<std::uint8_t>& input,
                           std::vector<PemBlock>& blocks,
                           std::string& error_message,
                           const LoadOptions options) {
    if (input.empty()) {
        error_message = "Input key data is empty";
        return false;
    }

    if (input.front() == 0x30) {
        blocks.push_back({"DER", input});
        return true;
    }

    const std::string text(input.begin(), input.end());
    std::size_t search_pos = 0;
    while (true) {
        const auto begin = text.find("-----BEGIN ", search_pos);
        if (begin == std::string::npos) {
            break;
        }

        const auto type_end = text.find("-----", begin + 11);
        if (type_end == std::string::npos) {
            error_message = "PEM begin marker is invalid";
            return false;
        }

        const std::string block_type = text.substr(begin + 11, type_end - (begin + 11));
        const std::string end_marker = "-----END " + block_type + "-----";
        const auto body_start = text.find('\n', type_end);
        const auto end = text.find(end_marker, body_start == std::string::npos ? type_end : body_start);
        if (body_start == std::string::npos || end == std::string::npos || end <= body_start) {
            error_message = "PEM end marker is missing";
            return false;
        }

        std::string payload;
        payload.reserve(end - body_start);
        for (std::size_t i = body_start + 1; i < end; ++i) {
            const char ch = text[i];
            if (IsBase64Char(ch)) {
                payload.push_back(ch);
            }
        }

        if (payload.empty()) {
            error_message = "PEM payload is empty";
            return false;
        }

        std::vector<std::uint8_t> decoded;
        if (!util::Base64Decode(payload, decoded)) {
            error_message = "PEM payload is invalid";
            return false;
        }

        blocks.push_back({block_type, std::move(decoded)});
        search_pos = end + end_marker.size();
    }

    if (blocks.empty()) {
        error_message = "Unsupported key container format";
        return false;
    }

    if (options.strict_mode) {
        for (const auto& block : blocks) {
            if (block.der_payload.empty() || block.der_payload.front() != 0x30) {
                error_message = "Strict mode expects ASN.1 DER SEQUENCE payload";
                return false;
            }
        }
    }

    return true;
}

bool JksKeyStoreParser::LoadPrivateKeyEntry(const std::vector<std::uint8_t>& input,
                                            const std::string& store_password,
                                            const std::string& key_password,
                                            const std::string& preferred_alias,
                                            PrivateKeyEntry& entry,
                                            std::string& error_message) {
    entry = {};

    if (input.size() < 12U + kJksDigestLength) {
        error_message = "JKS container is too short";
        return false;
    }

    const std::size_t body_size = input.size() - kJksDigestLength;
    std::size_t offset = 0;
    std::uint32_t magic = 0;
    if (!ReadU32(input, offset, body_size, magic) || magic != kJksMagic) {
        error_message = "JKS magic is invalid";
        return false;
    }

    std::uint32_t version = 0;
    std::uint32_t entries = 0;
    if (!ReadU32(input, offset, body_size, version) || !ReadU32(input, offset, body_size, entries)) {
        error_message = "JKS header is truncated";
        return false;
    }
    if (version != kJksVersion1 && version != kJksVersion2) {
        error_message = "JKS version is not supported";
        return false;
    }

    const std::string normalized_requested_alias =
        preferred_alias.empty() ? std::string{} : NormalizeJksAlias(preferred_alias);
    bool found_any_private_key = false;
    bool found_requested_alias = false;
    std::vector<std::uint8_t> selected_protected_private_key;
    std::vector<std::uint8_t> selected_first_certificate;
    std::vector<std::vector<std::uint8_t>> selected_certificate_chain;
    std::string selected_alias;

    for (std::uint32_t i = 0; i < entries; ++i) {
        std::uint32_t tag = 0;
        if (!ReadU32(input, offset, body_size, tag)) {
            error_message = "JKS entry header is truncated";
            return false;
        }

        std::string alias;
        if (!ReadModifiedUtf8(input, offset, body_size, alias)) {
            error_message = "JKS alias is invalid";
            return false;
        }

        std::uint64_t timestamp = 0;
        if (!ReadU64(input, offset, body_size, timestamp)) {
            error_message = "JKS timestamp is truncated";
            return false;
        }
        (void)timestamp;

        if (tag == 1U) {
            found_any_private_key = true;

            std::uint32_t key_length = 0;
            if (!ReadU32(input, offset, body_size, key_length)) {
                error_message = "JKS private key entry length is invalid";
                return false;
            }

            std::vector<std::uint8_t> protected_private_key;
            if (!ReadBytes(input, offset, body_size, key_length, protected_private_key)) {
                error_message = "JKS private key entry is truncated";
                return false;
            }

            std::uint32_t certificate_count = 0;
            if (!ReadU32(input, offset, body_size, certificate_count)) {
                error_message = "JKS certificate chain header is truncated";
                return false;
            }

            // С-06 (знайдено мутаційним зондом у tamga-tests): `reserve` за
            // лічильником, прочитаним прямо з контейнера, — це аллокація
            // довільного розміру за вказівкою недовіреного вхідного файла.
            // Крафтове 0xFFFFFFFF давало спробу зарезервувати десятки гігабайтів,
            // неперехоплений bad_alloc і аварійне завершення процесу (у CLI та
            // C++ API; у NativeAPI його ловив би лише зовнішній guard).
            //
            // Мінімальний запис ланцюжка — 4 байти довжини плюс щонайменше
            // один байт вмісту, тож більше за (залишок / 5) сертифікатів у
            // буфері бути не може. Це не політичний ліміт, а арифметичний факт
            // про сам буфер.
            constexpr std::size_t kMinCertificateEntryBytes = 5;
            const std::size_t remaining = body_size > offset ? body_size - offset : 0;
            if (static_cast<std::uint64_t>(certificate_count) >
                static_cast<std::uint64_t>(remaining / kMinCertificateEntryBytes)) {
                error_message = "JKS certificate chain count exceeds the container size";
                return false;
            }

            std::vector<std::vector<std::uint8_t>> certificate_chain;
            certificate_chain.reserve(certificate_count);
            for (std::uint32_t certificate_index = 0; certificate_index < certificate_count; ++certificate_index) {
                if (version == kJksVersion2) {
                    std::string certificate_type;
                    if (!ReadModifiedUtf8(input, offset, body_size, certificate_type)) {
                        error_message = "JKS certificate type field is invalid";
                        return false;
                    }
                }

                std::uint32_t certificate_length = 0;
                if (!ReadU32(input, offset, body_size, certificate_length)) {
                    error_message = "JKS certificate length field is invalid";
                    return false;
                }

                std::vector<std::uint8_t> certificate_der;
                if (!ReadBytes(input, offset, body_size, certificate_length, certificate_der)) {
                    error_message = "JKS certificate entry is truncated";
                    return false;
                }
                certificate_chain.push_back(std::move(certificate_der));
            }

            const bool alias_matches = normalized_requested_alias.empty()
                                           ? selected_protected_private_key.empty()
                                           : NormalizeJksAlias(alias) == normalized_requested_alias;
            if (alias_matches) {
                found_requested_alias = true;
                selected_alias = std::move(alias);
                selected_protected_private_key = std::move(protected_private_key);
                selected_certificate_chain = std::move(certificate_chain);
                selected_first_certificate =
                    selected_certificate_chain.empty() ? std::vector<std::uint8_t>{} : selected_certificate_chain.front();
            }
            continue;
        }

        if (tag == 2U) {
            if (version == kJksVersion2) {
                std::string certificate_type;
                if (!ReadModifiedUtf8(input, offset, body_size, certificate_type)) {
                    error_message = "JKS trusted certificate type is invalid";
                    return false;
                }
            }

            std::uint32_t certificate_length = 0;
            if (!ReadU32(input, offset, body_size, certificate_length)) {
                error_message = "JKS trusted certificate length field is invalid";
                return false;
            }

            std::vector<std::uint8_t> certificate_der;
            if (!ReadBytes(input, offset, body_size, certificate_length, certificate_der)) {
                error_message = "JKS trusted certificate entry is truncated";
                return false;
            }
            continue;
        }

        error_message = "JKS entry tag is unsupported";
        return false;
    }

    if (offset != body_size) {
        error_message = "JKS container has trailing bytes before integrity trailer";
        return false;
    }
    if (!VerifyJksIntegrity(input, body_size, store_password, error_message)) {
        return false;
    }
    if (!found_any_private_key) {
        error_message = "JKS does not contain private key entry";
        return false;
    }
    if (!normalized_requested_alias.empty() && !found_requested_alias) {
        error_message = "JKS does not contain requested private key alias";
        return false;
    }
    if (selected_protected_private_key.empty()) {
        error_message = "JKS does not contain readable private key entry";
        return false;
    }

    const std::string effective_key_password = key_password.empty() ? store_password : key_password;
    if (!RecoverJksPrivateKey(selected_protected_private_key, effective_key_password, entry.private_key_pkcs8, error_message)) {
        return false;
    }

    entry.alias = std::move(selected_alias);
    entry.certificate = std::move(selected_first_certificate);
    entry.certificate_chain = std::move(selected_certificate_chain);
    return true;
}

// ---------------------------------------------------------------------------
// Власний контейнер АТ «ІІТ» (`Key-6.dat`)
// ---------------------------------------------------------------------------

namespace {

// Вміст OID 1.3.6.1.4.1.19398.1.1.1.2 (без тега й довжини).
constexpr std::array<std::uint8_t, 12> kIitStoreOidValue = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0x97, 0x46, 0x01, 0x01, 0x01, 0x02,
};

constexpr std::size_t kIitMacLength = 4U;
constexpr std::size_t kIitBlockSize = 8U;
constexpr std::size_t kIitKeyLength = 32U;
constexpr unsigned kIitKdfPasses = 10000U;

struct IitContainer {
    std::vector<std::uint8_t> mac;
    std::vector<std::uint8_t> pad;
    std::vector<std::uint8_t> body;
};

// Розбір структури без жодної криптографії — доступний і в збірці без
// cryptonite, бо на ньому тримається розпізнавання формату.
bool ParseIitContainer(const std::vector<std::uint8_t>& input, IitContainer& out) {
    TlvView outer;
    if (!ParseTlvAt(input, 0U, input.size(), outer) || outer.tag != 0x30) {
        return false;
    }
    const std::size_t outer_limit = outer.value_offset + outer.value_length;

    TlvView algorithm;
    if (!ParseTlvAt(input, outer.value_offset, outer_limit, algorithm) || algorithm.tag != 0x30) {
        return false;
    }
    const std::size_t algorithm_limit = algorithm.value_offset + algorithm.value_length;

    TlvView oid;
    if (!ParseTlvAt(input, algorithm.value_offset, algorithm_limit, oid) || oid.tag != 0x06) {
        return false;
    }
    if (oid.value_length != kIitStoreOidValue.size() ||
        !std::equal(kIitStoreOidValue.begin(),
                    kIitStoreOidValue.end(),
                    input.begin() + static_cast<std::ptrdiff_t>(oid.value_offset))) {
        return false;
    }

    TlvView params;
    if (!ParseTlvAt(input, oid.next_offset, algorithm_limit, params) || params.tag != 0x30) {
        return false;
    }
    const std::size_t params_limit = params.value_offset + params.value_length;

    TlvView mac;
    if (!ParseTlvAt(input, params.value_offset, params_limit, mac) || mac.tag != 0x04) {
        return false;
    }
    out.mac.assign(input.begin() + static_cast<std::ptrdiff_t>(mac.value_offset),
                   input.begin() + static_cast<std::ptrdiff_t>(mac.value_offset + mac.value_length));

    out.pad.clear();
    if (mac.next_offset < params_limit) {
        TlvView pad;
        if (!ParseTlvAt(input, mac.next_offset, params_limit, pad) || pad.tag != 0x04) {
            return false;
        }
        out.pad.assign(input.begin() + static_cast<std::ptrdiff_t>(pad.value_offset),
                       input.begin() + static_cast<std::ptrdiff_t>(pad.value_offset + pad.value_length));
    }

    TlvView body;
    if (!ParseTlvAt(input, algorithm.next_offset, outer_limit, body) || body.tag != 0x04) {
        return false;
    }
    out.body.assign(input.begin() + static_cast<std::ptrdiff_t>(body.value_offset),
                    input.begin() + static_cast<std::ptrdiff_t>(body.value_offset + body.value_length));
    return true;
}

#if TAMGA_CRYPTONITE_ENABLED

// RAII поверх C-типів cryptonite: без них кожна гілка з `return false`
// пропускала б `*_free`, а таких гілок тут багато.
struct ByteArrayDeleter {
    void operator()(ByteArray* value) const noexcept { ba_free(value); }
};
struct Gost34311Deleter {
    void operator()(Gost34311Ctx* value) const noexcept { gost34_311_free(value); }
};
struct Gost28147Deleter {
    void operator()(Gost28147Ctx* value) const noexcept { gost28147_free(value); }
};

using ByteArrayPtr = std::unique_ptr<ByteArray, ByteArrayDeleter>;
using Gost34311Ptr = std::unique_ptr<Gost34311Ctx, Gost34311Deleter>;
using Gost28147Ptr = std::unique_ptr<Gost28147Ctx, Gost28147Deleter>;

ByteArrayPtr AllocIitByteArray(const std::uint8_t* data, const std::size_t size) {
    return ByteArrayPtr(ba_alloc_from_uint8(data, size));
}

// Синхропосилка ГОСТ 34.311 — 32 нульові байти (ІІТ використовує саме її).
ByteArrayPtr MakeZeroSync() {
    const std::array<std::uint8_t, kIitKeyLength> zero{};
    return AllocIitByteArray(zero.data(), zero.size());
}

bool Gost34311Hash(const ByteArray* sync,
                   const std::uint8_t* data,
                   const std::size_t size,
                   std::array<std::uint8_t, kIitKeyLength>& out) {
    const Gost34311Ptr ctx(gost34_311_alloc(GOST28147_SBOX_ID_1, sync));
    if (!ctx) {
        return false;
    }
    const ByteArrayPtr input = AllocIitByteArray(data, size);
    if (!input || gost34_311_update(ctx.get(), input.get()) != RET_OK) {
        return false;
    }
    ByteArray* raw_hash = nullptr;
    if (gost34_311_final(ctx.get(), &raw_hash) != RET_OK) {
        return false;
    }
    const ByteArrayPtr hash(raw_hash);
    return ba_to_uint8(hash.get(), out.data(), out.size()) == RET_OK;
}

// KDF ІІТ: h = H(пароль), далі (passes - 1) разів h = H(h).
bool DeriveIitKey(const std::string& password, std::array<std::uint8_t, kIitKeyLength>& key) {
    const ByteArrayPtr sync = MakeZeroSync();
    if (!sync) {
        return false;
    }
    if (!Gost34311Hash(sync.get(),
                       reinterpret_cast<const std::uint8_t*>(password.data()),
                       password.size(),
                       key)) {
        return false;
    }
    for (unsigned pass = 1U; pass < kIitKdfPasses; ++pass) {
        if (!Gost34311Hash(sync.get(), key.data(), key.size(), key)) {
            return false;
        }
    }
    return true;
}

bool ComputeIitMac(const std::array<std::uint8_t, kIitKeyLength>& key,
                   const std::vector<std::uint8_t>& plaintext,
                   std::vector<std::uint8_t>& mac) {
    const Gost28147Ptr ctx(gost28147_alloc(GOST28147_SBOX_ID_1));
    const ByteArrayPtr key_ba = AllocIitByteArray(key.data(), key.size());
    const ByteArrayPtr data_ba = AllocIitByteArray(plaintext.data(), plaintext.size());
    if (!ctx || !key_ba || !data_ba) {
        return false;
    }
    if (gost28147_init_mac(ctx.get(), key_ba.get()) != RET_OK ||
        gost28147_update_mac(ctx.get(), data_ba.get()) != RET_OK) {
        return false;
    }
    ByteArray* raw_mac = nullptr;
    if (gost28147_final_mac(ctx.get(), &raw_mac) != RET_OK) {
        return false;
    }
    const ByteArrayPtr mac_ba(raw_mac);
    const std::uint8_t* buffer = ba_get_buf(mac_ba.get());
    if (buffer == nullptr) {
        return false;
    }
    mac.assign(buffer, buffer + ba_get_len(mac_ba.get()));
    return true;
}

#endif // TAMGA_CRYPTONITE_ENABLED

} // namespace

// ── Контейнер `.ZS2` АЦСК «Україна» ──────────────────────────────────────────

namespace {

constexpr std::size_t kZs2KeyLength = 32U;    // Калина-256/256: ключ 256 біт
constexpr std::size_t kZs2BlockSize = 32U;    // і блок теж 256 біт

// OID у вигляді вмісту TLV (без тега і довжини).
constexpr std::array<std::uint8_t, 9> kOidPkcs7Data = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
};
constexpr std::array<std::uint8_t, 11> kOidShroudedKeyBag = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02,
};
constexpr std::array<std::uint8_t, 9> kOidPbes2 = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D,
};
constexpr std::array<std::uint8_t, 9> kOidPbkdf2 = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C,
};
// 1.2.804.2.1.1.1.1.2.2.4 — Купина-256 KMAC як PRF.
constexpr std::array<std::uint8_t, 11> kOidKupynaKmac256 = {
    0x2A, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x04,
};
// 1.2.804.2.1.1.1.1.1.3.5.2 — Калина-256/256 CBC.
constexpr std::array<std::uint8_t, 12> kOidKalyna256Cbc = {
    0x2A, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x05, 0x02,
};

struct Zs2Bag {
    std::vector<std::uint8_t> salt;
    std::vector<std::uint8_t> iv;
    std::vector<std::uint8_t> ciphertext;
    unsigned long iterations{0};
};

bool OidEquals(const std::vector<std::uint8_t>& data, const TlvView& tlv,
               const std::uint8_t* expected, const std::size_t expected_len) {
    return tlv.tag == 0x06 && tlv.value_length == expected_len &&
           std::equal(expected, expected + expected_len,
                      data.begin() + static_cast<std::ptrdiff_t>(tlv.value_offset));
}

// ContentInfo типу `data`: SEQUENCE { OID data, [0] { OCTET STRING } }.
// Повертає межі вмісту OCTET STRING.
bool ParseDataContentInfo(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t limit,
                          std::size_t& content_offset, std::size_t& content_length,
                          std::size_t& next_offset) {
    TlvView info;
    if (!ParseTlvAt(data, offset, limit, info) || info.tag != 0x30) {
        return false;
    }
    const std::size_t info_limit = info.value_offset + info.value_length;

    TlvView oid;
    if (!ParseTlvAt(data, info.value_offset, info_limit, oid) ||
        !OidEquals(data, oid, kOidPkcs7Data.data(), kOidPkcs7Data.size())) {
        return false;
    }
    TlvView explicit0;
    if (!ParseTlvAt(data, oid.next_offset, info_limit, explicit0) || explicit0.tag != 0xA0) {
        return false;
    }
    TlvView octets;
    if (!ParseTlvAt(data, explicit0.value_offset, explicit0.value_offset + explicit0.value_length,
                    octets) ||
        octets.tag != 0x04) {
        return false;
    }
    content_offset = octets.value_offset;
    content_length = octets.value_length;
    next_offset = info.next_offset;
    return true;
}

// PBES2-параметри мішка: сіль, ітерації, IV. Повертає false і тоді, коли
// алгоритми не ті — це і є ознака формату.
bool ParseZs2Encryption(const std::vector<std::uint8_t>& data, const TlvView& epki, Zs2Bag& out) {
    const std::size_t epki_limit = epki.value_offset + epki.value_length;

    TlvView alg;
    if (!ParseTlvAt(data, epki.value_offset, epki_limit, alg) || alg.tag != 0x30) {
        return false;
    }
    const std::size_t alg_limit = alg.value_offset + alg.value_length;

    TlvView pbes2_oid;
    if (!ParseTlvAt(data, alg.value_offset, alg_limit, pbes2_oid) ||
        !OidEquals(data, pbes2_oid, kOidPbes2.data(), kOidPbes2.size())) {
        return false;
    }
    TlvView params;
    if (!ParseTlvAt(data, pbes2_oid.next_offset, alg_limit, params) || params.tag != 0x30) {
        return false;
    }
    const std::size_t params_limit = params.value_offset + params.value_length;

    // keyDerivationFunc
    TlvView kdf;
    if (!ParseTlvAt(data, params.value_offset, params_limit, kdf) || kdf.tag != 0x30) {
        return false;
    }
    const std::size_t kdf_limit = kdf.value_offset + kdf.value_length;
    TlvView kdf_oid;
    if (!ParseTlvAt(data, kdf.value_offset, kdf_limit, kdf_oid) ||
        !OidEquals(data, kdf_oid, kOidPbkdf2.data(), kOidPbkdf2.size())) {
        return false;
    }
    TlvView kdf_params;
    if (!ParseTlvAt(data, kdf_oid.next_offset, kdf_limit, kdf_params) || kdf_params.tag != 0x30) {
        return false;
    }
    const std::size_t kdf_params_limit = kdf_params.value_offset + kdf_params.value_length;

    TlvView salt;
    if (!ParseTlvAt(data, kdf_params.value_offset, kdf_params_limit, salt) || salt.tag != 0x04) {
        return false;
    }
    TlvView iterations;
    if (!ParseTlvAt(data, salt.next_offset, kdf_params_limit, iterations) ||
        iterations.tag != 0x02 || iterations.value_length == 0 || iterations.value_length > 4) {
        return false;
    }
    unsigned long iters = 0;
    for (std::size_t i = 0; i < iterations.value_length; ++i) {
        iters = (iters << 8) | data[iterations.value_offset + i];
    }
    if (iters == 0) {
        return false;
    }

    // PRF обов'язковий: саме він відрізняє «нову» українську криптографію.
    TlvView prf;
    if (!ParseTlvAt(data, iterations.next_offset, kdf_params_limit, prf) || prf.tag != 0x30) {
        return false;
    }
    TlvView prf_oid;
    if (!ParseTlvAt(data, prf.value_offset, prf.value_offset + prf.value_length, prf_oid) ||
        !OidEquals(data, prf_oid, kOidKupynaKmac256.data(), kOidKupynaKmac256.size())) {
        return false;
    }

    // encryptionScheme
    TlvView enc;
    if (!ParseTlvAt(data, kdf.next_offset, params_limit, enc) || enc.tag != 0x30) {
        return false;
    }
    const std::size_t enc_limit = enc.value_offset + enc.value_length;
    TlvView enc_oid;
    if (!ParseTlvAt(data, enc.value_offset, enc_limit, enc_oid) ||
        !OidEquals(data, enc_oid, kOidKalyna256Cbc.data(), kOidKalyna256Cbc.size())) {
        return false;
    }
    TlvView enc_params;
    if (!ParseTlvAt(data, enc_oid.next_offset, enc_limit, enc_params) || enc_params.tag != 0x30) {
        return false;
    }
    TlvView iv;
    if (!ParseTlvAt(data, enc_params.value_offset, enc_params.value_offset + enc_params.value_length,
                    iv) ||
        iv.tag != 0x04 || iv.value_length != kZs2BlockSize) {
        return false;
    }

    // encryptedData
    TlvView body;
    if (!ParseTlvAt(data, alg.next_offset, epki_limit, body) || body.tag != 0x04 ||
        body.value_length == 0 || body.value_length % kZs2BlockSize != 0) {
        return false;
    }

    out.salt.assign(data.begin() + static_cast<std::ptrdiff_t>(salt.value_offset),
                    data.begin() + static_cast<std::ptrdiff_t>(salt.value_offset + salt.value_length));
    out.iv.assign(data.begin() + static_cast<std::ptrdiff_t>(iv.value_offset),
                  data.begin() + static_cast<std::ptrdiff_t>(iv.value_offset + iv.value_length));
    out.ciphertext.assign(
        data.begin() + static_cast<std::ptrdiff_t>(body.value_offset),
        data.begin() + static_cast<std::ptrdiff_t>(body.value_offset + body.value_length));
    out.iterations = iters;
    return true;
}

// Проходить PFX -> AuthenticatedSafe -> SafeContents і повертає ПЕРШИЙ
// `pkcs8ShroudedKeyBag`, захищений Купиною+Калиною.
bool ParseZs2FirstBag(const std::vector<std::uint8_t>& input, Zs2Bag& out) {
    TlvView pfx;
    if (!ParseTlvAt(input, 0U, input.size(), pfx) || pfx.tag != 0x30) {
        return false;
    }
    const std::size_t pfx_limit = pfx.value_offset + pfx.value_length;

    TlvView version;
    if (!ParseTlvAt(input, pfx.value_offset, pfx_limit, version) || version.tag != 0x02) {
        return false;
    }

    std::size_t safe_offset = 0;
    std::size_t safe_length = 0;
    std::size_t after_auth_safe = 0;
    if (!ParseDataContentInfo(input, version.next_offset, pfx_limit, safe_offset, safe_length,
                              after_auth_safe)) {
        return false;
    }

    // AuthenticatedSafe = SEQUENCE OF ContentInfo
    TlvView auth_safe;
    if (!ParseTlvAt(input, safe_offset, safe_offset + safe_length, auth_safe) ||
        auth_safe.tag != 0x30) {
        return false;
    }
    const std::size_t auth_limit = auth_safe.value_offset + auth_safe.value_length;

    std::size_t offset = auth_safe.value_offset;
    while (offset < auth_limit) {
        std::size_t contents_offset = 0;
        std::size_t contents_length = 0;
        std::size_t next = 0;
        if (!ParseDataContentInfo(input, offset, auth_limit, contents_offset, contents_length,
                                  next)) {
            return false;
        }
        offset = next;

        // SafeContents = SEQUENCE OF SafeBag
        TlvView safe_contents;
        if (!ParseTlvAt(input, contents_offset, contents_offset + contents_length, safe_contents) ||
            safe_contents.tag != 0x30) {
            return false;
        }
        const std::size_t contents_limit = safe_contents.value_offset + safe_contents.value_length;

        std::size_t bag_offset = safe_contents.value_offset;
        while (bag_offset < contents_limit) {
            TlvView bag;
            if (!ParseTlvAt(input, bag_offset, contents_limit, bag) || bag.tag != 0x30) {
                return false;
            }
            const std::size_t bag_limit = bag.value_offset + bag.value_length;
            bag_offset = bag.next_offset;

            TlvView bag_id;
            if (!ParseTlvAt(input, bag.value_offset, bag_limit, bag_id)) {
                return false;
            }
            if (!OidEquals(input, bag_id, kOidShroudedKeyBag.data(), kOidShroudedKeyBag.size())) {
                continue;  // certBag або keyBag — не наш випадок
            }
            TlvView bag_value;
            if (!ParseTlvAt(input, bag_id.next_offset, bag_limit, bag_value) ||
                bag_value.tag != 0xA0) {
                return false;
            }
            TlvView epki;
            if (!ParseTlvAt(input, bag_value.value_offset,
                            bag_value.value_offset + bag_value.value_length, epki) ||
                epki.tag != 0x30) {
                return false;
            }
            if (ParseZs2Encryption(input, epki, out)) {
                return true;
            }
        }
    }
    return false;
}

#if TAMGA_CRYPTONITE_ENABLED

// KMAC-256 над Купиною з ключем рівно 32 байти.
bool Zs2Kmac(const std::array<std::uint8_t, kZs2KeyLength>& key,
             const std::uint8_t* data, const std::size_t data_len,
             std::array<std::uint8_t, kZs2KeyLength>& out) {
    Dstu7564Ctx* ctx = dstu7564_alloc(DSTU7564_SBOX_1);
    if (ctx == nullptr) {
        return false;
    }
    ByteArray* key_ba = ba_alloc_from_uint8(key.data(), key.size());
    ByteArray* in = nullptr;
    ByteArray* mac = nullptr;
    bool ok = false;
    if (key_ba != nullptr && dstu7564_init_kmac(ctx, key_ba, out.size()) == RET_OK) {
        in = ba_alloc_from_uint8(data, data_len);
        if (in != nullptr && dstu7564_update_kmac(ctx, in) == RET_OK &&
            dstu7564_final_kmac(ctx, &mac) == RET_OK && mac != nullptr &&
            ba_get_len(mac) == out.size()) {
            std::memcpy(out.data(), ba_get_buf(mac), out.size());
            ok = true;
        }
    }
    ba_free(key_ba);
    ba_free(in);
    ba_free(mac);
    dstu7564_free(ctx);
    return ok;
}

// PBKDF2-подібний цикл, у якому PRF — KMAC, а ключем KMAC є пароль,
// доповнений нулями до 32 байтів.
bool DeriveZs2Key(const std::string& password, const std::vector<std::uint8_t>& salt,
                  const unsigned long iterations,
                  std::array<std::uint8_t, kZs2KeyLength>& derived) {
    std::array<std::uint8_t, kZs2KeyLength> kmac_key{};
    const std::size_t copy_len = std::min(password.size(), kmac_key.size());
    std::memcpy(kmac_key.data(), password.data(), copy_len);

    std::vector<std::uint8_t> block(salt);
    block.push_back(0);
    block.push_back(0);
    block.push_back(0);
    block.push_back(1);

    std::array<std::uint8_t, kZs2KeyLength> u{};
    if (!Zs2Kmac(kmac_key, block.data(), block.size(), u)) {
        tamga::util::SecureZero(kmac_key.data(), kmac_key.size());
        return false;
    }
    derived = u;
    for (unsigned long i = 1; i < iterations; ++i) {
        std::array<std::uint8_t, kZs2KeyLength> next{};
        if (!Zs2Kmac(kmac_key, u.data(), u.size(), next)) {
            tamga::util::SecureZero(kmac_key.data(), kmac_key.size());
            tamga::util::SecureZero(u.data(), u.size());
            return false;
        }
        u = next;
        for (std::size_t j = 0; j < derived.size(); ++j) {
            derived[j] = static_cast<std::uint8_t>(derived[j] ^ u[j]);
        }
    }
    tamga::util::SecureZero(kmac_key.data(), kmac_key.size());
    tamga::util::SecureZero(u.data(), u.size());
    return true;
}

#endif  // TAMGA_CRYPTONITE_ENABLED

}  // namespace

bool Zs2KeyContainerParser::Matches(const std::vector<std::uint8_t>& input) {
    Zs2Bag bag;
    return ParseZs2FirstBag(input, bag);
}

bool Zs2KeyContainerParser::Decrypt(const std::vector<std::uint8_t>& input,
                                    const std::string& password,
                                    std::vector<std::uint8_t>& pkcs8,
                                    std::string& error_message) {
    Zs2Bag bag;
    if (!ParseZs2FirstBag(input, bag)) {
        error_message = "ZS2 key container has malformed structure or unsupported algorithms";
        return false;
    }
    if (password.empty()) {
        error_message = "ZS2 key container requires password";
        return false;
    }

#if !TAMGA_CRYPTONITE_ENABLED
    (void)pkcs8;
    error_message = "ZS2 key container requires vendored cryptonite (built with TAMGA_ENABLE_VENDOR_CRYPTONITE=OFF)";
    return false;
#else
    std::array<std::uint8_t, kZs2KeyLength> key{};
    if (!DeriveZs2Key(password, bag.salt, bag.iterations, key)) {
        error_message = "ZS2 key derivation failed";
        return false;
    }

    Dstu7624Ctx* ctx = dstu7624_alloc(DSTU7624_SBOX_1);
    ByteArray* key_ba = ba_alloc_from_uint8(key.data(), key.size());
    ByteArray* iv_ba = ba_alloc_from_uint8(bag.iv.data(), bag.iv.size());
    ByteArray* in = ba_alloc_from_uint8(bag.ciphertext.data(), bag.ciphertext.size());
    ByteArray* out = nullptr;
    bool decrypted = false;
    if (ctx != nullptr && key_ba != nullptr && iv_ba != nullptr && in != nullptr &&
        dstu7624_init_cbc(ctx, key_ba, iv_ba) == RET_OK &&
        dstu7624_decrypt(ctx, in, &out) == RET_OK && out != nullptr) {
        pkcs8.assign(ba_get_buf(out), ba_get_buf(out) + ba_get_len(out));
        decrypted = true;
    }
    ba_free(key_ba);
    ba_free(iv_ba);
    ba_free(in);
    ba_free(out);
    if (ctx != nullptr) {
        dstu7624_free(ctx);
    }
    tamga::util::SecureZero(key.data(), key.size());

    if (!decrypted) {
        error_message = "ZS2 key container decryption failed";
        return false;
    }

    // PKCS#7-паддинг із блоком 32 байти. Некоректний паддинг — це насамперед
    // неправильний пароль: зовнішнього MAC ми на цьому шляху не перевіряємо.
    const std::uint8_t pad = pkcs8.empty() ? 0U : pkcs8.back();
    if (pad == 0 || pad > kZs2BlockSize || pad > pkcs8.size() ||
        !std::all_of(pkcs8.end() - pad, pkcs8.end(),
                     [pad](const std::uint8_t byte) { return byte == pad; })) {
        tamga::util::SecureZero(pkcs8.data(), pkcs8.size());
        pkcs8.clear();
        error_message = "ZS2 key container password is incorrect (padding mismatch)";
        return false;
    }
    pkcs8.resize(pkcs8.size() - pad);

    TlvView check;
    if (!ParseTlvAt(pkcs8, 0U, pkcs8.size(), check) || check.tag != 0x30 ||
        check.next_offset != pkcs8.size()) {
        tamga::util::SecureZero(pkcs8.data(), pkcs8.size());
        pkcs8.clear();
        error_message = "ZS2 key container did not decrypt into a DER private key";
        return false;
    }
    return true;
#endif
}

bool IitKeyContainerParser::Matches(const std::vector<std::uint8_t>& input) {
    IitContainer container;
    return ParseIitContainer(input, container);
}

bool IitKeyContainerParser::Decrypt(const std::vector<std::uint8_t>& input,
                                    const std::string& password,
                                    std::vector<std::uint8_t>& pkcs8,
                                    std::string& error_message) {
    IitContainer container;
    if (!ParseIitContainer(input, container)) {
        error_message = "IIT key container has malformed structure";
        return false;
    }
    if (container.mac.size() != kIitMacLength) {
        error_message = "IIT key container has unexpected MAC length";
        return false;
    }
    if (container.pad.size() >= kIitBlockSize) {
        error_message = "IIT key container has unexpected padding length";
        return false;
    }
    if (container.body.empty() ||
        (container.body.size() + container.pad.size()) % kIitBlockSize != 0U) {
        error_message = "IIT key container payload is not block aligned";
        return false;
    }
    if (password.empty()) {
        error_message = "IIT key container requires password";
        return false;
    }

#if !TAMGA_CRYPTONITE_ENABLED
    (void)pkcs8;
    error_message = "IIT key container requires vendored cryptonite (built with TAMGA_ENABLE_VENDOR_CRYPTONITE=OFF)";
    return false;
#else
    std::array<std::uint8_t, kIitKeyLength> key{};
    if (!DeriveIitKey(password, key)) {
        error_message = "IIT key derivation failed";
        return false;
    }

    std::vector<std::uint8_t> blocks;
    blocks.reserve(container.body.size() + container.pad.size());
    blocks.insert(blocks.end(), container.body.begin(), container.body.end());
    blocks.insert(blocks.end(), container.pad.begin(), container.pad.end());

    std::vector<std::uint8_t> plaintext;
    {
        const Gost28147Ptr cipher(gost28147_alloc(GOST28147_SBOX_ID_1));
        const ByteArrayPtr key_ba = AllocIitByteArray(key.data(), key.size());
        const ByteArrayPtr in_ba = AllocIitByteArray(blocks.data(), blocks.size());
        ByteArray* raw_out = nullptr;
        if (!cipher || !key_ba || !in_ba ||
            gost28147_init_ecb(cipher.get(), key_ba.get()) != RET_OK ||
            gost28147_decrypt(cipher.get(), in_ba.get(), &raw_out) != RET_OK) {
            util::SecureZero(key.data(), key.size());
            error_message = "IIT key container decryption failed";
            return false;
        }
        const ByteArrayPtr out_ba(raw_out);
        const std::uint8_t* buffer = ba_get_buf(out_ba.get());
        if (buffer == nullptr || ba_get_len(out_ba.get()) < container.body.size()) {
            util::SecureZero(key.data(), key.size());
            error_message = "IIT key container decryption produced short output";
            return false;
        }
        plaintext.assign(buffer, buffer + container.body.size());
    }

    // Поле `mac` — це imit ГОСТ 28147-89 від відкритого тексту на тому ж ключі.
    // Саме воно, а не «схожість на DER», відрізняє правильний пароль від
    // неправильного: помилковий пароль дає випадковий блок, який іноді
    // випадково починається з 0x30.
    std::vector<std::uint8_t> computed_mac;
    if (!ComputeIitMac(key, plaintext, computed_mac)) {
        util::SecureZero(key.data(), key.size());
        util::SecureClear(plaintext);
        error_message = "IIT key container MAC computation failed";
        return false;
    }
    util::SecureZero(key.data(), key.size());

    if (computed_mac.size() < kIitMacLength ||
        !std::equal(container.mac.begin(), container.mac.end(), computed_mac.begin())) {
        util::SecureClear(plaintext);
        error_message = "IIT key container password is incorrect (MAC mismatch)";
        return false;
    }

    pkcs8 = std::move(plaintext);
    return true;
#endif
}

} // namespace tamga::core
