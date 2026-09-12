#pragma once

#include <vector>
#include <string>
#include <array>

namespace tamga::core::policy {

inline std::uint32_t RotateRight(const std::uint32_t value, const int bits) {
    return (value >> bits) | (value << (32 - bits));
}

inline std::uint32_t ReadBigEndian32(const std::uint8_t* bytes) {
    return (static_cast<std::uint32_t>(bytes[0]) << 24) |
           (static_cast<std::uint32_t>(bytes[1]) << 16) |
           (static_cast<std::uint32_t>(bytes[2]) << 8) |
           static_cast<std::uint32_t>(bytes[3]);
}

inline void WriteBigEndian64(std::vector<std::uint8_t>& bytes, const std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

inline std::array<std::uint8_t, 32> Sha256(const std::vector<std::uint8_t>& input) {
    static constexpr std::array<std::uint32_t, 64> k = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
    };

    std::vector<std::uint8_t> message = input;
    const std::uint64_t bit_length = static_cast<std::uint64_t>(message.size()) * 8U;
    message.push_back(0x80U);
    while ((message.size() % 64U) != 56U) {
        message.push_back(0U);
    }
    WriteBigEndian64(message, bit_length);

    std::uint32_t h0 = 0x6a09e667U;
    std::uint32_t h1 = 0xbb67ae85U;
    std::uint32_t h2 = 0x3c6ef372U;
    std::uint32_t h3 = 0xa54ff53aU;
    std::uint32_t h4 = 0x510e527fU;
    std::uint32_t h5 = 0x9b05688cU;
    std::uint32_t h6 = 0x1f83d9abU;
    std::uint32_t h7 = 0x5be0cd19U;

    for (std::size_t offset = 0; offset < message.size(); offset += 64U) {
        std::array<std::uint32_t, 64> w = {};
        for (std::size_t i = 0; i < 16U; ++i) {
            w[i] = ReadBigEndian32(message.data() + offset + (i * 4U));
        }
        for (std::size_t i = 16U; i < 64U; ++i) {
            const std::uint32_t s0 = RotateRight(w[i - 15U], 7) ^
                                     RotateRight(w[i - 15U], 18) ^
                                     (w[i - 15U] >> 3);
            const std::uint32_t s1 = RotateRight(w[i - 2U], 17) ^
                                     RotateRight(w[i - 2U], 19) ^
                                     (w[i - 2U] >> 10);
            w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
        }

        std::uint32_t a = h0;
        std::uint32_t b = h1;
        std::uint32_t c = h2;
        std::uint32_t d = h3;
        std::uint32_t e = h4;
        std::uint32_t f = h5;
        std::uint32_t g = h6;
        std::uint32_t h = h7;

        for (std::size_t i = 0; i < 64U; ++i) {
            const std::uint32_t s1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
            const std::uint32_t ch = (e & f) ^ ((~e) & g);
            const std::uint32_t temp1 = h + s1 + ch + k[i] + w[i];
            const std::uint32_t s0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    const std::array<std::uint32_t, 8> words = {h0, h1, h2, h3, h4, h5, h6, h7};
    std::array<std::uint8_t, 32> digest = {};
    for (std::size_t i = 0; i < words.size(); ++i) {
        digest[i * 4U] = static_cast<std::uint8_t>((words[i] >> 24) & 0xffU);
        digest[(i * 4U) + 1U] = static_cast<std::uint8_t>((words[i] >> 16) & 0xffU);
        digest[(i * 4U) + 2U] = static_cast<std::uint8_t>((words[i] >> 8) & 0xffU);
        digest[(i * 4U) + 3U] = static_cast<std::uint8_t>(words[i] & 0xffU);
    }
    return digest;
}

inline std::string LowerHex(const std::array<std::uint8_t, 32>& digest) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(digest.size() * 2U);
    for (const std::uint8_t byte : digest) {
        output.push_back(hex[(byte >> 4) & 0x0fU]);
        output.push_back(hex[byte & 0x0fU]);
    }
    return output;
}

inline std::string ComputeSha256Hex(const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty()) {
        return "";
    }
    return "sha256:" + LowerHex(Sha256(bytes));
}

} // namespace tamga::core::policy
