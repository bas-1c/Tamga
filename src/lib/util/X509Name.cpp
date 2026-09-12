#include "util/X509Name.h"

#include <iomanip>
#include <sstream>
#include <vector>

#include "util/Der.h"
#include "util/Hex.h"

namespace tamga::util {
std::string OidToString(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return {};
    }

    std::ostringstream out;
    const unsigned first = data[0];
    out << (first / 40U) << '.' << (first % 40U);

    unsigned long arc = 0;
    for (std::size_t i = 1; i < size; ++i) {
        arc = (arc << 7U) | (data[i] & 0x7FU);
        if ((data[i] & 0x80U) == 0) {
            out << '.' << arc;
            arc = 0;
        }
    }
    return out.str();
}

const char* LookupOidShortName(const std::string& dotted_oid) {
    struct OidShortName {
        const char* dotted;
        const char* short_name;
    };
    // ОБʼЄДНАННЯ трьох таблиць, що жили в дереві паралельно:
    //   * `cryptonite/Names.cpp` — 10 записів, серед них українські DRFO і
    //     EDRPOU, але без L/ST/STREET;
    //   * `session/SessionHelpers.ipp` — 20 стандартних атрибутів X.500 і
    //     ЖОДНОГО українського: ДРФО та ЄДРПОУ показувались сирим OID;
    //   * `policy/CertificateChainValidator.cpp` — 8 записів, серед них
    //     2.5.4.97, якого не знала жодна інша.
    // Конфліктів не було — лише прогалини, тому таблиця саме обʼєднана.
    static const OidShortName kKnownOids[] = {
        {"2.5.4.3", "CN"},
        {"2.5.4.4", "SN"},
        {"2.5.4.5", "SERIALNUMBER"},
        {"2.5.4.6", "C"},
        {"2.5.4.7", "L"},
        {"2.5.4.8", "ST"},
        {"2.5.4.9", "STREET"},
        {"2.5.4.10", "O"},
        {"2.5.4.11", "OU"},
        {"2.5.4.12", "T"},
        {"2.5.4.13", "description"},
        {"2.5.4.15", "businessCategory"},
        {"2.5.4.17", "postalCode"},
        {"2.5.4.42", "GN"},
        {"2.5.4.43", "initials"},
        {"2.5.4.44", "generationQualifier"},
        {"2.5.4.46", "dnQualifier"},
        {"2.5.4.97", "OID.2.5.4.97"},
        {"1.2.840.113549.1.9.1", "emailAddress"},
        {"0.9.2342.19200300.100.1.1", "UID"},
        {"0.9.2342.19200300.100.1.25", "DC"},
        // Українські ідентифікатори: без них ДРФО і ЄДРПОУ у звіті
        // виглядали як 1.2.804.2.1.1.1.11.1.4=#<hex>.
        {"1.2.804.2.1.1.1.11.1.4", "DRFO"},
        {"1.2.804.2.1.1.1.11.1.5", "EDRPOU"},
    };
    for (const auto& entry : kKnownOids) {
        if (dotted_oid == entry.dotted) {
            return entry.short_name;
        }
    }
    return nullptr;
}

std::string EscapeRfc4514(const std::string& value) {
    std::string result;
    result.reserve(value.size() + 8U);
    for (std::size_t i = 0; i < value.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(value[i]);
        if (ch == '\\' || ch == '"' || ch == '+' || ch == ',' || ch == ';' || ch == '<' || ch == '>' || ch == '\0') {
            result += '\\';
            result += static_cast<char>(ch);
        } else if (ch == '#' && i == 0) {
            result += "\\#";
        } else if (ch == ' ' && (i == 0 || i == value.size() - 1)) {
            result += "\\ ";
        } else {
            result += static_cast<char>(ch);
        }
    }
    return result;
}

std::string ExtractDerStringValue(const std::uint8_t* data, const std::size_t offset,
                                  const std::size_t limit) {
    if (offset >= limit) {
        return {};
    }
    // Хвиля 8, п.2 (доповнення): тут була ТРЕТЯ копія розбору довжини DER, і
    // вона лишилася поза консолідацією, бо той пошук вівся лише по `.cpp`/`.h`.
    // Копія містила ту саму вразливу форму `len_offset + value_len > limit`
    // і не мала guard проти втрати старших бітів при зсуві, тож `value_len` міг
    // сягнути SIZE_MAX, сума переповнитись, а перевірка — мовчки пройти.
    //
    // Тут це небезпечніше, ніж у двох виправлених раніше копіях: байти йдуть
    // напряму з сертифіката (`FormatRdnSequence` над сирим DER), а не з
    // `ANY_t::buf`, довжину якого вже перевірив ASN.1-декодер cryptonite.
    // Тобто жоден зовнішній інваріант шлях не прикривав.
    TlvView tlv{};
    if (!ParseTlvAt(data, offset, limit, tlv)) {
        return {};
    }
    const auto tag = tlv.tag;
    const std::size_t len_offset = tlv.value_offset;
    const std::size_t value_len = tlv.value_length;

    if (tag == 0x0C || tag == 0x13 || tag == 0x16) {
        return std::string(reinterpret_cast<const char*>(data + len_offset), value_len);
    }
    if (tag == 0x1E && value_len >= 2) {
        std::string result;
        result.reserve(value_len / 2);
        for (std::size_t i = 0; i + 1 < value_len; i += 2) {
            const auto hi = data[len_offset + i];
            const auto lo = data[len_offset + i + 1];
            if (hi == 0 && lo >= 0x20 && lo < 0x7F) {
                result += static_cast<char>(lo);
            } else {
                std::ostringstream esc;
                esc << "\\x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(hi)
                    << std::setw(2) << static_cast<unsigned>(lo);
                result += esc.str();
            }
        }
        return result;
    }

    return HexEncode(data + len_offset, value_len);
}

std::string FormatRdnSequence(const std::uint8_t* data, std::size_t size) {
    std::vector<std::string> rdns;
    std::size_t offset = 0;

    // Копія буфера робиться ОДИН раз. У попередній редакції вона стояла
    // всередині циклу, тобто весь DER перекопіювався на кожен RDN.
    const std::vector<std::uint8_t> buf(data, data + size);

    while (offset < size) {
        TlvView set_tlv{};
        if (!ParseTlvAt(buf, offset, set_tlv) || set_tlv.tag != 0x31) {
            break;
        }

        std::vector<std::string> rdn_parts;
        std::size_t inner = set_tlv.value_offset;
        while (inner < set_tlv.next_offset) {
            TlvView seq_tlv{};
            if (!ParseTlvAt(buf, inner, seq_tlv) || seq_tlv.tag != 0x30) {
                break;
            }

            TlvView oid_tlv{};
            if (!ParseTlvAt(buf, seq_tlv.value_offset, oid_tlv) || oid_tlv.tag != 0x06) {
                inner = seq_tlv.next_offset;
                continue;
            }

            const std::string dotted = OidToString(&data[oid_tlv.value_offset], oid_tlv.value_length);
            const char* short_name = LookupOidShortName(dotted);

            const std::string value_str = ExtractDerStringValue(data, oid_tlv.next_offset, size);

            std::string attr;
            if (short_name != nullptr) {
                attr = std::string(short_name) + "=" + EscapeRfc4514(value_str);
            } else {
                attr = dotted + "=#" + HexEncode(&data[oid_tlv.next_offset],
                    seq_tlv.next_offset > oid_tlv.next_offset ? seq_tlv.next_offset - oid_tlv.next_offset : 0);
            }
            rdn_parts.push_back(std::move(attr));
            inner = seq_tlv.next_offset;
        }

        if (!rdn_parts.empty()) {
            std::string rdn_str;
            for (std::size_t i = 0; i < rdn_parts.size(); ++i) {
                if (i > 0) {
                    rdn_str += '+';
                }
                rdn_str += rdn_parts[i];
            }
            rdns.push_back(std::move(rdn_str));
        }

        offset = set_tlv.next_offset;
    }

    std::string result;
    for (auto it = rdns.rbegin(); it != rdns.rend(); ++it) {
        if (!result.empty()) {
            result += ',';
        }
        result += *it;
    }
    return result;
}
} // namespace tamga::util
