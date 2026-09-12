#include "core/cryptonite/Names.h"

#include "util/Hex.h"
#include "util/X509Name.h"

#include "util/Der.h"

#if TAMGA_CRYPTONITE_ENABLED

// ADR-027: таблиця OID, екранування RFC 4514 і розбір значення атрибута
// винесені в `util/X509Name` — вони не потребують ASN.1-структур і мусять
// бути доступні також у збірці `vendor=OFF`. Тут лишається лише те, що
// працює з декодованими типами cryptonite.
using tamga::util::HexEncode;

namespace tamga::core::cryptonite_detail {




std::string OidFromAsn1(const OBJECT_IDENTIFIER_t& oid) {
    unsigned long arcs[16] = {};
    const int arc_count = OBJECT_IDENTIFIER_get_arcs(&oid, arcs, sizeof(arcs[0]), 16);
    if (arc_count <= 0) {
        return {};
    }

    std::ostringstream stream;
    for (int i = 0; i < arc_count && i < 16; ++i) {
        if (i > 0) {
            stream << '.';
        }
        stream << arcs[i];
    }
    return stream.str();
}

std::vector<NameAttribute> CollectNameAttributes(const Name_t* name) {
    std::vector<NameAttribute> attributes;
    if (name == nullptr || name->present != Name_PR_rdnSequence) {
        return attributes;
    }

    const RDNSequence_t* rdn_seq = &name->choice.rdnSequence;
    for (int i = 0; i < rdn_seq->list.count; ++i) {
        const RelativeDistinguishedName_t* rdn = rdn_seq->list.array[i];
        if (rdn == nullptr) {
            continue;
        }
        for (int j = 0; j < rdn->list.count; ++j) {
            const AttributeTypeAndValue_t* atv = rdn->list.array[j];
            if (atv == nullptr) {
                continue;
            }

            NameAttribute attribute;
            attribute.oid = OidFromAsn1(atv->type);
            const char* short_name = LookupOidShortName(attribute.oid);
            attribute.short_name = short_name == nullptr ? attribute.oid : short_name;
            attribute.value = ExtractDerStringValue(atv->value.buf, 0U,
                                                   static_cast<std::size_t>(atv->value.size));
            attributes.push_back(std::move(attribute));
        }
    }
    return attributes;
}

std::string FormatNameRfc4514(const Name_t* name) {
    if (name == nullptr || name->present != Name_PR_rdnSequence) {
        return {};
    }

    const RDNSequence_t* rdn_seq = &name->choice.rdnSequence;
    std::vector<std::string> rdns;
    for (int i = 0; i < rdn_seq->list.count; ++i) {
        const RelativeDistinguishedName_t* rdn = rdn_seq->list.array[i];
        if (rdn == nullptr) {
            continue;
        }

        std::vector<std::string> parts;
        for (int j = 0; j < rdn->list.count; ++j) {
            const AttributeTypeAndValue_t* atv = rdn->list.array[j];
            if (atv == nullptr) {
                continue;
            }

            const std::string dotted = OidFromAsn1(atv->type);
            const char* short_name = LookupOidShortName(dotted);
            const auto* value_data = atv->value.buf;
            const auto value_size = static_cast<std::size_t>(atv->value.size);
            const std::string value = ExtractDerStringValue(value_data, 0U, value_size);
            if (short_name != nullptr) {
                parts.push_back(std::string(short_name) + "=" + EscapeRfc4514(value));
            } else {
                parts.push_back(dotted + "=#" + HexEncode(value_data, value_size));
            }
        }

        if (!parts.empty()) {
            std::string rdn_text;
            for (std::size_t k = 0; k < parts.size(); ++k) {
                if (k > 0) {
                    rdn_text += '+';
                }
                rdn_text += parts[k];
            }
            rdns.push_back(std::move(rdn_text));
        }
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

std::string FirstNameAttributeValue(const std::vector<NameAttribute>& attributes,
                                    const std::initializer_list<const char*> names_or_oids) {
    for (const auto* name_or_oid : names_or_oids) {
        for (const auto& attribute : attributes) {
            if (attribute.short_name == name_or_oid || attribute.oid == name_or_oid) {
                return attribute.value;
            }
        }
    }
    return {};
}

}  // namespace tamga::core::cryptonite_detail

#endif  // TAMGA_CRYPTONITE_ENABLED
