#include "core/validation/EvidenceStore.h"

#include <array>
#include <cstddef>

#include "core/policy/Sha256Helper.h"

namespace tamga::core::validation {
namespace {

// Хвиля 8: тут лежала ПОБАЙТОВО ІДЕНТИЧНА копія всієї реалізації SHA-256
// з `core/policy/Sha256Helper.h` — RotateRight, ReadBigEndian32,
// WriteBigEndian64, Sha256 і LowerHex. Криптографічний примітив, скопійований
// цілком, бо заголовок лежав у чужому namespace і його не помітили.
//
// Саме такі копії й закриває сторожа `tamga-symbol-duplication-tests`.
using policy::LowerHex;
using policy::Sha256;

std::string EvidenceIdForBytes(const std::vector<std::uint8_t>& bytes) {
    return "sha256:" + LowerHex(Sha256(bytes));
}

std::string JsonUnicodeEscape(const std::uint8_t value) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string escaped = "\\u00";
    escaped.push_back(hex[(value >> 4) & 0x0fU]);
    escaped.push_back(hex[value & 0x0fU]);
    return escaped;
}

std::string EscapeJsonString(const std::string& value) {
    std::string escaped;
    for (const unsigned char ch : value) {
        switch (ch) {
            case '"':
                escaped += "\\\"";
                break;
            case '\\':
                escaped += "\\\\";
                break;
            case '\b':
                escaped += "\\b";
                break;
            case '\f':
                escaped += "\\f";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                if (ch < 0x20U) {
                    escaped += JsonUnicodeEscape(ch);
                } else {
                    escaped.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    return escaped;
}

std::string BuildCanonicalJson(const std::map<std::string, std::string>& fields) {
    std::string json = "{";
    bool first = true;
    for (const auto& [key, value] : fields) {
        if (!first) {
            json += ",";
        }
        first = false;
        json += "\"";
        json += EscapeJsonString(key);
        json += "\":\"";
        json += EscapeJsonString(value);
        json += "\"";
    }
    json += "}";
    return json;
}

std::vector<std::uint8_t> StringBytes(const std::string& value) {
    return std::vector<std::uint8_t>(value.begin(), value.end());
}

} // namespace

std::string EvidenceStore::PutRawEvidence(const std::string& type,
                                          const std::vector<std::uint8_t>& bytes,
                                          const std::string& source) {
    const std::string id = EvidenceIdForBytes(bytes);
    if (records_.find(id) == records_.end()) {
        EvidenceRecord record;
        record.id = id;
        record.type = type;
        record.source = source;
        record.bytes = bytes;
        records_.emplace(id, std::move(record));
    }
    return id;
}

std::string EvidenceStore::PutDerivedEvidence(
    const std::string& type,
    const std::vector<std::pair<std::string, std::string>>& fields) {
    std::map<std::string, std::string> canonical_fields;
    for (const auto& field : fields) {
        if (field.first == "type" || canonical_fields.find(field.first) != canonical_fields.end()) {
            return "";
        }
        canonical_fields.emplace(field.first, field.second);
    }
    canonical_fields["type"] = type;

    const std::string canonical_json = BuildCanonicalJson(canonical_fields);
    const std::string id = EvidenceIdForBytes(StringBytes(canonical_json));
    if (records_.find(id) == records_.end()) {
        EvidenceRecord record;
        record.id = id;
        record.type = type;
        const auto source = canonical_fields.find("source");
        if (source != canonical_fields.end()) {
            record.source = source->second;
        }
        record.canonical_json = canonical_json;
        records_.emplace(id, std::move(record));
    }
    return id;
}

const EvidenceRecord* EvidenceStore::Resolve(const std::string& id) const {
    const auto found = records_.find(id);
    if (found == records_.end()) {
        return nullptr;
    }
    return &found->second;
}

} // namespace tamga::core::validation
