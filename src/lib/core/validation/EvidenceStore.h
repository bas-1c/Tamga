#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace tamga::core::validation {

struct EvidenceRecord {
    std::string id;
    std::string type;
    std::string source;
    std::vector<std::uint8_t> bytes;
    std::string canonical_json;
};

class EvidenceStore final {
public:
    std::string PutRawEvidence(const std::string& type,
                               const std::vector<std::uint8_t>& bytes,
                               const std::string& source);

    std::string PutDerivedEvidence(
        const std::string& type,
        const std::vector<std::pair<std::string, std::string>>& fields);

    // Returned pointer is valid until this store is destroyed; std::map keeps it stable across inserts.
    const EvidenceRecord* Resolve(const std::string& id) const;

    const std::map<std::string, EvidenceRecord>& GetAllRecords() const { return records_; }

private:
    std::map<std::string, EvidenceRecord> records_;
};

} // namespace tamga::core::validation
