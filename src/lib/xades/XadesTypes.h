#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tamga::xades {

// Моделі QualifyingProperties для XAdES згідно ETSI EN 319 132-1.

// Рівень профілю XAdES, що визначає набір присутніх властивостей підпису.
enum class XadesProfile {
    BES,
    T,
    C,
    X,
    X_L,
    A,
};

// Підписана політика підпису (SignaturePolicyIdentifier).
struct SignaturePolicy {
    std::string policy_id;
    std::string policy_hash_algo_uri;
    std::vector<std::uint8_t> policy_hash_value;
};

// Опис формату підписаного обʼєкта даних (DataObjectFormat).
struct DataObjectFormat {
    std::string object_reference;
    std::string mime_type;
    std::string description;
};

// Архівна позначка часу (ArchiveTimeStamp) для профілю A.
struct ArchiveTimestamp {
    std::string ts_token_base64;
    std::vector<std::string> include_uris;
};

// Підписані властивості (SignedProperties) кваліфікуючих властивостей XAdES.
struct SignedProperties {
    std::string id;
    std::string signing_time;
    std::string signing_certificate_xml;
    std::vector<DataObjectFormat> data_object_formats;
    std::optional<SignaturePolicy> signature_policy;
};

// Непідписані властивості (UnsignedProperties) — позначки часу та посилання
// на сертифікати/відкликання, що додаються профілями T/C/X/X-L/A.
struct UnsignedProperties {
    std::vector<std::string> timestamp_tokens;           // T, X/X-L/A
    std::vector<std::string> complete_certificate_refs;  // C/X/X-L/A
    std::vector<std::string> complete_revocation_refs;   // C/X/X-L/A
    std::vector<std::string> archive_timestamps;         // A
};

// Кореневий контейнер кваліфікуючих властивостей XAdES.
struct QualifyingProperties {
    SignedProperties signed_props;
    UnsignedProperties unsigned_props;
};

}  // namespace tamga::xades
