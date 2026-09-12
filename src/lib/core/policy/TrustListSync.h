#pragma once

#include <string>

#include "core/policy/TrustListParser.h"
#include "core/policy/TrustListSettings.h"

namespace tamga::core::policy {

struct TrustListSyncResult {
    bool succeeded{false};
    bool used_cache{false};
    std::string source_url;
    std::string cache_status{"not-checked"};
    std::string last_sync;
    std::string message;
    // B-3: makes "the TL signature was not verified" observable instead of
    // indistinguishable from "it was verified". One of:
    //   "verified-pinned"            — ds:Signature valid AND signer cert equals the pinned cert
    //   "verified-self-consistent"   — ds:Signature valid against the cert inside the same XML
    //                                  only; NOT proof of origin (substitution still possible)
    //   "not-verified-disabled"      — xml_signature_policy == Disabled
    //   "not-verified-unsupported"   — requested, but this build has no XMLDSIG engine
    //                                  (sync fails closed; kept for diagnostics)
    //   "failed"                     — verification ran and rejected the document
    // С-22 (доопрацювання): дефолт керує РЕАЛЬНИМ шляхом, а не лише
    // теоретичним. Коли завантаження TL не вдалося і Sync повертається на
    // кеш (два ранні return), перевірка підпису не виконувалась зовсім —
    // "not-verified-disabled" стверджував би, що її вимкнено політикою.
    // Значення узгоджене з core::TrustListSyncReport.
    std::string xml_signature_status{"not-checked"};
    TrustListParseResult parsed;
};

class TrustListSync final {
public:
    TrustListSyncResult Sync(const std::string& work_dir, const TrustListSettings& settings) const;
};

} // namespace tamga::core::policy
