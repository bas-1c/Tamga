#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "core/policy/TrustListParser.h"

namespace tamga::core::policy {

struct PolicyCacheState {
    std::string source_url;
    std::string cache_status{"not-checked"};
    std::string last_sync;
    bool update_succeeded{false};
    std::string etag;
    std::string last_modified;
};

struct PolicyCacheEntry {
    std::string filename;
    std::vector<std::uint8_t> xml;
    TrustListParseResult parsed;
    bool is_historical{false};
};

class PolicyCache final {
public:
    explicit PolicyCache(const std::string& work_dir);
    explicit PolicyCache(std::filesystem::path work_dir);
    bool EnsureLayout(std::string& error_message) const;
    bool WriteTrustList(const std::vector<std::uint8_t>& xml, const PolicyCacheState& state) const;
    bool WriteTrustListMaterialized(const std::vector<std::uint8_t>& xml,
                                    const PolicyCacheState& state,
                                    const TrustListParseResult& parsed) const;
    bool WriteTrustListsMaterialized(const std::vector<PolicyCacheEntry>& entries,
                                     const PolicyCacheState& state) const;
    bool ReadState(PolicyCacheState& state) const;
    // ME-06 (повний фікс): читає trust-store-metadata.json (записаний
    // WriteTrustListsMaterialized/SyncTrustList) і повертає перший tspUrl
    // будь-якого GRANTED TSA-сервісу офіційного TL (MR-TSA/QTST або
    // National-TSA/QTST), без прив'язки до issuer'а конкретного сертифіката
    // (рішення користувача: RFC 3161 не вимагає такого зв'язку). Читає файл
    // ЩОРАЗУ, без кешування в пам'яті — переживає рестарт процесу. Локальний
    // файл, тому дозволено викликати й у offline_mode. Порожній рядок, якщо
    // кеш відсутній чи жодного GRANTED TSA-сервісу з tspUrls немає.
    std::string ResolveGrantedTspUrl() const;
    std::filesystem::path TrustListPath() const;
    std::filesystem::path TrustListPath(const std::string& filename) const;
    std::filesystem::path StatePath() const;
    std::filesystem::path TrustStoreMetadataPath() const;
    std::filesystem::path TrustStoreDir() const;
    std::filesystem::path HistoricalTrustStoreDir() const;
    std::filesystem::path IntermediateStoreDir() const;
    std::filesystem::path CrlStoreDir() const;
    std::filesystem::path PolicyDir() const;

private:
    std::filesystem::path work_dir_;
};

} // namespace tamga::core::policy
