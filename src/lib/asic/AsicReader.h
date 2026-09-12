#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::asic {

struct AsicFileEntry {
    std::string name;
    std::vector<std::uint8_t> data;
};

class AsicReader final {
public:
    AsicReader();
    ~AsicReader();

    // Disable copy
    AsicReader(const AsicReader&) = delete;
    AsicReader& operator=(const AsicReader&) = delete;

    // Load ZIP container from memory or file
    bool LoadFromBuffer(const std::vector<std::uint8_t>& data, std::string& error_message);
    bool LoadFromFile(const std::string& filepath, std::string& error_message);

    // Retrieve container mimetype from the "mimetype" file
    bool GetMimetype(std::string& out_mimetype) const;

    // Retrieve all files inside the container
    bool GetFiles(std::vector<AsicFileEntry>& out_files, std::string& error_message) const;

    // Extract specific file by name
    bool ExtractFile(const std::string& name, std::vector<std::uint8_t>& out_data, std::string& error_message) const;

private:
    struct Impl;
    Impl* impl_;
};

} // namespace tamga::asic
