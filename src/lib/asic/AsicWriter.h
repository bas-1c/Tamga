#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::asic {

enum class AsicType {
    AsicS,
    AsicE
};

class AsicWriter final {
public:
    explicit AsicWriter(AsicType type);
    ~AsicWriter();

    // Disable copy
    AsicWriter(const AsicWriter&) = delete;
    AsicWriter& operator=(const AsicWriter&) = delete;

    // Add file to container
    bool AddFile(const std::string& name, const std::vector<std::uint8_t>& data, bool compress = true);

    // Finalize creation and get container bytes
    bool Finalize(std::vector<std::uint8_t>& out_container, std::string& error_message);

    // Finalize and save directly to file
    bool SaveToFile(const std::string& filepath, std::string& error_message);

private:
    AsicType type_;
    struct Impl;
    Impl* impl_;
};

} // namespace tamga::asic
