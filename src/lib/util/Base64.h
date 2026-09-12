#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tamga::util {

std::string Base64Encode(const std::vector<std::uint8_t>& input);
bool Base64Decode(const std::string& input, std::vector<std::uint8_t>& out);

} // namespace tamga::util
