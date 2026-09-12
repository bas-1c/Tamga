#include "util/Iso8601.h"

namespace tamga::util {

std::string FormatAsIso8601(const std::string& generalized_time) {
    if (generalized_time.size() < 14 || generalized_time.find('-') != std::string::npos) {
        return generalized_time;
    }
    return generalized_time.substr(0, 4) + "-" +
           generalized_time.substr(4, 2) + "-" +
           generalized_time.substr(6, 2) + "T" +
           generalized_time.substr(8, 2) + ":" +
           generalized_time.substr(10, 2) + ":" +
           generalized_time.substr(12, 2) + "Z";
}

} // namespace tamga::util
