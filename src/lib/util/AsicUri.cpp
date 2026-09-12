#include "util/AsicUri.h"

namespace tamga::util {

namespace {

int HexValue(const char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

}  // namespace

bool NormalizeAsicEntryUri(const std::string& uri, std::string& out, std::string& error_message) {
    out.clear();
    out.reserve(uri.size());
    for (std::size_t i = 0; i < uri.size(); ++i) {
        const char ch = uri[i];
        if (ch != '%') {
            out.push_back(ch);
            continue;
        }
        if (i + 2 >= uri.size()) {
            error_message = "Некоректне percent-encoding у URI-посиланні: " + uri;
            return false;
        }
        const int hi = HexValue(uri[i + 1]);
        const int lo = HexValue(uri[i + 2]);
        if (hi < 0 || lo < 0) {
            error_message = "Некоректне percent-encoding у URI-посиланні: " + uri;
            return false;
        }
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
    }
    if (out.rfind("./", 0) == 0) {
        out.erase(0, 2);
    }
    return true;
}

}  // namespace tamga::util
