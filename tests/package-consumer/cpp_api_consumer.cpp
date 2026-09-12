#include <string>

#include <tamga/tamga_c_api.h>

int main() {
    const char* version = tamga_version();
    return version != nullptr && std::string(version).find('.') != std::string::npos ? 0 : 1;
}
