#include <stddef.h>
#include <string.h>

#include <tamga/tamga_c_api.h>

int main(void) {
    const char* version = tamga_version();
    if (version == NULL || strlen(version) == 0) return 1;

    tamga_session_t session = tamga_session_create();
    if (session == NULL) return 2;
    if (tamga_session_is_key_loaded(session) != 0) return 3;

    tamga_session_destroy(session);
    return 0;
}
