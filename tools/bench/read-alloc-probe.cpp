// Проба вимірювання алокацій під час ReadBinaryFileLimited / ReadTextFileLimited.
// Перехоплює глобальні operator new/delete і рахує «великі» алокації (>= 64 KiB).
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <new>
#include <string>
#include <vector>
#include <fstream>

#include "util/FileSystem.h"

namespace {
constexpr std::size_t kBigThreshold = 64u * 1024u;

struct Stats {
    bool active = false;
    unsigned long long big_count = 0;
    unsigned long long big_bytes = 0;
    unsigned long long big_max = 0;
};

Stats g_stats;
}  // namespace

void* operator new(std::size_t n) {
    if (g_stats.active && n >= kBigThreshold) {
        ++g_stats.big_count;
        g_stats.big_bytes += n;
        if (n > g_stats.big_max) {
            g_stats.big_max = n;
        }
    }
    void* p = std::malloc(n != 0 ? n : 1);
    if (p == nullptr) {
        throw std::bad_alloc();
    }
    return p;
}

void* operator new[](std::size_t n) { return operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

int main(int argc, char** argv) {
    const std::size_t file_size = (argc > 1) ? static_cast<std::size_t>(std::strtoull(argv[1], nullptr, 10))
                                             : 16u * 1024u * 1024u;
    const char* path = "alloc_probe_input.bin";

    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        std::vector<char> block(64u * 1024u, 'A');
        std::size_t written = 0;
        while (written < file_size) {
            const std::size_t chunk = (file_size - written < block.size()) ? (file_size - written) : block.size();
            out.write(block.data(), static_cast<std::streamsize>(chunk));
            written += chunk;
        }
    }

    const std::uintmax_t limit = 64ull * 1024ull * 1024ull;

    {
        std::vector<std::uint8_t> data;
        std::string err;
        g_stats = Stats{};
        g_stats.active = true;
        const bool ok = tamga::util::ReadBinaryFileLimited(path, limit, data, err);
        g_stats.active = false;
        std::printf("binary: ok=%d size=%zu capacity=%zu big_allocs=%llu big_bytes=%llu big_max=%llu\n",
                    ok ? 1 : 0, data.size(), data.capacity(), g_stats.big_count, g_stats.big_bytes,
                    g_stats.big_max);
    }

    {
        std::string text;
        std::string err;
        g_stats = Stats{};
        g_stats.active = true;
        const bool ok = tamga::util::ReadTextFileLimited(path, limit, text, err);
        g_stats.active = false;
        std::printf("text:   ok=%d size=%zu capacity=%zu big_allocs=%llu big_bytes=%llu big_max=%llu\n",
                    ok ? 1 : 0, text.size(), text.capacity(), g_stats.big_count, g_stats.big_bytes,
                    g_stats.big_max);
    }

    std::remove(path);
    return 0;
}
