#include "asic/AsicWriter.h"
#include <cstdlib>
#include "miniz.h"
#include <cstring>
#include <fstream>
#include <filesystem>
#include <stdexcept>

namespace tamga::asic {

namespace {

struct MemoryReadContext {
    const std::uint8_t* data;
    std::size_t size;
};

std::size_t ReadMemory(void* opaque, mz_uint64 offset, void* buffer, std::size_t bytes_requested) {
    const auto* context = static_cast<const MemoryReadContext*>(opaque);
    if (!context || offset >= context->size || bytes_requested == 0) {
        return 0;
    }

    const auto local_offset = static_cast<std::size_t>(offset);
    const auto available = context->size - local_offset;
    const auto bytes_to_copy = bytes_requested < available ? bytes_requested : available;
    std::memcpy(buffer, context->data + local_offset, bytes_to_copy);
    return bytes_to_copy;
}

bool AddMemoryEntry(mz_zip_archive& zip,
                    const char* name,
                    const void* data,
                    std::size_t size,
                    bool compress) {
    MemoryReadContext context{
        static_cast<const std::uint8_t*>(data),
        size,
    };
    // B-01: обидві гілки тернарного оператора мусять мати ОДИН тип.
    // `MZ_DEFAULT_LEVEL` — enum-константа miniz, `0u` — unsigned. MSVC це
    // проковтує, а GCC з `-Wextra -Werror` відхиляє
    // (`enumerated and non-enumerated type in conditional expression`), і
    // через один цей рядок не збиралася ЖОДНА з трьох Linux-конфігурацій.
    const mz_uint level_and_flags =
        (compress ? static_cast<mz_uint>(MZ_DEFAULT_LEVEL) : 0u) | MZ_ZIP_FLAG_WRITE_HEADER_SET_SIZE;
    return mz_zip_writer_add_read_buf_callback(
               &zip,
               name,
               ReadMemory,
               &context,
               static_cast<mz_uint64>(size),
               nullptr,
               nullptr,
               0,
               level_and_flags,
               nullptr,
               0,
               nullptr,
               0) != 0;
}

}  // namespace

struct AsicWriter::Impl {
    mz_zip_archive zip;
    bool initialized{false};
    bool finalized{false};

    Impl() {
        std::memset(&zip, 0, sizeof(zip));
    }

    ~Impl() {
        if (initialized && !finalized) {
            mz_zip_writer_end(&zip);
        }
    }
};

AsicWriter::AsicWriter(AsicType type)
    : type_(type)
    , impl_(new Impl()) {
}

AsicWriter::~AsicWriter() {
    delete impl_;
}

bool AsicWriter::AddFile(const std::string& name, const std::vector<std::uint8_t>& data, bool compress) {
    if (!impl_->initialized) {
        if (!mz_zip_writer_init_heap(&impl_->zip, 0, 65536)) {
            return false;
        }
        impl_->initialized = true;

        // Add mimetype first without compression
        const char* mimetype = (type_ == AsicType::AsicS) ? "application/vnd.etsi.asic-s+zip"
                                                          : "application/vnd.etsi.asic-e+zip";
        if (!AddMemoryEntry(impl_->zip, "mimetype", mimetype, std::strlen(mimetype), false)) {
            return false;
        }
    }

    if (impl_->finalized) {
        return false;
    }

    return AddMemoryEntry(impl_->zip, name.c_str(), data.data(), data.size(), compress);
}

bool AsicWriter::Finalize(std::vector<std::uint8_t>& out_container, std::string& error_message) {
    if (!impl_->initialized) {
        // If no files were added, initialize and write mimetype
        std::vector<std::uint8_t> empty;
        if (!AddFile("", empty, false)) { // This forces initialization
            error_message = "Failed to initialize archive";
            return false;
        }
    }

    if (impl_->finalized) {
        error_message = "Archive already finalized";
        return false;
    }

    void* buf = nullptr;
    size_t size = 0;
    if (!mz_zip_writer_finalize_heap_archive(&impl_->zip, &buf, &size)) {
        error_message = "Failed to finalize heap archive";
        return false;
    }
    // Н-09: власність над heap-буфером miniz переходить до RAII ДО `assign`,
    // який може кинути `std::bad_alloc`. Раніше `std::free(buf)` стояв ПІСЛЯ
    // нього — на шляху відмови аллокатора буфер губився назавжди.
    struct HeapBuffer {
        void* ptr{nullptr};
        explicit HeapBuffer(void* p) noexcept : ptr(p) {}
        HeapBuffer(const HeapBuffer&) = delete;
        HeapBuffer& operator=(const HeapBuffer&) = delete;
        ~HeapBuffer() { std::free(ptr); }
    } owned(buf);

    // Н-09: `finalized` виставляється лише ПІСЛЯ успішного копіювання. Раніше
    // прапорець ставився до потенційно кидаючого `assign`, тож при винятку
    // деструктор вважав архів завершеним і пропускав власне прибирання.
    if (buf && size > 0) {
        out_container.assign(static_cast<uint8_t*>(buf), static_cast<uint8_t*>(buf) + size);
    }
    impl_->finalized = true;

    mz_zip_writer_end(&impl_->zip);
    return true;
}

bool AsicWriter::SaveToFile(const std::string& filepath, std::string& error_message) {
    std::vector<std::uint8_t> data;
    if (!Finalize(data, error_message)) {
        return false;
    }

    std::ofstream out(std::filesystem::u8path(filepath), std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        error_message = "Unable to open file for writing: " + filepath;
        return false;
    }

    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return true;
}

} // namespace tamga::asic
