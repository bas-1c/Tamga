#include "asic/AsicReader.h"
#include "miniz.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <exception>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <unordered_set>

namespace tamga::asic {

namespace {

// Н-09: власник буфера, виділеного miniz через malloc.
//
// Раніше `std::free(p)` викликався ПІСЛЯ `vector::assign` — а assign може
// кинути `std::bad_alloc`. У такому разі буфер miniz втрачався назавжди.
// Витік проявляється лише на шляху відмови аллокатора, тож ані звичайний
// прогін, ані ASan його не показували — але саме на цьому шляху витік
// найшкідливіший.
struct MinizHeapBuffer {
    void* ptr{nullptr};
    explicit MinizHeapBuffer(void* p) noexcept : ptr(p) {}
    MinizHeapBuffer(const MinizHeapBuffer&) = delete;
    MinizHeapBuffer& operator=(const MinizHeapBuffer&) = delete;
    ~MinizHeapBuffer() { std::free(ptr); }
};


// WP-8: ліміти захисту від zip-bomb / traversal / дублікатів. Узгоджені з
// kMaxInputFileSize (64 MiB) у SessionHelpers.ipp. Легітимні UA/Дія-контейнери
// (PDF + кілька XML) лежать значно нижче цих порогів.
constexpr std::uint64_t kMaxAsicEntries = 4096;
constexpr std::uint64_t kMaxEntryUncompressedSize = 64ULL * 1024ULL * 1024ULL;   // 64 MiB
constexpr std::uint64_t kMaxTotalUncompressedSize = 256ULL * 1024ULL * 1024ULL;  // 256 MiB
constexpr std::uint64_t kCompressionRatioFloor = 1ULL * 1024ULL * 1024ULL;       // 1 MiB
constexpr std::uint64_t kMaxCompressionRatio = 100;

// HI-05: верхня межа розміру самого стиснутого .asice-файлу, яку
// LoadFromFile перевіряє ДО аллокації буфера під увесь вміст. Значення
// узгоджене з kMaxTotalUncompressedSize (стиснутий контейнер зі стандартним
// deflate не може бути суттєво більшим за суму допустимих uncompressed
// розмірів entries) з запасом на ZIP-накладні витрати.
constexpr std::uint64_t kMaxCompressedContainerSize = 300ULL * 1024ULL * 1024ULL;  // 300 MiB

// true -> ім'я entry небезпечне (traversal/абсолютний шлях/backslash).
bool IsUnsafeEntryName(const std::string& name) {
    if (name.empty()) {
        return true;
    }
    if (name.front() == '/' || name.front() == '\\') {
        return true;  // абсолютний (POSIX) або UNC/Windows-роздільник
    }
    if (name.size() >= 2 && name[1] == ':') {
        return true;  // диск-літера (C:...)
    }
    if (name.find('\\') != std::string::npos) {
        return true;  // ASiC ZIP використовує '/'; backslash -> підозра на обхід
    }
    // Будь-який сегмент шляху, що дорівнює "..", означає вихід за межі контейнера.
    std::size_t start = 0;
    while (true) {
        const std::size_t slash = name.find('/', start);
        const std::size_t end = (slash == std::string::npos) ? name.size() : slash;
        if (name.compare(start, end - start, "..") == 0) {
            return true;
        }
        if (slash == std::string::npos) {
            break;
        }
        start = slash + 1;
    }
    return false;
}

// Перевіряє архів на adversarial-ознаки ПЕРЕД будь-якою розпаковкою.
bool ValidateArchiveSafety(mz_zip_archive& zip, std::string& error_message) {
    const mz_uint num_files = mz_zip_reader_get_num_files(&zip);
    if (num_files > kMaxAsicEntries) {
        error_message = "ASiC container rejected: too many entries (" +
                        std::to_string(num_files) + " > " + std::to_string(kMaxAsicEntries) + ")";
        return false;
    }

    std::unordered_set<std::string> seen_names;
    std::uint64_t total_uncompressed = 0;
    for (mz_uint i = 0; i < num_files; ++i) {
        mz_zip_archive_file_stat stat;
        if (!mz_zip_reader_file_stat(&zip, i, &stat)) {
            error_message = "ASiC container rejected: unreadable entry metadata";
            return false;
        }
        const std::string name(stat.m_filename);

        if (IsUnsafeEntryName(name)) {
            error_message = "ASiC container rejected: unsafe entry name '" + name + "'";
            return false;
        }
        if (!seen_names.insert(name).second) {
            error_message = "ASiC container rejected: duplicate entry name '" + name + "'";
            return false;
        }
        if (stat.m_is_directory) {
            continue;
        }

        const std::uint64_t uncomp = stat.m_uncomp_size;
        const std::uint64_t comp = stat.m_comp_size;
        if (uncomp > kMaxEntryUncompressedSize) {
            error_message = "ASiC container rejected: entry '" + name + "' exceeds the per-entry size limit";
            return false;
        }
        total_uncompressed += uncomp;
        if (total_uncompressed > kMaxTotalUncompressedSize) {
            error_message = "ASiC container rejected: total uncompressed size exceeds the limit";
            return false;
        }
        if (uncomp > kCompressionRatioFloor && comp > 0 && (uncomp / comp) > kMaxCompressionRatio) {
            error_message = "ASiC container rejected: entry '" + name + "' has a suspicious compression ratio (zip bomb)";
            return false;
        }
    }
    return true;
}

}  // namespace

struct AsicReader::Impl {
    mz_zip_archive zip;
    bool initialized{false};
    std::vector<std::uint8_t> buffer;

    Impl() {
        std::memset(&zip, 0, sizeof(zip));
    }

    ~Impl() {
        if (initialized) {
            mz_zip_reader_end(&zip);
        }
    }
};

AsicReader::AsicReader()
    : impl_(new Impl()) {
}

AsicReader::~AsicReader() {
    delete impl_;
}

bool AsicReader::LoadFromBuffer(const std::vector<std::uint8_t>& data, std::string& error_message) {
    if (impl_->initialized) {
        mz_zip_reader_end(&impl_->zip);
        impl_->initialized = false;
    }

    // В-04: прямий буферний вхід обходив перевірку розміру — буфер копіювався
    // цілком ДО будь-яких zip-перевірок, тобто вдвічі більше пам'яті на
    // довільно великий недовірений вміст. Ліміти в `ValidateArchiveSafety`
    // стосуються вже РОЗПАКОВАНОГО вмісту і тут не допомагають: до них треба
    // спершу дожити.
    //
    // Межа — та сама `kMaxCompressedContainerSize`, що й у `LoadFromFile`
    // (HI-05), а не загальний `kMaxInputFileSize`: інакше той самий контейнер
    // поводився б по-різному залежно від того, прийшов він шляхом чи буфером.
    if (static_cast<std::uint64_t>(data.size()) > kMaxCompressedContainerSize) {
        error_message = "ASiC container rejected: buffer too large (" +
                        std::to_string(static_cast<std::uint64_t>(data.size())) + " > " +
                        std::to_string(kMaxCompressedContainerSize) + " bytes)";
        return false;
    }

    impl_->buffer = data;

    if (!mz_zip_reader_init_mem(&impl_->zip, impl_->buffer.data(), impl_->buffer.size(), 0)) {
        error_message = "Failed to initialize ZIP reader from memory buffer";
        return false;
    }

    // WP-8: відхиляємо adversarial-контейнери (zip-bomb / traversal / дублікати)
    // до будь-якої розпаковки, поки рідер відкрито.
    if (!ValidateArchiveSafety(impl_->zip, error_message)) {
        mz_zip_reader_end(&impl_->zip);
        return false;
    }

    impl_->initialized = true;
    return true;
}

bool AsicReader::LoadFromFile(const std::string& filepath, std::string& error_message) {
    try {
        std::ifstream in(std::filesystem::u8path(filepath), std::ios::binary);
        if (!in.is_open()) {
            error_message = "Unable to open file: " + filepath;
            return false;
        }

        in.seekg(0, std::ios::end);
        auto size = in.tellg();
        if (size < 0) {
            error_message = "Invalid file size for: " + filepath;
            return false;
        }
        // HI-05: відхиляємо занадто великий вхідний файл ДО аллокації
        // буфера під увесь його вміст (перед будь-якими ZIP-safety
        // перевірками у ValidateArchiveSafety, які запускаються пізніше).
        if (static_cast<std::uint64_t>(size) > kMaxCompressedContainerSize) {
            error_message = "ASiC container rejected: file too large (" +
                            std::to_string(static_cast<std::uint64_t>(size)) + " > " +
                            std::to_string(kMaxCompressedContainerSize) + " bytes)";
            return false;
        }
        in.seekg(0, std::ios::beg);

        std::vector<std::uint8_t> buffer(static_cast<size_t>(size));
        if (size > 0) {
            // Звуження явне, і воно безпечне саме тому, що `size` уже звірено з
            // `kMaxCompressedContainerSize` вище — інакше тут був би шлях, яким
            // недовірений файл задає довжину читання. На 32-бітній збірці
            // `std::streamsize` — це `int`, тож без цього приведення GCC із
            // `-Wconversion -Werror` відхиляє складання (linux-x86).
            in.read(reinterpret_cast<char*>(buffer.data()),
                    static_cast<std::streamsize>(size));
            if (!in.good()) {
                error_message = "Unable to read file: " + filepath;
                return false;
            }
        }

        return LoadFromBuffer(buffer, error_message);
    } catch (const std::exception& ex) {
        error_message = "Unable to load ASiC file: " + filepath + " (" + ex.what() + ")";
        return false;
    } catch (...) {
        error_message = "Unable to load ASiC file: " + filepath + " (unknown C++ exception)";
        return false;
    }
}

bool AsicReader::GetMimetype(std::string& out_mimetype) const {
    if (!impl_->initialized) {
        return false;
    }

    std::vector<std::uint8_t> data;
    std::string err;
    if (!ExtractFile("mimetype", data, err)) {
        return false;
    }

    out_mimetype.assign(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

bool AsicReader::ExtractFile(const std::string& name, std::vector<std::uint8_t>& out_data, std::string& error_message) const {
    if (!impl_->initialized) {
        error_message = "Reader not initialized";
        return false;
    }

    int file_index = mz_zip_reader_locate_file(&impl_->zip, name.c_str(), nullptr, 0);
    if (file_index < 0) {
        error_message = "File not found in archive: " + name;
        return false;
    }

    size_t size = 0;
    void* p = mz_zip_reader_extract_to_heap(&impl_->zip, static_cast<mz_uint>(file_index), &size, 0);
    if (p == nullptr) {
        error_message = "Failed to extract file: " + name;
        return false;
    }

    // Н-09: власність передається RAII ДО assign, який може кинути.
    MinizHeapBuffer owned(p);
    out_data.assign(static_cast<uint8_t*>(p), static_cast<uint8_t*>(p) + size);
    return true;
}

bool AsicReader::GetFiles(std::vector<AsicFileEntry>& out_files, std::string& error_message) const {
    if (!impl_->initialized) {
        error_message = "Reader not initialized";
        return false;
    }

    out_files.clear();
    mz_uint num_files = mz_zip_reader_get_num_files(&impl_->zip);
    for (mz_uint i = 0; i < num_files; i++) {
        mz_zip_archive_file_stat file_stat;
        if (!mz_zip_reader_file_stat(&impl_->zip, i, &file_stat)) {
            error_message = "Failed to read file stat";
            return false;
        }

        if (file_stat.m_is_directory) {
            continue;
        }

        std::vector<std::uint8_t> data;
        std::string err;
        if (!ExtractFile(file_stat.m_filename, data, err)) {
            error_message = err;
            return false;
        }

        out_files.push_back({file_stat.m_filename, data});
    }

    return true;
}

} // namespace tamga::asic
