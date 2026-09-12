#include "util/FileSystem.h"

#include <atomic>
#include <fstream>
#include <limits>
#include <string>
#include <system_error>

#if defined(_WIN32)
// GetCurrentProcessId
#else
#include <unistd.h>
#endif

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace tamga::util {
// ADR-027: винесено з анонімного namespace — копія цієї функції жила ще
// в `core/policy/PolicyCache.cpp`. Тіла збігалися.
std::filesystem::path PathWithSuffix(std::filesystem::path path, const char* suffix) {
    path += suffix;
    return path;
}

std::string PathToUtf8(const std::filesystem::path& path) {
    const auto value = path.u8string();
#if defined(__cpp_char8_t)
    return std::string(reinterpret_cast<const char*>(value.data()), value.size());
#else
    return value;
#endif
}

namespace {

// Унікальне ім'я тимчасового файлу поруч із ціллю.
//
// Фіксований `<target>.tmp` був передбачуваним: два процеси, що пишуть один
// цільовий файл, зустрічалися на одному тимчасовому імені. Pid розводить
// процеси, лічильник — потоки й послідовні виклики в одному процесі.
// Це не заміна файловому блокуванню (одночасний запис ОДНІЄЇ цілі двома
// процесами і далі лишає невизначеним, чий вміст переможе), але кожен із них
// тепер пише СВОЇ байти і заміщує ціль цілим файлом, а не змішаним.
std::filesystem::path MakeUniqueTempPath(const std::filesystem::path& final_path) {
    static std::atomic<unsigned long long> counter{0};
#if defined(_WIN32)
    const unsigned long long pid = static_cast<unsigned long long>(GetCurrentProcessId());
#else
    const unsigned long long pid = static_cast<unsigned long long>(getpid());
#endif
    const unsigned long long serial = counter.fetch_add(1, std::memory_order_relaxed);
    const std::string suffix = ".tmp." + std::to_string(pid) + "." + std::to_string(serial);
    return PathWithSuffix(final_path, suffix.c_str());
}

}  // namespace

AtomicWriteResult WriteBytesAtomic(const std::filesystem::path& final_path,
                                   const void* data,
                                   const std::size_t size) {
    if (final_path.empty()) {
        return {AtomicWriteStatus::TargetUnusable, "output path is empty"};
    }

    std::error_code ec;
    // Каталог створюємо ЛИШЕ якщо він непорожній. Для голого відносного імені
    // (`out.asics`) `parent_path()` порожній, і безумовний
    // `create_directories("")` виставляв `ec` — тобто запис у поточний каталог
    // падав ще до відкриття файлу. Саме через це `RawSignFile` був єдиним
    // користувачем цього хелпера: решта місць приймає імена від користувача.
    const std::filesystem::path parent = final_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return {AtomicWriteStatus::TargetUnusable,
                    "unable to create output directory: " + ec.message()};
        }
    }

    const std::filesystem::path temp_path = MakeUniqueTempPath(final_path);
    std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return {AtomicWriteStatus::TargetUnusable, "unable to create temporary output file"};
    }
    if (size > 0 && data != nullptr) {
        out.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
    }
    const bool written = out.good();
    out.close();
    if (!written || !out.good()) {
        std::filesystem::remove(temp_path, ec);
        return {AtomicWriteStatus::WriteFailed, "failed writing temporary output file"};
    }

#ifdef _WIN32
    if (MoveFileExW(temp_path.wstring().c_str(),
                    final_path.wstring().c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        std::filesystem::remove(temp_path, ec);
        return {AtomicWriteStatus::WriteFailed, "failed to replace output file"};
    }
#else
    std::filesystem::rename(temp_path, final_path, ec);
    if (ec) {
        const std::string message = "failed to replace output file: " + ec.message();
        std::error_code cleanup_ec;
        std::filesystem::remove(temp_path, cleanup_ec);
        return {AtomicWriteStatus::WriteFailed, message};
    }
#endif
    return {};
}

bool WriteBinaryFileAtomic(const std::filesystem::path& final_path, const std::vector<std::uint8_t>& data) {
    return static_cast<bool>(WriteBytesAtomic(final_path, data.data(), data.size()));
}

bool WriteTextFileAtomic(const std::filesystem::path& final_path, const std::string& text) {
    return static_cast<bool>(WriteBytesAtomic(final_path, text.data(), text.size()));
}

namespace {

// Спільна реалізація для двійкового і текстового читання: різниця лише в
// типі контейнера, а політика ліміту мусить бути одна.
template <typename Container>
bool ReadLimited(const std::filesystem::path& path, const std::uintmax_t max_size,
                 Container& out, std::string& error_message) {
    out.clear();
    error_message.clear();

    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    const bool size_known = !ec;
    if (size_known && size > max_size) {
        error_message = "input exceeds the maximum supported size";
        return false;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        error_message = "unable to open input file";
        return false;
    }

    // O-01: розмір уже перевірено вище, тож резервуємо його ОДИН раз замість
    // того, щоб дати контейнеру намацати місткість геометричним ростом.
    //
    // Вимірювання (проба рахувала виклики `operator new` від 64 KiB, файл
    // 16 777 216 байтів): без резервування — 14 великих алокацій, сумарно
    // 50 822 274 байти, найбільша 17 006 151. Це сума виділених за виклик
    // буферів, а не пікова RSS. Обіцянок щодо часу тут немає: час не мірявся.
    //
    // Резервуємо лише для звичайного файла: у каналу чи символьного пристрою
    // `file_size` не має визначеного значення, і довіряти йому як місткості
    // не можна. Порожній файл пропускаємо — резервувати нічого.
    std::error_code kind_ec;
    if (size_known && size > 0 && std::filesystem::is_regular_file(path, kind_ec) && !kind_ec) {
        constexpr auto kSizeMax = static_cast<std::uintmax_t>((std::numeric_limits<std::size_t>::max)());
        out.reserve(static_cast<std::size_t>(size < kSizeMax ? size : kSizeMax));
    }

    // Читання порціями з повторною перевіркою межі: `file_size` вище — лише
    // підказка, а не гарантія, і резервування її не робить гарантією. Файл міг
    // вирости між stat і read (або взагалі не мати визначеного розміру, як
    // іменований канал), тож ліміт має триматися й на самому потоці.
    constexpr std::size_t kChunk = 64 * 1024;
    char buffer[kChunk];
    while (in) {
        in.read(buffer, static_cast<std::streamsize>(kChunk));
        const auto got = static_cast<std::size_t>(in.gcount());
        if (got == 0) {
            break;
        }
        if (out.size() + got > max_size) {
            out.clear();
            error_message = "input exceeds the maximum supported size";
            return false;
        }
        out.insert(out.end(), buffer, buffer + got);
    }

    if (in.bad()) {
        out.clear();
        error_message = "input file read failed";
        return false;
    }
    return true;
}

}  // namespace

bool ReadBinaryFileLimited(const std::filesystem::path& path, const std::uintmax_t max_size,
                           std::vector<std::uint8_t>& out, std::string& error_message) {
    return ReadLimited(path, max_size, out, error_message);
}

bool ReadTextFileLimited(const std::filesystem::path& path, const std::uintmax_t max_size,
                         std::string& out, std::string& error_message) {
    return ReadLimited(path, max_size, out, error_message);
}

} // namespace tamga::util
