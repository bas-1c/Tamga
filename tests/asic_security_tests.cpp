#include "support/FixturePaths.h"
// WP-21 security-regression suite — ASiC ZIP hardening (plan section 6, #3).
//
// Перевіряє adversarial ASiC-контейнери проти AsicReader. Тести стверджують
// БАЖАНУ захищену поведінку (WP-8): zip-bomb, path-traversal та дубльовані
// entry-імена мають відхилятися. Поки WP-8 не реалізовано, AsicReader не має
// таких лімітів, тож цей виконуваний файл повертає ненульовий код і позначений
// у CTest як `WILL_FAIL TRUE` (xfail). Коли WP-8 закриє ці діри, тест почне
// повертати 0 -> CTest впаде -> сигнал зняти xfail-маркер.
//
// Повертає: 0 = усі діри закрито (WP-8 готовий); 1 = ще вразливо (поточний
// стан); 77 = фікстури відсутні (skip).

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "asic/AsicReader.h"

namespace {

constexpr int kSkip = 77;
// Запас на легітимні контейнери; будь-який entry понад це у фікстурі-бомбі
// має відхилятися захищеним рідером.
constexpr std::size_t kSaneUncompressedCap = 20u * 1024u * 1024u;

std::filesystem::path FixturePath(const char* name) {
    return tamga_test::TestDataRoot() / "tests" / "fixtures" / "security" / "asic" / name;
}

bool ReadFile(const std::filesystem::path& path, std::vector<std::uint8_t>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool HasTraversalName(const std::string& name) {
    if (name.empty()) return false;
    if (name.front() == '/' || name.front() == '\\') return true;
    if (name.size() >= 2 && name[1] == ':') return true;  // drive-letter absolute
    if (name.find('\\') != std::string::npos) return true;
    // ".." лише як окремий сегмент шляху (щоб не хибити на "report..pdf").
    std::string component;
    for (const char ch : name) {
        if (ch == '/') {
            if (component == "..") return true;
            component.clear();
        } else {
            component.push_back(ch);
        }
    }
    return component == "..";
}

// true -> захищено (діру закрито); false -> ще вразливо.
bool CheckZipBomb(std::vector<std::uint8_t>& buf) {
    tamga::asic::AsicReader reader;
    std::string err;
    if (!reader.LoadFromBuffer(buf, err)) {
        std::cout << "[zip-bomb] SECURE: container refused at load (" << err << ")\n";
        return true;
    }
    std::vector<tamga::asic::AsicFileEntry> files;
    if (!reader.GetFiles(files, err)) {
        std::cout << "[zip-bomb] SECURE: GetFiles refused oversized container (" << err << ")\n";
        return true;
    }
    for (const auto& f : files) {
        if (f.data.size() > kSaneUncompressedCap) {
            std::cout << "[zip-bomb] VULNERABLE: extracted entry '" << f.name << "' of "
                      << f.data.size() << " bytes without an uncompressed-size limit\n";
            return false;
        }
    }
    std::cout << "[zip-bomb] SECURE: no entry exceeded the uncompressed cap\n";
    return true;
}

bool CheckTraversal(std::vector<std::uint8_t>& buf) {
    tamga::asic::AsicReader reader;
    std::string err;
    if (!reader.LoadFromBuffer(buf, err)) {
        std::cout << "[traversal] SECURE: container refused at load (" << err << ")\n";
        return true;
    }
    std::vector<tamga::asic::AsicFileEntry> files;
    if (!reader.GetFiles(files, err)) {
        std::cout << "[traversal] SECURE: GetFiles refused traversal entries (" << err << ")\n";
        return true;
    }
    bool vulnerable = false;
    for (const auto& f : files) {
        if (HasTraversalName(f.name)) {
            std::cout << "[traversal] VULNERABLE: exposed unsafe entry name '" << f.name << "'\n";
            vulnerable = true;
        }
    }
    if (!vulnerable) std::cout << "[traversal] SECURE: no unsafe entry names exposed\n";
    return !vulnerable;
}

bool CheckDuplicates(std::vector<std::uint8_t>& buf) {
    tamga::asic::AsicReader reader;
    std::string err;
    if (!reader.LoadFromBuffer(buf, err)) {
        std::cout << "[duplicates] SECURE: container refused at load (" << err << ")\n";
        return true;
    }
    std::vector<tamga::asic::AsicFileEntry> files;
    if (!reader.GetFiles(files, err)) {
        std::cout << "[duplicates] SECURE: GetFiles refused duplicate entries (" << err << ")\n";
        return true;
    }
    std::size_t dup_count = 0;
    for (std::size_t i = 0; i < files.size(); ++i) {
        for (std::size_t j = i + 1; j < files.size(); ++j) {
            if (files[i].name == files[j].name) ++dup_count;
        }
    }
    if (dup_count > 0) {
        std::cout << "[duplicates] VULNERABLE: " << dup_count
                  << " duplicate entry name(s) accepted without detection\n";
        return false;
    }
    std::cout << "[duplicates] SECURE: duplicate entry names rejected/deduplicated\n";
    return true;
}

}  // namespace

int main() {
    struct Case {
        const char* fixture;
        bool (*check)(std::vector<std::uint8_t>&);
    };
    const Case cases[] = {
        {"zipbomb.zip", &CheckZipBomb},
        {"traversal.zip", &CheckTraversal},
        {"duplicate-entries.zip", &CheckDuplicates},
    };

    bool all_secure = true;
    for (const auto& c : cases) {
        std::vector<std::uint8_t> buf;
        if (!ReadFile(FixturePath(c.fixture), buf)) {
            std::cerr << "Skipping ASiC security suite: missing fixture " << c.fixture << '\n';
            return kSkip;
        }
        all_secure &= c.check(buf);
    }

    if (all_secure) {
        std::cout << "ASiC hardening complete: all adversarial containers rejected.\n";
        return EXIT_SUCCESS;
    }
    std::cout << "ASiC hardening pending (WP-8): adversarial containers still accepted.\n";
    return EXIT_FAILURE;
}
