// Хвиля 8, п.2: єдиний DER-декодер і доказ, що консолідація не косметична.
//
// Аудит зафіксував С-06 як КЛАС помилки, а не як окремий дефект: переповнення
// `offset + length <= limit` виправили в одній копії парсера з чотирьох.
// Перевірка дерева підтвердила діагноз — дві інші копії (`Names.cpp`,
// `CertificateChainValidator.cpp`) дослівно містили ту саму вразливу форму
// `offset + value_len > total_size`.
//
// Тест перевіряє дві речі:
//   1) єдиний парсер `util::ParseDerLength` відхиляє переповнення;
//   2) стара форма перевірки на тих самих даних його ПРОПУСКАЛА — інакше
//      неможливо стверджувати, що тест щось доводить.
//
// Другий пункт принциповий. Тест, зелений і до, і після виправлення, нічого
// не доводить — цей висновок уже зафіксовано в С-07, С-16 і Н-04.

#include "util/Der.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void Check(const bool condition, const std::string& what) {
    if (!condition) {
        std::cerr << "FAIL: " << what << '\n';
        ++g_failures;
    }
}

// Довга форма довжини: 0x88 = 8 наступних байтів кодують довжину.
// Значення підібране так, щоб `value_offset + length` переповнилося.
std::vector<std::uint8_t> BuildOverflowingLengthTlv() {
    std::vector<std::uint8_t> der;
    der.push_back(0x04);  // OCTET STRING
    der.push_back(0x88);  // довга форма, 8 байтів довжини
    // SIZE_MAX - 4: сума з невеликим зсувом переповнюється й дає маленьке число.
    const std::size_t huge = std::numeric_limits<std::size_t>::max() - 4U;
    for (int shift = 56; shift >= 0; shift -= 8) {
        der.push_back(static_cast<std::uint8_t>((static_cast<std::uint64_t>(huge) >> shift) & 0xFFU));
    }
    der.resize(der.size() + 16U, 0xAA);  // трохи «вмісту», щоб буфер був реальним
    return der;
}

void TestOverflowRejected() {
    // B-03: `if constexpr`, а не `if`. Умова залежить лише від розрядності,
    // тобто відома на компіляції — і MSVC на раннері (windows-2022) видає на
    // неї `C4127: conditional expression is constant`, що під `/WX` валить
    // три Windows-джоби. Локальний MSVC 19.51 цього попередження не дає, тож
    // дефект був видимий ЛИШЕ в CI.
    if constexpr (sizeof(std::size_t) < 8U) {
        // На 32-бітній збірці 8-байтова довжина відхиляється раніше — за
        // `count > sizeof(size_t)`. Це теж коректно, але доказ переповнення
        // тут будується інакше, тож сценарій пропускаємо явно.
        std::cout << "  (32-bit: сценарій 8-байтової довжини не застосовний)\n";
        return;
    }

    const std::vector<std::uint8_t> der = BuildOverflowingLengthTlv();

    std::size_t offset = 1U;  // одразу за тегом
    std::size_t length = 0U;
    const bool accepted = tamga::util::ParseDerLength(der.data(), der.size(), offset, length);
    Check(!accepted, "ParseDerLength мусить відхилити довжину, що переповнює межу");

    // Негативний контроль: та сама перевірка у СТАРІЙ формі пропускала ці дані.
    // Відтворюємо її буквально, щоб довести, що вхід справді небезпечний,
    // а не просто «якийсь невалідний DER».
    std::size_t legacy_offset = 1U;
    std::size_t legacy_length = 0U;
    {
        const std::uint8_t first = der[legacy_offset++];
        const std::size_t count = first & 0x7FU;
        for (std::size_t i = 0; i < count; ++i) {
            legacy_length = (legacy_length << 8U) | der[legacy_offset++];
        }
    }
    // Ось вона, вразлива форма: сума переповнюється по модулю 2^N.
    const bool legacy_accepted = (legacy_offset + legacy_length) <= der.size();
    Check(legacy_accepted,
          "негативний контроль: стара форма `offset + length <= limit` мусила ПРОПУСКАТИ "
          "цей вхід — інакше тест не доводить, що дефект був реальним");

    if (legacy_accepted) {
        std::cout << "  негативний контроль: стара форма прийняла довжину "
                  << legacy_length << " у буфері на " << der.size() << " байтів\n";
    }
}

void TestShortFormBounds() {
    // Коротка форма, що виходить за межу: 0x04 0x10 і лише 2 байти вмісту.
    const std::vector<std::uint8_t> der = {0x04, 0x10, 0xAA, 0xBB};
    std::size_t offset = 1U;
    std::size_t length = 0U;
    Check(!tamga::util::ParseDerLength(der.data(), der.size(), offset, length),
          "коротка форма поза межами буфера мусить відхилятися");
}

void TestWellFormed() {
    // 0x04 0x03 AA BB CC — коректний OCTET STRING на 3 байти.
    const std::vector<std::uint8_t> der = {0x04, 0x03, 0xAA, 0xBB, 0xCC};
    tamga::util::TlvView view{};
    Check(tamga::util::ParseTlvAt(der, 0U, view), "коректний TLV мусить розбиратися");
    Check(view.tag == 0x04, "тег");
    Check(view.value_offset == 2U, "зсув значення");
    Check(view.value_length == 3U, "довжина значення");
    Check(view.next_offset == 5U, "зсув наступного TLV");
}

void TestNestedLimitRespected() {
    // Вкладений TLV не має права вийти за межу зовнішнього значення, навіть
    // якщо в буфері далі є ще байти.
    const std::vector<std::uint8_t> der = {
        0x30, 0x03, 0x04, 0x05, 0xAA,  // SEQUENCE(3) { OCTET STRING заявляє 5 }
        0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // байти поза зовнішнім значенням
    };
    tamga::util::TlvView outer{};
    Check(tamga::util::ParseTlvAt(der, 0U, outer), "зовнішній SEQUENCE розбирається");

    tamga::util::TlvView inner{};
    Check(!tamga::util::ParseTlvAt(der, outer.value_offset, outer.next_offset, inner),
          "вкладений TLV, що виходить за межу зовнішнього, мусить відхилятися");

    // Без обмеження межею той самий вхід проходить — доказ, що параметр `limit`
    // справді працює, а не ігнорується.
    tamga::util::TlvView unbounded{};
    Check(tamga::util::ParseTlvAt(der, outer.value_offset, der.size(), unbounded),
          "без обмеження межею той самий TLV розбирається — параметр limit значущий");
}

void TestLengthOfLengthRejected() {
    // count == 0 (0x80, indefinite length) неприпустимий у DER.
    const std::vector<std::uint8_t> indefinite = {0x04, 0x80, 0xAA};
    std::size_t offset = 1U;
    std::size_t length = 0U;
    Check(!tamga::util::ParseDerLength(indefinite.data(), indefinite.size(), offset, length),
          "невизначена довжина (0x80) неприпустима в DER");

    // count > sizeof(size_t) — свідомо завелика кількість байтів довжини.
    const std::vector<std::uint8_t> too_many = {0x04, 0x8F, 0xAA, 0xBB};
    offset = 1U;
    length = 0U;
    Check(!tamga::util::ParseDerLength(too_many.data(), too_many.size(), offset, length),
          "кількість байтів довжини понад sizeof(size_t) мусить відхилятися");
}

void TestEmptyAndNull() {
    tamga::util::TlvView view{};
    const std::vector<std::uint8_t> empty;
    Check(!tamga::util::ParseTlvAt(empty, 0U, view), "порожній буфер");

    std::size_t offset = 0U;
    std::size_t length = 0U;
    Check(!tamga::util::ParseDerLength(nullptr, 10U, offset, length), "nullptr");
}


// Сторожа КЛАСУ: саморобний розбір довжини DER поза `util/Der.cpp`.
//
// Ця перевірка зʼявилася тому, що консолідація в п.2 була НЕПОВНОЮ, і
// виявив це не тест, а випадкове читання коду. Той пошук вівся командою з
// `--include=*.cpp --include=*.h`, тобто файли `.ipp` до нього не потрапили —
// а саме там жила третя копія (`SessionHelpers.ipp`), причому з тією самою
// вразливою формою. Пізніше знайшлися ще дві (`PadesVerifier`,
// `CertificateFetcher`).
//
// Правило: довга форма довжини DER розбирається лише в `util/Der.cpp`.
// Ознака — маска `0x7F` над байтом довжини поруч із перевіркою `0x80`.
void TestDerLengthParsedInOnePlaceOnly() {
    namespace fs = std::filesystem;
    const fs::path lib_root = fs::path(TAMGA_TEST_SOURCE_DIR) / "src" / "lib";
    const fs::path single_source = lib_root / "util" / "Der.cpp";

    std::error_code ec;
    if (!fs::exists(lib_root, ec)) {
        Check(false, "не знайдено src/lib — сторожа не може виконати свою роботу");
        return;
    }

    std::size_t inspected = 0;
    std::size_t hits_in_single_source = 0;
    for (const auto& entry : fs::recursive_directory_iterator(lib_root)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const fs::path& path = entry.path();
        const std::string ext = path.extension().string();
        if (ext != ".cpp" && ext != ".h" && ext != ".hpp" && ext != ".ipp") {
            continue;
        }
        ++inspected;
        const bool is_single_source = fs::equivalent(path, single_source, ec) && !ec;

        std::ifstream source(path, std::ios::binary);
        std::string line;
        std::size_t line_no = 0;
        bool saw_high_bit_test = false;
        while (std::getline(source, line)) {
            ++line_no;
            const auto first = line.find_first_not_of(" \t");
            const bool is_comment = first != std::string::npos &&
                                    (line.compare(first, 2, "//") == 0 || line[first] == '*');
            if (is_comment) {
                continue;
            }
            // Перевірка старшого біта байта довжини — перша половина патерну.
            if (line.find("& 0x80") != std::string::npos) {
                saw_high_bit_test = true;
                continue;
            }
            // Друга половина: маска 0x7F, що дає кількість байтів довжини.
            const bool masks_low_seven =
                line.find("& 0x7F") != std::string::npos;
            if (!masks_low_seven || !saw_high_bit_test) {
                continue;
            }
            if (is_single_source) {
                ++hits_in_single_source;
                continue;
            }
            Check(false, "саморобний розбір довжини DER поза util/Der.cpp: " +
                             path.filename().string() + ":" + std::to_string(line_no));
        }
    }

    Check(inspected != 0, "не переглянуто жодного файлу — сторожа вакуумна");
    Check(hits_in_single_source != 0,
          "у util/Der.cpp не знайдено розбору довжини — перевірка недостовірна");
}

}  // namespace

int main() {
    TestOverflowRejected();
    TestShortFormBounds();
    TestWellFormed();
    TestNestedLimitRespected();
    TestLengthOfLengthRejected();
    TestEmptyAndNull();
    TestDerLengthParsedInOnePlaceOnly();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "DER parsing tests passed\n";
    return 0;
}
