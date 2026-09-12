#pragma once

// Спільна інфраструктура тестів (Хвиля 8, п.5 — тестовий моноліт).
//
// `tests/tamga_tests.cpp` — одна одиниця трансляції на 12 535 рядків, у якій
// **усі 224 тестові функції лежать в одному анонімному namespace**. Через це
// ніщо з нього не можна винести: ні тести, ні хелпери не видно ззовні файлу.
// Це та сама причина, що описана в ADR-027 для `src/lib`, лише в тестах.
//
// Цей заголовок — перший сім. Він виносить шар підтримки (лічильники,
// ExpectTrue/ExpectFalse, фікстурні хелпери) так, щоб тематичні групи тестів
// могли переїжджати у власні файли поодинці, а не одним ризикованим кроком.
//
// ІНВАРІАНТ РОЗКОЛУ: після кожного переносу бінарник мусить виконувати ТІ САМІ
// тести в ТОМУ САМОМУ порядку. Кожен тест друкує `Running <name>`, тож список
// цих рядків до і після — це доказ, що жодного тесту не загублено. Перевіряти
// саме його, а не «ctest зелений»: мовчазна втрата тесту зеленому ctest не
// заважає.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "types.h"
#include "core/Session.h"
#include "core/policy/TrustListSettings.h"
#include "nativeapi/TamgaAddIn.h"

namespace tamga_tests {

// --- облік результатів -----------------------------------------------------
extern int g_failures;
extern int g_skips;

// С-16: пропущений тест раніше просто друкував [SKIP] і мовчки повертався —
// CTest бачив Passed. Baseline — кількість пропусків, яка вважається відомою
// і прийнятною; її перевищення робить прогін невдалим. Значення виміряне, а не
// вгадане: постачальна конфігурація — 1, базова — 1, vendor=OFF — 7.
//
// Хвиля 8, п.1 (залишок): 6 -> 7. Доданий `TestReportJsonSharedSectionsAgree`
// звіряє два звіти після СПРАВЖНЬОЇ перевірки підпису, тож без cryptonite
// йому нема на чому працювати. Гейт спрацював як задумано: новий пропуск не
// проліз мовчки, а зажадав явного рішення.
//
// П-03: 7 -> 8. Доданий `TestCadesAsicECoverageRejectsUnsignedEntry` мусить
// СПРАВДІ підписати документ, щоб довести, що непокритий запис відхиляється
// попри валідний підпис, — інакше він доводив би лише те, що невалідний
// контейнер відхиляється, а це інше твердження. Без cryptonite підписати
// нема чим. Гейт удруге спрацював як задумано: прогін vendor=OFF став
// червоним і зажадав цього рядка.
//
// Р-1: 8 -> 9. Доданий `TestAsicSRejectsMultipleDataObjects` теж мусить СПРАВДІ
// підписати документ: він доводить, що контейнер із зайвим файлом відхиляється
// попри ВАЛІДНИЙ підпис. Без cryptonite підписати нема чим.
inline constexpr int kExpectedMaxSkips = 9;

void RecordSkip(const std::string& reason);
void ExpectTrue(bool condition, const char* message);
void ExpectFalse(bool condition, const char* message);

// --- дрібні предикати ------------------------------------------------------
bool Contains(const std::string& haystack, const std::string& needle);
bool IsValidJson(const std::string& input);
std::string EscapeJson(const std::string& value);

// --- фікстури й тимчасові файли --------------------------------------------
std::filesystem::path FixturePath(const std::string& relative_path);
std::vector<std::uint8_t> ReadBinaryFixture(const std::filesystem::path& path);
std::filesystem::path MakeTemporaryFixturePath(const std::string& suffix);
bool WriteBinaryFile(const std::filesystem::path& path, const std::vector<std::uint8_t>& data);
std::size_t CountCerFilesForTest(const std::filesystem::path& dir);

// --- розбір DER у тестах ---------------------------------------------------
// Власний walker: тести навмисно не спираються на `util::ParseTlvAt`, щоб
// перевірка не використовувала той самий код, який перевіряє.
struct TestTlvView {
    std::uint8_t tag{0};
    std::size_t value_offset{0};
    std::size_t value_length{0};
    std::size_t next_offset{0};
};

bool ParseTestDerLength(const std::vector<std::uint8_t>& data, std::size_t& offset,
                        std::size_t& length);
bool ParseTestTlvAt(const std::vector<std::uint8_t>& data, std::size_t offset, TestTlvView& out);
std::string HexForTest(const std::uint8_t* data, std::size_t size);
std::string ExtractDerCertificateSerialHexForTest(const std::vector<std::uint8_t>& certificate_der);
std::string ExtractPemCertificatePayloadForTest(const std::vector<std::uint8_t>& pem_blob);

// --- побудова тестових артефактів ------------------------------------------
std::vector<std::uint8_t> MakeMinimalPdf(const std::string& marker);
std::string ExtractArchiveTimeStampTokenForTest(const std::string& signed_xml);
std::string ReplaceArchiveTimeStampTokenForTest(const std::string& signed_xml,
                                                const std::string& new_token_b64);
std::string StripX509CertificateForTest(const std::string& signed_xml);
std::vector<std::uint8_t> BuildTrustListXmlForTest(const std::string& service_type,
                                                   const std::string& status,
                                                   const std::vector<std::uint8_t>& custom_cert_der = {});
std::vector<std::uint8_t> BuildGrantedCaTrustListXmlForTest(
    const std::vector<std::uint8_t>& custom_cert_der = {});

// --- NativeAPI-хелпери -----------------------------------------------------
long FindMethod(tamga::nativeapi::TamgaAddIn& addin, const std::wstring& name);
bool CallNoArgs(tamga::nativeapi::TamgaAddIn& addin, long method, tVariant& ret);
bool PrepareInitializedSession(tamga::core::Session& session);


// --- додаткові асерції -----------------------------------------------------
// Перенесені з моноліту разом із першими групами тестів: без них жодна
// група, що ними користується, переїхати не може.
void ExpectContains(const std::string& haystack, const std::string& needle, const char* message);
void ExpectContainsValue(const std::vector<std::string>& values, const std::string& expected, const char* message);
void ExpectNotContainsValue(const std::vector<std::string>& values, const std::string& unexpected, const char* message);
void ExpectValidJson(const std::string& json, const char* message);
void ExpectInvalidJson(const std::string& json, const char* message);
void ExpectSessionTrue(tamga::core::Session& session, const bool condition, const char* message);
void ExpectSummary(const tamga::core::VerifyReport& report, const char* expected, const char* message);
void ExpectPolicyDecision(const tamga::core::VerifyReport& report, const bool expected_valid, const char* expected_level, const char* expected_summary, const char* message);
void ExpectDefaultString(tamga::nativeapi::TamgaAddIn& addin, long method, long param, const std::wstring& expected, const char* message);
void ExpectDefaultInt32(tamga::nativeapi::TamgaAddIn& addin, long method, long param, std::int32_t expected, const char* message);
void ExpectDefaultBool(tamga::nativeapi::TamgaAddIn& addin, long method, long param, bool expected, const char* message);


// --- важкі фікстури --------------------------------------------------------
// Генерація ключової пари ДСТУ, mock-TSA, CRL і завантаження пари для
// резолвера. Переїхали сюди разом із групами тестів, які ними користуються.
class TestMemoryManager final : public IMemoryManager {
public:
    bool ADDIN_API AllocMemory(void** pMemory, unsigned long ulCountByte) override {
        if (pMemory == nullptr) {
            return false;
        }
        if (ulCountByte == 0) {
            ulCountByte = 1;
        }
        *pMemory = std::malloc(ulCountByte);
        return *pMemory != nullptr;
    }

    void ADDIN_API FreeMemory(void** pMemory) override {
        if (pMemory != nullptr && *pMemory != nullptr) {
            std::free(*pMemory);
            *pMemory = nullptr;
        }
    }
};

struct DstuFixture {
    std::vector<std::uint8_t> pkcs12_blob;
    std::vector<std::uint8_t> cert_der;
    bool valid{false};
};

#if TAMGA_CRYPTONITE_ENABLED
DstuFixture GenerateDstuFixture();
// ПД-01: та сама фікстура, але з extendedKeyUsage id-kp-timeStamping —
// для тестів, які перевіряють ПОВНИЙ вердикт канонічного TimestampEngine.
DstuFixture GenerateDstuTsaFixture();
bool MockTsaTimestamp(const DstuFixture& fixture, const std::vector<std::uint8_t>& tbs, std::vector<std::uint8_t>& token_out, std::string& error);
bool GenerateGoodCrlForTest(const DstuFixture& fixture, std::vector<std::uint8_t>& crl_der_out, std::string& error);
bool LoadResolverKeyPair(std::vector<std::uint8_t>& key_container, std::vector<std::uint8_t>& cert_der, std::string& password);
#endif  // TAMGA_CRYPTONITE_ENABLED

tamga::core::TrustListSettings MechanicsOnlyTrustListSettings();
std::vector<std::uint8_t> BuildSyntheticAiaDerForTest(const std::string& url);

// V-06: фікстура "голого" PKCS#8 разом із сертифікатом, що йому відповідає.
//
// Навіщо окрема від GenerateDstuFixture: та будує ключ усередині PKCS#12, тож
// гілка PKCS#8 у ExtractSpkiFromKeyContainer не виконувалась у тестах ЖОДНОГО
// разу. Саме через це дефект «SPKI непорівнянний із сертифікатом» дожив до
// ручної перевірки на живому JKS — а JKS після нормалізації дає рівно такий
// самий "голий" PKCS#8, як тут.
struct DstuPkcs8Fixture {
    std::vector<std::uint8_t> pkcs8_der;
    std::vector<std::uint8_t> cert_der;
    bool valid{false};
};

#if TAMGA_CRYPTONITE_ENABLED
DstuPkcs8Fixture GenerateDstuPkcs8Fixture();
std::vector<std::uint8_t> CreateTstInfoDer(const std::vector<std::uint8_t>& imprint_hash,
                                           const std::string& gen_time_str,
                                           const std::string& hash_algorithm_oid = "1.2.804.2.1.1.1.1.2.2.1");
bool GenerateMockTspToken(const std::vector<std::uint8_t>& key_material,
                          const std::vector<std::uint8_t>& certificate_der,
                          const std::vector<std::uint8_t>& tst_info_der,
                          std::vector<std::uint8_t>& out_token_der);
#endif  // TAMGA_CRYPTONITE_ENABLED

} // namespace tamga_tests
