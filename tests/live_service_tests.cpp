// Живі перевірки OCSP і TSP — окремо від довірчого списку (п.19 аудиту
// 2026-08-29, продовження Хвилі 8 п.6).
//
// НАВІЩО ОКРЕМА ЦІЛЬ ВІД `live_policy_tests.cpp`. Та сюїта доводить, що ми
// коректно БЕРЕМО довіру з ЦЗО. Вона нічого не каже про найдовший шлях
// відмови: «довірчий список синхронізувався, а сервіс за адресою З НЬОГО не
// відповідає або відповідає інакше». Саме цей шлях не мав жодного тригера.
//
// Тести тут — ОКРЕМІ від TL-перевірки навмисно: кожен із них осмислений і
// тоді, коли TL-перевірку пропущено, і кожен дає виразний діагноз, коли
// адресу взяти нема звідки.
//
// СЕМАНТИКА РЕЗУЛЬТАТУ — та сама, що в `docs/live-replay-suite-dod.md`:
//
//   * сервіс НЕ відповів (або адреси нема звідки взяти) -> код 77,
//     CTest показує `Skipped`. Це не провал: сюїта перевіряє НАШУ поведінку,
//     а не аптайм КНЕДП;
//   * сервіс ВІДПОВІВ, а ми обробили відповідь неправильно -> код 1,
//     CTest показує `Failed`. Провал зарезервовано рівно за цим випадком;
//   * усе гаразд -> код 0.
//
// Сюїта, що червоніє від чужої недоступності, починає ігноруватися — і тоді
// вона гірша за відсутню. Це не стилістика, а причина, через яку кожен
// ранній вихід нижче повертає саме 77.
//
// ЖОДНОГО ОЧІКУВАНОГО ЧИСЛА Й ЖОДНОЇ ЗАШИТОЇ АДРЕСИ. Адреса OCSP береться з
// сервісного запису довірчого списку, адреса TSP — з
// `PolicyCache::ResolveGrantedTspUrl()`. Саме тому мок-транспорт може
// підмінити їх цілком, а оновлення списку на боці ЦЗО нічого тут не ламає.
//
// REPLAY-ДВІЙНИК (правило 3 DoD). Режими `replay-ocsp` і `replay-tsp` женуть
// ТУ САМУ логіку перевірки на детермінованому мок-транспорті, без мережі.
// Живий тест ловить зміни на боці сервісу; двійник ловить регресії в нас,
// зокрема тоді, коли сервіс недоступний і живе покриття зникає разом із ним.
//
// Ручні сценарії (не реєструються в CTest, бо два з трьох мусять бути
// «червоними» за побудовою — вони існують, щоб довести, що семантика
// результату справді працює):
//
//   TAMGA_LIVE_MOCK=good    tamga-live-service-tests tsp   -> 0  (Passed)
//   TAMGA_LIVE_MOCK=bad     tamga-live-service-tests tsp   -> 1  (Failed)
//   TAMGA_LIVE_MOCK=outage  tamga-live-service-tests tsp   -> 77 (Skipped)
//   TAMGA_LIVE_MOCK=good    tamga-live-service-tests ocsp  -> 77 (Skipped, див. нижче)
//   TAMGA_LIVE_MOCK=bad     tamga-live-service-tests ocsp  -> 1  (Failed)
//   TAMGA_LIVE_MOCK=outage  tamga-live-service-tests ocsp  -> 77 (Skipped)
//
// ВІДОМА МЕЖА мок-транспорту для OCSP. Позитивної ПІДПИСАНОЇ OCSP-відповіді
// («цей сертифікат good, ось підпис респондера») цей набір не синтезує — це
// свідомий обсяг, а не встановлений блокер: схоже, що локальний респондер
// збирається з наявних `eocspresp_alloc`/`eocspresp_generate` і фікстурного
// ключа, але це НЕ ПЕРЕВІРЕНО. Тому `TAMGA_LIVE_MOCK=good ocsp` віддає
// `unauthorized` — і це закономірно ПРОПУСК, а не успіх: респондер відмовився
// відповідати по суті.
// Позитивне відображення статусів (`good`/`revoked`/`unknown` і чужий CertID)
// перевіряється детерміновано в `replay-ocsp` — на тому самому шарі
// `MapOcspStatusForRequestedCertId`, який ухвалює це рішення в продакшні.
//
// Ціль не входить у типовий набір: реєструється лише при
// `-DTAMGA_ENABLE_LIVE_POLICY_TESTS=ON`.

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#include "core/HttpClient.h"
#include "core/TspClient.h"
#include "core/policy/ImprintDigest.h"
#include "core/policy/OcspValidator.h"
#include "core/policy/PolicyCache.h"
#include "core/policy/PolicyTypes.h"
#include "core/policy/TimestampValidator.h"
#include "core/policy/TrustListParser.h"
#include "core/policy/TrustListSettings.h"
#include "core/policy/TrustListSync.h"
#include "core/validation/TimestampEngine.h"

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "byte_array.h"
#include "cert.h"
#include "oids.h"
#include "pkix_utils.h"
#include "ExtendedKeyUsage.h"
}
#include "core/cryptonite/CertUtil.h"
#include "core/policy/EkuUtils.h"
#include "support/TestSupport.h"
#endif

namespace fs = std::filesystem;

namespace {

constexpr int kSkip = 77;
constexpr int kFail = 1;
constexpr int kUsage = 2;

int g_failures = 0;

void Check(const bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        ++g_failures;
    }
}

// Єдина точка виходу «пропущено». Причина ЗАВЖДИ друкується: пропуск, якого
// не видно, — це та сама брехня, що й зелений прогін на старих бінарниках
// (правило 2 DoD).
int Skip(const std::string& reason) {
    std::cerr << "\nПРОПУЩЕНО (код " << kSkip << "): " << reason << "\n"
              << "Це НЕ провал. Провал тут означав би, що сервіс відповів, а ми\n"
              << "обробили відповідь неправильно. Див. docs/live-replay-suite-dod.md.\n";
    return kSkip;
}

int Finish(const char* suite) {
    if (g_failures != 0) {
        std::cerr << "\n" << suite << ": " << g_failures << " failure(s)\n";
        return kFail;
    }
    std::cout << suite << ": усі інваріанти виконано\n";
    return 0;
}

std::string EnvOrEmpty(const char* name) {
#if defined(_MSC_VER)
    char* value = nullptr;
    std::size_t size = 0;
    if (_dupenv_s(&value, &size, name) != 0 || value == nullptr) {
        return {};
    }
    std::string result(value);
    std::free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string(value);
#endif
}

std::vector<std::uint8_t> ReadBinaryFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());
}

std::string ReadTextFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

std::vector<std::vector<std::uint8_t>> ReadDerDirectory(const fs::path& dir) {
    std::vector<std::vector<std::uint8_t>> out;
    std::error_code ec;
    if (!fs::exists(dir, ec)) {
        return out;
    }
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        auto bytes = ReadBinaryFile(entry.path());
        if (!bytes.empty()) {
            out.push_back(std::move(bytes));
        }
    }
    return out;
}

// --- мок-транспорт ---------------------------------------------------------
//
// Мок існує рівно для того, щоб ТРИ можливі результати сюїти можна було
// відтворити без жодного звернення до державної інфраструктури. Він же —
// replay-двійник із правила 3 DoD.

enum class MockScenario {
    None,     // справжня мережа (живий прогін)
    Good,     // сервіс відповів правильно
    Bad,      // сервіс відповів, але відповідь не та, що ми надіслали / не розбирається
    Outage,   // сервіс не відповів
};

MockScenario ScenarioFromEnv() {
    const std::string value = EnvOrEmpty("TAMGA_LIVE_MOCK");
    if (value.empty()) {
        return MockScenario::None;
    }
    if (value == "good") {
        return MockScenario::Good;
    }
    if (value == "bad") {
        return MockScenario::Bad;
    }
    if (value == "outage") {
        return MockScenario::Outage;
    }
    std::cerr << "УВАГА: невідомий TAMGA_LIVE_MOCK=" << value
              << " — вважаю живим прогоном\n";
    return MockScenario::None;
}

const char* ScenarioName(const MockScenario scenario) {
    switch (scenario) {
        case MockScenario::Good:   return "good";
        case MockScenario::Bad:    return "bad";
        case MockScenario::Outage: return "outage";
        case MockScenario::None:   break;
    }
    return "none";
}

using ScopedTransport = std::unique_ptr<tamga::core::HttpClient::ScopedMockTransport>;

tamga::core::HttpResponse MockOutageResponse() {
    tamga::core::HttpResponse response;
    response.succeeded = false;
    response.status_code = 0;
    response.message = "mock-транспорт: сервіс не відповів";
    return response;
}

// --- спільне: звідки беруться адреси --------------------------------------
//
// `TAMGA_LIVE_POLICY_WORK_DIR` дозволяє перевикористати каталог, у який
// довірчий список уже синхронізовано. Без нього кожен із двох тестів
// синхронізував би TL самостійно, тобто бив би по ЦЗО двічі поспіль заради
// того самого файла.

struct TrustMaterial {
    bool available{false};
    std::string reason;                          // чому недоступне (для пропуску)
    fs::path work_dir;
    bool work_dir_is_temporary{false};
    tamga::core::policy::TrustListParseResult parsed;
};

TrustMaterial AcquireTrustMaterial() {
    TrustMaterial material;

    const std::string external = EnvOrEmpty("TAMGA_LIVE_POLICY_WORK_DIR");
    if (!external.empty()) {
        material.work_dir = fs::u8path(external);
        std::cerr << "робочий каталог політики (готовий): " << external << "\n";
        const tamga::core::policy::PolicyCache cache(material.work_dir);
        const std::string xml = ReadTextFile(cache.TrustListPath());
        if (xml.empty()) {
            material.reason =
                "TAMGA_LIVE_POLICY_WORK_DIR=" + external +
                " не містить кешованого довірчого списку — адреси OCSP/TSP взяти нема звідки";
            return material;
        }
        material.parsed = tamga::core::policy::TrustListParser{}.Parse(xml);
        if (!material.parsed.ok) {
            material.reason = "кешований довірчий список не розібрано: " + material.parsed.message;
            return material;
        }
        material.available = true;
        return material;
    }

    material.work_dir = fs::temp_directory_path() / "tamga-live-service-tests";
    material.work_dir_is_temporary = true;
    std::error_code ec;
    fs::remove_all(material.work_dir, ec);
    fs::create_directories(material.work_dir, ec);
    if (ec) {
        material.reason = "не вдалося створити робочий каталог: " + ec.message();
        return material;
    }

    tamga::core::TrustListSettings settings;
    std::cerr << "довірчий список: " << settings.url << " (timeout " << settings.timeout_ms
              << " мс)\n";
    const auto sync = tamga::core::policy::TrustListSync{}.Sync(material.work_dir.string(), settings);
    if (!sync.succeeded) {
        material.reason = "довірчий список ЦЗО недоступний (" + sync.message +
                          ", cache_status=" + sync.cache_status +
                          "), тож адреси OCSP/TSP взяти нема звідки";
        return material;
    }
    std::cerr << "  xmlSignatureStatus = " << sync.xml_signature_status << "\n";
    material.parsed = sync.parsed;
    material.available = true;
    return material;
}

void ReleaseTrustMaterial(const TrustMaterial& material) {
    if (!material.work_dir_is_temporary) {
        return;
    }
    std::error_code ec;
    fs::remove_all(material.work_dir, ec);
}

// Сервіс довірчого списку, який РАЗОМ несе і сертифікат КНЕДП, і адресу його
// OCSP-респондера. Пара потрібна саме разом: без сертифіката видавця
// OCSP-запит неможливо сформувати, а без адреси — нікуди надіслати.
struct OcspEndpointFromTrustList {
    bool found{false};
    std::string provider;
    std::string url;
    std::vector<std::uint8_t> issuer_der;
};

bool LooksGranted(const std::string& status) {
    return status.find("granted") != std::string::npos ||
           status.find("recognisedatnationallevel") != std::string::npos;
}

OcspEndpointFromTrustList PickOcspEndpoint(
    const tamga::core::policy::TrustListParseResult& parsed) {
    OcspEndpointFromTrustList picked;
    // Два проходи: спершу лише чинні сервіси, потім — будь-які. Другий прохід
    // потрібен не для послаблення, а для діагнозу: якщо в списку взагалі є
    // OCSP-адреси, але жодна не належить чинному сервісу, це інша новина, ніж
    // «адрес немає».
    for (int pass = 0; pass < 2 && !picked.found; ++pass) {
        for (const auto& service : parsed.services) {
            if (service.endpoints.ocsp_urls.empty() || service.certificates.empty()) {
                continue;
            }
            if (pass == 0 && !LooksGranted(service.status)) {
                continue;
            }
            picked.found = true;
            picked.provider = service.provider_name.empty() ? service.subject_name
                                                            : service.provider_name;
            picked.url = service.endpoints.ocsp_urls.front();
            picked.issuer_der = service.certificates.front();
            if (pass == 1) {
                std::cerr << "  УВАГА: жоден ЧИННИЙ сервіс не має OCSP-адреси; узято "
                             "сервіс зі статусом "
                          << service.status << "\n";
            }
            break;
        }
    }
    return picked;
}

// --- живий OCSP ------------------------------------------------------------

int RunOcspLive() {
    const MockScenario scenario = ScenarioFromEnv();
    std::cerr << "=== live OCSP (mock=" << ScenarioName(scenario) << ") ===\n";

#if !TAMGA_CRYPTONITE_ENABLED
    return Skip("збірка без cryptonite: OCSP-перевірка не підтримується (NotSupported за контрактом)");
#else
    std::string url;
    std::vector<std::uint8_t> issuer_der;
    std::vector<std::uint8_t> subject_der;
    bool probe_certificate = true;  // сертифікат, якого цей КНЕДП свідомо не видавав
    ScopedTransport transport;
    TrustMaterial material;

    if (scenario == MockScenario::None) {
        material = AcquireTrustMaterial();
        if (!material.available) {
            return Skip(material.reason);
        }
        const auto endpoint = PickOcspEndpoint(material.parsed);
        if (!endpoint.found) {
            ReleaseTrustMaterial(material);
            return Skip(
                "у довірчому списку немає жодного сервісу, який мав би ОДНОЧАСНО "
                "сертифікат і ocspUrl — адресу OCSP взяти нема звідки");
        }
        std::cerr << "КНЕДП   : " << endpoint.provider << "\n"
                  << "OCSP URL: " << endpoint.url << "  (джерело: довірчий список ЦЗО)\n";
        url = endpoint.url;
        issuer_der = endpoint.issuer_der;

        // Сертифікат-предмет запиту. Якщо оператор дав справжній — питаємо про
        // нього; інакше формуємо CertID із серійного номера сертифіката, якого
        // цей КНЕДП не видавав. Другий випадок теж змістовний: він перевіряє
        // весь шлях (запит -> HTTP -> розбір -> підпис відповіді) і головний
        // fail-open інваріант «невідомий сертифікат не стає good».
        const std::string subject_path = EnvOrEmpty("TAMGA_LIVE_OCSP_CERT");
        if (!subject_path.empty()) {
            subject_der = ReadBinaryFile(fs::u8path(subject_path));
            if (subject_der.empty()) {
                ReleaseTrustMaterial(material);
                return Skip("TAMGA_LIVE_OCSP_CERT=" + subject_path + " не читається як DER");
            }
            probe_certificate = false;
            std::cerr << "предмет : сертифікат оператора з " << subject_path << "\n";
        } else {
            subject_der = issuer_der;
            std::cerr << "предмет : зондовий CertID (сертифіката, виданого цим КНЕДП, "
                         "не задано через TAMGA_LIVE_OCSP_CERT)\n";
        }
    } else {
        const auto fixture = tamga_tests::GenerateDstuFixture();
        if (!fixture.valid) {
            return Skip("ДСТУ-фікстура недоступна: мок-сценарій нема на чому виконати");
        }
        issuer_der = fixture.cert_der;
        subject_der = fixture.cert_der;
        url = "https://ocsp.example.test/ocsp";
        transport = std::make_unique<tamga::core::HttpClient::ScopedMockTransport>(
            [scenario](const tamga::core::HttpRequest&) {
                if (scenario == MockScenario::Outage) {
                    return MockOutageResponse();
                }
                tamga::core::HttpResponse response;
                response.succeeded = true;
                response.status_code = 200;
                if (scenario == MockScenario::Bad) {
                    // Респондер ВІДПОВІВ, але тіло не є OCSPResponse. Це саме
                    // той випадок, за яким зарезервовано провал.
                    const char kGarbage[] = "not-an-ocsp-response";
                    response.body.assign(kGarbage, kGarbage + sizeof(kGarbage) - 1);
                } else {
                    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED(6 unauthorized) }
                    //
                    // Підписаної позитивної відповіді тут немає навмисно: її
                    // не можна синтезувати без ключа респондера. Цей варіант
                    // доводить інше і теж потрібне — що відмову по суті ми
                    // відрізняємо від мовчання (`responder_answered`).
                    response.body = {0x30, 0x03, 0x0A, 0x01, 0x06};
                }
                return response;
            });
    }

    tamga::core::policy::OcspValidationInput input;
    input.url = url;
    input.use_nonce = true;
    input.timeout_ms = 10000;
    input.signer_certificate_der = subject_der;
    input.issuer_certificate_der = issuer_der;

    const auto result = tamga::core::policy::OcspValidator{}.Validate(input);
    ReleaseTrustMaterial(material);

    std::cerr << "  checked            = " << (result.checked ? "true" : "false") << "\n"
              << "  responder_answered = " << (result.responder_answered ? "true" : "false") << "\n"
              << "  status             = "
              << static_cast<int>(result.status) << " (" << result.message << ")\n"
              << "  requestEvidenceId  = " << result.request_evidence_id << "\n"
              << "  responseEvidenceId = " << result.response_evidence_id << "\n";

    using tamga::core::policy::RevocationStatus;

    // Запит навіть не сформувався — це наша помилка, а не чужа недоступність.
    if (!result.checked) {
        Check(false, "OCSP-запит не сформовано: " + result.message);
        return Finish("live_ocsp_tests");
    }

    if (!result.responder_answered) {
        return Skip("OCSP-респондер не відповів: " + result.message);
    }

    if (result.status == RevocationStatus::ResponderUnavailable) {
        // Відповідь є, але це не successful-статус OCSP (unauthorized,
        // tryLater тощо). Респондер свідомо відмовився відповідати по суті —
        // це його право, а не наша помилка.
        return Skip("OCSP-респондер відповів відмовою по суті: " + result.message);
    }

    // --- Інваріант 1: відповідь розібрано, підпис перевірено ---------------
    //
    // `RevocationStatus::Invalid` повертається рівно тоді, коли відповідь
    // прийшла, але не пройшла: розбір DER, вікно свіжості (thisUpdate/
    // nextUpdate/producedAt через `eocspreq_validate_resp`) або перевірку
    // підпису — включно з делегованим respondera за RFC 6960 §4.2.2.2.
    // Другої реалізації цих перевірок тут навмисно немає: політика живе в
    // `OcspValidator`, тест дивиться на її вердикт.
    Check(result.status != RevocationStatus::Invalid,
          "респондер відповів, але відповідь не пройшла розбір / вікно свіжості / "
          "перевірку підпису: " + result.message);
    Check(result.status != RevocationStatus::NotChecked,
          "респондер відповів, а статус лишився NotChecked — відповідь мовчки проігноровано");

    // --- Інваріант 2: доказ зафіксовано ------------------------------------
    Check(!result.request_evidence_id.empty(),
          "ідентифікатор доказу запиту мусить бути обчислений");
    Check(!result.response_evidence_id.empty(),
          "ідентифікатор доказу відповіді мусить бути обчислений");

    // --- Інваріант 3: fail-open заборонено ---------------------------------
    if (probe_certificate) {
        // Головний інваріант живого OCSP. `unknown` НЕ дорівнює `good`: саме
        // це переплутування перетворює перевірку відкликання на декорацію.
        Check(result.status != RevocationStatus::Good,
              "fail-open: респондер повернув `good` для CertID, якого цей КНЕДП не видавав");
        Check(!result.revoked,
              "зондовий CertID не може бути позначений відкликаним");
    } else {
        Check(result.status == RevocationStatus::Good || result.status == RevocationStatus::Revoked,
              "для справжнього сертифіката КНЕДП статус мусить бути розпізнаний як good або revoked, "
              "а не залишитися невизначеним: " + result.message);
        Check(result.revoked == (result.status == RevocationStatus::Revoked),
              "прапорець revoked мусить узгоджуватися зі статусом");
    }

    return Finish("live_ocsp_tests");
#endif
}

// --- живий TSP -------------------------------------------------------------

#if TAMGA_CRYPTONITE_ENABLED
// Розбирає GeneralizedTime виду YYYYMMDDHHMMSS[.fff]Z у time_t (UTC).
bool ParseGeneralizedTime(const std::string& text, std::time_t& out) {
    if (text.size() < 14) {
        return false;
    }
    for (std::size_t i = 0; i < 14; ++i) {
        if (text[i] < '0' || text[i] > '9') {
            return false;
        }
    }
    const auto part = [&text](const std::size_t offset, const std::size_t length) {
        return std::stoi(text.substr(offset, length));
    };
    std::tm tm{};
    tm.tm_year = part(0, 4) - 1900;
    tm.tm_mon = part(4, 2) - 1;
    tm.tm_mday = part(6, 2);
    tm.tm_hour = part(8, 2);
    tm.tm_min = part(10, 2);
    tm.tm_sec = part(12, 2);
#if defined(_WIN32)
    out = _mkgmtime(&tm);
#else
    out = timegm(&tm);
#endif
    return out != static_cast<std::time_t>(-1);
}

bool CertificateHasTimestampingEku(const std::vector<std::uint8_t>& der) {
    const auto cert = tamga::core::cryptonite_detail::DecodeCertificateDer(der);
    if (!cert) {
        return false;
    }
    return tamga::core::policy::HasTimestampingEku(cert.get());
}

// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken [OPTIONAL] }
// PKIStatusInfo ::= SEQUENCE { status INTEGER (0 = granted) }
std::vector<std::uint8_t> WrapTokenInTimeStampResp(const std::vector<std::uint8_t>& token) {
    const std::vector<std::uint8_t> status = {0x30, 0x03, 0x02, 0x01, 0x00};
    std::vector<std::uint8_t> content;
    content.insert(content.end(), status.begin(), status.end());
    content.insert(content.end(), token.begin(), token.end());

    std::vector<std::uint8_t> out;
    out.push_back(0x30);
    const std::size_t length = content.size();
    if (length < 0x80U) {
        out.push_back(static_cast<std::uint8_t>(length));
    } else {
        std::vector<std::uint8_t> length_bytes;
        std::size_t remaining = length;
        while (remaining != 0U) {
            length_bytes.push_back(static_cast<std::uint8_t>(remaining & 0xFFU));
            remaining >>= 8;
        }
        out.push_back(static_cast<std::uint8_t>(0x80U | length_bytes.size()));
        out.insert(out.end(), length_bytes.rbegin(), length_bytes.rend());
    }
    out.insert(out.end(), content.begin(), content.end());
    return out;
}
#endif

int RunTspLive() {
    const MockScenario scenario = ScenarioFromEnv();
    std::cerr << "=== live TSP (mock=" << ScenarioName(scenario) << ") ===\n";

#if !TAMGA_CRYPTONITE_ENABLED
    return Skip("збірка без cryptonite: TSP-перевірка не підтримується (NotSupported за контрактом)");
#else
    std::string url;
    ScopedTransport transport;
    TrustMaterial material;
    std::vector<std::vector<std::uint8_t>> tsa_anchors;
    std::vector<std::vector<std::uint8_t>> trust_anchors;

    // Дані, які штампуємо. У живому прогоні вони унікальні для запуску, щоб
    // відповідь не могла виявитися кешованою; у мок-режимі — детерміновані,
    // бо двійник мусить бути відтворюваним.
    std::vector<std::uint8_t> payload;
    if (scenario == MockScenario::None) {
        const auto now = std::chrono::system_clock::now().time_since_epoch().count();
        const std::string text = "tamga-live-tsp-" + std::to_string(now);
        payload.assign(text.begin(), text.end());
    } else {
        const std::string text = "tamga-live-tsp-replay";
        payload.assign(text.begin(), text.end());
    }

    tamga::core::ImprintResult imprint;
    std::string imprint_error;
    if (!tamga::core::ComputeImprint(tamga::core::ImprintDigest::Kupyna256, payload, imprint,
                                     imprint_error)) {
        return Skip("не вдалося обчислити імпринт Купина-256: " + imprint_error);
    }
    std::cerr << "imprint : " << imprint.digest_oid << ", " << imprint.hash.size() << " байтів\n";

    tamga_tests::DstuFixture fixture;
    if (scenario == MockScenario::None) {
        material = AcquireTrustMaterial();
        if (!material.available) {
            return Skip(material.reason);
        }
        const tamga::core::policy::PolicyCache cache(material.work_dir);
        url = cache.ResolveGrantedTspUrl();
        if (url.empty()) {
            ReleaseTrustMaterial(material);
            return Skip(
                "PolicyCache::ResolveGrantedTspUrl() не дав адреси: у довірчому списку немає "
                "жодного чинного TSA-сервісу з tspUrls — адресу TSP взяти нема звідки");
        }
        std::cerr << "TSP URL : " << url
                  << "  (джерело: PolicyCache::ResolveGrantedTspUrl)\n";
        tsa_anchors = ReadDerDirectory(material.work_dir / "tsa-store");
        trust_anchors = ReadDerDirectory(material.work_dir / "trust-store");
        std::cerr << "  якорів: tsa-store = " << tsa_anchors.size()
                  << ", trust-store = " << trust_anchors.size() << "\n";
    } else {
        fixture = tamga_tests::GenerateDstuFixture();
        if (!fixture.valid) {
            return Skip("ДСТУ-фікстура недоступна: мок-сценарій нема на чому виконати");
        }
        url = "https://tsa.example.test/tsp";
        std::vector<std::uint8_t> token_imprint = imprint.hash;
        if (scenario == MockScenario::Bad) {
            // Сервіс ВІДПОВІВ і токен криптографічно валідний, але заштампував
            // не те, що ми надіслали. Саме цю підміну зобовʼязана спіймати
            // перевірка імпринта.
            token_imprint.assign(imprint.hash.size(), 0xAA);
        }
        const auto tst_info = tamga_tests::CreateTstInfoDer(token_imprint, "20260615220000Z");
        std::vector<std::uint8_t> token;
        if (!tamga_tests::GenerateMockTspToken(fixture.pkcs12_blob, fixture.cert_der, tst_info,
                                               token)) {
            return Skip("не вдалося згенерувати мок-токен TSP");
        }
        const auto body = WrapTokenInTimeStampResp(token);
        transport = std::make_unique<tamga::core::HttpClient::ScopedMockTransport>(
            [scenario, body](const tamga::core::HttpRequest&) {
                if (scenario == MockScenario::Outage) {
                    return MockOutageResponse();
                }
                tamga::core::HttpResponse response;
                response.succeeded = true;
                response.status_code = 200;
                response.body = body;
                return response;
            });
        tsa_anchors.push_back(fixture.cert_der);
    }

    std::vector<std::uint8_t> token;
    std::string error_message;
    const bool got = tamga::core::TspClient::GetTimestamp(imprint.hash, imprint.digest_oid, url,
                                                          10000, "", token, error_message);
    ReleaseTrustMaterial(material);

    // Правило 1: сервіс не відповів -> ПРОПУСК.
    if (!got) {
        return Skip("TSA за адресою з довірчого списку не видав токен: " + error_message);
    }
    if (token.empty()) {
        Check(false, "TSA повідомив про успіх, але токен порожній");
        return Finish("live_tsp_tests");
    }
    std::cerr << "токен   : " << token.size() << " байтів\n";

    // --- Інваріант 1: заштамповано саме те, що ми надіслали -----------------
    //
    // Головний інваріант TSP. Токен, виданий на чужий імпринт, нічого не
    // доводить про наші дані — а виявити це можна лише звіркою.
    const auto validated = tamga::core::policy::ValidateTimestampToken(token, payload);
    std::cerr << "  genTime = " << validated.gen_time << "\n"
              << "  valid   = " << (validated.valid ? "true" : "false") << " (" << validated.message
              << ")\n";
    Check(validated.valid,
          "токен TSA не пройшов криптографічну перевірку (імпринт або підпис): " +
              validated.message);

    // --- Інваріант 2: перевірка імпринта справді розрізняє ------------------
    //
    // Негативний контроль. Без нього інваріант 1 міг би виконуватися тому, що
    // перевірка приймає будь-що. Мережі не коштує нічого.
    std::vector<std::uint8_t> other_payload = payload;
    other_payload.push_back(0x00);
    const auto mismatched = tamga::core::policy::ValidateTimestampToken(token, other_payload);
    Check(!mismatched.valid,
          "перевірка імпринта прийняла ІНШІ дані — вона не розрізняє, що саме заштамповано");

    // --- Інваріант 3: genTime розібрано і не в майбутньому ------------------
    Check(!validated.gen_time.empty(), "токен мусить нести genTime");
    std::time_t gen_time_sec = 0;
    if (ParseGeneralizedTime(validated.gen_time, gen_time_sec)) {
        const std::time_t now = std::time(nullptr);
        // Допуск на розбіжність годинників. Мітка з майбутнього — не дрібниця:
        // на ній будується весь висновок «підпис існував не пізніше, ніж».
        constexpr std::time_t kSkewToleranceSec = 300;
        Check(gen_time_sec <= now + kSkewToleranceSec,
              "genTime мітки часу лежить у майбутньому більш ніж на 5 хвилин: " +
                  validated.gen_time);
    } else if (scenario == MockScenario::None) {
        Check(false, "genTime не розбирається як GeneralizedTime: " + validated.gen_time);
    }

    // --- Інваріант 4: сертифікат TSA має EKU timestamping -------------------
    //
    // Використано спільний `policy::HasTimestampingEku` — ASN.1-коректну
    // перевірку RFC 5280 §4.2.1.12, ту саму, що застосовує канонічний
    // `TimestampEngine`. Другої реалізації тут немає навмисно.
    Check(!validated.tsa_certificate_der.empty(),
          "у токені мусить бути сертифікат підписанта TSA");
    if (!validated.tsa_certificate_der.empty() && scenario == MockScenario::None) {
        Check(CertificateHasTimestampingEku(validated.tsa_certificate_der),
              "сертифікат TSA не містить EKU id-kp-timeStamping (1.3.6.1.5.5.7.3.8) — "
              "за RFC 3161 §2.3 такий сертифікат не має права видавати мітки часу");
    }

    // --- Інваріант 5: канонічний рушій приймає токен ------------------------
    //
    // Ланцюг, строк дії та довіру до TSA перевіряє `TimestampEngine`, а не цей
    // тест. Тут ЖОРСТКИЙ провал лише за станами, які означають «сервіс
    // відповів, а ми обробили відповідь неправильно»; питання довіри до
    // конкретного TSA (`UntrustedTsa`, `TsaExpired`) виводяться попередженням:
    // склад `tsa-store` визначає ЦЗО, і його зміна не є нашою помилкою.
    tamga::core::validation::TimestampEngineInput engine_input;
    engine_input.explicit_timestamp_token_der = token;
    engine_input.explicit_timestamp_imprint_source = payload;
    engine_input.tsa_trust_anchors_der = tsa_anchors;
    engine_input.current_trust_anchors_der = trust_anchors;
    const auto engine_result = tamga::core::validation::TimestampEngine{}.Validate(engine_input);
    std::cerr << "  TimestampEngine.status = " << static_cast<int>(engine_result.status) << "\n";
    for (const auto& reason : engine_result.because) {
        std::cerr << "    - " << reason << "\n";
    }

    using tamga::core::policy::TimestampStatus;
    Check(engine_result.status != TimestampStatus::InvalidImprint,
          "канонічний TimestampEngine визнав імпринт токена невідповідним нашим даним");
    Check(engine_result.status != TimestampStatus::InvalidSignature,
          "канонічний TimestampEngine відхилив підпис TSA");
    Check(engine_result.status != TimestampStatus::Missing,
          "канонічний TimestampEngine не побачив мітки часу у виданому токені");
    Check(engine_result.status != TimestampStatus::Unsupported,
          "канонічний TimestampEngine не зміг обробити токен: " +
              (engine_result.because.empty() ? std::string{} : engine_result.because.front()));
    if (engine_result.status != TimestampStatus::Valid) {
        std::cerr << "  УВАГА: TimestampEngine не визнав мітку повністю валідною "
                     "(довіра/строк дії TSA). Склад tsa-store визначає ЦЗО — "
                     "це попередження, а не провал.\n";
    }

    return Finish("live_tsp_tests");
#endif
}

// --- replay-двійники -------------------------------------------------------
//
// Правило 3 DoD: кожен живий тест має двійника на фіксованому вході. Живий
// тест ловить зміни на боці сервісу, двійник — регресії в нас. Без другого
// перший нічого не стереже: коли КНЕДП недоступний, покриття зникає разом
// із ним.

int RunOcspReplay() {
    std::cerr << "=== replay OCSP (без мережі) ===\n";
#if !TAMGA_CRYPTONITE_ENABLED
    return Skip("збірка без cryptonite: відображення статусів OCSP не компілюється");
#else
    using tamga::core::policy::RevocationStatus;
    namespace detail = tamga::core::policy::detail;

    detail::OcspCertIdFields requested;
    requested.issuer_name_hash = std::vector<std::uint8_t>(32, 0x11);
    requested.issuer_key_hash = std::vector<std::uint8_t>(32, 0x22);
    requested.serial_number = {0x01, 0x02, 0x03, 0x04};

    const auto make_status = [&requested](const std::string& status) {
        detail::OcspMappedCertificateStatus entry;
        entry.cert_id = requested;
        entry.status = status;
        return entry;
    };

    // 1. `unknown` НЕ дорівнює `good`. Це і є той fail-open, який живий тест
    //    перевіряє проти справжнього респондера, — тут він зафіксований
    //    детерміновано.
    {
        bool revoked = true;
        std::time_t revocation_time = 0;
        std::string message;
        const auto status = detail::MapOcspStatusForRequestedCertId(
            requested, {make_status("unknown")}, revoked, revocation_time, message);
        Check(status == RevocationStatus::Unknown, "`unknown` мусить мапитися в Unknown");
        Check(status != RevocationStatus::Good, "`unknown` НЕ мусить мапитися в Good");
        Check(!revoked, "`unknown` не робить сертифікат відкликаним");
    }

    // 2. `revoked` розпізнається як відкликання, а не як «щось не так».
    {
        bool revoked = false;
        std::time_t revocation_time = 0;
        std::string message;
        const auto status = detail::MapOcspStatusForRequestedCertId(
            requested, {make_status("revoked")}, revoked, revocation_time, message);
        Check(status == RevocationStatus::Revoked, "`revoked` мусить мапитися в Revoked");
        Check(revoked, "`revoked` мусить піднімати прапорець revoked");
    }

    // 3. `good` розпізнається.
    {
        bool revoked = true;
        std::time_t revocation_time = 0;
        std::string message;
        const auto status = detail::MapOcspStatusForRequestedCertId(
            requested, {make_status("good")}, revoked, revocation_time, message);
        Check(status == RevocationStatus::Good, "`good` мусить мапитися в Good");
        Check(!revoked, "`good` не піднімає прапорець revoked");
    }

    // 4. Відповідь ПРО ІНШИЙ сертифікат не стає відповіддю про наш. Респондер,
    //    який відповів на щось інше, не дає нам права вважати наш сертифікат
    //    чинним.
    {
        detail::OcspMappedCertificateStatus other;
        other.cert_id = requested;
        other.cert_id.serial_number = {0x09, 0x09};
        other.status = "good";

        bool revoked = true;
        std::time_t revocation_time = 0;
        std::string message;
        const auto status = detail::MapOcspStatusForRequestedCertId(
            requested, {other}, revoked, revocation_time, message);
        Check(status != RevocationStatus::Good,
              "статус `good` для ЧУЖОГО CertID не має ставати нашим `good`");
        Check(!message.empty(), "невідповідність CertID мусить бути пояснена в повідомленні");
    }

    // 5. Порожня відповідь не дає Good.
    {
        bool revoked = true;
        std::time_t revocation_time = 0;
        std::string message;
        const auto status = detail::MapOcspStatusForRequestedCertId(
            requested, {}, revoked, revocation_time, message);
        Check(status != RevocationStatus::Good,
              "відповідь без жодного запису про статус не може дати Good");
    }

    return Finish("replay_ocsp_tests");
#endif
}

int RunTspReplay() {
    std::cerr << "=== replay TSP (мок-транспорт, без мережі) ===\n";
#if !TAMGA_CRYPTONITE_ENABLED
    return Skip("збірка без cryptonite: мок-токен TSP нема чим згенерувати");
#else
    // Двійник — це та сама логіка живого TSP-тесту на детермінованому
    // «правильному» сервісі. Він мусить бути ЗЕЛЕНИМ завжди й без мережі.
#if defined(_WIN32)
    _putenv_s("TAMGA_LIVE_MOCK", "good");
#else
    setenv("TAMGA_LIVE_MOCK", "good", 1);
#endif
    return RunTspLive();
#endif
}

void PrintUsage() {
    std::cerr << "Використання: tamga-live-service-tests <ocsp|tsp|replay-ocsp|replay-tsp>\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return kUsage;
    }
    const std::string mode = argv[1];
    if (mode == "ocsp") {
        return RunOcspLive();
    }
    if (mode == "tsp") {
        return RunTspLive();
    }
    if (mode == "replay-ocsp") {
        return RunOcspReplay();
    }
    if (mode == "replay-tsp") {
        return RunTspReplay();
    }
    PrintUsage();
    return kUsage;
}
