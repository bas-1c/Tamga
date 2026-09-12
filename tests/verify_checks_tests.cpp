// Хвиля 8, п.1: вердикти звіту мають рівно одне джерело (ADR-026).
//
// `GetUserReport()` і `GetReport()` — дві проєкції одного `VerifyReport`.
// Донедавна кожна мала ВЛАСНУ копію логіки вердиктів: вісім пар
// `XxxCheck` / `XxxCheckForV2` плюс п'ять пар предикатів. Копії збігалися
// рядок у рядок лише тому, що К-01, В-03 і HI-02 щоразу правили обидві
// вручну. Забути другу — і два звіти про той самий підпис почали б
// суперечити один одному мовчки, без жодної діагностики.
//
// Це не гіпотеза. Рівно так поводився С-06 (guard проти переповнення в одній
// копії DER-парсера з чотирьох) і С-19 (перевірка строку дії TSA лише в
// одному з двох валідаторів). Обидва «виправлені» дефекти жили далі в копіях,
// яких виправлення не торкнулося.
//
// Тест закріплює два твердження:
//   1) таблиця вердиктів поводиться так, як вимагають К-01, В-03 і HI-02;
//   2) вердикти БУДУЮТЬСЯ лише в одному файлі — `core/policy/VerifyChecks.cpp`.
//      Друге важливіше за перше: воно стереже не значення, а архітектуру.

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include <set>
#include <thread>
#include <vector>

#include "core/Session.h"
#include "core/policy/VerifyChecks.h"
#include "core/session/VerifyReportCommit.h"
#include "core/session/VerifyReportOwnership.h"
#include "core/session/VerifySummary.h"

namespace {

namespace fs = std::filesystem;
using tamga::core::VerifyReport;
namespace policy = tamga::core::policy;

int g_failures = 0;

void Fail(const std::string& what) {
    std::cerr << "FAIL: " << what << '\n';
    ++g_failures;
}

void ExpectCheck(const policy::VerifyCheck& actual,
                 const char* status,
                 const char* code,
                 const std::string& scenario) {
    if (std::string(actual.status) != status || std::string(actual.code) != code) {
        Fail(scenario + ": очікували " + status + "/" + code + ", отримали " +
             actual.status + "/" + actual.code);
    }
}

VerifyReport BaseValidReport() {
    VerifyReport r;
    r.has_result = true;
    r.execution_succeeded = true;
    r.signature_valid = true;
    r.container_coverage_complete = true;
    r.signer_certificate_present = true;
    r.certificate_time_valid = true;
    r.chain_checked = true;
    r.chain_valid = true;
    r.trust_checked = true;
    r.trust_valid = true;
    r.trust_status = "trusted-anchor-validated";
    r.revocation_checked = true;
    r.revocation_status = "good";
    r.timestamp_checked = true;
    r.timestamp_valid = true;
    r.timestamp_status = "timestamp-valid";
    r.tsp_checked = true;
    r.signature_format = "XAdES";
    r.format_profile = "XAdES-B-LT";
    r.container_type = "ASiC-E";
    r.validation_time_source = "signing-time";
    r.ltv_evidence_validated = true;
    return r;
}

// --- 1. Таблиця вердиктів --------------------------------------------------

void TestBaselineIsValid() {
    const auto r = BaseValidReport();
    ExpectCheck(policy::SummaryCheck(r), "valid", "SIGNATURE_VALID", "базовий валідний");
    ExpectCheck(policy::SignatureCheck(r), "valid", "SIGNATURE_CRYPTOGRAPHICALLY_VALID", "базовий валідний");
    ExpectCheck(policy::TrustCheck(r), "valid", "TRUST_VALID", "базовий валідний");
    ExpectCheck(policy::RevocationCheck(r), "valid", "REVOCATION_VALID", "базовий валідний");
    ExpectCheck(policy::TimestampCheck(r), "valid", "TIMESTAMP_VALID", "базовий валідний");
    ExpectCheck(policy::LtvCheck(r), "valid", "LTV_VALID", "базовий валідний");
}

void TestCoverageIncompleteIsInvalid() {
    // К-01: неповне покриття робить документ невалідним, хай навіть підпис
    // криптографічно бездоганний. Це те виправлення, яке довелося вносити
    // у ДВІ копії; тепер копія одна.
    auto r = BaseValidReport();
    r.container_coverage_complete = false;
    ExpectCheck(policy::SummaryCheck(r), "invalid", "CONTAINER_COVERAGE_INCOMPLETE", "К-01");
    // Криптографічний вердикт при цьому не бреше в інший бік.
    ExpectCheck(policy::SignatureCheck(r), "valid", "SIGNATURE_CRYPTOGRAPHICALLY_VALID", "К-01");
}

void TestPartialTimestampBeatsValidFlag() {
    // В-03: частковий статус перевіряється ПЕРШИМ. Якби гілку `timestamp_valid`
    // залишили вище, форматний крипто-результат перекривав би ознаку того, що
    // довіру до TSA не перевіряли, — і `timestamp-partial` став би недосяжним.
    auto r = BaseValidReport();
    r.timestamp_status = "timestamp-partial";
    r.timestamp_valid = true;  // навмисно суперечливо: прапорець каже «валідно»
    ExpectCheck(policy::TimestampCheck(r), "warning", "TIMESTAMP_NOT_FULLY_VALIDATED", "В-03");

    auto r2 = BaseValidReport();
    r2.trust_status = "timestamp-not-fully-validated";
    ExpectCheck(policy::TimestampCheck(r2), "warning", "TIMESTAMP_NOT_FULLY_VALIDATED", "В-03 (trust_status)");
}

void TestLtvRequiresValidatedEvidence() {
    // HI-02: структурна наявність LTV-доказів не дорівнює підтвердженій довірі.
    auto r = BaseValidReport();
    r.ltv_valid = true;
    r.ltv_evidence_validated = false;
    ExpectCheck(policy::LtvCheck(r), "unavailable", "LTV_EVIDENCE_UNAVAILABLE", "HI-02");

    auto cades = BaseValidReport();
    cades.signature_format = "CAdES";
    cades.ltv_valid = true;
    cades.ltv_evidence_validated = false;
    ExpectCheck(policy::LtvCheck(cades), "skipped", "LTV_NOT_APPLICABLE", "HI-02 (CAdES)");
}

// П-02: «перевірку не завершено» і «перевірку завершено й вона ВІДМОВИЛА» —
// це різні відповіді, і `summary` мусить їх розрізняти.
//
// Доти `SummaryCheck` повертав один і той самий
// {"warning","SIGNATURE_INTEGRITY_ONLY"} для будь-якої невдачі політики, а
// повідомлення до цього коду каже «повна перевірка політики НЕ ЗАВЕРШЕНА».
// Для відкликаного сертифіката вона завершена — і дала відмову. Аудит
// 2026-08-29 виміряв це зондом: відкликаний сертифікат, прострочений і просто
// ненаcтроєний довірчий список давали нерозрізнимий вердикт. Інтеграція 1С,
// що читає `summary.status` (спосіб, який рекомендує `docs/user-guide.md`),
// бачила «попередження» там, де сертифікат ВІДКЛИКАНО.
//
// Тест закріплює обидві сторони межі: доведена відмова -> invalid; відсутність
// матеріалу для перевірки -> лишається warning. Друга половина не менш
// важлива за першу — без неї «виправленням» було б просто оголосити invalid
// усе підряд, і штатний сценарій без довірчого списку почав би виглядати як
// підробка.
void TestProvenPolicyFailureIsInvalid() {
    struct Case {
        const char* trust_status;
        const char* revocation_status;
        const char* status;
        const char* code;
        const char* scenario;
    };

    // Доведена відмова: перевірка виконалась і відхилила підпис.
    const Case decisive[] = {
        {"certificate-revoked", "revoked", "invalid", "CERTIFICATE_REVOKED",
         "сертифікат відкликано"},
        {"certificate-time-invalid", "good", "invalid", "CERTIFICATE_INVALID_AT_VALIDATION_TIME",
         "сертифікат поза строком дії"},
        {"certificate-chain-time-invalid", "good", "invalid", "CERTIFICATE_INVALID_AT_VALIDATION_TIME",
         "сертифікат ланцюга поза строком дії"},
        {"revocation-check-invalid", "invalid", "invalid", "REVOCATION_INVALID",
         "дані про відкликання некоректні"},
        {"ocsp-response-invalid", "invalid", "invalid", "REVOCATION_INVALID",
         "відповідь OCSP некоректна"},
        {"timestamp-invalid", "good", "invalid", "TIMESTAMP_INVALID",
         "мітку часу відхилено"},
    };
    for (const auto& c : decisive) {
        auto r = BaseValidReport();
        r.trust_valid = false;
        r.trust_status = c.trust_status;
        r.revocation_status = c.revocation_status;
        ExpectCheck(policy::SummaryCheck(r), c.status, c.code, c.scenario);
    }

    // Перевірити не було чим або сервіс не відповів — це НЕ відмова.
    const Case inconclusive[] = {
        {"trust-store-empty", "not-checked", "warning", "SIGNATURE_INTEGRITY_ONLY",
         "довірчий список не налаштовано"},
        {"no-trust-store-configured", "not-checked", "warning", "SIGNATURE_INTEGRITY_ONLY",
         "сховище довіри не задано"},
        {"certificate-chain-incomplete", "not-checked", "warning", "SIGNATURE_INTEGRITY_ONLY",
         "ланцюг не добудовано до якоря"},
        {"ocsp-responder-unavailable", "temporarily-unavailable", "warning", "SIGNATURE_INTEGRITY_ONLY",
         "OCSP-сервіс недоступний"},
        {"timestamp-not-fully-validated", "good", "warning", "SIGNATURE_INTEGRITY_ONLY",
         "довіру до TSA не доведено"},
    };
    for (const auto& c : inconclusive) {
        auto r = BaseValidReport();
        r.trust_valid = false;
        r.trust_status = c.trust_status;
        r.revocation_status = c.revocation_status;
        ExpectCheck(policy::SummaryCheck(r), c.status, c.code, c.scenario);
    }

    // Відкликання, доведене самим revocation_status, без спеціального
    // trust_status: вердикт має бути той самий. Інакше правило залежало б від
    // того, який саме шар першим записав відмову.
    {
        auto r = BaseValidReport();
        r.trust_valid = false;
        r.trust_status = "certificate-chain-incomplete";
        r.revocation_status = "revoked";
        ExpectCheck(policy::SummaryCheck(r), "invalid", "CERTIFICATE_REVOKED",
                    "відкликання доведене revocation_status");
    }

    // Криптографічний вердикт у жодному з випадків не змінюється: підпис
    // цілий, проблема в політиці. Це та сама межа, що й у К-01.
    {
        auto r = BaseValidReport();
        r.trust_valid = false;
        r.trust_status = "certificate-revoked";
        r.revocation_status = "revoked";
        ExpectCheck(policy::SignatureCheck(r), "valid", "SIGNATURE_CRYPTOGRAPHICALLY_VALID",
                    "П-02: крипто-вердикт лишається валідним");
    }
}

// ADR-029: структурно поламаний контейнер — окремий стан, а не «підпис не
// зійшовся» і не «перевірку не вдалося завершити».
//
// Доти два шляхи одного формату ASiC-E давали різні з цих двох назв: CAdES —
// SIGNATURE_INVALID, XAdES — VERIFICATION_EXECUTION_FAILED. Жодна не була
// правдою: до криптографії не дійшло, а інфраструктура не збоїла.
void TestMalformedContainerHasItsOwnVerdict() {
    auto r = BaseValidReport();
    r.signature_valid = false;
    r.container_malformed = true;
    ExpectCheck(policy::SummaryCheck(r), "invalid", "CONTAINER_MALFORMED",
                "поламаний контейнер");
    const std::string summary_code = tamga::core::ComputeVerifySummary(r);
    if (summary_code != "container-malformed") {
        Fail("summaryCode поламаного контейнера: очікували container-malformed, отримали " +
             summary_code);
    }

    // ПОРЯДОК і є змістом: якби гілку поставили після перевірки підпису, вона
    // стала б недосяжною — при поламаному контейнері signature_valid завжди
    // false, і вердикт назавжди лишився б SIGNATURE_INVALID.
    auto plain = BaseValidReport();
    plain.signature_valid = false;
    ExpectCheck(policy::SummaryCheck(plain), "invalid", "SIGNATURE_INVALID",
                "звичайний невалідний підпис не має ставати CONTAINER_MALFORMED");

    // Виконання, що справді зірвалося, лишається окремим станом і має
    // пріоритет: там вердикту немає взагалі.
    auto failed = BaseValidReport();
    failed.execution_succeeded = false;
    failed.container_malformed = true;
    ExpectCheck(policy::SummaryCheck(failed), "invalid", "VERIFICATION_EXECUTION_FAILED",
                "зірване виконання важливіше за структуру контейнера");
}

void TestNotExecutedAndFailures() {
    VerifyReport empty;
    ExpectCheck(policy::SummaryCheck(empty), "skipped", "NOT_EXECUTED", "не виконувався");
    ExpectCheck(policy::SignatureCheck(empty), "skipped", "SIGNATURE_NOT_CHECKED", "не виконувався");
    ExpectCheck(policy::PolicyCheck(empty), "skipped", "POLICY_NOT_EVALUATED", "не виконувався");

    auto failed = BaseValidReport();
    failed.execution_succeeded = false;
    ExpectCheck(policy::SummaryCheck(failed), "invalid", "VERIFICATION_EXECUTION_FAILED", "виконання провалилось");
    ExpectCheck(policy::SignatureCheck(failed), "unavailable", "SIGNATURE_CHECK_UNAVAILABLE", "виконання провалилось");

    auto revoked = BaseValidReport();
    revoked.revocation_status = "revoked";
    ExpectCheck(policy::RevocationCheck(revoked), "invalid", "CERTIFICATE_REVOKED", "відкликано");

    auto unavailable = BaseValidReport();
    unavailable.revocation_status = "temporarily-unavailable";
    ExpectCheck(policy::RevocationCheck(unavailable), "unavailable", "REVOCATION_UNAVAILABLE", "відкликання недоступне");

    auto historical = BaseValidReport();
    historical.historical_trust_used = true;
    ExpectCheck(policy::TrustCheck(historical), "warning", "TRUST_VALID_HISTORICAL", "історична довіра");

    auto no_cert = BaseValidReport();
    no_cert.signer_certificate_present = false;
    ExpectCheck(policy::CertificateCheck(no_cert), "unavailable", "SIGNER_CERTIFICATE_MISSING", "немає сертифіката");
}

// --- 2. Сторожа єдиного джерела -------------------------------------------

bool LooksLikeVerdictCode(const std::string& text) {
    // Код вердикту — ALL_CAPS з підкресленнями (SIGNATURE_VALID, LTV_VALID...).
    if (text.empty()) {
        return false;
    }
    for (const char ch : text) {
        const bool upper = ch >= 'A' && ch <= 'Z';
        if (!upper && ch != '_') {
            return false;
        }
    }
    return true;
}

// Шукає конструювання вердикту виду {"<status>", "<CODE>"}.
bool LineBuildsVerdict(const std::string& line) {
    static const char* kStatuses[] = {"valid", "invalid", "warning",
                                      "skipped", "unavailable", "unknown"};
    for (const char* status : kStatuses) {
        const std::string needle = std::string("{\"") + status + "\", \"";
        std::size_t pos = line.find(needle);
        while (pos != std::string::npos) {
            const std::size_t code_start = pos + needle.size();
            const std::size_t code_end = line.find('"', code_start);
            if (code_end != std::string::npos &&
                LooksLikeVerdictCode(line.substr(code_start, code_end - code_start))) {
                return true;
            }
            pos = line.find(needle, pos + 1);
        }
    }
    return false;
}

void TestVerdictsAreBuiltInOnePlaceOnly() {
    const fs::path lib_root = fs::path(TAMGA_TEST_SOURCE_DIR) / "src" / "lib";
    const fs::path single_source = lib_root / "core" / "policy" / "VerifyChecks.cpp";

    std::error_code ec;
    if (!fs::exists(lib_root, ec)) {
        Fail("не знайдено src/lib — сторожа не може виконати свою роботу");
        return;
    }

    std::size_t inspected = 0;
    std::size_t verdicts_in_single_source = 0;
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
        while (std::getline(source, line)) {
            ++line_no;
            if (!LineBuildsVerdict(line)) {
                continue;
            }
            if (is_single_source) {
                ++verdicts_in_single_source;
                continue;
            }
            Fail("вердикт будується поза VerifyChecks.cpp: " +
                 path.filename().string() + ":" + std::to_string(line_no));
        }
    }

    if (inspected == 0) {
        Fail("не переглянуто жодного файлу — сторожа проходила б вакуумно");
    }
    if (verdicts_in_single_source < 8U) {
        // Якщо в єдиному джерелі раптом менше вердиктів, ніж блоків звіту,
        // сканер не бачить того, що має бачити, — і «успіх» нічого не вартий.
        Fail("у VerifyChecks.cpp знайдено лише " +
             std::to_string(verdicts_in_single_source) +
             " вердиктів — перевірка недостовірна");
    }
}

// --- 3. Р-1: сторожа ТОЧОК ЗАСТОСУВАННЯ інваріанта покриття ---------------
//
// Навіщо вона існує. Аудит 2026-08-29 знайшов один і той самий дефект у трьох
// незалежних місцях, і форма була щоразу однакова: у дереві є дві сестринські
// реалізації одного інваріанта, виправлення застосували до однієї, друга
// лишилася вразливою.
//
//   * PAdES: відбиток покривав /Contents, але не /Resources (К-01/E);
//   * ASiC-E XAdES рахував покриття, ASiC-E CAdES не рахував зовсім (П-03);
//   * ASiC-S не рахує й досі — саме цей тест його і знайшов.
//
// Наявний храповик дублювання (ADR-027) цього не бачить: він ловить однакові
// ІМЕНА функцій, а тут не копії коду, а РОЗБІЖНІ реалізації спільного
// інваріанта. Тому потрібна окрема сторожа — за точками застосування.
//
// Правило: кожен шлях `Session::Verify*`, який повертає вердикт про КОНТЕЙНЕР
// або ДОКУМЕНТ, зобовʼязаний явно оголосити покриття (`coverage_status`).
// Мовчання дає дефолт `not-applicable` + `container_coverage_complete=true`,
// тобто «покрито все» — і гейт К-01 у SummaryCheck перетворюється на no-op.
//
// Друга половина правила важливіша за першу: НОВИЙ шлях `Session::Verify*`,
// якого немає в жодному зі списків нижче, теж валить сторожу. Так рішення
// «оголошує покриття / не має його оголошувати» стає обовʼязковим і явним, а
// не пропущеним за замовчуванням.
struct VerifyPathExpectation {
    const char* function;
    bool must_declare_coverage;
    const char* why;
};

const VerifyPathExpectation kVerifyPaths[] = {
    // Контейнерні та документні формати: покриття є частиною вердикту.
    {"VerifyFileAsicS", true, "ASiC-S: рівно один підписаний обʼєкт (ETSI TS 102 918)"},
    {"VerifyFileAsicE", true, "ASiC-E CAdES: кожен data-object має бути покритий"},
    {"VerifyFileAsicEXades", true, "ASiC-E XAdES: кожен data-object має ds:Reference"},
    {"VerifyPdf", true, "PAdES: після підписаної ревізії немає непідписаних змін"},
    // Формати без поняття контейнера чи ревізій: покриття не визначене, і
    // дефолт `not-applicable` тут чесний.
    {"VerifyXml", false, "XMLDSIG/XAdES поза контейнером: обсяг задають ds:Reference"},
    {"VerifyFile", false, "detached CMS над файлом: контейнера й ревізій немає"},
};

// Приватні помічники, чиї імена починаються на `Verify`, але шляхами перевірки
// не є. Список навмисно явний: мовчазне виключення за патерном імені сховало б
// і справжній новий шлях, назва якого просто не вгадала патерн.
const char* const kNonVerificationHelpers[] = {
    "VerifyReportStillOwnedByThisThreadLocked",
};

std::string ReadWholeFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return {};
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

// Тіло функції `bool Session::<name>(` — від її сигнатури до наступного
// визначення `bool Session::` (або кінця файлу).
std::string ExtractSessionFunctionBody(const std::string& source, const std::string& name) {
    const std::string signature = "bool Session::" + name + "(";
    const std::size_t start = source.find(signature);
    if (start == std::string::npos) {
        return {};
    }
    const std::size_t next = source.find("\nbool Session::", start + signature.size());
    return source.substr(start, next == std::string::npos ? std::string::npos : next - start);
}

void TestCoverageInvariantIsAppliedOnEveryContainerPath() {
    const fs::path session_dir = fs::path(TAMGA_TEST_SOURCE_DIR) / "src" / "lib" / "core" / "session";
    std::error_code ec;
    if (!fs::exists(session_dir, ec)) {
        Fail("не знайдено src/lib/core/session — сторожа не може виконати свою роботу");
        return;
    }

    std::string all_sources;
    std::size_t inspected = 0;
    for (const auto& entry : fs::directory_iterator(session_dir)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".ipp") {
            continue;
        }
        ++inspected;
        all_sources += ReadWholeFile(entry.path());
        all_sources += "\n";
    }
    if (inspected == 0) {
        Fail("не переглянуто жодного .ipp — сторожа проходила б вакуумно");
        return;
    }

    // 1. Кожен відомий шлях поводиться так, як записано.
    for (const auto& expectation : kVerifyPaths) {
        const std::string body = ExtractSessionFunctionBody(all_sources, expectation.function);
        if (body.empty()) {
            Fail(std::string("шлях ") + expectation.function +
                 " зник або перейменований — оновіть kVerifyPaths разом зі змінами");
            continue;
        }
        const bool declares = body.find("coverage_status") != std::string::npos;
        if (expectation.must_declare_coverage && !declares) {
            Fail(std::string(expectation.function) +
                 " не оголошує coverage_status, хоча зобовʼязаний (" + expectation.why +
                 "). Мовчання дає дефолт not-applicable і робить гейт К-01 у SummaryCheck no-op");
        }
        if (!expectation.must_declare_coverage && declares) {
            Fail(std::string(expectation.function) +
                 " оголошує coverage_status, хоча за kVerifyPaths не мав би — "
                 "поведінка змінилась, оновіть список і поясніть чому");
        }
    }

    // 2. Храповик: новий шлях Verify* не може зʼявитися без явного рішення.
    std::size_t pos = 0;
    const std::string marker = "bool Session::Verify";
    while ((pos = all_sources.find(marker, pos)) != std::string::npos) {
        const std::size_t name_start = pos + std::string("bool Session::").size();
        const std::size_t paren = all_sources.find('(', name_start);
        pos = name_start;
        if (paren == std::string::npos) {
            continue;
        }
        const std::string name = all_sources.substr(name_start, paren - name_start);
        bool known = false;
        for (const auto& expectation : kVerifyPaths) {
            if (name == expectation.function) {
                known = true;
                break;
            }
        }
        for (const char* helper : kNonVerificationHelpers) {
            if (name == helper) {
                known = true;
                break;
            }
        }
        // `VerifyData*` — крипто-примітиви над байтами, а не над контейнером;
        // вони не мають ані контейнера, ані ревізій. Решта мусить бути в списку.
        if (!known && name.rfind("VerifyData", 0) != 0) {
            Fail("новий шлях перевірки `Session::" + name +
                 "` відсутній у kVerifyPaths: вирішіть явно, чи зобовʼязаний він "
                 "оголошувати coverage_status, і внесіть його до списку");
        }
    }
}

// --- 4. ADR-033: прямі перевірки шару коміту звіту ------------------------
//
// Усе нижче донедавна перевірити було НЕМОЖЛИВО. `ApplyFormatTimestampVerdict`,
// `ApplyEntryTimestampVerdict`, `BuildVerifyMessage` і таблиця форматів жили в
// анонімних namespace усередині `.ipp`/`.cpp`: ззовні їх не видно, тож єдиний
// доступний спосіб перевірити правило В-03 чи текст С-08 — прогнати повний
// Verify* із ключем, файлом і (для мітки часу) мережею. Саме тому чотири
// дефекти цього циклу (К-01, П-02, П-03, FND-015) жили в цій ділянці не
// поміченими: тести бачили лише підсумок, а не саме правило.
//
// Тепер це чисті функції над `VerifyReport`/`SignatureEntry` у
// `core/session/VerifyReportCommit`, і кожне правило перевіряється прямо.

void ExpectTimestamp(const VerifyReport& report,
                     const bool expected_valid,
                     const char* expected_status,
                     const std::string& scenario) {
    if (report.timestamp_valid != expected_valid || report.timestamp_status != expected_status) {
        Fail(scenario + ": очікували " + (expected_valid ? "valid" : "invalid") + "/" +
             expected_status + ", отримали " + (report.timestamp_valid ? "valid" : "invalid") +
             "/" + report.timestamp_status);
    }
}

void TestClearedReportCarriesContractDefaults() {
    const VerifyReport cleared = tamga::core::MakeClearedVerifyReport();

    // Три поля мають НЕ порожні значення за замовчуванням, і саме ці значення
    // читає 1С, доки жодної перевірки ще не було. Порожній рядок тут означав
    // би «немає даних», що не те саме, що «не перевірялося».
    if (cleared.policy != "crypto-integrity-only") {
        Fail("очищений звіт: policy=" + cleared.policy + ", очікували crypto-integrity-only");
    }
    if (cleared.trust_status != "not-implemented") {
        Fail("очищений звіт: trustStatus=" + cleared.trust_status + ", очікували not-implemented");
    }
    if (cleared.revocation_status != "not-checked") {
        Fail("очищений звіт: revocationStatus=" + cleared.revocation_status + ", очікували not-checked");
    }
    if (cleared.has_result || cleared.execution_succeeded || cleared.signature_valid) {
        Fail("очищений звіт не має стверджувати ані результату, ані валідності");
    }
    if (tamga::core::ComputeVerifySummary(cleared) != "not-executed") {
        Fail("очищений звіт має давати summaryCode=not-executed, отримали " +
             tamga::core::ComputeVerifySummary(cleared));
    }
}

void TestCommitFillsOnlyDeclaredFields() {
    tamga::core::VerifyOutcome outcome;
    outcome.operation = "VerifyFileAsicEXades";
    outcome.execution_succeeded = true;
    outcome.signature_valid = true;

    VerifyReport xades = tamga::core::MakeClearedVerifyReport();
    tamga::core::CommitVerifyOutcome(xades, outcome);
    if (xades.container_type != "ASiC-E" || xades.signature_format != "XAdES" ||
        xades.format_profile != "XAdES") {
        Fail("коміт VerifyFileAsicEXades має проставити ASiC-E/XAdES/XAdES, отримали " +
             xades.container_type + "/" + xades.signature_format + "/" + xades.format_profile);
    }
    if (!xades.has_result || !xades.execution_succeeded || !xades.signature_valid) {
        Fail("коміт не переніс факти виконання у звіт");
    }

    // Дзеркальна половина: жодна ІНША операція міток формату не отримує.
    // Без цієї перевірки «зручне» розширення умови на сусідню операцію
    // пройшло б непоміченим — це рівно та форма, що дала П-03.
    const VerifyReport untouched = tamga::core::MakeClearedVerifyReport();
    tamga::core::VerifyOutcome other = outcome;
    other.operation = "VerifyFileAsicE";
    VerifyReport cades = tamga::core::MakeClearedVerifyReport();
    tamga::core::CommitVerifyOutcome(cades, other);
    if (cades.container_type != untouched.container_type ||
        cades.signature_format != untouched.signature_format ||
        cades.format_profile != untouched.format_profile) {
        Fail("коміт VerifyFileAsicE не має чіпати мітки формату, отримали " +
             cades.container_type + "/" + cades.signature_format + "/" + cades.format_profile);
    }
}

void TestBuildVerifyMessageDoesNotOverstate() {
    using tamga::core::BuildVerifyMessage;

    if (BuildVerifyMessage(true, true, "власна причина") != "власна причина") {
        Fail("власне повідомлення викликача має лишатися незмінним");
    }
    // С-08: успішна перевірка цілісності НЕ сміє звучати як повна перевірка
    // довіри — і навпаки, не сміє стверджувати, що довіри не реалізовано.
    const std::string success = BuildVerifyMessage(true, true, {});
    if (success.find("policyDecision") == std::string::npos) {
        Fail("повідомлення про успіх має відсилати до policyDecision, отримали: " + success);
    }
    if (success.find("not implemented") != std::string::npos) {
        Fail("рецидив С-08: повідомлення знову каже, що trust validation не реалізовано");
    }
    const std::string negative = BuildVerifyMessage(true, false, {});
    if (negative.find("negative result") == std::string::npos) {
        Fail("невдала перевірка має так і називатися, отримали: " + negative);
    }
    if (!BuildVerifyMessage(false, false, {}).empty()) {
        Fail("операція, яка не виконалась, не має вигадувати собі текст");
    }
}

void TestFormatTimestampVerdictRequiresCanonicalProof() {
    using tamga::core::ApplyFormatTimestampVerdict;

    VerifyReport report = tamga::core::MakeClearedVerifyReport();

    ApplyFormatTimestampVerdict(report, /*crypto_valid=*/false, /*canonical_full=*/false);
    ExpectTimestamp(report, false, "timestamp-invalid", "крипто-провал");

    // В-03, ядро правила: коректно підписаний токен від НЕПЕРЕВІРЕНОЇ TSA — це
    // `timestamp-partial`, а не `timestamp-valid`. Перевіряємо саме з уже
    // проставленого «valid», щоб довести ПОНИЖЕННЯ, а не просто збіг дефолту.
    report.timestamp_valid = true;
    report.timestamp_status = "timestamp-valid";
    ApplyFormatTimestampVerdict(report, /*crypto_valid=*/true, /*canonical_full=*/false);
    ExpectTimestamp(report, false, "timestamp-partial", "крипто-ок без канонічного доказу");

    ApplyFormatTimestampVerdict(report, /*crypto_valid=*/true, /*canonical_full=*/true);
    ExpectTimestamp(report, true, "timestamp-valid", "канонічний доказ повний");

    // Канонічний доказ НЕ рятує зламану криптографію.
    ApplyFormatTimestampVerdict(report, /*crypto_valid=*/false, /*canonical_full=*/true);
    ExpectTimestamp(report, false, "timestamp-invalid", "канонічний доказ проти крипто-провалу");
}

void TestEntryAndFormatTimestampVerdictsAgree() {
    // В-03 (per-signature). Дефект був не в самому правилі, а в тому, що
    // верхньорівневе поле і запис `signatures[]` рахувались ОКРЕМО: звіт казав
    // `timestamp-partial` угорі й `timestamp-valid` у кожному записі поруч.
    // Тепер обидві функції поруч і порівнюються прямо — рівно тієї форми
    // перевірки, якої бракувало.
    for (const bool crypto_valid : {false, true}) {
        VerifyReport report = tamga::core::MakeClearedVerifyReport();
        tamga::core::SignatureEntry entry;
        entry.timestamp_valid = true;
        entry.timestamp_status = "timestamp-valid";

        tamga::core::ApplyFormatTimestampVerdict(report, crypto_valid, /*canonical_full=*/false);
        tamga::core::ApplyEntryTimestampVerdict(entry, crypto_valid);

        if (report.timestamp_valid != entry.timestamp_valid ||
            report.timestamp_status != entry.timestamp_status) {
            Fail(std::string("вердикт мітки часу розійшовся між звітом і записом signatures[] при cryptoValid=") +
                 (crypto_valid ? "true" : "false") + ": " + report.timestamp_status + " проти " +
                 entry.timestamp_status);
        }
    }
}

void TestTimestampNotesAreAppendedWithDistinctPrefixes() {
    VerifyReport report = tamga::core::MakeClearedVerifyReport();

    tamga::core::AppendContainerTimestampMessage(report, {});
    if (!report.message.empty()) {
        Fail("порожня примітка не має нічого дописувати");
    }

    tamga::core::AppendContainerTimestampMessage(report, "перша причина");
    if (report.message != "ASiC container timestamp: перша причина") {
        Fail("перша примітка не має отримувати розділювач: " + report.message);
    }

    tamga::core::AppendXadesTimestampMessage(report, "друга причина");
    if (report.message !=
        "ASiC container timestamp: перша причина; XAdES timestamp policy: друга причина") {
        Fail("друга примітка має відділятися '; ' і мати ВЛАСНИЙ префікс: " + report.message);
    }
}

// Р-1 у формі, застосовній до шару коміту: кожна операція, назву якої код
// справді записує у звіт, мусить бути в таблиці нижче з ЯВНИМ рішенням про
// мітки формату. Мовчазний дефолт `unknown/unknown` тут не помилка сам по
// собі — помилкою є не помітити, що нова операція його отримала.
struct OperationLabelExpectation {
    const char* operation;
    const char* container_type;   // очікуване значення з таблиці
    const char* signature_format;
    const char* why;
};

const OperationLabelExpectation kOperationLabels[] = {
    {"VerifyData", "CAdES detached", "cms-detached", "detached CMS над байтами"},
    {"VerifyDataBase64", "CAdES detached", "cms-detached", "той самий шлях, вхід у Base64"},
    {"VerifyFile", "CAdES detached", "cms-detached", "detached CMS над файлом"},
    {"RawVerifyFile", "CAdES detached", "cms-detached", "detached CMS, сирий підпис із файлу"},
    {"VerifyDataInternal", "CAdES attached", "cms-attached", "attached CMS над байтами"},
    {"VerifyDataInternalBase64", "CAdES attached", "cms-attached", "той самий шлях, вхід у Base64"},
    {"VerifyDataInternalStr", "CAdES attached", "cms-attached", "той самий шлях, рядковий результат"},
    {"VerifyDataInternalBase64Str", "CAdES attached", "cms-attached", "той самий шлях, Base64 + рядок"},
    {"VerifyFileAsicS", "ASiC-S", "asic-s", "контейнер ASiC-S"},
    {"VerifyFileAsicE", "ASiC-E", "asic-e", "контейнер ASiC-E з CAdES"},
    {"VerifyFileAsicEXades", "ASiC-E", "XAdES", "контейнер ASiC-E з XAdES"},
    // Дві операції НАВМИСНО падають у дефолт: мітки їм задає сам шлях
    // перевірки, викликаючи RefreshUserReport("PDF", "PAdES") і
    // RefreshUserReport("", "XAdES") напряму. Таблиця для них не працює, і це
    // зафіксовано явно, а не мовчки: якщо котрийсь із цих шляхів колись
    // перейде на RefreshUserReportForCurrentOperation(), звіт втратить мітки —
    // і цей рядок буде першим місцем, куди подивиться наступний виконавець.
    {"VerifyPdf", "unknown", "unknown", "мітки задає SessionPdfOps: RefreshUserReport(\"PDF\", \"PAdES\")"},
    {"VerifyXml", "unknown", "unknown", "мітки задає SessionXmlOps: RefreshUserReport(\"\", \"XAdES\")"},
};

// Витягує всі рядкові літерали операцій, які код записує у звіт.
std::set<std::string> CollectCommittedOperationNames(const std::string& sources) {
    static const char* const kSetters[] = {
        "SetVerifyReport(\"",
        "OverrideVerifyReportOperation(\"",
        "operation = \"",
    };
    std::set<std::string> names;
    for (const char* setter : kSetters) {
        const std::string needle = setter;
        std::size_t pos = 0;
        while ((pos = sources.find(needle, pos)) != std::string::npos) {
            const std::size_t start = pos + needle.size();
            const std::size_t end = sources.find('"', start);
            pos = start;
            if (end == std::string::npos) {
                continue;
            }
            const std::string name = sources.substr(start, end - start);
            if (name.rfind("Verify", 0) == 0 || name.rfind("RawVerify", 0) == 0) {
                names.insert(name);
            }
        }
    }
    return names;
}

void TestUserReportFormatTableCoversEveryOperation() {
    using tamga::core::UserReportFormatForOperation;

    for (const auto& expectation : kOperationLabels) {
        const auto labels = UserReportFormatForOperation(expectation.operation);
        if (std::string(labels.container_type) != expectation.container_type ||
            std::string(labels.signature_format) != expectation.signature_format) {
            Fail(std::string("мітки формату для ") + expectation.operation + " змінилися: очікували " +
                 expectation.container_type + "/" + expectation.signature_format + ", отримали " +
                 labels.container_type + "/" + labels.signature_format);
        }
    }

    // Храповик: нова операція не може зʼявитися без явного рішення про мітки.
    const fs::path session_dir = fs::path(TAMGA_TEST_SOURCE_DIR) / "src" / "lib" / "core" / "session";
    std::string sources;
    std::error_code ec;
    if (!fs::exists(session_dir, ec)) {
        Fail("не знайдено src/lib/core/session — сторожа міток не може працювати");
        return;
    }
    for (const auto& entry : fs::recursive_directory_iterator(session_dir)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const std::string ext = entry.path().extension().string();
        if (ext != ".cpp" && ext != ".ipp") {
            continue;
        }
        sources += ReadWholeFile(entry.path());
        sources += '\n';
    }
    if (sources.empty()) {
        Fail("не прочитано жодного джерела сесії — сторожа міток проходила б вакуумно");
        return;
    }

    const std::set<std::string> committed = CollectCommittedOperationNames(sources);
    if (committed.size() < 10U) {
        Fail("знайдено лише " + std::to_string(committed.size()) +
             " операцій — сканер не бачить того, що має бачити");
    }
    for (const std::string& name : committed) {
        bool known = false;
        for (const auto& expectation : kOperationLabels) {
            if (name == expectation.operation) {
                known = true;
                break;
            }
        }
        if (!known) {
            Fail("операція `" + name +
                 "` записується у звіт, але відсутня в kOperationLabels: вирішіть явно, "
                 "які мітки формату має бачити 1С, і внесіть рядок");
        }
    }
}

void TestVerifyReportOwnershipTracksCommittingThread() {
    // Н-04. Раніше цей інваріант можна було перевірити лише двома
    // паралельними Verify* на живій сесії — з ключем, файлом і гонкою, яку
    // тест не контролює. Тепер він перевіряється прямо.
    tamga::core::VerifyReportOwnership fresh;
    if (fresh.StillOwnedByThisThread()) {
        Fail("звіт без жодного коміту не може вважатися власним");
    }

    tamga::core::VerifyReportOwnership first;
    first.MarkCommitted();
    if (!first.StillOwnedByThisThread()) {
        Fail("одразу після власного коміту звіт має лишатися власним");
    }

    // Той самий потік закомітив ІНШИЙ звіт — попередній перестав бути актуальним.
    tamga::core::VerifyReportOwnership second;
    second.MarkCommitted();
    if (first.StillOwnedByThisThread()) {
        Fail("після наступного коміту в тому ж потоці попередній звіт більше не свій");
    }
    if (!second.StillOwnedByThisThread()) {
        Fail("останній коміт потоку має лишатися своїм");
    }

    // Ядро Н-04: звіт, закомічений ІНШИМ потоком, не сміє вважатися своїм —
    // саме це не давало доуточненню (операція, статус мітки часу) потрапити в
    // чужий результат.
    tamga::core::VerifyReportOwnership foreign;
    std::thread worker([&foreign] { foreign.MarkCommitted(); });
    worker.join();
    if (foreign.StillOwnedByThisThread()) {
        Fail("звіт, закомічений іншим потоком, не може вважатися власним");
    }
    if (foreign.epoch() == 0 || foreign.epoch() == second.epoch()) {
        Fail("епохи мають бути глобально унікальними, отримали " +
             std::to_string(foreign.epoch()) + " і " + std::to_string(second.epoch()));
    }
}

} // namespace

int main() {
    TestBaselineIsValid();
    TestCoverageIncompleteIsInvalid();
    TestPartialTimestampBeatsValidFlag();
    TestLtvRequiresValidatedEvidence();
    TestNotExecutedAndFailures();
    TestMalformedContainerHasItsOwnVerdict();
    TestProvenPolicyFailureIsInvalid();
    TestVerdictsAreBuiltInOnePlaceOnly();
    TestCoverageInvariantIsAppliedOnEveryContainerPath();
    TestClearedReportCarriesContractDefaults();
    TestCommitFillsOnlyDeclaredFields();
    TestBuildVerifyMessageDoesNotOverstate();
    TestFormatTimestampVerdictRequiresCanonicalProof();
    TestEntryAndFormatTimestampVerdictsAgree();
    TestTimestampNotesAreAppendedWithDistinctPrefixes();
    TestUserReportFormatTableCoversEveryOperation();
    TestVerifyReportOwnershipTracksCommittingThread();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "verify checks: OK\n";
    return 0;
}
