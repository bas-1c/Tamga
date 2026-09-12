// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Дрібні примітиви, від яких залежить усе інше: base64, відображення кодів
// помилок, конвертація Variant для 1С, завантажувач ключів PEM/DER, перелік
// підтримуваних медіа-типів.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "types.h"
#include "IMemoryManager.h"
#include "asic/AsicReader.h"
#include "asic/AsicWriter.h"
#include "asic/AsicContainers.h"
#include "miniz.h"
#include "core/Errors.h"
#include "core/HttpClient.h"
#include "core/KeyParsers.h"
#include "core/net/CaSettingsRegistry.h"
#include "core/net/CertificateFetcher.h"
#include "core/net/CertificateResolver.h"
#include "core/Session.h"
#include "tamga/tamga_c_api.h"
#include "core/TspClient.h"
#include "core/policy/AiaIssuerFetcher.h"
#include "core/policy/CertificateChainValidator.h"
#include "core/policy/CrlValidator.h"
#include "core/policy/CrlCache.h"
#include "core/policy/ImprintDigest.h"
#include "core/policy/OcspValidator.h"
#include "core/policy/PolicyCache.h"
#include "core/policy/TimestampValidator.h"
#include "core/policy/TlXmlSigCheck.h"
#include "core/policy/TrustListParser.h"
#include "core/policy/TrustListSettings.h"
#include "core/policy/TrustListSync.h"
#include "core/policy/Sha256Helper.h"
#include "core/policy/UserReportBuilder.h"
#include "core/session/VerifySummary.h"
#include "core/validation/EvidenceStore.h"
#include "core/validation/PathEngine.h"
#include "core/validation/PolicyResolver.h"
#include "core/validation/SigningTimeResolver.h"
#include "core/validation/ValidationReportJson.h"
#include "core/validation/ValidationReportProjection.h"
#include "core/validation/TrustServiceEvaluator.h"
#include "core/validation/RevocationEngine.h"
#include "core/validation/TimestampEngine.h"
#include "core/validation/ValidationEngine.h"
#include "core/CryptoniteAdapter.h"
#include "cli/CliEvidence.h"
#include "cli/CliExitCodes.h"
#include "core/policy/ImprintDigest.h"
#include "nativeapi/TamgaAddIn.h"
#include "util/AsicUri.h"
#include "util/Base64.h"
#include "util/FileSystem.h"
#include "util/SecureZero.h"
#include "util/Utf.h"
#include "nativeapi/VariantUtils.h"

// Phase 0 (ADR 012): стаб-заголовки форматних підсистем XMLDSIG/XAdES/PAdES.
// Включення тут дає compile-smoke у проєктному тулчейні — заголовки мають
// парситися й бути взаємно консистентними, поки .cpp зʼявляться у фазах 1-6.
#include "core/SignatureRequest.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/XmlTransformEngine.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSecContext.h"
#include "xmldsig/XmlSignatureBuilder.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xades/XadesTypes.h"
#include "xades/XadesBuilder.h"
#include "xades/XadesVerifier.h"
#include "pades/PdfTypes.h"
#include "pades/PdfParser.h"
#include "pades/PdfByteRange.h"
#include "pades/PadesBuilder.h"
#include "pades/PadesVerifier.h"

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "aid.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "cert_engine.h"
#include "certificate_request_engine.h"
#include "crl.h"
#include "crl_engine.h"
#include "cryptonite_manager.h"
#include "digest_adapter.h"
#include "dstu4145.h"
#include "dstu7564.h"
#include "ext.h"
#include "gost28147.h"
#include "oids.h"
#include "ocsp_response.h"
#include "ocsp_response_engine.h"
#include "pkcs12.h"
#include "pkcs8.h"
#include "sign_adapter.h"
#include "spki.h"
#include "verify_adapter.h"
#include "content_info.h"
#include "signed_data.h"
#include "CertificateSerialNumber.h"
#include "RevokedCertificate.h"
#include "TSTInfo.h"
#include "signed_data_engine.h"
#include "signer_info_engine.h"
#include "signer_info.h"
#include "CertificateSet.h"
#include "SignerIdentifier.h"
#include "pkix_utils.h"
#include "tsp_request.h"
#include "tsp_response.h"
#include "tsp_request_engine.h"
#include "tsp_response_engine.h"
#include "adapters_map.h"
#include "DigestAlgorithmIdentifiers.h"
#include "MessageImprint.h"
#include "AlgorithmIdentifier.h"
#if defined(_WIN32)
#include "dirent_internal.h"
#endif
}
#endif

#include "support/TestSupport.h"
#include "suites/Suites.h"

using namespace tamga_tests;

void TestBase64WhitespaceDecode() {
    std::vector<std::uint8_t> decoded;
    ExpectTrue(tamga::util::Base64Decode("SGV s\nbG8=\r\n", decoded), "Base64Decode should ignore ASCII whitespace");
    ExpectTrue(std::string(decoded.begin(), decoded.end()) == "Hello", "Base64Decode should preserve payload after whitespace removal");
}

void TestErrorsToStringMapping() {
    using tamga::core::ErrorCode;
    using tamga::core::ToString;

    ExpectTrue(std::string(ToString(ErrorCode::None)) == "OK", "ErrorCode::None should map to OK");
    ExpectTrue(std::string(ToString(ErrorCode::InvalidArgument)) == "Invalid argument", "ErrorCode::InvalidArgument should map to readable text");
    ExpectTrue(std::string(ToString(static_cast<ErrorCode>(9999))) == "Unknown error", "Unknown ErrorCode should map to Unknown error");
}

void TestCliSignFailureExitCodeMapsMissingCertificateAsKeyError() {
    using tamga::core::ErrorCode;

    const std::string missing_certificate =
        "Не знайдено відкритий сертифікат для закритого ключа. "
        "Покладіть файл сертифіката (.cer/.crt) поруч із ключем";
    ExpectTrue(tamga::cli::SignFailureExitCode(ErrorCode::InternalError,
                                               missing_certificate) == 2,
               "CLI missing-certificate failure must use the documented key-error exit code");
    ExpectTrue(tamga::cli::SignFailureExitCode(
                   ErrorCode::InternalError,
                   "XAdES signing failed: " + missing_certificate) == 2,
               "CLI must recognize a nested missing-certificate diagnostic from every signer");
    ExpectTrue(tamga::cli::SignFailureExitCode(ErrorCode::OnlineServiceUnavailable,
                                               "TSP unavailable") == 3,
               "CLI online-service failure must preserve exit code 3");
    ExpectTrue(tamga::cli::SignFailureExitCode(ErrorCode::InternalError,
                                               "generic signing failure") == 1,
               "CLI generic signing failure must preserve exit code 1");
}

// O-03: код виходу перевірки більше не обирається пошуком підрядків у тексті
// звіту. Тест закріплює саме те, що робило стару схему крихкою: значення
// беруться з ЯВНОГО шляху в документі, а збіг у чужій секції не рахується.
void TestCliVerificationExitCodeIsTyped() {
    using tamga::cli::ReadVerifyReportFacts;
    using tamga::cli::VerificationFailureExitCode;
    using tamga::core::ErrorCode;

    const auto exit_code = [](const std::string& report) {
        return VerificationFailureExitCode(ErrorCode::InternalError, ReadVerifyReportFacts(report));
    };
    const auto report_with_flags = [](const std::string& flags) {
        return "{\"summary\":{\"status\":\"invalid\"},\"revocation\":{\"revocationStatus\":\"valid\"},"
               "\"diagnostics\":{\"flags\":{" + flags + "}}}";
    };

    // Коди помилок сесії мають пріоритет і зберігають свої значення.
    ExpectTrue(VerificationFailureExitCode(ErrorCode::KeyNotLoaded, {}) == 2,
               "KeyNotLoaded must keep exit code 2");
    ExpectTrue(VerificationFailureExitCode(ErrorCode::OnlineServiceUnavailable, {}) == 3,
               "OnlineServiceUnavailable must keep exit code 3");
    ExpectTrue(VerificationFailureExitCode(ErrorCode::RevocationCheckFailed, {}) == 6,
               "RevocationCheckFailed must keep exit code 6");

    ExpectTrue(exit_code(report_with_flags("\"signatureValid\":false")) == 4,
               "A broken signature must keep exit code 4");
    ExpectTrue(exit_code(report_with_flags("\"signatureValid\":true,"
                                           "\"containerCoverageComplete\":false")) == 4,
               "Incomplete container coverage must keep exit code 4 (K-01)");
    ExpectTrue(exit_code(report_with_flags("\"signatureValid\":true,"
                                           "\"certificateTimeValid\":false")) == 5,
               "An expired certificate must keep exit code 5");
    ExpectTrue(exit_code("{\"revocation\":{\"revocationStatus\":\"revoked\"},"
                         "\"diagnostics\":{\"flags\":{\"signatureValid\":true}}}") == 6,
               "A revoked certificate must keep exit code 6");
    ExpectTrue(exit_code(report_with_flags("\"signatureValid\":true,\"trustValid\":false")) == 7,
               "An untrusted chain must keep exit code 7");
    ExpectTrue(exit_code("") == 7,
               "A missing report must fall back to the policy-failure exit code");

    // Ось чого стара схема не вміла: та сама пара «ключ:значення» у ЧУЖІЙ
    // секції звіту більше не керує кодом виходу. `signatures[]` описує
    // окремий підпис, а не зведений вердикт.
    const std::string foreign_section =
        "{\"revocation\":{\"revocationStatus\":\"valid\"},"
        "\"diagnostics\":{\"flags\":{\"signatureValid\":true,\"trustValid\":false}},"
        "\"signatures\":[{\"signatureValid\":false,\"revocationStatus\":\"revoked\"}]}";
    ExpectTrue(exit_code(foreign_section) == 7,
               "A per-signature field must not override the summary verdict");
}

// Q-07: CLI ігнорував невдачу запису `--evidence-out`. Для валідного підпису це
// давало exit 0 БЕЗ запитаного файла доказів, а звіт про НЕВДАЛУ перевірку у
// файл не потрапляв узагалі, бо блок збереження стояв після раннього виходу.
void TestCliEvidenceOutcomeGovernsExitCode() {
    using tamga::cli::ApplyEvidenceOutcome;
    using tamga::cli::EvidenceOutcome;
    using tamga::cli::WriteEvidence;

    const auto real_writer = [](const std::string& path, const std::string& text) {
        return tamga::util::WriteTextFileAtomic(std::filesystem::u8path(path), text);
    };
    const auto report_provider = [](std::string& out) {
        out = "{\"operation\":\"VerifyFile\"}";
        return true;
    };

    // 1. Артефакта не просили — поведінка CLI не змінюється.
    ExpectTrue(WriteEvidence(std::string(), report_provider, real_writer) == EvidenceOutcome::NotRequested,
               "An empty --evidence-out must stay a no-op");
    ExpectTrue(ApplyEvidenceOutcome(EvidenceOutcome::NotRequested, 0) == 0,
               "Without --evidence-out a valid signature must still exit 0");
    ExpectTrue(ApplyEvidenceOutcome(EvidenceOutcome::NotRequested, 4) == 4,
               "Without --evidence-out the verification verdict must pass through unchanged");

    // 2. Успішний запис: файл існує, вміст той самий, вердикт зберігається.
    const auto evidence_path = MakeTemporaryFixturePath(".evidence.json");
    const auto outcome_ok = WriteEvidence(evidence_path.string(), report_provider, real_writer);
    ExpectTrue(outcome_ok == EvidenceOutcome::Written, "A writable evidence path must produce a file");
    ExpectTrue(std::filesystem::exists(evidence_path), "The evidence file must exist after a successful write");
    {
        std::ifstream written(evidence_path, std::ios::binary);
        const std::string content((std::istreambuf_iterator<char>(written)), std::istreambuf_iterator<char>());
        ExpectTrue(content == "{\"operation\":\"VerifyFile\"}",
                   "The evidence file must contain the technical report verbatim");
    }
    ExpectTrue(ApplyEvidenceOutcome(outcome_ok, 0) == 0,
               "A successful evidence write must not change the exit code");
    ExpectTrue(ApplyEvidenceOutcome(outcome_ok, 6) == 6,
               "A successful evidence write must keep a revoked-certificate verdict");

    // 3. Непридатний батьківський шлях: батьком є звичайний ФАЙЛ, тож
    //    create_directories усередині атомарного writer не може його створити.
    //    Просто неіснуючий каталог тут не годиться — writer створює його сам.
    const auto blocking_file = MakeTemporaryFixturePath(".not-a-directory");
    {
        std::ofstream blocker(blocking_file, std::ios::binary | std::ios::trunc);
        blocker << "x";
    }
    const auto unusable_path = (blocking_file / "evidence.json").string();
    const auto outcome_bad = WriteEvidence(unusable_path, report_provider, real_writer);
    ExpectTrue(outcome_bad == EvidenceOutcome::WriteFailed,
               "An unusable evidence parent path must be reported as a write failure");
    ExpectTrue(ApplyEvidenceOutcome(outcome_bad, 0) == tamga::cli::kEvidenceIoExitCode,
               "Q-07: a valid signature must NOT exit 0 when the requested evidence file was not written");
    ExpectTrue(ApplyEvidenceOutcome(outcome_bad, 4) == tamga::cli::kEvidenceIoExitCode,
               "A failed evidence write must stay non-zero for an invalid signature too");

    // 4. Невдала перевірка з --evidence-out: звіт все одно зберігається, а
    //    код виходу лишається кодом вердикту, а не 0.
    const auto failed_verify_path = MakeTemporaryFixturePath(".failed.json");
    const auto failure_report_provider = [](std::string& out) {
        out = "{\"operation\":\"tamga_session_verify_file\",\"signatureValid\":false}";
        return true;
    };
    const auto outcome_failed_verify =
        WriteEvidence(failed_verify_path.string(), failure_report_provider, real_writer);
    ExpectTrue(outcome_failed_verify == EvidenceOutcome::Written,
               "Q-07: the report of a FAILED verification must reach the evidence file as well");
    ExpectTrue(std::filesystem::exists(failed_verify_path),
               "The evidence file of a failed verification must exist");
    ExpectTrue(ApplyEvidenceOutcome(outcome_failed_verify, 4) == 4,
               "A stored evidence file must not mask the verification verdict");

    // 5. Сесія не віддала звіт — це теж невиконаний запит, а не тиха норма.
    const auto missing_report_provider = [](std::string& out) {
        out.clear();
        return false;
    };
    const auto outcome_no_report =
        WriteEvidence(MakeTemporaryFixturePath(".none.json").string(), missing_report_provider, real_writer);
    ExpectTrue(outcome_no_report == EvidenceOutcome::ReportUnavailable,
               "A missing technical report must be reported, not silently skipped");
    ExpectTrue(ApplyEvidenceOutcome(outcome_no_report, 0) == tamga::cli::kEvidenceIoExitCode,
               "A missing technical report must not leave exit code 0 for a requested artifact");

    std::error_code ec;
    std::filesystem::remove(evidence_path, ec);
    std::filesystem::remove(failed_verify_path, ec);
    std::filesystem::remove(blocking_file, ec);
}

void TestVariantUtilsRoundTrip() {
    TestMemoryManager memory;

    tVariant var{};
    tamga::util::SetBool(&var, true);
    bool bool_value = false;
    ExpectTrue(tamga::util::GetBool(&var, bool_value) && bool_value, "VariantUtils bool round-trip should succeed");

    tVariant int_var{};
    tVarInit(&int_var);
    TV_VT(&int_var) = VTYPE_UI2;
    TV_UI2(&int_var) = 655U;
    std::int32_t parsed_int = 0;
    ExpectTrue(tamga::util::GetInt32(&int_var, parsed_int) && parsed_int == 655, "VariantUtils GetInt32 should support UI2");

    tVariant str_var{};
    const std::wstring text = L"Тестовий рядок";
    ExpectTrue(tamga::util::SetWString(&memory, &str_var, text), "VariantUtils SetWString should allocate and populate value");
    std::wstring text_out;
    ExpectTrue(tamga::util::GetWString(&str_var, text_out) && text_out == text, "VariantUtils GetWString should decode UTF-16 payload");
    void* str_ptr = str_var.pwstrVal;
    memory.FreeMemory(&str_ptr);

    tVariant blob_var{};
    const std::vector<std::uint8_t> blob = {0x00, 0xAB, 0xCD, 0xEF};
    ExpectTrue(tamga::util::SetBlob(&memory, &blob_var, blob), "VariantUtils SetBlob should allocate binary payload");
    std::vector<std::uint8_t> blob_out;
    ExpectTrue(tamga::util::GetBlob(&blob_var, blob_out) && blob_out == blob, "VariantUtils GetBlob should copy binary payload");
    void* blob_ptr = blob_var.pstrVal;
    memory.FreeMemory(&blob_ptr);
}

namespace {

std::vector<std::uint8_t> ReadWrittenFileForTest(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());
}

// Рахує «сміття» поруч із ціллю: файли, чиє ім'я починається з імені цілі, але
// не дорівнює йому. Саме так виглядає забутий тимчасовий файл writer-а.
std::size_t CountTempSiblingsForTest(const std::filesystem::path& target) {
    const std::filesystem::path dir = target.parent_path().empty()
                                          ? std::filesystem::current_path()
                                          : target.parent_path();
    const std::string name = target.filename().string();
    std::size_t count = 0;
    std::error_code ec;
    for (std::filesystem::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string entry = it->path().filename().string();
        if (entry.size() > name.size() && entry.compare(0, name.size(), name) == 0) {
            ++count;
        }
    }
    return count;
}

}  // namespace

void TestAtomicOutputWriteCoversAllPaths() {
    // П-12: усі вихідні шляхи проєкту йдуть через один атомарний writer.
    //
    // Раніше `WriteBinaryFileAtomic` існував, але користувався ним лише
    // `RawSignFile`; вісім інших місць писали прямим `std::ofstream ... trunc`.
    // `trunc` обнуляє ціль ДО появи першого байта нового вмісту, тож перервана
    // операція лишала на місці підписаного контейнера усічений файл.
    //
    // Сам хелпер при цьому мав два власні дефекти, і обидва перевіряються тут.
    const std::vector<std::uint8_t> valuable(64, 0xA5);
    const std::vector<std::uint8_t> replacement(4096, 0x5A);
    std::error_code ec;

    // 1) Голе відносне ім'я без каталогу.
    //    `parent_path()` тут ПОРОЖНІЙ, а `create_directories("")` виставляє
    //    error_code (перевірено на MSVC: ERROR_PATH_NOT_FOUND) — тобто запис у
    //    поточний каталог падав ще до відкриття файлу. Це й пояснює, чому
    //    атомарним writer-ом користувалося рівно одне місце.
    {
        const std::filesystem::path bare = "tamga-atomic-bare-name.bin";
        std::filesystem::remove(bare, ec);
        ExpectTrue(tamga::util::WriteBinaryFileAtomic(bare, replacement),
                   "Atomic write should accept a bare relative name with no parent directory");
        ExpectTrue(ReadWrittenFileForTest(bare) == replacement,
                   "Atomic write to a bare relative name should produce the full content");
        ExpectTrue(CountTempSiblingsForTest(bare) == 0U,
                   "Atomic write should not leave a temporary file next to a bare-name target");
        std::filesystem::remove(bare, ec);
    }

    // 2) Наявний цінний файл заміщується цілком, а не усікається.
    {
        const auto target = MakeTemporaryFixturePath(".asics");
        std::filesystem::remove(target, ec);
        ExpectTrue(tamga::util::WriteBinaryFileAtomic(target, valuable),
                   "Atomic write should create the target file");
        ExpectTrue(ReadWrittenFileForTest(target) == valuable,
                   "Atomic write should store the first version in full");
        ExpectTrue(tamga::util::WriteBinaryFileAtomic(target, replacement),
                   "Atomic write should replace an existing target");
        ExpectTrue(ReadWrittenFileForTest(target) == replacement,
                   "Replacing an existing target should leave the new content in full");
        ExpectTrue(CountTempSiblingsForTest(target) == 0U,
                   "Atomic write should not leave a temporary file next to the target");
        std::filesystem::remove(target, ec);
    }

    // 3) Unicode-шлях і відсутній батьківський каталог.
    //    Непорожній батьківський каталог і далі створюється — це та половина
    //    старої поведінки, яку треба було зберегти.
    {
        const auto root = MakeTemporaryFixturePath(".unicode-out");
        std::filesystem::remove_all(root, ec);
        const auto target = root / u8"Тамга підпис" / u8"документ.asice";
        const std::string text = u8"вміст із кирилицею";
        ExpectTrue(tamga::util::WriteTextFileAtomic(target, text),
                   "Atomic write should create missing parent directories for a Unicode path");
        const auto written = ReadWrittenFileForTest(target);
        ExpectTrue(std::string(written.begin(), written.end()) == text,
                   "Atomic write should store the whole text payload on a Unicode path");
        ExpectTrue(CountTempSiblingsForTest(target) == 0U,
                   "Atomic write should not leave a temporary file on a Unicode path");
        std::filesystem::remove_all(root, ec);
    }
}

void TestVariantUtilsEnforcesDirectInputLimit() {
    // П-11: межа розміру для ПРЯМИХ (не файлових) вхідних даних з 1С.
    //
    // Ліміт `kMaxInputFileSize` застосовувався лише там, де вхід приходив
    // ШЛЯХОМ до файлу. `SignXml`/`VerifyXml`/`SignPdf`/`VerifyPdf`/`SignData`
    // приймають дані ЗНАЧЕННЯМ, і там межі не було жодної: довжини `strLen`
    // і `wstrLen` повністю керуються тим, хто викликає компоненту.
    //
    // Чого цей тест НЕ стверджує: що без межі падав процес 1С.
    // `NativeApiExceptionGuard` (`src/nativeapi/Export.cpp`) обгортає кожну
    // точку входу `IComponentBase` і ловить `std::bad_alloc` — метод повертає
    // false, процес живий. Проблема була в іншому: межі не було, тож відмова
    // наставала не за правилом, а за фактом вичерпання пам'яті.
    const std::uintmax_t limit = tamga::util::kMaxInputFileSize;

    // --- BLOB: ліміт + 1 байт має бути відхилений -------------------------
    {
        std::vector<char> payload(static_cast<std::size_t>(limit) + 1U, 'b');
        tVariant blob_var{};
        tVarInit(&blob_var);
        TV_VT(&blob_var) = VTYPE_BLOB;
        blob_var.pstrVal = payload.data();
        blob_var.strLen = static_cast<std::uint32_t>(payload.size());

        std::vector<std::uint8_t> out;
        ExpectFalse(tamga::util::GetBlob(&blob_var, out),
                    "GetBlob should reject a blob larger than the shared input limit");
        ExpectTrue(out.empty(), "GetBlob must not copy anything from an oversized blob");
    }

    // --- BLOB: рівно ліміт має проходити ----------------------------------
    // Без цієї половини «межа» була б просто забороною: треба довести, що
    // відсікається саме перевищення, а не легітимний граничний розмір.
    {
        std::vector<char> payload(static_cast<std::size_t>(limit), 'a');
        tVariant blob_var{};
        tVarInit(&blob_var);
        TV_VT(&blob_var) = VTYPE_BLOB;
        blob_var.pstrVal = payload.data();
        blob_var.strLen = static_cast<std::uint32_t>(payload.size());

        std::vector<std::uint8_t> out;
        ExpectTrue(tamga::util::GetBlob(&blob_var, out),
                   "GetBlob should accept a blob of exactly the shared input limit");
        ExpectTrue(out.size() == static_cast<std::size_t>(limit),
                   "GetBlob should copy the whole blob at the limit");
    }

    // --- Рядок: межа рахується в байтах UTF-16-навантаження ---------------
    const std::size_t units_at_limit = static_cast<std::size_t>(limit) / sizeof(WCHAR_T);
    {
        std::vector<WCHAR_T> payload(units_at_limit + 1U, static_cast<WCHAR_T>(u'x'));
        tVariant str_var{};
        tVarInit(&str_var);
        TV_VT(&str_var) = VTYPE_PWSTR;
        str_var.pwstrVal = payload.data();
        str_var.wstrLen = static_cast<std::uint32_t>(payload.size());

        std::wstring out;
        ExpectFalse(tamga::util::GetWString(&str_var, out),
                    "GetWString should reject a string larger than the shared input limit");
        ExpectTrue(out.empty(), "GetWString must not convert anything from an oversized string");
    }
    {
        std::vector<WCHAR_T> payload(units_at_limit, static_cast<WCHAR_T>(u'x'));
        tVariant str_var{};
        tVarInit(&str_var);
        TV_VT(&str_var) = VTYPE_PWSTR;
        str_var.pwstrVal = payload.data();
        str_var.wstrLen = static_cast<std::uint32_t>(payload.size());

        std::wstring out;
        ExpectTrue(tamga::util::GetWString(&str_var, out),
                   "GetWString should accept a string of exactly the shared input limit");
        ExpectTrue(out.size() == units_at_limit,
                   "GetWString should convert the whole string at the limit");
    }

    // --- Межа перевіряється ДО копіювання ---------------------------------
    //
    // Тут `tVariant` бреше про довжину: реальний буфер — 16 байтів, а
    // заявлено більше за ліміт. Цей блок безпечний РІВНО ТОМУ, що перевірка
    // стоїть перед `assign`/конверсією. Якби вона стояла після, тест не
    // «впав би асертом», а прочитав би за межами буфера — тобто сам факт, що
    // ці чотири рядки виконуються і повертають false, і є доказом порядку.
    {
        std::vector<char> tiny(16, 'z');
        tVariant lying_blob{};
        tVarInit(&lying_blob);
        TV_VT(&lying_blob) = VTYPE_BLOB;
        lying_blob.pstrVal = tiny.data();
        lying_blob.strLen = static_cast<std::uint32_t>(limit + 1U);

        std::vector<std::uint8_t> out;
        ExpectFalse(tamga::util::GetBlob(&lying_blob, out),
                    "GetBlob should reject an oversized length before touching the buffer");

        std::vector<WCHAR_T> tiny_units(8, static_cast<WCHAR_T>(u'z'));
        tVariant lying_str{};
        tVarInit(&lying_str);
        TV_VT(&lying_str) = VTYPE_PWSTR;
        lying_str.pwstrVal = tiny_units.data();
        lying_str.wstrLen = static_cast<std::uint32_t>(units_at_limit + 1U);

        std::wstring text_out;
        ExpectFalse(tamga::util::GetWString(&lying_str, text_out),
                    "GetWString should reject an oversized length before converting the buffer");
    }
}

void TestSecureClearWideStringReleasesBuffer() {
    // П-06 (обмежений доказ — читай уважно).
    //
    // Перевірити, що звільнена купа справді занулена, з тесту НЕМОЖЛИВО: читання
    // за звільненим вказівником — UB, і саме та оптимізація, від якої захищає
    // `SecureZero`, робить будь-який такий «доказ» недостовірним. Тому тут
    // перевіряється рівно те, що перевірити можна: нове перевантаження
    // `SecureClear(std::wstring&)`, яким користується межа з 1С, дійсно
    // скидає і вміст, і ЄМНІСТЬ (звичайний `clear()` ємності не звільняє, і
    // саме через це затерті байти лишалися б у буфері контейнера).
    //
    // Те, що межа NativeAPI справді бере ці копії під `ScopedSecret`,
    // доводиться код-рев'ю і зіставленням із двома наявними еталонами —
    // `SessionKeyLoading.ipp` (`SecureErase`) і `src/cli/main.cpp`
    // (`ScopedSecret`). Тестом це не доводиться, і вдавати протилежне не варто.
    std::wstring secret(512, L'\u0410');
    ExpectTrue(secret.capacity() >= 512U, "wide secret should own a heap buffer before clearing");
    tamga::util::SecureClear(secret);
    ExpectTrue(secret.empty(), "SecureClear(std::wstring&) should empty the value");
    ExpectTrue(secret.capacity() < 512U, "SecureClear(std::wstring&) should release the buffer capacity");

    // `ScopedSecret` мусить приймати wide-рядок так само, як narrow і вектор:
    // інакше межа з 1С тримала б власний, другий механізм затирання — рівно те
    // розходження, що дало С-05.
    std::wstring scoped(256, L'\u042F');
    {
        const tamga::util::ScopedSecret guard(scoped);
        ExpectFalse(scoped.empty(), "ScopedSecret must not clear the value before scope exit");
    }
    ExpectTrue(scoped.empty(), "ScopedSecret(std::wstring&) should clear the value at scope exit");
}

void TestKeyParsersPemDerLoader() {
    const auto pem_data = ReadBinaryFixture(FixturePath("pki/keycert.pem"));
    std::string type;
    std::string error;
    std::vector<std::uint8_t> der;
    ExpectTrue(tamga::core::PemDerLoader::Load(pem_data, der, type, error), "PemDerLoader::Load should parse first PEM block");
    ExpectContains(type, "PRIVATE KEY", "PemDerLoader::Load should extract private key block");
    ExpectFalse(der.empty(), "PemDerLoader::Load should return non-empty DER");

    std::vector<tamga::core::PemDerLoader::PemBlock> blocks;
    tamga::core::PemDerLoader::LoadOptions options;
    options.strict_mode = true;
    ExpectTrue(tamga::core::PemDerLoader::LoadAll(pem_data, blocks, error, options), "PemDerLoader::LoadAll should parse strict multi-block PEM");
    ExpectTrue(blocks.size() >= 2U, "PemDerLoader::LoadAll should produce private key and certificate blocks");
}

void TestSupportedMediaAdvertisesVerifyPolicy() {
    tamga::core::Session session;
    std::string json;
    ExpectTrue(session.DescribeSupportedMedia(json), "DescribeSupportedMedia should succeed");
    ExpectContains(json, "\"verificationPolicy\":{", "Supported media should include verification policy section");
    ExpectContains(json, "\"embeddedChainValidation\":true", "Supported media should advertise embedded chain validation");
    #if TAMGA_CRYPTONITE_ENABLED
    ExpectContains(json, "\"trustValidation\":true", "Cryptonite build should advertise trust validation capability");
#else
    ExpectContains(json, "\"trustValidation\":false", "Diagnostic build should not advertise trust validation");
#endif
}
