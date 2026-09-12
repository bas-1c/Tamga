// tamga-interop-diag — перевірка Tamga проти РЕАЛЬНИХ зовнішніх артефактів.
//
// Закриває дві невизначеності, які неможливо перевірити внутрішніми тестами,
// бо ті перевіряють Tamga проти Tamga:
//
//   1) B-3: чи здатен власний XMLDSIG-рушій Tamga перевірити підпис справжнього
//      довірчого списку ЦЗО (`TL-UA-EC.xml`). Від цього залежить, чи можна
//      лишати новий дефолт `xml_signature_policy = PreferAvailable`, чи він
//      зламає синхронізацію в продакшені.
//
//   2) S-006: чи приймає Tamga підписи, створені сторонніми українськими
//      засобами (Дія, ІІТ, банківські КЕП) — тобто чи правильне припущення
//      ADR-013 про кодування ДСТУ-підпису в `ds:SignatureValue`.
//
// Команди:
//   tamga-interop-diag tl-sig <TL.xml> [pinned-signer.cer]
//   tamga-interop-diag asice  <container.asice> [--work-dir dir]
//   tamga-interop-diag xml    <signed.xml>      [--work-dir dir]
//   tamga-interop-diag cms    <data-file> <signature.p7s> [--work-dir dir]
//
// Код повернення: 0 — перевірка пройшла; 1 — не пройшла; 2 — помилка запуску.
// Інструмент лише читає файли й нічого не надсилає в мережу, якщо не задано
// --work-dir з увімкненим online (за замовчуванням offline).

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "core/Session.h"
#include "core/CryptoniteAdapter.h"
#include "core/KeyParsers.h"
#include "core/net/CertificateResolver.h"
#include "core/policy/TlXmlSigCheck.h"
#include "util/Utf.h"

#if defined(_WIN32)
#include <windows.h>
#include <shellapi.h>
#endif

namespace {

constexpr int kOk = 0;
constexpr int kVerificationFailed = 1;
constexpr int kUsageError = 2;

// Аргументи вже в UTF-8 (див. main), тому шлях будуємо через u8path:
// std::filesystem::path(std::string) на Windows трактує вузький рядок як ANSI,
// і кириличні шляхи не відкриваються.
std::filesystem::path Utf8Path(const std::string& value) {
    return std::filesystem::u8path(value);
}

bool ReadFileBytes(const std::filesystem::path& path, std::vector<std::uint8_t>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>{});
    return true;
}

std::string ArgValue(int argc, char** argv, const std::string& flag) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (flag == argv[i]) {
            return argv[i + 1];
        }
    }
    return {};
}

void PrintUsage() {
    std::cout
        << "tamga-interop-diag — verify Tamga against real third-party artefacts\n\n"
        << "  tl-sig <TL.xml> [pinned-signer.cer]   verify the ds:Signature of a CZO trust list\n"
        << "  asice  <container.asice> [--work-dir d]  verify a third-party ASiC-E / XAdES container\n"
        << "  xml    <signed.xml>      [--work-dir d]  verify a third-party XMLDSIG / XAdES document\n"
        << "  cms    <data> <sig.p7s>  [--work-dir d]  verify a third-party detached CMS/CAdES signature\n\n"
        << "  resolve-cert <key.dat> [--password-file f] [--work-dir d]\n"
        << "                                        resolve the certificate for a key container\n"
        << "Exit: 0 = verified, 1 = not verified, 2 = usage/IO error.\n";
}

// ── 1) Підпис довірчого списку ЦЗО ────────────────────────────────────────────
int RunTlSig(int argc, char** argv) {
    if (argc < 3) {
        PrintUsage();
        return kUsageError;
    }
    const std::filesystem::path xml_path = Utf8Path(argv[2]);
    std::vector<std::uint8_t> xml_bytes;
    if (!ReadFileBytes(xml_path, xml_bytes) || xml_bytes.empty()) {
        std::cerr << "Cannot read trust list XML: " << xml_path.string() << '\n';
        return kUsageError;
    }

    std::vector<std::uint8_t> pinned;
    if (argc >= 4 && std::string(argv[3]).rfind("--", 0) != 0) {
        const std::filesystem::path pinned_path = Utf8Path(argv[3]);
        if (!ReadFileBytes(pinned_path, pinned) || pinned.empty()) {
            std::cerr << "Cannot read pinned certificate: " << pinned_path.string() << '\n';
            return kUsageError;
        }
    }

    std::cout << "trust list : " << xml_path.string() << " (" << xml_bytes.size() << " bytes)\n"
              << "pinned cert: " << (pinned.empty() ? "<none — self-consistency only>"
                                                    : std::to_string(pinned.size()) + " bytes")
              << '\n';

    const std::string xml(xml_bytes.begin(), xml_bytes.end());
    const auto result = tamga::core::policy::VerifyTlXmlSignature(xml, pinned);

    if (result.not_supported) {
        std::cout << "RESULT     : NOT SUPPORTED — this build has no XMLDSIG engine\n"
                  << "             rebuild with -DTAMGA_ENABLE_XML_SIGNATURES=ON\n";
        return kVerificationFailed;
    }
    if (!result.succeeded) {
        std::cout << "RESULT     : NOT VERIFIED\n"
                  << "reason     : " << result.error << '\n'
                  << "\nThis is the answer to the open B-3 question: Tamga's own XMLDSIG engine\n"
                     "cannot validate this trust list, so xml_signature_policy=PreferAvailable\n"
                     "would break synchronisation. Keep it Disabled until this passes.\n";
        return kVerificationFailed;
    }
    std::cout << "RESULT     : VERIFIED"
              << (pinned.empty() ? " (self-consistent only — origin NOT proven)" : " (pinned origin proven)")
              << "\n\nB-3 answered: the default xml_signature_policy=PreferAvailable is safe for\n"
                 "this trust list.";
    if (pinned.empty()) {
        std::cout << " Supply the CZO signer certificate to also prove origin.";
    }
    std::cout << '\n';
    return kOk;
}

// ── 2) Сторонні підписи: спільний друк звіту ─────────────────────────────────
int ReportOutcome(tamga::core::Session& session, const bool executed, const bool valid,
                  const char* what) {
    std::string report;
    (void)session.GetLastVerifyReport(report);

    if (!executed) {
        const auto err = session.GetLastError();
        std::cout << "RESULT : EXECUTION FAILED\nreason : " << err.message << '\n';
        if (!report.empty()) {
            std::cout << "\nreport :\n" << report << '\n';
        }
        return kVerificationFailed;
    }
    std::cout << "RESULT : " << (valid ? "SIGNATURE ACCEPTED" : "SIGNATURE REJECTED") << '\n';
    if (!report.empty()) {
        std::cout << "\nreport :\n" << report << '\n';
    }
    if (!valid) {
        std::cout << "\nA rejected third-party " << what << " is exactly the S-006 signal:\n"
                     "inspect diagnostics.message above for the failing reference/digest —\n"
                     "it shows whether the DSTU SignatureValue encoding assumption holds.\n";
    }
    return valid ? kOk : kVerificationFailed;
}

bool PrepareSession(tamga::core::Session& session, int argc, char** argv) {
    tamga::core::Settings settings;
    settings.offline_mode = true;  // діагностика не має залежати від мережі
    const auto work_dir = ArgValue(argc, argv, "--work-dir");
    if (!work_dir.empty()) {
        settings.work_dir = work_dir;
    }
    settings.trust_mode = "compatibility";  // не відкидати legacy-якорі на цьому кроці
    if (!session.SetSettings(settings)) {
        std::cerr << "SetSettings failed: " << session.GetLastError().message << '\n';
        return false;
    }
    if (!session.Initialize()) {
        std::cerr << "Initialize failed: " << session.GetLastError().message << '\n';
        return false;
    }
    return true;
}

int RunAsice(int argc, char** argv) {
    if (argc < 3) {
        PrintUsage();
        return kUsageError;
    }
    const std::string container = argv[2];
    std::cout << "container: " << container << '\n';
    tamga::core::Session session;
    if (!PrepareSession(session, argc, argv)) {
        return kUsageError;
    }
    bool valid = false;
    const bool executed = session.VerifyFileAsicEXades(container, valid);
    return ReportOutcome(session, executed, valid, "ASiC-E/XAdES container");
}

int RunXml(int argc, char** argv) {
    if (argc < 3) {
        PrintUsage();
        return kUsageError;
    }
    const std::filesystem::path xml_path = Utf8Path(argv[2]);
    std::vector<std::uint8_t> xml_bytes;
    if (!ReadFileBytes(xml_path, xml_bytes) || xml_bytes.empty()) {
        std::cerr << "Cannot read XML: " << xml_path.string() << '\n';
        return kUsageError;
    }
    std::cout << "document : " << xml_path.string() << " (" << xml_bytes.size() << " bytes)\n";
    tamga::core::Session session;
    if (!PrepareSession(session, argc, argv)) {
        return kUsageError;
    }
    const std::string xml(xml_bytes.begin(), xml_bytes.end());
    bool valid = false;
    const bool executed = session.VerifyXml(xml, valid);
    return ReportOutcome(session, executed, valid, "XMLDSIG/XAdES document");
}

int RunCms(int argc, char** argv) {
    if (argc < 4) {
        PrintUsage();
        return kUsageError;
    }
    std::vector<std::uint8_t> data;
    std::vector<std::uint8_t> signature;
    if (!ReadFileBytes(Utf8Path(argv[2]), data)) {
        std::cerr << "Cannot read data file: " << argv[2] << '\n';
        return kUsageError;
    }
    if (!ReadFileBytes(Utf8Path(argv[3]), signature) || signature.empty()) {
        std::cerr << "Cannot read signature file: " << argv[3] << '\n';
        return kUsageError;
    }
    std::cout << "data     : " << argv[2] << " (" << data.size() << " bytes)\n"
              << "signature: " << argv[3] << " (" << signature.size() << " bytes)\n";
    tamga::core::Session session;
    if (!PrepareSession(session, argc, argv)) {
        return kUsageError;
    }
    bool valid = false;
    const bool executed = session.VerifyData(data, signature, valid);
    return ReportOutcome(session, executed, valid, "CMS/CAdES signature");
}

// Attached CMS (eContent усередині підпису). Вчасно віддає саме такий контейнер:
// зовнішній `.pdf` — це ВІЗУАЛІЗАЦІЯ зі штампом, а підписані байти лежать у самому
// `.p7s`. Подавати зовнішній PDF як detached-дані — помилка вимірювання, тому для
// таких файлів потрібен цей режим, а не `cms`.
int RunCmsAttached(int argc, char** argv) {
    if (argc < 3) {
        PrintUsage();
        return kUsageError;
    }
    std::vector<std::uint8_t> signature;
    if (!ReadFileBytes(Utf8Path(argv[2]), signature) || signature.empty()) {
        std::cerr << "Cannot read signature file: " << argv[2] << '\n';
        return kUsageError;
    }
    std::cout << "attached CMS: " << argv[2] << " (" << signature.size() << " bytes)\n";
    tamga::core::Session session;
    if (!PrepareSession(session, argc, argv)) {
        return kUsageError;
    }
    bool valid = false;
    std::vector<std::uint8_t> content;
    const bool executed = session.VerifyDataInternal(signature, valid, content);
    std::cout << "extracted   : " << content.size() << " bytes of embedded content\n";
    const auto out_path = ArgValue(argc, argv, "--extract-to");
    if (!out_path.empty() && !content.empty()) {
        std::ofstream out(std::filesystem::u8path(out_path), std::ios::binary | std::ios::trunc);
        if (out.is_open()) {
            out.write(reinterpret_cast<const char*>(content.data()),
                      static_cast<std::streamsize>(content.size()));
            std::cout << "written     : " << out_path << '\n';
        }
    }
    return ReportOutcome(session, executed, valid, "attached CMS/CAdES signature");
}


// PAdES: підпис вбудований у сам PDF (/ByteRange + /Contents). Потребує збірки з
// TAMGA_ENABLE_PDF_SIGNATURES=ON (qpdf).
int RunPades(int argc, char** argv) {
    if (argc < 3) {
        PrintUsage();
        return kUsageError;
    }
    const std::filesystem::path pdf_path = Utf8Path(argv[2]);
    std::vector<std::uint8_t> pdf;
    if (!ReadFileBytes(pdf_path, pdf) || pdf.empty()) {
        std::cerr << "Cannot read PDF: " << argv[2] << '\n';
        return kUsageError;
    }
    std::cout << "document : " << argv[2] << " (" << pdf.size() << " bytes)\n";

    tamga::core::Session session;
    if (!PrepareSession(session, argc, argv)) {
        return kUsageError;
    }
    bool valid = false;
    const bool executed = session.VerifyPdf(pdf, valid);
    return ReportOutcome(session, executed, valid, "PAdES document");
}

// ── Авто-резолвер сертифіката (ТЗ Рівні 1-3) ─────────────────────────────────
// Перевіряє на СПРАВЖНЬОМУ контейнері ключа те, що інакше доводиться приймати
// на віру: чи знаходить резолвер відкритий сертифікат і чи справді той
// відповідає закритому ключу. Пароль читається з ФАЙЛУ, а не з командного
// рядка, щоб не осідати в історії оболонки й у списку процесів.
int RunResolveCert(int argc, char** argv) {
    if (argc < 3) {
        PrintUsage();
        return kUsageError;
    }
    std::vector<std::uint8_t> key_material;
    if (!ReadFileBytes(Utf8Path(argv[2]), key_material) || key_material.empty()) {
        std::cerr << "Cannot read key container: " << argv[2] << '\n';
        return kUsageError;
    }

    std::string password;
    const auto pass_file = ArgValue(argc, argv, "--password-file");
    if (!pass_file.empty()) {
        std::vector<std::uint8_t> raw;
        if (!ReadFileBytes(Utf8Path(pass_file), raw)) {
            std::cerr << "Cannot read password file: " << pass_file << '\n';
            return kUsageError;
        }
        password.assign(raw.begin(), raw.end());
        while (!password.empty() && (password.back() == '\n' || password.back() == '\r' ||
                                     password.back() == ' ' || password.back() == '\t')) {
            password.pop_back();
        }
    }

    // JKS нормалізуємо ТАК САМО, як це робить Session, інакше діагностика міряла
    // б власну похибку: резолвер приймає PKCS#12/PKCS#8, а не сирий контейнер
    // Java. Заразом JKS зазвичай несе власний ланцюг, тож резолверу тут просто
    // немає що шукати — і це теж треба показати, а не приховати.
    std::vector<std::uint8_t> chain_certificate;
    if (key_material.size() > 4 && key_material[0] == 0xFE && key_material[1] == 0xED &&
        key_material[2] == 0xFE && key_material[3] == 0xED) {
        tamga::core::JksKeyStoreParser::PrivateKeyEntry entry;
        std::string jks_error;
        if (!tamga::core::JksKeyStoreParser::LoadPrivateKeyEntry(
                key_material, password, password, ArgValue(argc, argv, "--alias"), entry, jks_error)) {
            std::cerr << "JKS parse failed: " << jks_error << '\n';
            return 1;
        }
        std::cout << "container     : JKS, alias=" << entry.alias
                  << ", chain=" << entry.certificate_chain.size() << " certificate(s)\n";
        key_material = entry.private_key_pkcs8;
        // Витягнутий із JKS PKCS#8 уже РОЗШИФРОВАНИЙ, тож пароль сховища до
        // нього не застосовується. Якщо його не скинути, звірка з ключем
        // відхилить навіть правильний сертифікат.
        password.clear();
        std::vector<std::uint8_t> matched;
        if (tamga::core::CryptoniteAdapter::FindMatchingCertificate(
                key_material, entry.certificate_chain, matched)) {
            chain_certificate = std::move(matched);
            std::cout << "in-container  : certificate matching the private key FOUND ("
                      << chain_certificate.size() << " bytes)\n";
        } else if (!entry.certificate.empty()) {
            std::cout << "in-container  : chain present, but NONE matches the private key\n";
        }
    }

    tamga::core::net::CertificateResolveRequest request;
    request.key_material = key_material;
    request.password = password;
    request.key_file_path = argv[2];
    request.work_dir = ArgValue(argc, argv, "--work-dir");
    request.offline_mode = ArgValue(argc, argv, "--online").empty();
    request.explicit_certificate_path = ArgValue(argc, argv, "--cert");
    request.ldap_url = ArgValue(argc, argv, "--ldap-url");
    request.subject_identifier = ArgValue(argc, argv, "--subject");

    std::cout << "key container : " << argv[2] << " (" << key_material.size() << " bytes)\n"
              << "password      : " << (password.empty() ? "<none>" : "<from file>") << '\n'
              << "mode          : " << (request.offline_mode ? "offline" : "online") << "\n\n";

    // Сам SPKI, а не лише його відбиток: коли дві перевірки належності ключа
    // розходяться, різницю видно тільки в байтах — параметри кривої ДСТУ 4145
    // можуть кодуватись по-різному при однаковій точці відкритого ключа.
    {
        std::vector<std::uint8_t> key_spki;
        std::string spki_err;
        if (tamga::core::CryptoniteAdapter::ExtractSubjectPublicKeyInfo(
                request.key_material, request.password, key_spki, spki_err)) {
            std::cout << "key SPKI DER  : " << key_spki.size() << " bytes\n" << "  ";
            for (std::size_t i = 0; i < key_spki.size() && i < 48; ++i) {
                static const char* kHex = "0123456789abcdef";
                std::cout << kHex[key_spki[i] >> 4] << kHex[key_spki[i] & 0x0F];
            }
            std::cout << (key_spki.size() > 48 ? " ..." : "") << '\n';
        }
    }

    // --verify-pairing: НЕЗАЛЕЖНА відповідь на питання "чи належить цей
    // сертифікат цьому ключу" — підписати ним і перевірити сертифікатом.
    // Потрібно, коли структурні перевірки розходяться: підпис або сходиться,
    // або ні, і це не залежить від того, як закодовано SPKI.
    const auto pairing_cert_path = ArgValue(argc, argv, "--verify-pairing");
    if (!pairing_cert_path.empty()) {
        std::vector<std::uint8_t> cert;
        if (!ReadFileBytes(Utf8Path(pairing_cert_path), cert) || cert.empty()) {
            std::cerr << "Cannot read certificate: " << pairing_cert_path << '\n';
            return kUsageError;
        }
        std::vector<std::uint8_t> hash(32, 0x5A);
        std::vector<std::uint8_t> signature;
        std::string err;
        const bool signed_ok = tamga::core::CryptoniteAdapter::SignHash(
            false, request.key_material, cert, request.password, hash, signature, err);
        std::cout << "pairing test  : SignHash " << (signed_ok ? "ok" : ("FAILED: " + err)) << '\n';
        if (signed_ok) {
            bool valid = false;
            std::string verr;
            const bool executed = tamga::core::CryptoniteAdapter::VerifyHash(cert, hash, signature, valid, verr);
            std::cout << "                VerifyHash executed=" << (executed ? "yes" : "no")
                      << " valid=" << (valid ? "YES" : "no")
                      << (verr.empty() ? "" : (" (" + verr + ")")) << '\n'
                      << "                => certificate " << (valid ? "BELONGS to" : "does NOT belong to")
                      << " this private key\n";
        }
    }

    const auto result = tamga::core::net::CertificateResolver{}.Resolve(request);
    std::cout << "spki sha256   : " << result.spki_sha256 << '\n'
              << "rejected      : " << result.rejected_candidates << " candidate(s)\n";
    if (!result.succeeded) {
        std::cout << "RESULT        : NOT RESOLVED\n"
                  << "reason        : " << result.message << '\n';
        return 1;
    }
    std::cout << "source        : " << result.source << '\n'
              << "detail        : " << result.source_detail << '\n'
              << "certificate   : " << result.certificate_der.size() << " bytes\n"
              << "RESULT        : RESOLVED (matches the private key)\n";
    return 0;
}
}  // namespace

// Windows передає argv у ANSI-кодуванні консолі, тому кириличні шляхи приходять
// НЕ як UTF-8, а Tamga очікує саме UTF-8. Щоб діагностика міряла Tamga, а не
// власну похибку кодування, аргументи беремо з GetCommandLineW і конвертуємо в
// UTF-8 самі.
int RunMain(int argc, char** argv);

#if defined(_WIN32)
int main() {
    int wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (wargv == nullptr) {
        std::cerr << "CommandLineToArgvW failed" << '\n';
        return kUsageError;
    }
    std::vector<std::string> utf8_args;
    utf8_args.reserve(static_cast<std::size_t>(wargc));
    for (int i = 0; i < wargc; ++i) {
        utf8_args.push_back(tamga::util::ToUtf8(std::wstring(wargv[i])));
    }
    LocalFree(wargv);
    std::vector<char*> argv_utf8;
    argv_utf8.reserve(utf8_args.size() + 1);
    for (auto& a : utf8_args) {
        argv_utf8.push_back(a.data());
    }
    argv_utf8.push_back(nullptr);
    return RunMain(wargc, argv_utf8.data());
}
#else
int main(int argc, char** argv) { return RunMain(argc, argv); }
#endif

int RunMain(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return kUsageError;
    }
    const std::string command = argv[1];
    if (command == "tl-sig") {
        return RunTlSig(argc, argv);
    }
    if (command == "asice") {
        return RunAsice(argc, argv);
    }
    if (command == "xml") {
        return RunXml(argc, argv);
    }
    if (command == "cms") {
        return RunCms(argc, argv);
    }
    if (command == "cms-attached") {
        return RunCmsAttached(argc, argv);
    }
    if (command == "resolve-cert") {
        return RunResolveCert(argc, argv);
    }
    if (command == "pades") {
        return RunPades(argc, argv);
    }
    PrintUsage();
    return kUsageError;
}
