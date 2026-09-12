/**
 * kalyna-tsp-diag — CLI утиліта для діагностики TSP-підписання з реальним ключем.
 *
 * Використання:
 *   kalyna-tsp-diag --key <key.jks|key.p12|key.pem>
 *                   --password <пароль>
 *                   [--key-password <пароль_ключа_якщо_відрізняється>]
 *                   [--alias <alias_у_JKS>]
 *                   [--work-dir <робочий_каталог>]
 *                   [--file <файл_для_підпису>]
 *                   [--tsp-url <url>]
 *                   [--offline]
 *                   [--out <output.p7s>]
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>  // SetConsoleOutputCP, GetTempPathA
#endif

#include "core/Session.h"
#include "core/Errors.h"
#include "core/CryptoniteAdapter.h"

using namespace tamga::core;

static void PrintUsage(const char* argv0) {
    std::fprintf(stderr,
        "Використання:\n"
        "  %s --key <шлях> --password <пароль> [параметри]\n"
        "\n"
        "Параметри:\n"
        "  --key          Шлях до файлу ключа (JKS, PKCS12, PEM, DER)\n"
        "  --password-file Файл із паролем сховища (рекомендовано)\n"
        "  --key-password-file Файл із паролем ключа\n"
        "  --password     Пароль сховища (DEPRECATED: видимий у списку процесів)\n"
        "  --key-password Пароль ключа (якщо відрізняється від store)\n"
        "  --alias        Alias запису у JKS/PKCS12\n"
        "  --work-dir     Робочий каталог компоненти (за замовч: системний temp)\n"
        "  --file         Файл для підписання (за замовч: тестовий рядок)\n"
        "  --tsp-url      TSP сервер (за замовч: автовизначення по сертифікату)\n"
        "  --tsp-timeout-ms HTTP timeout для TSP (за замовч: 10000)\n"
        "  --policy-oid   TSP policy OID (за замовч: policy cryptonite/TSA)\n"
        "  --trace-dir    Каталог для request.der/response.der/CMS-артефактів\n"
        "  --offline      Підписати без TSP (CAdES-BES)\n"
        "  --out          Зберегти підпис у файл (за замовч: signature.p7s)\n",
        argv0);
}

static std::vector<std::uint8_t> ReadFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return {std::istreambuf_iterator<char>(f), {}};
}

static bool WriteFile(const std::string& path, const std::vector<std::uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return f.good();
}

static std::string AbsolutePath(const std::string& path) {
    std::error_code ec;
    auto abs = std::filesystem::absolute(std::filesystem::u8path(path), ec);
    if (ec) return path;
    return abs.u8string();
}

static void SetTraceDirectory(const std::string& trace_dir) {
#ifdef _WIN32
    _putenv_s("TAMGA_TSP_TRACE_DIR", trace_dir.c_str());
#else
    setenv("TAMGA_TSP_TRACE_DIR", trace_dir.c_str(), 1);
#endif
}

static void PrintArtifact(const std::string& trace_dir, const char* name) {
    std::error_code ec;
    const auto path = std::filesystem::u8path(trace_dir) / name;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        std::cout << "    - " << name << ": not written\n";
    } else {
        std::cout << "    - " << name << ": " << size << " bytes\n";
    }
}

static std::string ErrorStr(const Session& s) {
    auto e = s.GetLastError();
    if (e.code == ErrorCode::None) return "";
    return std::string(ToString(e.code)) + ": " + e.message;
}

// В-07: пароль ключа КЕП не має проходити через argv — там він видимий у
// списку процесів, історії оболонки та логах CI. Той самий канал, що вже є
// в tools/interop-diag і тепер у tamga-cli.
static bool ReadPasswordFile(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                            out.back() == ' ' || out.back() == '\t')) {
        out.pop_back();
    }
    return !out.empty();
}

int main(int argc, char** argv) {
    std::string key_path, password, key_password, alias, file_path, tsp_url, out_path, work_dir;
    std::string password_file, key_password_file;
    std::string trace_dir, policy_oid, effective_tsp_url;
    int tsp_timeout_ms = 10000;
    bool offline = false;

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    for (int i = 1; i < argc; ++i) {
        if      (std::strcmp(argv[i], "--key")          == 0 && i+1<argc) key_path     = argv[++i];
        else if (std::strcmp(argv[i], "--password")     == 0 && i+1<argc) password     = argv[++i];
        else if (std::strcmp(argv[i], "--key-password") == 0 && i+1<argc) key_password = argv[++i];
        else if (std::strcmp(argv[i], "--password-file") == 0 && i+1<argc) password_file = argv[++i];
        else if (std::strcmp(argv[i], "--key-password-file") == 0 && i+1<argc) key_password_file = argv[++i];
        else if (std::strcmp(argv[i], "--alias")        == 0 && i+1<argc) alias        = argv[++i];
        else if (std::strcmp(argv[i], "--work-dir")     == 0 && i+1<argc) work_dir     = argv[++i];
        else if (std::strcmp(argv[i], "--file")         == 0 && i+1<argc) file_path    = argv[++i];
        else if (std::strcmp(argv[i], "--tsp-url")      == 0 && i+1<argc) tsp_url      = argv[++i];
        else if (std::strcmp(argv[i], "--tsp-timeout-ms")==0 && i+1<argc) tsp_timeout_ms = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--policy-oid")   == 0 && i+1<argc) policy_oid   = argv[++i];
        else if (std::strcmp(argv[i], "--trace-dir")    == 0 && i+1<argc) trace_dir    = argv[++i];
        else if (std::strcmp(argv[i], "--offline")      == 0)             offline       = true;
        else if (std::strcmp(argv[i], "--out")          == 0 && i+1<argc) out_path     = argv[++i];
        else if (std::strcmp(argv[i], "--help")         == 0 ||
                 std::strcmp(argv[i], "-h")             == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    // В-07: файл має пріоритет; одночасне задання обох — майже напевно помилка
    // виклику, тож відмовляємо явно замість мовчазного вибору.
    if (!password_file.empty()) {
        if (!password.empty()) {
            std::fprintf(stderr, "[ERROR] specify either --password or --password-file, not both\n");
            return 1;
        }
        if (!ReadPasswordFile(password_file, password)) {
            std::fprintf(stderr, "[ERROR] cannot read --password-file: %s\n", password_file.c_str());
            return 1;
        }
    }
    if (!key_password_file.empty()) {
        if (!key_password.empty()) {
            std::fprintf(stderr, "[ERROR] specify either --key-password or --key-password-file, not both\n");
            return 1;
        }
        if (!ReadPasswordFile(key_password_file, key_password)) {
            std::fprintf(stderr, "[ERROR] cannot read --key-password-file: %s\n", key_password_file.c_str());
            return 1;
        }
    }

    if (key_path.empty() || password.empty()) {
        std::fprintf(stderr, "[ERROR] --key and --password are required.\n\n");
        PrintUsage(argv[0]);
        return 1;
    }
    if (out_path.empty()) out_path = "signature.p7s";
    if (key_password.empty()) key_password = password;
    if (tsp_timeout_ms <= 0) tsp_timeout_ms = 10000;
    if (trace_dir.empty()) {
        auto parent = std::filesystem::u8path(out_path).parent_path();
        trace_dir = parent.empty() ? "." : parent.u8string();
    }
    std::error_code trace_ec;
    std::filesystem::create_directories(std::filesystem::u8path(trace_dir), trace_ec);
    trace_dir = AbsolutePath(trace_dir);
    SetTraceDirectory(trace_dir);

    // Визначаємо робочий каталог
    if (work_dir.empty()) {
#ifdef _WIN32
        char tmp[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp);
        work_dir = std::string(tmp) + "kalyna-diag";
        CreateDirectoryA(work_dir.c_str(), nullptr);
#else
        work_dir = "/tmp/kalyna-diag";
#endif
    }

    std::cout << "\n=== Tamga TSP Diagnostic Tool ===\n\n";

    // ── 1. SetSettings() ДО Initialize() ──────────────────────────────────
    std::cout << "[1] SetSettings + Initialize...\n";
    Session session;
    {
        Settings settings;
        settings.offline_mode = offline;
        settings.work_dir = work_dir;
        session.SetSettings(settings);
    }
    if (!session.Initialize()) {
        std::cerr << "    ERROR: " << ErrorStr(session) << "\n";
        return 1;
    }
    std::cout << "    OK (work_dir: " << work_dir << ")\n";
    std::cout << "    TSP trace dir: " << trace_dir << "\n";

    // ── 2. TSP налаштування ───────────────────────────────────────────────
    if (!tsp_url.empty()) {
        TspSettings tsp;
        tsp.url = tsp_url;
        tsp.timeout_ms = tsp_timeout_ms;
        tsp.policy_oid = policy_oid;
        session.SetTspSettings(tsp);
        effective_tsp_url = tsp_url;
        std::cout << "[2] TSP URL (manually): " << tsp_url << "\n";
    } else {
        std::cout << "[2] TSP URL: will be auto-resolved from certificate\n";
    }
    if (offline) {
        std::cout << "    Mode: OFFLINE - no TSP (CAdES-BES)\n";
    }

    // ── 3. Завантаження ключа ─────────────────────────────────────────────
    std::cout << "[3] Loading key: " << key_path << "\n";
    if (!alias.empty()) std::cout << "    Alias: " << alias << "\n";

    auto key_data = ReadFile(key_path);
    if (key_data.empty()) {
        std::cerr << "    ERROR: cannot read key file\n";
        return 1;
    }

    if (!session.ReadPrivateKeyBinary(key_data, password, key_password, alias)) {
        std::cerr << "    ERROR: " << ErrorStr(session) << "\n";
        return 1;
    }
    std::cout << "    OK - key loaded\n";

    // ── 4. TSP URL автовизначення ────────────────────────────────────────
    if (tsp_url.empty() && !offline) {
        std::string resolved = session.ResolveDefaultTspUrl();
        if (!resolved.empty()) {
            TspSettings tsp;
            tsp.url = resolved;
            tsp.timeout_ms = tsp_timeout_ms;
            tsp.policy_oid = policy_oid;
            session.SetTspSettings(tsp);
            effective_tsp_url = resolved;
            std::cout << "[4] TSP URL (auto): " << resolved << "\n";
        } else {
            std::cout << "[4] TSP URL: NOT RESOLVED (unknown issuer)\n";
            std::cout << "    WARNING: signature will be CAdES-BES (no timestamp)!\n";
            std::cout << "    Use --tsp-url to specify server manually.\n";
        }
    }
    if (!offline) {
        std::cout << "[4a] Session TSP parameters:\n";
        std::cout << "    offline_mode=false\n";
        std::cout << "    tsp_settings.url=" << effective_tsp_url << "\n";
        std::cout << "    tsp_settings.timeout_ms=" << tsp_timeout_ms << "\n";
        std::cout << "    tsp_settings.policy_oid="
                  << (policy_oid.empty() ? "(default: 1.2.804.2.1.1.1.2.3.1)" : policy_oid) << "\n";
        std::cout << "    hash_oid=1.2.804.2.1.1.1.1.2.2.1 (Kupyna-256)\n";
    }

    // ── 5. Дані для підписання ───────────────────────────────────────────
    std::vector<std::uint8_t> data_to_sign;
    if (!file_path.empty()) {
        data_to_sign = ReadFile(file_path);
        if (data_to_sign.empty()) {
            std::cerr << "[5] ERROR: cannot read file: " << file_path << "\n";
            return 1;
        }
        std::cout << "[5] File: " << file_path << " (" << data_to_sign.size() << " bytes)\n";
    } else {
        std::string test_str = "Hello Tamga TSP Diagnostic";
        data_to_sign.assign(test_str.begin(), test_str.end());
        std::cout << "[5] Test data: \"" << test_str << "\"\n";
    }

    // ── 6. Підписання ────────────────────────────────────────────────────
    std::cout << "[6] Signing (detached CMS)...\n";
    std::vector<std::uint8_t> signature;
    bool sign_ok = session.SignData(data_to_sign, signature);

    auto sign_err = session.GetLastError();
    if (sign_err.code != ErrorCode::None) {
        std::cout << "\n    [!] WARNING after signing:\n";
        std::cout << "        Code: " << ToString(sign_err.code) << "\n";
        std::cout << "        Info: " << sign_err.message << "\n";
        if (sign_err.message.find("TSP [") != std::string::npos) {
            std::cout << "\n    DIAGNOSIS: TSP server did not respond or rejected request.\n";
            std::cout << "    Signature saved as CAdES-BES (no timestamp).\n";
            std::cout << "    Validator will show: 'Timestamp not confirmed'.\n";
            std::cout << "\n    Recommendations:\n";
            std::cout << "    1) Check TSP server availability (firewall/internet)\n";
            auto pos1 = sign_err.message.find("TSP [");
            auto pos2 = sign_err.message.find("]", pos1);
            if (pos1 != std::string::npos && pos2 != std::string::npos) {
                std::string url = sign_err.message.substr(pos1 + 5, pos2 - pos1 - 5);
                std::cout << "       curl -v -H 'Content-Type: application/timestamp-query' " << url << "\n";
            }
            std::cout << "    2) Try: --tsp-url https://acsk.privatbank.ua/services/tsp/\n";
            std::cout << "    3) Try: --tsp-url http://ca.informjust.ua/services/tsp/\n";
        }
    }

    if (!sign_ok) {
        std::cerr << "\n    SIGN FAILED: " << ErrorStr(session) << "\n";
        return 1;
    }

    std::cout << "\n    Signature size: " << signature.size() << " bytes\n";

    bool tsp_embedded = false;
    std::string tsp_check_err;
    const bool tsp_checked = CryptoniteAdapter::HasSignatureTimestampToken(signature, tsp_embedded, tsp_check_err);
    const bool tsp_failed_silently = (sign_err.code == ErrorCode::None) && !offline && tsp_checked && !tsp_embedded;

    if (tsp_embedded) {
        std::cout << "    Status: CAdES-T (timestamp embedded) OK\n";
    } else if (offline) {
        std::cout << "    Status: CAdES-BES (offline mode, no timestamp by design)\n";
    } else if (tsp_failed_silently) {
        std::cout << "    Status: CAdES-BES (TSP token NOT embedded!)\n";
        std::cout << "\n    DIAGNOSIS: TSP server reached but token was rejected/invalid.\n";
        std::cout << "    Possible causes:\n";
        std::cout << "    1) TSP server rejected policy OID (1.2.804.2.1.1.1.2.3.1)\n";
        std::cout << "    2) TSP server requires client authentication\n";
        std::cout << "    3) Hash algorithm OID mismatch (server expects different hash)\n";
        std::cout << "    4) TSP response parsed OK but AppendTspToken failed\n";
        std::cout << "\n    Check TSP server response manually:\n";
        std::cout << "       Try: --tsp-url http://ca.informjust.ua/services/tsp/\n";
    } else if (!offline && !tsp_checked) {
        std::cout << "    Status: unable to inspect CMS timestamp attribute\n";
        std::cout << "    Inspect error: " << tsp_check_err << "\n";
    } else {
        std::cout << "    Status: CAdES-BES (TSP failed, see warnings above)\n";
    }

    // ── 7. Збереження ──────────────────────────────────────────────────────
    if (!WriteFile(out_path, signature)) {
        std::cerr << "[7] ERROR writing: " << out_path << "\n";
        return 1;
    }
    std::cout << "[7] Signature saved: " << out_path << "\n";
    std::cout << "    Diagnostic artifacts:\n";
    PrintArtifact(trace_dir, "request.der");
    PrintArtifact(trace_dir, "response.der");
    PrintArtifact(trace_dir, "request.http.txt");
    PrintArtifact(trace_dir, "http-headers.txt");
    PrintArtifact(trace_dir, "signature_before_tsp.bin");
    PrintArtifact(trace_dir, "signature_with_tsp.bin");
    if (!effective_tsp_url.empty()) {
        std::cout << "    Curl replay:\n";
        std::cout << "       cd /d \"" << trace_dir << "\" && curl.exe -v --data-binary @request.der "
                  << "-H \"Content-Type: application/timestamp-query\" \""
                  << effective_tsp_url << "\" -o response.der\n";
    }

    // ── 8. Верифікація ─────────────────────────────────────────────────────
    std::cout << "[8] Verifying signature...\n";
    bool is_valid = false;
    bool verify_ok = session.VerifyData(data_to_sign, signature, is_valid);
    auto verify_err = session.GetLastError();
    if (verify_ok && is_valid) {
        std::cout << "    Signature cryptographically valid OK\n";
    } else {
        std::cout << "    Signature NOT valid or verify error\n";
        if (verify_err.code != ErrorCode::None) {
            std::cout << "    " << ToString(verify_err.code) << ": " << verify_err.message << "\n";
        }
    }

    std::string verify_report;
    if (session.GetLastVerifyReport(verify_report)) {
        std::cout << "\n    Verify report:\n    " << verify_report << "\n";
    }

    std::cout << "\n=== Diagnostics complete ===\n";
    return (sign_ok && !tsp_url.empty() && !offline && sign_err.code != ErrorCode::None) ? 2 : 0;
}
