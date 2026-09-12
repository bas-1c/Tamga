#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include "CliEvidence.h"
#include "CliExitCodes.h"
#include "tamga/Tamga.h"
#include "util/FileSystem.h"
#include "util/Json.h"
#include "util/SecureZero.h"

namespace {

struct CliOptions {
    std::string command;
    std::string subcommand;
    bool help{false};
    std::map<std::string, std::string> values;
};

std::string Trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

// O-03: власної копії тут більше немає. Стара відрізнялася від
// `util::EscapeJson` рівно тим, що НЕ екранувала керівні байти поза списком
// `\b \f \n \r \t`: байт 0x01 у шляху чи паролі йшов у JSON-дескриптор сирим,
// і той самий дескриптор власний парсер Tamga (`util::ParseJsonString`)
// відхиляв як некоректний JSON. Спільна реалізація емітує для таких байтів
// `\u00XX`.
using tamga::util::EscapeJson;

// В-04: див. TamgaCApi.cpp — CLI мав ту саму прогалину.
bool ReadBinaryFile(const std::string& path, std::vector<std::uint8_t>& out) {
    std::string error;
    return tamga::util::ReadBinaryFileLimited(std::filesystem::u8path(path),
                                              tamga::util::kMaxInputFileSize, out, error);
}

bool ReadTextFile(const std::string& path, std::string& out) {
    std::string error;
    return tamga::util::ReadTextFileLimited(std::filesystem::u8path(path),
                                            tamga::util::kMaxInputFileSize, out, error);
}

// В-07: пароль ключа КЕП не має проходити через argv — там він видимий у
// списку процесів, історії оболонки та логах CI. Патерн уже реалізовано в
// tools/interop-diag (`--password-file`) саме з цієї причини; тут він був
// відсутній рівно там, де важить найбільше.
//
// Хвостові пробільні символи обрізаються: редактори майже завжди дописують
// перенос рядка, і без цього пароль мовчки не збігався б.
bool ReadPasswordFile(const std::string& path, std::string& out, std::string& error) {
    std::vector<std::uint8_t> raw;
    // `raw` тримає пароль у відкритому вигляді, тож стирається В УСІХ шляхах
    // виходу, а не лише в успішному. Раніше стирання не було взагалі: буфер
    // просто виходив з області видимості, лишаючи пароль у купі до першого
    // перевикористання пам'яті. `ScopedSecret` ставиться ОДРАЗУ після
    // оголошення — саме тому, що ранні `return` нижче інакше його обійшли б.
    tamga::util::ScopedSecret raw_guard(raw);
    // Пароль — не документ: власний невеликий ліміт замість загального 64 MiB.
    if (!tamga::util::ReadBinaryFileLimited(std::filesystem::u8path(path), 64 * 1024, raw, error)) {
        return false;
    }
    out.assign(raw.begin(), raw.end());
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                            out.back() == ' ' || out.back() == '\t')) {
        out.pop_back();
    }
    if (out.empty()) {
        error = "password file is empty";
        return false;
    }
    return true;
}

// П-12: вихідні файли CLI пишуться тим самим атомарним writer-ом, що й решта
// вихідних шляхів проєкту. Семантику перезапису описано один раз у
// `util/FileSystem.h`.
bool WriteBinaryFile(const std::string& path, const std::vector<std::uint8_t>& data) {
    return tamga::util::WriteBinaryFileAtomic(std::filesystem::u8path(path), data);
}

bool WriteTextFile(const std::string& path, const std::string& text) {
    return tamga::util::WriteTextFileAtomic(std::filesystem::u8path(path), text);
}

bool LoadConfig(const std::string& path, std::map<std::string, std::string>& values) {
    std::ifstream input(std::filesystem::u8path(path));
    if (!input.is_open()) {
        return false;
    }
    std::string line;
    while (std::getline(input, line)) {
        const auto trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }
        const auto separator = trimmed.find('=');
        if (separator == std::string::npos) {
            return false;
        }
        values[Trim(trimmed.substr(0, separator))] = Trim(trimmed.substr(separator + 1));
    }
    return true;
}

void PrintUsage() {
    std::cout
        << "Tamga CLI\n"
        << "Usage: tamga-cli <command> [--config file] [--offline true|false] [--work-dir dir] [--trust-mode strict|compatibility] [--key value]\n\n"
        << "Commands:\n"
        << "  media\n"
        << "  base64-encode --input file [--output file]\n"
        << "  base64-decode --input file [--output file]\n"
        << "  sign-file     --input file --output file [--key file] [--password-file f] [--format cms|cms-detached|cms-attached|cades-bes|cades-t|xades|xades-bes|xades-t|pades|pades-b|pades-t|pades-lt|pades-lta|asic-s|asic-e|asic-s-cades|asic-e-cades]\n"
        << "  verify-file   --input file [--signature sig] [--format cms|xades|pades|pades-b|pades-t|pades-lt|pades-lta|asic-s|asic-e|asic-s-cades|asic-e-cades|asic-e-xades] [--report technical-json|pretty-json]\n"
        << "  trust sync    --work-dir dir [--url url] [--timeout-ms n] [--ttl-hours n]\n"
        << "  verify        --input file [--signature sig] [--format cms|xades|pades|pades-b|pades-t|pades-lt|pades-lta|asic-s|asic-e|asic-s-cades|asic-e-cades|asic-e-xades] [--report technical-json|pretty-json]\n"
        << "                [--validation-profile strict|compatibility|ukraine-legal|offline|forensic]\n"
        << "                [--validation-level basic|standard|extended|forensic]\n"
        << "                [--evidence-out <path>]\n\n"
        << "ASiC layouts:\n"
        << "  asic-s / asic-e             XAdES (META-INF/signatures*.xml)\n"
        << "  asic-s-cades                CAdES (META-INF/signature.p7s)\n"
        << "  asic-e-cades                CAdES (META-INF/ASiCManifestNNN.xml + signatureNNN.p7s)\n\n"
        << "Key loading options (for sign-file):\n"
        << "  --key <path>           Path to private key container (.jks, .p12, .pfx, .dat, .ZS2, .pem, .der)\n"
        << "  --password-file <path> Read the store password from a file (preferred)\n"
        << "  --key-password-file <path> Read the key entry password from a file\n"
        << "  --password <pass>      Password for key container / store (DEPRECATED: visible in the process list)\n"
        << "  --key-password <pass>  Key entry password (DEPRECATED: visible in the process list)\n"
        << "  --alias <name>         Key alias for JKS / PKCS#12\n"
        << "  --cert <path>          Path to matching X.509 certificate file\n"
        << "  --ca <name>            CA / provider hint for certificate resolver\n\n"
        << "Exit codes:\n"
        << "  0  Success (operation succeeded / signature valid)\n"
        << "  1  Invalid Arguments / Syntax / I/O Error\n"
        << "  2  Key Error (missing key, invalid password, key container parse error)\n"
        << "  3  Network Error (online service unavailable, connection timeout)\n"
        << "  4  Signature Invalid (integrity check failed or signature does not cover the whole document)\n"
        << "  5  Certificate Expired (signing or validation time outside certificate validity)\n"
        << "  6  Certificate Revoked (certificate is revoked by CRL or OCSP)\n"
        << "  7  Policy Invalid / Trust Verification Failure\n";
}

void PrintTrustUsage() {
    std::cout
        << "Tamga CLI trust\n"
        << "Usage:\n"
        << "  tamga-cli trust --help\n"
        << "  tamga-cli trust sync --work-dir dir [--url url] [--timeout-ms n] [--ttl-hours n]\n\n"
        << "Commands:\n"
        << "  trust sync    Synchronize the online CZO trust list cache and print technical JSON report.\n";
}

void PrintVerifyUsage() {
    std::cout
        << "Tamga CLI verify\n"
        << "Usage:\n"
        << "  tamga-cli verify --help\n"
        << "  tamga-cli verify --input file [--signature sig] [--format cms|xades|pades|pades-b|pades-t|pades-lt|pades-lta|asic-s|asic-e|asic-s-cades|asic-e-cades|asic-e-xades] [--work-dir dir] [--report technical-json|pretty-json]\n"
        << "         [--validation-profile strict|compatibility|ukraine-legal|offline|forensic]\n"
        << "         [--validation-level basic|standard|extended|forensic]\n"
        << "         [--evidence-out <path>]\n"
        << "  tamga-cli verify-file --input file [--signature sig] [--format cms|xades|pades|pades-b|pades-t|pades-lt|pades-lta|asic-s|asic-e|asic-s-cades|asic-e-cades|asic-e-xades] [--work-dir dir] [--report technical-json|pretty-json]\n"
        << "         [--validation-profile strict|compatibility|ukraine-legal|offline|forensic]\n"
        << "         [--validation-level basic|standard|extended|forensic]\n"
        << "         [--evidence-out <path>]\n\n"
        << "Formats:\n"
        << "  cms-detached (default) Detached CMS/CAdES (requires --input and --signature)\n"
        << "  cms-attached           Attached CMS/CAdES\n"
        << "  xades / xmldsig        XMLDSIG / XAdES signed XML\n"
        << "  pades / pades-b        PAdES-B signed PDF\n"
        << "  pades-t/lt/lta         PAdES-T/LT/LTA signed PDF\n"
        << "  asic-s                 ASiC-S container with XAdES (.asics / .zip)\n"
        << "  asic-e                 ASiC-E container with XAdES (.asice / .zip)\n"
        << "  asic-s-cades           ASiC-S container with CAdES (.asics / .zip)\n"
        << "  asic-e-cades           ASiC-E container with CAdES (.asice / .zip)\n"
        << "  asic-e-xades           Explicit ASiC-E XAdES verification alias (.asice / .zip)\n\n"
        << "Report modes:\n"
        << "  technical-json    Print GetReport() / GetLastVerifyReport() JSON.\n"
        << "  pretty-json       Print GetUserReport() JSON.\n\n"
        << "Validation profiles:\n"
        << "  strict            Strict trust mode; no historical fallback.\n"
        << "  compatibility     Compatibility trust mode; allows historical trust fallback.\n"
        << "  ukraine-legal     Same as compatibility; intended for Ukrainian legal KEP.\n"
        << "  offline           Offline strict mode; no network requests.\n"
        << "  forensic          Compatibility trust mode for forensic analysis.\n\n"
        << "Validation levels:\n"
        << "  basic             Basic cryptographic integrity check.\n"
        << "  standard          Standard: integrity + trust chain.\n"
        << "  extended          Extended: integrity + trust + revocation.\n"
        << "  forensic          Full forensic evidence package.\n";
}

bool ParseArgs(int argc, char** argv, CliOptions& options) {
    if (argc < 2) {
        return false;
    }
    options.command = argv[1];
    if (options.command == "--help" || options.command == "help") {
        options.help = true;
        return true;
    }
    int first_option = 2;
    if ((options.command == "trust" || options.command == "verify") && first_option < argc) {
        const std::string candidate = argv[first_option];
        if (candidate.rfind("--", 0) != 0) {
            options.subcommand = candidate;
            ++first_option;
        }
    }
    if (options.command == "trust" || options.command == "verify") {
        for (int i = first_option; i < argc; ++i) {
            if (std::string(argv[i]) == "--help") {
                options.help = true;
                return true;
            }
        }
    }
    for (int i = first_option; i < argc; ++i) {
        std::string key = argv[i];
        if (key.rfind("--", 0) != 0) {
            return false;
        }
        key = key.substr(2);
        if (key == "help" && (options.command == "trust" || options.command == "verify")) {
            options.help = true;
            continue;
        }
        if (i + 1 >= argc) {
            return false;
        }
        options.values[key] = argv[++i];
    }
    const auto config = options.values.find("config");
    if (config != options.values.end()) {
        std::map<std::string, std::string> config_values;
        if (!LoadConfig(config->second, config_values)) {
            std::cerr << "Cannot read config file: " << config->second << '\n';
            return false;
        }
        for (const auto& entry : config_values) {
            options.values.emplace(entry.first, entry.second);
        }
    }
    return true;
}

std::string GetValue(const CliOptions& options, const std::string& key) {
    const auto it = options.values.find(key);
    return it == options.values.end() ? std::string{} : it->second;
}

bool TryParseInt(const CliOptions& options, const std::string& key, std::int32_t default_value, std::int32_t& out) {
    const auto value = GetValue(options, key);
    if (value.empty()) {
        out = default_value;
        return true;
    }
    try {
        std::size_t parsed = 0;
        const int number = std::stoi(value, &parsed);
        if (parsed != value.size()) {
            return false;
        }
        out = static_cast<std::int32_t>(number);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool IsAllowedReportMode(const std::string& report_mode) {
    return report_mode.empty() || report_mode == "technical-json" || report_mode == "pretty-json";
}

bool IsAllowedValidationProfile(const std::string& p) {
    return p.empty() || p == "strict" || p == "compatibility" ||
           p == "ukraine-legal" || p == "offline" || p == "forensic";
}

bool IsAllowedValidationLevel(const std::string& l) {
    return l.empty() || l == "basic" || l == "standard" ||
           l == "extended" || l == "forensic";
}

bool IsAllowedFormat(const std::string& fmt, bool is_sign) {
    if (fmt.empty()) {
        return true;
    }
    if (is_sign) {
        return fmt == "cms" || fmt == "cms-detached" || fmt == "cms-attached" ||
               fmt == "cades-bes" || fmt == "cades-t" ||
               fmt == "xades" || fmt == "xades-bes" || fmt == "xades-t" ||
               fmt == "pades" || fmt == "pades-b" || fmt == "pades-t" ||
               fmt == "pades-lt" || fmt == "pades-lta" ||
               fmt == "asic-s" || fmt == "asic-e" ||
               fmt == "asic-s-cades" || fmt == "asic-e-cades";
    }
    // С-23: docs/cli.md давно описував перевірку `cades-bes` і `cades-t`, а
    // код їх відхиляв — `verify --format cades-bes` завершувався
    // "Unknown signature format". Для ПЕРЕВІРКИ це той самий detached CMS:
    // профілі BES/T відрізняються складом підписаних атрибутів, який
    // валідатор і так розбирає. Приймаємо їх як синоніми замість того, щоб
    // прибирати з документації працездатний сценарій.
    return fmt == "cms" || fmt == "cms-detached" || fmt == "cms-attached" ||
           fmt == "cades-bes" || fmt == "cades-t" ||
           fmt == "xades" || fmt == "xmldsig" || fmt == "pades" ||
           fmt == "pades-b" || fmt == "pades-t" ||
           fmt == "pades-lt" || fmt == "pades-lta" ||
           fmt == "asic-s" || fmt == "asic-e" || fmt == "asic-e-xades" ||
           fmt == "asic-s-cades" || fmt == "asic-e-cades";
}

bool ConfigureSession(const CliOptions& options, tamga::core::Session& session) {
    tamga::core::Settings settings;
    settings.offline_mode = GetValue(options, "offline") != "false";
    settings.work_dir = GetValue(options, "work-dir");
    const auto trust_mode = GetValue(options, "trust-mode");
    if (!trust_mode.empty()) {
        settings.trust_mode = trust_mode;
    }
    // --validation-profile overrides --trust-mode when provided
    const auto profile = GetValue(options, "validation-profile");
    if (profile == "strict") {
        settings.trust_mode = "strict";
    } else if (profile == "compatibility" || profile == "ukraine-legal") {
        settings.trust_mode = "compatibility";
    } else if (profile == "offline") {
        settings.offline_mode = true;
        settings.trust_mode = "strict";
    } else if (profile == "forensic") {
        settings.trust_mode = "compatibility";
    }
    const auto level = GetValue(options, "validation-level");
    if (!level.empty()) {
        settings.validation_level = level;
    }
    return session.SetSettings(settings) && session.Initialize();
}

bool LoadKeyIfSpecified(const CliOptions& options, tamga::core::Session& session, std::string& error_message) {
    auto key_path = GetValue(options, "key");
    if (key_path.empty()) {
        key_path = GetValue(options, "key-path");
    }
    if (key_path.empty()) {
        key_path = GetValue(options, "key-file");
    }
    if (key_path.empty()) {
        return true; // No key specified
    }

    // В-07: файл має пріоритет над argv. Якщо задано обидва — це майже напевно
    // помилка виклику, і мовчки обрати один означало б підписати не тим ключем.
    auto password = GetValue(options, "password");
    if (password.empty()) {
        password = GetValue(options, "pass");
    }
    // Охоронець ставиться ТУТ, а не перед передачею в сесію. Між цими двома
    // місцями є три ранні `return false` (конфлікт --password/--password-file,
    // конфлікт для ключа, невдале читання файлу), і кожен із них лишав пароль
    // у купі: значення вже прочитане з argv, а затирання ще не оголошене.
    const tamga::util::ScopedSecret password_guard(password);
    const auto password_file = GetValue(options, "password-file");
    if (!password_file.empty()) {
        if (!password.empty()) {
            std::cerr << "Specify either --password or --password-file, not both\n";
            return false;
        }
        std::string read_error;
        if (!ReadPasswordFile(password_file, password, read_error)) {
            std::cerr << "Cannot read --password-file: " << read_error << "\n";
            return false;
        }
    }

    auto key_password = GetValue(options, "key-password");
    if (key_password.empty()) {
        key_password = GetValue(options, "entry-password");
    }
    const tamga::util::ScopedSecret key_password_guard(key_password);
    const auto key_password_file = GetValue(options, "key-password-file");
    if (!key_password_file.empty()) {
        if (!key_password.empty()) {
            std::cerr << "Specify either --key-password or --key-password-file, not both\n";
            return false;
        }
        std::string read_error;
        if (!ReadPasswordFile(key_password_file, key_password, read_error)) {
            std::cerr << "Cannot read --key-password-file: " << read_error << "\n";
            return false;
        }
    }
    const auto alias = GetValue(options, "alias");
    auto cert_path = GetValue(options, "cert");
    if (cert_path.empty()) {
        cert_path = GetValue(options, "cert-path");
    }
    if (cert_path.empty()) {
        cert_path = GetValue(options, "certificate-path");
    }
    auto ca_hint = GetValue(options, "ca");
    if (ca_hint.empty()) {
        ca_hint = GetValue(options, "provider");
    }
    auto edrpou = GetValue(options, "edrpou");
    if (edrpou.empty()) {
        edrpou = GetValue(options, "drfo");
    }
    if (edrpou.empty()) {
        edrpou = GetValue(options, "subject");
    }

    std::string descriptor = "{";
    descriptor += "\"path\":\"" + EscapeJson(key_path) + "\"";
    if (!password.empty()) {
        descriptor += ",\"password\":\"" + EscapeJson(password) + "\"";
    }
    if (!key_password.empty()) {
        descriptor += ",\"keyPassword\":\"" + EscapeJson(key_password) + "\"";
    }
    if (!alias.empty()) {
        descriptor += ",\"alias\":\"" + EscapeJson(alias) + "\"";
    }
    if (!cert_path.empty()) {
        descriptor += ",\"certificatePath\":\"" + EscapeJson(cert_path) + "\"";
    }
    if (!ca_hint.empty()) {
        descriptor += ",\"ca\":\"" + EscapeJson(ca_hint) + "\"";
    }
    if (!edrpou.empty()) {
        descriptor += ",\"subject\":\"" + EscapeJson(edrpou) + "\"";
    }
    descriptor += "}";

    // В-07 (доопрацювання): пароль потрапляє і в окремий аргумент, і всередину
    // JSON-дескриптора. Додавши файловий канал замість argv, лишити ці копії
    // жити до кінця процесу було б непослідовно — прибрати пароль зі списку
    // процесів і забути його в купі означає зупинитися на півдорозі.
    // Затираємо ОБИДВІ копії одразу після передачі в сесію, незалежно від
    // результату.
    // Пароль і пароль ключа вже під охоронцями з місця їх зчитування (вище) —
    // тут лишається дескриптор, який будується щойно.
    const tamga::util::ScopedSecret descriptor_guard(descriptor);

    if (!session.ReadPrivateKey(descriptor, password)) {
        error_message = session.GetLastError().message;
        return false;
    }
    return true;
}

// O-03: сам вибір коду виходу живе в `cli/CliExitCodes.h` і працює над
// типізованими фактами звіту, а не над пошуком підрядків у його тексті.
// Тут лишилося тільки дістати звіт із сесії.
int MapVerificationExitCode(const tamga::core::Session& session, bool is_valid) {
    if (is_valid) {
        return 0;
    }
    std::string report;
    if (!session.GetLastVerifyReport(report)) {
        report.clear();
    }
    return tamga::cli::VerificationFailureExitCode(session.GetLastError().code,
                                                   tamga::cli::ReadVerifyReportFacts(report));
}

int RunBase64Encode(const CliOptions& options) {
    std::vector<std::uint8_t> input;
    if (!ReadBinaryFile(GetValue(options, "input"), input)) {
        std::cerr << "Cannot read input\n";
        return 1;
    }
    const auto encoded = tamga::util::Base64Encode(input);
    const auto output_path = GetValue(options, "output");
    if (output_path.empty()) {
        std::cout << encoded << '\n';
        return 0;
    }
    const std::vector<std::uint8_t> bytes(encoded.begin(), encoded.end());
    return WriteBinaryFile(output_path, bytes) ? 0 : 1;
}

int RunBase64Decode(const CliOptions& options) {
    std::vector<std::uint8_t> encoded_bytes;
    if (!ReadBinaryFile(GetValue(options, "input"), encoded_bytes)) {
        std::cerr << "Cannot read input\n";
        return 1;
    }
    std::vector<std::uint8_t> decoded;
    const std::string encoded(encoded_bytes.begin(), encoded_bytes.end());
    if (!tamga::util::Base64Decode(encoded, decoded)) {
        std::cerr << "Invalid base64 input\n";
        return 1;
    }
    const auto output_path = GetValue(options, "output");
    if (output_path.empty()) {
        std::cout.write(reinterpret_cast<const char*>(decoded.data()), static_cast<std::streamsize>(decoded.size()));
        return 0;
    }
    return WriteBinaryFile(output_path, decoded) ? 0 : 1;
}

int RunMedia(const CliOptions& options) {
    tamga::core::Session session;
    if (!ConfigureSession(options, session)) {
        std::cerr << session.GetLastError().message << '\n';
        return 1;
    }
    std::string json;
    if (!session.DescribeSupportedMedia(json)) {
        std::cerr << session.GetLastError().message << '\n';
        return 1;
    }
    std::cout << json << '\n';
    return 0;
}

int RunTrustSync(const CliOptions& options) {
    const auto work_dir = GetValue(options, "work-dir");
    if (work_dir.empty()) {
        std::cerr << "Missing required --work-dir\n";
        return 1;
    }
    const auto offline = GetValue(options, "offline");
    if (!offline.empty() && offline != "false") {
        std::cerr << "trust sync is online-only; use --offline false or omit --offline\n";
        return 1;
    }

    tamga::core::TrustListSettings trust_settings;
    const auto url = GetValue(options, "url");
    if (!url.empty()) {
        trust_settings.url = url;
    }
    if (!TryParseInt(options, "timeout-ms", trust_settings.timeout_ms, trust_settings.timeout_ms) ||
        !TryParseInt(options, "ttl-hours", trust_settings.cache_ttl_hours, trust_settings.cache_ttl_hours) ||
        trust_settings.timeout_ms <= 0 ||
        trust_settings.timeout_ms > 300000 ||
        trust_settings.cache_ttl_hours <= 0) {
        std::cerr << "Invalid numeric trust sync option\n";
        return 1;
    }

    tamga::core::Session session;
    tamga::core::Settings settings;
    settings.offline_mode = false;
    settings.work_dir = work_dir;
    session.SetSettings(settings);
    session.Initialize();

    if (!session.SetTrustListSettings(trust_settings)) {
        std::cerr << session.GetLastError().message << '\n';
        return 1;
    }

    const bool synced = session.SyncTrustList();
    std::string report;
    if (session.GetLastVerifyReport(report)) {
        std::cout << report << '\n';
    }
    if (!synced) {
        const auto err = session.GetLastError();
        std::cerr << err.message << '\n';
        if (err.code == tamga::core::ErrorCode::OnlineServiceUnavailable) {
            return 3;
        }
        return 1;
    }
    return 0;
}

int RunSignFile(const CliOptions& options) {
    auto format = GetValue(options, "format");
    if (format.empty()) {
        format = GetValue(options, "signature-format");
    }
    if (!IsAllowedFormat(format, true)) {
        std::cerr << "Unknown signature format: " << format << '\n';
        return 1;
    }

    const auto input_path = GetValue(options, "input");
    const auto output_path = GetValue(options, "output");
    if (input_path.empty() || output_path.empty()) {
        std::cerr << "Missing required --input or --output\n";
        return 1;
    }

    tamga::core::Session session;
    if (!ConfigureSession(options, session)) {
        std::cerr << session.GetLastError().message << '\n';
        return 1;
    }

    std::string key_error;
    if (!LoadKeyIfSpecified(options, session, key_error)) {
        std::cerr << (key_error.empty() ? "Failed to load private key" : key_error) << '\n';
        return 2;
    }

    if (!session.IsPrivateKeyLoaded()) {
        std::cerr << "Private key is not loaded. Specify --key <path> and --password <pass>\n";
        return 2;
    }

    bool success = false;
    if (format.empty() || format == "cms" || format == "cms-detached") {
        success = session.RawSignFile(input_path, output_path);
    } else if (format == "cades-bes") {
        success = session.RawSignFile(input_path, output_path, tamga::core::TimestampMode::Disabled);
    } else if (format == "cades-t") {
        success = session.RawSignFile(input_path, output_path, tamga::core::TimestampMode::Required);
    } else if (format == "cms-attached") {
        std::vector<std::uint8_t> input_bytes;
        if (!ReadBinaryFile(input_path, input_bytes)) {
            std::cerr << "Cannot read input file: " << input_path << '\n';
            return 1;
        }
        std::vector<std::uint8_t> signed_bytes;
        success = session.SignDataInternal(input_bytes, signed_bytes);
        if (success) {
            success = WriteBinaryFile(output_path, signed_bytes);
        }
    } else if (format == "xades" || format == "xades-bes") {
        std::string xml_in;
        if (!ReadTextFile(input_path, xml_in)) {
            std::cerr << "Cannot read input XML file: " << input_path << '\n';
            return 1;
        }
        std::string xml_out;
        success = session.SignXml(xml_in, "xades-bes", xml_out);
        if (success) {
            success = WriteTextFile(output_path, xml_out);
        }
    } else if (format == "xades-t") {
        std::string xml_in;
        if (!ReadTextFile(input_path, xml_in)) {
            std::cerr << "Cannot read input XML file: " << input_path << '\n';
            return 1;
        }
        std::string xml_out;
        success = session.SignXml(xml_in, "xades-t", xml_out);
        if (success) {
            success = WriteTextFile(output_path, xml_out);
        }
    } else if (format == "pades" || format == "pades-b" ||
               format == "pades-t" || format == "pades-lt" ||
               format == "pades-lta") {
        std::vector<std::uint8_t> pdf_in;
        if (!ReadBinaryFile(input_path, pdf_in)) {
            std::cerr << "Cannot read input PDF file: " << input_path << '\n';
            return 1;
        }
        std::vector<std::uint8_t> pdf_out;
        const auto profile = format == "pades" ? std::string{} : format;
        success = session.SignPdf(pdf_in, profile, pdf_out);
        if (success) {
            success = WriteBinaryFile(output_path, pdf_out);
        }
    } else if (format == "asic-s") {
        success = session.SignFileAsicS(input_path, output_path);
    } else if (format == "asic-e") {
        success = session.SignFileAsicE(input_path, output_path);
    } else if (format == "asic-s-cades") {
        success = session.SignFileAsicSCades(input_path, output_path);
    } else if (format == "asic-e-cades") {
        success = session.SignFileAsicECades(input_path, output_path);
    }

    if (!success) {
        const auto err = session.GetLastError();
        std::cerr << (err.message.empty() ? "Sign operation failed" : err.message) << '\n';
        return tamga::cli::SignFailureExitCode(err.code, err.message);
    }
    return 0;
}

int RunVerifyFile(const CliOptions& options) {
    const auto report_mode = GetValue(options, "report");
    if (!IsAllowedReportMode(report_mode)) {
        std::cerr << "Unknown report mode: " << report_mode << '\n';
        return 1;
    }
    const auto validation_profile = GetValue(options, "validation-profile");
    if (!IsAllowedValidationProfile(validation_profile)) {
        std::cerr << "Unknown validation profile: " << validation_profile << '\n';
        return 1;
    }
    const auto validation_level = GetValue(options, "validation-level");
    if (!IsAllowedValidationLevel(validation_level)) {
        std::cerr << "Unknown validation level: " << validation_level << '\n';
        return 1;
    }
    auto format = GetValue(options, "format");
    if (format.empty()) {
        format = GetValue(options, "signature-format");
    }
    if (!IsAllowedFormat(format, false)) {
        std::cerr << "Unknown signature format: " << format << '\n';
        return 1;
    }

    const auto input_path = GetValue(options, "input");
    const auto signature_path = GetValue(options, "signature");

    if (input_path.empty() && signature_path.empty()) {
        std::cerr << "Missing required --input\n";
        return 1;
    }

    tamga::core::Session session;
    if (!ConfigureSession(options, session)) {
        std::cerr << session.GetLastError().message << '\n';
        return 1;
    }

    bool valid = false;
    bool execution_ok = false;

    if (format.empty() || format == "cms" || format == "cms-detached" ||
        format == "cades-bes" || format == "cades-t") {
        if (input_path.empty() || signature_path.empty()) {
            std::cerr << "CMS detached verification requires both --input and --signature\n";
            return 1;
        }
        execution_ok = session.RawVerifyFile(input_path, signature_path, valid);
    } else if (format == "cms-attached") {
        const auto target_file = input_path.empty() ? signature_path : input_path;
        std::vector<std::uint8_t> data;
        if (!ReadBinaryFile(target_file, data)) {
            std::cerr << "Cannot read attached CMS file: " << target_file << '\n';
            return 1;
        }
        std::vector<std::uint8_t> content;
        execution_ok = session.VerifyDataInternal(data, valid, content);
    } else if (format == "xades" || format == "xmldsig") {
        const auto target_file = input_path.empty() ? signature_path : input_path;
        std::string xml;
        if (!ReadTextFile(target_file, xml)) {
            std::cerr << "Cannot read XML file: " << target_file << '\n';
            return 1;
        }
        execution_ok = session.VerifyXml(xml, valid);
    } else if (format == "pades" || format == "pades-b" ||
               format == "pades-t" || format == "pades-lt" ||
               format == "pades-lta") {
        const auto target_file = input_path.empty() ? signature_path : input_path;
        std::vector<std::uint8_t> pdf;
        if (!ReadBinaryFile(target_file, pdf)) {
            std::cerr << "Cannot read PDF file: " << target_file << '\n';
            return 1;
        }
        execution_ok = session.VerifyPdf(pdf, valid);
    } else if (format == "asic-s") {
        const auto target_file = input_path.empty() ? signature_path : input_path;
        execution_ok = session.VerifyFileAsicS(target_file, valid);
    } else if (format == "asic-e") {
        const auto target_file = input_path.empty() ? signature_path : input_path;
        execution_ok = session.VerifyFileAsicE(target_file, valid);
    } else if (format == "asic-s-cades") {
        const auto target_file = input_path.empty() ? signature_path : input_path;
        execution_ok = session.VerifyFileAsicS(target_file, valid);
    } else if (format == "asic-e-cades") {
        const auto target_file = input_path.empty() ? signature_path : input_path;
        execution_ok = session.VerifyFileAsicE(target_file, valid);
    } else if (format == "asic-e-xades") {
        const auto target_file = input_path.empty() ? signature_path : input_path;
        execution_ok = session.VerifyFileAsicEXades(target_file, valid);
    }

    // Q-07: `--evidence-out` обробляється ДО будь-якого виходу з цієї точки —
    // і на успішній, і на невдалій перевірці. Раніше блок збереження стояв
    // після раннього `return` по `!execution_ok`, тож звіт саме про невдалу
    // перевірку у файл не потрапляв ніколи. Правила — у `cli/CliEvidence.h`.
    const auto evidence_out = GetValue(options, "evidence-out");
    const auto evidence_outcome = tamga::cli::WriteEvidence(
        evidence_out,
        [&session](std::string& out) { return session.GetLastVerifyReport(out); },
        // П-12: запис іде через атомарний writer. Звіт-доказ, обірваний на
        // півслові, гірший за його відсутність — він виглядає як файл.
        [](const std::string& path, const std::string& text) { return WriteTextFile(path, text); });
    if (evidence_outcome == tamga::cli::EvidenceOutcome::ReportUnavailable) {
        std::cerr << "Cannot build evidence report: " << session.GetLastError().message << '\n';
    } else if (evidence_outcome == tamga::cli::EvidenceOutcome::WriteFailed) {
        std::cerr << "Cannot write evidence file: " << evidence_out << '\n';
    }

    if (!execution_ok) {
        std::cerr << session.GetLastError().message << '\n';
        return tamga::cli::ApplyEvidenceOutcome(evidence_outcome,
                                                MapVerificationExitCode(session, false));
    }

    // Q-07: кожен вихід нижче проходить через ApplyEvidenceOutcome. Саме тут
    // жив дефект: для валідного підпису поверталося 0 навіть тоді, коли
    // запитаний `--evidence-out` записати не вдалося.
    if (report_mode == "technical-json") {
        std::string report;
        if (!session.GetLastVerifyReport(report)) {
            std::cerr << session.GetLastError().message << '\n';
            return tamga::cli::ApplyEvidenceOutcome(evidence_outcome,
                                                    MapVerificationExitCode(session, false));
        }
        std::cout << report << '\n';
        return tamga::cli::ApplyEvidenceOutcome(evidence_outcome,
                                                MapVerificationExitCode(session, valid));
    }
    if (report_mode == "pretty-json") {
        std::string report;
        if (!session.GetUserReport(report)) {
            std::cerr << session.GetLastError().message << '\n';
            return tamga::cli::ApplyEvidenceOutcome(evidence_outcome,
                                                    MapVerificationExitCode(session, false));
        }
        std::cout << report << '\n';
        return tamga::cli::ApplyEvidenceOutcome(evidence_outcome,
                                                MapVerificationExitCode(session, valid));
    }
    std::cout << (valid ? "valid" : "invalid") << '\n';
    return tamga::cli::ApplyEvidenceOutcome(evidence_outcome,
                                            MapVerificationExitCode(session, valid));
}

} // namespace

int main(int argc, char** argv) {
    CliOptions options;
    if (!ParseArgs(argc, argv, options)) {
        PrintUsage();
        return 1;
    }
    if (options.command == "--help" || options.command == "help") {
        PrintUsage();
        return 0;
    }
    if (options.command == "media") {
        return RunMedia(options);
    }
    if (options.command == "base64-encode") {
        return RunBase64Encode(options);
    }
    if (options.command == "base64-decode") {
        return RunBase64Decode(options);
    }
    if (options.command == "sign-file") {
        return RunSignFile(options);
    }
    if (options.command == "verify-file") {
        return RunVerifyFile(options);
    }
    if (options.command == "trust") {
        if (options.help || options.subcommand.empty()) {
            PrintTrustUsage();
            return 0;
        }
        if (options.subcommand == "sync") {
            return RunTrustSync(options);
        }
        std::cerr << "Unknown trust command: " << options.subcommand << '\n';
        PrintTrustUsage();
        return 1;
    }
    if (options.command == "verify") {
        if (options.help) {
            PrintVerifyUsage();
            return 0;
        }
        return RunVerifyFile(options);
    }
    std::cerr << "Unknown command: " << options.command << '\n';
    PrintUsage();
    return 1;
}
