#include "core/net/CertificateResolver.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>

#include "core/CryptoniteAdapter.h"
#include "core/cryptonite/CertUtil.h"
#include "core/cryptonite/KeyPairing.h"
#include "core/net/CaSettingsRegistry.h"
#include "core/net/CertificateFetcher.h"
#include "core/policy/Sha256Helper.h"
#include "util/Base64.h"
#include "util/FileSystem.h"

namespace tamga::core::net {
namespace {

constexpr char kCacheDirName[] = "cert-cache";
constexpr char kMissingCertificateMessage[] =
    "Не знайдено відкритий сертифікат для закритого ключа. "
    "Покладіть файл сертифіката (.cer/.crt) поруч із ключем або передайте "
    "через параметр certificatePath";

bool CertificateAllowsSigningUsage(const std::vector<std::uint8_t>& der) {
#if TAMGA_CRYPTONITE_ENABLED
    const auto certificate = cryptonite_detail::DecodeCertificateDer(der);
    return certificate != nullptr &&
           cryptonite_detail::CertificateAllowsSigning(certificate.get());
#else
    (void)der;
    return false;
#endif
}

std::string ToLowerHex(const std::array<std::uint8_t, 32>& digest) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const auto byte : digest) {
        stream << std::setw(2) << static_cast<unsigned>(byte);
    }
    return stream.str();
}

bool ReadBinary(const std::filesystem::path& path, std::vector<std::uint8_t>& out) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || !std::filesystem::is_regular_file(path, ec)) {
        return false;
    }
    std::string read_error;
    if (!util::ReadBinaryFileLimited(path, util::kMaxCertificateFileSize, out, read_error)) {
        return false;
    }
    return !out.empty();
}

// КНЕДП видають сертифікати і в DER, і в PEM (`.cer` буває як текстовим, так і
// бінарним). Приймаємо обидва, щоб sidecar-пошук не залежав від того, як
// конкретний надавач зберіг файл.
bool NormalizeCertificateBytes(std::vector<std::uint8_t> raw, std::vector<std::uint8_t>& der) {
    if (raw.empty()) {
        return false;
    }
    if (raw.front() == 0x30) {  // ASN.1 SEQUENCE — уже DER
        der = std::move(raw);
        return true;
    }
    const std::string text(raw.begin(), raw.end());
    const auto begin = text.find("-----BEGIN");
    if (begin == std::string::npos) {
        return false;
    }
    const auto header_end = text.find('\n', begin);
    const auto footer = text.find("-----END", header_end == std::string::npos ? begin : header_end);
    if (header_end == std::string::npos || footer == std::string::npos) {
        return false;
    }
    const std::string body = text.substr(header_end + 1, footer - header_end - 1);
    return tamga::util::Base64Decode(body, der) && !der.empty() && der.front() == 0x30;
}

std::filesystem::path Utf8Path(const std::string& value) {
    return std::filesystem::u8path(value);
}

// path -> UTF-8 std::string, сумісно з C++17 і C++20 (де u8string() дає char8_t).
// ADR-027: копія прибрана — одна реалізація в `util/FileSystem`.
using tamga::util::PathToUtf8;

// Кандидати поруч із ключем: спершу однойменний файл (key.dat -> key.cer/.crt/
// .der/.pem), потім усі решта сертифікатів у тому ж каталозі. Порядок важливий:
// однойменний файл — найсильніша підказка користувача.
std::vector<std::filesystem::path> CollectSidecarCandidates(const std::string& key_file_path) {
    std::vector<std::filesystem::path> candidates;
    if (key_file_path.empty()) {
        return candidates;
    }
    std::error_code ec;
    auto key_path = Utf8Path(key_file_path);
    if (key_path.parent_path().empty()) {
        // Q-02. `key.dat` без каталогу — це файл у ПОТОЧНОМУ каталозі процесу,
        // а не файл без каталогу. Саме так його читає `ReadBinaryFile`, тож
        // sidecar-пошук зобовʼязаний трактувати шлях так само. Раніше порожній
        // `parent_path()` віддавав порожній список кандидатів, і типовий виклик
        // CLI `--key key.dat` не бачив `key.cer` поруч із ключем.
        //
        // Розгортаємо в абсолютний шлях саме тут, а не в `ResolveFilePath`:
        // той резолвер спільний для ВСІХ файлових операцій (вхід, вихід, ASiC,
        // XML, PDF), і його результат потрапляє в повідомлення про помилки та
        // у звіти перевірки. Робити там шляхи абсолютними означало б змінити
        // спостережуваний контракт усіх цих операцій заради дефекту, що існує
        // рівно в одному місці. Побічна вигода локального розгортання: і
        // однойменні кандидати, і `directory_iterator` дають однакову форму
        // шляху, тому дедуплікація нижче працює без нормалізації.
        auto absolute_path = std::filesystem::absolute(key_path, ec);
        if (!ec && !absolute_path.empty()) {
            key_path = absolute_path.lexically_normal();
        }
    }
    const auto dir = key_path.parent_path();
    if (dir.empty() || !std::filesystem::is_directory(dir, ec)) {
        return candidates;
    }

    static const char* kExtensions[] = {".cer", ".crt", ".der", ".pem"};
    auto stem_path = key_path;
    stem_path.replace_extension();
    for (const char* ext : kExtensions) {
        auto sibling = stem_path;
        sibling += ext;
        if (std::filesystem::is_regular_file(sibling, ec)) {
            candidates.push_back(sibling);
        }
    }

    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec || !entry.is_regular_file(ec)) {
            continue;
        }
        auto ext = entry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (std::find(std::begin(kExtensions), std::end(kExtensions), ext) == std::end(kExtensions)) {
            continue;
        }
        if (std::find(candidates.begin(), candidates.end(), entry.path()) == candidates.end()) {
            candidates.push_back(entry.path());
        }
    }
    return candidates;
}

}  // namespace

bool CertificateResolver::ComputeSpkiFingerprint(const std::vector<std::uint8_t>& key_material,
                                                 const std::string& password,
                                                 std::string& fingerprint_hex,
                                                 std::string& error_message) {
    fingerprint_hex.clear();
    std::vector<std::uint8_t> spki;
    if (!CryptoniteAdapter::ExtractSubjectPublicKeyInfo(key_material, password, spki, error_message)) {
        return false;
    }
    fingerprint_hex = ToLowerHex(policy::Sha256(spki));
    return !fingerprint_hex.empty();
}

CertificateResolveResult CertificateResolver::Resolve(const CertificateResolveRequest& request) const {
    CertificateResolveResult result;

    if (request.key_material.empty()) {
        result.message = "Certificate resolution requires the private key material";
        return result;
    }

    // Відпечаток ключа потрібен і для кешу, і для діагностики. Якщо його не вдалося
    // обчислити, ми не зможемо fail-closed перевірити жодного кандидата — тоді
    // краще відмовитись, ніж повернути неперевірений сертифікат.
    std::string fingerprint_error;
    if (!ComputeSpkiFingerprint(request.key_material, request.password, result.spki_sha256,
                                fingerprint_error)) {
        result.message = "Unable to derive the public key from the container: " + fingerprint_error;
        return result;
    }

    // O-02: набір відкритих ключів контейнера дістається ОДИН раз на весь
    // `Resolve`, а не заново на кожного кандидата.
    //
    // Раніше кожен кандидат ішов через `CertificateMatchesPrivateKey`, і той
    // щоразу наново декодував (а для PKCS#12 — і розшифровував) контейнер.
    // Для каталогу з багатьма `.cer/.crt/.der/.pem` це давало лінійне зростання
    // саме на найдорожчій операції: виміряно 2026-09-09 на ДСТУ 4145 M257_PB —
    // 6070 мс (PKCS#12) і 1914 мс (PKCS#8) на 100 кандидатів проти 61 і 26 мс
    // на одного. Після зміни ті самі 100 кандидатів — 86 і 60 мс. Повна
    // таблиця і методика — у `core/cryptonite/KeyPairing.h`.
    //
    // Що НЕ змінилося: критерій приймання (повний DER SubjectPublicKeyInfo),
    // підтримка кількох ключів у контейнері та наступна перевірка `keyUsage`.
    // Знімок містить лише ВІДКРИТІ ключі й живе рівно стільки, скільки триває
    // цей виклик, — незашифрований секрет ніде не затримується.
    ContainerPublicKeys container_keys;
    std::string container_keys_error;
    if (!ContainerPublicKeys::Load(request.key_material, request.password, container_keys,
                                   container_keys_error)) {
        // Fail-closed: без набору ключів контейнера жодного кандидата не можна
        // звірити по-справжньому, тож нічого й не повертаємо.
        result.message =
            "Unable to enumerate the container public keys: " + container_keys_error;
        return result;
    }

    // Єдина точка прийняття рішення: кандидат приймається лише якщо він
    // математично відповідає закритому ключу та його keyUsage дозволяє підпис.
    bool rejected_by_key_usage = false;
    const auto accept = [&](std::vector<std::uint8_t> candidate, const char* source,
                            std::string detail) -> bool {
        std::vector<std::uint8_t> der;
        if (!NormalizeCertificateBytes(std::move(candidate), der)) {
            return false;
        }
        if (!container_keys.Matches(der)) {
            ++result.rejected_candidates;
            return false;
        }
        if (!CertificateAllowsSigningUsage(der)) {
            ++result.rejected_candidates;
            rejected_by_key_usage = true;
            return false;
        }
        result.succeeded = true;
        result.certificate_der = std::move(der);
        result.source = source;
        result.source_detail = std::move(detail);
        return true;
    };

    // ── Рівень 1: явно переданий сертифікат ───────────────────────────────────
    if (!request.explicit_certificate_der.empty()) {
        if (accept(request.explicit_certificate_der, "explicit-der", "descriptor")) {
            return result;
        }
        // Явна вказівка користувача, що не пройшла перевірку, — це помилка
        // конфігурації, а не привід шукати далі: інакше ми тихо підмінили б
        // те, що людина свідомо задала.
        result.message = rejected_by_key_usage
            ? "Сертифікат відповідає ключу, але його keyUsage не дозволяє підпис"
            : "The supplied certificate does not match the private key in the container";
        return result;
    }
    if (!request.explicit_certificate_path.empty()) {
        std::vector<std::uint8_t> raw;
        if (!ReadBinary(Utf8Path(request.explicit_certificate_path), raw)) {
            result.message = "Certificate file cannot be read: " + request.explicit_certificate_path;
            return result;
        }
        if (accept(std::move(raw), "explicit-path", request.explicit_certificate_path)) {
            return result;
        }
        result.message = rejected_by_key_usage
            ? "Сертифікат відповідає ключу, але його keyUsage не дозволяє підпис: " +
                  request.explicit_certificate_path
            : "The certificate at " + request.explicit_certificate_path +
                  " does not match the private key in the container";
        return result;
    }

    // Шлях кешу обчислюємо заздалегідь, але читаємо його ПІСЛЯ sidecar.
    // Однойменний сертифікат поруч із ключем є сильнішою, свіжішою підказкою
    // користувача: перевиданий сертифікат може мати той самий SPKI, що й стара
    // кешована копія, і обидва кандидати пройдуть математичний гейт.
    std::filesystem::path cache_file;
    if (!request.work_dir.empty()) {
        cache_file = Utf8Path(request.work_dir) / kCacheDirName / (result.spki_sha256 + ".cer");
    }

    // ── Рівень 2а: sidecar-файли поруч із ключем ──────────────────────────────
    // CollectSidecarCandidates гарантує порядок: спочатку однойменні
    // .cer/.crt/.der/.pem, потім решта сертифікатів каталогу.
    for (const auto& candidate_path : CollectSidecarCandidates(request.key_file_path)) {
        std::vector<std::uint8_t> raw;
        if (!ReadBinary(candidate_path, raw)) {
            continue;
        }
        if (accept(std::move(raw), "sidecar", PathToUtf8(candidate_path))) {
            // Знайдений локально сертифікат кешуємо, щоб наступні сесії не
            // сканували каталог і щоб працював офлайн навіть без sidecar.
            if (!cache_file.empty()) {
                std::error_code ec;
                std::filesystem::create_directories(cache_file.parent_path(), ec);
                (void)tamga::util::WriteBinaryFileAtomic(cache_file, result.certificate_der);
            }
            return result;
        }
    }

    // ── Рівень 2б: локальний кеш ──────────────────────────────────────────────
    // Кеш — fallback після всіх локальних підказок користувача. Кандидат із
    // кешу проходить ті самі ownership/keyUsage-гейти, що й sidecar.
    if (!cache_file.empty()) {
        std::vector<std::uint8_t> cached;
        if (ReadBinary(cache_file, cached) &&
            accept(std::move(cached), "cache", PathToUtf8(cache_file))) {
            return result;
        }
    }

    // ── Рівень 3: мережа ──────────────────────────────────────────────────────
    if (request.offline_mode) {
        result.message = std::string(kMissingCertificateMessage) +
                         " (offline, spki=" + result.spki_sha256 + ")";
        return result;
    }

    // Кожен мережевий кандидат проходить ТОЙ САМИЙ `accept`, що й локальні —
    // без винятків. Саме тому джерело не може підсунути чужий сертифікат: воно
    // взагалі не має права нічого приймати, лише пропонувати.
    const auto try_source = [&](const CertificateFetchResult& fetched, const char* source,
                                const std::string& detail) -> bool {
        for (const auto& candidate : fetched.candidates) {
            if (accept(candidate, source, detail)) {
                // Мережевий результат кешуємо: наступний підпис має працювати
                // навіть офлайн, і без повторного обходу каталогу.
                if (!cache_file.empty()) {
                    std::error_code ec;
                    std::filesystem::create_directories(cache_file.parent_path(), ec);
                    (void)tamga::util::WriteBinaryFileAtomic(cache_file, result.certificate_der);
                }
                return true;
            }
        }
        return false;
    };

    std::vector<std::string> attempts;

    // Реєстр КНЕДП (`CAs.json` ЦЗО) — джерело адрес, коли їх не задано явно.
    // У довірчому списку `cmpAddress` немає взагалі, тож без реєстру CMP-крок
    // просто нікуди адресувати.
    std::string ldap_url = request.ldap_url;
    std::string cmp_url = request.cmp_url;
    if ((ldap_url.empty() || cmp_url.empty()) && !request.preferred_ca_hint.empty()) {
        std::vector<CaSettingsEntry> registry;
        std::string registry_error;
        if (CaSettingsRegistry::Load(request.work_dir, request.offline_mode,
                                     request.ca_registry_url, request.network_timeout_ms,
                                     registry, registry_error)) {
            if (const auto* ca = CaSettingsRegistry::Find(registry, request.preferred_ca_hint)) {
                if (cmp_url.empty()) {
                    cmp_url = ca->cmp_url;
                }
            } else {
                attempts.push_back("ca-registry: no CA matches hint '" + request.preferred_ca_hint + "'");
            }
        } else {
            attempts.push_back("ca-registry: " + registry_error);
        }
    }

    // ── Рівень 3а: LDAP-каталог КНЕДП ─────────────────────────────────────────
    if (!ldap_url.empty()) {
        CertificateFetchRequest fetch;
        fetch.url = ldap_url;
        fetch.base_dn = request.ldap_base_dn;
        fetch.subject_hint = request.subject_identifier;
        fetch.timeout_ms = request.network_timeout_ms;
        const auto fetched = LdapCertificateFetcher::Fetch(fetch);
        if (try_source(fetched, "ldap", ldap_url)) {
            return result;
        }
        attempts.push_back("ldap: " + (fetched.executed
                                           ? ("no matching certificate among " +
                                              std::to_string(fetched.candidates.size()) + " candidate(s)")
                                           : fetched.message));
    }

    // ── Рівень 3б: HTTP-точка видачі (одиночний сертифікат або .p7b) ──────────
    if (!request.http_certificate_url.empty()) {
        CertificateFetchRequest fetch;
        fetch.url = request.http_certificate_url;
        fetch.subject_hint = request.subject_identifier;
        fetch.timeout_ms = request.network_timeout_ms;
        const auto fetched = HttpCertificateFetcher::Fetch(fetch);
        if (try_source(fetched, "czo-http", request.http_certificate_url)) {
            return result;
        }
        attempts.push_back("http: " + (fetched.executed
                                           ? ("no matching certificate among " +
                                              std::to_string(fetched.candidates.size()) + " candidate(s)")
                                           : fetched.message));
    }

    // ── Рівень 3в: CMP (RFC 4210/6712) ───────────────────────────────────────
    // Адреса — з `CAs.json`. Надсилається стандартний `genm`/`id-it-caCerts`;
    // вендорні профілі отримання ВЛАСНОГО сертифіката не вигадуємо (див.
    // коментар до CmpCertificateFetcher). Ризику це не додає: усе, що повернув
    // CMP, проходить ту саму звірку з ключем, тож хибний профіль може лише
    // нічого не знайти, але не підсунути чужий сертифікат.
    if (!cmp_url.empty()) {
        CertificateFetchRequest fetch;
        fetch.url = cmp_url;
        fetch.subject_hint = request.subject_identifier;
        fetch.timeout_ms = request.network_timeout_ms;
        const auto fetched = CmpCertificateFetcher::Fetch(fetch);
        if (try_source(fetched, "cmp", cmp_url)) {
            return result;
        }
        attempts.push_back("cmp: " + (fetched.executed
                                          ? ("no matching certificate among " +
                                             std::to_string(fetched.candidates.size()) + " candidate(s)")
                                          : fetched.message));
    }

    result.message = std::string(kMissingCertificateMessage) +
                     " (spki=" + result.spki_sha256 + ")";
    if (!attempts.empty()) {
        result.message += " (";
        for (std::size_t i = 0; i < attempts.size(); ++i) {
            if (i > 0) {
                result.message += "; ";
            }
            result.message += attempts[i];
        }
        result.message += ")";
    } else {
        result.message += " (no network source configured: set ldap_url, http_certificate_url, cmp_url, or a CA hint resolvable via CAs.json)";
    }
    return result;
}

}  // namespace tamga::core::net
