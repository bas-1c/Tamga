#include "core/net/CertificateFetcher.h"
#include "util/Vectors.h"

#include "util/Der.h"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <utility>

#include "core/CryptoniteAdapter.h"
#include "core/HttpClient.h"
#include "util/Base64.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winldap.h>
#endif

namespace tamga::core::net {
namespace {

// ── Mock-seam мережевих джерел: синхронізація (П-05) ─────────────────────────
//
// Раніше тут лежали три голі глобальні `std::function`, які `ScopedMockTransport`
// ПИСАВ, а `Fetch` ЧИТАВ — без жодної синхронізації. Одночасне читання й запис
// `std::function` — невизначена поведінка, а не «майже безпечно»: під час
// присвоєння об'єкт проходить стан, у якому вказівник на vtable/буфер уже
// змінено, а сам буфер ще ні.
//
// Рішення взяте не з повітря: точний близнюк цієї конструкції в
// `core/HttpClient.cpp` (`g_mock_transport`, `g_mock_resolver`) уже захищений
// мутексом, і всі точки доступу там беруть `lock_guard`. Тут відтворено той
// самий контракт, включно з головною його частиною: під замком робиться лише
// КОПІЯ `std::function`, а сам виклик транспорту виконується ПОЗА замком.
// Це навмисно — мережевий (або тестовий) виклик не має тримати блокування,
// інакше довгий fetch серіалізував би всі інші сесії.
//
// Копіювання під замком закриває ще одну ваду попереднього коду: він робив
// `if (LdapTransport()) return LdapTransport()(request);` — тобто читав
// глобал ДВІЧІ. Скидання мока між перевіркою і викликом давало виклик
// порожньої `std::function` навіть без гонки на рівні байтів.
struct MockTransportSlot {
    std::mutex mutex;
    CertificateFetchTransport transport;
};

MockTransportSlot& LdapSlot() {
    static MockTransportSlot slot;
    return slot;
}

MockTransportSlot& HttpSlot() {
    static MockTransportSlot slot;
    return slot;
}

MockTransportSlot& CmpSlot() {
    static MockTransportSlot slot;
    return slot;
}

// Повертає КОПІЮ транспорту. Викликати її треба вже без замка.
CertificateFetchTransport LoadTransport(MockTransportSlot& slot) {
    std::lock_guard<std::mutex> lock(slot.mutex);
    return slot.transport;
}

void StoreTransport(MockTransportSlot& slot, CertificateFetchTransport transport) {
    std::lock_guard<std::mutex> lock(slot.mutex);
    slot.transport = std::move(transport);
}

// ── Мінімальний DER-кодувальник для тіла CMP ─────────────────────────────────
// Потрібні рівно три речі: довжина, примітив і конструктор. Повного ASN.1-стека
// тут не треба, а зайвий був би зайвою поверхнею для помилок.
void AppendDerLength(std::vector<std::uint8_t>& out, const std::size_t length) {
    if (length < 0x80) {
        out.push_back(static_cast<std::uint8_t>(length));
        return;
    }
    std::uint8_t buf[sizeof(std::size_t)];
    int n = 0;
    std::size_t value = length;
    while (value != 0) {
        buf[n++] = static_cast<std::uint8_t>(value & 0xFF);
        value >>= 8;
    }
    out.push_back(static_cast<std::uint8_t>(0x80 | n));
    for (int i = n - 1; i >= 0; --i) {
        out.push_back(buf[i]);
    }
}

std::vector<std::uint8_t> DerTlv(const std::uint8_t tag, const std::vector<std::uint8_t>& content) {
    std::vector<std::uint8_t> out;
    out.push_back(tag);
    AppendDerLength(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

// ADR-027: копія прибрана — шаблон живе в `util/Vectors.h`.
using tamga::util::AppendAll;

// Приймає DER, PEM або PKCS#7-набір. Порядок перевірок — від найдешевшої.
void AppendCertificates(const std::vector<std::uint8_t>& raw,
                        std::vector<std::vector<std::uint8_t>>& out) {
    if (raw.empty()) {
        return;
    }

    // PKCS#7 / .p7b: контейнер із набором сертифікатів (типова форма видачі
    // ланцюга КНЕДП). Розбираємо через cryptonite, бо це той самий SignedData.
    std::vector<std::vector<std::uint8_t>> bundle;
    std::string bundle_error;
    if (CryptoniteAdapter::ExtractCertificatesFromPkcs7(raw, bundle, bundle_error) && !bundle.empty()) {
        for (auto& cert : bundle) {
            out.push_back(std::move(cert));
        }
        return;
    }

    if (raw.front() == 0x30) {  // одиночний DER
        out.push_back(raw);
        return;
    }

    // PEM: у відповіді може бути кілька блоків підряд.
    const std::string text(raw.begin(), raw.end());
    std::size_t pos = 0;
    while ((pos = text.find("-----BEGIN", pos)) != std::string::npos) {
        const auto header_end = text.find('\n', pos);
        if (header_end == std::string::npos) {
            break;
        }
        const auto footer = text.find("-----END", header_end);
        if (footer == std::string::npos) {
            break;
        }
        std::vector<std::uint8_t> der;
        if (tamga::util::Base64Decode(text.substr(header_end + 1, footer - header_end - 1), der) &&
            !der.empty() && der.front() == 0x30) {
            out.push_back(std::move(der));
        }
        pos = footer + 1;
    }
}

#if defined(_WIN32)

// ldap://host:port/base-dn -> складові. Порожній результат означає «не LDAP-URL».
bool SplitLdapUrl(const std::string& url, std::string& host, int& port, std::string& base_dn) {
    const std::string scheme = "ldap://";
    if (url.size() <= scheme.size() ||
        !std::equal(scheme.begin(), scheme.end(), url.begin(),
                    [](char a, char b) {
                        return std::tolower(static_cast<unsigned char>(a)) ==
                               std::tolower(static_cast<unsigned char>(b));
                    })) {
        return false;
    }
    std::string rest = url.substr(scheme.size());
    const auto slash = rest.find('/');
    std::string authority = rest;
    if (slash != std::string::npos) {
        authority = rest.substr(0, slash);
        base_dn = rest.substr(slash + 1);
    }
    const auto colon = authority.rfind(':');
    port = LDAP_PORT;
    if (colon != std::string::npos) {
        host = authority.substr(0, colon);
        const std::string port_text = authority.substr(colon + 1);
        if (!port_text.empty() &&
            std::all_of(port_text.begin(), port_text.end(),
                        [](unsigned char c) { return std::isdigit(c) != 0; })) {
            port = std::stoi(port_text);
        }
    } else {
        host = authority;
    }
    return !host.empty();
}

// Екранування за RFC 4515: підказка приходить ззовні (з дескриптора ключа), тож
// без цього спецсимвол у ЄДРПОУ/CN міг би змінити структуру фільтра.
std::string EscapeLdapFilterValue(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
            case '*':  out += "\\2a"; break;
            case '(':  out += "\\28"; break;
            case ')':  out += "\\29"; break;
            case '\\': out += "\\5c"; break;
            case '\0': out += "\\00"; break;
            default:   out += ch;     break;
        }
    }
    return out;
}

CertificateFetchResult FetchViaWinLdap(const CertificateFetchRequest& request) {
    CertificateFetchResult result;

    std::string host;
    std::string base_dn = request.base_dn;
    int port = LDAP_PORT;
    if (!SplitLdapUrl(request.url, host, port, base_dn)) {
        result.message = "LDAP fetch: unsupported URL (expected ldap://host[:port][/base-dn])";
        return result;
    }
    if (base_dn.empty()) {
        result.message = "LDAP fetch: base DN is required (neither in the URL nor in settings)";
        return result;
    }

    LDAP* ld = ldap_initA(const_cast<PSTR>(host.c_str()), port);
    if (ld == nullptr) {
        result.message = "LDAP fetch: connection could not be initialised";
        return result;
    }

    // Гарантія звільнення на всіх шляхах виходу — сесія 1С довгоживуча.
    struct LdapGuard {
        LDAP* handle;
        ~LdapGuard() {
            if (handle != nullptr) {
                ldap_unbind(handle);
            }
        }
    } guard{ld};

    ULONG version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    LDAP_TIMEVAL timeout{};
    timeout.tv_sec = request.timeout_ms / 1000;
    timeout.tv_usec = (request.timeout_ms % 1000) * 1000;

    if (ldap_connect(ld, &timeout) != LDAP_SUCCESS) {
        result.message = "LDAP fetch: connect failed";
        return result;
    }
    // Анонімний bind: каталоги сертифікатів КНЕДП публічні за призначенням.
    if (ldap_simple_bind_sA(ld, nullptr, nullptr) != LDAP_SUCCESS) {
        result.message = "LDAP fetch: anonymous bind rejected";
        return result;
    }

    std::string filter = "(objectClass=*)";
    if (!request.subject_hint.empty()) {
        const std::string hint = EscapeLdapFilterValue(request.subject_hint);
        filter = "(|(serialNumber=" + hint + ")(cn=" + hint + ")(ou=" + hint + "))";
    }

    char attr_cert[] = "userCertificate;binary";
    char attr_cert_plain[] = "userCertificate";
    char* attrs[] = {attr_cert, attr_cert_plain, nullptr};

    LDAPMessage* reply = nullptr;
    const ULONG rc = ldap_search_stA(ld, const_cast<PSTR>(base_dn.c_str()), LDAP_SCOPE_SUBTREE,
                                     const_cast<PSTR>(filter.c_str()), attrs, 0, &timeout, &reply);
    if (rc != LDAP_SUCCESS || reply == nullptr) {
        if (reply != nullptr) {
            ldap_msgfree(reply);
        }
        result.message = "LDAP fetch: search failed (rc = " + std::to_string(static_cast<long>(rc)) + ")";
        return result;
    }

    for (LDAPMessage* entry = ldap_first_entry(ld, reply); entry != nullptr;
         entry = ldap_next_entry(ld, entry)) {
        for (char* attr : {attr_cert, attr_cert_plain}) {
            berval** values = ldap_get_values_lenA(ld, entry, attr);
            if (values == nullptr) {
                continue;
            }
            for (int i = 0; values[i] != nullptr; ++i) {
                const auto* bytes = reinterpret_cast<const std::uint8_t*>(values[i]->bv_val);
                if (bytes != nullptr && values[i]->bv_len > 0) {
                    AppendCertificates(std::vector<std::uint8_t>(bytes, bytes + values[i]->bv_len),
                                       result.candidates);
                }
            }
            ldap_value_free_len(values);
        }
    }
    ldap_msgfree(reply);

    result.executed = true;
    if (result.candidates.empty()) {
        result.message = "LDAP fetch: directory returned no certificates";
    }
    return result;
}

#endif  // _WIN32

}  // namespace

LdapCertificateFetcher::ScopedMockTransport::ScopedMockTransport(CertificateFetchTransport transport) {
    StoreTransport(LdapSlot(), std::move(transport));
}

LdapCertificateFetcher::ScopedMockTransport::~ScopedMockTransport() {
    StoreTransport(LdapSlot(), nullptr);
}

HttpCertificateFetcher::ScopedMockTransport::ScopedMockTransport(CertificateFetchTransport transport) {
    StoreTransport(HttpSlot(), std::move(transport));
}

HttpCertificateFetcher::ScopedMockTransport::~ScopedMockTransport() {
    StoreTransport(HttpSlot(), nullptr);
}

CmpCertificateFetcher::ScopedMockTransport::ScopedMockTransport(CertificateFetchTransport transport) {
    StoreTransport(CmpSlot(), std::move(transport));
}

CmpCertificateFetcher::ScopedMockTransport::~ScopedMockTransport() {
    StoreTransport(CmpSlot(), nullptr);
}

CertificateFetchResult LdapCertificateFetcher::Fetch(const CertificateFetchRequest& request) {
    // Копія під замком (див. `LoadTransport`), виклик — уже без замка.
    if (const CertificateFetchTransport transport = LoadTransport(LdapSlot())) {
        return transport(request);
    }
    if (request.url.empty()) {
        CertificateFetchResult result;
        result.message = "LDAP fetch: no directory URL configured";
        return result;
    }
#if defined(_WIN32)
    return FetchViaWinLdap(request);
#else
    CertificateFetchResult result;
    result.message = "LDAP fetch is only implemented on Windows (winldap)";
    return result;
#endif
}

std::vector<std::uint8_t> CmpCertificateFetcher::BuildCaCertsGenMessage() {
    // PKIHeader ::= SEQUENCE { pvno INTEGER(2), sender GeneralName,
    //                          recipient GeneralName, ... }
    // sender/recipient — directoryName [4] з порожнім RDNSequence: запит
    // неавтентифікований, конкретного відправника немає.
    const std::vector<std::uint8_t> null_dn = DerTlv(0xA4, DerTlv(0x30, {}));

    std::vector<std::uint8_t> header_content;
    AppendAll(header_content, DerTlv(0x02, {0x02}));  // pvno = cmp2000(2)
    AppendAll(header_content, null_dn);               // sender
    AppendAll(header_content, null_dn);               // recipient
    const std::vector<std::uint8_t> header = DerTlv(0x30, header_content);

    // InfoTypeAndValue ::= SEQUENCE { infoType OID, infoValue ANY OPTIONAL }
    // id-it-caCerts = 1.3.6.1.5.5.7.4.17 (RFC 4210 §5.3.19.15)
    const std::vector<std::uint8_t> id_it_ca_certs =
        DerTlv(0x06, {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x11});
    const std::vector<std::uint8_t> info = DerTlv(0x30, id_it_ca_certs);

    // PKIBody ::= CHOICE { ..., genm [21] GenMsgContent }
    // GenMsgContent ::= SEQUENCE OF InfoTypeAndValue; тег [21] у context-specific
    // constructed формі: 0xA0 | 21 = 0xB5 (21 < 31, тож high-tag форма не потрібна).
    const std::vector<std::uint8_t> pki_body = DerTlv(0xB5, DerTlv(0x30, info));

    std::vector<std::uint8_t> message_content;
    AppendAll(message_content, header);
    AppendAll(message_content, pki_body);
    return DerTlv(0x30, message_content);
}

std::vector<std::vector<std::uint8_t>> CmpCertificateFetcher::HarvestCertificates(
    const std::vector<std::uint8_t>& der_blob) {
    std::vector<std::vector<std::uint8_t>> found;
    if (der_blob.size() < 64) {
        return found;
    }

    for (std::size_t i = 0; i + 4 < der_blob.size();) {
        if (der_blob[i] != 0x30) {
            ++i;
            continue;
        }
        // Розбираємо лише довгу форму довжини: сертифікат коротшим за 128 байт
        // не буває, тож коротка форма тут завідомо не сертифікат.
        // Хвиля 8, п.2 (доповнення): розбір довжини йде через спільний
        // `util::ParseTlvAt`, який рахує межі без переповнення. Раніше тут було
        // `i + total > der_blob.size()`: у 32-бітній збірці (x86-компонента для
        // тонкого клієнта 1С) `total` міг переповнитись і дати маленьке число,
        // після чого кандидат вирізався б не тієї довжини. OOB це не давало,
        // але сканер знаходив би сміття замість сертифіката.
        if ((der_blob[i + 1] & 0x80) == 0) {
            // Сертифікат коротшим за 128 байт не буває, тож коротка форма тут
            // завідомо не сертифікат.
            ++i;
            continue;
        }
        tamga::util::TlvView tlv{};
        if (!tamga::util::ParseTlvAt(der_blob, i, der_blob.size(), tlv)) {
            ++i;
            continue;
        }
        const std::size_t length = tlv.value_length;
        const std::size_t total = tlv.next_offset - i;
        if (length == 0) {
            ++i;
            continue;
        }

        std::vector<std::uint8_t> candidate(der_blob.begin() + static_cast<std::ptrdiff_t>(i),
                                            der_blob.begin() + static_cast<std::ptrdiff_t>(i + total));
        if (CryptoniteAdapter::IsCertificateDer(candidate)) {
            found.push_back(std::move(candidate));
            i += total;  // не шукаємо вкладені структури всередині сертифіката
            continue;
        }
        ++i;
    }
    return found;
}

CertificateFetchResult CmpCertificateFetcher::Fetch(const CertificateFetchRequest& request) {
    if (const CertificateFetchTransport transport = LoadTransport(CmpSlot())) {
        return transport(request);
    }

    CertificateFetchResult result;
    if (request.url.empty()) {
        result.message = "CMP fetch: no endpoint configured (cmpAddress is empty for this CA)";
        return result;
    }

    const auto body = BuildCaCertsGenMessage();
    // RFC 6712: CMP over HTTP, media type application/pkixcmp.
    const HttpPostResult response = HttpClient::Post(request.url, body, "application/pkixcmp",
                                                     "application/pkixcmp", request.timeout_ms);
    if (!response.succeeded || response.status_code < 200 || response.status_code >= 300) {
        result.message = "CMP fetch: request failed (status " +
                         std::to_string(response.status_code) + ")";
        return result;
    }

    result.candidates = HarvestCertificates(response.body);
    result.executed = true;
    if (result.candidates.empty()) {
        result.message = "CMP fetch: response contained no certificates";
    }
    return result;
}

CertificateFetchResult HttpCertificateFetcher::Fetch(const CertificateFetchRequest& request) {
    if (const CertificateFetchTransport transport = LoadTransport(HttpSlot())) {
        return transport(request);
    }

    CertificateFetchResult result;
    if (request.url.empty()) {
        result.message = "HTTP fetch: no certificate URL configured";
        return result;
    }

    const HttpPostResult response = HttpClient::Get(
        request.url, "application/pkcs7-mime, application/x-x509-ca-cert, */*", request.timeout_ms);
    if (!response.succeeded || response.status_code < 200 || response.status_code >= 300) {
        result.message = "HTTP fetch: request failed (status " +
                         std::to_string(response.status_code) + ")";
        return result;
    }

    AppendCertificates(response.body, result.candidates);
    result.executed = true;
    if (result.candidates.empty()) {
        result.message = "HTTP fetch: response contained no certificates";
    }
    return result;
}

}  // namespace tamga::core::net
