#include "core/HttpClient.h"

#include "core/net/HttpAccessPolicy.h"
#include "core/net/HttpMessageSyntax.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

// ── libcurl (пріоритет якщо знайдено через find_package) ─────────────────
#if TAMGA_LIBCURL_ENABLED
#include <curl/curl.h>
#endif

// ── WinHTTP fallback (Windows-only, без зовнішніх залежностей) ───────────
#if !TAMGA_LIBCURL_ENABLED && defined(_WIN32)
#define TAMGA_WINHTTP_ENABLED 1
#include <windows.h>
#include <winhttp.h>
#include <string>
#pragma comment(lib, "winhttp.lib")
#else
#define TAMGA_WINHTTP_ENABLED 0
#endif

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <sstream>
#include <utility>

namespace tamga::core {

namespace {

std::mutex g_mock_transport_mutex;
HttpTransport g_mock_transport;
std::mutex g_mock_resolver_mutex;
HttpHostResolver g_mock_resolver;

// WP-16: HTTP hardening. URL-и OCSP/CRL/AIA/TSP надходять із полів сертифіката
// (під контролем видавця/зловмисника), тож обмежуємо протоколи/редиректи/розмір.


std::vector<std::string> ResolveSystemHost(const std::string& host) {
#if defined(_WIN32)
    static std::once_flag winsock_once;
    static int winsock_result = WSASYSNOTREADY;
    std::call_once(winsock_once, []() {
        WSADATA data{};
        winsock_result = WSAStartup(MAKEWORD(2, 2), &data);
    });
    if (winsock_result != 0) return {};
#endif
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* addresses = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &addresses) != 0 || addresses == nullptr) {
        return {};
    }
    std::vector<std::string> result;
    for (const addrinfo* current = addresses; current != nullptr; current = current->ai_next) {
        char buffer[NI_MAXHOST]{};
        if (getnameinfo(current->ai_addr, static_cast<socklen_t>(current->ai_addrlen),
                        buffer, sizeof(buffer), nullptr, 0, NI_NUMERICHOST) == 0) {
            if (std::find(result.begin(), result.end(), buffer) == result.end()) result.emplace_back(buffer);
        }
    }
    freeaddrinfo(addresses);
    return result;
}


// піком пам'яті на ті самі до 64 МіБ, які щойно прибрано з `HttpPostResult`.
HttpPostResult ToPostResult(HttpResponse response) {
    HttpPostResult result;
    result.attempted = true;
    result.succeeded = response.succeeded;
    result.status_code = response.status_code;
    result.message = std::move(response.message);
    result.response_headers = std::move(response.response_headers);
    result.body = std::move(response.body);
    return result;
}

// Єдина точка, де політика зустрічається з глобальною мок-семою. Раніше
// політика сама лізла в цю глобальну змінну — саме тому її не можна було
// викликати без транспорту й без глобального стану, і саме тому розходження
// полярності П-08 не міг спіймати жоден прямий тест.
HttpDestinationResult CheckDestinationVia(const std::string& url,
                                          const bool treat_missing_resolver_as_allowed) {
    HttpHostResolver resolver;
    {
        std::lock_guard<std::mutex> lock(g_mock_resolver_mutex);
        resolver = g_mock_resolver;
    }
    // Порядок умов зберігає ТОЧНУ попередню поведінку: коли викликач дозволив
    // пропустити DNS (детерміновані мок-тести) і мок-резолвера немає,
    // системний DNS НЕ підставляється — інакше ці тести почали б ходити в
    // мережу, а перевірка призначення мовчки змінила б сенс.
    if (!resolver && !treat_missing_resolver_as_allowed) {
        resolver = [](const std::string& host) { return ResolveSystemHost(host); };
    }
    return net::CheckDestination(url, resolver, treat_missing_resolver_as_allowed);
}

} // namespace

#if TAMGA_LIBCURL_ENABLED
// WP-16: обмежуємо схеми лише HTTP/HTTPS (у т.ч. на редиректах), кількість
// редиректів і максимальний розмір відповіді за Content-Length. Потоковий cap
// (для chunked/без Content-Length) додатково стоїть у WriteCallback.
static void ApplyCurlSecurityHardening(CURL* curl) {
    // CURLOPT_PROTOCOLS(_STR) — enum-значення, не макроси, тож перевіряємо
    // саме версію: *_STR зʼявились у 7.85.0 (0x075500) і не є deprecated.
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS,
                     static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS,
                     static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, net::kMaxHttpRedirects);
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, static_cast<long>(net::kMaxHttpResponseSize));
}

static curl_socket_t OpenPublicSocketOnly(void*, curlsocktype purpose, struct curl_sockaddr* address) {
    if (purpose != CURLSOCKTYPE_IPCXN || address == nullptr) return CURL_SOCKET_BAD;
    char numeric[NI_MAXHOST]{};
    // П-08: обидва backend-и питають ОДИН предикат, щоб полярність не могла
    // розійтися вдруге. Тут вона й раніше була правильною — фіксуємо це.
    if (getnameinfo(&address->addr, static_cast<socklen_t>(address->addrlen),
                    numeric, sizeof(numeric), nullptr, 0, NI_NUMERICHOST) != 0 ||
        !detail::IsAllowedPublicAddress(numeric)) {
        return CURL_SOCKET_BAD;
    }
    return ::socket(address->family, address->socktype, address->protocol);
}

static void ApplyCurlDestinationGuard(CURL* curl) {
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, OpenPublicSocketOnly);
}
#endif

HttpClient::ScopedMockTransport::ScopedMockTransport(HttpTransport transport) {
    std::lock_guard<std::mutex> lock(g_mock_transport_mutex);
    previous_ = std::move(g_mock_transport);
    g_mock_transport = std::move(transport);
}

HttpClient::ScopedMockTransport::~ScopedMockTransport() {
    std::lock_guard<std::mutex> lock(g_mock_transport_mutex);
    g_mock_transport = std::move(previous_);
}

HttpClient::ScopedMockResolver::ScopedMockResolver(HttpHostResolver resolver) {
    std::lock_guard<std::mutex> lock(g_mock_resolver_mutex);
    previous_ = std::move(g_mock_resolver);
    g_mock_resolver = std::move(resolver);
}

HttpClient::ScopedMockResolver::~ScopedMockResolver() {
    std::lock_guard<std::mutex> lock(g_mock_resolver_mutex);
    g_mock_resolver = std::move(previous_);
}

HttpDestinationResult HttpClient::CheckDestination(const std::string& url) {
    return CheckDestinationVia(url, false);
}

// ── WinHTTP helper functions ──────────────────────────────────────────────
#if TAMGA_WINHTTP_ENABLED

// Конвертація UTF-8 → wide БЕЗ null-термінатора у результаті.
// Ключовий момент: передаємо s.size() а не -1, щоб MultiByteToWideChar
// не включав null у wide рядок (інакше WinHTTP повертає ERROR_INVALID_PARAMETER).
static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int wlen = MultiByteToWideChar(CP_UTF8, 0,
        s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (wlen <= 0) return {};
    std::wstring result(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0,
        s.c_str(), static_cast<int>(s.size()), &result[0], wlen);
    return result;
}

static std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0,
        s.c_str(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string result(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0,
        s.c_str(), static_cast<int>(s.size()), &result[0], len, nullptr, nullptr);
    return result;
}

struct ParsedUrl {
    bool is_https{false};
    std::wstring host;
    INTERNET_PORT port{80};
    std::wstring path;
    bool valid{false};
};

static ParsedUrl ParseUrl(const std::string& url) {
    ParsedUrl r;
    std::wstring wurl = Utf8ToWide(url);
    if (wurl.empty()) return r;

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t scheme_buf[16]{}, host_buf[256]{}, path_buf[1024]{};
    uc.lpszScheme   = scheme_buf;  uc.dwSchemeLength   = _countof(scheme_buf);
    uc.lpszHostName = host_buf;    uc.dwHostNameLength = _countof(host_buf);
    uc.lpszUrlPath  = path_buf;    uc.dwUrlPathLength  = _countof(path_buf);

    if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc)) return r;

    r.is_https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    r.host     = host_buf;
    r.port     = uc.nPort;
    r.path     = (uc.dwUrlPathLength > 0) ? path_buf : L"/";
    r.valid    = true;
    return r;
}

// В-01 (DNS rebinding): `CheckDestinationImpl` резолвить ім'я хоста і
// перевіряє ВСІ отримані адреси, після чого `WinHttpConnect` резолвить ім'я
// ПОВТОРНО й незалежно. Між двома резолвами (TTL=0, round-robin, або DNS під
// контролем власника домену з AIA/OCSP/CRL/TSP URL) підставляється внутрішня
// адреса. На шляху libcurl вікно закрите `CURLOPT_OPENSOCKETFUNCTION`, який
// класифікує фактичну peer-адресу ДО відкриття сокета; у WinHTTP еквівалента
// немає, а конфігурація постачання лінкує саме WinHTTP
// (`TAMGA_LIBCURL_ENABLED=0`).
//
// WinHTTP не дає pre-connect хука, але дозволяє дізнатися фактичну адресу
// встановленого зʼєднання. Ми перевіряємо її одразу після
// `WinHttpSendRequest` і, якщо вона не публічна, відмовляємось використовувати
// відповідь.
//
// ЧЕСНА МЕЖА цього заходу: сам запит уже надіслано, тож побічні ефекти на
// внутрішньому сервісі він не скасовує. Він гарантує, що дані з приватної
// адреси НЕ потраплять у trust/revocation-рішення, і робить подію видимою.
// Повне закриття вікна потребує підключення за перевіреною IP, що у WinHTTP
// несумісне з SNI, — або libcurl як обовʼязкового backend-у постачання.
// Див. docs/security.md.
//
// П-08: усі гілки, на яких перевірка НЕ ВІДБУЛАСЯ (опція недоступна, адресу не
// вдалося відформатувати, невідома address family), раніше повертали `true` —
// тобто «дозволено». Це перетворювало захід на такий, що спрацьовує лише коли
// все й так добре. Тепер вони fail-closed: якщо ми не змогли встановити, з ким
// саме зʼєдналися, ми не використовуємо цю відповідь. Ціна відомa — відмова
// там, де адреса насправді була б публічною; вона прийнятна, бо йдеться про
// дані, що йдуть у рішення про довіру.
//
// `peer_text` у таких гілках наповнюється діагностичним маркером, а не
// адресою, щоб повідомлення користувача не виглядало як «адреса порожня».
bool WinHttpPeerAddressIsPublic(HINTERNET hRequest, std::string& peer_text) {
    peer_text.clear();
#if defined(WINHTTP_OPTION_CONNECTION_INFO)
    WINHTTP_CONNECTION_INFO info{};
    DWORD size = sizeof(info);
    if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_CONNECTION_INFO, &info, &size)) {
        // Fail-closed: без адреси зʼєднання твердження «це публічний вузол»
        // нічим не підкріплене, а саме на ньому тримається В-01.
        peer_text = "connection info unavailable";
        return false;
    }

    char buffer[NI_MAXHOST] = {0};
    const auto* addr = reinterpret_cast<const sockaddr*>(&info.RemoteAddress);
    if (addr->sa_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(addr);
        if (InetNtopA(AF_INET, &v4->sin_addr, buffer, sizeof(buffer)) == nullptr) {
            peer_text = "IPv4 peer address could not be formatted";
            return false;
        }
    } else if (addr->sa_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (InetNtopA(AF_INET6, &v6->sin6_addr, buffer, sizeof(buffer)) == nullptr) {
            peer_text = "IPv6 peer address could not be formatted";
            return false;
        }
    } else {
        peer_text = "unknown peer address family";
        return false;
    }

    peer_text = buffer;
    return detail::IsAllowedPublicAddress(peer_text);
#else
    // Компіляція без `WINHTTP_OPTION_CONNECTION_INFO` означає Windows SDK без
    // цієї опції (у підтримуваних SDK вона є з Vista). У такій збірці контроль
    // В-01 фізично відсутній, тож WinHTTP-backend не може дати гарантії, на
    // якій тримається destination policy, — і мовчки видавати «дозволено» тут
    // було б гіршим із двох варіантів.
    (void)hRequest;
    peer_text = "WINHTTP_OPTION_CONNECTION_INFO is unavailable in this SDK";
    return false;
#endif
}

// Загальна WinHTTP request-функція для GET/POST.
static HttpPostResult WinHttpRequestOnce(const std::string& method,
                                         const std::string& url,
                                         const std::vector<std::uint8_t>& body,
                                         const std::string& content_type,
                                         const std::string& accept,
                                         std::int32_t timeout_ms) {
    HttpPostResult result;
    result.attempted = true;

    auto parsed = ParseUrl(url);
    if (!parsed.valid) {
        result.message = "WinHTTP: failed to parse URL: " + url;
        return result;
    }

    // Конвертація content-type у wide — використовуємо Utf8ToWide без null
    std::wstring wct = Utf8ToWide(content_type);

    HINTERNET hSession = WinHttpOpen(
        L"Tamga/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        result.message = "WinHTTP: WinHttpOpen failed, code=" + std::to_string(GetLastError());
        return result;
    }

    // Таймаут
    WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    HINTERNET hConnect = WinHttpConnect(hSession, parsed.host.c_str(), parsed.port, 0);
    if (!hConnect) {
        result.message = "WinHTTP: WinHttpConnect failed, code=" + std::to_string(GetLastError());
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD flags = parsed.is_https ? WINHTTP_FLAG_SECURE : 0;
    const std::wstring wmethod = Utf8ToWide(method);
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, wmethod.c_str(), parsed.path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        result.message = "WinHTTP: WinHttpOpenRequest failed, code=" + std::to_string(GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    // FND-004: WinHTTP не повинен автоматично піти за Location до адреси, яку
    // destination policy ще не перевірив. Redirect-и обробляє wrapper нижче.
    DWORD disabled_features = WINHTTP_DISABLE_REDIRECTS;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE,
                     &disabled_features, sizeof(disabled_features));

    // Заголовки
    std::wstring headers = L"Accept: " + Utf8ToWide(accept) + L"\r\n";
    if (!content_type.empty()) {
        headers += L"Content-Type: " + wct + L"\r\n";
    }
    BOOL sent = WinHttpSendRequest(
        hRequest,
        headers.c_str(), static_cast<DWORD>(headers.size()),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<void*>(static_cast<const void*>(body.data())),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);

    if (!sent) {
        DWORD err = GetLastError();
        result.message = "WinHTTP: WinHttpSendRequest failed, code=" + std::to_string(err);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    // В-01: фактична адреса зʼєднання проти destination policy.
    {
        std::string peer;
        if (!WinHttpPeerAddressIsPublic(hRequest, peer)) {
            result.message = "WinHTTP: peer address did not pass destination policy (" + peer +
                             "); response rejected";
            result.succeeded = false;
            result.body.clear();
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return result;
        }
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD err = GetLastError();
        result.message = "WinHTTP: WinHttpReceiveResponse failed, code=" + std::to_string(err);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    // HTTP статус
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status_code, &status_size, WINHTTP_NO_HEADER_INDEX);
    result.status_code = static_cast<long>(status_code);

    DWORD raw_headers_size = 0;
    if (!WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_RAW_HEADERS_CRLF,
        WINHTTP_HEADER_NAME_BY_INDEX,
        nullptr, &raw_headers_size, WINHTTP_NO_HEADER_INDEX) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && raw_headers_size > 0) {
        std::wstring raw_headers(raw_headers_size / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            WINHTTP_HEADER_NAME_BY_INDEX,
            raw_headers.data(), &raw_headers_size, WINHTTP_NO_HEADER_INDEX)) {
            while (!raw_headers.empty() && raw_headers.back() == L'\0') {
                raw_headers.pop_back();
            }
            result.response_headers = WideToUtf8(raw_headers);
        }
    }

    DWORD content_type_size = 0;
    if (!WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_CONTENT_TYPE,
        WINHTTP_HEADER_NAME_BY_INDEX,
        nullptr, &content_type_size, WINHTTP_NO_HEADER_INDEX) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && content_type_size > 0) {
        std::wstring response_content_type_w(content_type_size / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_CONTENT_TYPE,
            WINHTTP_HEADER_NAME_BY_INDEX,
            response_content_type_w.data(), &content_type_size, WINHTTP_NO_HEADER_INDEX)) {
            while (!response_content_type_w.empty() && response_content_type_w.back() == L'\0') {
                response_content_type_w.pop_back();
            }
            result.response_content_type = WideToUtf8(response_content_type_w);
        }
    }

    // Читання тіла відповіді (WP-16: з лімітом сумарного розміру).
    DWORD bytes_available = 0;
    bool response_too_large = false;
    bool read_failed = false;
    DWORD read_error_code = 0;
    for (;;) {
        bytes_available = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &bytes_available)) {
            // B-06: FALSE тут означає відмову API, а не кінець потоку. Стара
            // умова циклу (`Query(...) && bytes_available > 0`) зливала ці два
            // випадки в один: обрив зʼєднання після HTTP 200 виглядав так само,
            // як нормальне завершення, `read_failed` лишався false, і функція
            // повертала `succeeded = true` з частковим тілом. Наслідок той
            // самий, що й у С-14 нижче, лише з іншого боку: недовантажений
            // довірчий список, CRL або OCSP приходив до парсера як «повний».
            read_failed = true;
            read_error_code = GetLastError();
            break;
        }
        if (bytes_available == 0U) {
            break;  // Потік справді скінчився — єдиний випадок успішного виходу.
        }
        if (result.body.size() + static_cast<std::size_t>(bytes_available) > net::kMaxHttpResponseSize) {
            response_too_large = true;
            break;
        }
        std::vector<std::uint8_t> chunk(bytes_available);
        DWORD bytes_read = 0;
        if (!WinHttpReadData(hRequest, chunk.data(), bytes_available, &bytes_read)) {
            // С-14: раніше помилка ігнорувалася — цикл тривав, а накопичене
            // тіло поверталося як успішна відповідь. Обірваний TL XML, CRL чи
            // OCSP доходили до парсера як «повні», і користувач бачив
            // «некоректний формат документа» замість «мережа обірвалась».
            read_failed = true;
            read_error_code = GetLastError();
            break;
        }
        result.body.insert(result.body.end(), chunk.begin(), chunk.begin() + bytes_read);
    }
    if (read_failed) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        result.body.clear();
        result.succeeded = false;
        result.message = "WinHTTP: response body read failed, code=" + std::to_string(read_error_code);
        return result;
    }

    if (response_too_large) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        result.body.clear();
        result.succeeded = false;
        result.message = "WinHTTP: response exceeds the maximum allowed size";
        return result;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    result.succeeded = (result.status_code >= 200 && result.status_code < 300);
    result.message = result.succeeded ? "ok" : "HTTP status " + std::to_string(result.status_code);
    return result;
}

static HttpPostResult WinHttpRequest(const std::string& method,
                                     const std::string& url,
                                     const std::vector<std::uint8_t>& body,
                                     const std::string& content_type,
                                     const std::string& accept,
                                     std::int32_t timeout_ms) {
    std::string current_method = method;
    std::string current_url = url;
    std::vector<std::uint8_t> current_body = body;
    std::string current_content_type = content_type;
    const bool initial_https = net::ParseDestinationUrl(url).scheme == "https";
    for (long redirect = 0; redirect <= net::kMaxHttpRedirects; ++redirect) {
        const auto destination = CheckDestinationVia(current_url, false);
        if (!destination.allowed) {
            HttpPostResult denied;
            denied.message = destination.message;
            return denied;
        }
        HttpPostResult result = WinHttpRequestOnce(
            current_method, current_url, current_body, current_content_type, accept, timeout_ms);
        if (!net::IsRedirectStatus(result.status_code)) return result;
        if (redirect == net::kMaxHttpRedirects) {
            result.succeeded = false;
            result.message = "WinHTTP: too many redirects";
            return result;
        }
        const std::string location = net::ResponseHeaderValue(result.response_headers, "location");
        const std::string next_url = net::ResolveHttpRedirectUrl(current_url, location);
        const net::DestinationUrl next = net::ParseDestinationUrl(next_url);
        if (!next.valid || (initial_https && next.scheme != "https")) {
            result.succeeded = false;
            result.message = "WinHTTP: redirect destination denied";
            return result;
        }
        const auto next_destination = CheckDestinationVia(next_url, false);
        if (!next_destination.allowed) {
            result.succeeded = false;
            result.message = next_destination.message;
            return result;
        }
        if (result.status_code == 303L || ((result.status_code == 301L || result.status_code == 302L) && current_method == "POST")) {
            current_method = "GET";
            current_body.clear();
            current_content_type.clear();
        }
        current_url = next_url;
    }
    HttpPostResult unreachable;
    unreachable.message = "WinHTTP: redirect processing failed";
    return unreachable;
}

static HttpPostResult WinHttpGet(const std::string& url,
                                 const std::string& accept,
                                 std::int32_t timeout_ms) {
    return WinHttpRequest("GET", url, std::vector<std::uint8_t>{}, "", accept, timeout_ms);
}

static HttpPostResult WinHttpPost(const std::string& url,
                                  const std::vector<std::uint8_t>& body,
                                  const std::string& content_type,
                                  const std::string& accept,
                                  std::int32_t timeout_ms) {
    return WinHttpRequest("POST", url, body, content_type, accept, timeout_ms);
}

static HttpProbeResult WinHttpProbe(const std::string& url, std::int32_t timeout_ms) {
    HttpProbeResult result;
    result.attempted = true;
    // Для probe надсилаємо HEAD-подібний запит (порожній POST)
    std::vector<std::uint8_t> empty;
    auto post = WinHttpPost(url, empty, "application/octet-stream", "application/octet-stream", timeout_ms);
    result.status_code = post.status_code;
    result.succeeded   = (post.status_code >= 200 && post.status_code < 500);
    result.message     = post.message;
    return result;
}
#endif // TAMGA_WINHTTP_ENABLED

HttpPostResult ExecuteMockRequest(HttpTransport transport, HttpRequest request) {
    const bool initial_https = net::ParseDestinationUrl(request.url).scheme == "https";
    for (long redirect = 0; redirect <= net::kMaxHttpRedirects; ++redirect) {
        const auto destination = CheckDestinationVia(request.url, true);
        if (!destination.allowed) {
            HttpPostResult denied;
            denied.message = destination.message;
            return denied;
        }
        HttpPostResult result = ToPostResult(transport(request));
        if (!net::IsRedirectStatus(result.status_code)) return result;
        if (redirect == net::kMaxHttpRedirects) {
            result.succeeded = false;
            result.message = "mock HTTP transport: too many redirects";
            return result;
        }
        const std::string next_url = net::ResolveHttpRedirectUrl(
            request.url, net::ResponseHeaderValue(result.response_headers, "location"));
        const net::DestinationUrl next = net::ParseDestinationUrl(next_url);
        if (!next.valid || (initial_https && next.scheme != "https")) {
            result.succeeded = false;
            result.message = "mock HTTP transport: redirect destination denied";
            return result;
        }
        if (result.status_code == 303L ||
            ((result.status_code == 301L || result.status_code == 302L) && request.method == "POST")) {
            request.method = "GET";
            request.body.clear();
            request.content_type.clear();
        }
        request.url = next_url;
    }
    HttpPostResult unreachable;
    unreachable.message = "mock HTTP transport: redirect processing failed";
    return unreachable;
}

// ═══════════════════════════════════════════════════════════════════════════
// HttpClient::ProbeEndpoint
// ═══════════════════════════════════════════════════════════════════════════
HttpProbeResult HttpClient::ProbeEndpoint(const std::string& url, const std::int32_t timeout_ms) {
    HttpProbeResult result;
    const auto destination = CheckDestinationVia(url, false);
    if (!destination.allowed) {
        result.message = destination.message;
        return result;
    }
    result.attempted = true;

#if TAMGA_LIBCURL_ENABLED
    static std::once_flag curl_global_once;
    static CURLcode curl_global_rc = CURLE_OK;
    std::call_once(curl_global_once, []() {
        curl_global_rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    });
    if (curl_global_rc != CURLE_OK) {
        result.message = "curl_global_init failed";
        return result;
    }

    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        result.message = "curl_easy_init failed";
        return result;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    ApplyCurlSecurityHardening(curl);
    ApplyCurlDestinationGuard(curl);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    const CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        result.message = curl_easy_strerror(rc);
        curl_easy_cleanup(curl);
        return result;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status_code);
    result.succeeded = result.status_code >= 200L && result.status_code < 500L;
    result.message = result.succeeded ? "ok" : "unexpected HTTP status";
    curl_easy_cleanup(curl);

#elif TAMGA_WINHTTP_ENABLED
    result = WinHttpProbe(url, timeout_ms);

#else
    (void)url;
    (void)timeout_ms;
    result.message = "No HTTP backend available (no libcurl, no WinHTTP)";
#endif

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// HttpClient::Get / HttpClient::Post
// ═══════════════════════════════════════════════════════════════════════════
#if TAMGA_LIBCURL_ENABLED
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    auto* mem = static_cast<std::vector<std::uint8_t>*>(userp);
    // WP-16: перериваємо завантаження, якщо відповідь перевищує ліміт (захист
    // від memory-DoS через велетенський CRL/OCSP). Повернення != realsize
    // сигналізує curl про помилку і зупиняє передачу.
    if (mem->size() > net::kMaxHttpResponseSize || realsize > net::kMaxHttpResponseSize - mem->size()) {
        return 0;
    }
    mem->insert(mem->end(), static_cast<uint8_t*>(contents),
                static_cast<uint8_t*>(contents) + realsize);
    return realsize;
}

static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    const size_t realsize = size * nitems;
    auto* headers = static_cast<std::string*>(userdata);
    headers->append(buffer, realsize);
    return realsize;
}
#endif

HttpPostResult HttpClient::Get(const std::string& url,
                               const std::string& accept,
                               const std::int32_t timeout_ms) {
    HttpPostResult result;

    HttpTransport mock_transport;
    {
        std::lock_guard<std::mutex> lock(g_mock_transport_mutex);
        mock_transport = g_mock_transport;
    }
    const auto destination = CheckDestinationVia(url, static_cast<bool>(mock_transport));
    if (!destination.allowed) {
        result.message = destination.message;
        return result;
    }
    result.attempted = true;
    if (mock_transport) {
        HttpRequest request;
        request.method = "GET";
        request.url = url;
        request.accept = accept;
        request.timeout_ms = timeout_ms;
        return ExecuteMockRequest(std::move(mock_transport), std::move(request));
    }

#if TAMGA_LIBCURL_ENABLED
    static std::once_flag curl_global_once;
    static CURLcode curl_global_rc = CURLE_OK;
    std::call_once(curl_global_once, []() {
        curl_global_rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    });
    if (curl_global_rc != CURLE_OK) {
        result.message = "curl_global_init failed";
        return result;
    }

    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        result.message = "curl_easy_init failed";
        return result;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    struct curl_slist* headers = nullptr;
    std::string accept_header = "Accept: " + accept;
    headers = curl_slist_append(headers, accept_header.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &result.response_headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    ApplyCurlSecurityHardening(curl);
    ApplyCurlDestinationGuard(curl);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    const CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (rc != CURLE_OK) {
        result.message = curl_easy_strerror(rc);
        curl_easy_cleanup(curl);
        return result;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status_code);
    char* response_content_type = nullptr;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &response_content_type);
    if (response_content_type != nullptr) {
        result.response_content_type = response_content_type;
    }
    result.succeeded = result.status_code >= 200L && result.status_code < 300L;
    result.message = result.succeeded ? "ok" : "unexpected HTTP status";
    curl_easy_cleanup(curl);

#elif TAMGA_WINHTTP_ENABLED
    result = WinHttpGet(url, accept, timeout_ms);

#else
    (void)url;
    (void)accept;
    (void)timeout_ms;
    result.message = "No HTTP backend available (no libcurl, no WinHTTP)";
#endif

    return result;
}

HttpPostResult HttpClient::Post(const std::string& url,
                                 const std::vector<std::uint8_t>& request_body,
                                 const std::string& content_type,
                                 const std::string& accept,
                                 const std::int32_t timeout_ms) {
    HttpPostResult result;

    HttpTransport mock_transport;
    {
        std::lock_guard<std::mutex> lock(g_mock_transport_mutex);
        mock_transport = g_mock_transport;
    }
    const auto destination = CheckDestinationVia(url, static_cast<bool>(mock_transport));
    if (!destination.allowed) {
        result.message = destination.message;
        return result;
    }
    result.attempted = true;
    if (mock_transport) {
        HttpRequest request;
        request.method = "POST";
        request.url = url;
        request.body = request_body;
        request.content_type = content_type;
        request.accept = accept;
        request.timeout_ms = timeout_ms;
        return ExecuteMockRequest(std::move(mock_transport), std::move(request));
    }

#if TAMGA_LIBCURL_ENABLED
    static std::once_flag curl_global_once;
    static CURLcode curl_global_rc = CURLE_OK;
    std::call_once(curl_global_once, []() {
        curl_global_rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    });
    if (curl_global_rc != CURLE_OK) {
        result.message = "curl_global_init failed";
        return result;
    }

    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        result.message = "curl_easy_init failed";
        return result;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request_body.size()));

    struct curl_slist* headers = nullptr;
    std::string ct_header = "Content-Type: " + content_type;
    std::string accept_header = "Accept: " + accept;
    headers = curl_slist_append(headers, ct_header.c_str());
    headers = curl_slist_append(headers, accept_header.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &result.response_headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    ApplyCurlSecurityHardening(curl);
    ApplyCurlDestinationGuard(curl);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    const CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (rc != CURLE_OK) {
        result.message = curl_easy_strerror(rc);
        curl_easy_cleanup(curl);
        return result;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status_code);
    char* response_content_type = nullptr;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &response_content_type);
    if (response_content_type != nullptr) {
        result.response_content_type = response_content_type;
    }
    result.succeeded = result.status_code >= 200L && result.status_code < 300L;
    result.message = result.succeeded ? "ok" : "unexpected HTTP status";
    curl_easy_cleanup(curl);

#elif TAMGA_WINHTTP_ENABLED
    result = WinHttpPost(url, request_body, content_type, accept, timeout_ms);

#else
    (void)url;
    (void)request_body;
    (void)content_type;
    (void)timeout_ms;
    result.message = "No HTTP backend available (no libcurl, no WinHTTP)";
#endif

    return result;
}

HttpPostResult HttpClient::Post(const std::string& url,
                                const std::vector<std::uint8_t>& request_body,
                                const std::string& content_type,
                                const std::int32_t timeout_ms) {
    return Post(url, request_body, content_type, "application/timestamp-reply", timeout_ms);
}

} // namespace tamga::core
