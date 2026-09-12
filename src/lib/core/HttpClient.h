#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace tamga::core {

struct HttpRequest {
    std::string method;
    std::string url;
    std::vector<std::uint8_t> body;
    std::string content_type;
    std::string accept;
    std::int32_t timeout_ms{10000};
};

struct HttpResponse {
    bool succeeded{false};
    long status_code{0};
    std::vector<std::uint8_t> body;
    std::string message;
    std::string response_headers;
};

using HttpTransport = std::function<HttpResponse(const HttpRequest&)>;
using HttpHostResolver = std::function<std::vector<std::string>(const std::string& host)>;

struct HttpDestinationResult {
    bool allowed{false};
    std::string message;
    std::vector<std::string> resolved_addresses;
};

struct HttpProbeResult {
    bool attempted{false};
    bool succeeded{false};
    long status_code{0};
    std::string message;
};

struct HttpPostResult {
    bool attempted{false};
    bool succeeded{false};
    long status_code{0};
    std::string message;
    std::string response_content_type;
    std::string response_headers;
    // П-17 (закриває Н-03): тіло відповіді має РІВНО ОДНЕ поле.
    //
    // Раніше тут лежала пара `body` + `response_body` з тим самим вмістом:
    // WinHTTP/curl-шляхи наповнювали `response_body`, копіювали його в `body`
    // перед поверненням, а споживачі читали `body`. Аудит (Н-03) визнав це
    // боргом чистоти, а не дефектом, — і на рівні коректності це правда.
    // Ціна, однак, була не косметична: при дозволеному ліміті відповіді
    // 64 МіБ копія давала до ПОДВІЙНОГО пікового споживання пам'яті на кожен
    // завантажений CRL чи бандл сертифікатів.
    //
    // `HttpPostResult` — внутрішній тип бібліотеки: він не оголошений у
    // `include/tamga/tamga_c_api.h` і не входить до жодного встановлюваного
    // заголовка (`install(FILES include/tamga/tamga_c_api.h ...)`), тож
    // прибирання поля не зачіпає публічний C ABI.
    std::vector<std::uint8_t> body;
};

// ADR-027: 2xx і `succeeded` — один критерій «запит вдався» на весь проєкт.
// Копії жили в `policy/AiaIssuerFetcher` і `policy/TrustListSync`; тіла
// збігалися. Предикат належить типу, а не модулям, які його читають.
inline bool IsHttpSuccess(const HttpPostResult& response) {
    return response.succeeded && response.status_code >= 200L && response.status_code < 300L;
}

namespace detail {

// П-08: сім, який робить перевірку фактичної peer-адреси зʼєднання
// тестованою без живої мережі.
//
// Класифікатор адрес має ТРИ стани (не IP / публічна / заблокована), і саме
// на цьому раніше розійшлися дві точки застосування: перевірка призначення
// вимагала `== Public` (тобто «не IP» — заборонено), а перевірка фактичної
// адреси зʼєднання питала `!= Blocked` (тобто «не IP» — ДОЗВОЛЕНО). Один
// класифікатор із протилежним замовчуванням у двох місцях — це не оптимізація,
// а дірка: усе, що не розпізналося як IP, проходило.
//
// Тут закріплено один-єдиний контракт: дозволено рівно те, що класифіковано
// як публічна адреса. Порожній рядок, ім'я хоста, обрізаний або невідомий
// формат — відмова (fail-closed).
//
// Реалізація доступна на всіх платформах, хоча споживач (WinHTTP-шлях) —
// лише Windows. Це навмисно: інакше правило неможливо було б перевірити
// тестом у конфігураціях без WinHTTP.
bool IsAllowedPublicAddress(const std::string& peer_address_text);

} // namespace detail

class HttpClient final {
public:
    class ScopedMockTransport final {
    public:
        explicit ScopedMockTransport(HttpTransport transport);
        ~ScopedMockTransport();
        ScopedMockTransport(const ScopedMockTransport&) = delete;
        ScopedMockTransport& operator=(const ScopedMockTransport&) = delete;

    private:
        HttpTransport previous_;
    };

    // Детермінований DNS seam для regression-тестів destination policy.
    // Production-виклики використовують системний resolver і перевіряють усі
    // отримані A/AAAA адреси до відкриття з'єднання.
    class ScopedMockResolver final {
    public:
        explicit ScopedMockResolver(HttpHostResolver resolver);
        ~ScopedMockResolver();
        ScopedMockResolver(const ScopedMockResolver&) = delete;
        ScopedMockResolver& operator=(const ScopedMockResolver&) = delete;

    private:
        HttpHostResolver previous_;
    };

    static HttpDestinationResult CheckDestination(const std::string& url);

    static HttpProbeResult ProbeEndpoint(const std::string& url, std::int32_t timeout_ms);
    static HttpPostResult Get(const std::string& url,
                              const std::string& accept,
                              std::int32_t timeout_ms);
    static HttpPostResult Post(const std::string& url,
                               const std::vector<std::uint8_t>& request_body,
                               const std::string& content_type,
                               const std::string& accept,
                               std::int32_t timeout_ms);
    static HttpPostResult Post(const std::string& url,
                               const std::vector<std::uint8_t>& request_body,
                               const std::string& content_type,
                               std::int32_t timeout_ms);
};

} // namespace tamga::core
