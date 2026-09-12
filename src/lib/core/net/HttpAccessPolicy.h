#pragma once

// Політика мережевого доступу: рішення, чи ДОЗВОЛЕНО звертатися за адресою.
//
// Навіщо окремий модуль (п.18 плану аудиту). Раніше вся ця логіка жила в
// анонімному просторі імен `HttpClient.cpp` разом із транспортом WinHTTP.
// Наслідок був не косметичний: найчутливіша до безпеки частина — захист від
// SSRF — перевірялася лише опосередковано, через справжній HTTP-клієнт, а
// отже кожна перевірка тягла за собою транспорт, мок-семи і глобальний стан.
// Саме в такій конфігурації і виник П-08: два місця застосування одного
// класифікатора розійшлися полярністю, і жоден тест цього не показав, бо
// прямо викликати класифікатор було нізвідки.
//
// Тут немає ані WinHTTP, ані libcurl, ані глобальних змінних. Резолвер імен
// передається параметром — це і робить політику перевірюваною без мережі.

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "core/HttpClient.h"

namespace tamga::core::net {

// WP-16: URL-и OCSP/CRL/AIA/TSP надходять із полів сертифіката (під контролем
// видавця або зловмисника), тож обмеження мають бути частиною політики, а не
// налаштуванням транспорту.
inline constexpr std::size_t kMaxHttpResponseSize = 64u * 1024u * 1024u;  // 64 MiB
inline constexpr long kMaxHttpRedirects = 5;

// Розібраний пункт призначення. `valid == false` означає, що URL не є
// придатним HTTP(S)-посиланням — далі політика не розглядає його взагалі.
struct DestinationUrl {
    std::string scheme;
    std::string host;
    bool valid{false};
};

// Три стани, а не два. Саме тритактність тут суттєва: `NotAnIp` — це не
// «дозволено» і не «заборонено», а «це не адреса, питання вирішується далі».
// Змішування `NotAnIp` із дозволом і було дефектом П-08.
enum class IpClassification { NotAnIp, Public, Blocked };

std::string LowerAscii(std::string value);

DestinationUrl ParseDestinationUrl(const std::string& url);

IpClassification ClassifyIpAddress(const std::string& text);

bool IsBlockedHostname(const std::string& host);

// Єдиний предикат для ОБОХ точок застосування (адреси з DNS і фактична
// peer-адреса з'єднання) оголошений як `tamga::core::detail::IsAllowedPublicAddress`
// у `core/HttpClient.h` і ВИЗНАЧЕНИЙ у `HttpAccessPolicy.cpp`. Ім'я лишилося
// на місці навмисно: воно вже є частиною контракту, на нього спираються тести,
// а перенести визначення й водночас перейменувати означало б у тому самому
// коміті і рухати код, і міняти контракт. Дублювати цю умову деінде не можна:
// саме розходження двох копій дало П-08.

// Резолвер імені у список текстових адрес — той самий тип, що вже несе
// мок-сему `ScopedMockResolver`. Політика не знає, чи це системний DNS, чи
// підміна з тесту, і не повинна знати.

// Повний вердикт щодо призначення.
//
// `treat_missing_resolver_as_allowed` зберігає наявну поведінку детермінованих
// мок-тестів, які не залежать від живого DNS; у продуктивному шляху — `false`.
HttpDestinationResult CheckDestination(const std::string& url,
                                       const HttpHostResolver& resolver,
                                       bool treat_missing_resolver_as_allowed);

}  // namespace tamga::core::net
