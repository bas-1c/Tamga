#pragma once

// Розбір HTTP-повідомлення: заголовки і побудова URL редиректу.
//
// Ці функції не роблять запитів і не знають про транспорт. Вони жили в
// анонімному просторі імен `HttpClient.cpp` і були неперевірюваними — хоча
// саме тут вирішується, КУДИ піде наступний запит після `3xx`. Розбір
// відносного `Location` — класичне місце для обходу перевірки призначення,
// і він заслуговує на прямі тести, а не на перевірку через живий клієнт.

#include <string>

namespace tamga::core::net {

// Значення заголовка за іменем без урахування регістру; порожній рядок, якщо
// заголовка немає.
std::string ResponseHeaderValue(const std::string& headers, const std::string& requested_name);

// Абсолютний URL наступного кроку за базовим URL і полем `Location`.
// Порожній рядок означає, що побудувати URL не вдалося — і це відмова, а не
// «йдемо за початковою адресою».
std::string ResolveHttpRedirectUrl(const std::string& base, const std::string& location);

bool IsRedirectStatus(long status);

}  // namespace tamga::core::net
