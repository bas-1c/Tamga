#pragma once

// Перетворення ASN.1 GeneralizedTime у ISO-8601 — одне на весь проєкт
// (ADR-027).
//
// Копії жили в `policy/TimestampValidator` і `validation/TimestampEngine`.
// Тіла відрізнялися лише розкладкою (одна писала через проміжні змінні, друга
// одним виразом), поведінка — та сама. Обидва модулі описують ОДИН і той
// самий момент часу з одного й того ж токена TSA, тож і формат мусить бути
// один: розбіжність тут проявилася б як два різні `signingTime` в одному
// звіті.

#include <string>

namespace tamga::util {

// `YYYYMMDDHHMMSS[...]` -> `YYYY-MM-DDTHH:MM:SSZ`.
//
// Вхід, коротший за 14 символів, або той, що вже містить `-`, повертається без
// змін: він або не GeneralizedTime, або вже у потрібному вигляді. Мовчазне
// повернення тут доречне — це форматування для показу, а не перевірка.
std::string FormatAsIso8601(const std::string& generalized_time);

} // namespace tamga::util
