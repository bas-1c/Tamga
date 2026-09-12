#pragma once

// Розбір і форматування X.509-імен над СИРИМ DER — одна реалізація (ADR-027).
//
// Чому цей модуль не в `core/cryptonite`: увесь `cryptonite/Names.cpp` стоїть
// під `#if TAMGA_CRYPTONITE_ENABLED`, а `Session` мусить форматувати DN і в
// діагностичній збірці `vendor=OFF`. Саме через це в `SessionHelpers.ipp`
// свого часу зʼявився переписаний `Names.cpp` — п'ять функцій. Тут лежить та
// їх частина, що працює з байтами й не потребує ASN.1-структур cryptonite.
//
// Розбіжності, знайдені при зведенні (усі три копії різнилися):
//
//   * `LookupOidShortName` мав ТРИ несумісні таблиці OID, і кожна була
//     неповною по-своєму. У cryptonite були українські `DRFO` і `EDRPOU`,
//     але не було `L`, `ST`, `STREET`. У `SessionHelpers` — навпаки: двадцять
//     стандартних атрибутів X.500 і ЖОДНОГО українського, тобто ДРФО та
//     ЄДРПОУ показувались користувачу сирим OID у шістнадцятковому вигляді.
//     Третя таблиця (`OidShortName` у `CertificateChainValidator`) знала ще
//     `2.5.4.97`. Той самий сертифікат отримував три різні DN залежно від
//     шляху. Тут таблиця обʼєднана: конфліктів між ними не було, лише
//     прогалини.
//
//   * `ExtractDerStringValue` у `SessionHelpers` містив ту саму вразливу форму
//     перевірки меж, що й С-06, і працював із сирими байтами сертифіката —
//     без захисту інваріантом ASN.1-декодера. Тут використовується спільний
//     `util::ParseTlvAt`.

#include <cstddef>
#include <cstdint>
#include <string>

namespace tamga::util {

// Коротке ім'я атрибута за OID у крапковій формі ("2.5.4.3" -> "CN");
// nullptr для невідомих — тоді значення виводиться як `oid=#<hex>`.
const char* LookupOidShortName(const std::string& dotted_oid);

// Екранування значення атрибута за RFC 4514.
std::string EscapeRfc4514(const std::string& value);

// OID із сирого DER-вмісту (без тега й довжини) у крапкову форму.
std::string OidToString(const std::uint8_t* data, std::size_t size);

// Значення атрибута: DirectoryString у будь-якому з очікуваних кодувань.
// `offset` — початок TLV, `limit` — межа, за яку виходити не можна.
// Некоректне кодування дає порожній рядок, а не читання за межами буфера.
std::string ExtractDerStringValue(const std::uint8_t* data, std::size_t offset,
                                  std::size_t limit);

// RDNSequence (вміст SEQUENCE, без зовнішнього тега) у рядок RFC 4514.
std::string FormatRdnSequence(const std::uint8_t* data, std::size_t size);

} // namespace tamga::util
