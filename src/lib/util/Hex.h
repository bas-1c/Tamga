#pragma once

// Шістнадцяткове кодування — одне на весь проєкт (ADR-027).
//
// До консолідації `HexEncode` існував у **пʼяти** визначеннях:
// `cryptonite/Internal.h`, `policy/CertificateChainValidator.cpp` (дві
// перевантаження), `session/SessionHelpers.ipp` і
// `xmldsig/XmlSignatureVerifier.cpp`. Усі семантично тотожні — просто жодна не
// була доступна ззовні свого файлу, тож кожен модуль писав свою.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tamga::util {

// Нижній регістр, по два символи на байт, без роздільників.
std::string HexEncode(const std::uint8_t* data, std::size_t size);
std::string HexEncode(const std::vector<std::uint8_t>& data);

// 64-бітове число у шістнадцятковий рядок. Копії жили в
// `policy/AiaIssuerFetcher` і `policy/PolicyCache`; тіла збігалися.
std::string HexFromUInt64(std::uint64_t value);

// Стабільний нерозподілений відбиток байтів (FNV-1a, 64 біти) у hex.
// НЕ криптографічний хеш: використовується як ключ кешу й ідентифікатор
// доказу, де потрібна лише відтворюваність між запусками. Копії жили в
// `policy/AiaIssuerFetcher` і `policy/PolicyCache`; тіла збігалися
// побайтово.
std::string StableDerHash(const std::vector<std::uint8_t>& data);

} // namespace tamga::util
