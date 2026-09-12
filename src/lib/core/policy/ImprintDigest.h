#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace tamga::core {

enum class ImprintDigest {
    Kupyna256,
    Gost34311,
    Sha256,
    Sha384,
    Sha512
};

struct ImprintResult {
    std::string digest_oid;
    std::vector<std::uint8_t> hash;
};

// OID-и:
//   Kupyna-256  = "1.2.804.2.1.1.1.1.2.2.1"
//   GOST 34.311 = "1.2.804.2.1.1.1.1.2.1"
//   SHA-256     = "2.16.840.1.101.3.4.2.1"
//   SHA-384     = "2.16.840.1.101.3.4.2.2"
//   SHA-512     = "2.16.840.1.101.3.4.2.3"

// Обчислює хеш Kupyna-256 (ДСТУ 7564, SBOX_1, довжина виходу 32 байти) через
// cryptonite. Раніше ця функція існувала окремими ідентичними копіями в
// анонімних namespace ImprintDigest.cpp і TimestampValidator.cpp (O-06 аудиту):
// зміна параметрів Купини (sbox, довжина) вимагала синхронної правки у двох
// місцях, що було реальним ризиком розходження. Тепер це єдина спільна
// реалізація; TimestampValidator використовує саме її.
// Повертає false, якщо cryptonite вимкнено в збірці (TAMGA_ENABLE_VENDOR_CRYPTONITE=OFF).
bool ComputeKupyna256(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& out_hash);

// Обчислює імпринт за вибраним алгоритмом.
// Повертає false, якщо алгоритм недоступний у поточній збірці (наприклад, якщо cryptonite вимкнено).
bool ComputeImprint(ImprintDigest alg,
                    const std::vector<std::uint8_t>& data,
                    ImprintResult& out,
                    std::string& error_message);

// Обчислює імпринт за явно заданим алгоритмом. Для параметризованого ГОСТ
// cryptonite-адаптер може взяти DKE/sbox із сертифіката, але лише якщо його
// фактичний digest algorithm збігається з fallback_alg. Сертифікат із Купиною
// більше не може непомітно підмінити оголошений у XMLDSIG ГОСТ і створити
// хибнопозитивний локальний round-trip.
bool ComputeImprintByCertificate(const std::vector<std::uint8_t>& certificate_der,
                                 ImprintDigest fallback_alg,
                                 const std::vector<std::uint8_t>& data,
                                 ImprintResult& out,
                                 std::string& error_message);

// Мапінг OID підпису/гешу → ImprintDigest. Невідомий OID → std::nullopt.
std::optional<ImprintDigest> ImprintFromDigestOid(const std::string& digest_oid);

} // namespace tamga::core
