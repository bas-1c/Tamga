#ifndef TAMGA_CORE_POLICY_CRL_CACHE_H
#define TAMGA_CORE_POLICY_CRL_CACHE_H

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace tamga::core::policy {

// Дефолтний best-effort timeout завантаження CRL за CDP-URL (мс).
constexpr std::int32_t kDefaultCrlFetchTimeoutMs = 10000;

// Витягує CDP-URL (що завершуються на ".crl") із DER-сертифіката.
std::vector<std::string> ExtractCrlDistributionUrls(const std::vector<std::uint8_t>& cert_der);

// Перевіряє, чи є байти повним і валідним ASN.1 DER CRL (без обривів і з коректним синтаксисом).
bool IsValidCrlDer(const std::vector<std::uint8_t>& crl_der);

// true, якщо видавець CRL відповідає видавцю сертифіката (issuer DN match).
bool CrlMatchesCertificate(const std::vector<std::uint8_t>& crl_der,
                           const std::vector<std::uint8_t>& cert_der);

// true, якщо закешований CRL ще чинний на момент `now` (nextUpdate > now).
// Порожній/нерозбірливий CRL вважається нечинним (потребує перезавантаження).
bool IsCachedCrlFresh(const std::vector<std::uint8_t>& crl_der, std::time_t now);

// Завантажує і кешує CRL для всіх CDP-URL сертифіката у <work_dir>/crl-store/.
// Мережевий запит виконується лише для відсутніх або прострочених (за nextUpdate)
// кеш-файлів. Безпечно для порожніх аргументів (no-op). Неповні/пошкоджені не кешуються.
void DownloadAndCacheCrlsForCert(const std::vector<std::uint8_t>& cert_der,
                                 const std::string& work_dir,
                                 std::int32_t timeout_ms = kDefaultCrlFetchTimeoutMs);

// Зчитує всі DER-файли CRL із директорій crl-store/ та crls/ у work_dir.
void LoadCrlsFromWorkDir(const std::string& work_dir,
                         std::vector<std::vector<std::uint8_t>>& crls);

// Зчитує лише валідні CRL з work_dir, чий видавець відповідає хоча б одному сертифікату з certs.
void LoadMatchingCrlsFromWorkDir(const std::string& work_dir,
                                 const std::vector<std::vector<std::uint8_t>>& certs,
                                 std::vector<std::vector<std::uint8_t>>& crls);

} // namespace tamga::core::policy

#endif // TAMGA_CORE_POLICY_CRL_CACHE_H
