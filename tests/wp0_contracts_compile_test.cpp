// WP-0 contract compile-guard.
//
// Доводить DoD WP-0: заморожені контракти-headers самодостатні й компілюються
// (хай і зі стабами реалізації), тож паралельні WP можуть на них спиратися.
// Перевіряє лише форму типів — реалізацію функцій не лінкуємо (вони ще стаби).

#include <cstdint>
#include <optional>
#include <type_traits>
#include <vector>

#include "core/policy/TimestampValidationContext.h"
#include "core/validation/ValidationReportProjection.h"
#include "xmldsig/SignatureContext.h"
#include "xmldsig/XmlAlgorithmRegistry.h"

namespace {

static_assert(std::is_default_constructible<tamga::xmldsig::SignatureContext>::value,
              "SignatureContext must be a default-constructible data contract");
static_assert(std::is_default_constructible<tamga::core::policy::TimestampValidationContext>::value,
              "TimestampValidationContext must be a default-constructible data contract");

// Реєстр алгоритмів — enum-форма зафіксована.
static_assert(static_cast<int>(tamga::xmldsig::DigestAlg::Kupyna256) >= 0, "DigestAlg frozen");
static_assert(static_cast<int>(tamga::xmldsig::SignatureAlg::Dstu4145WithKupyna) >= 0, "SignatureAlg frozen");

}  // namespace

int main() {
    // hash_algorithm_oid — обовʼязкове поле контракту TSA-валідації.
    tamga::core::policy::TimestampValidationContext ts_ctx;
    ts_ctx.hash_algorithm_oid = "1.2.804.2.1.1.1.1.2.2.1";  // Kupyna-256
    (void)ts_ctx.require_trusted_tsa;

    tamga::xmldsig::SignatureContext sig_ctx;
    sig_ctx.signature_index = 0;
    (void)sig_ctx.has_duplicate_ids;

    // Звертаємось до сигнатури проєкції лише в decltype-контексті: функція ще
    // стаб (реалізація — WP-11), тож її НЕ ODR-використовуємо.
    using ProjectFn = decltype(&tamga::core::ProjectVerifyReport);
    static_assert(std::is_pointer<ProjectFn>::value, "ProjectVerifyReport signature frozen");

    return 0;
}
