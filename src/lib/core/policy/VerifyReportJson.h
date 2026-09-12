#pragma once

// Хвиля 8, п.1 (залишок): ЄДИНЕ джерело ФОРМИ обох звітів.
//
// `VerifyChecks.h` уже звів до одного місця *вердикти* — `status`/`code`
// кожного блоку (ADR-026). Але сама розмітка JSON лишалася в двох місцях:
// `policy::UserReportBuilder::Build` і `Session::GetLastVerifyReport`
// у `core/session/SessionCertificateOps.ipp`. Обидва писали
// `"trust":{...}`, `"revocation":{...}`, `"timestamp":{...}`, `"ltv":{...}`
// посимвольно однаково — і залишалися однаковими лише тому, що кожну правку
// (ME-02, HI-02, WP-3) хтось щоразу вносив двічі.
//
// Це той самий механізм, який ADR-027 назвав причиною копій: спільна річ
// живе в анонімному namespace всередині .cpp/.ipp, ззовні недосяжна, тож
// коли вона потрібна в другому місці — її пишуть заново. Тут вона винесена
// назовні й має ім'я.
//
// Що НЕ уніфіковано і чому. Звіти лишаються двома різними проєкціями:
//   * користувацький додає дані підписувача і двомовні повідомлення;
//   * технічний додає `validatedProfile`, `qualifyingPropertiesPresent`,
//     `signaturePolicy`, `dataObjectFormats`, `signatures[]` і повну
//     діагностику.
// Ці відмінності свідомі, тому вони не сховані за прапорцем «режим», а
// виражені типами: секція приймає структуру додаткових полів, і те, чого в
// ній немає, просто не емітується. Відмінність лишається видимою на місці
// виклику, а не розчиняється в спільному коді.

#include <sstream>
#include <string>

#include "core/CryptoniteAdapter.h"
#include "core/Session.h"
#include "core/policy/VerifyChecks.h"

namespace tamga::core::policy {

// Чи додавати до кожного блоку двомовне поле `message`. Користувацький звіт
// його має, технічний — ні: там код вердикту читає програма, а не людина.
enum class MessageStyle { None, Bilingual };

// Порожні значення означають «не підставляти нічого». Користувацький звіт
// підставляє формат і тип контейнера, виведені з імені операції, коли сам
// звіт їх не містить; технічний передає порожні й отримує ту саму поведінку,
// що й раніше.
struct FormatFallbacks final {
    std::string signature_format;
    std::string container_type;
};

// Додаткові поля секції `signature`. nullptr — поле не емітується.
struct SignatureSectionExtras final {
    const std::string* validated_profile = nullptr;  // лише технічний звіт
};

// Додаткові поля секції `certificate`. nullptr — поле не емітується.
struct CertificateSectionExtras final {
    const bool* qualifying_properties_present = nullptr;  // лише технічний
    const CertificateMetadata* signer_metadata = nullptr;  // лише користувацький
};

// --- двомовні повідомлення -------------------------------------------------

// Повертає пару {en, uk} для коду вердикту або попередження. Невідомий код
// дає нейтральне «перевірку не виконано» — мовчазний fallback тут доречний,
// бо код уже прийшов із `VerifyChecks`, тобто з закритого переліку.
std::pair<const char*, const char*> MessageForCode(const std::string& code);

// --- блоки звіту -----------------------------------------------------------
//
// Кожна функція пише ПОВНУ секцію разом з іменем, дужками і комою після неї.
// Виклик у потрібному порядку — і є схема звіту.

void WriteCheckFields(std::ostringstream& json, const VerifyCheck& check, MessageStyle style);

void WriteSummarySection(std::ostringstream& json, const VerifyReport& report, MessageStyle style);

void WriteSignatureSection(std::ostringstream& json, const VerifyReport& report,
                           const FormatFallbacks& fallbacks, const SignatureSectionExtras& extras,
                           MessageStyle style);

void WriteCertificateSection(std::ostringstream& json, const VerifyReport& report,
                             const CertificateSectionExtras& extras, MessageStyle style);

void WriteTrustSection(std::ostringstream& json, const VerifyReport& report, MessageStyle style);

void WriteRevocationSection(std::ostringstream& json, const VerifyReport& report, MessageStyle style);

void WriteTimestampSection(std::ostringstream& json, const VerifyReport& report, MessageStyle style);
void WriteTimestampDetails(std::ostringstream& json, const std::vector<TimestampEntry>& details);

void WriteLtvSection(std::ostringstream& json, const VerifyReport& report, MessageStyle style);

// Перелік попереджень — один на обидва звіти. Раніше він був у двох копіях,
// які відрізнялися лише наявністю `message`: додане в одну попередження не
// з'явилося б у другій.
void WritePolicySection(std::ostringstream& json, const VerifyReport& report, MessageStyle style);

// Спільний початок секції `diagnostics`: ім'я, дужка і поля, які є в обох
// звітах. Кому після себе НЕ пише — далі кожен звіт додає своє й закриває
// секцію сам.
void WriteDiagnosticsPrefix(std::ostringstream& json, const VerifyReport& report,
                            const FormatFallbacks& fallbacks);

// Спільний початок блоку `diagnostics.flags`. Так само не закривається.
void WriteDiagnosticsFlagsPrefix(std::ostringstream& json, const VerifyReport& report);

const char* ErrorCodeName(ErrorCode code);

} // namespace tamga::core::policy
