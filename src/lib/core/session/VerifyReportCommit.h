#pragma once

#include <string>

#include "core/Errors.h"
#include "core/Session.h"

namespace tamga::core {

// ADR-033: шар «коміт звіту» — ділянка, де вердикт потрапляє у `VerifyReport`.
//
// Донедавна ця ділянка жила в анонімному namespace `SessionHelpers.ipp` і в
// приватних методах `Session`. Ззовні її не було видно, тож перевірити її
// можна було лише опосередковано — через повний Verify* із ключем, файлом і
// (для мітки часу) мережею. Саме тут сталися чотири дефекти цього циклу
// (К-01, П-02, П-03, FND-015/ADR-029), і всі одного роду: один шлях присвоює
// поле, сусідній забуває.
//
// Тут — лише чисті функції над `VerifyReport`/`SignatureEntry`. Ані стану
// сесії, ані мутекса, ані вводу-виводу: на вхід факти, на вихід звіт.

// Початковий стан звіту перед будь-яким комітом. Три поля мають НЕ порожні
// значення за замовчуванням, і ці значення — частина контракту `GetReport()`.
VerifyReport MakeClearedVerifyReport();

// Факти, з яких складається коміт.
struct VerifyOutcome {
    std::string operation;
    bool execution_succeeded{false};
    bool signature_valid{false};
    ErrorCode error_code{ErrorCode::None};
    std::string message;
};

// Записує факти в очищений звіт. Викликач відповідає за те, щоб `report`
// прийшов уже з `MakeClearedVerifyReport()`: коміт нічого не доочищає, бо
// доочищення в цьому місці й було коренем «сусідній шлях забув поле».
void CommitVerifyOutcome(VerifyReport& report, VerifyOutcome outcome);

// С-08: текст за замовчуванням для `VerifyReport::message`. Порожній
// `message` означає «своєї причини немає» — тоді підставляється формулювання,
// що НЕ перебільшує і НЕ применшує доведеного.
std::string BuildVerifyMessage(bool execution_succeeded, bool signature_valid, std::string message);

// В-03: форматні шляхи (PAdES, XAdES, ASiC) перевіряють RFC 3161 токен ЛИШЕ
// криптографічно — `ValidateTimestampToken` звіряє messageImprint і підпис
// TSA, але не будує ланцюг сертифіката TSA, не перевіряє EKU
// `id-kp-timeStamping` і не з'ясовує відкликання. Подавати такий результат як
// `timestamp-valid` означає стверджувати більше, ніж доведено: коректно
// підписаний токен від НЕДОВІРЕНОЇ TSA виглядав як повністю дійсна мітка часу
// (спостережено у звіті одночасно з `trustStatus=trust-store-empty`).
//
// `canonical_full` — чи встиг канонічний `TimestampEngine` (через
// `ValidationReportProjection`) підтвердити повну валідність. Його вердикт
// сильніший і не понижується; форматний шлях може лише не підвищувати свій.
void ApplyFormatTimestampVerdict(VerifyReport& report, bool crypto_valid, bool canonical_full);

// Агрегує всі наявні канонічні результати: invalid має пріоритет над partial.
void ApplyTimestampDetailsVerdict(VerifyReport& report);

// В-03 (per-signature): той самий висновок для записів `signatures[]`.
// Без цього мультипідписний звіт лишався суперечливим — верхньорівневе поле
// казало `timestamp-partial`, а кожен окремий запис поруч і далі стверджував
// `timestamp-valid`, тобто саме те, що виправлення й прибирає.
void ApplyEntryTimestampVerdict(SignatureEntry& entry, bool crypto_valid);

// Хвиля 8, п.3: діагностичний рядок про мітку часу дописується до
// `VerifyReport::message` з префіксом, який каже, про ЯКУ саме мітку йдеться.
// Раніше це були дві окремі функції з тілами, що збігалися все, крім
// префікса — рівно той «молодший близнюк», проти якого спрямовано ADR-033.
void AppendContainerTimestampMessage(VerifyReport& report, const std::string& message);
void AppendXadesTimestampMessage(VerifyReport& report, const std::string& message);

// Підстановка формату, виведеного з імені операції: користувацький звіт
// показує тип контейнера й формат підпису навіть тоді, коли шлях перевірки
// не встиг заповнити відповідні поля `VerifyReport`.
struct VerifyReportFormatLabels {
    const char* container_type;
    const char* signature_format;
};
VerifyReportFormatLabels UserReportFormatForOperation(const std::string& operation);

} // namespace tamga::core
