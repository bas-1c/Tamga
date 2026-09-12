#pragma once

#include <string>
#include <utility>

namespace tamga::cli {

// Q-07: доказовий файл `--evidence-out` — це ЗАПИТАНИЙ артефакт, а не побічний
// ефект. До цієї зміни CLI лише друкував "Cannot write evidence file: ..." у
// stderr, а код повернення далі визначала виключно валідність підпису. Для
// валідного документа це давало exit 0 БЕЗ файла, який просили, — тобто
// автоматизований виклик («перевір і поклади доказ») звітував про успіх,
// маючи на диску порожнє місце.
//
// Друга половина того самого дефекту: блок збереження стояв ПІСЛЯ раннього
// виходу по `!execution_ok`, тож звіт саме про невдалу перевірку — найцінніший
// для розбору — у файл не потрапляв узагалі.
//
// Рішення винесене з `main.cpp` сюди, бо самі коди виходу перевіряються
// тестом у наявному бінарнику (`tamga-tests`), а не запуском процесу: у трьох
// штатних конфігураціях кількість CTest-тестів зафіксована на етапі configure,
// і нова ціль ctest ламала б цей гейт.

// Документований код завершення для помилки вводу-виводу (`docs/cli.md`,
// таблиця exit-кодів: 1 = InvalidArgument / SyntaxError / IOError).
inline constexpr int kEvidenceIoExitCode = 1;

enum class EvidenceOutcome {
    NotRequested,       // --evidence-out не задано: артефакта ніхто не просив
    Written,            // файл записано повністю
    ReportUnavailable,  // сесія не віддала звіт, записувати нічого
    WriteFailed,        // звіт є, але файл не записався (шлях, права, диск)
};

inline bool EvidenceOutcomeIsFailure(const EvidenceOutcome outcome) {
    return outcome == EvidenceOutcome::ReportUnavailable ||
           outcome == EvidenceOutcome::WriteFailed;
}

// Невдача запитаного артефакта перекриває вердикт перевірки: зовнішній
// сценарій, що не отримав доказ, не може діяти й за самим вердиктом.
// Вердикт при цьому лишається у stdout/stderr, тож інформація не втрачається.
inline int ApplyEvidenceOutcome(const EvidenceOutcome outcome, const int verdict_exit_code) {
    return EvidenceOutcomeIsFailure(outcome) ? kEvidenceIoExitCode : verdict_exit_code;
}

// `get_report(std::string&) -> bool` — джерело технічного звіту (сесія),
// `write(const std::string& path, const std::string& text) -> bool` — writer.
// Обидва інжектуються, щоб тест перевіряв саме правило, а не конкретний бекенд.
template <typename ReportProvider, typename Writer>
EvidenceOutcome WriteEvidence(const std::string& path, ReportProvider&& get_report, Writer&& write) {
    if (path.empty()) {
        return EvidenceOutcome::NotRequested;
    }
    std::string report;
    if (!std::forward<ReportProvider>(get_report)(report)) {
        return EvidenceOutcome::ReportUnavailable;
    }
    if (!std::forward<Writer>(write)(path, report)) {
        return EvidenceOutcome::WriteFailed;
    }
    return EvidenceOutcome::Written;
}

}  // namespace tamga::cli
