#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pades/PdfTypes.h"

namespace tamga::pades {

// Парсер/валідатор PDF поверх qpdf. Доступний лише у збірці з
// TAMGA_ENABLE_PDF_SIGNATURES.
class PdfParser {
public:
    // Перевіряє, що байти є коректним PDF (qpdf processMemoryFile).
    // false + error_message, якщо документ не парситься.
    static bool IsValidPdf(const std::vector<std::uint8_t>& pdf, std::string& error_message);

    // Витягує всі поля підпису (AcroForm/Sig) через об'єктний граф qpdf.
    // Кожен запис містить ByteRange (числа з PDF-словника, не текстовий
    // пошук), вміст /Contents (двійкові байти, включно з NUL-паддінгом) і
    // SubFilter. Порожній вектор — немає полів підпису або qpdf-помилка.
    // NUL-паддінг /Contents необхідно обрізати викликачем (DerLength).
    static std::vector<PdfSignatureDictionary> ExtractSignatureFields(
        const std::vector<std::uint8_t>& pdf);

    // Розбирає /DSS (Document Security Store) через об'єктний граф qpdf:
    // резолвить непрямі посилання в масивах /Certs, /CRLs, /OCSPs на
    // stream-обʼєкти й повертає їхній декодований вміст (сирі DER-байти
    // сертифікатів/CRL/OCSP-відповідей). На відміну від пошуку підрядків
    // "/DSS"/"/Certs" — фактично парсить структуру каталогу й дереференсує
    // кожен запис масиву. Повертає false, якщо /DSS відсутній або не є
    // словником; часткові результати (напр. лише /Certs без /CRLs) — це
    // не помилка, відповідні вектори просто лишаються порожніми.
    static bool ParseDss(const std::vector<std::uint8_t>& pdf,
                        std::vector<std::vector<std::uint8_t>>& certificates_der,
                        std::vector<std::vector<std::uint8_t>>& ocsp_responses_der,
                        std::vector<std::vector<std::uint8_t>>& crls_der);

    // К-01: чи змінює вміст документа те, що дописано ПІСЛЯ підписаної
    // ревізії.
    //
    // PAdES дозволяє інкрементальні оновлення після підписання: саме так
    // додається /DSS у PAdES-LT (у реальних контейнерах Дії це ~14 КБ, не
    // покритих жодним ByteRange) і DocTimeStamp у LTA. Тому сам факт
    // непокритого «хвоста» НЕ означає підробки — але й не означає, що вміст
    // недоторканий.
    //
    // Метод розбирає підписану ревізію (префікс `signed_prefix_size` байтів —
    // за інкрементальної моделі PDF це самодостатній документ) і повний файл
    // як два незалежні PDF, після чого звіряє те, що бачить читач: кількість
    // сторінок, декодовані потоки вмісту кожної сторінки та потоки вигляду
    // (/AP) її анотацій.
    //
    // `content_changed = true` — вміст після підписання змінено.
    // Повертає false, якщо порівняння виконати не вдалося (тоді викликач
    // зобовʼязаний трактувати це fail-closed, а не як «змін немає»).
    static bool ComparePageContentWithSignedRevision(const std::vector<std::uint8_t>& pdf,
                                                     std::size_t signed_prefix_size,
                                                     bool& content_changed,
                                                     std::string& detail);
};

}  // namespace tamga::pades
