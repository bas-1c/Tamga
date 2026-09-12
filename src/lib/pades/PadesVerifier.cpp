#include "pades/PadesVerifier.h"

#include <sstream>

#if defined(TAMGA_PDF_SIGNATURES_ENABLED)

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "core/CryptoniteAdapter.h"
#include "core/policy/TimestampValidator.h"
#include "util/Der.h"
#include "pades/PdfByteRange.h"
#include "pades/PdfParser.h"

namespace tamga::pades {

namespace {

// Точна довжина зовнішнього DER-обʼєкта (для відкидання NUL-паддінгу
// /Contents, який PadesBuilder додає до фіксованого розміру hex-слоту).
std::size_t DerLength(const std::vector<std::uint8_t>& der) {
    if (der.size() < 2 || der[0] != 0x30) return der.size();
    // Хвиля 8, п.2 (доповнення): раніше довжина розбиралася тут вручну, без
    // guard проти зсуву — `2 + num + length` міг переповнитись і дати маленьке
    // число, через що DER обрізався б не там. Memory-safety це не ламало
    // (`TrimDer` лише зменшує розмір), але результат був неправильним.
    tamga::util::TlvView tlv{};
    if (!tamga::util::ParseTlvAt(der, 0U, der.size(), tlv)) {
        return der.size();
    }
    return tlv.next_offset;
}

// Обрізає NUL-паддінг /Contents до реальної DER-довжини.
std::vector<std::uint8_t> TrimDer(std::vector<std::uint8_t> data) {
    const std::size_t n = DerLength(data);
    if (n < data.size()) data.resize(n);
    return data;
}

// К-01: чи завершується файл маркером кінця ревізії PDF. Кожна ревізія (як
// початкова, так і будь-яке інкрементальне оновлення) закінчується рядком
// %%EOF, після якого стандарт допускає лише пробільні символи. Довільні
// дописані байти цього інваріанта не задовольняють.
bool EndsWithPdfEof(const std::vector<std::uint8_t>& pdf) {
    static const char kEof[] = {'%', '%', 'E', 'O', 'F'};
    std::size_t end = pdf.size();
    while (end > 0) {
        const std::uint8_t c = pdf[end - 1];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t' || c == '\f' || c == 0x00) {
            --end;
            continue;
        }
        break;
    }
    if (end < sizeof(kEof)) return false;
    return std::equal(kEof, kEof + sizeof(kEof), pdf.begin() + static_cast<std::ptrdiff_t>(end - sizeof(kEof)));
}

}  // namespace

PadesVerifier::PadesVerifier(tamga::core::CryptoniteAdapter& crypto, tamga::core::TspClient& tsp)
    : crypto_(crypto), tsp_(tsp) {}

bool PadesVerifier::VerifyPdf(const std::vector<std::uint8_t>& pdf,
                              PadesVerificationResult& result,
                              std::string& error_message) {
    result = PadesVerificationResult{};

    std::string pdf_error;
    result.pdf_well_formed = PdfParser::IsValidPdf(pdf, pdf_error);
    if (!result.pdf_well_formed) result.notes.push_back("qpdf: " + pdf_error);

    // S-005: витяг полів підпису через обʼєктний граф qpdf (AcroForm → SigField)
    // замість наївного пошуку підрядків "/ByteRange [". Усуває помилкову
    // ідентифікацію ByteRange у потоках вмісту та co-sign misdetect.
    const auto sig_fields = PdfParser::ExtractSignatureFields(pdf);
    if (sig_fields.empty()) {
        error_message = "Не знайдено полів підпису (AcroForm/Sig)";
        return false;
    }

    // F-002: розрізнення основних підписів (adbe.pkcs7.detached /
    // ETSI.CAdES.detached) і документних міток часу (ETSI.RFC3161).
    std::vector<const PdfSignatureDictionary*> main_sigs;
    std::vector<const PdfSignatureDictionary*> doctimestamps;
    for (const auto& f : sig_fields) {
        if (f.sub_filter == "ETSI.RFC3161") {
            doctimestamps.push_back(&f);
        } else {
            main_sigs.push_back(&f);
        }
    }

    if (main_sigs.empty()) {
        error_message = "Не знайдено основного підпису (всі поля мають SubFilter ETSI.RFC3161)";
        return false;
    }

    result.signature_count = static_cast<int>(main_sigs.size());

    // К-01: чи покривають підписи ВЕСЬ документ.
    //
    // Кожне поле підпису покриває [offset1, offset1+length1) ∪ [offset2,
    // offset2+length2). Кінець підписаної ревізії — offset2+length2. Байти
    // після найдальшого такого кінця не покриті жодним підписом: у PDF це
    // інкрементальне оновлення, додане ПІСЛЯ підписання і ним не захищене.
    //
    // Агрегуємо по sig_fields (а не по main_sigs), бо DocTimeStamp у PAdES-LTA
    // — теж підписане поле, і саме воно легітимно покриває секцію, дописану
    // після основного підпису. Без урахування DocTimeStamp коректний LTA
    // хибно вважався б неповним.
    {
        const std::uint64_t pdf_size = static_cast<std::uint64_t>(pdf.size());
        result.document_size = pdf_size;
        std::uint64_t coverage_end = 0;
        for (const auto& f : sig_fields) {
            // Складання без переповнення: діапазон поза межами файлу не може
            // розширювати покриття (його окремо відхиляє перевірка ByteRange).
            if (f.byte_range.offset2 > pdf_size) continue;
            if (f.byte_range.length2 > pdf_size - f.byte_range.offset2) continue;
            const std::uint64_t end = f.byte_range.offset2 + f.byte_range.length2;
            if (end > coverage_end) coverage_end = end;
        }
        result.signed_coverage_end = coverage_end;
        result.unsigned_trailing_bytes = pdf_size > coverage_end ? pdf_size - coverage_end : 0;

        if (coverage_end == pdf_size) {
            result.coverage_status = "complete";
            result.coverage_complete = true;
        } else if (!EndsWithPdfEof(pdf)) {
            // Найпростіший і найпоширеніший клас підробки: довільні байти,
            // дописані у кінець файла. Коректна ревізія PDF завжди
            // завершується маркером %%EOF, тож його відсутність наприкінці —
            // однозначний доказ, що «хвіст» не є оновленням документа.
            result.coverage_status = "unsigned-data-appended";
            result.coverage_complete = false;
            std::ostringstream note;
            note << "Після підписаної ревізії дописано " << result.unsigned_trailing_bytes
                 << " байт(ів), які не утворюють коректного інкрементального оновлення PDF"
                 << " (файл не завершується маркером %%EOF)";
            result.notes.push_back(note.str());
        } else {
            // «Хвіст» структурно є інкрементальним оновленням. Це нормальний
            // стан для PAdES-LT (/DSS) і LTA: у реальних контейнерах Дії
            // непокритими лишаються ~14 КБ саме через /DSS. Тож питання не в
            // наявності «хвоста», а в тому, чи змінює він те, що бачить читач.
            bool content_changed = false;
            std::string detail;
            const bool compared = PdfParser::ComparePageContentWithSignedRevision(
                pdf, static_cast<std::size_t>(coverage_end), content_changed, detail);
            std::ostringstream note;
            if (!compared) {
                // Fail-closed: якщо порівняти не вдалося, ми НЕ маємо права
                // стверджувати, що змін немає.
                result.coverage_status = "coverage-unverifiable";
                result.coverage_complete = false;
                note << "Не вдалося перевірити, чи змінює документ "
                     << result.unsigned_trailing_bytes
                     << " байт(ів), дописаних після підписаної ревізії: " << detail;
            } else if (content_changed) {
                result.coverage_status = "modified-after-signing";
                result.coverage_complete = false;
                note << "Документ змінено після підписання: " << detail
                     << " (непокрито " << result.unsigned_trailing_bytes << " байт(ів))";
            } else {
                result.coverage_status = "extended-by-unsigned-revisions";
                result.coverage_complete = true;
                note << "Після підписаної ревізії додано " << result.unsigned_trailing_bytes
                     << " байт(ів) інкрементальних оновлень (типово /DSS для PAdES-LT);"
                     << " вміст сторінок не змінено";
            }
            result.notes.push_back(note.str());
        }
    }

    // --- LT: розбір /DSS через обʼєктний граф qpdf. ---
    // Робиться ДО перевірки підписів, бо сертифікат підписанта TSA у PAdES-LT/LTA
    // за ETSI EN 319 142-1 виноситься саме сюди й може бути відсутній у самому
    // токені мітки часу — валідація мітки нижче отримує /DSS/Certs як пул
    // кандидатів.
    const bool has_dss = tamga::pades::PdfParser::ParseDss(
        pdf, result.dss_certificates_der, result.dss_ocsp_responses_der, result.dss_crls_der);
    result.ltv_valid = has_dss && !result.dss_certificates_der.empty();

    // --- Основні підписи (всі мають бути дійсними для signature_valid=true). ---
    bool all_sigs_valid = true;
    bool signer_cert_set = false;
    bool has_embedded_ts = false;
    bool embedded_ts_valid = true;

    int main_sig_index = 0;
    for (const auto* sig : main_sigs) {
        ++main_sig_index;
        // S-005: коректна перевірка покриття ByteRange:
        // (1) offset1==0 — покриття від початку файлу;
        // (2) offset2 > length1 — є проміжок для /Contents (gap > 0);
        // (3) offset2 + length2 <= file_size — діапазони в межах файлу.
        // Використовуємо <= (не ==), щоб коректно обробляти LTA-PDF, де
        // основний підпис покриває базовий файл, а інкрементальна секція
        // DocTimeStamp додана після (offset2+length2 == file_size_base < pdf.size()).
        const std::uint64_t pdf_size = static_cast<std::uint64_t>(pdf.size());
        const bool first_range_in_bounds =
            sig->byte_range.offset1 <= pdf_size &&
            sig->byte_range.length1 <= pdf_size - sig->byte_range.offset1;
        const bool second_range_in_bounds =
            sig->byte_range.offset2 <= pdf_size &&
            sig->byte_range.length2 <= pdf_size - sig->byte_range.offset2;
        const bool br_valid =
            (sig->byte_range.offset1 == 0) &&
            (sig->byte_range.offset2 > sig->byte_range.length1) &&
            first_range_in_bounds && second_range_in_bounds;
        if (!signer_cert_set) {
            result.byte_range_valid = br_valid;
        }
        if (!br_valid) {
            all_sigs_valid = false;
            result.notes.push_back("ByteRange не покриває файл повністю");
        }

        const std::vector<std::uint8_t> cms = TrimDer(sig->signature);
        const std::vector<std::uint8_t> signed_bytes =
            PdfByteRange::ExtractSignedBytes(pdf, sig->byte_range);

        bool sig_valid = false;
        tamga::core::VerifyPolicyInfo policy_info;
        std::string verify_error;
        if (!tamga::core::CryptoniteAdapter::VerifyDetached(
                signed_bytes, cms, sig_valid, policy_info, verify_error)) {
            all_sigs_valid = false;
            result.notes.push_back("VerifyDetached: " + verify_error);
        } else {
            if (!sig_valid) {
                all_sigs_valid = false;
                // Раніше цей шлях не лишав ЖОДНОГО сліду: VerifyDetached
                // відпрацював без помилки виконання, але підпис не збігся, і звіт
                // казав лише "невалідний" без підказки, який шар зламався.
                // Фіксуємо структурні факти, за якими можна відрізнити
                // (а) невірно зібрані байти ByteRange, (б) непокриття файлу,
                // (в) відмову самої CMS-перевірки.
                std::ostringstream note;
                note << "CMS integrity failed for signature #" << main_sig_index
                     << ": byteRange=[" << sig->byte_range.offset1 << ' ' << sig->byte_range.length1
                     << ' ' << sig->byte_range.offset2 << ' ' << sig->byte_range.length2 << ']'
                     << ", signedBytes=" << signed_bytes.size()
                     << ", cms=" << cms.size()
                     << ", signerCertPresent=" << (policy_info.signer_certificate_present ? "true" : "false")
                     << ", signers=" << policy_info.signer_count;
                result.notes.push_back(note.str());
            }
            if (!signer_cert_set) {
                result.signer_certificate_der = policy_info.signer_certificate_der;
                // ПД-01: разом із сертифікатом віддаємо і сам CMS цього ж
                // підпису — саме він є носієм timestamp evidence для
                // канонічного ValidationEngine/TimestampEngine.
                result.signer_cms_der = cms;
                signer_cert_set = true;
            }
        }

        // --- T: вбудована signature-timestamp у CMS. ---
        bool has_token = false;
        std::string e;
        if (tamga::core::CryptoniteAdapter::HasSignatureTimestampToken(cms, has_token, e) &&
            has_token) {
            has_embedded_ts = true;
            std::vector<std::uint8_t> token, sigval;
            if (tamga::core::CryptoniteAdapter::ExtractSignatureTimestampToken(cms, token, e) &&
                tamga::core::CryptoniteAdapter::GetSignatureValue(cms, sigval, e)) {
                auto vr = tamga::core::policy::ValidateTimestampToken(token, sigval,
                                                                      result.dss_certificates_der);
                if (!vr.valid) {
                    embedded_ts_valid = false;
                    result.notes.push_back("signature-timestamp: " + vr.message);
                } else if (vr.tsa_certificate_external) {
                    result.notes.push_back("signature-timestamp: TSA certificate resolved from /DSS");
                }
            } else {
                embedded_ts_valid = false;
                result.notes.push_back("signature-timestamp: extract failed");
            }
        }
        result.main_signatures.push_back(
            {cms, policy_info.signer_certificate_der, sig_valid && br_valid, has_token,
             br_valid ? sig->byte_range.offset2 + sig->byte_range.length2 : 0});
    }

    result.signature_valid = all_sigs_valid;
    result.signature_timestamp_present = has_embedded_ts;

    // --- LTA: документні мітки часу (SubFilter ETSI.RFC3161). ---
    // F-002: перевіряє кожне поле DocTimeStamp окремо, а не трактує другий
    // ByteRange як DocTimeStamp незалежно від SubFilter.
    const bool has_doctimestamp = !doctimestamps.empty();
    bool doctimestamp_valid = true;
    for (const auto* dts : doctimestamps) {
        const std::vector<std::uint8_t> token = TrimDer(dts->signature);
        const std::vector<std::uint8_t> signed_bytes =
            PdfByteRange::ExtractSignedBytes(pdf, dts->byte_range);
        // ПД-01: віддаємо токен і його джерело imprint назовні — DocTimeStamp
        // не лежить у CMS підпису, тож канонічний TimestampEngine отримає його
        // лише через explicit-вхід (Session::VerifyPdf → TryCanonicalTimestampVerdict).
        result.document_timestamp_tokens_der.push_back(token);
        result.document_timestamp_imprint_sources.push_back(signed_bytes);
        const auto pdf_size = static_cast<std::uint64_t>(pdf.size());
        const bool dts_range_valid = dts->byte_range.offset1 == 0 &&
            dts->byte_range.offset2 > dts->byte_range.length1 &&
            dts->byte_range.offset2 <= pdf_size &&
            dts->byte_range.length2 <= pdf_size - dts->byte_range.offset2;
        result.document_timestamp_revision_ends.push_back(
            dts_range_valid ? dts->byte_range.offset2 + dts->byte_range.length2 : 0);
        if (!dts_range_valid) doctimestamp_valid = false;
        auto vr = tamga::core::policy::ValidateTimestampToken(token, signed_bytes,
                                                              result.dss_certificates_der);
        if (!vr.valid) {
            doctimestamp_valid = false;
            result.notes.push_back("DocTimeStamp: " + vr.message);
        } else if (vr.tsa_certificate_external) {
            result.notes.push_back("DocTimeStamp: TSA certificate resolved from /DSS");
        }
    }

    const bool any_ts = has_embedded_ts || has_doctimestamp;
    result.timestamps_valid = any_ts && (!has_embedded_ts || embedded_ts_valid) &&
                              (!has_doctimestamp || doctimestamp_valid);

    if (has_doctimestamp) {
        result.detected_profile = PadesProfile::LTA;
    } else if (has_dss) {
        result.detected_profile = PadesProfile::LT;
    } else if (has_embedded_ts) {
        result.detected_profile = PadesProfile::T;
    } else {
        result.detected_profile = PadesProfile::B;
    }

    return true;
}

}  // namespace tamga::pades

#endif  // TAMGA_PDF_SIGNATURES_ENABLED
