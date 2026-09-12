#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pades/PdfTypes.h"

// Форвард-оголошення крипто-бекендів core, щоб PDF-рушій не протікав у заголовки.
namespace tamga::core {
class CryptoniteAdapter;
class TspClient;
}  // namespace tamga::core

namespace tamga::pades {

// Незалежні докази кожного основного PDF-підпису. Перший CMS не може
// представляти мітки часу наступних співпідписантів.
struct PadesSignatureEvidence {
    std::vector<std::uint8_t> cms_der;
    std::vector<std::uint8_t> signer_certificate_der;
    bool signature_valid{false};
    bool signature_timestamp_present{false};
    std::uint64_t signed_revision_end{0};
};

// Результат верифікації PAdES-підпису PDF-документа.
struct PadesVerificationResult {
    PadesProfile detected_profile{PadesProfile::B};
    bool signature_valid{false};
    bool byte_range_valid{false};
    bool pdf_well_formed{false};
    bool timestamps_valid{false};
    bool ltv_valid{false};
    // К-01: покриття документа підписами. ByteRange одного підпису навмисно
    // перевіряється через `<=`, а не `==` (інакше ламається PAdES-LTA, де
    // DocTimeStamp додається інкрементальною секцією ПІСЛЯ основного
    // підпису). Через це окрема перевірка ByteRange не може відповісти на
    // питання «чи покритий весь файл»: байти після offset2+length2 останнього
    // підпису раніше не аналізувались узагалі, і файл із дописаним суфіксом
    // давав звіт, ідентичний звіту оригіналу.
    //
    // Правильна відповідь — АГРЕГАЦІЯ по ВСІХ полях підпису (і основних, і
    // ETSI.RFC3161 DocTimeStamp): легітимний LTA лишається повним, бо
    // DocTimeStamp покриває власний «хвіст», а довільний дописаний блок — ні.
    std::uint64_t document_size{0};
    std::uint64_t signed_coverage_end{0};       // max(offset2 + length2) по всіх полях
    std::uint64_t unsigned_trailing_bytes{0};   // document_size - signed_coverage_end
    // Класифікація «хвоста»:
    //   "complete"                       — підписи покривають файл до останнього байта;
    //   "extended-by-unsigned-revisions" — далі є коректні інкрементальні
    //                                      оновлення (типово /DSS у PAdES-LT),
    //                                      але вміст сторінок не змінено;
    //   "modified-after-signing"         — вміст сторінок змінено після підписання;
    //   "unsigned-data-appended"         — «хвіст» не є коректним оновленням PDF;
    //   "coverage-unverifiable"          — класифікувати не вдалося (fail-closed).
    std::string coverage_status{"complete"};
    bool coverage_complete{false};
    int signature_count{0};                            // кількість основних полів підпису
    std::vector<std::uint8_t> signer_certificate_der;  // із вбудованого CMS (перший підпис)
    // ПД-01: сирий детачд CMS (/Contents) ТОГО САМОГО (першого) підпису, з
    // якого взято `signer_certificate_der`. Раніше CMS лишався всередині
    // верифікатора, тож канонічний `validation::ValidationEngine` отримував
    // порожній `cms_der` і НЕ БАЧИВ жодного timestamp evidence: signature
    // timestamp PAdES-T/LT лежить саме в неприв'язаних атрибутах цього CMS
    // (id-aa-signatureTimeStampToken). Труба була прокладена, доказ у неї не
    // подавався — статус мітки лишався `timestamp-partial` назавжди.
    std::vector<std::uint8_t> signer_cms_der;
    std::vector<PadesSignatureEvidence> main_signatures;
    // ПД-01: чи має цей CMS вбудовану signature-timestamp (профіль ≥ T).
    bool signature_timestamp_present{false};
    // ПД-01: документні мітки часу (поля SubFilter=ETSI.RFC3161, PAdES-LTA).
    // Вони НЕ є частиною CMS підпису, тож канонічний рушій може отримати їх
    // лише явно: токен + джерело imprint (підписані байти ByteRange поля).
    // Індекси двох векторів відповідають один одному.
    std::vector<std::vector<std::uint8_t>> document_timestamp_tokens_der;
    std::vector<std::vector<std::uint8_t>> document_timestamp_imprint_sources;
    std::vector<std::uint64_t> document_timestamp_revision_ends;
    // Embedded evidence з /DSS (WP-5-подібне до XAdES CertificateValues/
    // RevocationValues) — сирі DER-байти, дереференсовані з масивів
    // /Certs, /OCSPs, /CRLs через обʼєктний граф qpdf (PdfParser::ParseDss).
    std::vector<std::vector<std::uint8_t>> dss_certificates_der;
    std::vector<std::vector<std::uint8_t>> dss_ocsp_responses_der;
    std::vector<std::vector<std::uint8_t>> dss_crls_der;
    std::vector<std::string> notes;
};

// Верифікатор PAdES-підписів: перевіряє ByteRange-цілісність і детачд CMS над
// підписаними байтами. Доступний лише у збірці з TAMGA_ENABLE_PDF_SIGNATURES.
class PadesVerifier {
public:
    PadesVerifier(tamga::core::CryptoniteAdapter& crypto, tamga::core::TspClient& tsp);

    bool VerifyPdf(const std::vector<std::uint8_t>& pdf,
                   PadesVerificationResult& result,
                   std::string& error_message);

private:
    tamga::core::CryptoniteAdapter& crypto_;
    tamga::core::TspClient& tsp_;
};

}  // namespace tamga::pades
