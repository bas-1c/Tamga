#include "core/policy/CrlValidator.h"

#include <ctime>

#include "core/CryptoniteAdapter.h"
#include "core/cryptonite/CertUtil.h"
#include "core/policy/CertificateChainValidator.h"  // ParseIso8601Time
#include "core/policy/Sha256Helper.h"

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

namespace tamga::core::policy {

namespace {
#if TAMGA_CRYPTONITE_ENABLED
// Видавець CRL має відповідати issuer DN цільового сертифіката. Ця
// перевірка лише відсіює сторонні докази; збіг DN не замінює підпис CRL.
bool HasDifferentCrlIssuer(const std::vector<std::uint8_t>& crl_der,
                          const Certificate_t* certificate) {
    using namespace cryptonite_detail;
    if (!certificate) return false;
    ScopedByteArray encoded(MakeByteArray(crl_der), ba_free);
    ScopedCrl crl(crl_alloc(), crl_free);
    if (!encoded || !crl || crl_decode(crl.get(), encoded.get()) != RET_OK) return false;
    return !asn_equals(&Name_desc, &crl->tbsCertList.issuer, &certificate->tbsCertificate.issuer);
}
#endif
} // namespace

CrlValidationResult CrlValidator::Validate(const CrlValidationInput& input) const {
    CrlValidationResult result;

#if !TAMGA_CRYPTONITE_ENABLED
    (void)input;
    result.checked = false;
    result.status = RevocationStatus::Unknown;
    result.message = "CRL revocation validation is not supported without cryptonite.";
    return result;
#else
    if (input.crls_der.empty()) {
        result.checked = false;
        result.status = RevocationStatus::Unknown;
        result.message = "No local CRLs are available.";
        return result;
    }

    // В-02 (fail-open, аудит 2026-08-26). Без сертифіката issuer підпис CRL
    // ніде не перевіряється: `CheckCertificateRevocation` обчислює `crl_valid`
    // ЛИШЕ коли issuer переданий. А `crl_check_cert` у vendored cryptonite
    // звіряє **тільки серійний номер** — ані issuer CRL, ані дати. Отже
    // будь-який CRL, зокрема вбудований у сам недовірений документ
    // (`ValidationEngine` додає `embedded_revocation_crl_der` до пулу), чий
    // список не містить серійника, давав `Good`.
    //
    // Досяжність: `issuer_certificate_der` порожній саме тоді, коли ланцюг не
    // побудовано (`signer_issuer_certificate_der` присвоюється лише у
    // trusted-гілці `CertificateChainValidator`). Перевернути `trust_valid` це
    // не могло, але `revocationStatus=Good` за підробленим доказом — fail-open
    // звітного поля й пролом у глибокому ешелонуванні: тим самим шляхом
    // `TimestampEngine` перевіряє сертифікат TSA.
    //
    // Реакція НАВМИСНО асиметрична:
    //   * «не відкликаний» без перевіреного підпису CRL — НЕ доказ -> Unknown;
    //   * знайдений у списку серійник лишається сигналом -> Revoked.
    // Симетричне блокування обох напрямків було б суворішим за букву, але
    // зняло б наявний захисний сигнал і не додало б безпеки: хибне «відкликано»
    // веде до відмови у прийнятті документа, а хибне «не відкликано» — до
    // прийняття відкликаного. Ціна помилок різна, тому й правила різні.
    const bool issuer_available = !input.issuer_certificate_der.empty();

    result.status = RevocationStatus::Invalid;
    result.message = "No local CRL produced a valid revocation check.";
    bool saw_invalid = false;
    // В-02: «CRL є, але його підпис нікому перевірити» — це НЕ те саме, що
    // «дані відкликання некоректні». Перше дає Unknown, друге — Invalid, і
    // змішувати їх не можна: Invalid у профілях із hard-fail читається як
    // доведена проблема з доказом, якої тут немає.
    bool saw_unverifiable = false;
    bool saw_unrelated = false;
    bool saw_stale = false;
    std::string stale_message;
    CrlValidationResult good_result;
    const auto certificate = cryptonite_detail::DecodeCertificateDer(input.signer_certificate_der);

    // С-01: момент, на який оцінюється свіжість CRL. Поле `validation_time`
    // існувало у вхідній структурі, але не читалося жодного разу — вікно
    // [thisUpdate, nextUpdate] не перевірялося взагалі.
    std::time_t validation_time_sec = std::time(nullptr);
    if (!input.validation_time.empty()) {
        std::time_t parsed = 0;
        if (ParseIso8601Time(input.validation_time, parsed)) {
            validation_time_sec = parsed;
        }
    }

    for (const auto& crl_der : input.crls_der) {
        if (HasDifferentCrlIssuer(crl_der, certificate.get())) {
            saw_unrelated = true;
            continue;
        }
        // С-01: прострочений CRL не є доказом «не відкликаний». Сертифікат
        // могли відкликати вже після його випуску, і саме цей CRL про це не
        // знає. `crl_check_cert` дат не дивиться, тож перевірка потрібна тут.
        //
        // Вердикт свіжості обчислюємо тут, а ЗАСТОСОВУЄМО нижче — лише до
        // висновку «не відкликаний». Причина та сама, що й для відсутнього
        // issuer: якщо серійник УЖЕ є у списку, застарілість CRL цього факту
        // не скасовує. Протилежне рішення коштувало б виявлення реальних
        // відкликань — саме на цьому впав тест із живим CRL ЦЗО.
        bool crl_fresh = true;
        std::string freshness_message;
        std::time_t this_update = 0;
        std::time_t next_update = 0;
        if (CryptoniteAdapter::GetCrlValidityWindow(crl_der, this_update, next_update)) {
            if (validation_time_sec < this_update) {
                crl_fresh = false;
                freshness_message = "CRL is not yet valid at the validation time.";
            } else if (next_update != 0 && validation_time_sec > next_update) {
                // next_update == 0 -> поле відсутнє (RFC 5280 дозволяє). Це
                // «без заявленої межі», а не «протерміновано»: відхиляти такий
                // CRL означало б ламати легітимні джерела.
                crl_fresh = false;
                freshness_message = "CRL is stale: nextUpdate is earlier than the validation time.";
            }
        }

        auto check = CryptoniteAdapter::CheckCertificateRevocation(
            input.signer_certificate_der,
            crl_der,
            input.issuer_certificate_der);

        if (!check.message.empty()) {
            result.message = check.message;
        }

        if (!check.checked) {
            saw_invalid = true;
            continue;
        }

        if (!input.issuer_certificate_der.empty() && !check.crl_valid) {
            saw_invalid = true;
            result.checked = true;
            result.status = RevocationStatus::Invalid;
            result.message = check.message.empty()
                ? "CRL signature validation failed."
                : "CRL signature validation failed: " + check.message;
            continue;
        }

        // С-01: свіжість блокує лише висновок «не відкликаний». Перевіряється
        // перед issuer-гілкою: застарілість — властивість самого CRL, і саме
        // її корисніше показати у повідомленні.
        if (!crl_fresh && !check.revoked) {
            saw_stale = true;
            stale_message = freshness_message;
            // Доказ усе одно був розглянутий — фіксуємо його для forensic-звіту.
            if (result.crl_evidence_id.empty()) {
                result.crl_evidence_id = ComputeSha256Hex(crl_der);
            }
            continue;
        }

        // В-02: «не відкликаний» приймається лише від CRL із перевіреним
        // підписом. Без issuer-сертифіката такий висновок не має доказової
        // сили — статус лишається невизначеним.
        if (!issuer_available && !check.revoked) {
            saw_unverifiable = true;
            if (result.crl_evidence_id.empty()) {
                result.crl_evidence_id = ComputeSha256Hex(crl_der);
            }
            continue;
        }

        CrlValidationResult candidate;
        candidate.checked = true;
        candidate.revoked = check.revoked;
        candidate.status = check.revoked ? RevocationStatus::Revoked : RevocationStatus::Good;
        candidate.message = check.message;
        candidate.crl_evidence_id = ComputeSha256Hex(crl_der);
        candidate.revocation_time = check.revocation_time;

        if (candidate.status == RevocationStatus::Revoked) {
            return candidate;
        }

        if (!good_result.checked) {
            good_result = candidate;
        }
    }

    if (good_result.checked) {
        return good_result;
    }

    if (saw_invalid) {
        result.status = RevocationStatus::Invalid;
        result.checked = true;
        return result;
    }

    if (saw_stale) {
        // Доказ перевірено, але він не покриває потрібний момент. Не губимо
        // цю точнішу причину в загальному Unknown.
        result.checked = true;
        result.status = RevocationStatus::Stale;
        result.message = stale_message.empty()
            ? std::string("CRL revocation status is unknown: the CRL is outside its validity window.")
            : stale_message;
        return result;
    }

    if (saw_unverifiable) {
        result.checked = false;
        result.status = RevocationStatus::Unknown;
        result.message =
            "CRL revocation status is unknown: the issuer certificate is unavailable, "
            "so the CRL signature could not be verified.";
    } else if (saw_unrelated) {
        result.checked = false;
        result.status = RevocationStatus::Unknown;
        result.message = "No local CRL matches the certificate issuer.";
    }
    return result;
#endif
}

} // namespace tamga::core::policy
