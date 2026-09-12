#include "core/policy/VerifyChecks.h"

#include "core/session/VerifySummary.h"

namespace tamga::core::policy {

bool EffectiveCertificateTimeValid(const VerifyReport& report) {
    // WP-3 (CR-02): `certificate_time_valid` канонічно виставляється
    // ValidationEngine/CertificateChainValidator (X.509 notBefore/notAfter на
    // реальний evaluation_time) для ВСІХ форматів, включно з XAdES-B-LT.
    // Optimistic fallback за timestamp_checked/ltv_valid прибрано — він міг
    // показати valid без фактичної перевірки сертифіката.
    return report.certificate_time_valid;
}

// ME-02: `ocsp_checked`/`revocation_checked` канонічно виставляються
// ValidationEngine/RevocationEngine (`ve_report.signer_revocation`) для ВСІХ
// форматів — той самий принцип, що WP-3 (CR-02) застосував до
// `certificate_time_valid`. Раніше тут був optimistic fallback: XAdES-B-LT з
// присутнім сертифікатом і валідним підписом звітував `ocspChecked=true`
// НАВІТЬ якщо canonical RevocationEngine фактично не зміг обробити embedded
// RevocationValues — звіт змішував «є LTV-докази в XML» з «ми дійсно
// перевірили відкликання». Структурний факт наявності доказів не втрачено:
// див. `revocation_evidence_present` у `VerifyReport`.
bool EffectiveOcspChecked(const VerifyReport& report) {
    return report.ocsp_checked;
}

bool EffectiveRevocationChecked(const VerifyReport& report) {
    return report.revocation_checked;
}

// WP-3 (CR-02): раніше — здогад за timestamp_valid/timestamp_checked/ltv_valid,
// не пов'язаний з тим, який час справді пішов у X.509-перевірку. Тепер —
// канонічне значення, виставлене разом із certificate_time_valid.
const std::string& ValidationTimeSource(const VerifyReport& report) {
    return report.validation_time_source;
}

bool HasPolicyWarning(const VerifyReport& report) {
    return report.historical_trust_used ||
           report.timestamp_status == "timestamp-partial" ||
           report.trust_status == "timestamp-not-fully-validated" ||
           report.trust_status == "ocsp-responder-unavailable" ||
           report.trust_status == "tsp-responder-unavailable" ||
           (EffectiveRevocationChecked(report) && report.revocation_status != "valid" &&
            report.revocation_status != "good" && report.revocation_status != "revoked" &&
            report.revocation_status != "invalid");
}

const char* FirstPolicyWarningCode(const VerifyReport& report) {
    if (report.historical_trust_used) return "HISTORICAL_TRUST_USED";
    if (report.trust_status == "timestamp-not-fully-validated" || report.timestamp_status == "timestamp-partial")
        return "TIMESTAMP_NOT_FULLY_VALIDATED";
    if (report.trust_status == "ocsp-responder-unavailable" || report.trust_status == "tsp-responder-unavailable") {
        return "ONLINE_SERVICE_UNAVAILABLE";
    }
    return "REVOCATION_STATUS_UNKNOWN";
}

VerifyCheck SummaryCheck(const VerifyReport& report) {
    const VerifyPolicyDecision decision = tamga::core::ComputeVerifyPolicyDecision(report);
    if (!report.has_result) return {"skipped", "NOT_EXECUTED"};
    if (!report.execution_succeeded) return {"invalid", "VERIFICATION_EXECUTION_FAILED"};
    // ADR-029: структурно поламаний контейнер перевіряється ПЕРЕД підписом.
    //
    // Порядок тут і є змістом. Обидва сусідні коди для цього випадку —
    // неправда: `SIGNATURE_INVALID` каже «криптографія не зійшлася», хоча до
    // неї не дійшло, а `VERIFICATION_EXECUTION_FAILED` каже «не вдалося
    // завершити», що звучить як збій інфраструктури й провокує повтор спроби.
    // Доти два шляхи одного формату ASiC-E давали різну з цих двох неправд:
    // CAdES — першу, XAdES — другу.
    if (report.container_malformed) {
        return {"invalid", "CONTAINER_MALFORMED"};
    }
    if (!report.signature_valid) return {"invalid", "SIGNATURE_INVALID"};
    // К-01: покриття документа підписом — окреме твердження від криптографічної
    // цілісності, і саме воно раніше нікуди не впливало: `container_coverage_complete`
    // лише виводилось у JSON. Через це PDF із дописаними після підпису байтами
    // і ASiC-E з непокритим файлом давали той самий summary, що й недоторканий
    // документ.
    //
    // Правило спільне для PAdES і ASiC-E: якщо частина вмісту не покрита жодним
    // підписом, документ у цілому не є валідно підписаним, хай навіть сам підпис
    // криптографічно бездоганний.
    if (!report.container_coverage_complete) {
        return {"invalid", "CONTAINER_COVERAGE_INCOMPLETE"};
    }
    if (decision.valid) {
        return HasPolicyWarning(report)
            ? VerifyCheck{"warning", "SIGNATURE_VALID_WITH_WARNINGS"}
            : VerifyCheck{"valid", "SIGNATURE_VALID"};
    }
    // П-02: «перевірку НЕ ЗАВЕРШЕНО» і «перевірку завершено, і вона ВІДМОВИЛА»
    // — різні відповіді, і підсумок мусить їх розрізняти.
    //
    // Доти сюди провалювалась будь-яка невдача політики й отримувала
    // {"warning","SIGNATURE_INTEGRITY_ONLY"}, повідомлення до якого каже
    // «повна перевірка політики не завершена». Для відкликаного сертифіката
    // вона завершена — і дала відмову. Аудит 2026-08-29 виміряв наслідок:
    // відкликаний сертифікат, прострочений і просто ненаcтроєний довірчий
    // список були нерозрізнимі за `summary.status`/`summary.code`. Інтеграція
    // 1С, що читає `summary.status` — спосіб, який рекомендує
    // `docs/user-guide.md`, — бачила «попередження» там, де сертифікат
    // ВІДКЛИКАНО.
    //
    // Розрізнення вже існувало в `summaryCode` (`integrity-but-revoked` проти
    // `integrity-without-trust-store`), але жоден інтегратор не зобовʼязаний
    // читати третє поле, щоб дізнатися, що документ відхилено.
    //
    // Межа проведена за наявністю ДОКАЗУ відмови, а не за «щось пішло не так»:
    // нижче лише ті стани, у яких перевірка виконалась і винесла негативний
    // вердикт. Стани «не було чим перевіряти» (`trust-store-empty`,
    // `certificate-chain-incomplete`) і «сервіс не відповів»
    // (`*-responder-unavailable`, `timestamp-not-fully-validated`) свідомо
    // лишаються `warning` — інакше штатний сценарій без налаштованого
    // довірчого списку почав би виглядати як підробка.
    if (report.revocation_status == "revoked" || report.trust_status == "certificate-revoked") {
        return {"invalid", "CERTIFICATE_REVOKED"};
    }
    if (report.trust_status == "certificate-time-invalid" ||
        report.trust_status == "certificate-chain-time-invalid") {
        return {"invalid", "CERTIFICATE_INVALID_AT_VALIDATION_TIME"};
    }
    if (report.trust_status == "revocation-check-invalid" ||
        report.trust_status == "ocsp-response-invalid") {
        return {"invalid", "REVOCATION_INVALID"};
    }
    if (report.trust_status == "timestamp-invalid" || report.timestamp_status == "timestamp-invalid") {
        return {"invalid", "TIMESTAMP_INVALID"};
    }
    return {"warning", "SIGNATURE_INTEGRITY_ONLY"};
}

VerifyCheck SignatureCheck(const VerifyReport& report) {
    if (!report.has_result) return {"skipped", "SIGNATURE_NOT_CHECKED"};
    if (!report.execution_succeeded) return {"unavailable", "SIGNATURE_CHECK_UNAVAILABLE"};
    return report.signature_valid
        ? VerifyCheck{"valid", "SIGNATURE_CRYPTOGRAPHICALLY_VALID"}
        : VerifyCheck{"invalid", "SIGNATURE_CRYPTOGRAPHICALLY_INVALID"};
}

VerifyCheck CertificateCheck(const VerifyReport& report) {
    if (!report.has_result) return {"skipped", "CERTIFICATE_NOT_CHECKED"};
    if (!report.signer_certificate_present) return {"unavailable", "SIGNER_CERTIFICATE_MISSING"};
    return EffectiveCertificateTimeValid(report)
        ? VerifyCheck{"valid", "CERTIFICATE_VALID_AT_VALIDATION_TIME"}
        : VerifyCheck{"invalid", "CERTIFICATE_INVALID_AT_VALIDATION_TIME"};
}

VerifyCheck TrustCheck(const VerifyReport& report) {
    if (!report.trust_checked) return {"skipped", "TRUST_NOT_CHECKED"};
    if (report.trust_valid) {
        return report.historical_trust_used
            ? VerifyCheck{"warning", "TRUST_VALID_HISTORICAL"}
            : VerifyCheck{"valid", "TRUST_VALID"};
    }
    return {"invalid", "TRUST_INVALID"};
}

VerifyCheck RevocationCheck(const VerifyReport& report) {
    if (!EffectiveRevocationChecked(report)) return {"skipped", "REVOCATION_NOT_CHECKED"};
    if (report.revocation_status == "valid" || report.revocation_status == "good") return {"valid", "REVOCATION_VALID"};
    if (report.revocation_status == "revoked") return {"invalid", "CERTIFICATE_REVOKED"};
    if (report.revocation_status == "invalid") return {"invalid", "REVOCATION_INVALID"};
    if (report.revocation_status == "temporarily-unavailable") return {"unavailable", "REVOCATION_UNAVAILABLE"};
    return {"unknown", "REVOCATION_UNKNOWN"};
}

VerifyCheck TimestampCheck(const VerifyReport& report) {
    if (!report.timestamp_checked) return {"skipped", "TIMESTAMP_NOT_CHECKED"};
    // В-03: частковий статус перевіряється ПЕРШИМ. Раніше гілка `timestamp_valid`
    // стояла вище, тож форматний крипто-результат перекривав будь-яку ознаку
    // того, що довіру до TSA не перевіряли.
    if (report.timestamp_status == "timestamp-partial" ||
        report.trust_status == "timestamp-not-fully-validated") {
        return {"warning", "TIMESTAMP_NOT_FULLY_VALIDATED"};
    }
    if (report.timestamp_valid) return {"valid", "TIMESTAMP_VALID"};
    return {"invalid", "TIMESTAMP_INVALID"};
}

// HI-02: "valid"-verdict (людський/policy-рівневий висновок) вимагає
// `ltv_evidence_validated` (докази прив'язані І trust-ланцюг довірений
// І відкликання підтверджено), а не лише структурний `ltv_valid`. Сирий
// `ltv_valid`/`ltvValid` у JSON НЕ змінюється — зберігається зворотна
// сумісність для інтеграторів, які читають його як «докази структурно є».
VerifyCheck LtvCheck(const VerifyReport& report) {
    if (LtvFullyValidated(report)) return {"valid", "LTV_VALID"};
    if (report.signature_format == "XAdES" || report.signature_format == "PAdES") {
        return {"unavailable", "LTV_EVIDENCE_UNAVAILABLE"};
    }
    return {"skipped", "LTV_NOT_APPLICABLE"};
}

bool LtvFullyValidated(const VerifyReport& report) {
    if (!report.ltv_evidence_validated || !report.timestamp_valid) return false;
    for (const auto& signer : report.signatures) {
        if (!signer.ltv_evidence_validated) return false;
    }
    return true;
}

VerifyCheck PolicyCheck(const VerifyReport& report) {
    const VerifyPolicyDecision decision = tamga::core::ComputeVerifyPolicyDecision(report);
    if (decision.valid) {
        return HasPolicyWarning(report)
            ? VerifyCheck{"warning", FirstPolicyWarningCode(report)}
            : VerifyCheck{"valid", "POLICY_VALID"};
    }
    return report.has_result
        ? VerifyCheck{"invalid", "POLICY_INVALID"}
        : VerifyCheck{"skipped", "POLICY_NOT_EVALUATED"};
}

} // namespace tamga::core::policy
