// Перевірка CMS/CAdES-підпису: розбір SignedData, покриття всіх SignerInfo,
// оцінка вбудованого ланцюга сертифікатів.
//
// Виділено з CryptoniteAdapter.cpp (O-01): VerifyDetached / VerifyAttached /
// VerifyHash.

#include "core/cryptonite/CertUtil.h"
#include "core/cryptonite/Internal.h"

namespace tamga::core {

// Внутрішні помічники реалізації видимі без кваліфікації: код перенесено з
// CryptoniteAdapter.cpp без єдиної правки тіл функцій, тому директива тут
// свідома — вона обмежена цим TU і не впливає на публічний контракт.
using namespace cryptonite_detail;

namespace {
#if TAMGA_CRYPTONITE_ENABLED

int ExtractSignerCertificate(const SignedData_t* signed_data, int signer_index, Certificate_t** certificate) {
    *certificate = nullptr;

    SignerInfo_t* signer_info_raw = nullptr;
    int rc = sdata_get_signer_info_by_idx(signed_data, signer_index, &signer_info_raw);
    ScopedSignerInfo signer_info(signer_info_raw, sinfo_free);
    if (rc != RET_OK) {
        return rc;
    }

    SignerIdentifier_t* signer_id_raw = nullptr;
    rc = sinfo_get_signer_id(signer_info.get(), &signer_id_raw);
    ScopedSignerIdentifier signer_id(signer_id_raw, FreeSignerIdentifier);
    if (rc != RET_OK) {
        return rc;
    }

    CertificateSet_t* certs_raw = nullptr;
    rc = sdata_get_certs(signed_data, &certs_raw);
    ScopedCertificateSet certs(certs_raw, FreeCertificateSet);
    if (rc != RET_OK || certs == nullptr) {
        return (rc == RET_OK) ? RET_PKIX_NO_CERTIFICATE : rc;
    }

    rc = get_cert_by_sid_and_usage(signer_id.get(), KEY_USAGE_DIGITAL_SIGNATURE, certs.get(), certificate);
    if (rc != RET_OK || *certificate == nullptr) {
        cert_free(*certificate);
        *certificate = nullptr;
        rc = get_cert_by_sid_and_usage(signer_id.get(), 0, certs.get(), certificate);
    }
    return rc;
}

void EvaluateEmbeddedChainPolicy(const Certificate_t* signer_certificate,
                                 const CertificateSet_t* certs,
                                 VerifyPolicyInfo& policy_info) {
    ResetPolicyInfo(policy_info);
    policy_info.trust_checked = true;
    policy_info.policy = "crypto-integrity-plus-embedded-chain";
    policy_info.trust_status = "signer-certificate-missing";
    policy_info.signer_certificate_present = signer_certificate != nullptr;

    if (signer_certificate == nullptr) {
        policy_info.message = "Signature integrity verified, but signer certificate is missing in CMS container.";
        return;
    }

    if (cert_check_validity(signer_certificate) != RET_OK) {
        policy_info.certificate_time_valid = false;
        policy_info.chain_checked = true;
        policy_info.chain_valid = false;
        policy_info.trust_status = "certificate-time-invalid";
        policy_info.message = "Signature integrity verified, but signer certificate is outside its validity period.";
        return;
    }

    policy_info.certificate_time_valid = true;
    policy_info.chain_checked = true;

    const Certificate_t* current = signer_certificate;
    std::vector<const Certificate_t*> visited;
    visited.reserve(certs == nullptr ? 1U : static_cast<std::size_t>(certs->list.count) + 1U);
    visited.push_back(current);

    for (int depth = 0; depth <= (certs == nullptr ? 0 : certs->list.count); ++depth) {
        if (IsCertificateSelfSigned(current)) {
            policy_info.chain_valid = true;
            policy_info.trust_valid = false;
            policy_info.trust_status = "no-trust-store-configured";
            policy_info.message =
                "Signature integrity verified. Embedded certificate chain is structurally valid, but trust-store validation is not configured.";
            return;
        }

        const Certificate_t* issuer = FindIssuerCertificate(current, certs, visited);
        if (issuer == nullptr) {
            policy_info.chain_valid = false;
            policy_info.trust_valid = false;
            policy_info.trust_status = "certificate-chain-incomplete";
            policy_info.message =
                "Signature integrity verified, but embedded certificate chain is incomplete or does not end in a self-signed issuer.";
            return;
        }

        if (cert_check_validity(issuer) != RET_OK) {
            policy_info.certificate_time_valid = false;
            policy_info.chain_valid = false;
            policy_info.trust_valid = false;
            policy_info.trust_status = "certificate-chain-time-invalid";
            policy_info.message =
                "Signature integrity verified, but one of the embedded issuer certificates is outside its validity period.";
            return;
        }

        visited.push_back(issuer);
        current = issuer;
    }

    policy_info.chain_valid = false;
    policy_info.trust_valid = false;
    policy_info.trust_status = "certificate-chain-cycle";
    policy_info.message =
        "Signature integrity verified, but embedded certificate chain contains a loop or exceeds expected depth.";
}

// Мультипідпис CMS: перевіряє РІВНО одного підписанта за індексом.
//
// Раніше VerifyCms брав лише SignerInfo[0], тож для контейнера з кількома
// підписантами (звична форма українського документообігу: один `.p7s` з
// підписами кількох сторін — Вчасно, M.E.Doc) вердикт стосувався одного
// підписанта з N, а решта не перевірялась взагалі. Це той самий клас
// хибнопозитиву, який HI-01 закрив для XAdES.
//
// Кожен підписант має власні verify/digest адаптери, бо вони будуються з його
// сертифіката (різні КНЕДП — різні алгоритми й параметри).
// Повертає RET_OK, якщо перевірку ВИКОНАНО; фактичний результат — у out_valid.
int VerifyCmsSignerAt(const SignedData_t* signed_data,
                      const int signer_index,
                      const ByteArray* external_data_ba,
                      bool& out_valid,
                      std::vector<std::uint8_t>& out_certificate_der,
                      std::string& error_message) {
    out_valid = false;
    out_certificate_der.clear();

    Certificate_t* signer_certificate_raw = nullptr;
    int rc = ExtractSignerCertificate(signed_data, signer_index, &signer_certificate_raw);
    ScopedCert signer_certificate(signer_certificate_raw, cert_free);
    if (rc != RET_OK || signer_certificate == nullptr) {
        error_message = BuildRcError("signer certificate resolution",
                                     rc == RET_OK ? RET_PKIX_NO_CERTIFICATE : rc);
        return rc == RET_OK ? RET_PKIX_NO_CERTIFICATE : rc;
    }

    VerifyAdapter* verify_adapter_raw = nullptr;
    rc = verify_adapter_init_by_cert(signer_certificate.get(), &verify_adapter_raw);
    ScopedVerifyAdapter verify_adapter(verify_adapter_raw, verify_adapter_free);
    if (rc != RET_OK) {
        error_message = BuildRcError("verify adapter initialization", rc);
        return rc;
    }

    // Дайджест беремо з SignerInfo.digestAlgorithm, а НЕ з сертифіката.
    //
    // digest_adapter_init_by_cert виводить хеш із алгоритму, яким CA підписав
    // сертифікат. Для українських КЕП це дає хибний результат: сертифікати Дія
    // підписані ДСТУ 4145 з ГОСТ 34.311 (1.2.804.2.1.1.1.1.3.1.1), а сам документ
    // може бути підписаний Купиною (digestAlgorithm 1.2.804.2.1.1.1.1.2.2.1).
    // Тоді cryptonite рахував ГОСТ там, де підпис вимагає Купину, і валідний
    // PAdES/CMS відхилявся. Це той самий клас дефекту, який уже виправлено для
    // XAdES (ShouldUseCertificateAdapter): оголошений алгоритм є нормативним,
    // сертифікат — лише запасний шлях, коли алгоритм невідомий.
    ScopedDigestAdapter digest_adapter(nullptr, digest_adapter_free);
    {
        SignerInfo_t* sinfo_for_digest_raw = nullptr;
        const int sinfo_rc =
            sdata_get_signer_info_by_idx(signed_data, signer_index, &sinfo_for_digest_raw);
        // sdata_get_signer_info_by_idx повертає власну копію. Раніше вона
        // звільнялася вручну в кінці блоку — саме тут і був витік, який довелося
        // виправляти окремо. Тепер звільнення прив'язане до області видимості.
        ScopedSignerInfo sinfo_for_digest(sinfo_for_digest_raw, sinfo_free);

        DigestAdapter* digest_adapter_raw = nullptr;
        if (sinfo_rc == RET_OK && sinfo_for_digest != nullptr) {
            rc = digest_adapter_init_by_aid(&sinfo_for_digest->digestAlgorithm, &digest_adapter_raw);
        } else {
            rc = RET_INVALID_PARAM;
        }
        digest_adapter.reset(digest_adapter_raw);
        if (rc != RET_OK || digest_adapter == nullptr) {
            // Запасний шлях: алгоритм із SignerInfo не розпізнано — пробуємо
            // вивести його із сертифіката (історична поведінка).
            //
            // reset() тут не лише обнуляє, а й ЗВІЛЬНЯЄ часткову алокацію: якщо
            // init_by_aid повернув помилку, але встиг віддати ненульовий адаптер,
            // старий код просто перезаписував вказівник і губив його.
            digest_adapter.reset();
            digest_adapter_raw = nullptr;
            rc = digest_adapter_init_by_cert(signer_certificate.get(), &digest_adapter_raw);
            digest_adapter.reset(digest_adapter_raw);
        }

        // Той самий принцип — і для ВЕРИФІКАЦІЙНОГО адаптера.
        //
        // digest_adapter відповідає лише за звірку messageDigest із вмістом.
        // Підпис же рахується над signedAttrs всередині verify-адаптера, а той
        // будується з сертифіката й для ДСТУ 4145 беззастережно брав ГОСТ 34.311.
        // Для документів Дія (сертифікат на ГОСТ-і, документ підписаний Купиною)
        // це давало хибнонегатив уже після того, як messageDigest збігся.
        // За RFC 5652 нормативне джерело — SignerInfo.digestAlgorithm, тож
        // прокидаємо його у verify-адаптер. Помилку не вважаємо фатальною:
        // якщо дайджест не підтримується, лишається поведінка за сертифікатом.
        if (sinfo_for_digest != nullptr && verify_adapter != nullptr &&
            verify_adapter->set_digest_alg != nullptr) {
            (void)verify_adapter->set_digest_alg(verify_adapter.get(),
                                                 &sinfo_for_digest->digestAlgorithm);
        }
    }
    if (rc != RET_OK) {
        error_message = BuildRcError("digest adapter initialization", rc);
        return rc;
    }

    if (external_data_ba != nullptr) {
        rc = sdata_verify_external_data_by_adapter(signed_data, digest_adapter.get(),
                                                   verify_adapter.get(), external_data_ba,
                                                   signer_index);
    } else {
        rc = sdata_verify_internal_data_by_adapter(signed_data, digest_adapter.get(),
                                                   verify_adapter.get(), signer_index);
    }

    if (rc == RET_OK) {
        out_valid = true;
        EncodeCertificateDer(signer_certificate.get(), out_certificate_der);
        error_message.clear();
    } else if (IsIntegrityFailureRc(rc)) {
        // Цілісність не підтверджена — це НЕ помилка виконання: сертифікат
        // повертаємо, щоб звіт міг показати, ЧИЙ саме підпис не пройшов.
        out_valid = false;
        EncodeCertificateDer(signer_certificate.get(), out_certificate_der);
        error_message.clear();
        rc = RET_OK;
    } else {
        error_message = BuildRcError(external_data_ba != nullptr
                                         ? "detached signature verification"
                                         : "attached signature verification", rc);
    }
    return rc;
}

bool VerifyCms(const std::vector<std::uint8_t>* external_data,
               const std::vector<std::uint8_t>& signature,
               bool& is_valid,
               std::vector<std::uint8_t>* internal_content,
               VerifyPolicyInfo* policy_info,
               std::string& error_message) {
    // EvaluateEmbeddedChainPolicy нижче викликає ResetPolicyInfo (policy_info = {}),
    // тому per-signer результати не можна писати в policy_info до неї — вони
    // накопичуються тут і переносяться після.
    std::vector<CmsSignerResult> signer_results;
    int signer_total_found = 0;

    is_valid = false;
    if (policy_info != nullptr) {
        ResetPolicyInfo(*policy_info);
    }
    if (internal_content != nullptr) {
        internal_content->clear();
    }

    ScopedByteArray signature_ba(MakeByteArray(signature), ba_free);
    if (signature_ba == nullptr) {
        error_message = "Unable to allocate cryptonite ByteArray for signature";
        return false;
    }

    ScopedContentInfo content_info(cinfo_alloc(), cinfo_free);
    if (content_info == nullptr) {
        error_message = "Unable to allocate ContentInfo";
        return false;
    }

    int rc = cinfo_decode(content_info.get(), signature_ba.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("ContentInfo decoding", rc);
        return false;
    }

    SignedData_t* signed_data_raw = nullptr;
    rc = cinfo_get_signed_data(content_info.get(), &signed_data_raw);
    ScopedSignedData signed_data(signed_data_raw, sdata_free);
    if (rc != RET_OK || signed_data == nullptr) {
        error_message = BuildRcError("SignedData extraction", rc == RET_OK ? RET_PKIX_CINFO_NOT_SIGNED_DATA : rc);
        return false;
    }

    CertificateSet_t* certificates_raw = nullptr;
    rc = sdata_get_certs(signed_data.get(), &certificates_raw);
    ScopedCertificateSet certificates(certificates_raw, FreeCertificateSet);
    if (rc != RET_OK) {
        error_message = BuildRcError("certificate set extraction", rc);
        return false;
    }

    // Репрезентативний сертифікат (SignerInfo[0]) лишаємо для сумісності полів
    // policy_info.signer_certificate_der / метаданих підписанта у звіті.
    Certificate_t* signer_certificate_raw = nullptr;
    rc = ExtractSignerCertificate(signed_data.get(), 0, &signer_certificate_raw);
    ScopedCert signer_certificate(signer_certificate_raw, cert_free);
    if (rc != RET_OK || signer_certificate == nullptr) {
        error_message = BuildRcError("signer certificate resolution", rc == RET_OK ? RET_PKIX_NO_CERTIFICATE : rc);
        return false;
    }

    // Distinguish "execution failed" (CMS decoding, adapter init, allocation errors) from
    // "integrity failed" (signature does not match). The latter is the documented output of
    // VerifyData / VerifyDataInternal: the call completes successfully with is_valid == false.
    // The authoritative list of integrity-failure rc codes lives in IntegrityFailureRcCodes()
    // at the top of this translation unit so that new upstream codes are added in one place.

    ScopedByteArray data_ba(external_data != nullptr ? MakeByteArray(*external_data) : nullptr, ba_free);
    if (external_data != nullptr && data_ba == nullptr) {
        error_message = "Unable to allocate cryptonite ByteArray for detached data";
        return false;
    }

    // ── Мультипідпис CMS: перевіряємо КОЖНОГО підписанта, вердикт — AND ──────
    // До цього перевірявся лише SignerInfo[0], і зламаний другий підпис давав
    // загальний ACCEPTED. Тепер signature_valid = AND по всіх підписантах, а
    // per-signer результати їдуть у звіт (policy_info->signers).
    {
        int signer_total = 1;
        SignerInfos_t* all_signers_raw = nullptr;
        const int signers_rc = sdata_get_signer_infos(signed_data.get(), &all_signers_raw);
        ScopedSignerInfos all_signers(all_signers_raw, FreeSignerInfos);
        if (signers_rc == RET_OK && all_signers != nullptr) {
            signer_total = static_cast<int>(all_signers->list.count);
        }
        if (signer_total < 1) {
            error_message = BuildRcError("SignedData has no signers", RET_PKIX_SDATA_NO_SIGNERS);
            return false;
        }

        bool all_signers_valid = true;
        int verified = 0;
        for (int idx = 0; idx < signer_total; ++idx) {
            bool signer_valid = false;
            std::vector<std::uint8_t> signer_cert_der;
            std::string signer_error;
            const int signer_rc = VerifyCmsSignerAt(signed_data.get(), idx,
                                                    external_data != nullptr ? data_ba.get() : nullptr,
                                                    signer_valid, signer_cert_der, signer_error);
            if (signer_rc != RET_OK) {
                // Помилка ВИКОНАННЯ (декодування/адаптер) — не «підпис невалідний».
                // Вердикт беремо з error_message, як і раніше: якщо VerifyCmsSignerAt
                // повернув помилку без тексту, це лишається «виконано» — поведінку
                // тут свідомо не змінюємо.
                error_message = signer_error;
                return error_message.empty();
            }
            ++verified;
            all_signers_valid = all_signers_valid && signer_valid;
            CmsSignerResult entry;
            entry.index = idx + 1;  // 1-based, як у signatures[] звіту
            entry.signature_valid = signer_valid;
            entry.certificate_der = std::move(signer_cert_der);
            signer_results.push_back(std::move(entry));
        }
        signer_total_found = signer_total;
        if (!all_signers_valid) {
            // Хоча б один підпис не пройшов — контейнер невалідний цілком.
            // Per-signer результати переносимо і тут: інакше на відмові звіт не
            // сказав би, ЧИЙ саме підпис упав, а видимість цього — сама суть зміни.
            // EvaluateEmbeddedChainPolicy (з її ResetPolicyInfo) на цьому шляху не
            // виконується, тому запис безпечний.
            if (policy_info != nullptr) {
                policy_info->signer_count = signer_total;
                policy_info->verified_signer_count = static_cast<int>(signer_results.size());
                policy_info->signers = std::move(signer_results);
            }
            is_valid = false;
            // Виконання пройшло успішно — невалідним є ПІДПИС, не виклик.
            // Тому true, а не false: саме це розрізнення читає Session.
            error_message.clear();
            return true;
        }
    }

    if (external_data == nullptr) {
        ByteArray* internal_ba_raw = nullptr;
        rc = sdata_get_data(signed_data.get(), &internal_ba_raw);
        ScopedByteArray internal_ba(internal_ba_raw, ba_free);
        if (rc != RET_OK && rc != RET_PKIX_SDATA_NO_CONTENT) {
            error_message = BuildRcError("attached payload extraction", rc);
            return false;
        }
        if (internal_ba != nullptr && internal_content != nullptr) {
            AssignFromByteArray(internal_ba.get(), *internal_content);
        }
    }

    is_valid = true;
    if (policy_info != nullptr) {
        EvaluateEmbeddedChainPolicy(signer_certificate.get(), certificates.get(), *policy_info);
        EncodeCertificateDer(signer_certificate.get(), policy_info->signer_certificate_der);
        CollectEmbeddedCertificatesDer(certificates.get(), policy_info->embedded_certificates_der);
        // Після ResetPolicyInfo у EvaluateEmbeddedChainPolicy — переносимо
        // накопичені per-signer результати.
        policy_info->signer_count = signer_total_found;
        policy_info->verified_signer_count = static_cast<int>(signer_results.size());
        policy_info->signers = std::move(signer_results);
    }
    error_message.clear();
    return true;
}

#endif  // TAMGA_CRYPTONITE_ENABLED
}  // namespace

bool CryptoniteAdapter::VerifyDetached(const std::vector<std::uint8_t>& data,
                                       const std::vector<std::uint8_t>& signature,
                                       bool& is_valid,
                                       VerifyPolicyInfo& policy_info,
                                       std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    return VerifyCms(&data, signature, is_valid, nullptr, &policy_info, error_message);
#else
    (void)data;
    (void)signature;
    is_valid = false;
    ResetPolicyInfo(policy_info);
    error_message = BuildDisabledError();
    return false;
#endif
}

bool CryptoniteAdapter::VerifyAttached(const std::vector<std::uint8_t>& signed_data,
                                       bool& is_valid,
                                       std::vector<std::uint8_t>& content,
                                       VerifyPolicyInfo& policy_info,
                                       std::string& error_message) {
#if TAMGA_CRYPTONITE_ENABLED
    return VerifyCms(nullptr, signed_data, is_valid, &content, &policy_info, error_message);
#else
    (void)signed_data;
    is_valid = false;
    content.clear();
    ResetPolicyInfo(policy_info);
    error_message = BuildDisabledError();
    return false;
#endif
}

bool CryptoniteAdapter::VerifyHash(const std::vector<std::uint8_t>& certificate_der,
                                   const std::vector<std::uint8_t>& hash,
                                   const std::vector<std::uint8_t>& signature,
                                   bool& is_valid,
                                   std::string& error_message) {
    is_valid = false;
#if TAMGA_CRYPTONITE_ENABLED
    ScopedByteArray cert_ba(MakeByteArray(certificate_der), ba_free);
    ScopedCert cert(cert_alloc(), cert_free);
    if (cert_ba == nullptr || cert == nullptr) {
        error_message = BuildRcError("certificate byte array", RET_MEMORY_ALLOC_ERROR);
        return false;
    }

    int rc = cert_decode(cert.get(), cert_ba.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("certificate decode", rc);
        return false;
    }

    VerifyAdapter* verify_adapter_raw = nullptr;
    rc = verify_adapter_init_by_cert(cert.get(), &verify_adapter_raw);
    ScopedVerifyAdapter verify_adapter(verify_adapter_raw, verify_adapter_free);
    if (rc != RET_OK || verify_adapter == nullptr) {
        error_message = BuildRcError("verify adapter init", rc);
        return false;
    }

    if (verify_adapter->verify_hash == nullptr) {
        error_message = "Верифікатор не підтримує verify_hash";
        return false;
    }

    ScopedByteArray hash_ba(MakeByteArray(hash), ba_free);
    ScopedByteArray sign_ba(MakeByteArray(signature), ba_free);
    if (hash_ba == nullptr || sign_ba == nullptr) {
        error_message = BuildRcError("verify byte arrays", RET_MEMORY_ALLOC_ERROR);
        return false;
    }

    // verify_hash повертає RET_OK для коректного підпису; інакше — некоректний
    // (це не помилка операції). Операція виконалась, тож повертаємо true.
    rc = verify_adapter->verify_hash(verify_adapter.get(), hash_ba.get(), sign_ba.get());
    is_valid = (rc == RET_OK);
    return true;
#else
    (void)certificate_der;
    (void)hash;
    (void)signature;
    error_message = BuildDisabledError();
    return false;
#endif
}

}  // namespace tamga::core
