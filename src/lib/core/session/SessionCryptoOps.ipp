bool Session::SignData(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& signature) {
    return SignData(data, signature, TimestampMode::BestEffort);
}

bool Session::SignData(const std::vector<std::uint8_t>& data,
                       std::vector<std::uint8_t>& signature,
                       TimestampMode timestamp_mode) {
#if TAMGA_CRYPTONITE_ENABLED
    bool ok = false;
    TspSettings tsp_settings;
    bool offline_mode = false;
    std::vector<std::uint8_t> certificate;
    std::string work_dir;
#endif
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            signature.clear();
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        if (!is_private_key_loaded_) {
            signature.clear();
            SetError(ErrorCode::KeyNotLoaded, ToString(ErrorCode::KeyNotLoaded));
            return false;
        }

#if TAMGA_CRYPTONITE_ENABLED
        std::string error_message;
        ok = CryptoniteAdapter::SignDetached(loaded_key_format_ == KeyFormat::Pkcs12,
                                             loaded_key_material_,
                                             loaded_certificate_,
                                             loaded_key_password_,
                                             data,
                                             signature,
                                             error_message);
        if (!ok) {
            signature.clear();
            SetError(ErrorCode::InternalError, std::move(error_message));
            return false;
        }
        tsp_settings = tsp_settings_;
        offline_mode = settings_.offline_mode;
        certificate = loaded_certificate_;
        work_dir = settings_.work_dir;
#else
        (void)data;
        (void)timestamp_mode;
        signature.clear();
        SetError(ErrorCode::NotSupported, kCryptoniteRequiredMessage);
        return false;
#endif
    }

#if TAMGA_CRYPTONITE_ENABLED
    WriteTspTraceBinary("signature_before_tsp.bin", signature);
    if (timestamp_mode == TimestampMode::Disabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearError();
        return true;
    }

    std::string tsp_url = tsp_settings.url;
    if (tsp_url.empty()) {
        tsp_url = ResolveDefaultTspUrlCombined(certificate, work_dir);
    }
    if (!tsp_url.empty() && tsp_settings.url.empty() && !offline_mode) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tsp_settings_.url.empty()) {
            tsp_settings_.url = tsp_url;
        }
    }
    if (!tsp_url.empty() && !offline_mode) {
        const bool timestamp_required = timestamp_mode == TimestampMode::Required;
        std::vector<std::uint8_t> sig_val;
        std::string err;
        if (CryptoniteAdapter::GetSignatureValue(signature, sig_val, err)) {
            ImprintResult imprint;
            std::string imprint_err;
            if (ResolveTspImprint(tsp_settings, sig_val, signature, imprint, imprint_err)) {
                std::vector<std::uint8_t> tsp_token;
                std::string tsp_err;
                bool tsp_ok = TspClient::GetTimestamp(imprint.hash, imprint.digest_oid, tsp_url, tsp_settings.timeout_ms, tsp_settings.policy_oid, tsp_token, tsp_err);
                if (tsp_ok) {
                    std::vector<std::uint8_t> cms_with_tsp;
                    std::lock_guard<std::mutex> lock(mutex_);
                    bool append_ok = CryptoniteAdapter::AppendTspToken(signature, tsp_token, cms_with_tsp, err);
                    if (append_ok) {
                        WriteTspTraceBinary("signature_with_tsp.bin", cms_with_tsp);
                        signature = std::move(cms_with_tsp);
                        // TSP успішний — скидаємо будь-яку попередню помилку
                        ClearError();
                    } else {
                        SetError(ErrorCode::OnlineServiceUnavailable,
                                 "TSP [" + tsp_url + "]: AppendTspToken failed: " + err);
                        if (timestamp_required) {
                            signature.clear();
                            return false;
                        }
                        ClearError();
                    }
                    return true;
                } else {
                    std::lock_guard<std::mutex> lock(mutex_);
                    SetError(ErrorCode::OnlineServiceUnavailable,
                             "TSP [" + tsp_url + "]: " + tsp_err);
                    if (timestamp_required) {
                        signature.clear();
                        return false;
                    }
                }
            } else {
                std::lock_guard<std::mutex> lock(mutex_);
                SetError(ErrorCode::OnlineServiceUnavailable,
                         "TSP: ResolveTspImprint failed: " + imprint_err);
                if (timestamp_required) {
                    signature.clear();
                    return false;
                }
            }
        } else {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::OnlineServiceUnavailable,
                     "TSP: GetSignatureValue failed: " + err);
            if (timestamp_required) {
                signature.clear();
                return false;
            }
        }
    } else {
        std::lock_guard<std::mutex> lock(mutex_);
        if (timestamp_mode == TimestampMode::Required) {
            SetError(ErrorCode::OnlineServiceUnavailable,
                     offline_mode ? "TSP unavailable in offline mode" : "TSP URL is not configured");
            signature.clear();
            return false;
        }
        ClearError();
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearError();
    }
#else
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearError();
    }
#endif
    return true;
}

bool Session::VerifyData(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& signature, bool& is_valid) {
    is_valid = false;

    // ME-04 (звуження critical section): той самий патерн, що вже застосований
    // у VerifyXml (WP-17) і VerifyPdf (PAdES-фікс) — mutex_ тримається лише для
    // (1) початкової перевірки стану + знімка Settings/OcspSettings і (2)
    // фінального коміту результату; CMS-парсинг і мережевий OCSP/CRL/AIA/chain
    // trust pipeline (ValidationEngine::Validate) працюють з ЛОКАЛЬНИМ станом,
    // без lock_guard. На відміну від VerifyXml/VerifyPdf, тут явно
    // викликається RefreshUserReportForCurrentOperation() у фінальному lock —
    // VerifyData і раніше оновлював last_user_report_json_ на кожен виклик, і
    // ця поведінка мусить лишитись незмінною.
    Settings local_settings;
    OcspSettings local_ocsp_settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            SetVerifyReport("VerifyData", false, false, ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        local_settings = settings_;
        local_ocsp_settings = ocsp_settings_;
    }

#if TAMGA_CRYPTONITE_ENABLED
    VerifyPolicyInfo policy_info;
    std::string error_message;
    if (!CryptoniteAdapter::VerifyDetached(data, signature, is_valid, policy_info, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyData", false, false, ErrorCode::InvalidArgument, error_message);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }

    // Будується у ЛОКАЛЬНОМУ report — жодних звернень до last_verify_report_
    // до фінального коміту нижче (той самий принцип, що VerifyXml/VerifyPdf).
    VerifyReport report;
    report.has_result = true;
    report.execution_succeeded = true;
    report.signature_valid = is_valid;
    report.operation = "VerifyData";
    report.error_code = ErrorCode::None;
    report.message = BuildVerifyMessage(true, is_valid, {});
    // WP-11 (HI-06): signer_certificate_present is a structural fact about the
    // parsed CMS, independent of the trust/revocation decision below — set
    // regardless of is_valid, matching the previous ApplyPolicyInfoToVerifyReport
    // behaviour (which ran unconditionally).
    report.signer_certificate_present = policy_info.signer_certificate_present;
    // Мультипідпис CMS: зараз валідується лише SignerInfo[0], тому робимо розрив
    // між кількістю підписантів і кількістю перевірених ЯВНИМ у звіті.
    report.cms_signer_count = policy_info.signer_count;
    report.cms_verified_signer_count = policy_info.verified_signer_count;
    // Мультипідпис CMS: кожен підписант отримує власний запис у signatures[] —
    // той самий масив, який XAdES-шлях наповнює після HI-01. Верхньорівневий
    // report.signature_valid уже є AND-агрегацією (обчислена в VerifyCms), тож
    // зламаний підпис будь-якого співпідписанта робить контейнер невалідним.
    report.signatures.clear();
    report.signatures.reserve(policy_info.signers.size());
    for (const auto& signer : policy_info.signers) {
        SignatureEntry entry;
        entry.index = signer.index;
        entry.signature_valid = signer.signature_valid;
        entry.signer_certificate_present = !signer.certificate_der.empty();
        report.signatures.push_back(std::move(entry));
    }
    CertificateMetadata local_signer_metadata;
    bool have_signer_metadata = false;
    if (!policy_info.signer_certificate_der.empty()) {
        std::string metadata_error;
        if (CryptoniteAdapter::ExtractCertificateMetadata(policy_info.signer_certificate_der,
                                                          local_signer_metadata,
                                                          metadata_error)) {
            have_signer_metadata = true;
        }
    }
    if (is_valid) {
        // WP-11 (HI-06): ValidationEngine is now the ONLY source of trust/
        // revocation/timestamp/certificate-time truth for CMS/CAdES — the
        // legacy ApplyTrustPipelineStatus pipeline (which used to mutate the
        // same VerifyReport fields a second time, independently) is retired.
        validation::ValidationContext ve_ctx;
        if (local_settings.trust_mode == "strict") {
            ve_ctx.profile = validation::ValidationProfile::Strict;
        } else if (local_settings.trust_mode == "ukraine-legal") {
            ve_ctx.profile = validation::ValidationProfile::UkraineLegal;
        } else if (local_settings.trust_mode == "offline") {
            ve_ctx.profile = validation::ValidationProfile::Offline;
        } else if (local_settings.trust_mode == "forensic") {
            ve_ctx.profile = validation::ValidationProfile::Forensic;
        } else {
            ve_ctx.profile = validation::ValidationProfile::Compatibility;
        }
        if (local_settings.validation_level == "basic") {
            ve_ctx.level = validation::ValidationLevel::Basic;
        } else if (local_settings.validation_level == "extended") {
            ve_ctx.level = validation::ValidationLevel::Extended;
        } else if (local_settings.validation_level == "forensic") {
            ve_ctx.level = validation::ValidationLevel::Forensic;
        } else {
            ve_ctx.level = validation::ValidationLevel::Standard;
        }
        ve_ctx.offline  = local_settings.offline_mode;
        ve_ctx.work_dir = local_settings.work_dir;
        ve_ctx.cms_der  = signature;
        ve_ctx.signature_crypto_valid = is_valid;  // F-04: фактичний вердикт VerifyDetached
        if (!local_settings.offline_mode) {
            ve_ctx.ocsp_url = local_ocsp_settings.url;
        }
        {
            std::string claimed_iso;
            if (CryptoniteAdapter::ExtractSigningTime(signature, claimed_iso)) {
                ve_ctx.claimed_signing_time = claimed_iso;  // WP-10: not crypto-proven
            }
        }
        const std::vector<std::vector<std::uint8_t>> embedded_certs =
            EnrichWithAiaIssuersIfNeeded(local_settings.work_dir, local_ocsp_settings.timeout_ms,
                                        !local_settings.offline_mode && local_settings.allow_aia_issuer_fetch,
                                        policy_info.signer_certificate_der,
                                        policy_info.embedded_certificates_der);
        const validation::ValidationReport ve_report =
            validation::ValidationEngine{}.Validate(
                ve_ctx,
                policy_info.signer_certificate_der,
                embedded_certs);
        ApplyValidationEngineReport(ve_report, report);
    }
    if (is_valid && !report.trust_valid && report.trust_checked) {
        report.error_code = TrustFailureErrorCode(report);
    }

    // Фінальний коміт: єдина ділянка, де це знову торкається спільного стану
    // Session, — короткий lock без жодного мережевого виклику під ним.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_verify_report_ = std::move(report);
        // Н-04: фіксуємо епоху цього коміту — доуточнення нижче застосується
        // лише якщо звіт усе ще належить цьому потоку.
        MarkVerifyReportCommittedLocked();
        if (have_signer_metadata) {
            last_signer_metadata_ = std::move(local_signer_metadata);
        }
        RefreshUserReportForCurrentOperation();
        ClearError();
    }
    return true;
#else
    (void)data;
    (void)signature;
    is_valid = false;
    std::lock_guard<std::mutex> lock(mutex_);
    SetVerifyReport("VerifyData", false, false, ErrorCode::NotSupported, kCryptoniteRequiredMessage);
    SetError(ErrorCode::NotSupported, kCryptoniteRequiredMessage);
    return false;
#endif
}

bool Session::SignDataBase64(const std::vector<std::uint8_t>& data, std::string& signature_base64) {
    std::vector<std::uint8_t> signature;
    if (!SignData(data, signature)) {
        return false;
    }
    signature_base64 = util::Base64Encode(signature);
    std::lock_guard<std::mutex> lock(mutex_);
    ClearError();
    return true;
}

bool Session::VerifyDataBase64(const std::vector<std::uint8_t>& data, const std::string& signature_base64, bool& is_valid) {
    std::vector<std::uint8_t> signature;
    if (!util::Base64Decode(signature_base64, signature)) {
        std::lock_guard<std::mutex> lock(mutex_);
        is_valid = false;
        SetVerifyReport("VerifyDataBase64", false, false, ErrorCode::InvalidArgument, "Signature Base64 is invalid");
        SetError(ErrorCode::InvalidArgument, "Signature Base64 is invalid");
        return false;
    }

    const bool result = VerifyData(data, signature, is_valid);
    OverrideVerifyReportOperation("VerifyDataBase64");
    return result;
}

bool Session::SignDataInternal(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& signed_data) {
    return SignDataInternal(data, signed_data, TimestampMode::BestEffort);
}

bool Session::SignDataInternal(const std::vector<std::uint8_t>& data,
                               std::vector<std::uint8_t>& signed_data,
                               TimestampMode timestamp_mode) {
#if TAMGA_CRYPTONITE_ENABLED
    bool ok = false;
    TspSettings tsp_settings;
    bool offline_mode = false;
    std::vector<std::uint8_t> certificate;
    std::string work_dir;
#endif
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            signed_data.clear();
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        if (!is_private_key_loaded_) {
            signed_data.clear();
            SetError(ErrorCode::KeyNotLoaded, ToString(ErrorCode::KeyNotLoaded));
            return false;
        }

#if TAMGA_CRYPTONITE_ENABLED
        std::string error_message;
        ok = CryptoniteAdapter::SignAttached(loaded_key_format_ == KeyFormat::Pkcs12,
                                             loaded_key_material_,
                                             loaded_certificate_,
                                             loaded_key_password_,
                                             data,
                                             signed_data,
                                             error_message);
        if (!ok) {
            signed_data.clear();
            SetError(ErrorCode::InternalError, std::move(error_message));
            return false;
        }
        tsp_settings = tsp_settings_;
        offline_mode = settings_.offline_mode;
        certificate = loaded_certificate_;
        work_dir = settings_.work_dir;
#else
        (void)data;
        (void)timestamp_mode;
        signed_data.clear();
        SetError(ErrorCode::NotSupported, kCryptoniteRequiredMessage);
        return false;
#endif
    }

#if TAMGA_CRYPTONITE_ENABLED
    WriteTspTraceBinary("signature_before_tsp.bin", signed_data);
    if (timestamp_mode == TimestampMode::Disabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearError();
        return true;
    }

    std::string tsp_url = tsp_settings.url;
    if (tsp_url.empty()) {
        tsp_url = ResolveDefaultTspUrlCombined(certificate, work_dir);
    }
    if (!tsp_url.empty() && tsp_settings.url.empty() && !offline_mode) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tsp_settings_.url.empty()) {
            tsp_settings_.url = tsp_url;
        }
    }
    if (!tsp_url.empty() && !offline_mode) {
        const bool timestamp_required = timestamp_mode == TimestampMode::Required;
        std::vector<std::uint8_t> sig_val;
        std::string err;
        if (CryptoniteAdapter::GetSignatureValue(signed_data, sig_val, err)) {
            ImprintResult imprint;
            std::string imprint_err;
            if (ResolveTspImprint(tsp_settings, sig_val, signed_data, imprint, imprint_err)) {
                std::vector<std::uint8_t> tsp_token;
                std::string tsp_err;
                if (TspClient::GetTimestamp(imprint.hash, imprint.digest_oid, tsp_url, tsp_settings.timeout_ms, tsp_settings.policy_oid, tsp_token, tsp_err)) {
                    std::vector<std::uint8_t> cms_with_tsp;
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (CryptoniteAdapter::AppendTspToken(signed_data, tsp_token, cms_with_tsp, err)) {
                        WriteTspTraceBinary("signature_with_tsp.bin", cms_with_tsp);
                        signed_data = std::move(cms_with_tsp);
                        ClearError();
                    } else {
                        SetError(ErrorCode::OnlineServiceUnavailable,
                                 "TSP [" + tsp_url + "]: AppendTspToken failed: " + err);
                        if (timestamp_required) {
                            signed_data.clear();
                            return false;
                        }
                        ClearError();
                    }
                    return true;
                } else {
                    std::lock_guard<std::mutex> lock(mutex_);
                    SetError(ErrorCode::OnlineServiceUnavailable,
                             "TSP [" + tsp_url + "]: " + tsp_err);
                    if (timestamp_required) {
                        signed_data.clear();
                        return false;
                    }
                }
            } else {
                std::lock_guard<std::mutex> lock(mutex_);
                SetError(ErrorCode::OnlineServiceUnavailable,
                         "TSP: ResolveTspImprint failed: " + imprint_err);
                if (timestamp_required) {
                    signed_data.clear();
                    return false;
                }
            }
        } else {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::OnlineServiceUnavailable,
                     "TSP: GetSignatureValue failed: " + err);
            if (timestamp_required) {
                signed_data.clear();
                return false;
            }
        }
    } else {
        std::lock_guard<std::mutex> lock(mutex_);
        if (timestamp_mode == TimestampMode::Required) {
            SetError(ErrorCode::OnlineServiceUnavailable,
                     offline_mode ? "TSP unavailable in offline mode" : "TSP URL is not configured");
            signed_data.clear();
            return false;
        }
        ClearError();
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearError();
    }
#else
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearError();
    }
#endif
    return true;
}


bool Session::VerifyDataInternal(const std::vector<std::uint8_t>& signed_data, bool& is_valid, std::vector<std::uint8_t>& content) {
    is_valid = false;

    // ME-04 (звуження critical section): та сама схема, що щойно застосована у
    // VerifyData (і раніше у VerifyXml/VerifyPdf) — mutex_ тримається лише для
    // знімка стану на вході й фінального коміту; CMS-парсинг і мережевий
    // trust pipeline працюють без lock_guard.
    Settings local_settings;
    OcspSettings local_ocsp_settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            SetVerifyReport("VerifyDataInternal", false, false, ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        local_settings = settings_;
        local_ocsp_settings = ocsp_settings_;
    }

#if TAMGA_CRYPTONITE_ENABLED
    VerifyPolicyInfo policy_info;
    std::string error_message;
    if (!CryptoniteAdapter::VerifyAttached(signed_data, is_valid, content, policy_info, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyDataInternal", false, false, ErrorCode::InvalidArgument, error_message);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }

    VerifyReport report;
    report.has_result = true;
    report.execution_succeeded = true;
    report.signature_valid = is_valid;
    report.operation = "VerifyDataInternal";
    report.error_code = ErrorCode::None;
    report.message = BuildVerifyMessage(true, is_valid, {});
    // WP-11 (HI-06): structural fact, independent of the trust decision below.
    report.signer_certificate_present = policy_info.signer_certificate_present;
    // Мультипідпис CMS: зараз валідується лише SignerInfo[0], тому робимо розрив
    // між кількістю підписантів і кількістю перевірених ЯВНИМ у звіті.
    report.cms_signer_count = policy_info.signer_count;
    report.cms_verified_signer_count = policy_info.verified_signer_count;
    // Мультипідпис CMS: кожен підписант отримує власний запис у signatures[] —
    // той самий масив, який XAdES-шлях наповнює після HI-01. Верхньорівневий
    // report.signature_valid уже є AND-агрегацією (обчислена в VerifyCms), тож
    // зламаний підпис будь-якого співпідписанта робить контейнер невалідним.
    report.signatures.clear();
    report.signatures.reserve(policy_info.signers.size());
    for (const auto& signer : policy_info.signers) {
        SignatureEntry entry;
        entry.index = signer.index;
        entry.signature_valid = signer.signature_valid;
        entry.signer_certificate_present = !signer.certificate_der.empty();
        report.signatures.push_back(std::move(entry));
    }
    CertificateMetadata local_signer_metadata;
    bool have_signer_metadata = false;
    if (!policy_info.signer_certificate_der.empty()) {
        std::string metadata_error;
        if (CryptoniteAdapter::ExtractCertificateMetadata(policy_info.signer_certificate_der,
                                                          local_signer_metadata,
                                                          metadata_error)) {
            have_signer_metadata = true;
        }
    }
    if (is_valid) {
        // WP-11 (HI-06): ValidationEngine is the sole trust/revocation/
        // timestamp/certificate-time source here too — legacy
        // ApplyTrustPipelineStatus retired.
        validation::ValidationContext ve_ctx;
        if (local_settings.trust_mode == "strict") {
            ve_ctx.profile = validation::ValidationProfile::Strict;
        } else if (local_settings.trust_mode == "ukraine-legal") {
            ve_ctx.profile = validation::ValidationProfile::UkraineLegal;
        } else if (local_settings.trust_mode == "offline") {
            ve_ctx.profile = validation::ValidationProfile::Offline;
        } else if (local_settings.trust_mode == "forensic") {
            ve_ctx.profile = validation::ValidationProfile::Forensic;
        } else {
            ve_ctx.profile = validation::ValidationProfile::Compatibility;
        }
        if (local_settings.validation_level == "basic") {
            ve_ctx.level = validation::ValidationLevel::Basic;
        } else if (local_settings.validation_level == "extended") {
            ve_ctx.level = validation::ValidationLevel::Extended;
        } else if (local_settings.validation_level == "forensic") {
            ve_ctx.level = validation::ValidationLevel::Forensic;
        } else {
            ve_ctx.level = validation::ValidationLevel::Standard;
        }
        ve_ctx.offline  = local_settings.offline_mode;
        ve_ctx.work_dir = local_settings.work_dir;
        ve_ctx.cms_der  = signed_data;
        ve_ctx.signature_crypto_valid = is_valid;  // F-04: фактичний вердикт VerifyDataInternal
        if (!local_settings.offline_mode) {
            ve_ctx.ocsp_url = local_ocsp_settings.url;
        }
        {
            std::string claimed_iso;
            if (CryptoniteAdapter::ExtractSigningTime(signed_data, claimed_iso)) {
                ve_ctx.claimed_signing_time = claimed_iso;  // WP-10: not crypto-proven
            }
        }
        const std::vector<std::vector<std::uint8_t>> embedded_certs =
            EnrichWithAiaIssuersIfNeeded(local_settings.work_dir, local_ocsp_settings.timeout_ms,
                                        !local_settings.offline_mode && local_settings.allow_aia_issuer_fetch,
                                        policy_info.signer_certificate_der,
                                        policy_info.embedded_certificates_der);
        const validation::ValidationReport ve_report =
            validation::ValidationEngine{}.Validate(
                ve_ctx,
                policy_info.signer_certificate_der,
                embedded_certs);
        ApplyValidationEngineReport(ve_report, report);
    }
    if (is_valid && !report.trust_valid && report.trust_checked) {
        report.error_code = TrustFailureErrorCode(report);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_verify_report_ = std::move(report);
        // Н-04: фіксуємо епоху цього коміту — доуточнення нижче застосується
        // лише якщо звіт усе ще належить цьому потоку.
        MarkVerifyReportCommittedLocked();
        if (have_signer_metadata) {
            last_signer_metadata_ = std::move(local_signer_metadata);
        }
        RefreshUserReportForCurrentOperation();
        ClearError();
    }
    return true;
#else
    (void)signed_data;
    is_valid = false;
    content.clear();
    std::lock_guard<std::mutex> lock(mutex_);
    SetVerifyReport("VerifyDataInternal", false, false, ErrorCode::NotSupported, kCryptoniteRequiredMessage);
    SetError(ErrorCode::NotSupported, kCryptoniteRequiredMessage);
    return false;
#endif
}

bool Session::SignDataInternalBase64(const std::vector<std::uint8_t>& data, std::string& signed_data_base64) {
    std::vector<std::uint8_t> signed_data;
    if (!SignDataInternal(data, signed_data)) {
        return false;
    }
    signed_data_base64 = util::Base64Encode(signed_data);
    std::lock_guard<std::mutex> lock(mutex_);
    ClearError();
    return true;
}

bool Session::VerifyDataInternalBase64(const std::string& signed_data_base64, bool& is_valid, std::vector<std::uint8_t>& content) {
    std::vector<std::uint8_t> signed_data;
    if (!util::Base64Decode(signed_data_base64, signed_data)) {
        std::lock_guard<std::mutex> lock(mutex_);
        is_valid = false;
        SetVerifyReport("VerifyDataInternalBase64", false, false, ErrorCode::InvalidArgument, "Internal Base64 payload is invalid");
        SetError(ErrorCode::InvalidArgument, "Internal Base64 payload is invalid");
        return false;
    }

    const bool result = VerifyDataInternal(signed_data, is_valid, content);
    OverrideVerifyReportOperation("VerifyDataInternalBase64");
    return result;
}

bool Session::VerifyDataInternalString(const std::vector<std::uint8_t>& signed_data, bool& is_valid, std::string& content_utf8) {
    std::vector<std::uint8_t> content;
    if (!VerifyDataInternal(signed_data, is_valid, content)) {
        OverrideVerifyReportOperation("VerifyDataInternalStr");
        return false;
    }
    content_utf8.assign(content.begin(), content.end());
    std::lock_guard<std::mutex> lock(mutex_);
    last_verify_report_.operation = "VerifyDataInternalStr";
    RefreshUserReportForCurrentOperation();
    ClearError();
    return true;
}

bool Session::VerifyDataInternalBase64String(const std::string& signed_data_base64, bool& is_valid, std::string& content_utf8) {
    std::vector<std::uint8_t> content;
    if (!VerifyDataInternalBase64(signed_data_base64, is_valid, content)) {
        OverrideVerifyReportOperation("VerifyDataInternalBase64Str");
        return false;
    }
    content_utf8.assign(content.begin(), content.end());
    std::lock_guard<std::mutex> lock(mutex_);
    last_verify_report_.operation = "VerifyDataInternalBase64Str";
    RefreshUserReportForCurrentOperation();
    ClearError();
    return true;
}

bool Session::SignFile(const std::string& path, std::vector<std::uint8_t>& signature) {
    return SignFile(path, signature, TimestampMode::BestEffort);
}

bool Session::SignFile(const std::string& path,
                       std::vector<std::uint8_t>& signature,
                       TimestampMode timestamp_mode) {
    FileStoreSettings settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        settings = file_store_settings_;
    }

    std::vector<std::uint8_t> data;
    std::string error_message;
    if (!ReadBinaryFile(ResolveFilePath(path, settings), "input file for signing", data, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        signature.clear();
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }
    if (data.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        signature.clear();
        SetError(ErrorCode::InvalidArgument, "Input file is empty");
        return false;
    }

    if (!SignData(data, signature, timestamp_mode)) {
        signature.clear();
        return false;
    }
    return true;
}

bool Session::VerifyFile(const std::string& path, const std::vector<std::uint8_t>& signature, bool& is_valid) {
    FileStoreSettings settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        settings = file_store_settings_;
    }

    std::vector<std::uint8_t> data;
    std::string error_message;
    if (!ReadBinaryFile(ResolveFilePath(path, settings), "input file for verification", data, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyFile", false, false, ErrorCode::InvalidArgument, error_message);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }
    if (data.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyFile", false, false, ErrorCode::InvalidArgument, "Input file is empty");
        SetError(ErrorCode::InvalidArgument, "Input file is empty");
        return false;
    }

    const bool result = VerifyData(data, signature, is_valid);
    OverrideVerifyReportOperation("VerifyFile");
    return result;
}

bool Session::RawSignFile(const std::string& input_path, const std::string& signature_path) {
    return RawSignFile(input_path, signature_path, TimestampMode::BestEffort);
}

bool Session::RawSignFile(const std::string& input_path,
                          const std::string& signature_path,
                          TimestampMode timestamp_mode) {
    FileStoreSettings settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        settings = file_store_settings_;
    }

    const std::string resolved_signature_path = ResolveFilePath(signature_path, settings);
    const std::filesystem::path fs_sig_path = std::filesystem::u8path(resolved_signature_path);
    const bool signature_file_exists = std::filesystem::exists(fs_sig_path);

    if (!settings.allow_overwrite && signature_file_exists) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Signature output file already exists");
        return false;
    }

    std::vector<std::uint8_t> signature;
    if (!SignFile(input_path, signature, timestamp_mode)) {
        // С-02: обнулення наявного .sig при невдалому Required-TSP — СВІДОМА
        // вимога, а не недогляд: після невдалого підписання поруч не має
        // лишитися файл, який викликач прийме за щойно створений підпис.
        // Контракт зафіксовано тестом
        // "Failed Required RawSignFile should clear stale signature output file".
        //
        // Аудит (С-02) відзначив цю поведінку як недокументовану — і це була
        // справедлива претензія саме до документації. Поведінку залишено, а
        // опис додано в docs/component-methods.md і docs/cli.md: викликач, для
        // якого попередній підпис цінний, має підписувати у тимчасовий шлях і
        // переносити його сам.
        if (timestamp_mode == TimestampMode::Required && signature_file_exists) {
            std::ofstream clear_output(fs_sig_path, std::ios::binary | std::ios::trunc);
            (void)clear_output;
        }
        return false;
    }

    // С-02: атомарний запис — спершу тимчасовий файл поруч, потім rename.
    // Проміжного стану «файл існує, але порожній/недописаний» не виникає навіть
    // при збої запису чи аварії процесу.
    if (!tamga::util::WriteBinaryFileAtomic(fs_sig_path, signature)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError, "Unable to write signature output file");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    ClearError();
    return true;
}

bool Session::RawVerifyFile(const std::string& input_path, const std::string& signature_path, bool& is_valid) {
    FileStoreSettings settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        settings = file_store_settings_;
    }

    std::vector<std::uint8_t> signature;
    std::string error_message;
    if (!ReadBinaryFile(ResolveFilePath(signature_path, settings), "signature file", signature, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("RawVerifyFile", false, false, ErrorCode::InvalidArgument, error_message);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }
    if (signature.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("RawVerifyFile", false, false, ErrorCode::InvalidArgument, "Signature file is empty");
        SetError(ErrorCode::InvalidArgument, "Signature file is empty");
        return false;
    }

    const bool result = VerifyFile(input_path, signature, is_valid);
    OverrideVerifyReportOperation("RawVerifyFile");
    return result;
}

bool Session::ShowCertificates() {
    std::lock_guard<std::mutex> lock(mutex_);
    SetError(ErrorCode::GuiNotAvailable, ToString(ErrorCode::GuiNotAvailable));
    return false;
}

bool Session::ShowCRLs() {
    std::lock_guard<std::mutex> lock(mutex_);
    SetError(ErrorCode::GuiNotAvailable, ToString(ErrorCode::GuiNotAvailable));
    return false;
}

bool Session::IsInitialized() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return is_initialized_;
}

bool Session::IsPrivateKeyLoaded() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return is_private_key_loaded_;
}

bool Session::NeedSetSettings() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return need_set_settings_;
}

bool Session::OfflineMode() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return settings_.offline_mode;
}

LastError Session::GetLastError() const {
