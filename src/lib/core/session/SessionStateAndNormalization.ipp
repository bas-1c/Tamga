    std::lock_guard<std::mutex> lock(mutex_);
    return last_error_;
}

void Session::SetError(const ErrorCode code, std::string message) {
    last_error_.code = code;
    last_error_.message = std::move(message);
}

void Session::ClearError() {
    last_error_ = {};
}

void Session::RecordVerifyFailure(std::string operation, const ErrorCode error_code, std::string message) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string report_message = message;
    SetVerifyReport(std::move(operation), false, false, error_code, std::move(report_message));
    SetError(error_code, std::move(message));
}

// ADR-033: облік епох звіту (Н-04) живе у `VerifyReportOwnership`. Методи
// нижче лишаються тонкими перехідниками, бо суфікс `Locked` у їхніх іменах —
// частина дисципліни виклику в межах `Session` (лише під `mutex_`), а сам
// `VerifyReportOwnership` про мутекс сесії нічого не знає.
void Session::MarkVerifyReportCommittedLocked() {
    verify_report_ownership_.MarkCommitted();
}

bool Session::VerifyReportStillOwnedByThisThreadLocked() const {
    return verify_report_ownership_.StillOwnedByThisThread();
}

void Session::ClearVerifyReport() {
    last_verify_report_ = MakeClearedVerifyReport();
    last_signer_metadata_ = {};
    RefreshUserReportForCurrentOperation();
}

void Session::SetVerifyReport(std::string operation,
                              const bool execution_succeeded,
                              const bool signature_valid,
                              const ErrorCode error_code,
                              std::string message) {
    ClearVerifyReport();
    VerifyOutcome outcome;
    outcome.operation = std::move(operation);
    outcome.execution_succeeded = execution_succeeded;
    outcome.signature_valid = signature_valid;
    outcome.error_code = error_code;
    outcome.message = std::move(message);
    CommitVerifyOutcome(last_verify_report_, std::move(outcome));
    MarkVerifyReportCommittedLocked();
    RefreshUserReportForCurrentOperation();
}

void Session::OverrideVerifyReportOperation(std::string operation) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!last_verify_report_.has_result) {
        return;
    }
    // Н-04: перейменовуємо ЛИШЕ власний звіт. Інакше паралельний Verify* на тій
    // самій сесії отримав би чужу назву операції — і споживач читав би,
    // наприклад, "VerifyFileAsicS" у результаті VerifyXml.
    if (!VerifyReportStillOwnedByThisThreadLocked()) {
        return;
    }
    last_verify_report_.operation = std::move(operation);
    RefreshUserReportForCurrentOperation();
}

bool Session::LoadKeyFromBytes(const std::vector<std::uint8_t>& key_data,
                               std::string store_password,
                               std::string key_password,
                               std::string jks_alias,
                               const bool strict_pem,
                               const CertificateHints& cert_hints) {
    return LoadPrivateKeyPayload(key_data, std::move(store_password), std::move(key_password), std::move(jks_alias), strict_pem, cert_hints);
}

// Авто-резолвер відкритого сертифіката (Рівні 1–3). Викликається ТІЛЬКИ якщо
// нормалізація контейнера не дала сертифіката — тобто для `.dat`/PKCS#12 без
// certBag, які видає більшість українських КНЕДП. Результат fail-closed:
// повертається лише сертифікат, що математично відповідає закритому ключу.
bool Session::ResolveMissingCertificate(const std::vector<std::uint8_t>& key_material,
                                        const std::string& password,
                                        const CertificateHints& cert_hints,
                                        std::vector<std::uint8_t>& certificate,
                                        std::string& error_message) const {
    net::CertificateResolveRequest request;
    request.key_material = key_material;
    request.password = password;
    request.explicit_certificate_path = cert_hints.certificate_path;
    request.key_file_path = cert_hints.key_file_path;
    request.preferred_ca_hint = cert_hints.ca_hint;
    if (!cert_hints.certificate_base64.empty() &&
        !util::Base64Decode(cert_hints.certificate_base64, request.explicit_certificate_der)) {
        error_message = "Descriptor certificateBase64 is invalid";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        request.work_dir = settings_.work_dir;
        request.offline_mode = settings_.offline_mode;
        request.network_timeout_ms = ocsp_settings_.timeout_ms;
        // ТЗ Рівень 3: адреса каталогу КНЕДП приходить із ConfigureLdap.
        // Порожній URL просто вимикає мережевий крок — резолвер лишається
        // повністю робочим на Рівнях 1–2, як і був.
        request.ldap_url = ldap_settings_.url;
        request.ldap_base_dn = ldap_settings_.base_dn;
        if (ldap_settings_.timeout_ms > 0) {
            request.network_timeout_ms = ldap_settings_.timeout_ms;
        }
    }
    // Ідентифікатор власника (ЄДРПОУ/ДРФО/CN) звужує вибірку каталогу. Це лише
    // підказка: остаточний відбір робить звірка з відкритим ключем.
    request.subject_identifier = cert_hints.subject_identifier;

    const auto resolved = net::CertificateResolver{}.Resolve(request);
    if (!resolved.succeeded) {
        error_message = resolved.message;
        return false;
    }
    certificate = resolved.certificate_der;
    return true;
}

bool Session::LoadPrivateKeyPayload(const std::vector<std::uint8_t>& key_data,
                                    std::string store_password,
                                    std::string key_password,
                                    std::string jks_alias,
                                    const bool strict_pem,
                                    const CertificateHints& cert_hints) {
    if (key_data.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Key container is empty");
        SecureErase(store_password);
        SecureErase(key_password);
        SecureErase(jks_alias);
        return false;
    }

    if (key_password.empty()) {
        key_password = store_password;
    }
    // Для `.ZS2` користувач може передати пароль лише як `keyPassword`.
    // Нормалізація вже приймає цей fallback; той самий ефективний пароль має
    // дійти до зіставлення sidecar-сертифіката і подальшої підготовки signer-а.
    const std::string& effective_key_password =
        store_password.empty() ? key_password : store_password;

    std::vector<std::uint8_t> normalized;
    std::vector<std::uint8_t> key_material;
    std::vector<std::uint8_t> certificate;
    KeyFormat detected_format = KeyFormat::Unknown;
    std::string error_message;
    if (!NormalizeKeyContainer(key_data,
                               store_password,
                               key_password,
                               jks_alias,
                               strict_pem,
                               normalized,
                               key_material,
                               certificate,
                               detected_format,
                               error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        SecureErase(store_password);
        SecureErase(key_password);
        SecureErase(jks_alias);
        return false;
    }

    // Контейнери без certBag (`.dat`, `key-6.dat`, PKCS#12 DER від українських
    // КНЕДП) доходять сюди з порожнім `certificate`, і далі PreparePkcs12Signer
    // впав би з RET_PKIX_NO_CERTIFICATE. Пробуємо авто-резолвер: явний шлях/base64
    // -> sidecar -> кеш -> мережа. Невдача НЕ є фатальною для самого завантаження
    // ключа (частина операцій, як-от SignHash, сертифіката не потребує), але
    // сертифікат лишається порожнім, тож підпис CMS чесно відмовить пізніше.
    if (certificate.empty()) {
        std::vector<std::uint8_t> resolved_certificate;
        std::string resolve_error;
        if (ResolveMissingCertificate(key_material, effective_key_password, cert_hints,
                                      resolved_certificate, resolve_error)) {
            certificate = std::move(resolved_certificate);
        } else if (!cert_hints.certificate_path.empty() || !cert_hints.certificate_base64.empty()) {
            // Користувач ЯВНО вказав сертифікат, і він не підійшов — це помилка
            // конфігурації, яку не можна проковтнути: інакше підпис піде з іншим
            // (або без) сертифікатом, ніж людина задала.
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::InvalidArgument, std::move(resolve_error));
            SecureErase(store_password);
            SecureErase(key_password);
            SecureErase(jks_alias);
            return false;
        }
    }

    CommitLoadedKey(std::move(normalized),
                    std::move(key_material),
                    std::move(certificate),
                    effective_key_password,
                    detected_format);
    SecureErase(store_password);
    SecureErase(key_password);
    SecureErase(jks_alias);
    return true;
}

void Session::CommitLoadedKey(std::vector<std::uint8_t> normalized,
                              std::vector<std::uint8_t> key_material,
                              std::vector<std::uint8_t> certificate,
                              const std::string& store_password,
                              const KeyFormat format) {
    std::lock_guard<std::mutex> lock(mutex_);
    SecureClearLoadedKey();
    loaded_key_ = std::move(normalized);
    loaded_key_material_ = std::move(key_material);
    loaded_certificate_ = std::move(certificate);
    loaded_key_password_ = store_password;
    loaded_key_format_ = format;
    is_private_key_loaded_ = true;
    ClearError();
}

bool Session::NormalizeKeyContainer(const std::vector<std::uint8_t>& key_data,
                                    const std::string& store_password,
                                    const std::string& key_password,
                                    const std::string& jks_alias,
                                    const bool strict_pem,
                                    std::vector<std::uint8_t>& normalized,
                                    std::vector<std::uint8_t>& key_material,
                                    std::vector<std::uint8_t>& certificate,
                                    KeyFormat& format,
                                    std::string& error_message) const {
    if (key_data.empty()) {
        error_message = "Key container is empty";
        return false;
    }

    if (StartsWith(key_data, {0xFE, 0xED, 0xFE, 0xED})) {
        format = KeyFormat::Jks;
        if (store_password.empty() && key_password.empty()) {
            error_message = "JKS key store requires store password or key password";
            return false;
        }

        JksKeyStoreParser::PrivateKeyEntry jks_entry;
        if (!JksKeyStoreParser::LoadPrivateKeyEntry(
                key_data, store_password, key_password, jks_alias, jks_entry, error_message)) {
            return false;
        }

        normalized = jks_entry.private_key_pkcs8;
        key_material = normalized;
        std::vector<std::uint8_t> matching_cert;
        if (CryptoniteAdapter::FindMatchingCertificate(key_material, jks_entry.certificate_chain, matching_cert)) {
            certificate = std::move(matching_cert);
        } else {
            certificate = std::move(jks_entry.certificate);
        }
        if (!IsValidDerContainer(normalized, error_message)) {
            return false;
        }
        if (!certificate.empty() && !IsValidDerContainer(certificate, error_message)) {
            return false;
        }
        return true;
    }

    // Власний контейнер АТ «ІІТ» (`Key-6.dat`). Перевіряти його треба ДО гілки
    // PEM/DER: контейнер теж починається з 0x30, і PemDerLoader прийняв би його
    // за «DER private key», після чого pkcs8_decode відмовив би з rc=102, бо
    // всередині лежить не PKCS#8, а зашифрований блок. Ознака формату —
    // OID 1.3.6.1.4.1.19398.1.1.1.2 у першому AlgorithmIdentifier.
    if (IitKeyContainerParser::Matches(key_data)) {
        // Формат назовні лишається Der: після розшифрування ми віддаємо
        // звичайний PKCS#8 PrivateKeyInfo, і далі працює наявний шлях PKCS#8.
        format = KeyFormat::Der;
        const std::string& iit_password = store_password.empty() ? key_password : store_password;
        if (iit_password.empty()) {
            error_message = "IIT key container requires password";
            return false;
        }

        std::vector<std::uint8_t> decrypted;
        if (!IitKeyContainerParser::Decrypt(key_data, iit_password, decrypted, error_message)) {
            return false;
        }

        normalized = std::move(decrypted);
        key_material = normalized;
        // Контейнер ІІТ ніколи не містить відкритого сертифіката — його шукає
        // ResolveMissingCertificate вище за стеком.
        certificate.clear();
        if (!IsValidDerContainer(normalized, error_message)) {
            return false;
        }
        return true;
    }

    // Контейнер `.ZS2` АЦСК «Україна» — це PKCS#12 із PBES2 на Купині й Калині.
    // Після патча cryptonite 0019 його треба передавати ЦІЛИМ у звичайний
    // PKCS#12-шлях. Так `pkcs12_enum_keys` бачить обидва ключі контейнера DU, а
    // signer може вибрати ключ, чий Q_key відповідає Q_cert сертифіката підпису.
    // Витяг лише першого shroudedKeyBag втрачав другий ключ і робив результат
    // залежним від порядку мішків у файлі.
    if (Zs2KeyContainerParser::Matches(key_data)) {
        format = KeyFormat::Pkcs12;
        const std::string& zs2_password = store_password.empty() ? key_password : store_password;
        if (zs2_password.empty()) {
            error_message = "ZS2 key container requires password";
            return false;
        }
        normalized = key_data;
        key_material = key_data;
        // `.ZS2` не містить certBag — сертифікат добирає ResolveMissingCertificate.
        certificate.clear();
        return IsValidDerContainer(normalized, error_message);
    }

    if (IsLikelyPem(key_data) || key_data[0] == 0x30) {
        std::vector<PemDerLoader::PemBlock> blocks;
        PemDerLoader::LoadOptions options;
        options.strict_mode = strict_pem;
        if (!PemDerLoader::LoadAll(key_data, blocks, error_message, options)) {
            return false;
        }

        const auto key_it = std::find_if(blocks.begin(), blocks.end(), [](const PemDerLoader::PemBlock& block) {
            return block.type.find("PRIVATE KEY") != std::string::npos || block.type == "DER";
        });
        if (key_it == blocks.end()) {
            error_message = "PEM/DER does not contain PRIVATE KEY block";
            return false;
        }

        const auto cert_it = std::find_if(blocks.begin(), blocks.end(), [](const PemDerLoader::PemBlock& block) {
            return block.type == "CERTIFICATE";
        });

        normalized = key_it->der_payload;
        key_material = normalized;
        certificate = cert_it == blocks.end() ? std::vector<std::uint8_t>{} : cert_it->der_payload;
        const std::string& container_type = key_it->type;

        if (container_type == "DER") {
            format = IsPkcs12Der(normalized) ? KeyFormat::Pkcs12 : KeyFormat::Der;
            if (format == KeyFormat::Pkcs12) {
                key_material = key_data;
                certificate.clear();
            }
        } else {
            format = KeyFormat::Pem;
        }

        if (!IsValidDerContainer(normalized, error_message)) {
            return false;
        }
        return true;
    }

    error_message = "Unsupported key format";
    return false;
}



bool Session::IsValidDerContainer(const std::vector<std::uint8_t>& der_data, std::string& error_message) {
    if (der_data.size() < 4 || der_data[0] != 0x30) {
        error_message = "DER container must start with SEQUENCE";
        return false;
    }

    TlvView outer{};
    if (!ParseTlvAt(der_data, 0, outer) || outer.tag != 0x30 || outer.next_offset != der_data.size()) {
        error_message = "DER container has invalid ASN.1 layout";
        return false;
    }
    return true;
}
void Session::SecureClearLoadedKey() {
    // С-05: раніше три байтові контейнери занулювалися звичайними циклами
    // `for (auto& b : v) b = 0;` — а двома рядками нижче SecureErase робив те
    // саме через volatile. Оскільки результат звичайного запису ніде не
    // читається, компілятор мав право усунути такі цикли як dead store, тобто
    // приватний ключ міг лишатися у звільненій купі. Тепер обидва шляхи —
    // один спільний util::SecureClear.
    tamga::util::SecureClear(loaded_key_);
    tamga::util::SecureClear(loaded_key_material_);
    tamga::util::SecureClear(loaded_certificate_);
    SecureErase(loaded_key_password_);
    loaded_key_format_ = KeyFormat::Unknown;
}

void Session::SecureErase(std::string& value) {
    tamga::util::SecureClear(value);
}

namespace {
// WP-17 (звуження critical section): settings/report передаються ЯВНО,
// а не через this->settings_/this->last_verify_report_. Дозволяє
// викликачам робити мережеву OCSP/CRL/chain-перевірку НЕ тримаючи
// mutex_ — знімок Settings і локальний VerifyReport передаються сюди
// поза lock_guard, а комітяться в last_verify_report_ лише коротким
// lock у кінці.
//
// F-04: `signature_crypto_valid` — вердикт криптоперевірки, зроблений викликачем
// (XmlSignatureVerifier / PadesVerifier / CryptoniteAdapter). Передається явно;
// ValidationEngine більше не припускає його істинним.
void RunFormatTrustValidationOn(const Settings& settings,
                                const std::vector<std::uint8_t>& signer_certificate_der,
                                const std::vector<std::uint8_t>& cms_der,
                                const std::vector<std::vector<std::uint8_t>>& embedded_certificates_der,
                                const std::vector<std::vector<std::uint8_t>>& embedded_revocation_ocsp_der,
                                const std::vector<std::vector<std::uint8_t>>& embedded_revocation_crl_der,
                                bool signature_crypto_valid,
                                VerifyReport& report) {
    if (signer_certificate_der.empty()) {
        return;
    }
#if TAMGA_CRYPTONITE_ENABLED
    validation::ValidationContext ve_ctx;
    if (settings.trust_mode == "strict") {
        ve_ctx.profile = validation::ValidationProfile::Strict;
    } else if (settings.trust_mode == "ukraine-legal") {
        ve_ctx.profile = validation::ValidationProfile::UkraineLegal;
    } else if (settings.trust_mode == "offline") {
        ve_ctx.profile = validation::ValidationProfile::Offline;
    } else if (settings.trust_mode == "forensic") {
        ve_ctx.profile = validation::ValidationProfile::Forensic;
    } else {
        ve_ctx.profile = validation::ValidationProfile::Compatibility;
    }
    if (settings.validation_level == "basic") {
        ve_ctx.level = validation::ValidationLevel::Basic;
    } else if (settings.validation_level == "extended") {
        ve_ctx.level = validation::ValidationLevel::Extended;
    } else if (settings.validation_level == "forensic") {
        ve_ctx.level = validation::ValidationLevel::Forensic;
    } else {
        ve_ctx.level = validation::ValidationLevel::Standard;
    }
    ve_ctx.offline = settings.offline_mode;
    ve_ctx.work_dir = settings.work_dir;
    ve_ctx.cms_der = cms_der;
    ve_ctx.embedded_revocation_ocsp_der = embedded_revocation_ocsp_der;
    ve_ctx.embedded_revocation_crl_der = embedded_revocation_crl_der;
    ve_ctx.signature_crypto_valid = signature_crypto_valid;  // F-04
    const validation::ValidationReport ve_report =
        validation::ValidationEngine{}.Validate(ve_ctx, signer_certificate_der, embedded_certificates_der);
    ApplyValidationEngineReport(ve_report, report);
#else
    (void)settings;
    (void)cms_der;
    (void)embedded_certificates_der;
    (void)embedded_revocation_ocsp_der;
    (void)embedded_revocation_crl_der;
    (void)signature_crypto_valid;
    (void)report;
#endif
}

// HI-01: незалежна trust/revocation/certificate.timeValid-перевірка ОДНОГО
// конкретного співпідписанта (окремий X.509 chain + OCSP/CRL на кожного,
// а не лише на репрезентативного) — переюз тієї самої `RunFormatTrustValidationOn`
// із порожнім, одноразовим `VerifyReport`, з якого копіюється лише relevantний
// підмножина полів у `SignatureEntry`. Формат-специфічні поля (operation/
// policy/containerType/signatureFormat/ltvValid тощо) тут НЕ зачіпаються —
// вони й далі лишаються репрезентативно-орієнтованими (поза скоупом HI-01,
// який стосується САМЕ trust/revocation/certificate.timeValid).
[[maybe_unused]] void ApplyPerSignerTrustValidation(const Settings& settings,
                                   const std::vector<std::uint8_t>& signer_certificate_der,
                                   const std::vector<std::vector<std::uint8_t>>& certificate_values_der,
                                   const std::vector<std::vector<std::uint8_t>>& revocation_values_ocsp_der,
                                   const std::vector<std::vector<std::uint8_t>>& revocation_values_crl_der,
                                   SignatureEntry& entry) {
    VerifyReport temp;
    // F-04: беремо крипто-вердикт САМЕ цього співпідписанта (HI-01 уже рахує
    // його окремо), а не загальний по контейнеру — інакше зламаний співпідписант
    // отримав би trust-вердикт, порахований так, ніби його підпис зійшовся.
    RunFormatTrustValidationOn(settings, signer_certificate_der, {}, certificate_values_der,
                              revocation_values_ocsp_der, revocation_values_crl_der,
                              entry.signature_valid, temp);
    entry.certificate_time_valid = temp.certificate_time_valid;
    entry.validation_time_source = temp.validation_time_source;
    entry.chain_checked = temp.chain_checked;
    entry.chain_valid = temp.chain_valid;
    entry.chain_debug = temp.chain_debug;
    entry.trust_checked = temp.trust_checked;
    entry.trust_valid = temp.trust_valid;
    entry.trust_status = temp.trust_status;
    entry.trust_mode = temp.trust_mode;
    entry.trust_reason = temp.trust_reason;
    entry.historical_trust_used = temp.historical_trust_used;
    entry.historical_anchor_subject = temp.historical_anchor_subject;
    entry.historical_anchor_serial = temp.historical_anchor_serial;
    entry.revocation_checked = temp.revocation_checked;
    entry.ocsp_checked = temp.ocsp_checked;
    entry.revocation_status = temp.revocation_status;
    // Gemini review (PR #37): без цього агрегація нижче могла дати
    // report.trust_valid=false (untrusted co-signer) при report.error_code
    // такому, що лишається None — неузгоджений звіт.
    entry.error_code = temp.error_code;
    entry.message = temp.message;
}

// HI-01: агрегує trust/revocation/certificate/chain-стан УСІХ підписантів
// (`report.signatures[]`, уже заповнений per-signer через
// `ApplyPerSignerTrustValidation`) у верхньорівневі поля `VerifyReport` —
// `all_valid` policy (рішення користувача): boolean-поля є кон'юнкцією по
// ВСІХ підписантах (кожен МАЄ бути trusted/valid), а не копією одного
// репрезентативного, як раніше. Рядкові діагностичні поля (trust_status/
// trust_reason/revocation_status/chain_debug/historical_*/
// validation_time_source) беруться з "найгіршого" підписанта: перший, чий
// trust_valid=false, інакше перший, чиє відкликання не підтверджено
// ("valid"/"good"), інакше перший загалом — той самий принцип вибору
// репрезентативного, що вже застосовувався до signature_valid (WP-2),
// тепер узагальнений і на trust/revocation. Викликається ПІСЛЯ того, як
// `report.signatures[]` уже заповнений — і НЕ зачіпає error_code/message
// (ці лишаються від репрезентативного crypto/timestamp виклику, поза
// скоупом HI-01).
[[maybe_unused]] void ApplyPerSignerTrustAggregation(VerifyReport& report) {
    if (report.signatures.empty()) {
        return;
    }
    std::size_t representative = 0;
    bool found_untrusted = false;
    for (std::size_t i = 0; i < report.signatures.size(); ++i) {
        if (!report.signatures[i].trust_valid) {
            representative = i;
            found_untrusted = true;
            break;
        }
    }
    if (!found_untrusted) {
        for (std::size_t i = 0; i < report.signatures.size(); ++i) {
            const auto& e = report.signatures[i];
            const bool revocation_confirmed = e.revocation_status == "valid" || e.revocation_status == "good";
            if (!revocation_confirmed) {
                representative = i;
                break;
            }
        }
    }

    bool all_trust_checked = true;
    bool all_trust_valid = true;
    bool all_chain_checked = true;
    bool all_chain_valid = true;
    bool all_certificate_time_valid = true;
    bool all_revocation_checked = true;
    bool all_ocsp_checked = true;
    for (const auto& e : report.signatures) {
        all_trust_checked = all_trust_checked && e.trust_checked;
        all_trust_valid = all_trust_valid && e.trust_valid;
        all_chain_checked = all_chain_checked && e.chain_checked;
        all_chain_valid = all_chain_valid && e.chain_valid;
        all_certificate_time_valid = all_certificate_time_valid && e.certificate_time_valid;
        all_revocation_checked = all_revocation_checked && e.revocation_checked;
        all_ocsp_checked = all_ocsp_checked && e.ocsp_checked;
    }

    const SignatureEntry& rep = report.signatures[representative];
    report.trust_checked = all_trust_checked;
    report.trust_valid = all_trust_valid;
    report.chain_checked = all_chain_checked;
    report.chain_valid = all_chain_valid;
    report.certificate_time_valid = all_certificate_time_valid;
    report.revocation_checked = all_revocation_checked;
    report.ocsp_checked = all_ocsp_checked;
    report.validation_time_source = rep.validation_time_source;
    report.trust_status = rep.trust_status;
    report.trust_mode = rep.trust_mode;
    report.trust_reason = rep.trust_reason;
    report.historical_trust_used = rep.historical_trust_used;
    report.historical_anchor_subject = rep.historical_anchor_subject;
    report.historical_anchor_serial = rep.historical_anchor_serial;
    report.revocation_status = rep.revocation_status;
    report.chain_debug = rep.chain_debug;
    // Gemini review (PR #37): без цього report.trust_valid=false (через
    // untrusted co-signer) міг лишити report.error_code=None/message
    // порожнім, попри те, що агрегований вердикт сигналізує про проблему.
    // Прокидаємо error_code/message "найгіршого" підписанта, як і решту
    // діагностичних полів вище. rep.message перевіряється на порожність,
    // щоб не затерти вже наявне (можливо змістовніше) повідомлення, коли
    // сам найгірший підписант не мав власного message (той самий принцип,
    // що вже застосовує ApplyValidationEngineReport для report.message).
    report.error_code = rep.error_code;
    if (!rep.message.empty()) {
        report.message = rep.message;
    }
}
}  // namespace

} // namespace tamga::core
