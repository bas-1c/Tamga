// А-04: кеш звіту користувача наповнюється ТИМ САМИМ будівником, що й далі —
// а не літералом у заголовку. Блокування тут не потрібне: об'єкт ще нікому не
// відданий, тож конкурувати за нього нема кому.
//
// Наслідок, який і був метою: `GetUserReport()`, викликаний до `Initialize()`,
// більше не може віддати звіт із версією схеми, якої вже не існує. Джерело
// значення тепер рівно одне.
Session::Session() {
    ClearVerifyReport();
}

bool Session::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Якщо SetSettings() ще не викликався — встановлюємо розумні дефолти.
    // offline_mode лишається true з Settings: онлайн-сервіси вмикаються явно.
    // work_dir     = %TEMP%\Tamga\<унікальний_ID>
    if (need_set_settings_) {
        if (settings_.work_dir.empty()) {
            try {
                namespace fs = std::filesystem;
                // Базовий каталог: %TEMP%/Tamga
                auto base = fs::temp_directory_path() / "Tamga";
                // Унікальний підкаталог на основі адреси об'єкту (не UUID,
                // але достатньо для розрізнення кількох сесій у процесі)
                std::ostringstream uid;
                uid << std::hex << reinterpret_cast<std::uintptr_t>(this);
                auto dir = base / uid.str();
                fs::create_directories(dir);
                settings_.work_dir = dir.u8string();
            } catch (...) {
                // При будь-якій помилці fs — залишаємо порожнім (graceful degradation)
            }
        }
        need_set_settings_ = false;
    }

    is_initialized_ = true;
    ClearVerifyReport();
    ClearError();
    return true;
}

bool Session::Finalize() {
    std::lock_guard<std::mutex> lock(mutex_);
    SecureClearLoadedKey();
    is_private_key_loaded_ = false;
    is_initialized_ = false;
    ClearVerifyReport();
    ClearError();
    return true;
}

bool Session::SetSettings(const Settings& settings) {
    std::lock_guard<std::mutex> lock(mutex_);
    Settings normalized = settings;
    if (normalized.trust_mode.empty()) {
        normalized.trust_mode = "strict";
    }
    if (normalized.trust_mode != "strict" &&
        normalized.trust_mode != "compatibility" &&
        normalized.trust_mode != "ukraine-legal" &&
        normalized.trust_mode != "offline" &&
        normalized.trust_mode != "forensic") {
        SetError(ErrorCode::InvalidArgument, "Invalid trust mode; expected strict, compatibility, ukraine-legal, offline or forensic");
        return false;
    }
    if (normalized.validation_level.empty()) {
        normalized.validation_level = "standard";
    }
    if (normalized.validation_level != "basic" &&
        normalized.validation_level != "standard" &&
        normalized.validation_level != "extended" &&
        normalized.validation_level != "forensic") {
        SetError(ErrorCode::InvalidArgument, "Invalid validation level; expected basic, standard, extended or forensic");
        return false;
    }
    settings_ = normalized;
    need_set_settings_ = false;
    ClearError();
    return true;
}

bool Session::SetFileStoreSettings(const FileStoreSettings& settings) {
    std::lock_guard<std::mutex> lock(mutex_);
    file_store_settings_ = settings;
    ClearError();
    return true;
}

bool Session::SetOcspSettings(const OcspSettings& settings) {
    std::lock_guard<std::mutex> lock(mutex_);
    if ((!settings.url.empty() && !IsLikelyUrl(settings.url)) || !IsValidTimeout(settings.timeout_ms)) {
        SetError(ErrorCode::InvalidArgument, "Invalid OCSP settings");
        return false;
    }
    ocsp_settings_ = settings;
    ClearError();
    return true;
}

bool Session::SetTspSettings(const TspSettings& settings) {
    std::lock_guard<std::mutex> lock(mutex_);
    if ((!settings.url.empty() && !IsLikelyUrl(settings.url)) || !IsValidTimeout(settings.timeout_ms)) {
        SetError(ErrorCode::InvalidArgument, "Invalid TSP settings");
        return false;
    }
    TspSettings normalized = settings;
    std::transform(normalized.imprint_digest_oid.begin(), normalized.imprint_digest_oid.end(),
                   normalized.imprint_digest_oid.begin(), [](unsigned char c) -> char {
                       return static_cast<char>(std::tolower(c));
                   });

    if (!normalized.imprint_digest_oid.empty() && normalized.imprint_digest_oid != "auto") {
        if (!ImprintFromDigestOid(normalized.imprint_digest_oid).has_value()) {
            SetError(ErrorCode::InvalidArgument, "Invalid TSP imprint digest OID");
            return false;
        }
    }
    tsp_settings_ = normalized;
    ClearError();
    return true;
}

bool Session::SetLdapSettings(const LdapSettings& settings) {
    std::lock_guard<std::mutex> lock(mutex_);
    if ((!settings.url.empty() && !IsLikelyUrl(settings.url)) || !IsValidTimeout(settings.timeout_ms)) {
        SetError(ErrorCode::InvalidArgument, "Invalid LDAP settings");
        return false;
    }
    if (settings.url.empty()) {
        ldap_settings_ = settings;
        ClearError();
        return true;
    }
    SetError(ErrorCode::NotSupported, ToString(ErrorCode::NotSupported));
    return false;
}

bool Session::SetCmpSettings(const CmpSettings& settings) {
    std::lock_guard<std::mutex> lock(mutex_);
    if ((!settings.url.empty() && !IsLikelyUrl(settings.url)) || !IsValidTimeout(settings.timeout_ms)) {
        SetError(ErrorCode::InvalidArgument, "Invalid CMP settings");
        return false;
    }
    if (settings.url.empty()) {
        cmp_settings_ = settings;
        ClearError();
        return true;
    }
    SetError(ErrorCode::NotSupported, ToString(ErrorCode::NotSupported));
    return false;
}

bool Session::SetTrustListSettings(const TrustListSettings& settings) {
    std::lock_guard<std::mutex> lock(mutex_);
    TrustListSettings normalized = settings;
    if (normalized.url.empty()) {
        normalized.url = TrustListSettings{}.url;
    }
    if (!IsLikelyUrl(normalized.url) || !IsValidTimeout(normalized.timeout_ms) || normalized.cache_ttl_hours <= 0) {
        SetError(ErrorCode::InvalidArgument, "Invalid trust list settings");
        return false;
    }
    trust_list_settings_ = normalized;
    ClearError();
    return true;
}

bool Session::SyncTrustList() {
    // Q-002 (звуження critical section): раніше mutex_ трималася на весь виклик,
    // включно з мережевим завантаженням Trust List у sync.Sync (мегабайтний TL
    // XML з czo.gov.ua, дефолтний timeout 30 с) — паралельний GetError()/
    // будь-який метод на тому ж Session блокувався на весь цей час. Тепер lock
    // тримається лише для (1) перевірки стану + знімка work_dir/trust_list_settings_
    // і (2) короткого фінального коміту last_trust_list_sync_report_; мережевий
    // sync.Sync працює над ЛОКАЛЬНИМИ копіями, без lock_guard — той самий
    // патерн, що WP-17/ME-04/PR #39 застосували до Verify*-методів.
    std::string work_dir;
    TrustListSettings tl_settings;
    bool offline_mode = true;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        work_dir = settings_.work_dir;
        tl_settings = trust_list_settings_;
        offline_mode = settings_.offline_mode;
    }

    // FND-003: offline є capability boundary, а не підказкою для окремих
    // resolver-ів. Відхиляємо sync ДО створення TrustListSync і HTTP-виклику.
    if (offline_mode) {
        std::lock_guard<std::mutex> lock(mutex_);
        last_trust_list_sync_report_.checked = true;
        last_trust_list_sync_report_.update_succeeded = false;
        last_trust_list_sync_report_.source = tl_settings.url;
        last_trust_list_sync_report_.cache_status = "blocked-offline";
        last_trust_list_sync_report_.last_sync.clear();
        last_trust_list_sync_report_.xml_signature_status = "not-checked-offline";
        SetError(ErrorCode::OnlineServiceUnavailable,
                 "Trust list synchronization is disabled in offline mode");
        return false;
    }

    ::tamga::core::policy::TrustListSync sync;
    const auto result = sync.Sync(work_dir, tl_settings);

    // WP-17 (ME-06): пишемо в окремий last_trust_list_sync_report_, а не в
    // last_verify_report_ — інакше цей виклик стер би trust-list-діагностику,
    // яку встановив попередній Verify*, або її стер би наступний Verify*
    // (кожен Verify* створює свіжий VerifyReport).
    std::lock_guard<std::mutex> lock(mutex_);
    last_trust_list_sync_report_.checked = true;
    last_trust_list_sync_report_.update_succeeded = result.succeeded;
    last_trust_list_sync_report_.source = result.source_url;
    last_trust_list_sync_report_.cache_status = result.cache_status;
    last_trust_list_sync_report_.last_sync = result.last_sync;
    last_trust_list_sync_report_.xml_signature_status = result.xml_signature_status;
    if (!result.succeeded) {
        SetError(ErrorCode::OnlineServiceUnavailable, result.message);
        return false;
    }
    ClearError();
    return true;
}

bool Session::DescribeSupportedMedia(std::string& out_json) const {
    std::ostringstream json;
    json << "{"
         << "\"version\":2,"
         << "\"media\":[\"pkcs12\",\"pkcs8\",\"jks\",\"pem\",\"der\"],"
         << "\"gui\":false,"
         << "\"cryptoniteEnabled\":" << (TAMGA_CRYPTONITE_ENABLED ? "true" : "false") << ","
         << "\"signing\":{"
         << "\"detached\":" << (TAMGA_CRYPTONITE_ENABLED ? "true" : "false") << ","
         << "\"attached\":" << (TAMGA_CRYPTONITE_ENABLED ? "true" : "false") << ","
         << "\"requiresCryptonite\":true"
         << "},"
         << "\"verificationPolicy\":{"
         << "\"detached\":\"crypto-integrity-plus-embedded-chain\","
         << "\"attached\":\"crypto-integrity-plus-embedded-chain\","
         << "\"embeddedChainValidation\":true,"
         << "\"certificateTimeValidation\":true,"
         << "\"trustValidation\":" << (TAMGA_CRYPTONITE_ENABLED ? "true" : "false") << ","
         << "\"revocationValidation\":" << (TAMGA_CRYPTONITE_ENABLED ? "true" : "false") << ","
         << "\"trustStoreTransport\":true"
         << "},"
         << "\"networkProviders\":{"
         << "\"ocsp\":" << (TAMGA_HTTP_ENABLED ? "true" : "false") << ","
         << "\"tsp\":" << (TAMGA_HTTP_ENABLED ? "true" : "false") << ","
         << "\"ldap\":false,"
         << "\"cmp\":false"
         << "}"
         << "}";
    out_json = json.str();
    return true;
}
