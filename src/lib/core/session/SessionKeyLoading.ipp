bool Session::ReadPrivateKey(const std::string& media_descriptor_json, std::string password) {
    std::string descriptor_password;
    if (TryExtractJsonString(media_descriptor_json, "password", descriptor_password) && password.empty()) {
        password = std::move(descriptor_password);
    }

    std::string key_password = password;
    std::string descriptor_key_password;
    if (TryExtractJsonString(media_descriptor_json, "keyPassword", descriptor_key_password) ||
        TryExtractJsonString(media_descriptor_json, "entryPassword", descriptor_key_password)) {
        key_password = std::move(descriptor_key_password);
    }

    std::string jks_alias;
    (void)TryExtractJsonString(media_descriptor_json, "alias", jks_alias);

    bool strict_pem = false;
    (void)TryExtractJsonBool(media_descriptor_json, "strictPem", strict_pem);

    // Рівень 1 авто-резолвера: явне джерело відкритого сертифіката для контейнерів
    // без certBag. Приймаємо обидва варіанти назв, бо різні інтеграції 1С уже
    // використовують і скорочену, і повну форму.
    CertificateHints cert_hints;
    if (!TryExtractJsonString(media_descriptor_json, "certificatePath", cert_hints.certificate_path)) {
        (void)TryExtractJsonString(media_descriptor_json, "certPath", cert_hints.certificate_path);
    }
    if (!TryExtractJsonString(media_descriptor_json, "certificateBase64", cert_hints.certificate_base64)) {
        (void)TryExtractJsonString(media_descriptor_json, "certBase64", cert_hints.certificate_base64);
    }
    if (!TryExtractJsonString(media_descriptor_json, "ca", cert_hints.ca_hint)) {
        (void)TryExtractJsonString(media_descriptor_json, "provider", cert_hints.ca_hint);
    }
    // Рівень 3: ідентифікатор власника для пошуку в LDAP-каталозі КНЕДП.
    // Приймаємо звичні для 1С назви — ЄДРПОУ для юросіб, ДРФО для фізосіб.
    if (!TryExtractJsonString(media_descriptor_json, "edrpou", cert_hints.subject_identifier)) {
        if (!TryExtractJsonString(media_descriptor_json, "drfo", cert_hints.subject_identifier)) {
            (void)TryExtractJsonString(media_descriptor_json, "subject", cert_hints.subject_identifier);
        }
    }

    std::string base64_payload;
    if (TryExtractJsonString(media_descriptor_json, "base64", base64_payload)) {
        std::vector<std::uint8_t> payload;
        if (!util::Base64Decode(base64_payload, payload)) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::InvalidArgument, "Descriptor base64 is invalid");
            SecureErase(password);
            SecureErase(key_password);
            SecureErase(jks_alias);
            return false;
        }
        return LoadKeyFromBytes(payload, std::move(password), std::move(key_password), std::move(jks_alias), strict_pem, cert_hints);
    }

    std::string path;
    if (TryExtractJsonString(media_descriptor_json, "path", path) ||
        TryExtractJsonString(media_descriptor_json, "filePath", path)) {
        if (path.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::InvalidArgument, "Path is empty");
            SecureErase(password);
            SecureErase(key_password);
            SecureErase(jks_alias);
            return false;
        }

        FileStoreSettings file_settings;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            file_settings = file_store_settings_;
        }

        // Рівень 2: реальний шлях до ключа — база для sidecar-пошуку (key.dat -> key.cer).
        const auto resolved_key_path = ResolveFilePath(path, file_settings);
        cert_hints.key_file_path = resolved_key_path;

        std::vector<std::uint8_t> key_data;
        std::string error_message;
        if (!ReadBinaryFile(resolved_key_path, "key file", key_data, error_message)) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::InvalidArgument, std::move(error_message));
            SecureErase(password);
            SecureErase(key_password);
            SecureErase(jks_alias);
            return false;
        }
        if (key_data.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::InvalidArgument, "Key file is empty");
            SecureErase(password);
            SecureErase(key_password);
            SecureErase(jks_alias);
            return false;
        }

        return LoadKeyFromBytes(key_data, std::move(password), std::move(key_password), std::move(jks_alias), strict_pem, cert_hints);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    SetError(ErrorCode::InvalidArgument, "Unsupported key media descriptor");
    SecureErase(password);
    SecureErase(key_password);
    SecureErase(jks_alias);
    return false;
}

bool Session::ReadPrivateKeyBinary(const std::vector<std::uint8_t>& key_data,
                                   std::string store_password,
                                   std::string key_password,
                                   std::string jks_alias) {
    return LoadKeyFromBytes(key_data, std::move(store_password), std::move(key_password), std::move(jks_alias), false);
}

bool Session::ReadPrivateKeyFile(const std::string& path,
                                 std::string store_password,
                                 std::string key_password,
                                 std::string jks_alias) {
    if (path.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Path is empty");
        SecureErase(store_password);
        SecureErase(key_password);
        SecureErase(jks_alias);
        return false;
    }

    FileStoreSettings file_settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        file_settings = file_store_settings_;
    }

    // Sidecar-пошук працює і для цього прямого API: саме ним користуються CLI та
    // NativeAPI `LoadKey`, тобто типовий шлях «поруч із key.dat лежить key.cer».
    const auto resolved_key_path = ResolveFilePath(path, file_settings);
    CertificateHints cert_hints;
    cert_hints.key_file_path = resolved_key_path;

    std::vector<std::uint8_t> key_data;
    std::string error_message;
    if (!ReadBinaryFile(resolved_key_path, "key file", key_data, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        SecureErase(store_password);
        SecureErase(key_password);
        SecureErase(jks_alias);
        return false;
    }
    if (key_data.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Key file is empty");
        SecureErase(store_password);
        SecureErase(key_password);
        SecureErase(jks_alias);
        return false;
    }

    return LoadKeyFromBytes(key_data, std::move(store_password), std::move(key_password), std::move(jks_alias), false, cert_hints);
}

bool Session::ResetPrivateKey() {
    std::lock_guard<std::mutex> lock(mutex_);
    SecureClearLoadedKey();
    is_private_key_loaded_ = false;
    ClearError();
    return true;
}

bool Session::Base64Encode(const std::vector<std::uint8_t>& input, std::string& out) const {
    out = util::Base64Encode(input);
    return true;
}

bool Session::Base64Decode(const std::string& input, std::vector<std::uint8_t>& out) const {
    // С-20: єдиний метод сесії, що не виставляв стан помилки. Після невдачі
    // GetError() повертав СТАРУ помилку попередньої операції — тобто метод
    // мовчки порушував власний контракт сесії, і 1С бачила чужу діагностику.
    if (util::Base64Decode(input, out)) {
        std::lock_guard<std::mutex> lock(mutex_);
        const_cast<Session*>(this)->ClearError();
        return true;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    const_cast<Session*>(this)->SetError(ErrorCode::InvalidArgument,
                                         "Base64 input is not valid");
    return false;
}
