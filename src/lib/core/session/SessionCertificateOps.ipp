bool Session::GetCertificateInfo(const std::vector<std::uint8_t>& cert_data, std::string& out_json,
                                 const std::string& validation_time_iso) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cert_data.empty()) {
        SetError(ErrorCode::InvalidArgument, "Certificate blob is empty");
        return false;
    }
    // ME-08: `validNow`/`validAtCurrentTime` нижче — це тільки cert.notBefore/
    // notAfter відносно ПОТОЧНОГО часу виклику, а НЕ те саме, що
    // `certificate.timeValid` у verify-звіті (який ставиться відносно
    // validation_time_source -- довіреного timestamp'а чи заявленого часу
    // підпису, залежно від профілю). Архівний підпис із простроченим ЗАРАЗ
    // сертифікатом підписанта коректно показує certificate.timeValid=true у
    // verify-звіті (бо перевірявся на момент довіреного timestamp'а), але тут
    // validNow=false -- це очікувана, а не суперечлива поведінка. Опційний
    // validationTimeIso (ISO 8601, напр. "2026-06-15T12:00:00Z") дозволяє
    // перевірити валідність на довільний момент часу через новий блок
    // "validAt" нижче, замість лише "зараз".
    bool validation_time_requested = !validation_time_iso.empty();
    time_t requested_time = 0;
    if (validation_time_requested &&
        !tamga::core::policy::ParseIso8601Time(validation_time_iso, requested_time)) {
        SetError(ErrorCode::InvalidArgument, "validationTimeIso is not a valid ISO 8601 timestamp");
        return false;
    }

    TlvView outer{};
    if (!ParseTlvAt(cert_data, 0, outer) || outer.tag != 0x30) {
        SetError(ErrorCode::InvalidArgument, "Certificate is not a valid DER SEQUENCE");
        return false;
    }
    TlvView tbs{};
    if (!ParseTlvAt(cert_data, outer.value_offset, tbs) || tbs.tag != 0x30) {
        SetError(ErrorCode::InvalidArgument, "Certificate TBS section is missing");
        return false;
    }

    std::size_t offset = tbs.value_offset;
    TlvView node{};
    if (!ParseTlvAt(cert_data, offset, node)) {
        SetError(ErrorCode::InvalidArgument, "Certificate parsing failed");
        return false;
    }
    if (node.tag == 0xA0) {
        offset = node.next_offset;
    }

    TlvView serial{};
    if (!ParseTlvAt(cert_data, offset, serial) || serial.tag != 0x02) {
        SetError(ErrorCode::InvalidArgument, "Certificate serial is missing");
        return false;
    }

    std::string serial_hex = HexEncode(&cert_data[serial.value_offset], serial.value_length);

    TlvView signature_algo{};
    TlvView issuer_tlv{};
    TlvView validity_tlv{};
    TlvView subject_tlv{};
    std::string issuer_dn;
    std::string subject_dn;
    if (ParseTlvAt(cert_data, serial.next_offset, signature_algo) && ParseTlvAt(cert_data, signature_algo.next_offset, issuer_tlv) &&
        ParseTlvAt(cert_data, issuer_tlv.next_offset, validity_tlv) && ParseTlvAt(cert_data, validity_tlv.next_offset, subject_tlv) &&
        issuer_tlv.tag == 0x30 && subject_tlv.tag == 0x30) {
        issuer_dn = FormatRdnSequence(&cert_data[issuer_tlv.value_offset], issuer_tlv.value_length);
        subject_dn = FormatRdnSequence(&cert_data[subject_tlv.value_offset], subject_tlv.value_length);
    }
    std::string not_before;
    std::string not_after;
    bool valid_now = false;
    time_t not_before_ts = 0;
    time_t not_after_ts = 0;
    bool has_validity = ParseValidityWindow(cert_data, not_before, not_after, valid_now, not_before_ts, not_after_ts);
    std::string key_usage = ExtractExtensionHex(cert_data, {0x55, 0x1D, 0x0F}, false);
    std::string subject_key_identifier = ExtractExtensionHex(cert_data, {0x55, 0x1D, 0x0E}, true);
    std::string ext_key_usage;
    std::string subject_alt_name;
    std::string crl_distribution_points;
    std::string authority_key_identifier;

#if TAMGA_CRYPTONITE_ENABLED
    ByteArray* cert_blob = ba_alloc_from_uint8(cert_data.data(), cert_data.size());
    Certificate_t* cert = cert_alloc();
    if (cert_blob == nullptr || cert == nullptr || cert_decode(cert, cert_blob) != RET_OK) {
        ba_free(cert_blob);
        cert_free(cert);
        SetError(ErrorCode::InvalidArgument, "Certificate decode via cryptonite cert API failed");
        return false;
    }

    ByteArray* serial_ba = nullptr;
    if (cert_get_sn(cert, &serial_ba) == RET_OK && serial_ba != nullptr) {
        serial_hex = HexEncode(ba_get_buf(serial_ba), ba_get_len(serial_ba));
    }
    ba_free(serial_ba);

    time_t cryptonite_not_before_ts = 0;
    time_t cryptonite_not_after_ts = 0;
    if (cert_get_not_before(cert, &cryptonite_not_before_ts) == RET_OK && cert_get_not_after(cert, &cryptonite_not_after_ts) == RET_OK) {
        const std::string not_before_formatted = FormatUnixTimeUtc(cryptonite_not_before_ts);
        const std::string not_after_formatted = FormatUnixTimeUtc(cryptonite_not_after_ts);
        if (!not_before_formatted.empty() && !not_after_formatted.empty()) {
            not_before = not_before_formatted;
            not_after = not_after_formatted;
            not_before_ts = cryptonite_not_before_ts;
            not_after_ts = cryptonite_not_after_ts;
            has_validity = true;
            valid_now = cert_check_validity(cert) == RET_OK;
        }
    }

    TBSCertificate_t* tbs_cert = nullptr;
    if (cert_get_tbs_cert(cert, &tbs_cert) == RET_OK && tbs_cert != nullptr) {
        issuer_dn = FormatNameRfc4514(&tbs_cert->issuer);
        subject_dn = FormatNameRfc4514(&tbs_cert->subject);
        ASN_FREE(get_TBSCertificate_desc(), tbs_cert);
    }

    key_usage = ExtractCertExtensionHex(cert, OID_KEY_USAGE_EXTENSION_ID, false);
    subject_key_identifier = ExtractCertExtensionHex(cert, OID_SUBJECT_KEY_IDENTIFIER_EXTENSION_ID, true);
    ext_key_usage = ExtractCertExtensionHex(cert, OID_EXT_KEY_USAGE_EXTENSION_ID, false);
    subject_alt_name = ExtractCertExtensionHex(cert, OID_SUBJECT_ALT_NAME_EXTENSION_ID, false);
    crl_distribution_points = ExtractCertExtensionHex(cert, OID_CRL_DISTRIBUTION_POINTS_EXTENSION_ID, false);

    ByteArray* auth_key_id_ba = nullptr;
    if (cert_get_auth_key_id(cert, &auth_key_id_ba) == RET_OK && auth_key_id_ba != nullptr) {
        authority_key_identifier = HexEncode(ba_get_buf(auth_key_id_ba), ba_get_len(auth_key_id_ba));
    }
    ba_free(auth_key_id_ba);

    ba_free(cert_blob);
    cert_free(cert);
#endif

    // ME-08: validAt обчислюється з тих самих not_before_ts/not_after_ts, що
    // й has_validity/valid_now вище (уніфіковано між TLV-only і cryptonite
    // шляхами через ParseValidityWindow/cert_get_not_before/cert_get_not_after).
    const bool valid_at_requested_time = has_validity && validation_time_requested &&
        requested_time >= not_before_ts && requested_time <= not_after_ts;

    std::ostringstream json;
    json << "{";
    json << "\"serial\":\"" << serial_hex << "\",";
    json << "\"validity\":{";
    json << "\"notBefore\":\"" << EscapeJson(not_before) << "\",";
    json << "\"notAfter\":\"" << EscapeJson(not_after) << "\",";
    json << "\"validNow\":" << (has_validity && valid_now ? "true" : "false") << ",";
    // ME-08: validAtCurrentTime -- явна, однозначна назва для того самого
    // значення, що validNow (legacy, збережено для сумісності). Обидва НЕ є
    // тим самим, що certificate.timeValid у verify-звіті -- див. коментар на
    // початку функції.
    json << "\"validAtCurrentTime\":" << (has_validity && valid_now ? "true" : "false") << ",";
    json << "\"validAt\":{";
    json << "\"time\":\"" << EscapeJson(validation_time_requested ? validation_time_iso : std::string()) << "\",";
    json << "\"valid\":" << (valid_at_requested_time ? "true" : "false");
    json << "}";
    json << "},";
    json << "\"keyUsage\":\"" << key_usage << "\",";
    json << "\"extKeyUsage\":\"" << ext_key_usage << "\",";
    json << "\"subjectKeyIdentifier\":\"" << subject_key_identifier << "\",";
    json << "\"authorityKeyIdentifier\":\"" << authority_key_identifier << "\",";
    json << "\"subjectAltName\":\"" << subject_alt_name << "\",";
    json << "\"crlDistributionPoints\":\"" << crl_distribution_points << "\",";
    json << "\"issuerDn\":\"" << EscapeJson(issuer_dn) << "\",";
    json << "\"subjectDn\":\"" << EscapeJson(subject_dn) << "\"";
    json << "}";
    out_json = json.str();
    ClearError();
    return true;
}

bool Session::CheckCertificateRevocation(const std::vector<std::uint8_t>& cert_data,
                                         const std::vector<std::uint8_t>& crl_data,
                                         const std::vector<std::uint8_t>& issuer_cert_data,
                                         std::string& out_json) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (cert_data.empty()) {
        SetError(ErrorCode::InvalidArgument, "Certificate blob is empty");
        return false;
    }
    if (crl_data.empty()) {
        SetError(ErrorCode::InvalidArgument, "CRL blob is empty");
        return false;
    }

#if TAMGA_CRYPTONITE_ENABLED
    auto result = CryptoniteAdapter::CheckCertificateRevocation(cert_data, crl_data, issuer_cert_data);

    std::ostringstream json;
    json << "{"
         << "\"checked\":" << (result.checked ? "true" : "false") << ","
         << "\"revoked\":" << (result.revoked ? "true" : "false") << ","
         << "\"crlSignatureValid\":" << (result.crl_valid ? "true" : "false") << ","
         << "\"message\":\"" << EscapeJson(result.message) << "\""
         << "}";
    out_json = json.str();
    ClearError();
    return true;
#else
    (void)crl_data;
    (void)issuer_cert_data;
    (void)out_json;
    SetError(ErrorCode::NotSupported, kCryptoniteRequiredMessage);
    return false;
#endif
}

namespace {

// Хвиля 8, п.1 (залишок): і вердикти, і РОЗМІТКА секцій тепер спільні з
// користувацьким звітом — `core/policy/VerifyChecks` і
// `core/policy/VerifyReportJson`. Тут лишилася тільки емісія того, чого
// в користувацькому звіті немає: signaturePolicy, dataObjectFormats,
// signatures[] і повна діагностика.

// WP-12: SignedDataObjectProperties/DataObjectFormat* (ETSI EN 319 132-1
// §5.2.2) як JSON-масив — спільний для верхньорівневого report і кожного
// SignatureEntry.
void WriteV2DataObjectFormats(std::ostringstream& json, const std::vector<DataObjectFormatEntry>& formats) {
    json << "[";
    bool first = true;
    for (const auto& dof : formats) {
        if (!first) json << ",";
        first = false;
        json << "{\"objectReference\":\"" << EscapeJson(dof.object_reference) << "\""
             << ",\"mimeType\":\"" << EscapeJson(dof.mime_type) << "\""
             << ",\"description\":\"" << EscapeJson(dof.description) << "\"}";
    }
    json << "]";
}

// WP-2 (Session-інтеграція): плаский масив per-signature крипто-стану для
// документів/контейнерів із кількома ds:Signature. Порожній масив -> операція
// без XAdES-мультипідпису (SignData/VerifyFile тощо) або ще не виконана.
void WriteV2Signatures(std::ostringstream& json, const VerifyReport& report) {
    json << "\"signatures\":[";
    bool first = true;
    for (const auto& entry : report.signatures) {
        if (!first) json << ",";
        first = false;
        json << "{\"index\":" << entry.index
             << ",\"signatureValid\":" << BoolJson(entry.signature_valid)
             << ",\"certificatePresent\":" << BoolJson(entry.signer_certificate_present)
             << ",\"qualifyingPropertiesPresent\":" << BoolJson(entry.qualifying_properties_present)
             << ",\"signingCertificateDigestValid\":" << BoolJson(entry.signing_certificate_digest_valid)
             << ",\"profile\":\"" << EscapeJson(entry.format_profile) << "\""
             << ",\"timestampChecked\":" << BoolJson(entry.timestamp_checked)
             << ",\"timestampValid\":" << BoolJson(entry.timestamp_valid)
             << ",\"timestampStatus\":\"" << EscapeJson(entry.timestamp_status) << "\""
             << ",\"timestamps\":";
        policy::WriteTimestampDetails(json, entry.timestamp_details);
        json << ",\"ltvValid\":" << BoolJson(entry.ltv_valid)
             // HI-02: evidence-binding (структурний сигнал, trust-незалежний).
             << ",\"ltvEvidenceBound\":" << BoolJson(entry.ltv_evidence_bound)
             // HI-01: докази прив'язані І trust-ланцюг САМЕ цього підписанта
             // довірений І його відкликання підтверджено — див. коментар при
             // SignatureEntry::ltv_evidence_validated у Session.h.
             << ",\"ltvEvidenceValidated\":" << BoolJson(entry.ltv_evidence_validated)
             // HI-01: повна незалежна trust/revocation/certificate.timeValid
             // перевірка САМЕ цього підписанта (окремий X.509 chain + OCSP/CRL
             // на кожного співпідписанта, а не лише на репрезентативного).
             << ",\"certificate\":{\"timeValid\":" << BoolJson(entry.certificate_time_valid)
             << ",\"validationTimeSource\":\"" << EscapeJson(entry.validation_time_source) << "\""
             << ",\"chain\":{\"checked\":" << BoolJson(entry.chain_checked)
             << ",\"valid\":" << BoolJson(entry.chain_valid) << "}}"
             << ",\"trust\":{\"checked\":" << BoolJson(entry.trust_checked)
             << ",\"valid\":" << BoolJson(entry.trust_valid)
             << ",\"mode\":\"" << EscapeJson(entry.trust_mode) << "\""
             << ",\"reason\":\"" << EscapeJson(entry.trust_reason) << "\""
             << ",\"trustStatus\":\"" << EscapeJson(entry.trust_status) << "\""
             << ",\"historicalTrustUsed\":" << BoolJson(entry.historical_trust_used)
             << ",\"historicalAnchor\":{\"subject\":\"" << EscapeJson(entry.historical_anchor_subject)
             << "\",\"serial\":\"" << EscapeJson(entry.historical_anchor_serial) << "\"}}"
             << ",\"revocation\":{\"checked\":" << BoolJson(entry.revocation_checked)
             << ",\"ocspChecked\":" << BoolJson(entry.ocsp_checked)
             << ",\"revocationStatus\":\"" << EscapeJson(entry.revocation_status) << "\"}"
             << ",\"signaturePolicyPresent\":" << BoolJson(entry.signature_policy_present)
             << ",\"signaturePolicyId\":\"" << EscapeJson(entry.signature_policy_id) << "\""
             << ",\"signaturePolicyHashAlgorithmUri\":\"" << EscapeJson(entry.signature_policy_hash_algo_uri) << "\""
             << ",\"dataObjectFormats\":";
        WriteV2DataObjectFormats(json, entry.data_object_formats);
        json << "}";
    }
    json << "]";
}

} // namespace

bool Session::GetLastVerifyReport(std::string& out_json) const {
    std::lock_guard<std::mutex> lock(mutex_);

    const auto& r = last_verify_report_;
    // Лишився тільки той предикат, який справді потрібен нижче у
    // diagnostics.flags. Два інші (`ocsp_checked`, `revocation_checked`)
    // рахувалися й не використовувалися після Хвилі 8, п.1: спільний
    // емітер тепер обчислює їх сам. Компілятор називав це C4189.
    const bool certificate_time_valid = policy::EffectiveCertificateTimeValid(r);

    // Технічний звіт не додає до вердиктів двомовних повідомлень: його
    // `code` читає програма, а не людина.
    constexpr policy::MessageStyle kStyle = policy::MessageStyle::None;
    const policy::FormatFallbacks kNoFallbacks;

    std::ostringstream json;
    json << "{\"schemaVersion\":\"2.2\",";

    policy::WriteSummarySection(json, r, kStyle);

    policy::SignatureSectionExtras signature_extras;
    signature_extras.validated_profile = &r.validated_profile;
    policy::WriteSignatureSection(json, r, kNoFallbacks, signature_extras, kStyle);

    policy::CertificateSectionExtras certificate_extras;
    certificate_extras.qualifying_properties_present = &r.qualifying_properties_present;
    policy::WriteCertificateSection(json, r, certificate_extras, kStyle);

    policy::WriteTrustSection(json, r, kStyle);
    policy::WriteRevocationSection(json, r, kStyle);
    policy::WriteTimestampSection(json, r, kStyle);
    policy::WriteLtvSection(json, r, kStyle);

    // WP-12: SignaturePolicyIdentifier/SignedDataObjectProperties (ETSI EN 319
    // 132-1 §5.2.1.3/§5.2.2) для репрезентативного підпису — структурний
    // парсинг рушія (XadesBuilder/XadesVerifier), БЕЗ криптографічної
    // перевірки signaturePolicyId проти реального зовнішнього документа
    // політики. Per-signature деталі — у signatures[] нижче.
    json << "\"signaturePolicy\":{"
         << "\"present\":" << BoolJson(r.signature_policy_present)
         << ",\"id\":\"" << EscapeJson(r.signature_policy_id) << "\""
         << ",\"hashAlgorithmUri\":\"" << EscapeJson(r.signature_policy_hash_algo_uri) << "\"},";
    json << "\"dataObjectFormats\":";
    WriteV2DataObjectFormats(json, r.data_object_formats);
    json << ",";

    policy::WritePolicySection(json, r, kStyle);

    policy::WriteDiagnosticsPrefix(json, r, kNoFallbacks);
    json
         << ",\"message\":\"" << EscapeJson(r.message) << "\""
         << ",\"trustList\":{"
         << "\"checked\":" << BoolJson(r.trust_list_checked)
         << ",\"source\":\"" << EscapeJson(r.trust_list_source) << "\""
         << ",\"cacheStatus\":\"" << EscapeJson(r.trust_list_cache_status) << "\""
         << ",\"lastSync\":\"" << EscapeJson(r.trust_list_last_sync) << "\""
         << ",\"updateSucceeded\":" << BoolJson(r.trust_list_update_succeeded)
         << "}"
         // WP-17 (ME-06): стан ОСТАННЬОГО явного SyncTrustList() — окремо від
         // `trustList` вище (яке описує лише trust-list-стан ЦЬОГО verify-виклику,
         // з ValidationEngine chain validation). Незалежні один від одного:
         // виклик SyncTrustList() між двома Verify* більше не підмінює
         // діагностику жодного з них.
         << ",\"trustListSync\":{"
         << "\"checked\":" << BoolJson(last_trust_list_sync_report_.checked)
         << ",\"source\":\"" << EscapeJson(last_trust_list_sync_report_.source) << "\""
         << ",\"cacheStatus\":\"" << EscapeJson(last_trust_list_sync_report_.cache_status) << "\""
         << ",\"lastSync\":\"" << EscapeJson(last_trust_list_sync_report_.last_sync) << "\""
         << ",\"updateSucceeded\":" << BoolJson(last_trust_list_sync_report_.update_succeeded)
         << ",\"xmlSignatureStatus\":\"" << EscapeJson(last_trust_list_sync_report_.xml_signature_status) << "\""
         << "}"
         << ",\"chainDebug\":{\"trace\":\"" << EscapeJson(r.chain_debug) << "\"}"
         << ",";
    policy::WriteDiagnosticsFlagsPrefix(json, r);
    json
         << ",\"cmsSignerCount\":" << r.cms_signer_count
         << ",\"cmsVerifiedSignerCount\":" << r.cms_verified_signer_count
         << ",\"signerCertificatePresent\":" << BoolJson(r.signer_certificate_present)
         << ",\"certificateTimeValid\":" << BoolJson(certificate_time_valid)
         << ",\"chainChecked\":" << BoolJson(r.chain_checked)
         << ",\"chainValid\":" << BoolJson(r.chain_valid)
         << ",\"ltvValid\":" << BoolJson(r.ltv_valid)
         << ",\"containerCoverageComplete\":" << BoolJson(r.container_coverage_complete)
         << "}},";

    WriteV2Signatures(json, r);

    json << "}";
    out_json = json.str();
    return true;
}

bool Session::GetUserReport(std::string& out_json) const {
    std::lock_guard<std::mutex> lock(mutex_);
    out_json = last_user_report_json_;
    return true;
}

namespace {

// ME-06 (повний фікс): TL-based резолюція за рішенням користувача — (1)
// читає workDir\policy\trust-store-metadata.json ЩОРАЗУ (без in-memory
// кешу сесії, щоб коректно переживати рестарт процесу 1С-компоненти між
// викликами SignData); (2) без provider-matching — бере ПЕРШИЙ ГРАНТОВАНИЙ
// TSA-сервіс з офіційного TL, незалежно від issuer'а сертифіката підписанта
// (RFC 3161 не вимагає такого зв'язку); (3) локальний файл, тому дозволено
// навіть у offline_mode. Хардкод-таблиця нижче лишається як safety net,
// коли TL ще не синхронізовано чи в кеші немає жодного TSA-сервісу.
std::string ResolveDefaultTspUrlFromTrustList(const std::string& work_dir) {
    if (work_dir.empty()) {
        return "";
    }
    return tamga::core::policy::PolicyCache(work_dir).ResolveGrantedTspUrl();
}

// ME-06: цей маппінг — best-effort compatibility fallback, що застосовується
// ЛИШЕ коли TL-based резолюція вище не дала URL (TL не синхронізовано чи
// немає TSA-сервісів у кеші) і SignData/SignDataInternal не отримали явного
// TSP URL через ConfigureTsp(). Він НЕ є security- чи policy-рішенням:
// обраний тут URL визначає лише КУДИ надіслати timestamp-запит під час
// підпису; сам RFC3161-токен, що повертається, незалежно й повністю
// криптографічно перевіряється (chain/EKU/timestamp-policy у
// TimestampValidator) кожним, хто пізніше верифікує підпис, — підміна цього
// URL (MITM/застарілий/хибний маппінг) у гіршому разі призводить до
// неуспішного/недовіреного timestamp на своєму ж підписі, а НЕ до
// прихованого прийняття підробленого доказу часу. Issuer-DN substring —
// крихке джерело (issuer може змінитись, збіг за підрядком неточний), і
// частина адрес досі на `http://` (сам timestamp-request, не
// токен-відповідь). Для production/regulated використання — явно
// викликайте ConfigureTsp() або синхронізуйте TL через SyncTrustList().
std::string ResolveDefaultTspUrlFromIssuerTable(const std::vector<std::uint8_t>& certificate) {
#if TAMGA_CRYPTONITE_ENABLED
    if (certificate.empty()) {
        return "";
    }

    ByteArray* cert_blob = ba_alloc_from_uint8(certificate.data(), certificate.size());
    Certificate_t* cert = cert_alloc();
    if (cert_blob == nullptr || cert == nullptr || cert_decode(cert, cert_blob) != RET_OK) {
        if (cert_blob) ba_free(cert_blob);
        if (cert) cert_free(cert);
        return "";
    }

    std::string issuer_dn;
    TBSCertificate_t* tbs_cert = nullptr;
    if (cert_get_tbs_cert(cert, &tbs_cert) == RET_OK && tbs_cert != nullptr) {
        issuer_dn = FormatNameRfc4514(&tbs_cert->issuer);
        ASN_FREE(get_TBSCertificate_desc(), tbs_cert);
    }
    cert_free(cert);
    ba_free(cert_blob);

    if (issuer_dn.empty()) {
        return "";
    }

    if (issuer_dn.find("ПРИВАТБАНК") != std::string::npos || issuer_dn.find("PRIVATBANK") != std::string::npos) {
        return "https:" "//acsk.privatbank.ua/services/tsp/";
    }
    if (issuer_dn.find("Дія") != std::string::npos || issuer_dn.find("DIIA") != std::string::npos || issuer_dn.find("юстиції") != std::string::npos) {
        return "http:" "//ca.informjust.ua/services/tsp/";
    }
    if (issuer_dn.find("ДПС") != std::string::npos || issuer_dn.find("TAX") != std::string::npos || issuer_dn.find("ІДД") != std::string::npos) {
        return "http:" "//ca.tax.gov.ua/services/tsp/";
    }
    if (issuer_dn.find("Ощадбанк") != std::string::npos || issuer_dn.find("Oschadbank") != std::string::npos) {
        return "http:" "//ca.oschadbank.ua/public/tsp";
    }
    if (issuer_dn.find("Казначейств") != std::string::npos || issuer_dn.find("treasury") != std::string::npos) {
        return "http:" "//ca.treasury.gov.ua:43221";
    }
    if (issuer_dn.find("Вчасно") != std::string::npos || issuer_dn.find("Vchasno") != std::string::npos) {
        return "http:" "//ca.vchasno.ua/services/tsp/dstu/";
    }
    if (issuer_dn.find("ДЕПОЗИТ САЙН") != std::string::npos || issuer_dn.find("DEPOSIT SIGN") != std::string::npos) {
        return "http:" "//ca.depositsign.com/services/tsp/dstu/";
    }
    if (issuer_dn.find("Україна") != std::string::npos || issuer_dn.find("uakey") != std::string::npos) {
        return "http:" "//uakey.com.ua/services/tsp/";
    }
    if (issuer_dn.find("monobank") != std::string::npos) {
        return "https:" "//ca.monobank.ua/services/tsp/dstu/";
    }
    if (issuer_dn.find("MASTERKEY") != std::string::npos || issuer_dn.find("АРТ-МАСТЕР") != std::string::npos || issuer_dn.find("Арт-мастер") != std::string::npos) {
        return "http:" "//masterkey.ua/services/tsp/";
    }
    if (issuer_dn.find("Укрзалізниці") != std::string::npos) {
        return "http:" "//csk.uz.gov.ua/services/tsp/";
    }
#else
    (void)certificate;
#endif
    return "";
}

// ME-06: єдина точка входу для callers (SignData/SignDataInternal/
// Session::ResolveDefaultTspUrl) — TL-based резолюція спочатку, хардкод-
// таблиця як safety net. Назва навмисно відрізняється від публічного
// Session::ResolveDefaultTspUrl(), щоб уникнути затінення імені методу
// всередині його ж тіла (unqualified lookup у member-функції спершу бачить
// ім'я класу, тому виклик з іншою кількістю аргументів був би помилкою
// компіляції, а не вибором цієї вільної функції).
std::string ResolveDefaultTspUrlCombined(const std::vector<std::uint8_t>& certificate, const std::string& work_dir) {
    std::string tsp_url = ResolveDefaultTspUrlFromTrustList(work_dir);
    if (!tsp_url.empty()) {
        return tsp_url;
    }
    return ResolveDefaultTspUrlFromIssuerTable(certificate);
}

} // namespace

std::string Session::ResolveDefaultTspUrl() const {
    std::vector<std::uint8_t> certificate;
    std::string work_dir;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        certificate = loaded_certificate_;
        work_dir = settings_.work_dir;
    }
    return ResolveDefaultTspUrlCombined(certificate, work_dir);
}
