namespace tamga::core {

// O-02: типи ASiC-контейнера живуть у власній підсистемі (src/lib/asic,
// namespace tamga::asic). Директива обмежена цим фрагментом TU і лишає
// тіла операцій без змін — межа підсистеми при цьому справжня, а не
// декларативна: core більше не ВОЛОДІЄ цими типами.
using namespace tamga::asic;


namespace {

// Чи лежить у контейнері XAdES-підпис (META-INF/signatures*.xml).
//
// ETSI EN 319 162-1 допускає дві розкладки: CAdES (META-INF/signature.p7s) і
// XAdES (META-INF/signatures*.xml). Розкладку визначає ВМІСТ контейнера, а не
// ім'я формату, з яким його прийшли перевіряти: інакше `asic-s`/`asic-e` не
// прочитали б власний новий вихід, а `asic-e-cades` — старі контейнери.
bool ContainerHasXadesSignature(const std::vector<std::uint8_t>& container) {
    tamga::asic::AsicReader reader;
    std::string error_message;
    if (!reader.LoadFromBuffer(container, error_message)) {
        return false;
    }
    std::vector<tamga::asic::AsicFileEntry> entries;
    if (!reader.GetFiles(entries, error_message)) {
        return false;
    }
    for (const auto& entry : entries) {
        if (entry.name.rfind("META-INF/signatures", 0) == 0 && entry.name.size() >= 4 &&
            entry.name.compare(entry.name.size() - 4, 4, ".xml") == 0) {
            return true;
        }
    }
    return false;
}

// OID дайджесту -> XMLDSIG-URI для `ds:DigestMethod` у маніфесті ASiC-E.
//
// URI відтворюють написання еталонних контейнерів Дії. Читач приймає також
// сумісні історичні alias-и, але генератор має писати один канонічний варіант.
// Порожній рядок означає, що для алгоритму URI немає, і викликач має
// відмовитись, а не писати маніфест із порожнім `Algorithm`.
std::string DigestOidToXmlDsigUri(const std::string& digest_oid) {
    if (digest_oid == "1.2.804.2.1.1.1.1.2.2.1") {
        return "http://www.w3.org/2001/04/xmlenc#dstu7564-256";
    }
    if (digest_oid == "1.2.804.2.1.1.1.1.2.1") {
        return "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    }
    if (digest_oid == "2.16.840.1.101.3.4.2.1") {
        return "http://www.w3.org/2001/04/xmlenc#sha256";
    }
    if (digest_oid == "2.16.840.1.101.3.4.2.2") {
        return "http://www.w3.org/2001/04/xmldsig-more#sha384";
    }
    if (digest_oid == "2.16.840.1.101.3.4.2.3") {
        return "http://www.w3.org/2001/04/xmlenc#sha512";
    }
    return {};
}

// Зворотне до `DigestOidToXmlDsigUri`: XMLDSIG-URI -> алгоритм імпринту.
std::optional<ImprintDigest> XmlDsigUriToDigest(const std::string& uri) {
    if (uri.find("kupyna256") != std::string::npos || uri.find("kupyna-256") != std::string::npos ||
        uri.find("dstu7564") != std::string::npos) {
        return ImprintDigest::Kupyna256;
    }
    if (uri.find("gost34311") != std::string::npos) {
        return ImprintDigest::Gost34311;
    }
    if (uri.find("sha256") != std::string::npos) {
        return ImprintDigest::Sha256;
    }
    return std::nullopt;
}

// Звіряє дайджест із `DataObjectReference` із фактичним вмістом data-об'єкта.
// Саме ця перевірка зв'язує підпис (він над маніфестом) із даними.
bool AsicManifestDigestMatches(const tamga::asic::AsicDataObjectRef& ref,
                               const std::vector<std::uint8_t>& data,
                               std::string& error_message) {
    const auto alg = XmlDsigUriToDigest(ref.digest_uri);
    if (!alg.has_value()) {
        error_message = "непідтримуваний DigestMethod: " + ref.digest_uri;
        return false;
    }

    std::vector<std::uint8_t> expected;
    if (!tamga::util::Base64Decode(ref.digest_base64, expected) || expected.empty()) {
        error_message = "DigestValue не є коректним base64";
        return false;
    }

    ImprintResult actual;
    std::string imprint_error;
    if (!ComputeImprint(*alg, data, actual, imprint_error)) {
        error_message = imprint_error;
        return false;
    }
    if (actual.hash != expected) {
        error_message = "обчислений геш не збігається зі значенням у маніфесті";
        return false;
    }
    return true;
}

// ME-03: обгортка над централізованим tamga::util::NormalizeAsicEntryUri
// (percent-decode + рівно один провідний "./"-strip, WP-7 ME-05) для legacy
// CAdES ASiC-E шляху. Раніше цей шлях мав власну, значно слабшу реалізацію
// (лише "/"-strip), що давало РІЗНУ поведінку на тому самому контейнері
// залежно від того, підписаний він XAdES чи CAdES: маніфест з
// URI="./file.pdf" або percent-encoded іменем міг резолвитись у XAdES-шляху
// (Session::VerifyFileAsicEXades), але провалювати резолвінг тут. Провідні
// "/" і далі стрипаються ПІСЛЯ percent-decode (легасі-толерантність до
// "URI=/document.pdf" у маніфесті; сирі ZIP entry-імена з провідним "/" уже
// відхиляються на рівні AsicReader::IsUnsafeEntryName, тому це стосується
// лише значень з маніфесту). Best-effort fallback на сирий рядок при
// некоректному percent-encoding — той самий патерн, що вже застосовує
// NormalizeCoverageUri вище.
std::string NormalizeAsicReference(std::string value) {
    std::string decoded;
    std::string error;
    if (!tamga::util::NormalizeAsicEntryUri(value, decoded, error)) {
        decoded = std::move(value);
    }
    std::size_t start = 0;
    while (start < decoded.size() && decoded[start] == '/') {
        ++start;
    }
    return decoded.substr(start);
}

std::vector<const AsicEContent::FileEntry*> FindAsicEReferencedFiles(
    const AsicEContent& content,
    const AsicEContent::SignatureEntry& signature,
    std::string& error_message) {
    if (signature.signature_data.empty()) {
        error_message = "ASiC-E signature entry is empty";
        return {};
    }

    if (signature.manifest_xml.empty()) {
        if (content.files.size() == 1) {
            return {&content.files.front()};
        }
        error_message = "ASiC-E signature has no manifest for multi-file container";
        return {};
    }

    std::string sig_uri;
    std::vector<tamga::asic::AsicDataObjectRef> data_refs;
    if (!ParseAsicManifestXml(signature.manifest_xml, sig_uri, data_refs)) {
        error_message = "ASiC-E signature manifest cannot be parsed";
        return {};
    }

    const std::string normalized_sig_uri = NormalizeAsicReference(sig_uri);
    const std::string normalized_sig_name = NormalizeAsicReference(signature.sig_filename);
    if (!normalized_sig_uri.empty() &&
        normalized_sig_uri != normalized_sig_name &&
        NormalizeAsicReference("META-INF/" + normalized_sig_uri) != normalized_sig_name) {
        error_message = "ASiC-E manifest signature reference does not match signature entry";
        return {};
    }

    if (data_refs.empty()) {
        error_message = "ASiC-E signature manifest must reference at least one signed data object";
        return {};
    }

    // ME-03: fail-closed захист від неоднозначності entry-імен — той самий
    // принцип, що вже застосовує VerifyFileAsicEXades (WP-7 ME-05): якщо два
    // РІЗНИХ сирих імені файлів у контейнері нормалізуються в один і той
    // самий канонічний ключ, контейнер відхиляється цілком, а не мовчки
    // резолвиться в "перше" збіжне ім'я (потенційна підміна файлу).
    std::map<std::string, std::string> normalized_to_raw;
    for (const auto& file : content.files) {
        const std::string normalized = NormalizeAsicReference(file.filename);
        const auto existing = normalized_to_raw.find(normalized);
        if (existing != normalized_to_raw.end() && existing->second != file.filename) {
            error_message = "ASiC-E контейнер містить неоднозначні entry-імена: '" +
                            existing->second + "' і '" + file.filename +
                            "' нормалізуються до однакового URI '" + normalized + "'";
            return {};
        }
        normalized_to_raw[normalized] = file.filename;
    }

    std::vector<const AsicEContent::FileEntry*> referenced_files;
    referenced_files.reserve(data_refs.size());
    std::set<std::string> referenced_names;
    for (const auto& data_ref : data_refs) {
        const std::string data_uri = NormalizeAsicReference(data_ref.uri);
        const auto match = normalized_to_raw.find(data_uri);
        if (match == normalized_to_raw.end()) {
            error_message = "ASiC-E manifest references a missing data object: " + data_uri;
            return {};
        }
        if (!referenced_names.insert(match->second).second) {
            error_message = "ASiC-E manifest references the same data object more than once: " +
                            data_uri;
            return {};
        }
        const auto file = std::find_if(
            content.files.begin(), content.files.end(),
            [&match](const AsicEContent::FileEntry& candidate) {
                return candidate.filename == match->second;
            });
        if (file == content.files.end()) {
            error_message = "ASiC-E manifest references a missing data object: " + data_uri;
            return {};
        }
        referenced_files.push_back(&*file);
    }
    return referenced_files;
}

[[maybe_unused]] std::string BoolText(bool value) {
    return value ? "true" : "false";
}

// Хвиля 8, п.3: ці три помічники стоять ПЕРЕД гейтом XML навмисно.
// Контейнерна мітка ASiC не потребує XMLDSIG, тож канонічна перевірка мітки
// має бути доступна і в конфігурації без XML-рушія. Перша спроба лишила їх
// усередині гейта — і збірки base/vendor-off одразу впали, а ctest на
// старих бінарниках відзвітував «100% passed». Третій такий випадок за
// сесію: код виходу збірки перевіряється ОКРЕМО від ctest саме тому.

[[maybe_unused]] validation::ValidationContext BuildXadesValidationContext(const Settings& settings) {
    validation::ValidationContext context;
    if (settings.trust_mode == "strict") {
        context.profile = validation::ValidationProfile::Strict;
    } else if (settings.trust_mode == "ukraine-legal") {
        context.profile = validation::ValidationProfile::UkraineLegal;
    } else if (settings.trust_mode == "offline") {
        context.profile = validation::ValidationProfile::Offline;
    } else if (settings.trust_mode == "forensic") {
        context.profile = validation::ValidationProfile::Forensic;
    } else {
        context.profile = validation::ValidationProfile::Compatibility;
    }

    if (settings.validation_level == "basic") {
        context.level = validation::ValidationLevel::Basic;
    } else if (settings.validation_level == "extended") {
        context.level = validation::ValidationLevel::Extended;
    } else if (settings.validation_level == "forensic") {
        context.level = validation::ValidationLevel::Forensic;
    } else {
        context.level = validation::ValidationLevel::Standard;
    }

    context.offline = settings.offline_mode;
    context.work_dir = settings.work_dir;
    return context;
}

// ADR-033: `AppendContainerTimestampMessage` і `AppendXadesTimestampMessage`
// переїхали у `core/session/VerifyReportCommit.{h,cpp}` і там зведені на одне
// тіло з префіксом-параметром — різниця між ними завжди була рівно в префіксі.

// Хвиля 8, п.3: ЄДИНИЙ канонічний шлях перевірки мітки часу.
//
// Донедавна їх було два. `validation::TimestampEngine` робить повну роботу —
// TL direct-match, перевірку строку дії сертифіката TSA НА МОМЕНТ мітки (С-19)
// і побудову з валідацією ланцюга. А контейнерні мітки ASiC (`timestamp.tst`)
// йшли повз нього, прямо в `policy::ValidateTimestampToken`, який уміє рівно
// одне: звірити imprint і підпис TSA.
//
// Обмеження чесно позначалося як `timestamp-partial`, тож fail-open тут не
// було. Але наслідок усе одно поганий: мітка від ПРОТЕРМІНОВАНОГО або
// недовіреного TSA виглядала в звіті так само, як від бездоганного, і жодна
// майбутня правка на кшталт С-19 до цього шляху не дійшла б.
//
// Тепер шлях один. Повертає false, коли канонічний вердикт недосяжний (немає
// cryptonite чи trust-матеріалу) — тоді викликач лишає крипто-результат
// частковим, як і раніше.
bool TryCanonicalTimestampVerdict(const Settings& settings,
                                  const std::vector<std::uint8_t>& token_der,
                                  const std::vector<std::uint8_t>& imprint_source,
                                  const std::string& validation_time,
                                  bool& out_valid,
                                  std::string& out_reason,
                                  const std::vector<std::vector<std::uint8_t>>& certificates = {},
                                  const std::vector<std::vector<std::uint8_t>>& ocsp = {},
                                  const std::vector<std::vector<std::uint8_t>>& crls = {},
                                  TimestampEntry* detail = nullptr) {
    out_valid = false;
    out_reason.clear();
#if TAMGA_CRYPTONITE_ENABLED
    if (token_der.empty() || imprint_source.empty()) {
        return false;
    }

    std::vector<std::vector<std::uint8_t>> current_trust_anchors;
    std::vector<std::vector<std::uint8_t>> historical_trust_anchors;
    std::vector<std::vector<std::uint8_t>> intermediate_store_certs;
    std::vector<std::vector<std::uint8_t>> tsa_trust_anchors;
    std::vector<std::vector<std::uint8_t>> historical_tsa_trust_anchors;
    CollectTrustAnchors(settings.work_dir, current_trust_anchors);
    CollectHistoricalTrustAnchors(settings.work_dir, historical_trust_anchors);
    CollectIntermediateCertificates(settings.work_dir, intermediate_store_certs);
    CollectTsaAnchors(settings.work_dir, tsa_trust_anchors);
    CollectHistoricalTsaAnchors(settings.work_dir, historical_tsa_trust_anchors);

    const validation::ValidationContext context = BuildXadesValidationContext(settings);
    const validation::ResolvedValidationPolicy resolved = validation::PolicyResolver{}.Resolve(context);

    validation::TimestampEngineInput input;
    input.explicit_timestamp_token_der = token_der;
    input.explicit_timestamp_imprint_source = imprint_source;
    input.validation_time = validation_time;
    input.policy = resolved.policy;
    input.plan = resolved.plan;
    input.current_trust_anchors_der = std::move(current_trust_anchors);
    input.tsa_trust_anchors_der = std::move(tsa_trust_anchors);
    input.historical_trust_anchors_der = std::move(historical_trust_anchors);
    input.historical_tsa_trust_anchors_der = std::move(historical_tsa_trust_anchors);
    input.intermediate_store_certificates_der = std::move(intermediate_store_certs);
    input.additional_tsa_candidate_certificates_der = certificates;
    input.embedded_ocsp_responses_der = ocsp;
    input.embedded_crls_der = crls;
    input.profile = context.profile;
    input.level = context.level;

    const validation::TimestampEngineResult timestamp_result = validation::TimestampEngine{}.Validate(input);
    if (detail != nullptr) {
        *detail = ProjectTimestampResult(timestamp_result);
    }
    out_valid = timestamp_result.valid;
    if (!timestamp_result.valid) {
        // `because` — це послідовність кроків, а не одна причина. Перший
        // запис може бути інформаційною нотаткою (наприклад «TL direct-match»),
        // тоді як вирішальна відмова стоїть ОСТАННЬОЮ. Беручи `front()`, звіт
        // повідомляв про успішний крок замість причини провалу — і саме на
        // цьому спіткнувся тест: у повідомленні був direct-match, а справжня
        // причина (немає EKU для timestamping) не потрапляла нікуди.
        //
        // Та сама вада була й у XAdES-шляху; тепер вона виправлена в обох, бо
        // шлях один.
        out_reason = timestamp_result.because.empty()
            ? "TSA signature, chain, EKU or revocation validation failed"
            : timestamp_result.because.back();
    }
    return true;
#else
    (void)settings;
    (void)token_der;
    (void)imprint_source;
    (void)validation_time;
    (void)certificates;
    (void)ocsp;
    (void)crls;
    (void)detail;
    out_reason = "full TSA validation requires TAMGA_ENABLE_VENDOR_CRYPTONITE=ON";
    return false;
#endif
}

#if defined(TAMGA_XML_SIGNATURES_ENABLED)
void ApplyXadesTimestampPolicyValidation(const Settings& settings,
                                         const tamga::xades::XadesVerificationResult& result,
                                         VerifyReport& report) {
    if (!result.signature_timestamp_present) {
        report.ltv_valid = false;
        return;
    }

    report.timestamp_checked = true;
    report.tsp_checked = result.tsp_checked;
    // В-03: стартовий стан — лише криптографічна перевірка токена. Повний
    // вердикт може дати ТІЛЬКИ TimestampEngine нижче; якщо він не запуститься
    // (немає trust-матеріалу — ранній return), статус мусить лишитися
    // частковим. Саме тут раніше crypto-only результат подавався як
    // "timestamp-valid".
    ApplyFormatTimestampVerdict(report, result.signature_timestamp_valid,
                                /*canonical_full=*/false);
    // ltv_valid зберігає СТРУКТУРНУ семантику й спирається на крипто-рівневий
    // факт, а не на щойно пониженим report.timestamp_valid — інакше зміна
    // статусу мітки мовчки змінила б і значення ltvValid.
    report.ltv_valid = result.signature_valid && result.ltv_data_present &&
                       result.signature_timestamp_valid;

    if (result.signature_timestamp_token_der.empty() ||
        result.signature_timestamp_canonicalized_data.empty()) {
        report.timestamp_valid = false;
        report.timestamp_status = "timestamp-invalid";
        report.ltv_valid = false;
        AppendXadesTimestampMessage(report, "missing token or canonicalized SignatureValue evidence");
        return;
    }

    bool canonical_valid = false;
    std::string reason;
    TimestampEntry detail;
    if (!TryCanonicalTimestampVerdict(settings, result.signature_timestamp_token_der,
                                      result.signature_timestamp_canonicalized_data,
                                      result.signing_time, canonical_valid, reason,
                                      result.certificate_values_der, result.revocation_values_ocsp_der,
                                      result.revocation_values_crl_der, &detail)) {
        if (!reason.empty()) {
            AppendXadesTimestampMessage(report, reason);
        }
        return;
    }

    report.tsp_checked = true;
    report.timestamp_checked = true;
    report.timestamp_details.push_back(std::move(detail));
    ApplyTimestampDetailsVerdict(report);
    report.ltv_valid = result.signature_valid && result.ltv_data_present && canonical_valid;
    if (!canonical_valid) {
        AppendXadesTimestampMessage(report, reason);
        // Хвиля 8, п.3: пониження довіри живе в одному місці й має власний тест.
        if (report.timestamp_status == "timestamp-invalid") ApplyTimestampFailureToTrust(report);
    }
}

void ApplyPerSignerXadesTimestampValidation(const Settings& settings,
                                           const tamga::xades::XadesVerificationResult& result,
                                           SignatureEntry& entry) {
    if (!result.signature_timestamp_present) return;
    VerifyReport timestamp_report;
    ApplyXadesTimestampPolicyValidation(settings, result, timestamp_report);
    entry.timestamp_checked = timestamp_report.timestamp_checked;
    entry.timestamp_valid = timestamp_report.timestamp_valid;
    entry.timestamp_status = timestamp_report.timestamp_status;
    entry.timestamp_details = std::move(timestamp_report.timestamp_details);
    // Навіть відсутній/пошкоджений EncapsulatedTimeStamp має окремий результат.
    if (entry.timestamp_details.empty()) {
        TimestampEntry detail;
        detail.status = entry.timestamp_status;
        detail.reason_code = "TIMESTAMP_EVIDENCE_MISSING";
        entry.timestamp_details.push_back(std::move(detail));
    }
    for (auto& detail : entry.timestamp_details) detail.signature_index = entry.index;
}
#endif

void AggregatePerSignerTimestamps(VerifyReport& report) {
    report.timestamp_details.clear();
    for (const auto& entry : report.signatures) {
        report.timestamp_details.insert(report.timestamp_details.end(),
                                        entry.timestamp_details.begin(), entry.timestamp_details.end());
    }
    ApplyTimestampDetailsVerdict(report);
    if (report.timestamp_status == "timestamp-invalid") ApplyTimestampFailureToTrust(report);
}

// WP-7 (ME-05): обгортка над централізованим tamga::util::NormalizeAsicEntryUri
// (percent-decode + "./"-strip, спільна з XmlReferenceResolver::ResolveReference
// і Session::VerifyFileAsicEXades) для best-effort coverage-порівняння. Якщо
// нормалізація провалюється (некоректний percent-encoding), використовуємо
// оригінальний рядок: coverage-перевірка лише діагностична, а РЕАЛЬНЕ
// ds:Reference з тим самим некоректним URI однаково провалить резолвінг
// нижче, давши явну помилку саме там.
inline std::string NormalizeCoverageUri(const std::string& uri) {
    std::string out;
    std::string error;
    if (!tamga::util::NormalizeAsicEntryUri(uri, out, error)) {
        return uri;
    }
    return out;
}

template <typename XadesResult>
std::string BuildXadesXmlDiagnostics(const XadesResult& result) {
    const auto& xml = result.xml_signature;
    std::string out = "XMLDSig diagnostics: digestValid=" + BoolText(xml.digest_valid) +
                      "; signatureValid=" + BoolText(xml.signature_valid) +
                      "; signatureValue=" + (xml.signature_value_valid ? "ok" : "failed");
    if (!xml.signature_value_error.empty()) {
        out += " error='" + xml.signature_value_error + "'";
    }
    out += "; xadesProfile=" + result.format_profile +
           "; signatureTimeStampPresent=" + BoolText(result.signature_timestamp_present) +
           "; timestampChecked=" + BoolText(result.signature_timestamp_checked) +
           "; timestampValid=" + BoolText(result.signature_timestamp_valid) +
           "; tspChecked=" + BoolText(result.tsp_checked) +
           "; certificateValues=" + std::to_string(result.certificate_values_count) +
           "; revocationValues=" + std::to_string(result.revocation_values_count) +
           "; ltvValid=" + BoolText(result.ltv_valid);
    out += "; signedInfoLen=" + std::to_string(xml.signed_info_canonicalized_length) +
           "; signedInfoHashHex=" + xml.signed_info_hash_hex +
           "; signedInfoHashBase64=" + xml.signed_info_hash_base64 +
           "; signedPropertiesLen=" + std::to_string(xml.signed_properties_canonicalized_length) +
           "; signedPropertiesHashHex=" + xml.signed_properties_hash_hex +
           "; signedPropertiesHashBase64=" + xml.signed_properties_hash_base64 +
           "; references=[";

    for (std::size_t i = 0; i < xml.reference_details.size(); ++i) {
        const auto& ref = xml.reference_details[i];
        if (i > 0) {
            out += "; ";
        }
        out += "uri='" + ref.uri + "'";
        out += " type='" + ref.type + "'";
        out += " digestMethod='" + ref.digest_method + "'";
        out += " status=" + ref.status;
        out += " expectedBase64='" + ref.expected_base64 + "'";
        out += " expectedHex='" + ref.expected_hex + "'";
        out += " computedBase64='" + ref.computed_base64 + "'";
        out += " computedHex='" + ref.computed_hex + "'";
        if (!ref.error.empty()) {
            out += " error='" + ref.error + "'";
        }
    }
    out += "]";
    return out;
}

// WP-12: конвертує XAdES DataObjectFormat (SignedDataObjectProperties,
// ETSI EN 319 132-1 §5.2.2) у Session-рівневий DataObjectFormatEntry.
// Шаблонна функція (як і BuildXadesXmlDiagnostics вище) — не потребує
// #include xades/XadesTypes.h тут; компілюється лише коли реально
// інстанціюється з XML-гейтованого коду (SessionXmlOps.ipp/тут нижче).
template <typename XadesDataObjectFormat>
std::vector<DataObjectFormatEntry> ToSessionDataObjectFormats(
    const std::vector<XadesDataObjectFormat>& formats) {
    // Н-07: копія структури в Session.h навмисна (Session.h не має залежати
    // від xades/XadesTypes.h — не всі збірки мають TAMGA_ENABLE_XML_SIGNATURES),
    // але від того вона не перестає бути копією. Якщо в XAdES-типі зʼявиться
    // нове поле, воно мовчки не потрапить у звіт: цикл нижче копіює рівно три.
    //
    // Розмір — не доказ ідентичності полів, але єдина перевірка, доступна
    // шаблону без залежності від конкретного типу. Її достатньо, щоб додане
    // поле зламало ЗБІРКУ, а не тихо загубилося у звіті.
    static_assert(sizeof(XadesDataObjectFormat) == sizeof(DataObjectFormatEntry),
                  "DataObjectFormatEntry розійшовся з xades::DataObjectFormat: "
                  "оновіть копію в Session.h і цей конвертер разом");

    std::vector<DataObjectFormatEntry> out;
    out.reserve(formats.size());
    for (const auto& dof : formats) {
        out.push_back({dof.object_reference, dof.mime_type, dof.description});
    }
    return out;
}

} // namespace


bool Session::SignFileAsicS(const std::string& input_path, const std::string& output_path) {
    return SignFileAsicXades(input_path, output_path, false);
}

// CAdES-розкладка ASiC-S (META-INF/signature.p7s). Доступна під іменем
// формату `asic-s-cades`. Типовий `asic-s` лишається XAdES-шляхом
// (`SignFileAsicXades`), а внутрішню розкладку користувач обирає явно.
bool Session::SignFileAsicSCades(const std::string& input_path, const std::string& output_path) {
    // Мітку часу і автономний режим тут НЕ вирішують: обидва питання ухвалює
    // `SignData` нижче (BestEffort). Захоплені сюди `tsp_settings` і
    // `offline_mode` були мертві — GCC із `-Werror=unused-but-set-variable`
    // відхиляв складання через скалярну з них.
    FileStoreSettings settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        if (!is_private_key_loaded_) {
            SetError(ErrorCode::KeyNotLoaded, ToString(ErrorCode::KeyNotLoaded));
            return false;
        }
        settings = file_store_settings_;
    }

    std::vector<std::uint8_t> file_data;
    std::string error_message;
    std::string resolved_input_path = ResolveFilePath(input_path, settings);
    if (!ReadBinaryFile(resolved_input_path, "input file for ASiC-S", file_data, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }
    if (file_data.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Input file is empty");
        return false;
    }

    std::vector<std::uint8_t> signature;
    if (!SignData(file_data, signature)) {
        return false;
    }

    // `SignData` у режимі BestEffort повертає true і тоді, коли TSA не
    // відповів: підпис валідний, але рівня T не має, а причина лежить у стані
    // помилки. Знімаємо її тут, бо безумовний `ClearError()` наприкінці
    // затирав саме цей запис — виклик звітував успіх, і 1С не мала способу
    // дізнатися, що мітки часу немає.
    LastError signing_error;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        signing_error = last_error_;
    }

    // Мітка часу вже всередині `signature`: `SignData` у режимі BestEffort
    // отримує токен і вкладає його в CMS як `id-aa-signatureTimeStampToken`,
    // тобто повертає готовий CAdES-T.
    //
    // До 2026-09-03 тут стояв ДРУГИЙ запит до TSA, а його результат лягав
    // окремим entry `META-INF/timestamp.tst`. Наслідків було два, і обидва
    // погані: зайвий круг до TSA на кожен підпис і контейнер, який порушує
    // ETSI EN 319 162-1 §4.3.3.2 — у META-INF ASiC-S має бути АБО
    // `signature.p7s`, АБО `timestamp.tst`, але не обидва. Сервіс перевірки
    // Дії відхиляв такий файл помилкою розбору («пошкоджені дані чи невірний
    // формат», 33), тоді як той самий підпис без `timestamp.tst` приймався.
    //
    // Standalone-timestamp — окремий профіль ASiC (контейнер БЕЗ підпису, де
    // токен штампує сам документ). Він тут не реалізований; змішувати його з
    // CAdES-T не можна.
    const std::vector<std::uint8_t> tsp_token;

    AsicSContent content;
    std::filesystem::path p(std::filesystem::u8path(resolved_input_path));
    content.filename = p.filename().u8string();
    content.file_data = file_data;
    content.signature_data = signature;
    content.timestamp_data = tsp_token;

    std::vector<std::uint8_t> container;
    if (!AsicSContainer::Pack(content, container, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError, "Failed to pack ASiC-S: " + error_message);
        return false;
    }

    std::string resolved_output_path = ResolveFilePath(output_path, settings);
    std::filesystem::path fs_out_path = std::filesystem::u8path(resolved_output_path);
    if (!settings.allow_overwrite && std::filesystem::exists(fs_out_path)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Output file already exists");
        return false;
    }

    // П-12: запис через спільний атомарний writer. Прямий `ofstream ... trunc`
    // обнуляв цільовий файл до появи першого байта нового контейнера, тож
    // перервана операція лишала на місці підписаного документа усічений файл.
    const auto write_result = util::WriteBytesAtomic(fs_out_path, container.data(), container.size());
    if (!write_result) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (write_result.status == util::AtomicWriteStatus::TargetUnusable) {
            SetError(ErrorCode::InvalidArgument, "Unable to open output file: " + resolved_output_path);
        } else {
            SetError(ErrorCode::InternalError,
                     "Failed writing ASiC-S output file: " + write_result.message);
        }
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (signing_error.code == ErrorCode::OnlineServiceUnavailable) {
        // Контейнер створено, але без мітки часу. Повідомляємо рівно це, а не
        // мовчазний успіх.
        SetError(signing_error.code, signing_error.message);
    } else {
        ClearError();
    }
    return true;
}

bool Session::VerifyFileAsicS(const std::string& asics_path, bool& is_valid) {
    FileStoreSettings settings;
    // Хвиля 8, п.3: знімок Settings під тим самим коротким lock — потрібен
    // канонічній перевірці мітки часу нижче (work_dir, trust_mode,
    // validation_level). Той самий прийом, що й у VerifyFileAsicEXades.
    Settings local_settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            SetVerifyReport("VerifyFileAsicS", false, false, ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        settings = file_store_settings_;
        local_settings = settings_;
    }

    is_valid = false;
    std::vector<std::uint8_t> container;
    std::string error_message;
    if (!ReadBinaryFile(ResolveFilePath(asics_path, settings), "ASiC-S file", container, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyFileAsicS", false, false, ErrorCode::InvalidArgument, error_message);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }

    // Розкладку визначаємо за вмістом: XAdES-контейнер (META-INF/signatures*.xml)
    // читає спільний XAdES-шлях, CAdES лишається нижче. Саме таку розкладку
    // тепер віддають `asic-s`/`asic-e`, тож без цієї гілки компонента не
    // перевіряла б власний вихід.
    if (ContainerHasXadesSignature(container)) {
        return VerifyFileAsicEXades(asics_path, is_valid);
    }

    AsicSContent content;
    if (!AsicSContainer::Unpack(container, content, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyFileAsicS", false, false, ErrorCode::InvalidArgument, "ASiC-S unpack failed: " + error_message);
        SetError(ErrorCode::InvalidArgument, "ASiC-S unpack failed: " + error_message);
        return false;
    }

    const bool result = VerifyData(content.file_data, content.signature_data, is_valid);
    OverrideVerifyReportOperation("VerifyFileAsicS");
    {
        // Р-1: контейнерний шлях зобовʼязаний ЯВНО оголосити покриття, а не
        // мовчати. Мовчання лишало дефолт `not-applicable` +
        // `container_coverage_complete=true`, тобто «покрито все» — і гейт
        // К-01 у SummaryCheck перетворювався на no-op саме для контейнера.
        //
        // Після перевірки в `AsicSContainer::Unpack` (рівно один data-object)
        // покриття тут повне за побудовою: підпис перевірено проти єдиного
        // обʼєкта контейнера. Контейнер із зайвим документом сюди вже не
        // доходить — Unpack відхиляє його вище.
        std::lock_guard<std::mutex> lock(mutex_);
        if (VerifyReportStillOwnedByThisThreadLocked()) {
            last_verify_report_.container_type = "ASiC-S";
            last_verify_report_.container_coverage_complete = true;
            last_verify_report_.coverage_status = "complete";
            RefreshUserReportForCurrentOperation();
        }
    }

    if (result && !content.timestamp_data.empty()) {
        // S-001: раніше timestamp_valid = is_valid (валідність CMS-підпису
        // видавалася за валідність RFC3161-токена контейнера, без жодної його
        // криптоперевірки). Тепер токен реально перевіряється:
        // ValidateTimestampToken звіряє messageImprint проти CMS-блоба підпису
        // (той самий блоб, який штампувався у SignFileAsicS через
        // ResolveTspImprint(..., signature, signature, ...)) і перевіряє підпис
        // TSA. Пошкоджений/чужий/сфабрикований токен тепер дає
        // timestamp_valid=false, а не хибнопозитив.
        // Хвиля 8, п.3: контейнерна мітка йде тим самим канонічним шляхом, що й
        // мітка XAdES. До цього вона перевірялася лише криптографічно
        // (`policy::ValidateTimestampToken`), тож ані строк дії сертифіката TSA
        // (С-19), ані його довіра не оцінювалися взагалі.
        bool canonical_valid = false;
        std::string canonical_reason;
        TimestampEntry container_detail;
        const bool canonical_available = TryCanonicalTimestampVerdict(
            local_settings, content.timestamp_data, content.signature_data,
            /*validation_time=*/std::string{}, canonical_valid, canonical_reason,
            {}, {}, {}, &container_detail);
        container_detail.kind = "container";
        const auto ts = tamga::core::policy::ValidateTimestampToken(content.timestamp_data,
                                                                    content.signature_data);
        std::lock_guard<std::mutex> lock(mutex_);
        // Н-04: доуточнюємо ЛИШЕ власний звіт. Між комітом VerifyData вище і
        // цим моментом mutex_ відпускався (перевірка токена — робота без
        // блокування), тож паралельний Verify* на тій самій сесії міг встигнути
        // закомітити свій результат. Без цієї перевірки статус мітки часу
        // потрапляв би в чужий звіт.
        if (!VerifyReportStillOwnedByThisThreadLocked()) {
            return true;
        }
        last_verify_report_.timestamp_checked = true;
        last_verify_report_.tsp_checked = true;
        last_verify_report_.timestamp_details.push_back(std::move(container_detail));
        // В-03: крипто-результат — база, канонічний вердикт лише ПІДВИЩУЄ.
        //
        // Перша версія цієї правки підставляла канонічний результат замість
        // крипто-результату — і тести показали, чому це хибно: контейнер із
        // криптографічно бездоганною міткою, але без trust-матеріалу для TSA,
        // ставав "timestamp-invalid". «Довіру не встановлено» — це не «мітка
        // недійсна»; саме цю різницю й фіксує В-03.
        ApplyFormatTimestampVerdict(last_verify_report_, ts.valid,
                                    /*canonical_full=*/canonical_available && canonical_valid);
        // Причина, чому повного вердикту немає, тепер видима. Доти контейнерна
        // мітка мовчала: користувач бачив "partial" і не міг відрізнити «TSA
        // недовірений» від «сертифікат TSA не має EKU для timestamping» чи
        // «trust-store порожній».
        if (!canonical_reason.empty()) {
            AppendContainerTimestampMessage(last_verify_report_, canonical_reason);
        }
        RefreshUserReportForCurrentOperation();
    }

    return result;
}

bool Session::SignFileAsicE(const std::string& input_path, const std::string& output_path) {
    return SignFileAsicXades(input_path, output_path, true);
}

// CAdES-розкладка ASiC-E (нумерована пара ASiCManifest/signature). Доступна під іменем
// формату `asic-e-cades`. Типовий `asic-e` лишається XAdES-шляхом
// (`SignFileAsicXades`), а внутрішню розкладку користувач обирає явно.
bool Session::SignFileAsicECades(const std::string& input_path, const std::string& output_path) {
    // Мітку часу і автономний режим тут НЕ вирішують: обидва питання ухвалює
    // `SignData` нижче (BestEffort). Захоплені сюди `tsp_settings` і
    // `offline_mode` були мертві — GCC із `-Werror=unused-but-set-variable`
    // відхиляв складання через скалярну з них.
    FileStoreSettings settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        if (!is_private_key_loaded_) {
            SetError(ErrorCode::KeyNotLoaded, ToString(ErrorCode::KeyNotLoaded));
            return false;
        }
        settings = file_store_settings_;
    }

    std::vector<std::uint8_t> file_data;
    std::string error_message;
    std::string resolved_input_path = ResolveFilePath(input_path, settings);
    if (!ReadBinaryFile(resolved_input_path, "input file for ASiC-E", file_data, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }
    if (file_data.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Input file is empty");
        return false;
    }

    // ASiC-E CAdES: підписується МАНІФЕСТ, а не сам документ. Маніфест несе
    // дайджести даних, тож ланцюг «підпис -> маніфест -> дані» замикається саме
    // так (ETSI EN 319 162-1). Те саме робить довідкова реалізація ETSI DSS:
    // `ASiCWithCAdESService` підписує `dataToSignHelper.getToBeSigned()`, яким
    // для ASiC-E є XML маніфесту.
    //
    // До 2026-09-03 Tamga підписувала документ напряму, а маніфест лишався
    // непідписаною пустишкою без дайджестів. Власний верифікатор це приймав,
    // сторонні — ні.
    const std::string data_entry_name =
        std::filesystem::u8path(resolved_input_path).filename().u8string();
    // Дія нумерує зв'язану пару ASiC-E однаковим тризначним
    // суфіксом. Ненумероване `signature.p7s` лишається профілем ASiC-S.
    const std::string sig_entry_name = "META-INF/signature001.p7s";

    // Еталони Дії для цього самого payload вказують у маніфесті
    // Купину-256 (`xmlenc#dstu7564-256`). CMS, створений `SignData`, також
    // вже оголошує OID Купини, тому явний вибір прибирає змішаний
    // профіль «CMS=Купина, DataObjectReference=ГОСТ».
    ImprintResult data_imprint;
    std::string imprint_error;
    if (!ComputeImprint(ImprintDigest::Kupyna256, file_data, data_imprint, imprint_error)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError, "ASiC-E manifest digest failed: " + imprint_error);
        return false;
    }

    tamga::asic::AsicDataObjectRef data_ref;
    data_ref.uri = data_entry_name;
    data_ref.mime_type = tamga::asic::GetMimeTypeFromFilename(data_entry_name);
    data_ref.digest_uri = DigestOidToXmlDsigUri(data_imprint.digest_oid);
    data_ref.digest_base64 = util::Base64Encode(data_imprint.hash);
    if (data_ref.digest_uri.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError,
                 "ASiC-E manifest digest algorithm has no XMLDSIG URI: " + data_imprint.digest_oid);
        return false;
    }

    const std::string manifest_xml =
        tamga::asic::GenerateAsicManifestXml(sig_entry_name, {data_ref});
    const std::vector<std::uint8_t> manifest_bytes(manifest_xml.begin(), manifest_xml.end());

    std::vector<std::uint8_t> signature;
    if (!SignData(manifest_bytes, signature)) {
        return false;
    }

    // `SignData` у режимі BestEffort повертає true і тоді, коли TSA не
    // відповів: підпис валідний, але рівня T не має, а причина лежить у стані
    // помилки. Знімаємо її тут, бо безумовний `ClearError()` наприкінці
    // затирав саме цей запис — виклик звітував успіх, і 1С не мала способу
    // дізнатися, що мітки часу немає.
    LastError signing_error;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        signing_error = last_error_;
    }

    // Мітка часу вже всередині `signature`: `SignData` у режимі BestEffort
    // отримує токен і вкладає його в CMS як `id-aa-signatureTimeStampToken`,
    // тобто повертає готовий CAdES-T.
    //
    // До 2026-09-03 тут стояв ДРУГИЙ запит до TSA, а його результат лягав
    // окремим entry `META-INF/timestamp.tst`. Наслідків було два, і обидва
    // погані: зайвий круг до TSA на кожен підпис і контейнер, який порушує
    // ETSI EN 319 162-1 §4.3.3.2 — у META-INF ASiC-S має бути АБО
    // `signature.p7s`, АБО `timestamp.tst`, але не обидва. Сервіс перевірки
    // Дії відхиляв такий файл помилкою розбору («пошкоджені дані чи невірний
    // формат», 33), тоді як той самий підпис без `timestamp.tst` приймався.
    //
    // Standalone-timestamp — окремий профіль ASiC (контейнер БЕЗ підпису, де
    // токен штампує сам документ). Він тут не реалізований; змішувати його з
    // CAdES-T не можна.
    const std::vector<std::uint8_t> tsp_token;

    AsicEContent content;
    std::filesystem::path p(std::filesystem::u8path(resolved_input_path));
    content.files.push_back({p.filename().u8string(), file_data});
    
    AsicEContent::SignatureEntry se;
    se.sig_filename = sig_entry_name;
    se.signature_data = signature;
    se.manifest_filename = "META-INF/ASiCManifest001.xml";
    // Той САМИЙ маніфест, який щойно підписано. Перегенерувати його тут
    // означало б покласти в контейнер документ, якого підпис не покриває.
    se.manifest_xml = manifest_xml;
    content.signatures.push_back(se);
    content.timestamp_data = tsp_token;

    std::vector<std::uint8_t> container;
    if (!AsicEContainer::Pack(content, container, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError, "Failed to pack ASiC-E: " + error_message);
        return false;
    }

    std::string resolved_output_path = ResolveFilePath(output_path, settings);
    std::filesystem::path fs_out_path = std::filesystem::u8path(resolved_output_path);
    if (!settings.allow_overwrite && std::filesystem::exists(fs_out_path)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Output file already exists");
        return false;
    }

    // П-12: запис через спільний атомарний writer. Прямий `ofstream ... trunc`
    // обнуляв цільовий файл до появи першого байта нового контейнера, тож
    // перервана операція лишала на місці підписаного документа усічений файл.
    const auto write_result = util::WriteBytesAtomic(fs_out_path, container.data(), container.size());
    if (!write_result) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (write_result.status == util::AtomicWriteStatus::TargetUnusable) {
            SetError(ErrorCode::InvalidArgument, "Unable to open output file: " + resolved_output_path);
        } else {
            SetError(ErrorCode::InternalError,
                     "Failed writing ASiC-E output file: " + write_result.message);
        }
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (signing_error.code == ErrorCode::OnlineServiceUnavailable) {
        // Контейнер створено, але без мітки часу. Повідомляємо рівно це, а не
        // мовчазний успіх.
        SetError(signing_error.code, signing_error.message);
    } else {
        ClearError();
    }
    return true;
}

bool Session::VerifyFileAsicE(const std::string& asice_path, bool& is_valid) {
    FileStoreSettings settings;
    // Хвиля 8, п.3: знімок Settings під тим самим коротким lock — потрібен
    // канонічній перевірці мітки часу нижче (work_dir, trust_mode,
    // validation_level). Той самий прийом, що й у VerifyFileAsicEXades.
    Settings local_settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            SetVerifyReport("VerifyFileAsicE", false, false, ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        settings = file_store_settings_;
        local_settings = settings_;
    }

    is_valid = false;
    std::vector<std::uint8_t> container;
    std::string error_message;
    if (!ReadBinaryFile(ResolveFilePath(asice_path, settings), "ASiC-E file", container, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyFileAsicE", false, false, ErrorCode::InvalidArgument, error_message);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }

    // Розкладку визначаємо за вмістом: XAdES-контейнер (META-INF/signatures*.xml)
    // читає спільний XAdES-шлях, CAdES лишається нижче. Саме таку розкладку
    // тепер віддають `asic-s`/`asic-e`, тож без цієї гілки компонента не
    // перевіряла б власний вихід.
    if (ContainerHasXadesSignature(container)) {
        return VerifyFileAsicEXades(asice_path, is_valid);
    }

    AsicEContent content;
    if (!AsicEContainer::Unpack(container, content, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyFileAsicE", false, false, ErrorCode::InvalidArgument, "ASiC-E unpack failed: " + error_message);
        SetError(ErrorCode::InvalidArgument, "ASiC-E unpack failed: " + error_message);
        return false;
    }

    if (content.files.empty() || content.signatures.empty()) {
        is_valid = false;
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyFileAsicE",
                        true,
                        false,
                        ErrorCode::None,
                        content.files.empty()
                            ? "ASiC-E container has no files to verify"
                            : "ASiC-E container has no signatures to verify");
        ClearError();
        return true;
    }

    // С-11: раніше цикл робив `break` на першому невалідному підписі, і
    // `signatures[]` не заповнювався зовсім. Співпідписант, що йшов після
    // зламаного, не був ані перевірений, ані згаданий у звіті — тобто
    // мультипідписний контейнер давав менше інформації, ніж однопідписний.
    // XAdES-шлях (WP-2/HI-01) перевіряє всі підписи; приводимо CAdES-шлях до
    // тієї самої поведінки.
    bool all_valid = true;
    std::string structural_error;
    std::vector<SignatureEntry> signature_entries;
    signature_entries.reserve(content.signatures.size());
    int signature_index = 0;
    int valid_count = 0;
    // П-03: множина фактично покритих data-об'єктів. Доти цей шлях перевіряв
    // кожен підпис проти РІВНО ОДНОГО об'єкта з його маніфесту й ніколи не
    // питав, чи лишилися в контейнері файли, не покриті жодним підписом.
    // `container_coverage_complete` тут не присвоювалося зовсім, тож лишалося
    // дефолтним `true` — і гейт К-01 у `SummaryCheck` на цьому шляху був
    // no-op. Контейнер із валідно підписаним `document.pdf` і додатковим
    // `payload.bin` приймався як валідний.
    std::set<std::string> covered_files;

    for (const auto& sig : content.signatures) {
        ++signature_index;
        SignatureEntry entry;
        entry.index = signature_index;

        std::string reference_error;
        const auto referenced_files = FindAsicEReferencedFiles(content, sig, reference_error);
        if (referenced_files.empty()) {
            // Структурна помилка стосується контейнера в цілому, тож
            // запам'ятовуємо ПЕРШУ й продовжуємо: решта підписів усе одно має
            // бути перевірена та показана.
            if (structural_error.empty()) {
                structural_error = std::move(reference_error);
            }
            all_valid = false;
            entry.signature_valid = false;
            signature_entries.push_back(std::move(entry));
            continue;
        }

        // Що саме покриває підпис, вирішує сам маніфест:
        //
        //   * канонічний ASiC-E (ETSI EN 319 162-1) — підпис над МАНІФЕСТОМ, а
        //     дані прив'язані до нього дайджестом у `DataObjectReference`;
        //   * контейнери, які Tamga писала до 2026-09-03, — підпис прямо над
        //     даними, а маніфест без дайджестів. Їх треба лишити читабельними,
        //     інакше раніше підписані документи стали б «невалідними» через
        //     зміну на нашому боці.
        //
        // Розрізняє саме наявність дайджесту, а не версія чи здогад.
        std::string manifest_sig_uri;
        std::vector<tamga::asic::AsicDataObjectRef> manifest_refs;
        const bool manifest_parsed =
            !sig.manifest_xml.empty() &&
            tamga::asic::ParseAsicManifestXml(sig.manifest_xml, manifest_sig_uri, manifest_refs);
        bool manifest_has_any_digest = false;
        bool manifest_has_all_digests = manifest_parsed && !manifest_refs.empty();
        for (const auto& ref : manifest_refs) {
            const bool has_uri = !ref.digest_uri.empty();
            const bool has_value = !ref.digest_base64.empty();
            manifest_has_any_digest = manifest_has_any_digest || has_uri || has_value;
            manifest_has_all_digests = manifest_has_all_digests && has_uri && has_value;
        }
        if (manifest_has_any_digest && !manifest_has_all_digests) {
            if (structural_error.empty()) {
                structural_error =
                    "ASiC-E manifest must provide DigestMethod and DigestValue for every data object";
            }
            all_valid = false;
            entry.signature_valid = false;
            signature_entries.push_back(std::move(entry));
            continue;
        }
        if (!manifest_has_all_digests && referenced_files.size() != 1) {
            if (structural_error.empty()) {
                structural_error =
                    "Legacy ASiC-E direct signature must reference exactly one data object";
            }
            all_valid = false;
            entry.signature_valid = false;
            signature_entries.push_back(std::move(entry));
            continue;
        }

        bool sig_valid = false;
        bool executed = false;
        if (manifest_has_all_digests) {
            const std::vector<std::uint8_t> manifest_bytes(sig.manifest_xml.begin(),
                                                           sig.manifest_xml.end());
            executed = VerifyData(manifest_bytes, sig.signature_data, sig_valid);

            // Підпис над маніфестом нічого не каже про самі дані — їх зв'язує
            // дайджест. Без цієї перевірки контейнер із підміненим документом
            // проходив би як валідний.
            if (executed && sig_valid) {
                for (std::size_t i = 0; i < manifest_refs.size(); ++i) {
                    std::string digest_error;
                    if (!AsicManifestDigestMatches(manifest_refs[i], referenced_files[i]->data,
                                                   digest_error)) {
                        sig_valid = false;
                        if (structural_error.empty()) {
                            structural_error =
                                "ASiC-E manifest digest does not match the data object '" +
                                referenced_files[i]->filename + "': " + digest_error;
                        }
                        break;
                    }
                }
            }
        } else {
            executed = VerifyData(referenced_files.front()->data, sig.signature_data, sig_valid);
        }
        entry.signature_valid = executed && sig_valid;
        if (executed) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (VerifyReportStillOwnedByThisThreadLocked()) {
                entry.timestamp_checked = last_verify_report_.timestamp_checked;
                entry.timestamp_valid = last_verify_report_.timestamp_valid;
                entry.timestamp_status = last_verify_report_.timestamp_status;
                entry.timestamp_details = last_verify_report_.timestamp_details;
                for (auto& detail : entry.timestamp_details) detail.signature_index = entry.index;
            }
        }
        if (!entry.signature_valid) {
            all_valid = false;
        } else {
            // Покритим вважається лише об'єкт, підпис над яким СПРАВДІ
            // перевірено. Інакше зламаний підпис «покривав» би свій файл і
            // ховав непокриття за іншою помилкою.
            for (const auto* referenced_file : referenced_files) {
                covered_files.insert(referenced_file->filename);
            }
            ++valid_count;
        }
        signature_entries.push_back(std::move(entry));
    }

    // П-03: інваріант ASiC-E — покритий має бути КОЖЕН data-об'єкт, а не
    // «хоча б один на підпис». `content.files` уже не містить ані `mimetype`,
    // ані `META-INF/*` (див. AsicEContainer::Unpack), тож усе, що тут є, —
    // це вміст, який мусить бути підписаний.
    //
    // Той самий інваріант і той самий формат діагностики, що на сестринському
    // шляху VerifyFileAsicEXades нижче: два шляхи для одного контейнерного
    // формату не сміють розходитися у визначенні покриття.
    std::string uncovered_list;
    for (const auto& file : content.files) {
        if (covered_files.count(file.filename) != 0) {
            continue;
        }
        if (!uncovered_list.empty()) {
            uncovered_list += ", ";
        }
        uncovered_list += file.filename;
    }
    const bool coverage_complete = uncovered_list.empty();

    is_valid = all_valid && !content.signatures.empty() && coverage_complete;
    if (!structural_error.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyFileAsicE", true, false, ErrorCode::InvalidArgument, structural_error);
        // ADR-029: контейнер не розібрався — це окремий стан, не «підпис не
        // зійшовся». Обидва шляхи ASiC-E позначають його однаково.
        last_verify_report_.container_malformed = true;
        // Доти тут стояв `ClearError()`, і це втрачало інформацію: 1С отримувала
        // `Ложь` без жодного пояснення, хоча пояснення вже лежало у звіті.
        // Логіка «виклик відпрацював -> помилки немає» тут не діє: структурна
        // вада контейнера — це причина відмови, і назвати її треба тим самим
        // каналом, яким користувач її шукає (`GetError()`), а не лише в JSON,
        // який читає не кожен. Сестринський шлях `VerifyFileAsicEXades` цю
        // причину повідомляв завжди.
        SetError(ErrorCode::InvalidArgument, structural_error);
    } else {
        OverrideVerifyReportOperation("VerifyFileAsicE");
    }

    // С-11: per-signature записи й підсумок — той самий формат, що вже дає
    // XAdES-шлях. Без цього звіт про контейнер із трьома підписами, з яких
    // зламаний другий, не показував ані третього, ані самої їх кількості.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Н-04: див. вище — per-signature записи теж належать конкретному
        // виклику й не сміють потрапити в чужий звіт.
        if (VerifyReportStillOwnedByThisThreadLocked()) {
            last_verify_report_.signatures = std::move(signature_entries);
            AggregatePerSignerTimestamps(last_verify_report_);
            // П-03: контейнерні факти. `container_type` доти лишався "unknown"
            // навіть після того, як Unpack звірив mimetype — звіт не казав, про
            // який контейнер узагалі йдеться, хоч і робив твердження про нього.
            last_verify_report_.container_type = "ASiC-E";
            last_verify_report_.container_coverage_complete = coverage_complete;
            last_verify_report_.coverage_status =
                coverage_complete ? "complete" : "container-object-not-signed";
            last_verify_report_.message += "; signaturesTotal=" +
                                           std::to_string(content.signatures.size()) +
                                           "; signaturesValid=" + std::to_string(valid_count) +
                                           "; containerCoverageComplete=" +
                                           (coverage_complete ? "true" : "false") +
                                           (coverage_complete ? "" : ("; uncovered=[" + uncovered_list + "]"));
            RefreshUserReportForCurrentOperation();
        }
    }
    
    if (is_valid && !content.timestamp_data.empty()) {
        // S-001: раніше timestamp_valid = true БЕЗУМОВНО (контейнерний токен не
        // декодувався взагалі). Тепер токен криптографічно перевіряється проти
        // CMS-блоба першого підпису (той самий блоб, який штампувався у
        // SignFileAsicE через ResolveTspImprint(..., signature, signature, ...)),
        // fail-closed при розбіжності imprint чи невалідному підписі TSA.
        // Хвиля 8, п.3 — див. коментар у VerifyFileAsicS вище.
        bool canonical_valid = false;
        std::string canonical_reason;
        TimestampEntry container_detail;
        const bool canonical_available = TryCanonicalTimestampVerdict(
            local_settings, content.timestamp_data, content.signatures.front().signature_data,
            /*validation_time=*/std::string{}, canonical_valid, canonical_reason,
            {}, {}, {}, &container_detail);
        container_detail.kind = "container";
        const auto ts = tamga::core::policy::ValidateTimestampToken(
            content.timestamp_data, content.signatures.front().signature_data);
        std::lock_guard<std::mutex> lock(mutex_);
        // Н-04: доуточнюємо ЛИШЕ власний звіт. Між комітом VerifyData вище і
        // цим моментом mutex_ відпускався (перевірка токена — робота без
        // блокування), тож паралельний Verify* на тій самій сесії міг встигнути
        // закомітити свій результат. Без цієї перевірки статус мітки часу
        // потрапляв би в чужий звіт.
        if (!VerifyReportStillOwnedByThisThreadLocked()) {
            return true;
        }
        last_verify_report_.timestamp_checked = true;
        last_verify_report_.timestamp_details.push_back(std::move(container_detail));
        last_verify_report_.tsp_checked = true;
        // В-03: крипто-результат — база, канонічний вердикт лише ПІДВИЩУЄ.
        //
        // Перша версія цієї правки підставляла канонічний результат замість
        // крипто-результату — і тести показали, чому це хибно: контейнер із
        // криптографічно бездоганною міткою, але без trust-матеріалу для TSA,
        // ставав "timestamp-invalid". «Довіру не встановлено» — це не «мітка
        // недійсна»; саме цю різницю й фіксує В-03.
        ApplyFormatTimestampVerdict(last_verify_report_, ts.valid,
                                    /*canonical_full=*/canonical_available && canonical_valid);
        // Причина, чому повного вердикту немає, тепер видима. Доти контейнерна
        // мітка мовчала: користувач бачив "partial" і не міг відрізнити «TSA
        // недовірений» від «сертифікат TSA не має EKU для timestamping» чи
        // «trust-store порожній».
        if (!canonical_reason.empty()) {
            AppendContainerTimestampMessage(last_verify_report_, canonical_reason);
        }
        RefreshUserReportForCurrentOperation();
    }
    
    return true;
}

bool Session::AddSignatureToAsicE(const std::string& asice_path, const std::string& output_path) {
    FileStoreSettings settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        if (!is_private_key_loaded_) {
            SetError(ErrorCode::KeyNotLoaded, ToString(ErrorCode::KeyNotLoaded));
            return false;
        }
        settings = file_store_settings_;
    }

    std::vector<std::uint8_t> container;
    std::string error_message;
    std::string resolved_asice_path = ResolveFilePath(asice_path, settings);
    if (!ReadBinaryFile(resolved_asice_path, "ASiC-E container", container, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, std::move(error_message));
        return false;
    }

    AsicEContent content;
    if (!AsicEContainer::Unpack(container, content, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Failed to unpack ASiC-E: " + error_message);
        return false;
    }

    if (content.files.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "ASiC-E container has no documents to sign");
        return false;
    }

    // Знаходимо вільний тризначний суфікс. Розмір списку не годиться як
    // номер: у контейнері можуть бути, наприклад, 001 і 003.
    std::size_t sig_num = content.signatures.size() + 1;
    std::string sig_name;
    std::string manifest_name;
    for (;;) {
        std::ostringstream suffix;
        suffix << std::setw(3) << std::setfill('0') << sig_num;
        sig_name = "META-INF/signature" + suffix.str() + ".p7s";
        manifest_name = "META-INF/ASiCManifest" + suffix.str() + ".xml";
        const bool occupied = std::any_of(
            content.signatures.begin(), content.signatures.end(),
            [&sig_name, &manifest_name](const AsicEContent::SignatureEntry& entry) {
                return entry.sig_filename == sig_name || entry.manifest_filename == manifest_name;
            });
        if (!occupied) {
            break;
        }
        ++sig_num;
    }

    // Кожен новий CAdES-підпис ASiC-E покриває свій готовий маніфест, а
    // маніфест — усі файли даних. Підпис першого payload напряму створював би
    // контейнер із декларацією, що не відповідає підписаним байтам.
    std::vector<AsicDataObjectRef> refs;
    refs.reserve(content.files.size());
    for (const auto& file : content.files) {
        ImprintResult imprint;
        std::string imprint_error;
        if (!ComputeImprint(ImprintDigest::Kupyna256, file.data, imprint, imprint_error)) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetError(ErrorCode::InternalError,
                     "Failed to hash ASiC-E data for co-signature manifest: " + imprint_error);
            return false;
        }
        AsicDataObjectRef ref;
        ref.uri = file.filename;
        ref.mime_type = GetMimeTypeFromFilename(file.filename);
        ref.digest_uri = DigestOidToXmlDsigUri(imprint.digest_oid);
        ref.digest_base64 = util::Base64Encode(imprint.hash);
        refs.push_back(std::move(ref));
    }
    const std::string manifest_xml = GenerateAsicManifestXml(sig_name, refs);
    const std::vector<std::uint8_t> manifest_data(manifest_xml.begin(), manifest_xml.end());
    std::vector<std::uint8_t> signature;
    if (!SignData(manifest_data, signature)) {
        return false;
    }

    std::vector<std::uint8_t> out_container;
    if (!AsicEContainer::AddSignature(container, signature, sig_name, manifest_name,
                                      manifest_xml, out_container, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InternalError, "Failed to add signature to ASiC-E: " + error_message);
        return false;
    }

    std::string resolved_output_path = ResolveFilePath(output_path, settings);
    std::filesystem::path fs_out_path = std::filesystem::u8path(resolved_output_path);
    if (!settings.allow_overwrite && std::filesystem::exists(fs_out_path)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetError(ErrorCode::InvalidArgument, "Output file already exists");
        return false;
    }

    // П-12: запис через спільний атомарний writer. Прямий `ofstream ... trunc`
    // обнуляв цільовий файл до появи першого байта нового контейнера, тож
    // перервана операція лишала на місці підписаного документа усічений файл.
    const auto write_result = util::WriteBytesAtomic(fs_out_path, out_container.data(), out_container.size());
    if (!write_result) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (write_result.status == util::AtomicWriteStatus::TargetUnusable) {
            SetError(ErrorCode::InvalidArgument, "Unable to open output file: " + resolved_output_path);
        } else {
            SetError(ErrorCode::InternalError,
                     "Failed writing modified ASiC-E output file: " + write_result.message);
        }
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    ClearError();
    return true;
}

} // namespace tamga::core

namespace tamga::core {

bool Session::VerifyFileAsicEXades(const std::string& asice_path, bool& is_valid) {
    FileStoreSettings settings;
    // HI-01: знімок Settings під тим самим коротким lock, що й file_store_settings_
    // вище — потрібен, щоб новий per-signer trust-validation цикл нижче (поза
    // lock_guard) міг безпечно читати trust_mode/validation_level/work_dir
    // тощо, не звертаючись напряму до settings_ без синхронізації.
    Settings local_settings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!is_initialized_) {
            SetError(ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            SetVerifyReport("VerifyFileAsicEXades", false, false, ErrorCode::NotInitialized, ToString(ErrorCode::NotInitialized));
            return false;
        }
        settings = file_store_settings_;
        local_settings = settings_;
    }
    is_valid = false;
#if defined(TAMGA_XML_SIGNATURES_ENABLED)
    AsicReader reader;
    std::string error_message;
    if (!reader.LoadFromFile(ResolveFilePath(asice_path, settings), error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyFileAsicEXades", false, false, ErrorCode::InvalidArgument, error_message);
        SetError(ErrorCode::InvalidArgument, error_message);
        return false;
    }
    // Тип контейнера беремо з файлу `mimetype`, а не припускаємо ASiC-E.
    // Раніше тут стояв жорсткий "ASiC-E" для будь-якого контейнера, тож
    // справжній ASiC-S (`application/vnd.etsi.asic-s+zip`) звітувався як ASiC-E.
    // Для 1С це видима неправда у звіті: профілі мають різні правила покриття
    // (ASiC-S — рівно один підписаний обʼєкт, ASiC-E — маніфест і кілька).
    const std::string detected_container_type = [&reader]() {
        std::string mimetype;
        if (reader.GetMimetype(mimetype)) {
            if (mimetype.find("asic-s") != std::string::npos) {
                return std::string("ASiC-S");
            }
            if (mimetype.find("asic-e") != std::string::npos) {
                return std::string("ASiC-E");
            }
        }
        // Немає/нерозпізнаний mimetype — ASiC-E лишається типовим, бо саме він
        // допускає META-INF/*signatures*.xml, який цей шлях і розбирає.
        return std::string("ASiC-E");
    }();

    std::vector<AsicFileEntry> entries;
    if (!reader.GetFiles(entries, error_message)) {
        std::lock_guard<std::mutex> lock(mutex_);
        SetVerifyReport("VerifyFileAsicEXades", false, false, ErrorCode::InvalidArgument, error_message);
        SetError(ErrorCode::InvalidArgument, error_message);
        return false;
    }
    std::map<std::string, std::vector<std::uint8_t>> external;
    // WP-7 (ME-05): external будується з НОРМАЛІЗОВАНИХ (не сирих) entry-імен,
    // тими самими правилами (percent-decode + "./"-strip), що й
    // ds:Reference URI у XmlReferenceResolver::ResolveReference — інакше
    // URI="./file.pdf" міг пройти coverage-перевірку (яка вже нормалізувала),
    // але провалити фактичний резолвінг вмісту (map був keyed сирим ім'ям).
    // normalized_to_raw ловить неоднозначність: якщо ДВА різних сирих
    // entry-імені нормалізуються в один і той самий ключ, контейнер
    // відхиляється цілком (fail-closed) — мовчазний вибір "останнього"
    // приховав би потенційну підміну entry.
    std::map<std::string, std::string> normalized_to_raw;
    std::vector<std::string> signature_xmls;
    for (const auto& e : entries) {
        if (e.name.rfind("META-INF/signatures", 0) == 0 && e.name.size() >= 4 && e.name.substr(e.name.size() - 4) == ".xml") {
            signature_xmls.emplace_back(e.data.begin(), e.data.end());
        } else if (e.name != "mimetype" && e.name.rfind("META-INF/", 0) != 0) {
            std::string normalized_name;
            std::string normalize_error;
            if (!tamga::util::NormalizeAsicEntryUri(e.name, normalized_name, normalize_error)) {
                normalized_name = e.name;  // best-effort: те саме, що й NormalizeCoverageUri
            }
            const auto existing = normalized_to_raw.find(normalized_name);
            if (existing != normalized_to_raw.end() && existing->second != e.name) {
                std::lock_guard<std::mutex> lock(mutex_);
                const std::string msg = "ASiC-E контейнер містить неоднозначні entry-імена: '" +
                                        existing->second + "' і '" + e.name +
                                        "' нормалізуються до однакового URI '" + normalized_name + "'";
                // ADR-029: доти цей шлях завалював сам ВИКЛИК
                // (`execution_succeeded=false`, `summary.code =
                // VERIFICATION_EXECUTION_FAILED`, повернення `false`), тоді як
                // CAdES-шлях на ту саму ваду повертав «виклик відпрацював,
                // документ невалідний». Два шляхи одного формату розповідали
                // про однакову подію по-різному, і жодна з двох назв не була
                // правдою. Тепер обидва: виклик відпрацював, вердикт винесено,
                // причина названа точно.
                SetVerifyReport("VerifyFileAsicEXades", true, false, ErrorCode::InvalidArgument, msg);
                last_verify_report_.container_malformed = true;
                RefreshUserReportForCurrentOperation();
                SetError(ErrorCode::InvalidArgument, msg);
                is_valid = false;
                return true;
            }
            normalized_to_raw[normalized_name] = e.name;
            external[normalized_name] = e.data;
        }
    }
    if (signature_xmls.empty() || external.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::string msg = signature_xmls.empty() ? "ASiC-E XAdES signature entry not found" : "ASiC-E document entry not found";
        SetVerifyReport("VerifyFileAsicEXades", true, false, ErrorCode::InvalidArgument, msg);
        ClearError();
        return true;
    }

    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesVerifier verifier(xml_verifier, crypto, tsp);

    // WP-2: перевіряємо ВСІ META-INF/signatures*.xml контейнера; агрегований
    // verdict — кон'юнкція (будь-який невалідний підпис робить контейнер
    // невалідним). Раніше брався лише ОСТАННІЙ signatures*.xml, тож невалідний/
    // додатковий підпис міг мовчки ігноруватись (C2 / HI-03 — хибнопозитив).
    // Для звіту-діагностики репрезентативним обираємо ПЕРШИЙ невалідний підпис
    // (а якщо всі валідні — перший загалом).
    tamga::xades::XadesVerificationResult result;
    bool have_result = false;
    bool result_valid = false;
    bool all_valid = true;
    std::size_t valid_count = 0;
    std::size_t total_count = 0;
    std::vector<std::string> covered_uris;  // WP-7: detached data-obj, покриті ds:Reference
    // WP-2 (Session-інтеграція): плаский список per-signature звіту — по
    // одному запису на кожен ds:Signature з КОЖНОГО META-INF/signatures*.xml
    // (кілька файлів co-signing X кілька підписів в одному файлі).
    std::vector<SignatureEntry> signature_entries;
    for (const std::string& sig_xml : signature_xmls) {
        tamga::xades::XadesSignatureSet one_set;
        std::string err;
        if (!verifier.VerifyAll(sig_xml, external, one_set, err)) {
            std::lock_guard<std::mutex> lock(mutex_);
            SetVerifyReport("VerifyFileAsicEXades", false, false, ErrorCode::InvalidArgument, err);
            SetError(ErrorCode::InvalidArgument, err);
            return false;
        }
        for (auto& r : one_set.signatures) {
            ++total_count;
            const bool sig_valid = r.signature_valid;
            if (sig_valid) {
                ++valid_count;
            } else {
                all_valid = false;
            }
            for (const auto& rd : r.xml_signature.reference_details) {
                if (!rd.uri.empty() && rd.uri.front() != '#') {
                    covered_uris.push_back(NormalizeCoverageUri(rd.uri));
                }
            }
            SignatureEntry entry;
            entry.index = static_cast<int>(total_count);
            entry.signature_valid = sig_valid;
            entry.signer_certificate_present = !r.signer_certificate_der.empty();
            entry.qualifying_properties_present = r.qualifying_properties_present;
            entry.signing_certificate_digest_valid = r.signing_certificate_digest_valid;
            entry.format_profile = r.format_profile.empty() ? "XAdES" : r.format_profile;
            entry.timestamp_checked = r.signature_timestamp_checked;
            if (entry.timestamp_checked) {
                ApplyEntryTimestampVerdict(entry, r.signature_timestamp_valid);
            }
            entry.ltv_valid = r.ltv_valid;
            entry.ltv_evidence_bound = r.ltv_evidence_bound;
            // HI-01: незалежна trust/revocation/certificate.timeValid-перевірка
            // САМЕ цього підписанта — ДО можливого std::move(r) нижче, інакше
            // цей запис лишиться без сертифіката/доказів для перевірки.
            ApplyPerSignerTrustValidation(local_settings, r.signer_certificate_der, r.certificate_values_der,
                                          r.revocation_values_ocsp_der, r.revocation_values_crl_der, entry);
            ApplyPerSignerXadesTimestampValidation(local_settings, r, entry);
            entry.ltv_evidence_validated = entry.ltv_evidence_bound && entry.trust_valid &&
                (entry.revocation_status == "valid" || entry.revocation_status == "good");
            entry.signature_policy_present = r.signature_policy_present;
            entry.signature_policy_id = r.signature_policy_id;
            entry.signature_policy_hash_algo_uri = r.signature_policy_hash_algo_uri;
            entry.data_object_formats = ToSessionDataObjectFormats(r.data_object_formats);
            signature_entries.push_back(std::move(entry));

            if (!have_result || (!sig_valid && result_valid)) {
                result = std::move(r);
                result_valid = sig_valid;
                have_result = true;
            }
        }
    }
    is_valid = all_valid;

    // WP-7 (M3): кожен data-obj контейнера має бути покритий якимось підписом;
    // доданий несигнований файл -> containerCoverageComplete=false (усуває FP).
    bool coverage_complete = true;
    std::string uncovered_list;
    for (const auto& kv : external) {
        // external вже keyed нормалізованими іменами (див. побудову вище) —
        // повторна нормалізація тут не потрібна.
        const std::string& key = kv.first;
        bool found = false;
        for (const std::string& c : covered_uris) {
            if (c == key) { found = true; break; }
        }
        if (!found) {
            coverage_complete = false;
            if (!uncovered_list.empty()) uncovered_list += ",";
            uncovered_list += kv.first;
        }
    }
    // К-01 (симетрія з PAdES): контейнер, що несе непідписаний файл, не є
    // валідно підписаним. Раніше `is_valid` вище відображав лише валідність
    // самих підписів, тож containerCoverageComplete=false співіснувало з
    // булевим `true` — саме той хибнопозитив, від якого застерігає коментар
    // у tests/asic_coverage_tests.cpp.
    is_valid = is_valid && coverage_complete;
    // Lock-narrowing (той самий патерн, що WP-17 застосував до VerifyXml):
    // звіт будується у ЛОКАЛЬНОМУ report, а вся trust/revocation/TSA-перевірка
    // (мережеві OCSP/CRL/chain- і TSA-виклики) виконується НАД НИМ, ПОЗА
    // lock_guard. Раніше ця ділянка тримала mutex_ на всю свою тривалість,
    // включно з мережевими викликами — потенційне блокування GetError()/
    // GetLastVerifyReport() з іншого потоку на час повільної (offline/online)
    // перевірки; HI-01 (PR #37) додатково впровадив per-signer цикл (N
    // окремих trust-викликів замість одного репрезентативного) усередину
    // цього самого блоку, пропорційно погіршуючи проблему — саме це стало
    // приводом звузити critical section тут так само, як WP-17 уже зробив
    // для VerifyXml.
    const std::string xades_profile = result.format_profile.empty() ? "XAdES" : result.format_profile;
    VerifyReport report;
    report.has_result = true;
    report.execution_succeeded = true;
    report.signature_valid = all_valid;
    report.signature_format = "XAdES";
    report.format_profile = xades_profile;
    report.container_type = detected_container_type;
    report.signer_certificate_present = !result.signer_certificate_der.empty();
    report.qualifying_properties_present = result.qualifying_properties_present;
    report.timestamp_checked = result.signature_timestamp_checked;
    report.tsp_checked = result.tsp_checked;
    if (report.timestamp_checked) {
        ApplyFormatTimestampVerdict(report, result.signature_timestamp_valid,
                                    /*canonical_full=*/false);
    }
    report.ltv_valid = result.ltv_valid;
    report.ltv_evidence_bound = result.ltv_evidence_bound;
    // ME-02: див. коментар при VerifyReport::revocation_evidence_present.
    report.revocation_evidence_present = result.revocation_values_present;
    report.signature_policy_present = result.signature_policy_present;
    report.signature_policy_id = result.signature_policy_id;
    report.signature_policy_hash_algo_uri = result.signature_policy_hash_algo_uri;
    report.data_object_formats = ToSessionDataObjectFormats(result.data_object_formats);
    report.container_coverage_complete = coverage_complete;
    report.coverage_status = coverage_complete ? "complete" : "container-object-not-signed";
    report.operation = "VerifyFileAsicEXades";
    report.policy = "xades-format";
    report.message = BuildXadesXmlDiagnostics(result) +
                     "; signaturesTotal=" + std::to_string(total_count) +
                     "; signaturesValid=" + std::to_string(valid_count) +
                     "; containerCoverageComplete=" + (coverage_complete ? "true" : "false") +
                     (coverage_complete ? "" : ("; uncovered=[" + uncovered_list + "]"));
    report.signatures = std::move(signature_entries);
    // Q-004: окремий RunFormatTrustValidationOn для репрезентативного
    // сертифіката видалений — ApplyPerSignerTrustAggregation нижче
    // заповнює error_code/message/chain_debug з "найгіршого" підписанта
    // (так само як trust_valid/revocation_status/chain_valid тощо), тому
    // попередній мережевий trust-виклик давав N+1 мережевих round-trips
    // при N підписантах без жодного корисного ефекту (HI-01).
    ApplyPerSignerTrustAggregation(report);
    // WP-5 (ME-04): фіксуємо evidence-binding verdict одразу після
    // сертифікат/revocation-перевірки — ДО ApplyXadesTimestampPolicyValidation,
    // яка може окремо (з причин TSA-довіри, WP-6) скинути trust_valid.
    // validated_profile описує саме підтвердження XAdES LTV-доказів і не
    // має залежати від ще не реалізованого TSA-chain trust.
    const bool xades_evidence_confirmed = result.ltv_evidence_bound &&
                                          report.trust_valid &&
                                          (report.revocation_status == "valid" ||
                                           report.revocation_status == "good");
    report.container_type = detected_container_type;
    report.signature_format = "XAdES";
    report.format_profile = xades_profile;
    AggregatePerSignerTimestamps(report);
    report.validated_profile = xades_evidence_confirmed ? xades_profile : std::string();
    // HI-02: той самий вираз, що вирішує validated_profile вище.
    report.ltv_evidence_validated = xades_evidence_confirmed;

    // Фінальний коміт: єдина ділянка, де це знову торкається спільного
    // стану Session, — короткий lock без жодного мережевого виклику під ним.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_verify_report_ = std::move(report);
        // Н-04: фіксуємо епоху цього коміту — доуточнення нижче застосується
        // лише якщо звіт усе ще належить цьому потоку.
        MarkVerifyReportCommittedLocked();
        RefreshUserReport("ASiC-E", "XAdES");
        ClearError();
    }
    return true;
#else
    (void)asice_path;
    std::lock_guard<std::mutex> lock(mutex_);
    SetVerifyReport("VerifyFileAsicEXades", false, false, ErrorCode::NotSupported,
                    "XMLDSIG support requires building with TAMGA_ENABLE_XML_SIGNATURES");
    SetError(ErrorCode::NotSupported, "XMLDSIG support requires building with TAMGA_ENABLE_XML_SIGNATURES");
    return false;
#endif
}

} // namespace tamga::core
