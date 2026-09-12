#include "xades/XadesVerifier.h"
#include "xmldsig/XmlHelpers.h"

#if defined(TAMGA_XML_SIGNATURES_ENABLED)

#include <vector>

#include "core/policy/TimestampValidator.h"
#include "util/Base64.h"
#include "xades/detail/XadesArchiveImprint.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/detail/XmlDocUtil.h"

namespace tamga::xades {

// ADR-027: хелпери libxml2 і URI живуть у `xmldsig/XmlHelpers` — тут були
// їх копії. Тіла збігалися, тож поведінка не змінюється.
using tamga::xmldsig::TrimmedText;

namespace {

using namespace tamga::xmldsig::detail;


// WP-5: збирає decoded DER для усіх елементів local_name у піддереві scope
// (напр. EncapsulatedX509Certificate під CertificateValues).
// П-13: збіг ЛИШЕ за (namespace XAdES з allowlist, локальна назва) —
// значення з чужого namespace не є доказом XAdES і не має потрапляти у звіт.
void CollectBase64Values(xmlNodePtr scope, const char* local_name,
                         std::vector<std::vector<std::uint8_t>>& out) {
    for (xmlNodePtr node = scope; node != nullptr; node = node->next) {
        if (IsXadesElementNamed(node, local_name)) {
            std::vector<std::uint8_t> der;
            if (tamga::util::Base64Decode(TrimmedText(node), der) && !der.empty()) {
                out.push_back(std::move(der));
            }
        }
        if (node->children != nullptr) {
            CollectBase64Values(node->children, local_name, out);
        }
    }
}

// WP-5: збирає вказівники на елементи local_name у піддереві (для обходу
// CompleteCertificateRefs/CompleteRevocationRefs — потрібен сам вузол, щоб
// дістатись до вкладеного DigestAlgAndValue/CertDigest).
// П-13: те саме — лише вузли XAdES із allowlist-namespace.
void CollectElementNodes(xmlNodePtr scope, const char* local_name, std::vector<xmlNodePtr>& out) {
    for (xmlNodePtr node = scope; node != nullptr; node = node->next) {
        if (IsXadesElementNamed(node, local_name)) {
            out.push_back(node);
        }
        if (node->children != nullptr) {
            CollectElementNodes(node->children, local_name, out);
        }
    }
}

// WP-5: чи збігається DigestMethod/DigestValue під digest_node з дайджестом
// хоча б одного кандидата. by_certificate обирає режим обчислення дайджесту:
// сертифікатні CertDigest у XAdES рахуються "по сертифікату" (як і
// SigningCertificate/CertDigest вище), а CRL/OCSP DigestAlgAndValue — над
// сирими байтами значення.
bool RefDigestMatchesAny(xmlNodePtr digest_node,
                         const std::vector<std::vector<std::uint8_t>>& candidates,
                         bool by_certificate) {
    if (digest_node == nullptr) {
        return false;
    }
    // П-13: DigestMethod/DigestValue всередині XAdES-структур належать саме
    // до namespace XMLDSIG (див. XadesBuilder::AddDigestAlgAndValue).
    xmlNodePtr dm = FindFirstDsigElement(digest_node->children, "DigestMethod");
    xmlNodePtr dv = FindFirstDsigElement(digest_node->children, "DigestValue");
    if (dm == nullptr || dv == nullptr) {
        return false;
    }
    const std::string algo = GetAttr(dm, "Algorithm");
    std::vector<std::uint8_t> expected;
    if (!tamga::util::Base64Decode(TrimmedText(dv), expected) || expected.empty()) {
        return false;
    }
    tamga::xmldsig::XmlDigestEngine digest_engine;
    for (const auto& candidate : candidates) {
        std::vector<std::uint8_t> computed;
        std::string e;
        const bool ok = by_certificate
            ? digest_engine.ComputeDigestByCertificate(candidate, algo, candidate, computed, e)
            : digest_engine.ComputeDigest(candidate, algo, computed, e);
        if (ok && computed == expected) {
            return true;
        }
    }
    return false;
}

struct TimestampCheck {
    bool present{false};
    bool checked{false};
    bool valid{false};
};

// WP-2 (продовження): повна XAdES-специфічна перевірка ОДНОГО підпису,
// прив'язана до конкретного signature_node (а не до кореня документа) і до
// signature_position_1based-го верхньорівневого ds:Signature для позиційної
// канонікалізації TBS часових міток. Викликається як для єдиного підпису
// (Verify(), position=1), так і для кожного підпису в межах VerifyAll() —
// в обох випадках XAdES-пошук ніколи не виходить за межі свого ds:Signature.
bool VerifyOneXadesSignature(xmlDocPtr doc_raw, xmlNodePtr signature_node, int signature_position_1based,
                             const tamga::xmldsig::XmlSignatureVerificationResult& xml_result,
                             XadesVerificationResult& result, std::string& error_message) {
    (void)error_message;  // структурні помилки цього рівня повідомляються через result.notes
    result = XadesVerificationResult{};
    result.xml_signature = xml_result;
    result.signature_valid = xml_result.signature_valid && xml_result.digest_valid;

    xmlNodePtr signed_props = FindFirstXadesElementInSubtree(signature_node, "SignedProperties");
    result.qualifying_properties_present = (signed_props != nullptr);
    if (signed_props == nullptr) {
        result.notes.push_back("missing xades:SignedProperties");
        return true;
    }

    if (xmlNodePtr signing_time = FindFirstXadesElement(signed_props->children, "SigningTime")) {
        result.signing_time = TrimmedText(signing_time);
    }

    // Звірка SigningCertificate/CertDigest з вбудованим сертифікатом.
    xmlNodePtr cert_digest = FindFirstXadesElement(signed_props->children, "CertDigest");
    xmlNodePtr x509_cert = FindFirstDsigElementInSubtree(signature_node, "X509Certificate");
    if (cert_digest != nullptr && x509_cert != nullptr) {
        xmlNodePtr dm = FindFirstDsigElement(cert_digest->children, "DigestMethod");
        xmlNodePtr dv = FindFirstDsigElement(cert_digest->children, "DigestValue");
        const std::string algo = dm != nullptr ? GetAttr(dm, "Algorithm") : std::string{};
        std::vector<std::uint8_t> cert_der;
        std::vector<std::uint8_t> expected;
        if (tamga::util::Base64Decode(TrimmedText(x509_cert), cert_der) &&
            dv != nullptr && tamga::util::Base64Decode(TrimmedText(dv), expected)) {
            result.signer_certificate_der = cert_der;  // для trust-валідації Session
            tamga::xmldsig::XmlDigestEngine digest_engine;
            std::vector<std::uint8_t> computed;
            std::string e;
            if (digest_engine.ComputeDigestByCertificate(cert_der, algo, cert_der, computed, e) && computed == expected) {
                result.signing_certificate_digest_valid = true;
            } else {
                result.notes.push_back("SigningCertificate CertDigest mismatch");
            }
        }
    } else {
        result.notes.push_back("missing CertDigest or X509Certificate");
    }
    // S-003: CertDigest mismatch or missing CertDigest/X509Certificate is a
    // mandatory XAdES check failure per ETSI EN 319 132-1 §5.2.2 — fail-closed.
    result.signature_valid = result.signature_valid && result.signing_certificate_digest_valid;

    // WP-12: SignaturePolicyIdentifier (ETSI EN 319 132-1 §5.2.1.3) —
    // структурний парсинг, БЕЗ криптографічної перевірки SigPolicyHash проти
    // зовнішнього документа політики (Tamga не має доступу до реєстру
    // політик підпису) — лише експонує присутні дані для звіту/аудиту.
    if (xmlNodePtr policy_id_node =
            FindFirstXadesElement(signed_props->children, "SignaturePolicyIdentifier")) {
        result.signature_policy_present = true;
        if (xmlNodePtr identifier = FindFirstXadesElement(policy_id_node->children, "Identifier")) {
            result.signature_policy_id = TrimmedText(identifier);
        }
        if (xmlNodePtr sph = FindFirstXadesElement(policy_id_node->children, "SigPolicyHash")) {
            if (xmlNodePtr dm = FindFirstDsigElement(sph->children, "DigestMethod")) {
                result.signature_policy_hash_algo_uri = GetAttr(dm, "Algorithm");
            }
            if (xmlNodePtr dv = FindFirstDsigElement(sph->children, "DigestValue")) {
                tamga::util::Base64Decode(TrimmedText(dv), result.signature_policy_hash_value);
            }
        }
    }

    // WP-12: SignedDataObjectProperties/DataObjectFormat (ETSI EN 319 132-1
    // §5.2.2) — структурний парсинг усіх записів у порядку документа.
    {
        std::vector<xmlNodePtr> dof_nodes;
        CollectElementNodes(signed_props->children, "DataObjectFormat", dof_nodes);
        for (xmlNodePtr dof_node : dof_nodes) {
            DataObjectFormat dof;
            dof.object_reference = GetAttr(dof_node, "ObjectReference");
            if (xmlNodePtr description = FindFirstXadesElement(dof_node->children, "Description")) {
                dof.description = TrimmedText(description);
            }
            if (xmlNodePtr mime_type = FindFirstXadesElement(dof_node->children, "MimeType")) {
                dof.mime_type = TrimmedText(mime_type);
            }
            result.data_object_formats.push_back(std::move(dof));
        }
    }

    // Валідація міток часу (T/X/A). Для SignatureTimeStamp XAdES вимагає
    // RFC3161 messageImprint від canonicalized ds:SignatureValue у контексті
    // ЦЬОГО КОНКРЕТНОГО підпису. Повертаємо окремо "present" і "checked", щоб
    // report не губив факт наявності токена, навіть якщо криптоперевірка впала.
    auto validate_ts = [&](const char* ts_name, const std::vector<std::string>& tbs_names,
                           const char* label) -> TimestampCheck {
        TimestampCheck check;
        xmlNodePtr ts = FindFirstXadesElementInSubtree(signature_node, ts_name);
        if (ts == nullptr) {
            return check;
        }
        check.present = true;
        xmlNodePtr enc = FindFirstXadesElement(ts->children, "EncapsulatedTimeStamp");
        std::vector<std::uint8_t> token;
        if (enc == nullptr || !tamga::util::Base64Decode(TrimmedText(enc), token)) {
            result.notes.push_back(std::string(label) + ": missing/invalid EncapsulatedTimeStamp");
            return check;
        }
        int mode = XML_C14N_1_0;
        int comments = 0;
        if (xmlNodePtr c14n = FindFirstDsigElement(ts->children, "CanonicalizationMethod")) {
            C14nUriToMode(GetAttr(c14n, "Algorithm"), mode, comments);
        }
        std::string tbs_str;
        std::string e;
        if (!ConcatCanonicalWithinSignature(doc_raw, signature_position_1based, signature_node, tbs_names, mode,
                                            comments, tbs_str, e)) {
            result.notes.push_back(std::string(label) + ": C14N failed");
            return check;
        }
        const std::vector<std::uint8_t> tbs(tbs_str.begin(), tbs_str.end());
        if (std::string(ts_name) == "SignatureTimeStamp") {
            result.signature_timestamp_token_der = token;
            result.signature_timestamp_canonicalized_data = tbs;
        }
        check.checked = true;
        auto vr = tamga::core::policy::ValidateTimestampToken(token, tbs);
        check.valid = vr.valid;
        if (!vr.valid) {
            result.notes.push_back(std::string(label) + ": " + vr.message);
        }
        return check;
    };

    const TimestampCheck sig_ts_state = validate_ts("SignatureTimeStamp", {"SignatureValue"}, "SignatureTimeStamp");
    const TimestampCheck sar_ts_state = validate_ts(
        "SigAndRefsTimeStamp",
        {"SignatureValue", "SignatureTimeStamp", "CompleteCertificateRefs", "CompleteRevocationRefs"},
        "SigAndRefsTimeStamp");

    // ArchiveTimeStamp (WP-13): ETSI EN 319 132-1 §5.5.2.3 message imprint
    // (not-distributed case) -- окремий шлях від validate_ts вище, бо
    // потребує обробки ds:Reference (крок 1) і виключення ds:Object з
    // QualifyingProperties (крок 6), яких немає в TBS SignatureTimeStamp/
    // SigAndRefsTimeStamp. Спільна функція з XadesBuilder, див.
    // xades/detail/XadesArchiveImprint.h. Tamga створює не більше одного
    // ArchiveTimeStamp за раз, тому "unsigned properties, що передують
    // ArchiveTimeStamp" (§5.5.2.3, validating an existing ATS) збігаються з
    // повним переліком, який передає builder при СТВОРЕННІ.
    TimestampCheck arch_ts_state;
    if (xmlNodePtr arch_ts_node = FindFirstXadesElementInSubtree(signature_node, "ArchiveTimeStamp")) {
        arch_ts_state.present = true;
        xmlNodePtr enc = FindFirstXadesElement(arch_ts_node->children, "EncapsulatedTimeStamp");
        std::vector<std::uint8_t> token;
        if (enc == nullptr || !tamga::util::Base64Decode(TrimmedText(enc), token)) {
            result.notes.push_back("ArchiveTimeStamp: missing/invalid EncapsulatedTimeStamp");
        } else {
            int mode = XML_C14N_1_0;
            int comments = 0;
            if (xmlNodePtr c14n = FindFirstDsigElement(arch_ts_node->children, "CanonicalizationMethod")) {
                C14nUriToMode(GetAttr(c14n, "Algorithm"), mode, comments);
            }
            const std::string archive_snapshot = SerializeNode(doc_raw, xmlDocGetRootElement(doc_raw));
            std::string tbs_str;
            std::string build_error;
            if (!tamga::xades::detail::BuildArchiveTimeStampImprintInput(
                    doc_raw, archive_snapshot, signature_position_1based, signature_node,
                    {"SignatureTimeStamp", "CompleteCertificateRefs", "CompleteRevocationRefs",
                     "SigAndRefsTimeStamp", "CertificateValues", "RevocationValues"},
                    mode, comments, tbs_str, build_error)) {
                result.notes.push_back("ArchiveTimeStamp: imprint-input build failed: " + build_error);
            } else {
                const std::vector<std::uint8_t> tbs(tbs_str.begin(), tbs_str.end());
                arch_ts_state.checked = true;
                auto vr = tamga::core::policy::ValidateTimestampToken(token, tbs);
                arch_ts_state.valid = vr.valid;
                if (!vr.valid) {
                    result.notes.push_back("ArchiveTimeStamp: " + vr.message);
                }
            }
        }
    }

    bool any_ts = false;
    bool all_ts_ok = true;
    for (const TimestampCheck& s : {sig_ts_state, sar_ts_state, arch_ts_state}) {
        if (!s.present) {
            continue;
        }
        any_ts = true;
        if (!s.checked || !s.valid) {
            all_ts_ok = false;
        }
    }
    result.signature_timestamp_present = sig_ts_state.present;
    result.signature_timestamp_checked = sig_ts_state.present;
    result.signature_timestamp_valid = sig_ts_state.valid;
    result.tsp_checked = sig_ts_state.checked || sar_ts_state.checked || arch_ts_state.checked;
    result.timestamps_valid = any_ts && all_ts_ok;
    result.archive_timestamps_valid = arch_ts_state.valid;
    result.timestamp_token_count =
        static_cast<std::size_t>(CountXadesElementsInSubtree(signature_node, "EncapsulatedTimeStamp"));

    // Повнота сертифікатів/відкликань + baseline визначення профілю.
    // Українські Дія.Підпис ASiC-E/XAdES-B-LT контейнери можуть містити
    // baseline LT values без старих XAdES-C Complete*Refs. Тому для B-LT
    // класифікації враховуємо саме CertificateValues + RevocationValues.
    // Legacy XAdES-X-L fixtures may carry refs/values without enough baseline
    // revocation values; keep the enum/profile compatible, but do not report
    // those signatures as baseline B-LT or mark LTV valid.
    // П-13: КЛАСИФІКАЦІЯ профілю — тут пошук за самою локальною назвою не
    // «суворіший», а помилковий: вузол із чужого namespace піднімав би
    // format_profile (B-B -> C/T/X-L/B-LT) і поля LTV-доказів у звіті для 1С.
    const bool has_cert_refs =
        FindFirstXadesElementInSubtree(signature_node, "CompleteCertificateRefs") != nullptr;
    const bool has_rev_refs =
        FindFirstXadesElementInSubtree(signature_node, "CompleteRevocationRefs") != nullptr;
    const bool has_cert_values =
        FindFirstXadesElementInSubtree(signature_node, "CertificateValues") != nullptr;
    const bool has_revocation_values =
        FindFirstXadesElementInSubtree(signature_node, "RevocationValues") != nullptr;
    const bool has_legacy_xl_evidence = has_cert_values || (has_cert_refs && has_rev_refs);
    result.certificate_values_present = has_cert_values;
    result.revocation_values_present = has_revocation_values;
    result.certificate_values_count =
        static_cast<std::size_t>(CountXadesElementsInSubtree(signature_node, "EncapsulatedX509Certificate"));
    result.revocation_values_count =
        static_cast<std::size_t>(CountXadesElementsInSubtree(signature_node, "EncapsulatedOCSPValue")) +
        static_cast<std::size_t>(CountXadesElementsInSubtree(signature_node, "EncapsulatedCRLValue"));
    result.cert_refs_complete = has_cert_refs || has_cert_values;
    result.revocation_refs_complete = has_rev_refs || has_revocation_values;
    result.ltv_data_present = has_cert_values && has_revocation_values;
    result.ltv_valid = result.signature_valid && result.signature_timestamp_valid && result.ltv_data_present;

    // WP-5 (ME-07): вилучаємо DER XAdES CertificateValues/RevocationValues, щоб
    // Session міг передати їх у ValidationEngine (intermediates) і
    // RevocationEngine (embedded OCSP/CRL), а не будувати ланцюг лише з
    // локального intermediate-store.
    if (xmlNodePtr cert_values = FindFirstXadesElementInSubtree(signature_node, "CertificateValues")) {
        CollectBase64Values(cert_values->children, "EncapsulatedX509Certificate", result.certificate_values_der);
    }
    if (xmlNodePtr rev_values = FindFirstXadesElementInSubtree(signature_node, "RevocationValues")) {
        CollectBase64Values(rev_values->children, "EncapsulatedOCSPValue", result.revocation_values_ocsp_der);
        CollectBase64Values(rev_values->children, "EncapsulatedCRLValue", result.revocation_values_crl_der);
    }
    result.revocation_values_der = result.revocation_values_ocsp_der;
    result.revocation_values_der.insert(result.revocation_values_der.end(),
                                        result.revocation_values_crl_der.begin(),
                                        result.revocation_values_crl_der.end());

    // WP-5 (ME-04): digest-binding CompleteCertificateRefs/CompleteRevocationRefs
    // проти CertificateValues/RevocationValues. Дія baseline B-LT цих Complete*Refs
    // не містить (LTV values достатньо саме по собі за ETSI EN 319 132-1) —
    // тоді binding вважається структурно ОК і фактичне підтвердження робить
    // downstream trust/revocation перевірка. Якщо ж refs присутні (legacy
    // XAdES-X-L), кожен ref має бути прив'язаний до відповідного value —
    // інакше це підозра на evidence-підміну.
    bool cert_refs_bound = true;
    if (xmlNodePtr cert_refs = FindFirstXadesElementInSubtree(signature_node, "CompleteCertificateRefs")) {
        std::vector<xmlNodePtr> cert_ref_nodes;
        CollectElementNodes(cert_refs->children, "Cert", cert_ref_nodes);
        if (cert_ref_nodes.empty()) {
            cert_refs_bound = false;
        }
        for (xmlNodePtr cert_ref : cert_ref_nodes) {
            xmlNodePtr digest = FindFirstXadesElement(cert_ref->children, "CertDigest");
            if (!RefDigestMatchesAny(digest, result.certificate_values_der, /*by_certificate=*/true)) {
                cert_refs_bound = false;
                result.notes.push_back("CompleteCertificateRefs: cert ref not bound to CertificateValues digest");
            }
        }
    }

    bool revocation_refs_bound = true;
    if (xmlNodePtr rev_refs = FindFirstXadesElementInSubtree(signature_node, "CompleteRevocationRefs")) {
        std::vector<xmlNodePtr> crl_ref_nodes;
        std::vector<xmlNodePtr> ocsp_ref_nodes;
        CollectElementNodes(rev_refs->children, "CRLRef", crl_ref_nodes);
        CollectElementNodes(rev_refs->children, "OCSPRef", ocsp_ref_nodes);
        if (crl_ref_nodes.empty() && ocsp_ref_nodes.empty()) {
            revocation_refs_bound = false;
        }
        for (xmlNodePtr crl_ref : crl_ref_nodes) {
            xmlNodePtr digest = FindFirstXadesElement(crl_ref->children, "DigestAlgAndValue");
            if (!RefDigestMatchesAny(digest, result.revocation_values_crl_der, /*by_certificate=*/false)) {
                revocation_refs_bound = false;
                result.notes.push_back("CompleteRevocationRefs: CRLRef not bound to RevocationValues digest");
            }
        }
        for (xmlNodePtr ocsp_ref : ocsp_ref_nodes) {
            xmlNodePtr digest = FindFirstXadesElement(ocsp_ref->children, "DigestAlgAndValue");
            if (!RefDigestMatchesAny(digest, result.revocation_values_ocsp_der, /*by_certificate=*/false)) {
                revocation_refs_bound = false;
                result.notes.push_back("CompleteRevocationRefs: OCSPRef not bound to RevocationValues digest");
            }
        }
    }

    result.ltv_evidence_bound = result.ltv_data_present && cert_refs_bound && revocation_refs_bound;

    // HI-04: format_profile/detected_profile="XAdES-A" МАЄ вимагати фактично
    // підтвердженого ArchiveTimeStamp (arch_ts_state.valid), а не лише
    // структурної наявності елемента (arch_ts_state.present). Інакше
    // пошкоджений/чужий ArchiveTimeStamp давав би format_profile="XAdES-A" — і
    // транзитивно, через Session::VerifyXml/VerifyFileAsicEXades,
    // validated_profile="XAdES-A" за наявності самих лише LTV-доказів
    // (validated_profile похідний саме від format_profile, а не від
    // archive_timestamps_valid окремо). Присутній-але-невалідний
    // ArchiveTimeStamp падає на наступний тир драбини (структурний детект за
    // фактично підтвердженим evidence), деталь лишається в result.notes.
    if (arch_ts_state.present && arch_ts_state.valid) {
        result.detected_profile = XadesProfile::A;
        result.format_profile = "XAdES-A";
    } else if (result.ltv_data_present && sig_ts_state.present) {
        result.detected_profile = XadesProfile::X_L;
        result.format_profile = "XAdES-B-LT";
    } else if (has_legacy_xl_evidence && sig_ts_state.present) {
        result.detected_profile = XadesProfile::X_L;
        result.format_profile = "XAdES-X-L";
    } else if (sig_ts_state.present) {
        result.detected_profile = XadesProfile::T;
        result.format_profile = "XAdES-T";
    } else if (has_cert_refs || has_rev_refs) {
        result.detected_profile = XadesProfile::C;
        result.format_profile = "XAdES-C";
    } else {
        result.detected_profile = XadesProfile::BES;
        result.format_profile = "XAdES-B-B";
    }

    return true;
}

}  // namespace

XadesVerifier::XadesVerifier(tamga::xmldsig::XmlSignatureVerifier& xml_sig_verifier,
                             tamga::core::CryptoniteAdapter& crypto,
                             tamga::core::TspClient& tsp)
    : xml_sig_verifier_(xml_sig_verifier), crypto_(crypto), tsp_(tsp) {}

bool XadesVerifier::Verify(const std::string& signed_xml,
                           XadesVerificationResult& result,
                           std::string& error_message) {
    static const std::map<std::string, std::vector<std::uint8_t>> empty_external;
    return Verify(signed_xml, empty_external, result, error_message);
}

bool XadesVerifier::Verify(const std::string& signed_xml,
                           const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                           XadesVerificationResult& result,
                           std::string& error_message) {
    result = XadesVerificationResult{};

    // 1. Криптоперевірка XMLDSIG (покриває і дані, і SignedProperties через
    // окремий ds:Reference).
    tamga::xmldsig::XmlSignatureVerificationResult xml_result;
    if (!xml_sig_verifier_.Verify(signed_xml, external_references, xml_result, error_message)) {
        return false;
    }

    // 2. XAdES-специфіка, прив'язана до єдиного ds:Signature документа (уже
    // гарантовано унікального перевіркою в кроці 1).
    XmlDocPtr doc = ParseHardened(signed_xml, error_message);
    if (!doc) {
        return false;
    }
    xmlNodePtr root = xmlDocGetRootElement(doc.get());
    // П-13: підписом вважається лише елемент у namespace XMLDSIG. Кількість
    // кандидатів (у т.ч. з чужих namespace) уже перевірено в кроці 1 —
    // звуження тут лише не дає ЧУЖОМУ вузлу стати «тим самим підписом».
    xmlNodePtr signature_node = FindFirstDsigElement(root, "Signature");
    if (signature_node == nullptr) {
        error_message = "Не знайдено ds:Signature";
        return false;
    }

    return VerifyOneXadesSignature(doc.get(), signature_node, /*signature_position_1based=*/1, xml_result, result,
                                   error_message);
}

bool XadesVerifier::VerifyAll(const std::string& signed_xml,
                              XadesSignatureSet& result,
                              std::string& error_message) {
    static const std::map<std::string, std::vector<std::uint8_t>> empty_external;
    return VerifyAll(signed_xml, empty_external, result, error_message);
}

bool XadesVerifier::VerifyAll(const std::string& signed_xml,
                              const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                              XadesSignatureSet& result,
                              std::string& error_message) {
    result = XadesSignatureSet{};

    // 1. Криптоперевірка XMLDSIG для КОЖНОГО верхньорівневого ds:Signature —
    // усі анти-wrapping інваріанти (жоден вкладений ds:Signature, рівно один
    // SignedInfo/SignatureValue, не більше одного SignedProperties на підпис,
    // глобальна унікальність same-document Id-фрагментів) вже гарантовані тут.
    std::vector<tamga::xmldsig::XmlSignatureVerificationResult> xml_results;
    if (!xml_sig_verifier_.VerifyAll(signed_xml, external_references, xml_results, error_message)) {
        return false;
    }

    XmlDocPtr doc = ParseHardened(signed_xml, error_message);
    if (!doc) {
        return false;
    }
    xmlNodePtr root = xmlDocGetRootElement(doc.get());

    std::vector<xmlNodePtr> signature_nodes;
    bool nested_found = false;
    CollectTopLevelSignatureNodes(root, signature_nodes, nested_found);
    if (nested_found) {
        error_message = "Вкладений ds:Signature у межах іншого ds:Signature (захист від wrapping)";
        return false;
    }
    if (signature_nodes.size() != xml_results.size()) {
        error_message = "Невідповідність кількості ds:Signature між XMLDSIG- і XAdES-парсингом документа";
        return false;
    }
    if (signature_nodes.empty()) {
        // Захист від "vacuous truth": без цієї перевірки порожній вектор
        // означав би, що цикл нижче жодного разу не виконається, і
        // all_valid (ініціалізоване як true) лишиться true — тобто
        // документ БЕЗ жодного підпису був би визнаний "усі підписи дійсні".
        error_message = "Не знайдено ds:Signature";
        return false;
    }

    bool all_valid = true;
    for (std::size_t i = 0; i < signature_nodes.size(); ++i) {
        XadesVerificationResult one;
        if (!VerifyOneXadesSignature(doc.get(), signature_nodes[i], static_cast<int>(i) + 1, xml_results[i], one,
                                     error_message)) {
            return false;
        }
        all_valid = all_valid && one.signature_valid;
        result.signatures.push_back(std::move(one));
    }
    result.all_valid = all_valid;
    result.aggregation = XadesSignatureSet::Aggregation::All;
    return true;
}

}  // namespace tamga::xades

#endif  // TAMGA_XML_SIGNATURES_ENABLED
