#include "xades/XadesBuilder.h"
#include "xmldsig/XmlHelpers.h"

#if defined(TAMGA_XML_SIGNATURES_ENABLED)

#include <ctime>
#include <string>
#include <vector>

#include "core/CryptoniteAdapter.h"
#include "core/policy/ImprintDigest.h"
#include "util/Base64.h"
#include "xades/detail/XadesArchiveImprint.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/XmlTransformEngine.h"
#include "xmldsig/detail/XmlDocUtil.h"

namespace tamga::xades {

// ADR-027: хелпери libxml2 і URI живуть у `xmldsig/XmlHelpers` — тут були
// їх копії. Тіла збігалися, тож поведінка не змінюється.
using tamga::xmldsig::AddChild;
using tamga::xmldsig::AddTextChild;
using tamga::xmldsig::C14nMethodToUri;
using tamga::xmldsig::SetAttr;

namespace {

using namespace tamga::xmldsig::detail;

constexpr const char* kEtsiNs = "http://uri.etsi.org/01903/v1.3.2#";
constexpr const char* kSignedPropsType = "http://uri.etsi.org/01903#SignedProperties";





std::string CurrentIso8601Utc() {
    std::time_t now = std::time(nullptr);
    std::tm tm_utc{};
#if defined(_WIN32)
    gmtime_s(&tm_utc, &now);
#else
    gmtime_r(&now, &tm_utc);
#endif
    char buffer[32] = {0};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    return std::string(buffer);
}

// Перетворює hex-рядок серійного номера у десятковий (X509SerialNumber).
std::string HexToDecimal(const std::string& hex) {
    std::vector<int> digits;  // десяткові цифри, молодші першими
    digits.push_back(0);
    for (char c : hex) {
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;
        int carry = v;
        for (std::size_t i = 0; i < digits.size(); ++i) {
            const int prod = digits[i] * 16 + carry;
            digits[i] = prod % 10;
            carry = prod / 10;
        }
        while (carry > 0) {
            digits.push_back(carry % 10);
            carry /= 10;
        }
    }
    std::string out;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        out.push_back(static_cast<char>('0' + *it));
    }
    return out.empty() ? "0" : out;
}

// Додає xades:Cert (CertDigest + IssuerSerial) під parent — для
// CompleteCertificateRefs та SigningCertificate.
bool AddCertRef(xmlNodePtr parent, xmlNsPtr ns_xades, xmlNsPtr ns_ds,
                const std::vector<std::uint8_t>& cert_der, const std::string& digest_uri,
                std::string& error) {
    tamga::xmldsig::XmlDigestEngine digest_engine;
    std::vector<std::uint8_t> digest;
    if (!digest_engine.ComputeDigest(cert_der, digest_uri, digest, error)) {
        return false;
    }
    xmlNodePtr cert = AddChild(parent, ns_xades, "Cert");
    xmlNodePtr cert_digest = AddChild(cert, ns_xades, "CertDigest");
    xmlNodePtr dm = AddChild(cert_digest, ns_ds, "DigestMethod");
    SetAttr(dm, "Algorithm", digest_uri);
    AddTextChild(cert_digest, ns_ds, "DigestValue", tamga::util::Base64Encode(digest));
    tamga::core::CertificateMetadata meta;
    std::string meta_error;
    if (tamga::core::CryptoniteAdapter::ExtractCertificateMetadata(cert_der, meta, meta_error)) {
        xmlNodePtr issuer_serial = AddChild(cert, ns_xades, "IssuerSerial");
        AddTextChild(issuer_serial, ns_ds, "X509IssuerName", meta.issuer);
        AddTextChild(issuer_serial, ns_ds, "X509SerialNumber", HexToDecimal(meta.serial_number_hex));
    }
    return true;
}

// Додає DigestAlgAndValue (для CRLRef/OCSPRef).
bool AddDigestAlgAndValue(xmlNodePtr parent, xmlNsPtr ns_xades, xmlNsPtr ns_ds,
                          const std::vector<std::uint8_t>& data, const std::string& digest_uri,
                          std::string& error) {
    tamga::xmldsig::XmlDigestEngine digest_engine;
    std::vector<std::uint8_t> digest;
    if (!digest_engine.ComputeDigest(data, digest_uri, digest, error)) {
        return false;
    }
    xmlNodePtr dav = AddChild(parent, ns_xades, "DigestAlgAndValue");
    xmlNodePtr dm = AddChild(dav, ns_ds, "DigestMethod");
    SetAttr(dm, "Algorithm", digest_uri);
    AddTextChild(dav, ns_ds, "DigestValue", tamga::util::Base64Encode(digest));
    return true;
}

}  // namespace

XadesBuilder::XadesBuilder(tamga::core::CryptoniteAdapter& crypto, tamga::core::TspClient& tsp)
    : crypto_(crypto), tsp_(tsp) {}

bool XadesBuilder::Sign(const std::string& xml,
                        const XadesParameters& params,
                        const tamga::core::SigningKey& signing_key,
                        std::string& signed_xml_out,
                        std::string& error_message) {
    if (params.xml_params.references.empty()) {
        error_message = "XAdES-підпис потребує хоча б одне посилання на дані";
        return false;
    }

    // Сертифікат підписувача (для KeyInfo та SigningCertificate).
    std::vector<std::uint8_t> cert_der = signing_key.certificate_der;
    if (cert_der.empty()) {
        std::string e;
        if (!tamga::core::CryptoniteAdapter::ExtractSignerCertificate(
                signing_key.use_pkcs12, signing_key.key_material, signing_key.certificate_der,
                signing_key.password, cert_der, e)) {
            error_message = "Не вдалося отримати сертифікат підписувача: " + e;
            return false;
        }
    }

    const std::string sig_id = params.xml_params.signature_id.empty()
                                   ? std::string("tamga-signature")
                                   : params.xml_params.signature_id;
    const std::string signed_props_id = params.signed_properties_id.empty()
                                            ? sig_id + "-signedprops"
                                            : params.signed_properties_id;
    // XAdES-властивості й часові мітки канонікалізуємо тим самим методом,
    // який викликач задав для SignedInfo. Це не дозволяє XML оголосити один
    // Algorithm, а фактично штампувати іншим методом.
    const std::string xades_c14n_uri = C14nMethodToUri(params.xml_params.c14n_method);

    // 1. Будуємо дерево підпису.
    XmlDocPtr doc = ParseHardened(xml, error_message);
    if (!doc) {
        return false;
    }
    xmlNodePtr root = xmlDocGetRootElement(doc.get());
    if (root == nullptr) {
        error_message = "Порожній XML-документ";
        return false;
    }

    xmlNodePtr sig = xmlNewNode(nullptr, reinterpret_cast<const xmlChar*>("Signature"));
    xmlNsPtr ns_ds = xmlNewNs(sig, reinterpret_cast<const xmlChar*>(DsigNamespace()),
                              reinterpret_cast<const xmlChar*>("ds"));
    xmlSetNs(sig, ns_ds);
    xmlAddChild(root, sig);
    SetAttr(sig, "Id", sig_id);

    xmlNodePtr signed_info = AddChild(sig, ns_ds, "SignedInfo");
    xmlNodePtr c14n_method = AddChild(signed_info, ns_ds, "CanonicalizationMethod");
    SetAttr(c14n_method, "Algorithm", C14nMethodToUri(params.xml_params.c14n_method));
    xmlNodePtr sig_method = AddChild(signed_info, ns_ds, "SignatureMethod");
    SetAttr(sig_method, "Algorithm", params.xml_params.signature_method_uri);

    // Посилання на дані (наприклад, enveloped).
    std::vector<xmlNodePtr> data_digest_nodes;
    for (const auto& ref : params.xml_params.references) {
        xmlNodePtr reference = AddChild(signed_info, ns_ds, "Reference");
        if (!ref.id.empty()) {
            SetAttr(reference, "Id", ref.id);
        }
        // Еталонні XAdES-контейнери Дії фізично містять порожній Type для
        // посилань на об'єкти даних. Окремий прапорець зберігає історичну
        // поведінку generic XAdES, де порожній Type означає відсутній атрибут.
        if (ref.emit_type_attribute || !ref.type.empty()) {
            SetAttr(reference, "Type", ref.type);
        }
        SetAttr(reference, "URI", ref.uri);
        if (!ref.transforms.empty()) {
            xmlNodePtr transforms = AddChild(reference, ns_ds, "Transforms");
            for (const auto& t : ref.transforms) {
                xmlNodePtr tn = AddChild(transforms, ns_ds, "Transform");
                SetAttr(tn, "Algorithm", t);
            }
        }
        xmlNodePtr dm = AddChild(reference, ns_ds, "DigestMethod");
        SetAttr(dm, "Algorithm", ref.digest_method);
        data_digest_nodes.push_back(AddTextChild(reference, ns_ds, "DigestValue", ""));
    }

    // Посилання на SignedProperties.
    xmlNodePtr sp_reference = AddChild(signed_info, ns_ds, "Reference");
    SetAttr(sp_reference, "Type", kSignedPropsType);
    SetAttr(sp_reference, "URI", "#" + signed_props_id);
    xmlNodePtr sp_transforms = AddChild(sp_reference, ns_ds, "Transforms");
    xmlNodePtr sp_transform = AddChild(sp_transforms, ns_ds, "Transform");
    SetAttr(sp_transform, "Algorithm", xades_c14n_uri);
    xmlNodePtr sp_dm = AddChild(sp_reference, ns_ds, "DigestMethod");
    SetAttr(sp_dm, "Algorithm", params.signed_properties_digest_uri);
    xmlNodePtr sp_digest_node = AddTextChild(sp_reference, ns_ds, "DigestValue", "");

    xmlNodePtr signature_value = AddChild(sig, ns_ds, "SignatureValue");

    // KeyInfo з сертифікатом підписувача.
    xmlNodePtr key_info = AddChild(sig, ns_ds, "KeyInfo");
    xmlNodePtr x509_data = AddChild(key_info, ns_ds, "X509Data");
    AddTextChild(x509_data, ns_ds, "X509Certificate", tamga::util::Base64Encode(cert_der));

    // ds:Object / xades:QualifyingProperties / xades:SignedProperties.
    xmlNodePtr object = AddChild(sig, ns_ds, "Object");
    xmlNodePtr qualifying = xmlNewChild(object, nullptr,
                                        reinterpret_cast<const xmlChar*>("QualifyingProperties"), nullptr);
    xmlNsPtr ns_xades = xmlNewNs(qualifying, reinterpret_cast<const xmlChar*>(kEtsiNs),
                                 reinterpret_cast<const xmlChar*>("xades"));
    xmlSetNs(qualifying, ns_xades);
    SetAttr(qualifying, "Target", "#" + sig_id);

    xmlNodePtr signed_props = AddChild(qualifying, ns_xades, "SignedProperties");
    SetAttr(signed_props, "Id", signed_props_id);
    xmlNodePtr ssp = AddChild(signed_props, ns_xades, "SignedSignatureProperties");

    const std::string signing_time = params.qualifying_properties.signed_props.signing_time.empty()
                                         ? CurrentIso8601Utc()
                                         : params.qualifying_properties.signed_props.signing_time;
    AddTextChild(ssp, ns_xades, "SigningTime", signing_time);

    // SigningCertificateV2 / Cert / CertDigest. Сучасний baseline-профіль і
    // контейнери Дії використовують V2; застарілий SigningCertificate був
    // прив'язаний до SHA-1 і змушував зовнішні системи відхиляти ГОСТ-профіль.
    {
        tamga::xmldsig::XmlDigestEngine digest_engine;
        const auto cert_alg = tamga::xmldsig::XmlDigestEngine::MapDigestUri(params.cert_digest_uri);
        std::vector<std::uint8_t> cert_digest;
        std::string e;
        if (!cert_alg || !digest_engine.ComputeDigestByCertificate(cert_der, params.cert_digest_uri, cert_der, cert_digest, e)) {
            error_message = "Не вдалося обчислити CertDigest: " + e;
            return false;
        }

        xmlNodePtr signing_cert = AddChild(ssp, ns_xades, "SigningCertificateV2");
        xmlNodePtr cert_node = AddChild(signing_cert, ns_xades, "Cert");
        xmlNodePtr cert_digest_node = AddChild(cert_node, ns_xades, "CertDigest");
        xmlNodePtr cd_method = AddChild(cert_digest_node, ns_ds, "DigestMethod");
        SetAttr(cd_method, "Algorithm", params.cert_digest_uri);
        AddTextChild(cert_digest_node, ns_ds, "DigestValue", tamga::util::Base64Encode(cert_digest));

    }

    // WP-12: SignaturePolicyIdentifier (ETSI EN 319 132-1 §5.2.1.3) — опційна
    // підписана властивість, що ідентифікує політику підпису через
    // SigPolicyId/Identifier і хеш документа політики (SigPolicyHash). Tamga
    // НЕ верифікує SigPolicyHash проти реального зовнішнього документа
    // політики (немає доступу до реєстру політик підпису) — лише генерує
    // елемент за переданими params; структурний парсинг/експонування у звіт
    // виконує верифікатор.
    if (const auto& policy = params.qualifying_properties.signed_props.signature_policy; policy.has_value()) {
        xmlNodePtr policy_identifier = AddChild(ssp, ns_xades, "SignaturePolicyIdentifier");
        xmlNodePtr signature_policy_id = AddChild(policy_identifier, ns_xades, "SignaturePolicyId");
        xmlNodePtr sig_policy_id = AddChild(signature_policy_id, ns_xades, "SigPolicyId");
        AddTextChild(sig_policy_id, ns_xades, "Identifier", policy->policy_id);
        xmlNodePtr sig_policy_hash = AddChild(signature_policy_id, ns_xades, "SigPolicyHash");
        xmlNodePtr sph_method = AddChild(sig_policy_hash, ns_ds, "DigestMethod");
        SetAttr(sph_method, "Algorithm", policy->policy_hash_algo_uri);
        AddTextChild(sig_policy_hash, ns_ds, "DigestValue", tamga::util::Base64Encode(policy->policy_hash_value));
    }

    // WP-12: SignedDataObjectProperties/DataObjectFormat (ETSI EN 319 132-1
    // §5.2.2) — опційний опис формату/MIME-типу кожного підписаного обʼєкта
    // даних, прив'язаний до конкретного ds:Reference через атрибут
    // ObjectReference (значення — відповідальність викликача, зазвичай
    // "#" + Id відповідного ds:Reference).
    if (!params.qualifying_properties.signed_props.data_object_formats.empty()) {
        xmlNodePtr sdop = AddChild(signed_props, ns_xades, "SignedDataObjectProperties");
        for (const auto& dof : params.qualifying_properties.signed_props.data_object_formats) {
            xmlNodePtr dof_node = AddChild(sdop, ns_xades, "DataObjectFormat");
            SetAttr(dof_node, "ObjectReference", dof.object_reference);
            if (!dof.description.empty()) {
                AddTextChild(dof_node, ns_xades, "Description", dof.description);
            }
            if (!dof.mime_type.empty()) {
                AddTextChild(dof_node, ns_xades, "MimeType", dof.mime_type);
            }
        }
    }

    // 2. Обчислюємо дайджести посилань по серіалізованому знімку (тим самим
    // шляхом, що й верифікатор: ResolveReference + ApplyTransforms).
    const std::string snapshot = SerializeNode(doc.get(), root);
    tamga::xmldsig::XmlReferenceResolver resolver;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;

    for (std::size_t i = 0; i < params.xml_params.references.size(); ++i) {
        const auto& ref = params.xml_params.references[i];
        std::vector<std::uint8_t> bytes;
        const auto external = params.xml_params.external_data.find(ref.uri);
        if (external != params.xml_params.external_data.end()) {
            // Зовнішній об'єкт даних (файл у контейнері ASiC): дайджест
            // рахується з сирих байтів. Резолвити його в документі підпису
            // нічим — його там немає, тож трансформації тут не застосовні.
            if (!ref.transforms.empty()) {
                error_message = "Посилання на зовнішній об'єкт даних не підтримує ds:Transforms: " + ref.uri;
                return false;
            }
            bytes = external->second;
        } else {
            std::string resolved;
            if (!resolver.ResolveReference(snapshot, ref, resolved, error_message)) return false;
            std::string octets;
            if (!transform_engine.ApplyTransforms(resolved, ref, octets, error_message)) return false;
            bytes.assign(octets.begin(), octets.end());
        }
        std::vector<std::uint8_t> digest;
        if (!digest_engine.ComputeDigestByCertificate(bytes, ref.digest_method, cert_der, digest, error_message)) return false;
        const std::string b64 = tamga::util::Base64Encode(digest);
        xmlNodeSetContent(data_digest_nodes[i], reinterpret_cast<const xmlChar*>(b64.c_str()));
    }

    // SignedProperties reference digest: канонікалізуємо елемент прямо в
    // оригінальному `doc` (XPath node-set за Id), а не через серіалізацію
    // знімку й перепарсинг — інакше намespace-декларації, успадковані від
    // QualifyingProperties (xmlns:xades) та Signature (xmlns:ds), губляться.
    {
        int sp_mode = 0;
        int sp_comments = 0;
        C14nUriToMode(xades_c14n_uri, sp_mode, sp_comments);
        std::string octets;
        if (!CanonicalizeSubtreeById(doc.get(), signed_props_id, sp_mode, sp_comments,
                                     octets, error_message)) {
            return false;
        }
        std::vector<std::uint8_t> bytes(octets.begin(), octets.end());
        std::vector<std::uint8_t> digest;
        if (!digest_engine.ComputeDigestByCertificate(bytes, params.signed_properties_digest_uri, cert_der, digest, error_message)) {
            return false;
        }
        const std::string b64 = tamga::util::Base64Encode(digest);
        xmlNodeSetContent(sp_digest_node, reinterpret_cast<const xmlChar*>(b64.c_str()));
    }

    // 3. Канонікалізуємо SignedInfo (із заповненими DigestValue) і підписуємо.
    int mode = 0;
    int comments = 0;
    C14nUriToMode(C14nMethodToUri(params.xml_params.c14n_method), mode, comments);
    std::string signed_info_octets;
    if (!CanonicalizeSubtreeByLocalName(doc.get(), "SignedInfo", mode, comments,
                                        signed_info_octets, error_message)) {
        return false;
    }

    const auto si_alg = tamga::xmldsig::XmlDigestEngine::MapSignatureMethodUri(
        params.xml_params.signature_method_uri);
    if (!si_alg) {
        error_message = "Непідтримуваний SignatureMethod URI: " + params.xml_params.signature_method_uri;
        return false;
    }
    tamga::core::ImprintResult imprint;
    const std::vector<std::uint8_t> si_bytes(signed_info_octets.begin(), signed_info_octets.end());
    // Симетрія з верифікатором (XmlSignatureVerifier): ГОСТ 34.311
    // ПАРАМЕТРИЗОВАНИЙ — sbox/sync беруться з AlgorithmIdentifier сертифіката.
    // Будівник рахував усі дайджести типовими параметрами, а верифікатор —
    // параметрами сертифіката, тож для сертифікатів із власним DKE не збігався
    // ЖОДЕН дайджест (посилання, SignedProperties, CertDigest) і підпис виходив
    // невалідним уже за власною перевіркою. Виявлено 2026-09-03 на ключі
    // ЦСК Україна (.ZS2).
    if (!tamga::core::ComputeImprintByCertificate(cert_der, *si_alg, si_bytes, imprint, error_message)) {
        return false;
    }

    std::vector<std::uint8_t> signature;
    if (!tamga::core::CryptoniteAdapter::SignHash(signing_key.use_pkcs12, signing_key.key_material,
                                                  signing_key.certificate_der, signing_key.password,
                                                  imprint.hash, signature, error_message)) {
        return false;
    }
    const std::string sig_b64 = tamga::util::Base64Encode(signature);
    xmlNodeSetContent(signature_value, reinterpret_cast<const xmlChar*>(sig_b64.c_str()));

    // 4. Непідписані властивості за профілем (T -> C -> X-L).
    if (params.profile != XadesProfile::BES) {
        const int level = static_cast<int>(params.profile);
        xmlNodePtr unsigned_props = AddChild(qualifying, ns_xades, "UnsignedProperties");
        xmlNodePtr usp = AddChild(unsigned_props, ns_xades, "UnsignedSignatureProperties");

        // T: SignatureTimeStamp над C14N(ds:SignatureValue).
        if (level >= static_cast<int>(XadesProfile::T)) {
            if (!params.timestamp_provider) {
                error_message = "Профіль XAdES-T+ потребує timestamp_provider";
                return false;
            }
            std::string sv_c14n;
            int ts_mode = XML_C14N_1_0;
            int ts_comments = 0;
            C14nUriToMode(xades_c14n_uri, ts_mode, ts_comments);
            if (!CanonicalizeSubtreeByLocalName(doc.get(), "SignatureValue", ts_mode, ts_comments,
                                                sv_c14n, error_message)) {
                return false;
            }
            std::vector<std::uint8_t> token;
            const std::vector<std::uint8_t> tbs(sv_c14n.begin(), sv_c14n.end());
            if (!params.timestamp_provider(tbs, token, error_message)) {
                return false;
            }
            xmlNodePtr sig_ts = AddChild(usp, ns_xades, "SignatureTimeStamp");
            SetAttr(sig_ts, "Id", sig_id + "-timestamp");
            xmlNodePtr ts_c14n = AddChild(sig_ts, ns_ds, "CanonicalizationMethod");
            SetAttr(ts_c14n, "Algorithm", xades_c14n_uri);
            xmlNodePtr encapsulated = AddTextChild(
                sig_ts, ns_xades, "EncapsulatedTimeStamp", tamga::util::Base64Encode(token));
            SetAttr(encapsulated, "Id", sig_id + "-timestamp-token");
        }

        // C: CompleteCertificateRefs (+ CompleteRevocationRefs за наявності даних).
        if (level >= static_cast<int>(XadesProfile::C)) {
            if (!params.certificate_chain.empty()) {
                xmlNodePtr cc_refs = AddChild(usp, ns_xades, "CompleteCertificateRefs");
                xmlNodePtr cert_refs = AddChild(cc_refs, ns_xades, "CertRefs");
                for (const auto& ca : params.certificate_chain) {
                    if (!AddCertRef(cert_refs, ns_xades, ns_ds, ca, params.cert_refs_digest_uri, error_message)) {
                        return false;
                    }
                }
            }
            if (!params.crls.empty() || !params.ocsp_responses.empty()) {
                xmlNodePtr cr_refs = AddChild(usp, ns_xades, "CompleteRevocationRefs");
                if (!params.crls.empty()) {
                    xmlNodePtr crl_refs = AddChild(cr_refs, ns_xades, "CRLRefs");
                    for (const auto& crl : params.crls) {
                        xmlNodePtr crl_ref = AddChild(crl_refs, ns_xades, "CRLRef");
                        if (!AddDigestAlgAndValue(crl_ref, ns_xades, ns_ds, crl, params.cert_refs_digest_uri, error_message)) {
                            return false;
                        }
                    }
                }
                if (!params.ocsp_responses.empty()) {
                    xmlNodePtr ocsp_refs = AddChild(cr_refs, ns_xades, "OCSPRefs");
                    for (const auto& ocsp : params.ocsp_responses) {
                        xmlNodePtr ocsp_ref = AddChild(ocsp_refs, ns_xades, "OCSPRef");
                        if (!AddDigestAlgAndValue(ocsp_ref, ns_xades, ns_ds, ocsp, params.cert_refs_digest_uri, error_message)) {
                            return false;
                        }
                    }
                }
            }
        }

        // X: SigAndRefsTimeStamp над C14N(SignatureValue + SignatureTimeStamp +
        // CompleteCertificateRefs + CompleteRevocationRefs).
        if (level >= static_cast<int>(XadesProfile::X)) {
            std::string tbs_str;
            int timestamp_mode = XML_C14N_1_0;
            int timestamp_comments = 0;
            C14nUriToMode(xades_c14n_uri, timestamp_mode, timestamp_comments);
            if (!ConcatCanonical(doc.get(),
                                 {"SignatureValue", "SignatureTimeStamp",
                                  "CompleteCertificateRefs", "CompleteRevocationRefs"},
                                 timestamp_mode, timestamp_comments, tbs_str, error_message)) {
                return false;
            }
            std::vector<std::uint8_t> token;
            const std::vector<std::uint8_t> tbs(tbs_str.begin(), tbs_str.end());
            if (!params.timestamp_provider(tbs, token, error_message)) {
                return false;
            }
            xmlNodePtr sar_ts = AddChild(usp, ns_xades, "SigAndRefsTimeStamp");
            xmlNodePtr c14n = AddChild(sar_ts, ns_ds, "CanonicalizationMethod");
            SetAttr(c14n, "Algorithm", xades_c14n_uri);
            AddTextChild(sar_ts, ns_xades, "EncapsulatedTimeStamp", tamga::util::Base64Encode(token));
        }

        // X-L: CertificateValues (+ RevocationValues за наявності даних).
        if (level >= static_cast<int>(XadesProfile::X_L)) {
            if (!params.certificate_chain.empty()) {
                xmlNodePtr cert_values = AddChild(usp, ns_xades, "CertificateValues");
                for (const auto& ca : params.certificate_chain) {
                    AddTextChild(cert_values, ns_xades, "EncapsulatedX509Certificate", tamga::util::Base64Encode(ca));
                }
            }
            if (!params.crls.empty() || !params.ocsp_responses.empty()) {
                xmlNodePtr rev_values = AddChild(usp, ns_xades, "RevocationValues");
                if (!params.crls.empty()) {
                    xmlNodePtr crl_values = AddChild(rev_values, ns_xades, "CRLValues");
                    for (const auto& crl : params.crls) {
                        AddTextChild(crl_values, ns_xades, "EncapsulatedCRLValue", tamga::util::Base64Encode(crl));
                    }
                }
                if (!params.ocsp_responses.empty()) {
                    xmlNodePtr ocsp_values = AddChild(rev_values, ns_xades, "OCSPValues");
                    for (const auto& ocsp : params.ocsp_responses) {
                        AddTextChild(ocsp_values, ns_xades, "EncapsulatedOCSPValue", tamga::util::Base64Encode(ocsp));
                    }
                }
            }
        }
        // A: ArchiveTimeStamp — message imprint за ETSI EN 319 132-1 §5.5.2.3
        // (not-distributed case): результати ds:Reference + SignedInfo/
        // SignatureValue/KeyInfo + unsigned properties, наявні на цей момент,
        // + ds:Object окрім QualifyingProperties (спільно з XadesVerifier, див.
        // xades/detail/XadesArchiveImprint.h).
        if (level >= static_cast<int>(XadesProfile::A)) {
            const std::string archive_snapshot = SerializeNode(doc.get(), root);
            std::string tbs_str;
            int archive_mode = XML_C14N_1_0;
            int archive_comments = 0;
            C14nUriToMode(xades_c14n_uri, archive_mode, archive_comments);
            if (!tamga::xades::detail::BuildArchiveTimeStampImprintInput(
                    doc.get(), archive_snapshot, /*signature_position_1based=*/1, sig,
                    {"SignatureTimeStamp", "CompleteCertificateRefs", "CompleteRevocationRefs",
                     "SigAndRefsTimeStamp", "CertificateValues", "RevocationValues"},
                    archive_mode, archive_comments, tbs_str, error_message)) {
                return false;
            }
            std::vector<std::uint8_t> token;
            const std::vector<std::uint8_t> tbs(tbs_str.begin(), tbs_str.end());
            if (!params.timestamp_provider(tbs, token, error_message)) {
                return false;
            }
            xmlNodePtr arch_ts = AddChild(usp, ns_xades, "ArchiveTimeStamp");
            xmlNodePtr c14n = AddChild(arch_ts, ns_ds, "CanonicalizationMethod");
            SetAttr(c14n, "Algorithm", xades_c14n_uri);
            AddTextChild(arch_ts, ns_xades, "EncapsulatedTimeStamp", tamga::util::Base64Encode(token));
        }
    }

    signed_xml_out = SerializeNode(doc.get(), root);
    if (signed_xml_out.empty()) {
        error_message = "Не вдалося серіалізувати XAdES-документ";
        return false;
    }
    return true;
}

}  // namespace tamga::xades

#endif  // TAMGA_XML_SIGNATURES_ENABLED
