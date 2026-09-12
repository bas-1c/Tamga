#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "xades/XadesTypes.h"
#include "xmldsig/XmlSignatureVerifier.h"

namespace tamga::core {
class CryptoniteAdapter;
class TspClient;
}  // namespace tamga::core

namespace tamga::xades {

// Результат верифікації XAdES-підпису з розбивкою за рівнями профілю.
struct XadesVerificationResult {
    XadesProfile detected_profile{XadesProfile::BES};
    std::string format_profile{"XAdES-BES"};
    bool signature_valid{false};           // XMLDSIG-підпис + усі дайджести
    bool qualifying_properties_present{false};
    bool signing_certificate_digest_valid{false};  // SigningCertificate/CertDigest
    bool timestamps_valid{false};          // T/X/A
    bool signature_timestamp_present{false};
    bool signature_timestamp_checked{false};
    bool signature_timestamp_valid{false};
    bool tsp_checked{false};
    bool cert_refs_complete{false};        // C/X/X-L/A або baseline LT values
    bool revocation_refs_complete{false};  // C/X/X-L/A або baseline LT values
    bool certificate_values_present{false};
    bool revocation_values_present{false};
    bool ltv_data_present{false};
    bool ltv_valid{false};
    bool archive_timestamps_valid{false};  // A
    std::size_t timestamp_token_count{0};
    std::size_t certificate_values_count{0};
    std::size_t revocation_values_count{0};
    std::string signing_time;              // SignedProperties/SigningTime
    std::vector<std::uint8_t> signer_certificate_der;  // з KeyInfo/X509Certificate
    std::vector<std::uint8_t> signature_timestamp_token_der;  // XAdES EncapsulatedTimeStamp DER
    std::vector<std::uint8_t> signature_timestamp_canonicalized_data;  // C14N ds:SignatureValue octets
    tamga::xmldsig::XmlSignatureVerificationResult xml_signature;
    std::vector<std::string> notes;

    // --- WP-0 заморожені поля (для WP-2/WP-5/WP-11) ---
    // Вилучені XAdES CertificateValues/RevocationValues (DER) для побудови
    // ланцюга та перевірки відкликання з embedded-доказів (WP-5/ME-07).
    std::vector<std::vector<std::uint8_t>> certificate_values_der;
    std::vector<std::vector<std::uint8_t>> revocation_values_der;  // OCSP+CRL, об'єднано (діагностика)
    // WP-5: типізований розподіл RevocationValues — окремо OCSP і CRL, бо
    // ValidationEngine/RevocationEngine приймають їх різними шляхами.
    std::vector<std::vector<std::uint8_t>> revocation_values_ocsp_der;
    std::vector<std::vector<std::uint8_t>> revocation_values_crl_der;
    // Структурний детект профілю (`format_profile`) проти ПІДТВЕРДЖЕНОГО
    // binding-ом профілю: `validated_profile` виставляється лише після
    // evidence-binding (WP-5/ME-04). Порожній -> ще не підтверджено.
    std::string validated_profile;
    // WP-5: чи прив'язані XAdES-докази (CertificateValues/RevocationValues) —
    // структурна перевірка digest-binding CompleteCertificateRefs/
    // CompleteRevocationRefs проти значень, коли refs присутні (legacy X-L).
    // Для baseline B-LT (без Complete*Refs) достатньо самої наявності values;
    // фактичне підтвердження довіри/відкликання відбувається downstream у
    // RunFormatTrustValidationOn (SessionStateAndNormalization.ipp).
    bool ltv_evidence_bound{false};

    // --- WP-12: SignaturePolicyIdentifier / SignedDataObjectProperties ---
    // Структурний парсинг ETSI EN 319 132-1 §5.2.1.3/§5.2.2 — НЕ включає
    // криптографічну перевірку signature_policy_hash проти реального
    // зовнішнього документа політики підпису (Tamga не має доступу до
    // реєстру політик); лише експонує присутні дані для звіту/аудиту.
    bool signature_policy_present{false};
    std::string signature_policy_id;               // SigPolicyId/Identifier
    std::string signature_policy_hash_algo_uri;     // SigPolicyHash/DigestMethod/@Algorithm
    std::vector<std::uint8_t> signature_policy_hash_value;  // SigPolicyHash/DigestValue (decoded)
    std::vector<DataObjectFormat> data_object_formats;  // SignedDataObjectProperties/DataObjectFormat*
};

// WP-0 (заморожений контракт) — для WP-2/WP-11.
// Результат верифікації КОНТЕЙНЕРА з кількома ds:Signature: по одному
// XadesVerificationResult на підпис + агрегований verdict. `all_valid` —
// кон'юнкція integrity усіх підписів (стратегія за замовчуванням All).
struct XadesSignatureSet {
    enum class Aggregation { All, Any };
    std::vector<XadesVerificationResult> signatures;
    bool all_valid{false};
    Aggregation aggregation{Aggregation::All};
};

// Верифікатор XAdES-підписів: делегує криптоперевірку XMLDSIG до
// XmlSignatureVerifier (SignedProperties покрито власним ds:Reference) і додає
// XAdES-перевірки (наявність QualifyingProperties, відповідність CertDigest).
// Реалізація доступна лише у збірці з TAMGA_ENABLE_XML_SIGNATURES.
class XadesVerifier {
public:
    XadesVerifier(tamga::xmldsig::XmlSignatureVerifier& xml_sig_verifier,
                  tamga::core::CryptoniteAdapter& crypto,
                  tamga::core::TspClient& tsp);

    bool Verify(const std::string& signed_xml,
                XadesVerificationResult& result,
                std::string& error_message);

    bool Verify(const std::string& signed_xml,
                const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                XadesVerificationResult& result,
                std::string& error_message);

    // WP-2 (продовження): кілька ds:Signature в ОДНОМУ XAdES-документі.
    // Делегує структурну/крипто-перевірку кожного підпису до
    // XmlSignatureVerifier::VerifyAll (яка вже гарантує анти-wrapping
    // інваріанти — жоден вкладений ds:Signature, рівно один SignedInfo/
    // SignatureValue і не більше одного SignedProperties на підпис), потім
    // додає XAdES-специфіку (SigningCertificate/CertDigest, часові мітки,
    // CertificateValues/RevocationValues, детект профілю) ОКРЕМО для
    // кожного підпису, прив'язану до саме його ds:Signature-піддерева —
    // жоден XAdES-пошук не виходить за межі свого підпису. Повертає false +
    // error_message лише при структурній помилці (успадкованій від
    // VerifyAll або невідповідності кількості підписів); інакше
    // result.signatures матиме по одному запису на кожен ds:Signature в
    // порядку документа.
    bool VerifyAll(const std::string& signed_xml,
                   XadesSignatureSet& result,
                   std::string& error_message);

    bool VerifyAll(const std::string& signed_xml,
                   const std::map<std::string, std::vector<std::uint8_t>>& external_references,
                   XadesSignatureSet& result,
                   std::string& error_message);

private:
    tamga::xmldsig::XmlSignatureVerifier& xml_sig_verifier_;
    tamga::core::CryptoniteAdapter& crypto_;
    tamga::core::TspClient& tsp_;
};

}  // namespace tamga::xades
