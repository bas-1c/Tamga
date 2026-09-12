// Читання сертифікатів як даних: розпізнавання DER, розбір PKCS#7-набору,
// витягання метаданих (суб'єкт, видавець, ЄДРПОУ/ДРФО, серійний номер).
//
// Виділено з CryptoniteAdapter.cpp (O-01).

#include "core/cryptonite/CertUtil.h"
#include "core/cryptonite/Internal.h"
#include "core/cryptonite/Names.h"

namespace tamga::core {

// Внутрішні помічники реалізації видимі без кваліфікації: код перенесено з
// CryptoniteAdapter.cpp без єдиної правки тіл функцій, тому директива тут
// свідома — вона обмежена цим TU і не впливає на публічний контракт.
using namespace cryptonite_detail;

bool CryptoniteAdapter::IsCertificateDer(const std::vector<std::uint8_t>& candidate_der) {
#if TAMGA_CRYPTONITE_ENABLED
    if (candidate_der.size() < 64 || candidate_der.front() != 0x30) {
        return false;
    }
    ScopedByteArray input(MakeByteArray(candidate_der), ba_free);
    if (input == nullptr) {
        return false;
    }
    ScopedCert cert(cert_alloc(), cert_free);
    return cert != nullptr && cert_decode(cert.get(), input.get()) == RET_OK;
#else
    (void)candidate_der;
    return false;
#endif
}

bool CryptoniteAdapter::ExtractCertificatesFromPkcs7(
    const std::vector<std::uint8_t>& pkcs7_der,
    std::vector<std::vector<std::uint8_t>>& certificates_out,
    std::string& error_message) {
    certificates_out.clear();
#if TAMGA_CRYPTONITE_ENABLED
    if (pkcs7_der.empty() || pkcs7_der.front() != 0x30) {
        error_message = "PKCS#7 bundle is empty or not DER";
        return false;
    }

    ScopedByteArray input(MakeByteArray(pkcs7_der), ba_free);
    if (input == nullptr) {
        error_message = "Unable to allocate cryptonite ByteArray for the PKCS#7 bundle";
        return false;
    }

    ScopedContentInfo content_info(cinfo_alloc(), cinfo_free);
    if (content_info == nullptr) {
        error_message = "Unable to allocate ContentInfo";
        return false;
    }
    if (cinfo_decode(content_info.get(), input.get()) != RET_OK) {
        error_message = "Content is not a PKCS#7 ContentInfo";
        return false;
    }

    SignedData_t* signed_data_raw = nullptr;
    const int sdata_rc = cinfo_get_signed_data(content_info.get(), &signed_data_raw);
    ScopedSignedData signed_data(signed_data_raw, sdata_free);
    if (sdata_rc != RET_OK || signed_data == nullptr) {
        error_message = "PKCS#7 ContentInfo does not carry SignedData";
        return false;
    }

    // `.p7b` — degenerate SignedData: підписантів немає, сенс лише в наборі
    // сертифікатів, тому відсутність SignerInfo тут НЕ помилка.
    CertificateSet_t* certificates_raw = nullptr;
    const int certs_rc = sdata_get_certs(signed_data.get(), &certificates_raw);
    ScopedCertificateSet certificates(certificates_raw, FreeCertificateSet);
    if (certs_rc != RET_OK || certificates == nullptr) {
        error_message = "PKCS#7 bundle contains no certificate set";
        return false;
    }

    CollectEmbeddedCertificatesDer(certificates.get(), certificates_out);
    if (certificates_out.empty()) {
        error_message = "PKCS#7 certificate set is empty";
        return false;
    }
    error_message.clear();
    return true;
#else
    (void)pkcs7_der;
    error_message = BuildDisabledError();
    return false;
#endif
}

bool CryptoniteAdapter::ExtractCertificateMetadata(const std::vector<std::uint8_t>& certificate_der,
                                                   CertificateMetadata& metadata,
                                                   std::string& error_message) {
    metadata = {};
#if TAMGA_CRYPTONITE_ENABLED
    if (certificate_der.empty()) {
        error_message = "Certificate metadata extraction failed: certificate DER is empty";
        return false;
    }

    ScopedByteArray cert_ba(MakeByteArray(certificate_der), ba_free);
    ScopedCert cert(cert_alloc(), cert_free);
    if (cert_ba == nullptr || cert == nullptr) {
        error_message = "Certificate metadata extraction failed: memory allocation failed";
        return false;
    }

    int rc = cert_decode(cert.get(), cert_ba.get());
    if (rc != RET_OK) {
        error_message = BuildRcError("certificate metadata decode", rc);
        return false;
    }

    TBSCertificate_t* tbs_raw = nullptr;
    rc = cert_get_tbs_cert(cert.get(), &tbs_raw);
    if (rc != RET_OK || tbs_raw == nullptr) {
        error_message = BuildRcError("certificate metadata TBS extraction", rc);
        return false;
    }
    std::unique_ptr<TBSCertificate_t, void (*)(TBSCertificate_t*)> tbs(
        tbs_raw,
        [](TBSCertificate_t* value) { ASN_FREE(get_TBSCertificate_desc(), value); });

    CertificateMetadata parsed;
    if (tbs->serialNumber.buf != nullptr && tbs->serialNumber.size > 0) {
        parsed.serial_number_hex = HexEncode(tbs->serialNumber.buf, static_cast<std::size_t>(tbs->serialNumber.size));
    }
    parsed.subject = FormatNameRfc4514(&tbs->subject);
    parsed.issuer = FormatNameRfc4514(&tbs->issuer);

    const auto subject_attributes = CollectNameAttributes(&tbs->subject);
    parsed.common_name = FirstNameAttributeValue(subject_attributes, {"CN", "2.5.4.3"});
    parsed.organization = FirstNameAttributeValue(subject_attributes, {"O", "2.5.4.10"});
    parsed.country = FirstNameAttributeValue(subject_attributes, {"C", "2.5.4.6"});
    parsed.tax_id = FirstNameAttributeValue(subject_attributes,
                                            {"DRFO", "EDRPOU", "SERIALNUMBER", "UID",
                                             "1.2.804.2.1.1.1.11.1.4",
                                             "1.2.804.2.1.1.1.11.1.5", "2.5.4.5"});

    metadata = std::move(parsed);
    error_message.clear();
    return true;
#else
    (void)certificate_der;
    error_message = BuildDisabledError();
    return false;
#endif
}

}  // namespace tamga::core
