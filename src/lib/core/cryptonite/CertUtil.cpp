#include "core/cryptonite/CertUtil.h"

#if TAMGA_CRYPTONITE_ENABLED

namespace tamga::core::cryptonite_detail {

bool VerifyCertificateByIssuer(const Certificate_t* certificate, const Certificate_t* issuer) {
    VerifyAdapter* verify_adapter_raw = nullptr;
    const int init_rc = verify_adapter_init_by_cert(issuer, &verify_adapter_raw);
    ScopedVerifyAdapter verify_adapter(verify_adapter_raw, verify_adapter_free);
    if (init_rc != RET_OK || verify_adapter == nullptr) {
        return false;
    }
    return cert_verify(certificate, verify_adapter.get()) == RET_OK;
}

namespace {

// Читає розширення keyUsage. `present=false` — розширення немає (або воно не
// розбирається), і тоді обмежень немає.
bool ReadKeyUsage(const Certificate_t* certificate, bool& present, KeyUsage_t*& usage) {
    present = false;
    usage = nullptr;
    if (certificate == nullptr) {
        return false;
    }
    const int rc = cert_get_key_usage(certificate, &usage);
    if (rc != RET_OK || usage == nullptr) {
        if (usage != nullptr) {
            ASN_FREE(get_KeyUsage_desc(), usage);
            usage = nullptr;
        }
        return false;
    }
    present = true;
    return true;
}

}  // namespace

bool CertificateAllowsKeyUsage(const Certificate_t* certificate, const int key_usage_bit) {
    if (certificate == nullptr) {
        return false;
    }
    bool present = false;
    KeyUsage_t* usage = nullptr;
    if (!ReadKeyUsage(certificate, present, usage)) {
        // Розширення немає — обмежень немає.
        return true;
    }
    int bit = 0;
    const bool allowed = asn_BITSTRING_get_bit(usage, key_usage_bit, &bit) == RET_OK && bit != 0;
    ASN_FREE(get_KeyUsage_desc(), usage);
    return allowed;
}

bool CertificateAllowsSigning(const Certificate_t* certificate) {
    if (certificate == nullptr) {
        return false;
    }
    bool present = false;
    KeyUsage_t* usage = nullptr;
    if (!ReadKeyUsage(certificate, present, usage)) {
        return true;
    }
    int digital_signature = 0;
    int non_repudiation = 0;
    const bool has_digital_signature =
        asn_BITSTRING_get_bit(usage, KeyUsage_digitalSignature, &digital_signature) == RET_OK &&
        digital_signature != 0;
    const bool has_non_repudiation =
        asn_BITSTRING_get_bit(usage, KeyUsage_nonRepudiation, &non_repudiation) == RET_OK &&
        non_repudiation != 0;
    ASN_FREE(get_KeyUsage_desc(), usage);
    return has_digital_signature || has_non_repudiation;
}

bool EncodeCertificateDer(const Certificate_t* certificate, std::vector<std::uint8_t>& out_der) {
    if (certificate == nullptr) {
        out_der.clear();
        return false;
    }
    ByteArray* encoded_raw = nullptr;
    const int rc = cert_encode(const_cast<Certificate_t*>(certificate), &encoded_raw);
    ScopedByteArray encoded(encoded_raw, ba_free);
    if (rc != RET_OK || encoded == nullptr) {
        out_der.clear();
        return false;
    }
    AssignFromByteArray(encoded.get(), out_der);
    return !out_der.empty();
}

void CollectEmbeddedCertificatesDer(const CertificateSet_t* certs,
                                    std::vector<std::vector<std::uint8_t>>& out_ders) {
    out_ders.clear();
    if (certs == nullptr) {
        return;
    }

    out_ders.reserve(static_cast<std::size_t>(certs->list.count));
    for (int index = 0; index < certs->list.count; ++index) {
        const CertificateChoices_t* choice = certs->list.array[index];
        if (choice == nullptr || choice->present != CertificateChoices_PR_certificate) {
            continue;
        }
        std::vector<std::uint8_t> der;
        if (EncodeCertificateDer(&choice->choice.certificate, der)) {
            out_ders.push_back(std::move(der));
        }
    }
}

bool IsCertificateSelfSigned(const Certificate_t* certificate) {
    return VerifyCertificateByIssuer(certificate, certificate);
}

const Certificate_t* FindIssuerCertificate(const Certificate_t* certificate,
                                           const CertificateSet_t* certs,
                                           const std::vector<const Certificate_t*>& visited) {
    if (certs == nullptr) {
        return nullptr;
    }

    for (int index = 0; index < certs->list.count; ++index) {
        CertificateChoices_t* choice = certs->list.array[index];
        if (choice == nullptr || choice->present != CertificateChoices_PR_certificate) {
            continue;
        }

        const Certificate_t* candidate = &choice->choice.certificate;
        if (std::find(visited.begin(), visited.end(), candidate) != visited.end()) {
            continue;
        }
        if (VerifyCertificateByIssuer(certificate, candidate)) {
            return candidate;
        }
    }

    return nullptr;
}

bool DecodeCertificateDerInto(const std::vector<std::uint8_t>& der, Certificate_t* certificate) {
    if (certificate == nullptr) {
        return false;
    }
    // MakeByteArrayOrNull повертає nullptr на порожньому вході — саме та з
    // двох іменованих семантик (Internal.h), яка тут потрібна: сертифікат із
    // нуля байтів не існує.
    ScopedByteArray encoded(MakeByteArrayOrNull(der), ba_free);
    return encoded != nullptr && cert_decode(certificate, encoded.get()) == RET_OK;
}

ScopedCert DecodeCertificateDer(const std::vector<std::uint8_t>& der) {
    ScopedCert certificate(cert_alloc(), cert_free);
    if (!DecodeCertificateDerInto(der, certificate.get())) {
        return ScopedCert(nullptr, cert_free);
    }
    return certificate;
}

}  // namespace tamga::core::cryptonite_detail

#endif  // TAMGA_CRYPTONITE_ENABLED
