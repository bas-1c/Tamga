#include "core/RsaVerifier.h"

#include "core/cryptonite/CertUtil.h"

#if defined(TAMGA_CRYPTONITE_ENABLED) && TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "aid.h"
#include "byte_array.h"
#include "cert.h"
#include "cryptonite_errors.h"
#include "cryptonite_manager.h"
#include "oids.h"
#include "pkix_utils.h"
#include "verify_adapter.h"
}
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// wincrypt.h має йти після windows.h; bcrypt.h дає BCryptVerifySignature.
#include <wincrypt.h>
#include <bcrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
// Оголошено в ntstatus.h, який тягне за собою конфлікти макросів із winnt.h;
// значення фіксоване в контракті NTSTATUS, тож визначаємо локально.
#ifndef STATUS_INVALID_SIGNATURE
#define STATUS_INVALID_SIGNATURE ((NTSTATUS)0xC000A000L)
#endif
#endif  // _WIN32

namespace tamga::core {

namespace {

std::size_t ExpectedDigestSize(const RsaHashAlg alg) {
    switch (alg) {
        case RsaHashAlg::Sha384: return 48U;
        case RsaHashAlg::Sha512: return 64U;
        case RsaHashAlg::Sha256:
        default:                 return 32U;
    }
}

#if defined(_WIN32)

// RAII для CERT_CONTEXT/ключа: шляхів виходу тут багато, і забутий free
// перетворився б на витік у довгоживучій 1С-сесії.
struct CertContextGuard {
    PCCERT_CONTEXT ctx{nullptr};
    ~CertContextGuard() {
        if (ctx != nullptr) {
            CertFreeCertificateContext(ctx);
        }
    }
};

struct BCryptKeyGuard {
    BCRYPT_KEY_HANDLE key{nullptr};
    ~BCryptKeyGuard() {
        if (key != nullptr) {
            BCryptDestroyKey(key);
        }
    }
};

PCCERT_CONTEXT MakeCertContext(const std::vector<std::uint8_t>& certificate_der) {
    if (certificate_der.empty()) {
        return nullptr;
    }
    return CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        certificate_der.data(),
                                        static_cast<DWORD>(certificate_der.size()));
}

const wchar_t* HashAlgorithmId(const RsaHashAlg alg) {
    switch (alg) {
        case RsaHashAlg::Sha384: return BCRYPT_SHA384_ALGORITHM;
        case RsaHashAlg::Sha512: return BCRYPT_SHA512_ALGORITHM;
        case RsaHashAlg::Sha256:
        default:                 return BCRYPT_SHA256_ALGORITHM;
    }
}

#endif  // _WIN32

#if defined(TAMGA_CRYPTONITE_ENABLED) && TAMGA_CRYPTONITE_ENABLED

// ADR-027: перейменовано з `DigestOid`. Однойменна функція в
// `policy/ImprintDigest` — ІНША: інший тип параметра (ImprintDigest),
// інший результат (рядок OID замість cryptonite OidId) і інший домен.
// Збіг імені лише створював враження спільної реалізації.
OidId RsaDigestOid(const RsaHashAlg alg) {
    switch (alg) {
        case RsaHashAlg::Sha384: return OID_PKI_SHA384_ID;
        case RsaHashAlg::Sha512: return OID_PKI_SHA512_ID;
        case RsaHashAlg::Sha256:
        default:                 return OID_PKI_SHA256_ID;
    }
}

// ADR-027: копія прибрана — декодування живе в `core/cryptonite/CertUtil`.
using tamga::core::cryptonite_detail::DecodeCertificateDer;
using tamga::core::cryptonite_detail::ScopedCert;

RsaVerifyResult VerifyWithCryptonite(const std::vector<std::uint8_t>& certificate_der,
                                     const RsaHashAlg hash_alg,
                                     const std::vector<std::uint8_t>& digest,
                                     const std::vector<std::uint8_t>& signature) {
    RsaVerifyResult result;
    ScopedCert cert(nullptr, cert_free);
    VerifyAdapter* adapter = nullptr;
    AlgorithmIdentifier_t* digest_aid = aid_alloc();
    ByteArray* hash = ba_alloc_from_uint8(digest.data(), digest.size());
    ByteArray* sign = ba_alloc_from_uint8(signature.data(), signature.size());

    int rc = digest_aid != nullptr && hash != nullptr && sign != nullptr ? 0 : -1;
    if (rc == 0) {
        cert = DecodeCertificateDer(certificate_der);
        rc = cert ? 0 : -1;
    }
    if (rc == 0) {
        rc = aid_init_by_oid(digest_aid, oids_get_oid_numbers_by_id(RsaDigestOid(hash_alg)));
    }
    if (rc == 0) {
        rc = verify_adapter_init_by_cert(cert.get(), &adapter);
    }
    if (rc == 0) {
        rc = adapter->set_digest_alg(adapter, digest_aid);
    }
    if (rc == 0) {
        rc = adapter->verify_hash(adapter, hash, sign);
        result.executed = rc == 0 || rc == RET_VERIFY_FAILED;
        result.valid = rc == 0;
    }

    aid_free(digest_aid);
    ba_free(hash);
    ba_free(sign);
    verify_adapter_free(adapter);

    if (result.executed && !result.valid) {
        result.message = "RSA signature does not match";
    } else if (!result.executed) {
        result.message = "RSA verification through cryptonite PKIX adapter failed (rc " +
                         std::to_string(rc) + ")";
    }
    return result;
}

#endif

}  // namespace

bool CertificateHasRsaPublicKey(const std::vector<std::uint8_t>& certificate_der) {
#if defined(_WIN32)
    CertContextGuard guard{MakeCertContext(certificate_der)};
    if (guard.ctx == nullptr || guard.ctx->pCertInfo == nullptr) {
        return false;
    }
    const char* oid = guard.ctx->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    return oid != nullptr && std::string(oid) == szOID_RSA_RSA;
#else
#if defined(TAMGA_CRYPTONITE_ENABLED) && TAMGA_CRYPTONITE_ENABLED
    // Гілка не-Windows: у трьох локальних конфігураціях не компілюється,
    // тож зміна тут навмисно мінімальна — та сама послідовність дій,
    // лише з канонічним декодером і RAII замість ручного cert_free.
    const tamga::core::cryptonite_detail::ScopedCert cert =
        tamga::core::cryptonite_detail::DecodeCertificateDer(certificate_der);
    if (!cert) {
        return false;
    }
    return pkix_check_oid_equal(
        &cert->tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm,
        oids_get_oid_numbers_by_id(OID_RSA_ENCRYPTION_ID));
#else
    (void)certificate_der;
    return false;
#endif
#endif
}

RsaVerifyResult VerifyRsaPkcs1(const std::vector<std::uint8_t>& certificate_der,
                               const RsaHashAlg hash_alg,
                               const std::vector<std::uint8_t>& digest,
                               const std::vector<std::uint8_t>& signature) {
    RsaVerifyResult result;

    if (certificate_der.empty() || digest.empty() || signature.empty()) {
        result.message = "RSA verification requires a certificate, a digest and a signature";
        return result;
    }
    if (digest.size() != ExpectedDigestSize(hash_alg)) {
        result.message = "RSA verification: digest length does not match the declared hash algorithm";
        return result;
    }

#if defined(_WIN32)
    CertContextGuard cert{MakeCertContext(certificate_der)};
    if (cert.ctx == nullptr || cert.ctx->pCertInfo == nullptr) {
        result.message = "RSA verification: certificate could not be parsed";
        return result;
    }

    const char* key_oid = cert.ctx->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    if (key_oid == nullptr || std::string(key_oid) != szOID_RSA_RSA) {
        result.message = "RSA verification: certificate does not carry an RSA public key";
        return result;
    }

    BCryptKeyGuard key;
    if (CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
                                    &cert.ctx->pCertInfo->SubjectPublicKeyInfo,
                                    0, nullptr, &key.key) == FALSE || key.key == nullptr) {
        result.message = "RSA verification: public key import failed";
        return result;
    }

    BCRYPT_PKCS1_PADDING_INFO padding{};
    padding.pszAlgId = HashAlgorithmId(hash_alg);

    const NTSTATUS status = BCryptVerifySignature(
        key.key, &padding,
        const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(digest.data())),
        static_cast<ULONG>(digest.size()),
        const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(signature.data())),
        static_cast<ULONG>(signature.size()),
        BCRYPT_PAD_PKCS1);

    // Перевірку виконано в обох випадках — розрізняємо «не збіглось» і «не змогли».
    result.executed = true;
    if (NT_SUCCESS(status)) {
        result.valid = true;
        return result;
    }
    result.valid = false;
    result.message = (status == STATUS_INVALID_SIGNATURE)
                         ? "RSA signature does not match"
                         : "RSA verification failed (NTSTATUS " + std::to_string(static_cast<long>(status)) + ")";
    return result;
#elif defined(TAMGA_CRYPTONITE_ENABLED) && TAMGA_CRYPTONITE_ENABLED
    return VerifyWithCryptonite(certificate_der, hash_alg, digest, signature);
#else
    (void)certificate_der;
    (void)hash_alg;
    (void)digest;
    (void)signature;
    result.message = "RSA verification requires vendored cryptonite on this platform";
    return result;
#endif
}

}  // namespace tamga::core
