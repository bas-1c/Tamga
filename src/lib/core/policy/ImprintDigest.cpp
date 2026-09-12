#include "core/policy/ImprintDigest.h"
#include "core/cryptonite/Internal.h"
#include "core/cryptonite/Names.h"
#include "core/policy/Sha256Helper.h"
#include <algorithm>
#include <cctype>
#include <sstream>

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "aid.h"
#include "byte_array.h"
#include "cert.h"
#include "cryptonite_errors.h"
#include "cryptonite_manager.h"
#include "dstu7564.h"
#include "gost34_311.h"
#include "sha2.h"
}
#endif

namespace tamga::core {

namespace {

// ADR-027: перейменовано з `DigestOid` — див. пояснення в RsaVerifier.cpp.
std::string ImprintDigestOid(ImprintDigest alg) {
    switch (alg) {
        case ImprintDigest::Kupyna256:
            return "1.2.804.2.1.1.1.1.2.2.1";
        case ImprintDigest::Gost34311:
            return "1.2.804.2.1.1.1.1.2.1";
        case ImprintDigest::Sha256:
            return "2.16.840.1.101.3.4.2.1";
        case ImprintDigest::Sha384:
            return "2.16.840.1.101.3.4.2.2";
        case ImprintDigest::Sha512:
            return "2.16.840.1.101.3.4.2.3";
    }
    return {};
}

// Чи можна дозволити cryptonite-адаптеру вивести хеш із сертифіката замість
// явно запитаного алгоритму.
//
// Дозволено ЛИШЕ для ГОСТ 34.311, і причина конкретна: ГОСТ 34.311 параметризований
// (sbox/sync), і ці параметри можуть приходити саме з AlgorithmIdentifier сертифіката,
// тому адаптер там дає правильніший результат, ніж «дефолтний» ГОСТ.
//
// Для Купини (ДСТУ 7564) адаптер ЗАБОРОНЕНО: алгоритм повністю визначений стандартом
// (SBOX_1, 32 байти) і жодних параметрів із сертифіката не потребує. Раніше він тут
// був дозволений, і це давало реальний хибнонегатив: у контейнерах Дія з
// `DigestMethod=...xmlenc#dstu7564-256`, але ГОСТ-овим сертифікатом підписанта,
// адаптер повертав ГОСТ-дайджест — усі `ds:Reference` не збігалися, і валідний
// XAdES-B-LT відхилявся. Знайдено на живому контейнері `sample-document.pdf.asice`.
//
// Загальний принцип (XMLDSIG): `DigestMethod` кожного `ds:Reference` є НОРМАТИВНИМ і
// не підмінюється алгоритмом сертифіката — це незалежні речі. Алгоритм відкритого
// ключа сертифіката лише обмежує сумісні `SignatureMethod`, а outer
// `signatureAlgorithm` описує підпис сертифіката його видавцем. Certificate-aware
// шлях лишається лише там, де він додає параметри, яких у самому URI немає.
bool ShouldUseCertificateAdapter(ImprintDigest alg) {
    return alg == ImprintDigest::Gost34311;
}

#if TAMGA_CRYPTONITE_ENABLED
// ADR-027: локальна копія прибрана — спільні обгортки живуть у
// `core/cryptonite/Internal.h`.
// Копія була побайтово тотожна.
using cryptonite_detail::BuildRcError;

ByteArray* AllocByteArray(const std::vector<std::uint8_t>& data) {
    if (data.empty()) {
        return ba_alloc_by_len(0);
    }
    return ba_alloc_from_uint8(data.data(), data.size());
}

bool AssignDigestFromCertificateAdapter(const std::vector<std::uint8_t>& certificate_der,
                                        ImprintDigest expected_alg,
                                        const std::vector<std::uint8_t>& data,
                                        std::vector<std::uint8_t>& out_hash,
                                        std::string& error_message) {
    ByteArray* cert_ba = nullptr;
    ByteArray* data_ba = nullptr;
    ByteArray* digest_ba = nullptr;
    Certificate_t* cert = nullptr;
    DigestAdapter* digest_adapter = nullptr;
    DigestAlgorithmIdentifier_t* digest_algorithm = nullptr;

    cert_ba = AllocByteArray(certificate_der);
    data_ba = AllocByteArray(data);
    cert = cert_alloc();
    if (cert_ba == nullptr || data_ba == nullptr || cert == nullptr) {
        error_message = BuildRcError("cert-aware digest allocation", RET_MEMORY_ALLOC_ERROR);
        goto cleanup;
    }

    {
        int rc = cert_decode(cert, cert_ba);
        if (rc != RET_OK) {
            error_message = BuildRcError("cert-aware digest certificate decode", rc);
            goto cleanup;
        }

        rc = digest_adapter_init_by_cert(cert, &digest_adapter);
        if (rc != RET_OK || digest_adapter == nullptr) {
            error_message = BuildRcError("cert-aware digest adapter init", rc == RET_OK ? RET_MEMORY_ALLOC_ERROR : rc);
            goto cleanup;
        }
        if (digest_adapter->update == nullptr || digest_adapter->final == nullptr) {
            error_message = "cert-aware digest adapter is incomplete";
            goto cleanup;
        }
        if (digest_adapter->get_alg == nullptr) {
            error_message = "cert-aware digest adapter does not expose its algorithm";
            goto cleanup;
        }

        rc = digest_adapter->get_alg(digest_adapter, &digest_algorithm);
        if (rc != RET_OK || digest_algorithm == nullptr) {
            error_message = BuildRcError(
                "cert-aware digest algorithm", rc == RET_OK ? RET_MEMORY_ALLOC_ERROR : rc);
            goto cleanup;
        }
        {
            const std::string actual_oid =
                cryptonite_detail::OidFromAsn1(digest_algorithm->algorithm);
            const auto actual_alg = ImprintFromDigestOid(actual_oid);
            if (!actual_alg.has_value() || *actual_alg != expected_alg) {
                error_message = "Алгоритм дайджесту сертифіката (" + actual_oid +
                    ") не відповідає явно оголошеному XMLDSIG алгоритму";
                goto cleanup;
            }
        }

        rc = digest_adapter->update(digest_adapter, data_ba);
        if (rc != RET_OK) {
            error_message = BuildRcError("cert-aware digest update", rc);
            goto cleanup;
        }

        rc = digest_adapter->final(digest_adapter, &digest_ba);
        if (rc != RET_OK || digest_ba == nullptr) {
            error_message = BuildRcError("cert-aware digest final", rc == RET_OK ? RET_MEMORY_ALLOC_ERROR : rc);
            goto cleanup;
        }
    }

    out_hash.assign(ba_get_buf(digest_ba), ba_get_buf(digest_ba) + ba_get_len(digest_ba));
    error_message.clear();

cleanup:
    aid_free(digest_algorithm);
    ba_free(digest_ba);
    digest_adapter_free(digest_adapter);
    cert_free(cert);
    ba_free(data_ba);
    ba_free(cert_ba);
    return error_message.empty();
}

bool ComputeGost34311(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& out_hash) {
    ByteArray* sync = ba_alloc_by_len(32);
    if (sync == nullptr) return false;
    ba_set(sync, 0);

    Gost34311Ctx* ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);
    if (ctx == nullptr) {
        ba_free(sync);
        return false;
    }

    ByteArray* ba_data = AllocByteArray(data);
    if (ba_data == nullptr) {
        gost34_311_free(ctx);
        ba_free(sync);
        return false;
    }

    if (gost34_311_update(ctx, ba_data) != 0) {
        ba_free(ba_data);
        gost34_311_free(ctx);
        ba_free(sync);
        return false;
    }

    ByteArray* ba_final = nullptr;
    if (gost34_311_final(ctx, &ba_final) != 0 || ba_final == nullptr) {
        ba_free(ba_data);
        gost34_311_free(ctx);
        ba_free(sync);
        return false;
    }

    out_hash.assign(ba_get_buf(ba_final), ba_get_buf(ba_final) + ba_get_len(ba_final));

    ba_free(ba_data);
    ba_free(ba_final);
    gost34_311_free(ctx);
    ba_free(sync);
    return true;
}

bool ComputeSha2(Sha2Variant variant, const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& out_hash) {
    Sha2Ctx* ctx = sha2_alloc(variant);
    if (ctx == nullptr) return false;

    ByteArray* ba_data = AllocByteArray(data);
    if (ba_data == nullptr) {
        sha2_free(ctx);
        return false;
    }

    if (sha2_update(ctx, ba_data) != 0) {
        ba_free(ba_data);
        sha2_free(ctx);
        return false;
    }

    ByteArray* ba_final = nullptr;
    if (sha2_final(ctx, &ba_final) != 0 || ba_final == nullptr) {
        ba_free(ba_data);
        sha2_free(ctx);
        return false;
    }

    out_hash.assign(ba_get_buf(ba_final), ba_get_buf(ba_final) + ba_get_len(ba_final));

    ba_free(ba_data);
    ba_free(ba_final);
    sha2_free(ctx);
    return true;
}
#endif

} // namespace

// Спільна реалізація Kupyna-256 (див. коментар у ImprintDigest.h): раніше
// існувала у двох ідентичних копіях (тут і в TimestampValidator.cpp), тепер
// це єдине джерело істини для параметрів Купини (SBOX_1, довжина 32 байти).
bool ComputeKupyna256(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& out_hash) {
#if TAMGA_CRYPTONITE_ENABLED
    Dstu7564Ctx* ctx = dstu7564_alloc(DSTU7564_SBOX_1);
    if (ctx == nullptr) return false;

    if (dstu7564_init(ctx, 32) != 0) {
        dstu7564_free(ctx);
        return false;
    }

    ByteArray* ba_data = AllocByteArray(data);
    if (ba_data == nullptr) {
        dstu7564_free(ctx);
        return false;
    }

    if (dstu7564_update(ctx, ba_data) != 0) {
        ba_free(ba_data);
        dstu7564_free(ctx);
        return false;
    }

    ByteArray* ba_final = nullptr;
    if (dstu7564_final(ctx, &ba_final) != 0 || ba_final == nullptr) {
        ba_free(ba_data);
        dstu7564_free(ctx);
        return false;
    }

    out_hash.assign(ba_get_buf(ba_final), ba_get_buf(ba_final) + ba_get_len(ba_final));

    ba_free(ba_data);
    ba_free(ba_final);
    dstu7564_free(ctx);
    return true;
#else
    (void)data;
    (void)out_hash;
    return false;
#endif
}

bool ComputeImprint(ImprintDigest alg,
                    const std::vector<std::uint8_t>& data,
                    ImprintResult& out,
                    std::string& error_message) {
    switch (alg) {
        case ImprintDigest::Kupyna256: {
#if TAMGA_CRYPTONITE_ENABLED
            if (ComputeKupyna256(data, out.hash)) {
                out.digest_oid = ImprintDigestOid(alg);
                return true;
            }
            error_message = "Помилка при обчисленні Kupyna-256 через cryptonite";
            return false;
#else
            error_message = "Kupyna-256 не підтримується у цій збірці (cryptonite вимкнено)";
            return false;
#endif
        }
        case ImprintDigest::Gost34311: {
#if TAMGA_CRYPTONITE_ENABLED
            if (ComputeGost34311(data, out.hash)) {
                out.digest_oid = ImprintDigestOid(alg);
                return true;
            }
            error_message = "Помилка при обчисленні GOST 34.311 через cryptonite";
            return false;
#else
            error_message = "GOST 34.311 не підтримується у цій збірці (cryptonite вимкнено)";
            return false;
#endif
        }
        case ImprintDigest::Sha256: {
            auto hash_arr = tamga::core::policy::Sha256(data);
            out.hash.assign(hash_arr.begin(), hash_arr.end());
            out.digest_oid = ImprintDigestOid(alg);
            return true;
        }
        case ImprintDigest::Sha384: {
#if TAMGA_CRYPTONITE_ENABLED
            if (ComputeSha2(SHA2_VARIANT_384, data, out.hash)) {
                out.digest_oid = ImprintDigestOid(alg);
                return true;
            }
            error_message = "Помилка при обчисленні SHA-384 через cryptonite";
            return false;
#else
            error_message = "SHA-384 не підтримується у цій збірці (cryptonite вимкнено)";
            return false;
#endif
        }
        case ImprintDigest::Sha512: {
#if TAMGA_CRYPTONITE_ENABLED
            if (ComputeSha2(SHA2_VARIANT_512, data, out.hash)) {
                out.digest_oid = ImprintDigestOid(alg);
                return true;
            }
            error_message = "Помилка при обчисленні SHA-512 через cryptonite";
            return false;
#else
            error_message = "SHA-512 не підтримується у цій збірці (cryptonite вимкнено)";
            return false;
#endif
        }
    }
    error_message = "Невідомий алгоритм гешування імпринту";
    return false;
}

bool ComputeImprintByCertificate(const std::vector<std::uint8_t>& certificate_der,
                                 ImprintDigest fallback_alg,
                                 const std::vector<std::uint8_t>& data,
                                 ImprintResult& out,
                                 std::string& error_message) {
    if (!ShouldUseCertificateAdapter(fallback_alg) || certificate_der.empty()) {
        return ComputeImprint(fallback_alg, data, out, error_message);
    }

#if TAMGA_CRYPTONITE_ENABLED
    std::vector<std::uint8_t> hash;
    std::string adapter_error;
    if (AssignDigestFromCertificateAdapter(
            certificate_der, fallback_alg, data, hash, adapter_error)) {
        out.hash = std::move(hash);
        out.digest_oid = ImprintDigestOid(fallback_alg);
        error_message.clear();
        return true;
    }

    // Для параметризованого ГОСТ generic fallback небезпечний: він утрачає
    // DKE/sbox із сертифіката. Невідповідність фактичного алгоритму адаптера
    // явно запитаному алгоритму є помилкою, а не приводом мовчки перейти на
    // інші параметри або інший хеш.
    error_message = adapter_error.empty()
        ? "Не вдалося обчислити certificate-aware ГОСТ 34.311"
        : std::move(adapter_error);
    return false;
#else
    return ComputeImprint(fallback_alg, data, out, error_message);
#endif
}

std::optional<ImprintDigest> ImprintFromDigestOid(const std::string& digest_oid) {
    std::string oid_lower = digest_oid;
    std::transform(oid_lower.begin(), oid_lower.end(), oid_lower.begin(), [](unsigned char c) -> char {
        return static_cast<char>(std::tolower(c));
    });

    auto starts_with = [](const std::string& str, const std::string& prefix) {
        return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
    };

    if (oid_lower == "1.2.804.2.1.1.1.1.2.2.1" ||
        oid_lower == "kupyna256" ||
        oid_lower == "kupyna-256" ||
        // Купина має ДВА поширені написання: неформальне "kupyna256" і назву
        // самого стандарту ДСТУ 7564:2014 — "dstu7564-256". Дія використовує
        // саме друге (`...xmlenc#dstu7564-256` у DigestMethod реальних ASiC-E
        // контейнерів), і без цих аліасів кожен ds:Reference не обчислювався
        // взагалі — підпис відхилявся як невалідний. Знайдено на живому
        // контейнері Дія, а не в юніт-тесті.
        oid_lower == "dstu7564-256" ||
        oid_lower == "dstu7564_256" ||
        oid_lower == "dstu7564" ||
        starts_with(oid_lower, "1.2.804.2.1.1.1.1.3")) {
        return ImprintDigest::Kupyna256;
    }
    
    if (oid_lower == "1.2.804.2.1.1.1.1.2.1" || 
        oid_lower == "gost34311" || 
        oid_lower == "gost-34311") {
        return ImprintDigest::Gost34311;
    }
    
    if (oid_lower == "2.16.840.1.101.3.4.2.1" || 
        oid_lower == "sha-256" || 
        oid_lower == "sha256" || 
        oid_lower == "1.2.840.113549.1.1.11" || 
        oid_lower == "1.2.840.10045.4.3.2") {
        return ImprintDigest::Sha256;
    }
    
    if (oid_lower == "2.16.840.1.101.3.4.2.2" || 
        oid_lower == "sha-384" || 
        oid_lower == "sha384" || 
        oid_lower == "1.2.840.113549.1.1.12" || 
        oid_lower == "1.2.840.10045.4.3.3") {
        return ImprintDigest::Sha384;
    }
    
    if (oid_lower == "2.16.840.1.101.3.4.2.3" || 
        oid_lower == "sha-512" || 
        oid_lower == "sha512" || 
        oid_lower == "1.2.840.113549.1.1.13" || 
        oid_lower == "1.2.840.10045.4.3.4") {
        return ImprintDigest::Sha512;
    }
    
    return std::nullopt;
}

} // namespace tamga::core
