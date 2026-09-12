// Fuzz-ціль: ASN.1/DER через vendored cryptonite.
//
// Найцінніша з чотирьох поверхонь: cryptonite — код на C з ручними
// malloc/free, і саме там уже знаходили витоки (V-07 `Sha1Ctx`, `sinfo` у
// VerifyCmsSignerAt). Усі знахідки звідси мають оформлюватися як записи черги
// patches/cryptonite/, а не правитися в дереві vendor напряму.
//
// Вхід іде в КОЖЕН розбірник паралельно, а не тільки в «свій»: сертифікат,
// поданий у розбір CMS, — коректний випадок, бо саме так поводиться зіпсований
// контейнер із реального обігу.

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include "core/CryptoniteAdapter.h"

namespace {

constexpr std::size_t kMaxInput = 4u * 1024u * 1024u;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > kMaxInput) {
        return 0;
    }
    const std::vector<std::uint8_t> input(data, data + size);
    using tamga::core::CryptoniteAdapter;

    (void)CryptoniteAdapter::IsCertificateDer(input);

    {
        tamga::core::CertificateMetadata metadata;
        std::string error;
        (void)CryptoniteAdapter::ExtractCertificateMetadata(input, metadata, error);
    }

    {
        std::vector<std::uint8_t> spki;
        std::string error;
        (void)CryptoniteAdapter::ExtractCertificateSubjectPublicKeyInfo(input, spki, error);
    }

    {
        std::vector<std::vector<std::uint8_t>> certificates;
        std::string error;
        (void)CryptoniteAdapter::ExtractCertificatesFromPkcs7(input, certificates, error);
    }

    // CMS SignedData: розбір атрибутів SignerInfo. Це той код, який O-01
    // переписав з goto cleanup на RAII, тож саме він потребує сторожа.
    {
        std::vector<std::uint8_t> signature_value;
        std::string error;
        (void)CryptoniteAdapter::GetSignatureValue(input, signature_value, error);
    }
    {
        std::string digest_oid;
        std::string error;
        (void)CryptoniteAdapter::GetSignerDigestAlgorithmOid(input, digest_oid, error);
    }
    {
        std::string signing_time;
        (void)CryptoniteAdapter::ExtractSigningTime(input, signing_time);
    }
    {
        bool has_token = false;
        std::string error;
        (void)CryptoniteAdapter::HasSignatureTimestampToken(input, has_token, error);
    }
    {
        std::vector<std::uint8_t> token;
        std::string error;
        (void)CryptoniteAdapter::ExtractSignatureTimestampToken(input, token, error);
    }

    // Перевірка підпису над самим собою: і дані, і підпис — той самий буфер.
    // Мета не «перевірити підпис», а прогнати повний шлях розбору SignedData
    // разом із побудовою verify/digest-адаптерів.
    {
        bool is_valid = false;
        tamga::core::VerifyPolicyInfo policy_info;
        std::string error;
        (void)CryptoniteAdapter::VerifyDetached(input, input, is_valid, policy_info, error);
    }
    {
        bool is_valid = false;
        std::vector<std::uint8_t> content;
        tamga::core::VerifyPolicyInfo policy_info;
        std::string error;
        (void)CryptoniteAdapter::VerifyAttached(input, is_valid, content, policy_info, error);
    }

    // CRL.
    {
        std::time_t next_update = 0;
        (void)CryptoniteAdapter::GetCrlNextUpdate(input, next_update);
    }
    {
        (void)CryptoniteAdapter::CheckCertificateRevocation(input, input, input);
    }

    return 0;
}
