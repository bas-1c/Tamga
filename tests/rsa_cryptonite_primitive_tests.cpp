#include "core/CryptoniteAdapter.h"
#include "util/Base64.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xmldsig/XmlTransformEngine.h"

extern "C" {
#include "asn1_utils.h"
#include "aid.h"
#include "byte_array.h"
#include "cert.h"
#include "cryptonite_errors.h"
#include "cryptonite_manager.h"
#include "oids.h"
#include "rsa.h"
#include "verify_adapter.h"
}

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> ReadFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

bool ReadDerLength(const std::vector<std::uint8_t>& der, std::size_t& offset, std::size_t& length) {
    if (offset >= der.size()) {
        return false;
    }
    const std::uint8_t first = der[offset++];
    if ((first & 0x80U) == 0U) {
        length = first;
        return true;
    }
    const std::size_t octets = first & 0x7FU;
    if (octets == 0 || octets > sizeof(std::size_t) || octets > der.size() - offset) {
        return false;
    }
    length = 0;
    for (std::size_t i = 0; i < octets; ++i) {
        if (length > (static_cast<std::size_t>(-1) >> 8U)) {
            return false;
        }
        length = (length << 8U) | der[offset++];
    }
    return true;
}

bool ReadDerIntegerLe(const std::vector<std::uint8_t>& der,
                      std::size_t& offset,
                      const std::size_t sequence_end,
                      std::vector<std::uint8_t>& value_le) {
    if (offset >= sequence_end || der[offset++] != 0x02U) {
        return false;
    }
    std::size_t length = 0;
    if (!ReadDerLength(der, offset, length) || length == 0 || length > sequence_end - offset) {
        return false;
    }
    const std::size_t end = offset + length;
    if ((der[offset] & 0x80U) != 0U) {
        return false;  // RSA n/e мають бути додатними ASN.1 INTEGER.
    }
    while (offset + 1 < end && der[offset] == 0) {
        ++offset;
    }
    value_le.assign(der.begin() + static_cast<std::ptrdiff_t>(offset),
                    der.begin() + static_cast<std::ptrdiff_t>(end));
    std::reverse(value_le.begin(), value_le.end());
    offset = end;
    return !value_le.empty();
}

bool DecodeRsaPublicKey(const Certificate_t* cert,
                        std::vector<std::uint8_t>& modulus_le,
                        std::vector<std::uint8_t>& exponent_le) {
    ByteArray* subject_public_key = nullptr;
    if (asn_BITSTRING2ba(&cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
                         &subject_public_key) != 0 || subject_public_key == nullptr) {
        ba_free(subject_public_key);
        return false;
    }
    const std::uint8_t* begin = ba_get_buf(subject_public_key);
    const std::vector<std::uint8_t> der(begin, begin + ba_get_len(subject_public_key));
    ba_free(subject_public_key);

    std::size_t offset = 0;
    if (der.empty() || der[offset++] != 0x30U) {
        return false;
    }
    std::size_t sequence_length = 0;
    if (!ReadDerLength(der, offset, sequence_length) || sequence_length != der.size() - offset) {
        return false;
    }
    const std::size_t sequence_end = offset + sequence_length;
    return ReadDerIntegerLe(der, offset, sequence_end, modulus_le) &&
           ReadDerIntegerLe(der, offset, sequence_end, exponent_le) && offset == sequence_end;
}

bool ExtractSignatureValue(const std::string& xml, std::vector<std::uint8_t>& signature) {
    const std::string open = "<ds:SignatureValue>";
    const std::string close = "</ds:SignatureValue>";
    const auto begin = xml.find(open);
    const auto end = begin == std::string::npos ? std::string::npos : xml.find(close, begin + open.size());
    if (begin == std::string::npos || end == std::string::npos) {
        return false;
    }
    std::string base64 = xml.substr(begin + open.size(), end - begin - open.size());
    base64.erase(std::remove_if(base64.begin(), base64.end(),
                                [](unsigned char ch) { return std::isspace(ch) != 0; }),
                 base64.end());
    return tamga::util::Base64Decode(base64, signature) && !signature.empty();
}

int Fail(const std::string& message) {
    std::cerr << "RSA cryptonite primitive test failed: " << message << '\n';
    return 1;
}

}  // namespace

int main() {
    const auto source = std::filesystem::path(TAMGA_TEST_SOURCE_DIR);
    const auto xml_bytes = ReadFile(source / "tests" / "TL-UA-EC.xml");
    const auto cert_der = ReadFile(source / "tests" / "fixtures" / "trust-list" / "czo-tl-signer.der");
    if (xml_bytes.empty() || cert_der.empty()) {
        return Fail("real TL/certificate fixtures are missing");
    }
    const std::string xml(xml_bytes.begin(), xml_bytes.end());

    // Чинний XMLDSIG-шлях дає канонікалізований SHA-256 SignedInfo; на Windows
    // він також є незалежним CNG-вердиктом для звірки примітива.
    tamga::core::CryptoniteAdapter crypto;
    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::xmldsig::XmlSignatureVerifier verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xmldsig::XmlSignatureVerificationResult xml_result;
    std::string error;
    if (!verifier.Verify(xml, xml_result, error)) {
        return Fail("XMLDSIG preparation failed: " + error);
    }
#if defined(_WIN32)
    if (!xml_result.signature_valid) {
        return Fail("the baseline CNG verdict for the real TL is not valid: " +
                    xml_result.signature_value_error);
    }
#endif
    std::vector<std::uint8_t> digest;
    if (!tamga::util::Base64Decode(xml_result.signed_info_hash_base64, digest) || digest.size() != 32U) {
        return Fail("SignedInfo SHA-256 was not produced");
    }

    std::vector<std::uint8_t> signature_be;
    if (!ExtractSignatureValue(xml, signature_be)) {
        return Fail("ds:SignatureValue was not extracted");
    }

    ByteArray* cert_ba = ba_alloc_from_uint8(cert_der.data(), cert_der.size());
    Certificate_t* cert = cert_alloc();
    if (cert_ba == nullptr || cert == nullptr || cert_decode(cert, cert_ba) != 0) {
        ba_free(cert_ba);
        cert_free(cert);
        return Fail("pinned signer certificate could not be decoded");
    }
    ba_free(cert_ba);

    std::vector<std::uint8_t> modulus_le;
    std::vector<std::uint8_t> exponent_le;
    const bool key_decoded = DecodeRsaPublicKey(cert, modulus_le, exponent_le);
    if (!key_decoded) {
        cert_free(cert);
        return Fail("RSAPublicKey (n/e) was not decoded from SubjectPublicKeyInfo");
    }

    std::vector<std::uint8_t> signature_le(signature_be.rbegin(), signature_be.rend());
    ByteArray* modulus = ba_alloc_from_uint8(modulus_le.data(), modulus_le.size());
    ByteArray* exponent = ba_alloc_from_uint8(exponent_le.data(), exponent_le.size());
    ByteArray* hash = ba_alloc_from_uint8(digest.data(), digest.size());
    ByteArray* signature = ba_alloc_from_uint8(signature_le.data(), signature_le.size());
    RsaCtx* rsa = rsa_alloc();

    const int init_rc = rsa == nullptr ? -1 :
        rsa_init_verify_pkcs1_v1_5(rsa, RSA_HASH_SHA256, modulus, exponent);
    const int verify_rc = init_rc == 0 ? rsa_verify_pkcs1_v1_5(rsa, hash, signature) : init_rc;

    // Підпис іншої розрядності не має доходити до арифметики іншого модуля.
    // Це також перевіряє добір хибного видавця під час побудови TSA-ланцюжка.
    bool invalid_sizes_rejected = true;
    if (init_rc == 0) {
        const auto size = signature_le.size();
        for (const auto bad_size : {std::size_t{0}, std::size_t{1}, size / 2, size - 1, size + 1, size * 2}) {
            std::vector<std::uint8_t> malformed(bad_size, 0);
            std::copy_n(signature_le.begin(), std::min(size, bad_size), malformed.begin());
            const std::uint8_t empty_marker = 0;
            ByteArray* bad = ba_alloc_from_uint8(bad_size == 0 ? &empty_marker : malformed.data(), bad_size);
            if (bad == nullptr || rsa_verify_pkcs1_v1_5(rsa, hash, bad) == RET_OK) {
                invalid_sizes_rejected = false;
            }
            ba_free(bad);
        }
        if (rsa_verify_pkcs1_v1_5(rsa, hash, modulus) == RET_OK) invalid_sizes_rejected = false;
        // Негативні спроби не псують контекст валідної перевірки.
        if (rsa_verify_pkcs1_v1_5(rsa, hash, signature) != RET_OK) invalid_sizes_rejected = false;
    }

    rsa_free(rsa);
    ba_free(modulus);
    ba_free(exponent);
    ba_free(hash);
    ba_free(signature);

    if (!invalid_sizes_rejected) {
        cert_free(cert);
        return Fail("RSA-підпис іншої довжини або поза [0,n) не відхилено");
    }

    if (init_rc != 0) {
        cert_free(cert);
        return Fail("rsa_init_verify_pkcs1_v1_5 rc=" + std::to_string(init_rc));
    }
    if (verify_rc != 0) {
        cert_free(cert);
        return Fail("rsa_verify_pkcs1_v1_5 rc=" + std::to_string(verify_rc));
    }

    // Варіант 2: той самий ключ/підпис має пройти через загальний PKIX
    // VerifyAdapter, а однобайтова мутація — дійти до примітива й упасти.
    VerifyAdapter* adapter = nullptr;
    AlgorithmIdentifier_t* sha256_aid = aid_alloc();
    ByteArray* adapter_hash = ba_alloc_from_uint8(digest.data(), digest.size());
    ByteArray* adapter_signature = ba_alloc_from_uint8(signature_be.data(), signature_be.size());
    int adapter_rc = sha256_aid == nullptr ? -1 :
        aid_init_by_oid(sha256_aid, oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID));
    if (adapter_rc == 0) {
        adapter_rc = verify_adapter_init_by_cert(cert, &adapter);
    }
    if (adapter_rc == 0) {
        adapter_rc = adapter->set_digest_alg(adapter, sha256_aid);
    }
    if (adapter_rc == 0) {
        adapter_rc = adapter->verify_hash(adapter, adapter_hash, adapter_signature);
    }
    if (adapter_rc != 0) {
        aid_free(sha256_aid);
        ba_free(adapter_hash);
        ba_free(adapter_signature);
        verify_adapter_free(adapter);
        cert_free(cert);
        return Fail("PKIX RSA VerifyAdapter rc=" + std::to_string(adapter_rc));
    }

    ba_free(adapter_signature);
    signature_be[0] ^= 0x01U;
    adapter_signature = ba_alloc_from_uint8(signature_be.data(), signature_be.size());
    const int mutated_rc = adapter->verify_hash(adapter, adapter_hash, adapter_signature);
    aid_free(sha256_aid);
    ba_free(adapter_hash);
    ba_free(adapter_signature);
    verify_adapter_free(adapter);
    cert_free(cert);
    if (mutated_rc != RET_VERIFY_FAILED) {
        return Fail("mutated RSA signature was not rejected by the primitive, rc=" +
                    std::to_string(mutated_rc));
    }

    std::cout << "RSA cryptonite primitive and PKIX VerifyAdapter verified the real TL-UA-EC.xml signature"
              << " (n=" << modulus_le.size() << " bytes, e=" << exponent_le.size() << " bytes)\n";
    return 0;
}
