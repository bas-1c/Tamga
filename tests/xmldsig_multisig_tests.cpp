#include "support/FixturePaths.h"
// WP-2 regression suite — XmlSignatureVerifier::VerifyAll (кілька ds:Signature
// в ОДНОМУ документі, на відміну від ASiC-E multi-file co-signing, вже
// підтриманого на рівні Session/SessionAsicOps.ipp).
//
// Перевіряє:
//   1) genuine позитивний випадок: два НЕЗАЛЕЖНІ, дійсні ds:Signature (різні
//      DSTU4145-ключі) над одним і тим самим документом -- VerifyAll має
//      повернути по одному коректному результату на кожен підпис.
//   2) незалежність вердиктів: підробка SignatureValue ОДНОГО з двох підписів
//      не повинна впливати на вердикт іншого.
//   3) регресія: наявні adversarial wrapping-фікстури (два ds:Signature з
//      навмисно задубльованими Id/SignedProperties, використані для того щоб
//      обдурити global "перший елемент" пошук) мають лишатися ВІДХИЛЕНИМИ
//      і під новою VerifyAll -- дублікати Id виявляються так само, глобально
//      по документу, незалежно від того, якому підпису вони "належать".
//
// Повертає: 0 = усі перевірки пройшли; 1 = регресія; 77 = збірка без
// TAMGA_ENABLE_VENDOR_CRYPTONITE / XMLDSIG.

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "asic/AsicReader.h"
#include "core/CryptoniteAdapter.h"
#include "core/Session.h"
#include "util/Base64.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xmldsig/XmlTransformEngine.h"

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "aid.h"
#include "byte_array.h"
#include "cert.h"
#include "cert_engine.h"
#include "certificate_request_engine.h"
#include "cryptonite_manager.h"
#include "digest_adapter.h"
#include "dstu4145.h"
#include "ext.h"
#include "gost28147.h"
#include "oids.h"
#include "pkcs12.h"
#include "sign_adapter.h"
#include "spki.h"
#include "verify_adapter.h"
}
#endif

namespace {

constexpr int kSkip = 77;

std::filesystem::path FixturePath(const char* name) {
    return tamga_test::TestDataRoot() / "tests" / "fixtures" / "security" / "asic" / name;
}

bool ReadText(const std::filesystem::path& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool Require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        return false;
    }
    return true;
}

#if TAMGA_CRYPTONITE_ENABLED

// Генерує PKCS12 із самопідписаним DSTU4145-сертифікатом -- та сама схема,
// що й GenerateDstuFixture у tamga_tests.cpp/GenerateCertWithEku у
// eku_utils_tests.cpp, тут самодостатня копія для незалежності тестового
// бінаря.
bool GenerateDstuPkcs12(std::vector<std::uint8_t>& pkcs12_out) {
    pkcs12_out.clear();

    Dstu4145Ctx* ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    Gost28147Ctx* cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    if (ec_params == nullptr || cipher_params == nullptr) {
        dstu4145_free(ec_params);
        gost28147_free(cipher_params);
        return false;
    }

    AlgorithmIdentifier_t* aid = nullptr;
    ByteArray* aid_ba = nullptr;
    Pkcs12Ctx* storage = nullptr;
    SignAdapter* sa = nullptr;
    DigestAdapter* da = nullptr;
    VerifyAdapter* va = nullptr;
    CertificateRequestEngine* creq_eng = nullptr;
    CertificationRequest_t* cert_req = nullptr;
    CertificateEngine* cert_eng = nullptr;
    Certificate_t* cert = nullptr;
    ByteArray* cert_encoded = nullptr;
    ByteArray* storage_body = nullptr;
    Extension_t* key_usage_ext = nullptr;
    Extensions_t* extensions = nullptr;
    SubjectPublicKeyInfo_t* spki = nullptr;
    int rc = 0;
    bool ok = false;

    rc = aid_create_dstu4145(ec_params, cipher_params, true, &aid);
    if (rc != 0) goto cleanup;
    rc = aid_encode(aid, &aid_ba);
    if (rc != 0) goto cleanup;
    rc = pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, "test", 1024, &storage);
    if (rc != 0) goto cleanup;
    rc = pkcs12_generate_key(storage, aid_ba);
    if (rc != 0) goto cleanup;
    rc = pkcs12_store_key(storage, "signer", "test", 1024);
    if (rc != 0) goto cleanup;
    rc = pkcs12_select_key(storage, "signer", "test");
    if (rc != 0) goto cleanup;
    rc = pkcs12_get_sign_adapter(storage, &sa);
    if (rc != 0) goto cleanup;
    rc = pkcs12_get_verify_adapter(storage, &va);
    if (rc != 0) goto cleanup;
    rc = va->get_pub_key(va, &spki);
    if (rc != 0) goto cleanup;
    rc = digest_adapter_init_by_aid(&spki->algorithm, &da);
    if (rc != 0) goto cleanup;
    rc = ecert_request_alloc(sa, &creq_eng);
    if (rc != 0) goto cleanup;
    rc = ecert_request_set_subj_name(creq_eng, "{CN=Tamga MultiSig Test}{O=Tamga}{C=UA}");
    if (rc != 0) goto cleanup;
    rc = ecert_request_generate(creq_eng, &cert_req);
    if (rc != 0) goto cleanup;

    rc = ext_create_key_usage(true,
        static_cast<KeyUsageBits>(KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_KEY_CERTSIGN),
        &key_usage_ext);
    if (rc != 0) goto cleanup;

    extensions = static_cast<Extensions_t*>(calloc(1, sizeof(Extensions_t)));
    if (extensions == nullptr) goto cleanup;
    rc = ASN_SEQUENCE_ADD(&extensions->list, key_usage_ext);
    if (rc != 0) goto cleanup;
    key_usage_ext = nullptr;  // ownership transferred

    rc = ecert_alloc(sa, da, true, &cert_eng);
    if (rc != 0) goto cleanup;

    {
        std::vector<unsigned char> serial_bytes(20);
        for (std::size_t i = 0; i < serial_bytes.size(); ++i) {
            serial_bytes[i] = static_cast<unsigned char>(0x40 + i + std::rand() % 16);
        }
        ByteArray* serial_ba = ba_alloc_from_uint8(serial_bytes.data(), serial_bytes.size());
        time_t not_before = std::time(nullptr) - 86400;
        time_t not_after = not_before + 365 * 86400;
        rc = ecert_generate(cert_eng, cert_req, 2, serial_ba, &not_before, &not_after, extensions, &cert);
        ba_free(serial_ba);
    }
    if (rc != 0) goto cleanup;

    rc = cert_encode(cert, &cert_encoded);
    if (rc != 0) goto cleanup;

    {
        const ByteArray* certs[2] = {cert_encoded, nullptr};
        rc = pkcs12_set_certificates(storage, certs);
    }
    if (rc != 0) goto cleanup;

    rc = pkcs12_encode(storage, &storage_body);
    if (rc != 0) goto cleanup;

    pkcs12_out.assign(ba_get_buf(storage_body), ba_get_buf(storage_body) + ba_get_len(storage_body));
    ok = true;

cleanup:
    ba_free(storage_body);
    ba_free(cert_encoded);
    cert_free(cert);
    ecert_free(cert_eng);
    if (extensions != nullptr) {
        ASN_FREE_CONTENT_STATIC(get_Extensions_desc(), extensions);
        free(extensions);
    }
    if (key_usage_ext != nullptr) {
        ASN_FREE(get_Extension_desc(), key_usage_ext);
    }
    ecert_request_free(creq_eng);
    if (cert_req != nullptr) {
        ASN_FREE(get_CertificationRequest_desc(), cert_req);
    }
    spki_free(spki);
    digest_adapter_free(da);
    verify_adapter_free(va);
    sign_adapter_free(sa);
    pkcs12_free(storage);
    ba_free(aid_ba);
    aid_free(aid);
    gost28147_free(cipher_params);
    dstu4145_free(ec_params);
    return ok;
}

bool SignWithFreshKey(const std::string& xml, std::string& signed_out) {
    std::vector<std::uint8_t> pkcs12;
    if (!GenerateDstuPkcs12(pkcs12)) {
        return false;
    }
    tamga::core::Session session;
    if (!session.Initialize()) {
        return false;
    }
    if (!session.ReadPrivateKeyBinary(pkcs12, "test", "test")) {
        return false;
    }
    return session.SignXml(xml, signed_out);
}

// Повертає перший блок <Signature ...>...</Signature> (нема нащадка
// Signature всередині Signature для документів, які виробляє наш власний
// SignXml -- єдиний підпис на документ).
bool ExtractSignatureBlock(const std::string& signed_xml, std::string& block_out) {
    const auto start = signed_xml.find("<Signature");
    if (start == std::string::npos) {
        return false;
    }
    const auto end_tag = signed_xml.find("</Signature>", start);
    if (end_tag == std::string::npos) {
        return false;
    }
    const auto end = end_tag + std::string("</Signature>").size();
    block_out = signed_xml.substr(start, end - start);
    return true;
}

// Вставляє other_signature_block як ДРУГОГО ds:Signature -- сиблінга
// першого -- в документ base_signed_xml, безпосередньо перед закриваючим
// тегом кореневого елемента.
bool MergeSecondSignature(const std::string& base_signed_xml, const std::string& other_signature_block,
                          std::string& merged_out) {
    const auto last_close = base_signed_xml.rfind("</Doc>");
    if (last_close == std::string::npos) {
        return false;
    }
    merged_out = base_signed_xml.substr(0, last_close) + other_signature_block +
                base_signed_xml.substr(last_close);
    return true;
}

bool RunGenuineTwoSignatureAcceptanceTest() {
    const std::string base_xml = "<Doc><Data>tamga multisig payload</Data></Doc>";

    std::string signed_a;
    std::string signed_b;
    if (!Require(SignWithFreshKey(base_xml, signed_a), "Failed to produce first independent signature") ||
        !Require(SignWithFreshKey(base_xml, signed_b), "Failed to produce second independent signature")) {
        return false;
    }

    std::string block_b;
    if (!Require(ExtractSignatureBlock(signed_b, block_b), "Failed to extract second Signature block")) {
        return false;
    }
    std::string merged;
    if (!Require(MergeSecondSignature(signed_a, block_b, merged),
                 "Failed to merge two independent ds:Signature into one document")) {
        return false;
    }
    if (!Require(merged.find("</Signature></Signature>") == std::string::npos &&
                 merged.find("<Doc>") == 0,
                 "Merged document must contain two sibling Signature elements under the same root")) {
        return false;
    }

    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    tamga::xmldsig::XmlSignatureVerifier verifier(canonicalizer, transform_engine, digest_engine, crypto);

    std::vector<tamga::xmldsig::XmlSignatureVerificationResult> results;
    std::string error;
    if (!Require(verifier.VerifyAll(merged, {}, results, error),
                 "VerifyAll must process a genuine two-signature document: " + error)) {
        return false;
    }
    if (!Require(results.size() == 2, "VerifyAll must report exactly two independent signature results")) {
        return false;
    }
    for (std::size_t i = 0; i < results.size(); ++i) {
        if (!Require(results[i].signature_valid, "signature #" + std::to_string(i) + " must be cryptographically valid") ||
            !Require(results[i].digest_valid, "signature #" + std::to_string(i) + " digests must all match")) {
            return false;
        }
    }
    return true;
}

bool RunIndependentVerdictTest() {
    const std::string base_xml = "<Doc><Data>tamga multisig independence payload</Data></Doc>";

    std::string signed_a;
    std::string signed_b;
    if (!Require(SignWithFreshKey(base_xml, signed_a), "Failed to produce first independent signature") ||
        !Require(SignWithFreshKey(base_xml, signed_b), "Failed to produce second independent signature")) {
        return false;
    }

    std::string block_b;
    if (!Require(ExtractSignatureBlock(signed_b, block_b), "Failed to extract second Signature block")) {
        return false;
    }

    // Псуємо SignatureValue ЛИШЕ у другому блоці (перед вставкою) -- перший
    // підпис лишається недоторканим і має верифікуватись незалежно.
    const auto sv_start = block_b.find("<SignatureValue>");
    const auto sv_end = block_b.find("</SignatureValue>", sv_start);
    if (!Require(sv_start != std::string::npos && sv_end != std::string::npos,
                 "Second signature block must contain SignatureValue")) {
        return false;
    }
    const auto content_start = sv_start + std::string("<SignatureValue>").size();
    std::string tampered_value = block_b.substr(content_start, sv_end - content_start);
    if (!tampered_value.empty()) {
        tampered_value[0] = (tampered_value[0] == 'A') ? 'B' : 'A';
    }
    block_b = block_b.substr(0, content_start) + tampered_value + block_b.substr(sv_end);

    std::string merged;
    if (!Require(MergeSecondSignature(signed_a, block_b, merged),
                 "Failed to merge tampered second signature")) {
        return false;
    }

    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    tamga::xmldsig::XmlSignatureVerifier verifier(canonicalizer, transform_engine, digest_engine, crypto);

    std::vector<tamga::xmldsig::XmlSignatureVerificationResult> results;
    std::string error;
    if (!Require(verifier.VerifyAll(merged, {}, results, error),
                 "VerifyAll must still process a document with one tampered signature: " + error)) {
        return false;
    }
    if (!Require(results.size() == 2, "VerifyAll must report two results even when one is tampered")) {
        return false;
    }
    return Require(results[0].signature_valid, "First (untouched) signature must remain valid") &&
           Require(!results[1].signature_valid, "Second (tampered SignatureValue) signature must be invalid") &&
           Require(results[0].digest_valid, "First signature's digests are unaffected by the other's tampering");
}

bool ExtractSignaturesXmlFromAsice(const std::filesystem::path& b64_path, std::string& signatures_xml_out) {
    std::string b64;
    if (!ReadText(b64_path, b64)) {
        return false;
    }
    std::vector<std::uint8_t> asice;
    if (!tamga::util::Base64Decode(b64, asice) || asice.empty()) {
        return false;
    }
    tamga::asic::AsicReader reader;
    std::string err;
    if (!reader.LoadFromBuffer(asice, err)) {
        return false;
    }
    std::vector<tamga::asic::AsicFileEntry> entries;
    if (!reader.GetFiles(entries, err)) {
        return false;
    }
    for (const auto& e : entries) {
        if (e.name.rfind("META-INF/signatures", 0) == 0 && e.name.size() >= 4 &&
            e.name.substr(e.name.size() - 4) == ".xml") {
            signatures_xml_out.assign(e.data.begin(), e.data.end());
            return true;
        }
    }
    return false;
}

// Наявні adversarial wrapping-фікстури (tests/xmldsig_wrapping_tests.cpp) мають
// лишатися ВІДХИЛЕНИМИ й під новою VerifyAll -- дублікати Id виявляються
// глобально по документу незалежно від multi-signature підтримки.
bool RunAdversarialFixtureStillRejectedTest(const char* fixture_name) {
    const auto path = FixturePath(fixture_name);
    std::string signatures_xml;
    if (!ExtractSignaturesXmlFromAsice(path, signatures_xml)) {
        std::cerr << "Skipping adversarial regression for missing fixture: " << fixture_name << '\n';
        return true;  // трактується як skip на рівні цієї конкретної фікстури
    }

    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    tamga::xmldsig::XmlSignatureVerifier verifier(canonicalizer, transform_engine, digest_engine, crypto);

    std::vector<tamga::xmldsig::XmlSignatureVerificationResult> results;
    std::string error;
    const bool executed = verifier.VerifyAll(signatures_xml, {}, results, error);
    if (executed) {
        bool all_valid = !results.empty();
        for (const auto& r : results) {
            all_valid = all_valid && r.signature_valid && r.digest_valid;
        }
        if (!Require(!all_valid,
                     std::string("VULNERABLE: adversarial wrapping fixture ") + fixture_name +
                     " reported all signatures valid under VerifyAll")) {
            return false;
        }
        std::cout << "[" << fixture_name << "] SECURE: VerifyAll ran but did not report full validity\n";
        return true;
    }
    std::cout << "[" << fixture_name << "] SECURE: VerifyAll rejected the document (" << error << ")\n";
    return true;
}

#endif  // TAMGA_CRYPTONITE_ENABLED

}  // namespace

int main() {
#if !TAMGA_CRYPTONITE_ENABLED
    std::cerr << "Skipping WP-2 multi-signature regression: built without TAMGA_ENABLE_VENDOR_CRYPTONITE\n";
    return kSkip;
#else
    bool ok = true;
    ok = RunGenuineTwoSignatureAcceptanceTest() && ok;
    ok = RunIndependentVerdictTest() && ok;
    ok = RunAdversarialFixtureStillRejectedTest("wrap-two-signatures.asice.b64") && ok;
    ok = RunAdversarialFixtureStillRejectedTest("wrap-dup-signedproperties.asice.b64") && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
#endif
}
