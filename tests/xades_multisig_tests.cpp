// WP-2 (продовження) regression suite — XadesVerifier::VerifyAll: кілька
// ds:Signature в одному XAdES-документі, з per-signature scoping.
//
// Раніше XadesVerifier::Verify() шукав SignedProperties/CertDigest/
// SignatureTimeStamp/CertificateValues через FindFirstElement(root, ...) --
// глобально по всьому документу. Для документа з кількома ds:Signature це
// означало б, що XAdES-перевірка одного підпису могла б випадково побачити
// SignedProperties/сертифікат/докази ІНШОГО підпису (класичний ризик
// wrapping на XAdES-рівні, аналогічний тому, що XmlSignatureVerifier::
// VerifyAll вже усунув на XMLDSIG-рівні). Цей тест перевіряє, що:
//   1) два НЕЗАЛЕЖНІ, дійсні XAdES-BES підписи (різні DSTU4145-ключі/
//      сертифікати) над одним документом дають по одному коректному
//      XadesVerificationResult, кожен зі СВОЇМ (не переплутаним) сертифікатом
//      і власним підтвердженим CertDigest;
//   2) підробка лише другого підпису (SignatureValue) не впливає на вердикт
//      першого;
//   3) сертифікат, вилучений для підпису N, дійсно належить підписанту N (а
//      не сусідньому підпису) -- пряма перевірка відсутності cross-
//      contamination між ds:Signature.
//
// Повертає: 0 = усі перевірки пройшли; 1 = регресія; 77 = збірка без
// TAMGA_ENABLE_VENDOR_CRYPTONITE / XMLDSIG.

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

#include "core/CryptoniteAdapter.h"
#include "core/SignatureRequest.h"
#include "core/TspClient.h"
#include "xades/XadesBuilder.h"
#include "xades/XadesVerifier.h"
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

bool Require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        return false;
    }
    return true;
}

#if TAMGA_CRYPTONITE_ENABLED

struct DstuFixture {
    std::vector<std::uint8_t> pkcs12_blob;
    std::vector<std::uint8_t> cert_der;
    bool valid{false};
};

// Той самий ecert_generate-патерн, що й у tamga_tests.cpp/eku_utils_tests.cpp/
// xmldsig_multisig_tests.cpp -- самодостатня копія для незалежності бінаря.
DstuFixture GenerateDstuFixture(const char* subject_cn) {
    DstuFixture result;

    Dstu4145Ctx* ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    Gost28147Ctx* cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    if (ec_params == nullptr || cipher_params == nullptr) {
        dstu4145_free(ec_params);
        gost28147_free(cipher_params);
        return result;
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
    rc = ecert_request_set_subj_name(creq_eng, (std::string("{CN=") + subject_cn + "}{O=Tamga}{C=UA}").c_str());
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
            serial_bytes[i] = static_cast<unsigned char>(0x10 + i + std::rand() % 16);
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

    result.pkcs12_blob.assign(ba_get_buf(storage_body), ba_get_buf(storage_body) + ba_get_len(storage_body));
    result.cert_der.assign(ba_get_buf(cert_encoded), ba_get_buf(cert_encoded) + ba_get_len(cert_encoded));
    result.valid = true;

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
    return result;
}

bool SignXadesBes(const DstuFixture& fixture, const std::string& xml, const std::string& signature_id,
                  std::string& signed_xml_out) {
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xades::XadesBuilder builder(crypto, tsp);

    tamga::xades::XadesParameters params;
    params.profile = tamga::xades::XadesProfile::BES;
    params.xml_params.signature_id = signature_id;
    params.xml_params.signature_method_uri = "http://www.w3.org/2001/04/xmldsig-more#dstu4145";
    params.xml_params.c14n_method = tamga::xmldsig::CanonicalizationMethod::C14N;
    tamga::xmldsig::XmlReference ref;
    ref.uri = "";
    ref.transforms = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    ref.digest_method = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
    params.xml_params.references.push_back(ref);

    tamga::core::SigningKey key;
    key.use_pkcs12 = true;
    key.key_material = fixture.pkcs12_blob;
    key.certificate_der = fixture.cert_der;
    key.password = "test";

    std::string error;
    return builder.Sign(xml, params, key, signed_xml_out, error);
}

// Перший блок <ds:Signature ...>...</ds:Signature> (XadesBuilder завжди
// префіксує "ds:").
bool ExtractSignatureBlock(const std::string& signed_xml, std::string& block_out) {
    const auto start = signed_xml.find("<ds:Signature");
    if (start == std::string::npos) {
        return false;
    }
    const auto end_tag = signed_xml.find("</ds:Signature>", start);
    if (end_tag == std::string::npos) {
        return false;
    }
    const auto end = end_tag + std::string("</ds:Signature>").size();
    block_out = signed_xml.substr(start, end - start);
    return true;
}

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

bool RunGenuineTwoXadesSignatureAcceptanceTest() {
    const DstuFixture fixture_a = GenerateDstuFixture("Tamga XAdES MultiSig A");
    const DstuFixture fixture_b = GenerateDstuFixture("Tamga XAdES MultiSig B");
    if (!Require(fixture_a.valid && fixture_b.valid, "Failed to generate DSTU fixtures")) {
        return false;
    }

    const std::string base_xml = "<Doc><Data>tamga xades multisig payload</Data></Doc>";

    std::string signed_a;
    std::string signed_b;
    if (!Require(SignXadesBes(fixture_a, base_xml, "sig1", signed_a), "Failed to produce first XAdES-BES signature") ||
        !Require(SignXadesBes(fixture_b, base_xml, "sig2", signed_b), "Failed to produce second XAdES-BES signature")) {
        return false;
    }

    std::string block_b;
    if (!Require(ExtractSignatureBlock(signed_b, block_b), "Failed to extract second ds:Signature block")) {
        return false;
    }
    std::string merged;
    if (!Require(MergeSecondSignature(signed_a, block_b, merged),
                 "Failed to merge two independent XAdES ds:Signature into one document")) {
        return false;
    }

    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesVerifier verifier(xml_verifier, crypto, tsp);

    tamga::xades::XadesSignatureSet set;
    std::string error;
    if (!Require(verifier.VerifyAll(merged, set, error),
                 "VerifyAll must process a genuine two-XAdES-signature document: " + error)) {
        return false;
    }
    if (!Require(set.signatures.size() == 2, "VerifyAll must report exactly two independent XAdES results")) {
        return false;
    }
    if (!Require(set.all_valid, "Both independent XAdES-BES signatures must be valid")) {
        return false;
    }

    for (std::size_t i = 0; i < set.signatures.size(); ++i) {
        const auto& r = set.signatures[i];
        if (!Require(r.qualifying_properties_present, "signature #" + std::to_string(i) + ": QualifyingProperties must be detected") ||
            !Require(r.signing_certificate_digest_valid, "signature #" + std::to_string(i) + ": CertDigest must match its OWN certificate") ||
            !Require(r.detected_profile == tamga::xades::XadesProfile::BES, "signature #" + std::to_string(i) + ": profile must be BES")) {
            return false;
        }
    }

    // Критична перевірка scoping-фіксу: сертифікат підпису #0 має належати
    // fixture_a, підпису #1 -- fixture_b (жодного cross-contamination між
    // ds:Signature при пошуку X509Certificate/CertDigest).
    if (!Require(set.signatures[0].signer_certificate_der == fixture_a.cert_der,
                 "Signature #0's extracted certificate must be fixture_a's, not fixture_b's")) {
        return false;
    }
    return Require(set.signatures[1].signer_certificate_der == fixture_b.cert_der,
                   "Signature #1's extracted certificate must be fixture_b's, not fixture_a's");
}

bool RunIndependentVerdictTest() {
    const DstuFixture fixture_a = GenerateDstuFixture("Tamga XAdES MultiSig C");
    const DstuFixture fixture_b = GenerateDstuFixture("Tamga XAdES MultiSig D");
    if (!Require(fixture_a.valid && fixture_b.valid, "Failed to generate DSTU fixtures")) {
        return false;
    }

    const std::string base_xml = "<Doc><Data>tamga xades multisig independence payload</Data></Doc>";

    std::string signed_a;
    std::string signed_b;
    if (!Require(SignXadesBes(fixture_a, base_xml, "sig1", signed_a), "Failed to produce first XAdES-BES signature") ||
        !Require(SignXadesBes(fixture_b, base_xml, "sig2", signed_b), "Failed to produce second XAdES-BES signature")) {
        return false;
    }

    std::string block_b;
    if (!Require(ExtractSignatureBlock(signed_b, block_b), "Failed to extract second ds:Signature block")) {
        return false;
    }

    // Псуємо SignatureValue лише другого підпису.
    const auto sv_start = block_b.find("<ds:SignatureValue>");
    const auto sv_end = block_b.find("</ds:SignatureValue>", sv_start);
    if (!Require(sv_start != std::string::npos && sv_end != std::string::npos,
                 "Second signature block must contain ds:SignatureValue")) {
        return false;
    }
    const auto content_start = sv_start + std::string("<ds:SignatureValue>").size();
    std::string tampered_value = block_b.substr(content_start, sv_end - content_start);
    if (!tampered_value.empty()) {
        tampered_value[0] = (tampered_value[0] == 'A') ? 'B' : 'A';
    }
    block_b = block_b.substr(0, content_start) + tampered_value + block_b.substr(sv_end);

    std::string merged;
    if (!Require(MergeSecondSignature(signed_a, block_b, merged), "Failed to merge tampered second signature")) {
        return false;
    }

    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesVerifier verifier(xml_verifier, crypto, tsp);

    tamga::xades::XadesSignatureSet set;
    std::string error;
    if (!Require(verifier.VerifyAll(merged, set, error),
                 "VerifyAll must still process a document with one tampered XAdES signature: " + error)) {
        return false;
    }
    if (!Require(set.signatures.size() == 2, "VerifyAll must report two results even when one is tampered")) {
        return false;
    }
    if (!Require(!set.all_valid, "Aggregate verdict must be invalid when one signature is tampered")) {
        return false;
    }
    return Require(set.signatures[0].signature_valid, "First (untouched) XAdES signature must remain valid") &&
           Require(!set.signatures[1].signature_valid, "Second (tampered) XAdES signature must be invalid");
}

// Регресія на знахідку Gemini review (PR #18): FindFirstElement(signature_node,
// ...) обходить не лише нащадків signature_node, а й НАСТУПНІ СИБЛІНГИ
// (node->next у зовнішньому циклі) -- якщо шуканий елемент відсутній у
// ВЛАСНОМУ піддереві signature_node, пошук "просочується" в сусідній
// ds:Signature. Перший підпис навмисно позбавлений власного
// ds:X509Certificate (структурно неповний/atacker-crafted підпис); якщо
// per-signature scoping колись знову зламається (напр. хтось поверне
// прямий виклик FindFirstElement замість FindFirstElementInSubtree),
// підпис #0 підхопить сертифікат підпису #1 -- цей тест це ловить.
bool RunFirstSignatureMissingCertificateDoesNotLeakToSecondTest() {
    const DstuFixture fixture_a = GenerateDstuFixture("Tamga XAdES MultiSig E");
    const DstuFixture fixture_b = GenerateDstuFixture("Tamga XAdES MultiSig F");
    if (!Require(fixture_a.valid && fixture_b.valid, "Failed to generate DSTU fixtures")) {
        return false;
    }

    const std::string base_xml = "<Doc><Data>tamga xades multisig cross-contamination payload</Data></Doc>";

    std::string signed_a;
    std::string signed_b;
    if (!Require(SignXadesBes(fixture_a, base_xml, "sig1", signed_a), "Failed to produce first XAdES-BES signature") ||
        !Require(SignXadesBes(fixture_b, base_xml, "sig2", signed_b), "Failed to produce second XAdES-BES signature")) {
        return false;
    }

    std::string block_a;
    std::string block_b;
    if (!Require(ExtractSignatureBlock(signed_a, block_a), "Failed to extract first ds:Signature block") ||
        !Require(ExtractSignatureBlock(signed_b, block_b), "Failed to extract second ds:Signature block")) {
        return false;
    }

    const std::string open_tag = "<ds:X509Certificate>";
    const std::string close_tag = "</ds:X509Certificate>";
    const auto open_pos = block_a.find(open_tag);
    if (!Require(open_pos != std::string::npos, "First signature block must contain ds:X509Certificate to strip")) {
        return false;
    }
    const auto close_pos = block_a.find(close_tag, open_pos);
    if (!Require(close_pos != std::string::npos, "First signature block's ds:X509Certificate must be well-formed")) {
        return false;
    }
    block_a.erase(open_pos, close_pos + close_tag.size() - open_pos);

    // Documented order matters for this regression: signature #0 (stripped)
    // FIRST, signature #1 (intact) SECOND -- this is exactly the ordering
    // required for the fixed bug's sibling-fallthrough to have leaked.
    const auto close_doc = base_xml.rfind("</Doc>");
    if (!Require(close_doc != std::string::npos, "base_xml must contain closing </Doc>")) {
        return false;
    }
    const std::string merged = base_xml.substr(0, close_doc) + block_a + block_b + base_xml.substr(close_doc);

    tamga::xmldsig::XmlCanonicalizer canonicalizer;
    tamga::xmldsig::XmlTransformEngine transform_engine;
    tamga::xmldsig::XmlDigestEngine digest_engine;
    tamga::core::CryptoniteAdapter crypto;
    tamga::core::TspClient tsp;
    tamga::xmldsig::XmlSignatureVerifier xml_verifier(canonicalizer, transform_engine, digest_engine, crypto);
    tamga::xades::XadesVerifier verifier(xml_verifier, crypto, tsp);

    tamga::xades::XadesSignatureSet set;
    std::string error;
    if (!Require(verifier.VerifyAll(merged, set, error),
                 "VerifyAll must still structurally process a document where one signature lacks its own certificate: " +
                     error)) {
        return false;
    }
    if (!Require(set.signatures.size() == 2, "VerifyAll must report two results even when one lacks a certificate")) {
        return false;
    }

    // Critical scoping assertion: signature #0 (stripped) must NOT pick up
    // fixture_b's certificate via a sibling-search leak into signature #1.
    if (!Require(set.signatures[0].signer_certificate_der.empty(),
                 "Signature #0 (missing its own X509Certificate) must NOT inherit signature #1's certificate")) {
        return false;
    }
    if (!Require(set.signatures[0].signer_certificate_der != fixture_b.cert_der,
                 "Signature #0's certificate must never equal fixture_b's (no cross-contamination)")) {
        return false;
    }
    return Require(set.signatures[1].signer_certificate_der == fixture_b.cert_der,
                   "Signature #1 (intact) must still correctly report fixture_b's own certificate");
}

#endif  // TAMGA_CRYPTONITE_ENABLED

}  // namespace

int main() {
#if !TAMGA_CRYPTONITE_ENABLED
    std::cerr << "Skipping WP-2 XAdES multi-signature regression: built without TAMGA_ENABLE_VENDOR_CRYPTONITE\n";
    return kSkip;
#else
    bool ok = true;
    ok = RunGenuineTwoXadesSignatureAcceptanceTest() && ok;
    ok = RunIndependentVerdictTest() && ok;
    ok = RunFirstSignatureMissingCertificateDoesNotLeakToSecondTest() && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
#endif
}
