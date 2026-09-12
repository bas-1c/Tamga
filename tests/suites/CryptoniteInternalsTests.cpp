// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Внутрішні деталі адаптера cryptonite, які видно лише зсередини: робота з
// UTF-8 шляхами на Windows, ініціалізація структур OCSP на шляхах помилок,
// офлайн-режим, звірка ключа з сертифікатом.
//
// Тести тут гейтовані так само, як були в моноліті: гейт їде разом із
// блоком, а не переписується вручну.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "types.h"
#include "IMemoryManager.h"
#include "asic/AsicReader.h"
#include "asic/AsicWriter.h"
#include "asic/AsicContainers.h"
#include "miniz.h"
#include "core/Errors.h"
#include "core/HttpClient.h"
#include "core/KeyParsers.h"
#include "core/net/CaSettingsRegistry.h"
#include "core/net/CertificateFetcher.h"
#include "core/net/CertificateResolver.h"
#include "core/Session.h"
#include "tamga/tamga_c_api.h"
#include "core/TspClient.h"
#include "core/policy/AiaIssuerFetcher.h"
#include "core/policy/CertificateChainValidator.h"
#include "core/policy/CrlValidator.h"
#include "core/policy/CrlCache.h"
#include "core/policy/ImprintDigest.h"
#include "core/policy/OcspValidator.h"
#include "core/policy/PolicyCache.h"
#include "core/policy/TimestampValidator.h"
#include "core/policy/TlXmlSigCheck.h"
#include "core/policy/TrustListParser.h"
#include "core/policy/TrustListSettings.h"
#include "core/policy/TrustListSync.h"
#include "core/policy/Sha256Helper.h"
#include "core/policy/UserReportBuilder.h"
#include "core/session/VerifySummary.h"
#include "core/validation/EvidenceStore.h"
#include "core/validation/PathEngine.h"
#include "core/validation/PolicyResolver.h"
#include "core/validation/SigningTimeResolver.h"
#include "core/validation/ValidationReportJson.h"
#include "core/validation/ValidationReportProjection.h"
#include "core/validation/TrustServiceEvaluator.h"
#include "core/validation/RevocationEngine.h"
#include "core/validation/TimestampEngine.h"
#include "core/validation/ValidationEngine.h"
#include "core/CryptoniteAdapter.h"
#include "core/policy/ImprintDigest.h"
#include "nativeapi/TamgaAddIn.h"
#include "util/AsicUri.h"
#include "util/Base64.h"
#include "util/Utf.h"
#include "nativeapi/VariantUtils.h"

// Phase 0 (ADR 012): стаб-заголовки форматних підсистем XMLDSIG/XAdES/PAdES.
// Включення тут дає compile-smoke у проєктному тулчейні — заголовки мають
// парситися й бути взаємно консистентними, поки .cpp зʼявляться у фазах 1-6.
#include "core/SignatureRequest.h"
#include "xmldsig/XmlCanonicalizer.h"
#include "xmldsig/XmlReferenceResolver.h"
#include "xmldsig/XmlTransformEngine.h"
#include "xmldsig/XmlDigestEngine.h"
#include "xmldsig/XmlSecContext.h"
#include "xmldsig/XmlSignatureBuilder.h"
#include "xmldsig/XmlSignatureVerifier.h"
#include "xades/XadesTypes.h"
#include "xades/XadesBuilder.h"
#include "xades/XadesVerifier.h"
#include "pades/PdfTypes.h"
#include "pades/PdfParser.h"
#include "pades/PdfByteRange.h"
#include "pades/PadesBuilder.h"
#include "pades/PadesVerifier.h"

#ifndef TAMGA_CRYPTONITE_ENABLED
#define TAMGA_CRYPTONITE_ENABLED 0
#endif

#if TAMGA_CRYPTONITE_ENABLED
extern "C" {
#include "aid.h"
#include "asn1_utils.h"
#include "byte_array.h"
#include "cert.h"
#include "cert_engine.h"
#include "certificate_request_engine.h"
#include "crl.h"
#include "crl_engine.h"
#include "cryptonite_manager.h"
#include "digest_adapter.h"
#include "dstu4145.h"
#include "dstu7564.h"
#include "ext.h"
#include "gost28147.h"
#include "hmac.h"
#include "oids.h"
#include "ocsp_response.h"
#include "ocsp_response_engine.h"
#include "pkcs12.h"
#include "pkcs5.h"
#include "pkcs8.h"
#include "sign_adapter.h"
#include "spki.h"
#include "verify_adapter.h"
#include "content_info.h"
#include "signed_data.h"
#include "CertificateSerialNumber.h"
#include "RevokedCertificate.h"
#include "TSTInfo.h"
#include "signed_data_engine.h"
#include "signer_info_engine.h"
#include "signer_info.h"
#include "CertificateSet.h"
#include "SignerIdentifier.h"
#include "pkix_utils.h"
#include "tsp_request.h"
#include "tsp_response.h"
#include "tsp_request_engine.h"
#include "tsp_response_engine.h"
#include "adapters_map.h"
#include "DigestAlgorithmIdentifiers.h"
#include "MessageImprint.h"
#include "AlgorithmIdentifier.h"
#include "EncryptedPrivateKeyInfo.h"
#include "GOST28147ParamsOptionalDke.h"
#if defined(_WIN32)
#include "dirent_internal.h"
#endif
}
#endif

#if TAMGA_CRYPTONITE_ENABLED
#include "core/cryptonite/CertUtil.h"
#endif

#include "support/TestSupport.h"
#include "suites/Suites.h"

using namespace tamga_tests;

#if TAMGA_CRYPTONITE_ENABLED && defined(_WIN32)
void TestCryptoniteIsDirHandlesUtf8Paths() {
    const auto root = MakeTemporaryFixturePath(".cryptonite-is-dir");
    const auto ascii_dir = root / "ascii-directory";
    const auto unicode_dir = root / u8"Київ-Калина";

    std::error_code ec;
    std::filesystem::create_directories(ascii_dir, ec);
    ExpectTrue(!ec, "is_dir smoke test should create the ASCII directory");
    ec.clear();
    std::filesystem::create_directories(unicode_dir, ec);
    ExpectTrue(!ec, "is_dir smoke test should create the Unicode directory");

    if (!ec) {
        const auto ascii_utf8 = ascii_dir.u8string();
        const auto unicode_utf8 = unicode_dir.u8string();
        ExpectTrue(is_dir(ascii_utf8.c_str()), "cryptonite is_dir should recognize an ASCII directory");
        ExpectTrue(is_dir(unicode_utf8.c_str()), "cryptonite is_dir should recognize a UTF-8 directory");
    }

    ec.clear();
    std::filesystem::remove_all(root, ec);
}
#endif  // TAMGA_CRYPTONITE_ENABLED && defined(_WIN32)

#if TAMGA_CRYPTONITE_ENABLED
void TestKalynaKupynaPkcs5RoundTrip() {
    const std::vector<std::uint8_t> kmac_key_bytes(32, 0xa5);
    const std::vector<std::uint8_t> kmac_data_bytes = {'T', 'a', 'm', 'g', 'a'};
    ByteArray* kmac_key = ba_alloc_from_uint8(kmac_key_bytes.data(), kmac_key_bytes.size());
    ByteArray* kmac_data = ba_alloc_from_uint8(kmac_data_bytes.data(), kmac_data_bytes.size());
    HmacCtx* kmac = hmac_alloc_dstu7564(DSTU7564_VARIANT_256);
    ByteArray* expected_mac = nullptr;
    bool reset_ok = kmac_key != nullptr && kmac_data != nullptr && kmac != nullptr &&
                    hmac_init(kmac, kmac_key) == RET_OK;
    for (std::size_t i = 0; reset_ok && i < 64; ++i) {
        ByteArray* actual_mac = nullptr;
        if (i != 0 && i % 8 == 0) {
            reset_ok = hmac_init(kmac, kmac_key) == RET_OK;
        }
        if (reset_ok) {
            reset_ok = hmac_update(kmac, kmac_data) == RET_OK &&
                       hmac_final(kmac, &actual_mac) == RET_OK && actual_mac != nullptr;
        }
        if (reset_ok && expected_mac == nullptr) {
            expected_mac = ba_copy_with_alloc(actual_mac, 0, 0);
            reset_ok = expected_mac != nullptr;
        } else if (reset_ok) {
            reset_ok = ba_cmp(expected_mac, actual_mac) == 0;
        }
        ba_free(actual_mac);
    }
    ExpectTrue(reset_ok,
               "Kupyna KMAC wrapper must support repeated init/final/reset without changing output");
    ba_free(expected_mac);
    hmac_free(kmac);
    ba_free(kmac_data);
    ba_free(kmac_key);

    const std::vector<std::uint8_t> plain_bytes = {
        0x30, 0x0a, 0x02, 0x01, 0x00, 0x04, 0x05, 'T', 'a', 'm', 'g', 'a'};
    const std::vector<std::uint8_t> iv_bytes(32, 0x5a);
    const std::vector<std::uint8_t> salt_bytes = {0x10, 0x20, 0x30, 0x40,
                                                  0x50, 0x60, 0x70, 0x80};

    AlgorithmIdentifier_t* kalyna_aid = aid_alloc();
    GOST28147ParamsOptionalDke_t* kalyna_params =
        static_cast<GOST28147ParamsOptionalDke_t*>(
            std::calloc(1, sizeof(GOST28147ParamsOptionalDke_t)));
    ByteArray* iv = ba_alloc_from_uint8(iv_bytes.data(), iv_bytes.size());
    ByteArray* salt = ba_alloc_from_uint8(salt_bytes.data(), salt_bytes.size());
    ByteArray* plain = ba_alloc_from_uint8(plain_bytes.data(), plain_bytes.size());
    EncryptedPrivateKeyInfo_t* encrypted = nullptr;
    ByteArray* decrypted = nullptr;
    ByteArray* wrong_password_result = nullptr;

    bool setup_ok = kalyna_aid != nullptr && kalyna_params != nullptr && iv != nullptr &&
                    salt != nullptr && plain != nullptr;
    if (setup_ok) {
        setup_ok = pkix_set_oid(oids_get_oid_numbers_by_id(OID_KALYNA256_CBC_ID),
                                &kalyna_aid->algorithm) == RET_OK &&
                   asn_ba2OCTSTRING(iv, &kalyna_params->iv) == RET_OK &&
                   asn_create_any(&GOST28147ParamsOptionalDke_desc, kalyna_params,
                                  &kalyna_aid->parameters) == RET_OK;
    }
    ExpectTrue(setup_ok, "Kalyna-256 CBC AlgorithmIdentifier must be constructed");

    const int encrypt_rc = setup_ok
        ? pkcs5_encrypt_dstu(plain, "secret", salt, 8, kalyna_aid, &encrypted)
        : RET_INVALID_PARAM;
    ExpectTrue(encrypt_rc == RET_OK && encrypted != nullptr,
               "PKCS#5 must encrypt with Kupyna KMAC PBKDF2 and Kalyna-256 CBC");

    const int decrypt_rc = encrypted != nullptr
        ? pkcs5_decrypt_dstu(encrypted, "secret", &decrypted)
        : RET_INVALID_PARAM;
    ExpectTrue(decrypt_rc == RET_OK && decrypted != nullptr && ba_cmp(plain, decrypted) == 0,
               "PKCS#5 Kalyna/Kupyna decrypt must restore the plaintext");

    const int wrong_password_rc = encrypted != nullptr
        ? pkcs5_decrypt_dstu(encrypted, "wrong", &wrong_password_result)
        : RET_INVALID_PARAM;
    ExpectTrue(wrong_password_rc != RET_OK && wrong_password_result == nullptr,
               "PKCS#5 Kalyna/Kupyna decrypt must reject invalid PKCS#7 padding");

    ba_free(wrong_password_result);
    ba_free(decrypted);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, encrypted);
    ba_free(plain);
    ba_free(salt);
    ba_free(iv);
    ASN_FREE(&GOST28147ParamsOptionalDke_desc, kalyna_params);
    aid_free(kalyna_aid);
}

void TestOfflineModePreventsAllHttpTransportCalls() {
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture should be available for offline network-boundary test");
    if (!fixture.valid) return;

    const auto work_dir = MakeTemporaryFixturePath(".offline-network-boundary");
    std::error_code ec;
    std::filesystem::remove_all(work_dir, ec);

    tamga::core::Session session;
    tamga::core::Settings settings;
    settings.offline_mode = true;
    settings.work_dir = work_dir.u8string();
    settings.allow_aia_issuer_fetch = true;  // offline має бути сильнішим за AIA opt-in.
    ExpectTrue(session.SetSettings(settings), "Offline settings should be accepted");
    ExpectTrue(session.Initialize(), "Offline session should initialize");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(fixture.pkcs12_blob, "test", "test", "signer"),
                      "Offline network-boundary test should load key");

    tamga::core::TspSettings tsp;
    tsp.url = "https://tsa.example.test/";
    ExpectTrue(session.SetTspSettings(tsp), "Offline test should accept TSP settings");
    tamga::core::OcspSettings ocsp;
    ocsp.url = "https://ocsp.example.test/";
    ExpectTrue(session.SetOcspSettings(ocsp), "Offline test should accept OCSP settings");

    std::atomic<int> calls{0};
    tamga::core::HttpClient::ScopedMockTransport transport(
        [&calls](const tamga::core::HttpRequest&) {
            ++calls;
            tamga::core::HttpResponse response;
            response.succeeded = true;
            response.status_code = 200;
            return response;
        });

    const std::vector<std::uint8_t> payload = {'o', 'f', 'f', 'l', 'i', 'n', 'e'};
    std::vector<std::uint8_t> timestamped;
    ExpectFalse(session.SignData(payload, timestamped, tamga::core::TimestampMode::Required),
                "Required timestamp must fail in offline mode");
    ExpectTrue(calls.load() == 0, "Offline signing must not invoke TSP transport");

    std::vector<std::uint8_t> signature;
    ExpectSessionTrue(session,
                      session.SignData(payload, signature, tamga::core::TimestampMode::Disabled),
                      "Offline signing without timestamp should succeed");
    bool valid = false;
    ExpectSessionTrue(session, session.VerifyData(payload, signature, valid),
                      "Offline verification should execute without network");
    ExpectTrue(valid, "Offline verification should preserve signature integrity result");
    ExpectTrue(calls.load() == 0, "Offline verification must not invoke OCSP or AIA transport");

    ExpectFalse(session.SyncTrustList(), "Trust-list sync must be rejected in offline mode");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::OnlineServiceUnavailable,
               "Offline trust-list sync should expose an explicit online-service error");
    ExpectTrue(calls.load() == 0, "Offline trust-list sync must not invoke HTTP transport");
    std::filesystem::remove_all(work_dir, ec);
}

void TestCryptoniteOcspResponseErrorPathsAreInitialized() {
    OCSPResponse_t* output = reinterpret_cast<OCSPResponse_t*>(static_cast<std::uintptr_t>(1U));
    const int generate_rc = eocspresp_generate(NULL, NULL, NULL, 0, &output);
    ExpectTrue(generate_rc == RET_INVALID_PARAM,
               "eocspresp_generate should reject invalid input without touching uninitialized storage");
    ExpectTrue(output == NULL, "eocspresp_generate must reset caller output before failing");

    ExpectTrue(eocspresp_form_unauthorized(NULL) == RET_INVALID_PARAM,
               "eocspresp_form_unauthorized(NULL) should return RET_INVALID_PARAM without UB");
    output = NULL;
    ExpectTrue(eocspresp_form_unauthorized(&output) == RET_OK && output != NULL,
               "eocspresp_form_unauthorized should still construct a valid response");
    ocspresp_free(output);
}

// V-03 (регресія): ідентифікатор знімка довірчого списку не має бути локальним шляхом.
//
// Раніше `TrustServiceDecision::snapshot_evidence_id` дорівнював АБСОЛЮТНОМУ
// шляху до `work_dir/trust-list/...` і серіалізувався у публічний звіт як
// `diagnostics.trustList.source`. Наслідком був витік топології машини (диск,
// імʼя користувача) у документ, який 1С може передавати далі, а сам звіт ставав
// недетермінованим: той самий підпис на двох машинах давав різні JSON.
//
// Тест б'є прямо в ValidationEngine, бо саме він формує ідентифікатор; шлях
// через Session сюди не доходить, якщо довірчого списку немає в work_dir.
void TestSnapshotIdIsNotALocalPath() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for the snapshot-id test");
    if (!fixture.valid) {
        return;
    }

    // Каталог із впізнаваним іменем: якби шлях знову потрапив в ідентифікатор,
    // цей маркер знайшовся б у ньому.
    const auto work_dir = MakeTemporaryFixturePath(".v03-snapshot-marker");
    std::error_code ec;
    std::filesystem::create_directories(work_dir / "trust-list", ec);
    const auto tl_xml = BuildGrantedCaTrustListXmlForTest();
    WriteBinaryFile(work_dir / "trust-list" / "TL-UA-EC.xml", tl_xml);

    tamga::core::validation::ValidationContext ctx;
    ctx.profile = tamga::core::validation::ValidationProfile::Compatibility;
    ctx.level = tamga::core::validation::ValidationLevel::Standard;
    ctx.offline = true;
    ctx.work_dir = work_dir.string();
    ctx.signature_crypto_valid = true;

    const auto report =
        tamga::core::validation::ValidationEngine{}.Validate(ctx, fixture.cert_der, {});

    const std::string& id = report.trust_service.snapshot_evidence_id;
    ExpectTrue(report.trust_service.checked,
               "sanity: trust service must be evaluated when a trust list is present");
    ExpectTrue(id.find(".v03-snapshot-marker") == std::string::npos,
               "V-03: snapshot id must not contain the work directory name");
    ExpectTrue(id.find(':') == std::string::npos,
               "V-03: snapshot id must not contain a drive letter or absolute path");
    ExpectTrue(id == "current" || id.rfind("history/", 0) == 0 || id == "unknown",
               "V-03: snapshot id must be a stable identifier");

    std::filesystem::remove_all(work_dir, ec);
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

// O-03 (регресія): вибір сертифіката з ланцюга JKS має спиратися на НАЛЕЖНІСТЬ
// ключу, а не на те, що з ним вдалося щось побудувати.
//
// Раніше FindMatchingCertificate вважала доказом успішну побудову sign-адаптера
// (PreparePkcs8Signer), тоді як авто-резолвер приймав кандидатів за порівнянням
// SubjectPublicKeyInfo. Це два РІЗНІ критерії, і на реальному JKS ПриватБанку
// вони дали протилежні відповіді. Тепер критерій один; тест фіксує саме
// семантику вибору: серед кандидатів мусить бути обраний той, що належить ключу,
// незалежно від його позиції в ланцюгу.
void TestFindMatchingCertificateSelectsByKeyOwnership() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto own = GenerateDstuPkcs8Fixture();
    const auto foreign = GenerateDstuFixture();
    ExpectTrue(own.valid, "PKCS#8 fixture must be generated");
    ExpectTrue(foreign.valid, "foreign fixture must be generated");
    if (!own.valid || !foreign.valid) {
        return;
    }
    ExpectTrue(own.cert_der != foreign.cert_der, "sanity: the two certificates must differ");

    // Чужий сертифікат стоїть ПЕРШИМ: якби вибір ішов за позицією або за самою
    // лише сумісністю алгоритму, обрали б саме його.
    const std::vector<std::vector<std::uint8_t>> chain = {foreign.cert_der, own.cert_der};

    std::vector<std::uint8_t> picked;
    ExpectTrue(tamga::core::CryptoniteAdapter::FindMatchingCertificate(own.pkcs8_der, chain, picked),
               "O-03: a certificate belonging to the key must be found in the chain");

    // ADR-027: інваріант, на якому будувалося злиття чотирьох копій
    // DecodeCertificate. Усі чотири однаково відхиляли порожній вхід — саме це
    // і дозволило звести їх в одну. Якщо спільний декодер колись стане
    // fail-open, злиття перетвориться на регресію, тож інваріант закріплено.
    //
    // Перевірка дописана в НАЯВНИЙ гейтований тест навмисно: окремий тест дав
    // би ще один пропуск у vendor=OFF, а платити пропуском за два рядки
    // асертів немає за що.
    using tamga::core::cryptonite_detail::DecodeCertificateDer;
    using tamga::core::cryptonite_detail::DecodeCertificateDerInto;

    ExpectFalse(DecodeCertificateDer({}) != nullptr,
                "ADR-027: an empty DER must never decode into a certificate");
    ExpectFalse(DecodeCertificateDer({0x30, 0x03, 0x02, 0x01, 0x00}) != nullptr,
                "ADR-027: a well-formed but non-certificate DER must be rejected");
    ExpectTrue(DecodeCertificateDer(own.cert_der) != nullptr,
               "ADR-027: a real certificate must still decode");
    ExpectFalse(DecodeCertificateDerInto({}, nullptr),
                "ADR-027: decoding into a null certificate must fail, not crash");
    ExpectTrue(picked == own.cert_der,
               "O-03: the certificate selected must be the one that BELONGS to the key");

    // Ланцюг лише з чужих сертифікатів -> нічого не обирається (fail-closed).
    std::vector<std::uint8_t> none;
    ExpectFalse(tamga::core::CryptoniteAdapter::FindMatchingCertificate(
                    own.pkcs8_der, {foreign.cert_der}, none),
                "O-03: a chain without the owner certificate must yield nothing");

    // Той самий вердикт, що й у гейті авто-резолвера — критерій справді один.
    ExpectTrue(tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(
                   own.pkcs8_der, "", own.cert_der),
               "O-03: both paths must agree on the owner certificate");
    ExpectFalse(tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(
                    own.pkcs8_der, "", foreign.cert_der),
                "O-03: both paths must agree on the foreign certificate");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

// V-06 (регресія): SPKI, витягнутий із "голого" PKCS#8, мусить бути
// ПОРІВНЯННИМ зі SPKI сертифіката.
//
// Дефект, який цей тест закриває: гілка PKCS#8 у ExtractSpkiFromKeyContainer
// використовувала pkcs8_get_spki і давала структуру, що закінчується
// OCTET STRING (72 байти на реальному ключі), тоді як SPKI сертифіката —
// 136 байтів із BIT STRING. Байтове порівняння в CertificateMatchesPrivateKey
// не сходилось НІКОЛИ, а оскільки це єдиний гейт приймання в
// CertificateResolver, для JKS/PKCS#8-ключів відкидались УСІ кандидати —
// sidecar, кеш і мережа. Рівні 1-3 були непрацездатні для цілого класу
// контейнерів.
//
// Тестів це не ловило, бо LoadResolverKeyPair будує лише PKCS#12.
void TestPkcs8SpkiIsComparableWithCertificate() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuPkcs8Fixture();
    ExpectTrue(fixture.valid, "PKCS#8 DSTU fixture must be generated");
    if (!fixture.valid) {
        return;
    }

    std::vector<std::uint8_t> key_spki;
    std::string err;
    ExpectTrue(tamga::core::CryptoniteAdapter::ExtractSubjectPublicKeyInfo(
                   fixture.pkcs8_der, "", key_spki, err),
               "SPKI must be extractable from a bare PKCS#8 key");
    ExpectFalse(key_spki.empty(), "extracted SPKI must not be empty");

    // Структурний інваріант: SubjectPublicKeyInfo — це SEQUENCE, останній
    // елемент якого BIT STRING (0x03). Стара реалізація давала OCTET STRING,
    // тобто взагалі не SPKI. Ця перевірка ловить дефект незалежно від того,
    // чи є під рукою відповідний сертифікат.
    ExpectTrue(!key_spki.empty() && key_spki.front() == 0x30,
               "V-06: SPKI must be a DER SEQUENCE");
    bool has_bit_string = false;
    for (std::size_t i = 0; i + 1 < key_spki.size(); ++i) {
        if (key_spki[i] == 0x03 && i > 2) {
            has_bit_string = true;
        }
    }
    ExpectTrue(has_bit_string,
               "V-06: SPKI must carry a BIT STRING public key, not an OCTET STRING private value");

    // Головне: та сама кодування, що й у сертифіката цього ключа.
    std::vector<std::uint8_t> cert_spki;
    ExpectTrue(tamga::core::CryptoniteAdapter::ExtractCertificateSubjectPublicKeyInfo(
                   fixture.cert_der, cert_spki, err),
               "SPKI must be extractable from the certificate");
    ExpectTrue(key_spki == cert_spki,
               "V-06: SPKI from PKCS#8 and from its certificate must be byte-identical");

    // Наскрізна перевірка через той самий гейт, який використовує резолвер.
    ExpectTrue(tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(
                   fixture.pkcs8_der, "", fixture.cert_der),
               "V-06: the matching certificate must be ACCEPTED for a PKCS#8 key");

    // Негатив: чужий сертифікат мусить бути відхилений (fail-closed не зламано).
    const auto other = GenerateDstuFixture();
    if (other.valid && !other.cert_der.empty()) {
        ExpectFalse(tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(
                        fixture.pkcs8_der, "", other.cert_der),
                    "V-06: a foreign certificate must still be REJECTED for a PKCS#8 key");
    }
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}
#endif  // TAMGA_CRYPTONITE_ENABLED
