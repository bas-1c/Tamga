// Регресія: підпис контейнером PKCS#12 БЕЗ `certBag` із зовнішнім сертифікатом.
//
// Українські КНЕДП (Вчасно, ДПС, ІІТ) видають `.dat`/`.pfx`, у яких лежать лише
// `pkcs8ShroudedKeyBag` — сертифіката всередині немає. До 2026-09-02
// `PreparePkcs12Signer` брав сертифікат ВИКЛЮЧНО з контейнера, тому:
//
//   * `pkcs12_get_certificate()` повертав RET_STORAGE_CERT_NOT_FOUND (rc=525),
//     і підпис падав навіть тоді, коли авто-резолвер сесії вже знайшов
//     правильний сертифікат (явний шлях / sidecar `.cer` / кеш / LDAP);
//   * після першої спроби виправлення сертифікат передавався окремим
//     out-параметром, але не потрапляв у сам `SignAdapter`, і наступний крок
//     `esigner_info_alloc()` падав із RET_PKIX_NO_CERTIFICATE (rc=272).
//
// Тест будує ключ і самопідписаний сертифікат до нього, кодує контейнер БЕЗ
// виклику `pkcs12_set_certificates()` і перевіряє обидві властивості:
//   1) із правильним зовнішнім сертифікатом підпис створюється;
//   2) із сертифікатом ЧУЖОГО ключа підпис НЕ створюється (fail-closed).
//
// Третій випадок (2026-09-02) стереже вибір ключа в «універсальному» контейнері.
// КНЕДП («Вчасно», ДПС, ІІТ) кладуть у той самий `.dat` ДВА закритих ключі:
// ключ підпису (digitalSignature/nonRepudiation) і ключ протоколів розподілу
// ключів (keyAgreement/dataEncipherment). `pkcs12_select_key(ctx, nullptr, pwd)`
// бере ПЕРШИЙ ключ у контейнері, тож коли ключ підпису лежить другим, підпис
// падав із RET_PKIX_NO_CERTIFICATE (rc=272) — «сертифікат не відповідає ключу»,
// хоча сертифікат був правильний. Фікстура `BuildTwoKeyContainer()` відтворює
// саме такий порядок: сертифікат відповідає ДРУГОМУ ключу.

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "core/CryptoniteAdapter.h"
#include "core/Session.h"
#include "core/cryptonite/KeyPairing.h"
#include "core/net/CertificateResolver.h"
#include "util/Base64.h"

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
#include "exts.h"
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

bool Require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
    }
    return condition;
}

#if TAMGA_CRYPTONITE_ENABLED

// Призначення ключа для тестового сертифіката. `kNoKeyUsage` — розширення
// взагалі немає (так виглядають сертифікати, для яких гейт keyUsage не має
// відмовляти).
constexpr int kNoKeyUsage = 0;

// Самопідписаний сертифікат до ключа, ВИБРАНОГО в сховищі (`pkcs12_select_key`).
// Винесено окремо, бо потрібне і для однокключового контейнера, і для
// «універсального» з двома ключами.
bool BuildSelfSignedCertificate(Pkcs12Ctx* storage,
                                const char* subject,
                                int key_usage_bits,
                                std::vector<std::uint8_t>& cert_der) {
    SignAdapter* sa = nullptr;
    VerifyAdapter* va = nullptr;
    DigestAdapter* da = nullptr;
    SubjectPublicKeyInfo_t* spki = nullptr;
    CertificateRequestEngine* creq_eng = nullptr;
    CertificationRequest_t* cert_req = nullptr;
    CertificateEngine* cert_eng = nullptr;
    Certificate_t* cert = nullptr;
    ByteArray* cert_encoded = nullptr;
    Extensions_t* exts = nullptr;
    Extension_t* key_usage_ext = nullptr;
    int rc = 0;
    bool ok = false;

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
    rc = ecert_request_set_subj_name(creq_eng, subject);
    if (rc != 0) goto cleanup;
    rc = ecert_request_generate(creq_eng, &cert_req);
    if (rc != 0) goto cleanup;
    rc = ecert_alloc(sa, da, true, &cert_eng);
    if (rc != 0) goto cleanup;

    // keyUsage додається лише коли його явно замовили: сертифікат БЕЗ цього
    // розширення — теж робочий випадок, і гейт не має його відхиляти.
    if (key_usage_bits != kNoKeyUsage) {
        exts = exts_alloc();
        if (exts == nullptr) goto cleanup;
        rc = ext_create_key_usage(true, static_cast<KeyUsageBits>(key_usage_bits), &key_usage_ext);
        if (rc != 0) goto cleanup;
        rc = exts_add_extension(exts, key_usage_ext);
        if (rc != 0) goto cleanup;
    }

    {
        const unsigned char serial_bytes[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
        ByteArray* serial_ba = ba_alloc_from_uint8(serial_bytes, sizeof(serial_bytes));
        time_t not_before = std::time(nullptr) - 86400;
        time_t not_after = not_before + 365 * 86400;
        rc = ecert_generate(cert_eng, cert_req, 2, serial_ba, &not_before, &not_after, exts, &cert);
        ba_free(serial_ba);
    }
    if (rc != 0) goto cleanup;

    rc = cert_encode(cert, &cert_encoded);
    if (rc != 0) goto cleanup;
    cert_der.assign(ba_get_buf(cert_encoded), ba_get_buf(cert_encoded) + ba_get_len(cert_encoded));

    ok = true;

cleanup:
    ext_free(key_usage_ext);
    exts_free(exts);
    ba_free(cert_encoded);
    cert_free(cert);
    ecert_free(cert_eng);
    if (cert_req != nullptr) {
        ASN_FREE(get_CertificationRequest_desc(), cert_req);
    }
    ecert_request_free(creq_eng);
    spki_free(spki);
    digest_adapter_free(da);
    verify_adapter_free(va);
    sign_adapter_free(sa);
    return ok;
}

// AlgorithmIdentifier для ДСТУ 4145-2002 (M257_PB + ГОСТ 28147 S-box #1).
bool BuildDstu4145Aid(ByteArray** aid_ba) {
    Dstu4145Ctx* ec_params = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);
    Gost28147Ctx* cipher_params = gost28147_alloc(GOST28147_SBOX_ID_1);
    AlgorithmIdentifier_t* aid = nullptr;
    int rc = 0;
    bool ok = false;

    if (ec_params == nullptr || cipher_params == nullptr) goto cleanup;
    rc = aid_create_dstu4145(ec_params, cipher_params, true, &aid);
    if (rc != 0) goto cleanup;
    rc = aid_encode(aid, aid_ba);
    if (rc != 0) goto cleanup;
    ok = true;

cleanup:
    aid_free(aid);
    gost28147_free(cipher_params);
    dstu4145_free(ec_params);
    return ok;
}

// Створює PKCS#12 БЕЗ certBag і самопідписаний сертифікат до того ж ключа.
bool BuildKeyWithoutCertBag(const char* subject,
                            std::vector<std::uint8_t>& pkcs12_der,
                            std::vector<std::uint8_t>& cert_der,
                            int key_usage_bits = kNoKeyUsage,
                            std::vector<std::uint8_t>* second_cert_der = nullptr) {
    ByteArray* aid_ba = nullptr;
    Pkcs12Ctx* storage = nullptr;
    ByteArray* storage_body = nullptr;
    int rc = 0;
    bool ok = false;

    if (!BuildDstu4145Aid(&aid_ba)) goto cleanup;

    rc = pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, "test", 1024, &storage);
    if (rc != 0) goto cleanup;
    rc = pkcs12_generate_key(storage, aid_ba);
    if (rc != 0) goto cleanup;
    rc = pkcs12_store_key(storage, "signer", "test", 1024);
    if (rc != 0) goto cleanup;
    rc = pkcs12_select_key(storage, "signer", "test");
    if (rc != 0) goto cleanup;

    if (!BuildSelfSignedCertificate(storage, subject, key_usage_bits, cert_der)) goto cleanup;
    if (second_cert_der != nullptr &&
        !BuildSelfSignedCertificate(storage,
                                    "{CN=Tamga Cached Certificate}{O=Tamga}{C=UA}",
                                    key_usage_bits,
                                    *second_cert_der)) {
        goto cleanup;
    }

    // САМЕ ТУТ суть фікстури: `pkcs12_set_certificates()` НЕ викликається, тому
    // закодований контейнер не має certBag — так само, як `.dat` від КНЕДП.
    rc = pkcs12_encode(storage, &storage_body);
    if (rc != 0) goto cleanup;
    pkcs12_der.assign(ba_get_buf(storage_body), ba_get_buf(storage_body) + ba_get_len(storage_body));

    ok = true;

cleanup:
    ba_free(storage_body);
    pkcs12_free(storage);
    ba_free(aid_ba);
    return ok;
}

// «Універсальний» контейнер КНЕДП: ДВА закритих ключі без certBag.
// Перший ключ (alias `key-agreement`) імітує ключ протоколів розподілу ключів,
// другий (alias `signature`) — ключ підпису. Повертає самопідписані сертифікати
// до ОБОХ ключів, щоб перевірити і «сертифікат до другого ключа», і
// «сертифікат до першого ключа» (щоб виправлення не зламало типовий порядок).
bool BuildTwoKeyContainer(std::vector<std::uint8_t>& pkcs12_der,
                          std::vector<std::uint8_t>& first_key_cert_der,
                          std::vector<std::uint8_t>& second_key_cert_der,
                          int first_key_usage_bits = kNoKeyUsage,
                          int second_key_usage_bits = kNoKeyUsage) {
    ByteArray* aid_ba = nullptr;
    Pkcs12Ctx* storage = nullptr;
    ByteArray* storage_body = nullptr;
    int rc = 0;
    bool ok = false;

    if (!BuildDstu4145Aid(&aid_ba)) goto cleanup;

    rc = pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, "test", 1024, &storage);
    if (rc != 0) goto cleanup;

    // Ключ №1 — «розподіл ключів». Саме він потрапляє в контейнер першим і саме
    // його бере `pkcs12_select_key(ctx, nullptr, pwd)`.
    rc = pkcs12_generate_key(storage, aid_ba);
    if (rc != 0) goto cleanup;
    rc = pkcs12_store_key(storage, "key-agreement", "test", 1024);
    if (rc != 0) goto cleanup;

    // Ключ №2 — «підпис».
    rc = pkcs12_generate_key(storage, aid_ba);
    if (rc != 0) goto cleanup;
    rc = pkcs12_store_key(storage, "signature", "test", 1024);
    if (rc != 0) goto cleanup;

    rc = pkcs12_select_key(storage, "key-agreement", "test");
    if (rc != 0) goto cleanup;
    if (!BuildSelfSignedCertificate(storage, "{CN=Tamga Key Agreement}{O=Tamga}{C=UA}",
                                    first_key_usage_bits, first_key_cert_der)) {
        goto cleanup;
    }

    rc = pkcs12_select_key(storage, "signature", "test");
    if (rc != 0) goto cleanup;
    if (!BuildSelfSignedCertificate(storage, "{CN=Tamga Signature}{O=Tamga}{C=UA}",
                                    second_key_usage_bits, second_key_cert_der)) {
        goto cleanup;
    }

    rc = pkcs12_encode(storage, &storage_body);
    if (rc != 0) goto cleanup;
    pkcs12_der.assign(ba_get_buf(storage_body), ba_get_buf(storage_body) + ba_get_len(storage_body));

    ok = true;

cleanup:
    ba_free(storage_body);
    pkcs12_free(storage);
    ba_free(aid_ba);
    return ok;
}

bool RunExternalCertificateAcceptedCase() {
    std::vector<std::uint8_t> pkcs12_der;
    std::vector<std::uint8_t> cert_der;
    if (!Require(BuildKeyWithoutCertBag("{CN=Tamga No CertBag}{O=Tamga}{C=UA}", pkcs12_der, cert_der),
                 "fixture: PKCS#12 without certBag must be built")) {
        return false;
    }

    const std::vector<std::uint8_t> data{'T', 'a', 'm', 'g', 'a'};
    std::vector<std::uint8_t> signature;
    std::string error_message;

    const bool signed_ok = tamga::core::CryptoniteAdapter::SignDetached(
        /*use_pkcs12=*/true, pkcs12_der, cert_der, "test", data, signature, error_message);

    if (!signed_ok) {
        std::cerr << "  cryptonite: " << error_message << "\n";
    }
    return Require(signed_ok,
                   "PKCS#12 without certBag must sign when the certificate comes from the resolver") &&
           Require(!signature.empty(), "detached CMS must not be empty");
}

bool RunForeignCertificateRejectedCase() {
    std::vector<std::uint8_t> pkcs12_der;
    std::vector<std::uint8_t> own_cert;
    std::vector<std::uint8_t> foreign_pkcs12;
    std::vector<std::uint8_t> foreign_cert;

    if (!Require(BuildKeyWithoutCertBag("{CN=Tamga Own Key}{O=Tamga}{C=UA}", pkcs12_der, own_cert) &&
                     BuildKeyWithoutCertBag("{CN=Tamga Foreign Key}{O=Tamga}{C=UA}", foreign_pkcs12,
                                            foreign_cert),
                 "fixture: two independent keys must be built")) {
        return false;
    }

    const std::vector<std::uint8_t> data{'T', 'a', 'm', 'g', 'a'};
    std::vector<std::uint8_t> signature;
    std::string error_message;

    // Сертифікат ЧУЖОГО ключа: `SignAdapter::set_cert` звіряє відповідність
    // закритому ключу, тому підпис має бути відхилений.
    const bool signed_ok = tamga::core::CryptoniteAdapter::SignDetached(
        /*use_pkcs12=*/true, pkcs12_der, foreign_cert, "test", data, signature, error_message);

    return Require(!signed_ok, "certificate of a different key must be rejected") &&
           Require(signature.empty(), "no signature bytes may be produced on rejection");
}

// Головний регрес: у контейнері два ключі, потрібен ДРУГИЙ.
// До виправлення `PreparePkcs12Signer` брав перший ключ і падав на `set_cert`
// із RET_PKIX_NO_CERTIFICATE (rc=272).
bool RunSecondKeySelectedByCertificateCase() {
    std::vector<std::uint8_t> pkcs12_der;
    std::vector<std::uint8_t> first_key_cert;
    std::vector<std::uint8_t> second_key_cert;

    if (!Require(BuildTwoKeyContainer(pkcs12_der, first_key_cert, second_key_cert),
                 "fixture: PKCS#12 with two keys must be built")) {
        return false;
    }

    const std::vector<std::uint8_t> data{'T', 'a', 'm', 'g', 'a'};
    bool ok = true;

    // Гейт авто-резолвера (`CertificateResolver` приймає кандидата лише через
    // `CertificateMatchesPrivateKey`) стоїть ПЕРЕД підписом. Поки він дивився
    // тільки на перший ключ, сертифікат другого ключа відхилявся з
    // «does not match the private key in the container», і виправлений вибір
    // ключа в signer до роботи не доходив.
    ok = Require(tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(pkcs12_der, "test",
                                                                             second_key_cert),
                 "certificate of the second key must be recognized as belonging to the container") &&
         ok;
    ok = Require(tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(pkcs12_der, "test",
                                                                             first_key_cert),
                 "certificate of the first key must still be recognized") &&
         ok;

    {
        std::vector<std::uint8_t> signature;
        std::string error_message;
        const bool signed_ok = tamga::core::CryptoniteAdapter::SignDetached(
            /*use_pkcs12=*/true, pkcs12_der, second_key_cert, "test", data, signature, error_message);
        if (!signed_ok) {
            std::cerr << "  cryptonite (second key): " << error_message << "\n";
        }
        ok = Require(signed_ok,
                     "container with two keys must sign with the key matching the certificate") &&
             Require(!signature.empty(), "detached CMS must not be empty for the second key") && ok;
    }

    // Дзеркальний випадок: сертифікат до ПЕРШОГО ключа має працювати так само,
    // тобто новий перебір не має зламати типовий порядок «ключ підпису перший».
    {
        std::vector<std::uint8_t> signature;
        std::string error_message;
        const bool signed_ok = tamga::core::CryptoniteAdapter::SignDetached(
            /*use_pkcs12=*/true, pkcs12_der, first_key_cert, "test", data, signature, error_message);
        if (!signed_ok) {
            std::cerr << "  cryptonite (first key): " << error_message << "\n";
        }
        ok = Require(signed_ok, "container with two keys must still sign with the first key") &&
             Require(!signature.empty(), "detached CMS must not be empty for the first key") && ok;
    }

    // Fail-closed лишається: сертифікат, якого немає в контейнері, відхиляється,
    // а не «підбирається» до якогось із двох ключів.
    {
        std::vector<std::uint8_t> foreign_pkcs12;
        std::vector<std::uint8_t> foreign_cert;
        if (!Require(BuildKeyWithoutCertBag("{CN=Tamga Foreign Key}{O=Tamga}{C=UA}", foreign_pkcs12,
                                            foreign_cert),
                     "fixture: independent foreign key must be built")) {
            return false;
        }

        ok = Require(!tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(pkcs12_der, "test",
                                                                                  foreign_cert),
                     "certificate of an unrelated key must not be recognized") &&
             ok;

        std::vector<std::uint8_t> signature;
        std::string error_message;
        const bool signed_ok = tamga::core::CryptoniteAdapter::SignDetached(
            /*use_pkcs12=*/true, pkcs12_der, foreign_cert, "test", data, signature, error_message);
        ok = Require(!signed_ok, "certificate of a key absent from the container must be rejected") &&
             Require(signature.empty(), "no signature bytes may be produced on rejection") && ok;
    }

    return ok;
}

// O-02: знімок відкритих ключів контейнера мусить лишатися ПОВНИМ.
//
// Резолвер більше не розкриває контейнер на кожного кандидата — він один раз
// бере `ContainerPublicKeys` і звіряє кандидатів із цим знімком. Уся підтримка
// «універсальних» контейнерів КНЕДП тепер тримається на тому, що знімок
// містить SPKI ОБОХ ключів. Якщо майбутня правка тихо зведе його до першого
// ключа, поведінка відкотиться рівно до дефекту 2026-09-02 — сертифікат
// другого ключа знову відхилятиметься. Цей випадок стереже саме це.
//
// Другий бік інваріанта: знімок дає ТІ САМІ відповіді, що й одноразова
// `CertificateMatchesPrivateKey`. Розходження між двома критеріями належності
// вже коштувало репозиторію окремого розслідування (див. O-03), тож рівність
// перевіряється явно, а не припускається.
bool RunContainerPublicKeysSnapshotCase() {
    std::vector<std::uint8_t> pkcs12_der;
    std::vector<std::uint8_t> first_key_cert;
    std::vector<std::uint8_t> second_key_cert;

    if (!Require(BuildTwoKeyContainer(pkcs12_der, first_key_cert, second_key_cert),
                 "fixture: PKCS#12 with two keys must be built")) {
        return false;
    }

    tamga::core::ContainerPublicKeys keys;
    std::string error_message;
    bool ok = Require(
        tamga::core::ContainerPublicKeys::Load(pkcs12_der, "test", keys, error_message),
        "the container public-key snapshot must load");
    if (!ok) {
        std::cerr << "  cryptonite: " << error_message << "\n";
        return false;
    }

    ok = Require(keys.Size() == 2,
                 "the snapshot must enumerate BOTH keys of a universal container") && ok;
    ok = Require(keys.Matches(first_key_cert),
                 "the snapshot must match the certificate of the first key") && ok;
    ok = Require(keys.Matches(second_key_cert),
                 "the snapshot must match the certificate of the second key") && ok;

    // Fail-closed: чужий сертифікат не приймається знімком так само, як не
    // приймався одноразовою перевіркою.
    std::vector<std::uint8_t> foreign_pkcs12;
    std::vector<std::uint8_t> foreign_cert;
    if (!Require(BuildKeyWithoutCertBag("{CN=Tamga Snapshot Foreign}{O=Tamga}{C=UA}",
                                        foreign_pkcs12, foreign_cert),
                 "fixture: independent foreign key must be built")) {
        return false;
    }
    ok = Require(!keys.Matches(foreign_cert),
                 "the snapshot must never match a certificate of an unrelated key") && ok;
    ok = Require(!keys.Matches({}), "an empty candidate must never match") && ok;

    // Знімок і одноразова перевірка мають бути ОДНИМ критерієм, а не двома.
    for (const auto& candidate : {first_key_cert, second_key_cert, foreign_cert}) {
        ok = Require(keys.Matches(candidate) ==
                         tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(
                             pkcs12_der, "test", candidate),
                     "the snapshot must agree with CertificateMatchesPrivateKey") && ok;
    }

    // Порожній знімок не приймає нічого — саме на це спирається fail-closed
    // гілка резолвера, коли контейнер розкрити не вдалося.
    tamga::core::ContainerPublicKeys empty;
    ok = Require(empty.Empty(), "a default-constructed snapshot must be empty") && ok;
    ok = Require(!empty.Matches(first_key_cert),
                 "an empty snapshot must reject even a genuine certificate") && ok;

    std::string load_error;
    tamga::core::ContainerPublicKeys unusable;
    ok = Require(!tamga::core::ContainerPublicKeys::Load({}, "test", unusable, load_error),
                 "loading a snapshot from empty key material must fail") && ok;
    ok = Require(!load_error.empty(), "a failed snapshot load must explain itself") && ok;

    return ok;
}

// Гейт призначення ключа: сертифікат, чий `keyUsage` не дозволяє підпис, не
// підписує — ні в контейнері з двома ключами, ні в контейнері з одним.
//
// Без гейта цей випадок проходить «успішно»: вибір ключа за сертифікатом
// (2026-09-02) знімає обмеження «лише перший ключ», і сертифікат ключа
// протоколів розподілу ключів починає знаходити свій ключ. Виміряно на
// реальному ключі КНЕДП «Вчасно»: `--cert CA-…194A3800.cer`
// (keyUsage=keyAgreement) давав CMS 2876 Б замість відмови.
bool RunKeyUsageGateCase() {
    const std::vector<std::uint8_t> data{'T', 'a', 'm', 'g', 'a'};
    bool ok = true;

    // Контейнер «як у КНЕДП»: ключ підпису і ключ протоколів розподілу ключів,
    // кожен зі своїм сертифікатом і РЕАЛЬНИМИ бітами keyUsage.
    std::vector<std::uint8_t> pkcs12_der;
    std::vector<std::uint8_t> signing_cert;
    std::vector<std::uint8_t> key_agreement_cert;
    if (!Require(BuildTwoKeyContainer(pkcs12_der, signing_cert, key_agreement_cert,
                                      KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_NON_REPUDIATION,
                                      KEY_USAGE_KEY_AGREEMENT),
                 "fixture: two-key container with explicit keyUsage must be built")) {
        return false;
    }

    {
        std::vector<std::uint8_t> signature;
        std::string error_message;
        const bool signed_ok = tamga::core::CryptoniteAdapter::SignDetached(
            /*use_pkcs12=*/true, pkcs12_der, key_agreement_cert, "test", data, signature,
            error_message);
        ok = Require(!signed_ok, "certificate with keyUsage=keyAgreement must not sign") &&
             Require(signature.empty(), "no signature bytes may be produced for a key-agreement cert") &&
             // Повідомлення має називати причину, а не бути дампом rc.
             Require(error_message.find("keyUsage") != std::string::npos,
                     "rejection message must name keyUsage as the reason") &&
             ok;
        if (!signed_ok) {
            std::cerr << "  (expected) " << error_message << "\n";
        }
    }

    // Той самий контейнер, сертифікат ключа ПІДПИСУ: підпис має працювати.
    {
        std::vector<std::uint8_t> signature;
        std::string error_message;
        const bool signed_ok = tamga::core::CryptoniteAdapter::SignDetached(
            /*use_pkcs12=*/true, pkcs12_der, signing_cert, "test", data, signature, error_message);
        if (!signed_ok) {
            std::cerr << "  cryptonite (signing cert): " << error_message << "\n";
        }
        ok = Require(signed_ok, "certificate with digitalSignature+nonRepudiation must still sign") &&
             Require(!signature.empty(), "detached CMS must not be empty for the signing certificate") &&
             ok;
    }

    // Контейнер з ОДНИМ ключем: гейт не залежить від кількості ключів.
    {
        std::vector<std::uint8_t> single_key_der;
        std::vector<std::uint8_t> single_key_cert;
        if (!Require(BuildKeyWithoutCertBag("{CN=Tamga Single Enc Key}{O=Tamga}{C=UA}", single_key_der,
                                            single_key_cert, KEY_USAGE_KEY_AGREEMENT),
                     "fixture: single key with keyAgreement certificate must be built")) {
            return false;
        }
        std::vector<std::uint8_t> signature;
        std::string error_message;
        const bool signed_ok = tamga::core::CryptoniteAdapter::SignDetached(
            /*use_pkcs12=*/true, single_key_der, single_key_cert, "test", data, signature,
            error_message);
        ok = Require(!signed_ok, "key-agreement certificate must not sign even with a single key") &&
             Require(signature.empty(), "no signature bytes may be produced in the single-key case") &&
             ok;
    }

    // Сертифікат БЕЗ розширення keyUsage лишається дозволеним (RFC 5280 його не
    // вимагає). Це стереже від надто суворого гейта — саме цю властивість
    // перевіряють і два перші випадки файлу, але тут вона названа явно.
    {
        std::vector<std::uint8_t> plain_key_der;
        std::vector<std::uint8_t> plain_cert;
        if (!Require(BuildKeyWithoutCertBag("{CN=Tamga No KeyUsage}{O=Tamga}{C=UA}", plain_key_der,
                                            plain_cert, kNoKeyUsage),
                     "fixture: certificate without keyUsage must be built")) {
            return false;
        }
        std::vector<std::uint8_t> signature;
        std::string error_message;
        const bool signed_ok = tamga::core::CryptoniteAdapter::SignDetached(
            /*use_pkcs12=*/true, plain_key_der, plain_cert, "test", data, signature, error_message);
        if (!signed_ok) {
            std::cerr << "  cryptonite (no keyUsage): " << error_message << "\n";
        }
        ok = Require(signed_ok, "certificate without keyUsage extension must still sign") && ok;
    }

    return ok;
}

bool WriteBinaryFile(const std::filesystem::path& path,
                     const std::vector<std::uint8_t>& bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    return stream.good();
}

// Sidecar із тим самим stem має найвищий пріоритет, але не може «перемогти»
// лише через ім'я, якщо це сертифікат ключа узгодження. Резолвер повинен
// пропустити його й знайти в каталозі сертифікат ключа підпису.
bool RunResolverSkipsKeyAgreementSidecarCase() {
    std::vector<std::uint8_t> pkcs12_der;
    std::vector<std::uint8_t> key_agreement_cert;
    std::vector<std::uint8_t> signing_cert;
    if (!Require(BuildTwoKeyContainer(pkcs12_der, key_agreement_cert, signing_cert,
                                      KEY_USAGE_KEY_AGREEMENT,
                                      KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_NON_REPUDIATION),
                 "fixture: dual-key container with signing and key-agreement certificates")) {
        return false;
    }

    const auto suffix = std::to_string(static_cast<unsigned long long>(std::time(nullptr)));
    const std::filesystem::path temp_dir =
        std::filesystem::temp_directory_path() / ("tamga-sidecar-" + suffix);
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);
    if (!Require(std::filesystem::create_directories(temp_dir, ec) && !ec,
                 "fixture: temporary sidecar directory must be created")) {
        return false;
    }

    const auto key_path = temp_dir / "signer.dat";
    const auto wrong_sidecar_path = temp_dir / "signer.crt";
    const auto signing_path = temp_dir / "signing.cer";
    bool ok = Require(WriteBinaryFile(key_path, pkcs12_der) &&
                          WriteBinaryFile(wrong_sidecar_path, key_agreement_cert) &&
                          WriteBinaryFile(signing_path, signing_cert),
                      "fixture: key and sidecar files must be written");

    tamga::core::net::CertificateResolveRequest request;
    request.key_material = pkcs12_der;
    request.password = "test";
    request.key_file_path = key_path.u8string();
    request.offline_mode = true;

    tamga::core::net::CertificateResolver resolver;
    const auto resolved = resolver.Resolve(request);
    ok = Require(resolved.succeeded,
                 "resolver must continue after a matching key-agreement sidecar") && ok;
    ok = Require(resolved.certificate_der == signing_cert,
                 "resolver must select the certificate whose keyUsage allows signing") && ok;
    ok = Require(resolved.rejected_candidates >= 1,
                 "resolver must report the rejected key-agreement sidecar") && ok;

    std::filesystem::remove_all(temp_dir, ec);
    return ok;
}

// Однойменний sidecar є явною локальною підказкою користувача і тому має
// випереджати кеш. Обидва сертифікати нижче видані на ТОЙ САМИЙ відкритий
// ключ і дозволяють підпис: звичайна перевірка належності не відрізнить
// перевиданий sidecar від старішої кешованої копії.
bool RunResolverPrefersSameStemSidecarOverCacheCase() {
    std::vector<std::uint8_t> pkcs12_der;
    std::vector<std::uint8_t> sidecar_cert;
    std::vector<std::uint8_t> cached_cert;
    if (!Require(BuildKeyWithoutCertBag(
                     "{CN=Tamga Sidecar Certificate}{O=Tamga}{C=UA}",
                     pkcs12_der,
                     sidecar_cert,
                     KEY_USAGE_DIGITAL_SIGNATURE,
                     &cached_cert),
                 "fixture: one key with two distinct signing certificates")) {
        return false;
    }

    bool ok = Require(sidecar_cert != cached_cert,
                      "fixture: sidecar and cached certificates must be distinct") &&
              Require(tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(
                          pkcs12_der, "test", sidecar_cert),
                      "fixture: sidecar certificate must belong to the key") &&
              Require(tamga::core::CryptoniteAdapter::CertificateMatchesPrivateKey(
                          pkcs12_der, "test", cached_cert),
                      "fixture: cached certificate must belong to the same key");

    const auto suffix = std::to_string(static_cast<unsigned long long>(std::time(nullptr)));
    const std::filesystem::path temp_dir =
        std::filesystem::temp_directory_path() / ("tamga-sidecar-cache-" + suffix);
    const auto work_dir = temp_dir / "work";
    const auto key_path = temp_dir / "signer.dat";
    const auto sidecar_path = temp_dir / "signer.crt";
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);
    if (!Require(std::filesystem::create_directories(work_dir / "cert-cache", ec) && !ec,
                 "fixture: cache directory must be created")) {
        return false;
    }

    std::string fingerprint;
    std::string fingerprint_error;
    if (!Require(tamga::core::net::CertificateResolver::ComputeSpkiFingerprint(
                     pkcs12_der, "test", fingerprint, fingerprint_error),
                 "fixture: key SPKI fingerprint must be computed")) {
        std::filesystem::remove_all(temp_dir, ec);
        return false;
    }
    const auto cache_path = work_dir / "cert-cache" / (fingerprint + ".cer");
    ok = Require(WriteBinaryFile(key_path, pkcs12_der) &&
                     WriteBinaryFile(sidecar_path, sidecar_cert) &&
                     WriteBinaryFile(cache_path, cached_cert),
                 "fixture: key, same-stem sidecar and cache entry must be written") &&
         ok;

    tamga::core::net::CertificateResolveRequest request;
    request.key_material = pkcs12_der;
    request.password = "test";
    request.key_file_path = key_path.u8string();
    request.work_dir = work_dir.u8string();
    request.offline_mode = true;

    const auto resolved = tamga::core::net::CertificateResolver{}.Resolve(request);
    ok = Require(resolved.succeeded, "resolver must select a local certificate") && ok;
    ok = Require(resolved.source == "sidecar",
                 "same-stem sidecar must have priority over a valid cache entry") && ok;
    ok = Require(resolved.certificate_der == sidecar_cert,
                 "resolver must return the user-supplied same-stem certificate") && ok;

    std::filesystem::remove_all(temp_dir, ec);
    return ok;
}

// `rc=525` не повинен виходити назовні як внутрішній номер cryptonite.
bool RunMissingCertificateDiagnosticCase() {
    std::vector<std::uint8_t> pkcs12_der;
    std::vector<std::uint8_t> unused_cert;
    if (!Require(BuildKeyWithoutCertBag("{CN=Tamga Missing Cert}{O=Tamga}{C=UA}",
                                        pkcs12_der, unused_cert),
                 "fixture: certificate-less PKCS#12 must be built")) {
        return false;
    }

    std::vector<std::uint8_t> signature;
    std::string error_message;
    const bool signed_ok = tamga::core::CryptoniteAdapter::SignDetached(
        /*use_pkcs12=*/true, pkcs12_der, {}, "test", {'T', 'a', 'm', 'g', 'a'},
        signature, error_message);
    return Require(!signed_ok, "signing without a certificate must fail") &&
           Require(error_message.find(
                       "Не знайдено відкритий сертифікат для закритого ключа") !=
                       std::string::npos,
                   "missing-certificate error must explain how to provide a sidecar");
}

// Регресія: пароль `.ZS2`/PKCS#12, переданий лише як `keyPassword`, має
// використовуватися і під час звірки зовнішнього сертифіката, і signer-ом.
bool RunSessionKeyPasswordOnlyCase() {
    std::vector<std::uint8_t> pkcs12_der;
    std::vector<std::uint8_t> cert_der;
    if (!Require(BuildKeyWithoutCertBag("{CN=Tamga Key Password}{O=Tamga}{C=UA}",
                                        pkcs12_der, cert_der),
                 "fixture: certificate-less PKCS#12 must be built")) {
        return false;
    }

    const std::string descriptor =
        "{\"base64\":\"" + tamga::util::Base64Encode(pkcs12_der) +
        "\",\"keyPassword\":\"test\",\"certificateBase64\":\"" +
        tamga::util::Base64Encode(cert_der) + "\"}";
    tamga::core::Session session;
    if (!Require(session.Initialize(), "session must initialize") ||
        !Require(session.ReadPrivateKey(descriptor, {}),
                 "keyPassword-only descriptor must load with its external certificate")) {
        std::cerr << "  session: " << session.GetLastError().message << "\n";
        return false;
    }

    std::vector<std::uint8_t> signature;
    return Require(session.SignData({'T', 'a', 'm', 'g', 'a'}, signature),
                   "keyPassword-only session must sign") &&
           Require(!signature.empty(), "keyPassword-only signature must not be empty");
}

#endif  // TAMGA_CRYPTONITE_ENABLED

}  // namespace

int main() {
#if !TAMGA_CRYPTONITE_ENABLED
    std::cerr << "Skipping PKCS#12 external-certificate regression: built without vendored cryptonite\n";
    return kSkip;
#else
    bool ok = true;
    ok = RunExternalCertificateAcceptedCase() && ok;
    ok = RunForeignCertificateRejectedCase() && ok;
    ok = RunSecondKeySelectedByCertificateCase() && ok;
    ok = RunContainerPublicKeysSnapshotCase() && ok;
    ok = RunKeyUsageGateCase() && ok;
    ok = RunResolverSkipsKeyAgreementSidecarCase() && ok;
    ok = RunResolverPrefersSameStemSidecarOverCacheCase() && ok;
    ok = RunMissingCertificateDiagnosticCase() && ok;
    ok = RunSessionKeyPasswordOnlyCase() && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
#endif
}
