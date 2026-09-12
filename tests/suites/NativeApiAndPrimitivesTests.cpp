// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Конфігурування через NativeAPI і криптографічні примітиви
// (Купина/ДСТУ 7564, SignHash/VerifyHash, mock-TSA).

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
#include "oids.h"
#include "ocsp_response.h"
#include "ocsp_response_engine.h"
#include "pkcs12.h"
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
#if defined(_WIN32)
#include "dirent_internal.h"
#endif
}
#endif

#include "support/TestSupport.h"
#include "suites/Suites.h"

using namespace tamga_tests;

// F-11: validationLevel доступний через 1С-контракт Configure.
//
// Раніше рівень валідації задавався лише з C++ через Settings, тож із 1С він
// завжди лишався "standard" — `extended`/`forensic` були недосяжні для головного
// споживача бібліотеки. Перевіряємо і прийняття валідного рівня, і fail-closed
// на нерозпізнаному (мовчазний відкат до типового приховав би помилку конфігурації).
void TestNativeApiConfigureAcceptsValidationLevel() {
    TestMemoryManager memory;
    tamga::nativeapi::TamgaAddIn addin;
    ExpectTrue(addin.setMemManager(&memory), "addin should accept memory manager");

    const long configure = FindMethod(addin, L"Configure");
    ExpectTrue(configure >= 0, "FindMethod should locate Configure");

    auto call_configure = [&](const std::wstring& level, bool& out_result) {
        std::array<tVariant, 4> params{};
        for (auto& p : params) { TV_VT(&p) = VTYPE_EMPTY; }
        tamga::util::SetBool(&params[0], true);  // offline — тест не має ходити в мережу
        std::wstring level_value = level;
        if (!tamga::util::SetWString(&memory, &params[3], level_value)) {
            return false;
        }
        tVariant ret{};
        if (!addin.CallAsFunc(configure, &ret, params.data(), static_cast<long>(params.size()))) {
            return false;
        }
        return tamga::util::GetBool(&ret, out_result);
    };

    for (const auto* level : {L"basic", L"standard", L"extended", L"forensic"}) {
        bool ok = false;
        ExpectTrue(call_configure(level, ok), "Configure should be callable with a validationLevel");
        ExpectTrue(ok, "Configure must accept every documented validation level");
    }

    bool bogus_ok = true;
    ExpectTrue(call_configure(L"super-forensic", bogus_ok),
               "Configure with a bogus level should still execute");
    ExpectFalse(bogus_ok,
                "an unrecognized validationLevel must be REJECTED, not silently downgraded to standard");

    // Порожній рядок = «не задано»: сумісність із 3-параметровими викликами.
    bool empty_ok = false;
    ExpectTrue(call_configure(L"", empty_ok), "Configure with an empty level should execute");
    ExpectTrue(empty_ok, "an empty validationLevel must mean 'unset' and default to standard");
}

void TestNativeApiConfigureUsesSafeOfflineDefault() {
    TestMemoryManager memory;
    tamga::nativeapi::TamgaAddIn addin;
    ExpectTrue(addin.setMemManager(&memory), "addin should accept memory manager for offline-default test");
    const long configure = FindMethod(addin, L"Configure");
    const long offline_property = addin.FindProp(u"OfflineMode");
    ExpectTrue(configure >= 0 && offline_property >= 0,
               "Configure and OfflineMode should be available for offline-default test");

    const auto read_offline = [&]() {
        tVariant value{};
        bool offline = false;
        ExpectTrue(addin.GetPropVal(offline_property, &value), "OfflineMode property should be readable");
        ExpectTrue(tamga::util::GetBool(&value, offline), "OfflineMode property should be Boolean");
        return offline;
    };

    tVariant no_args_result{};
    ExpectTrue(CallNoArgs(addin, configure, no_args_result), "Configure() with zero args should be callable");
    bool configured = false;
    ExpectTrue(tamga::util::GetBool(&no_args_result, configured) && configured,
               "Configure() with zero args should succeed");
    ExpectTrue(read_offline(), "Configure() omission must retain the safe offline=true default");

    tVariant explicit_online{};
    tamga::util::SetBool(&explicit_online, false);
    tVariant one_arg_result{};
    ExpectTrue(addin.CallAsFunc(configure, &one_arg_result, &explicit_online, 1),
               "Configure(false) should remain a supported explicit online opt-in");
    ExpectTrue(tamga::util::GetBool(&one_arg_result, configured) && configured,
               "Configure(false) should succeed");
    ExpectFalse(read_offline(), "An explicit offline=false must enable online mode");

    std::array<tVariant, 4> four_args{};
    tamga::util::SetBool(&four_args[0], true);
    ExpectTrue(tamga::util::SetWString(&memory, &four_args[1], L""),
               "Configure four-arg workDir should be settable");
    ExpectTrue(tamga::util::SetWString(&memory, &four_args[2], L"strict"),
               "Configure four-arg trustMode should be settable");
    ExpectTrue(tamga::util::SetWString(&memory, &four_args[3], L"standard"),
               "Configure four-arg validationLevel should be settable");
    tVariant four_args_result{};
    ExpectTrue(addin.CallAsFunc(configure, &four_args_result, four_args.data(), 4),
               "Legacy four-argument Configure should remain callable");
    ExpectTrue(tamga::util::GetBool(&four_args_result, configured) && configured,
               "Legacy four-argument Configure should succeed");
    ExpectTrue(read_offline(), "Legacy four-argument Configure must honor explicit offline=true");
}

// Купина: копія контексту мусить нести ПРОМІЖНИЙ стан і бути незалежною.
//
// Раніше `digest_adapter_copy_with_alloc` для Купини свідомо повертав помилку,
// бо upstream `dstu7564` не мав `copy_with_alloc`. Тепер примітив її має, і саме
// цей тест виправдовує зміну: клон стану хеш-функції без перевірки — рівно та
// річ, що дає хибнопозитив (копія з іншим станом порахувала б інший дайджест і
// підпис зійшовся б там, де не мав би).
//
// Перевіряється двоє: (1) копія продовжує з місця розгалуження, а не з нуля;
// (2) копія й оригінал далі не впливають одне на одного.
void TestKupynaContextCopyCarriesState() {
#if TAMGA_CRYPTONITE_ENABLED
    auto kupyna_of = [](const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>& out) {
        Dstu7564Ctx* ctx = dstu7564_alloc(DSTU7564_SBOX_1);
        if (ctx == nullptr || dstu7564_init(ctx, 32) != 0) {
            dstu7564_free(ctx);
            return false;
        }
        ByteArray* in = ba_alloc_from_uint8(data.data(), data.size());
        ByteArray* hash = nullptr;
        const bool ok = in != nullptr && dstu7564_update(ctx, in) == 0 &&
                        dstu7564_final(ctx, &hash) == 0 && hash != nullptr;
        if (ok) {
            out.assign(ba_get_buf(hash), ba_get_buf(hash) + ba_get_len(hash));
        }
        ba_free(hash);
        ba_free(in);
        dstu7564_free(ctx);
        return ok;
    };

    const std::vector<std::uint8_t> prefix = {'T', 'a', 'm', 'g', 'a', '-'};
    const std::vector<std::uint8_t> tail_a = {'A', 'A', 'A', 'A'};
    const std::vector<std::uint8_t> tail_b = {'B', 'B', 'B', 'B'};

    std::vector<std::uint8_t> expect_a, expect_b;
    std::vector<std::uint8_t> whole_a(prefix), whole_b(prefix);
    whole_a.insert(whole_a.end(), tail_a.begin(), tail_a.end());
    whole_b.insert(whole_b.end(), tail_b.begin(), tail_b.end());
    ExpectTrue(kupyna_of(whole_a, expect_a), "Kupyna reference digest (prefix+A) must compute");
    ExpectTrue(kupyna_of(whole_b, expect_b), "Kupyna reference digest (prefix+B) must compute");
    ExpectTrue(expect_a != expect_b, "the two reference digests must differ");

    // Спільний префікс -> розгалуження.
    Dstu7564Ctx* base = dstu7564_alloc(DSTU7564_SBOX_1);
    ExpectTrue(base != nullptr, "Kupyna context must allocate");
    if (base == nullptr) {
        return;
    }
    ExpectTrue(dstu7564_init(base, 32) == 0, "Kupyna context must initialize");

    ByteArray* prefix_ba = ba_alloc_from_uint8(prefix.data(), prefix.size());
    ExpectTrue(prefix_ba != nullptr && dstu7564_update(base, prefix_ba) == 0,
               "prefix must feed into the base context");

    Dstu7564Ctx* clone = dstu7564_copy_with_alloc(base);
    ExpectTrue(clone != nullptr, "dstu7564_copy_with_alloc must produce a context");

    if (clone != nullptr) {
        ByteArray* a_ba = ba_alloc_from_uint8(tail_a.data(), tail_a.size());
        ByteArray* b_ba = ba_alloc_from_uint8(tail_b.data(), tail_b.size());
        ByteArray* hash_base = nullptr;
        ByteArray* hash_clone = nullptr;

        // Оригінал добирає "AAAA", копія — "BBBB". Порядок навмисно різний,
        // щоб зловити спільний буфер стану, якби копія була поверхневою.
        ExpectTrue(a_ba != nullptr && dstu7564_update(base, a_ba) == 0, "base context must accept its tail");
        ExpectTrue(b_ba != nullptr && dstu7564_update(clone, b_ba) == 0, "cloned context must accept its tail");
        ExpectTrue(dstu7564_final(base, &hash_base) == 0 && hash_base != nullptr, "base digest must finalize");
        ExpectTrue(dstu7564_final(clone, &hash_clone) == 0 && hash_clone != nullptr, "cloned digest must finalize");

        if (hash_base != nullptr && hash_clone != nullptr) {
            const std::vector<std::uint8_t> got_base(ba_get_buf(hash_base),
                                                     ba_get_buf(hash_base) + ba_get_len(hash_base));
            const std::vector<std::uint8_t> got_clone(ba_get_buf(hash_clone),
                                                      ba_get_buf(hash_clone) + ba_get_len(hash_clone));
            ExpectTrue(got_base == expect_a,
                       "the original context must still yield Kupyna(prefix+A) after being cloned");
            ExpectTrue(got_clone == expect_b,
                       "the clone must yield Kupyna(prefix+B) — i.e. it carried the prefix state, "
                       "not a fresh context");
        }

        ba_free(hash_base);
        ba_free(hash_clone);
        ba_free(a_ba);
        ba_free(b_ba);
        dstu7564_free(clone);
    } else {
        dstu7564_free(base);
        base = nullptr;
    }

    ba_free(prefix_ba);
    if (clone != nullptr) {
        dstu7564_free(base);
    }
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestSignHashVerifyHashRoundTrip() {
#if TAMGA_CRYPTONITE_ENABLED
    using tamga::core::CryptoniteAdapter;
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture generation should succeed");
    if (!fixture.valid) {
        return;
    }

    // Геш ГОСТ 34.311 над довільними даними (відповідає алгоритму ключа).
    const std::vector<std::uint8_t> data = {'T', 'a', 'm', 'g', 'a', '-', 'X', 'M', 'L', 'D', 'S', 'I', 'G'};
    tamga::core::ImprintResult imprint;
    std::string error;
    ExpectTrue(tamga::core::ComputeImprint(tamga::core::ImprintDigest::Gost34311, data, imprint, error),
               "GOST 34.311 imprint should compute");

    // SignHash через pkcs12 (пароль фікстури "test").
    std::vector<std::uint8_t> signature;
    ExpectTrue(CryptoniteAdapter::SignHash(/*use_pkcs12=*/true, fixture.pkcs12_blob,
                                           /*certificate_der=*/{}, "test",
                                           imprint.hash, signature, error),
               "SignHash should produce a raw DSTU signature");
    ExpectFalse(signature.empty(), "raw signature must not be empty");

    // VerifyHash сертифікатом підписувача.
    bool is_valid = false;
    ExpectTrue(CryptoniteAdapter::VerifyHash(fixture.cert_der, imprint.hash, signature, is_valid, error),
               "VerifyHash operation should complete");
    ExpectTrue(is_valid, "valid raw signature must verify");

    // Підроблений геш -> підпис не валідний, але операція успішна.
    std::vector<std::uint8_t> tampered_hash = imprint.hash;
    tampered_hash[0] ^= 0xFF;
    bool tampered_valid = true;
    ExpectTrue(CryptoniteAdapter::VerifyHash(fixture.cert_der, tampered_hash, signature, tampered_valid, error),
               "VerifyHash over tampered hash should still complete");
    ExpectFalse(tampered_valid, "tampered hash must not verify");

    // Підроблений підпис -> не валідний.
    std::vector<std::uint8_t> tampered_sig = signature;
    tampered_sig[0] ^= 0xFF;
    bool tampered_sig_valid = true;
    ExpectTrue(CryptoniteAdapter::VerifyHash(fixture.cert_der, imprint.hash, tampered_sig, tampered_sig_valid, error),
               "VerifyHash over tampered signature should still complete");
    ExpectFalse(tampered_sig_valid, "tampered signature must not verify");
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

void TestMockTsaTokenValidates() {
#if TAMGA_CRYPTONITE_ENABLED
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU fixture for mock TSA");
    if (!fixture.valid) {
        return;
    }
    const std::vector<std::uint8_t> tbs = {'h', 'e', 'l', 'l', 'o', '-', 't', 's', 'a'};
    std::vector<std::uint8_t> token;
    std::string err;
    ExpectTrue(MockTsaTimestamp(fixture, tbs, token, err), "MockTsaTimestamp should mint a token");
    ExpectFalse(token.empty(), "mock TSA token must be non-empty");
    if (token.empty()) {
        std::cerr << "  mock TSA error: " << err << "\n";
        return;
    }
    auto vr = tamga::core::policy::ValidateTimestampToken(token, tbs);
    ExpectTrue(vr.valid, "ValidateTimestampToken should accept the mock TSA token");
    if (!vr.valid) {
        std::cerr << "  validate message: " << vr.message << "\n";
    }
#else
    std::cerr << "  (skipped: cryptonite not enabled)\n";
#endif
}

// Phase 0 contract smoke: форматні стаб-заголовки мають компілюватися і
// тримати узгоджені enum-и/моделі. Реальної криптографії тут немає — лише
// перевірка, що публічний контракт стабільний для подальших фаз.
void TestFormatStubHeadersContract() {
    using tamga::core::SignatureFormat;
    ExpectTrue(static_cast<int>(SignatureFormat::CMS) == 0,
               "SignatureFormat::CMS must be the zero value");
    ExpectTrue(static_cast<int>(SignatureFormat::PADES)
                   > static_cast<int>(SignatureFormat::XADES),
               "SignatureFormat ordering should keep XADES before PADES");

    tamga::core::SigningKey key;
    ExpectFalse(key.use_pkcs12, "SigningKey::use_pkcs12 should default to false");

    tamga::xmldsig::XmlSignatureParameters xml_params;
    ExpectTrue(xml_params.c14n_method
                   == tamga::xmldsig::CanonicalizationMethod::C14N_Exclusive,
               "XMLDSIG should default to exclusive C14N");

    tamga::xmldsig::XmlReference ref;
    ref.uri = "#data";
    ExpectTrue(ref.transforms.empty(),
               "XmlReference should start with no transforms");

    tamga::xades::QualifyingProperties qp;
    ExpectTrue(qp.signed_props.data_object_formats.empty(),
               "QualifyingProperties should start empty");
    ExpectTrue(static_cast<int>(tamga::xades::XadesProfile::BES) == 0,
               "XAdES profile BES must be the zero value");

    tamga::pades::PdfSignatureDictionary sig_dict;
    ExpectTrue(sig_dict.profile == tamga::pades::PadesProfile::B,
               "PAdES dictionary should default to profile B");
    tamga::pades::ByteRange br;
    ExpectTrue(br.offset1 == 0 && br.length1 == 0,
               "ByteRange should zero-initialize");
}

void TestTamgaCApi() {
    const char* ver = tamga_version();
    // Тут стояв зашитий літерал версії, і при кожному підйомі версії тест
    // падав — тобто змушував дублювати число ще в одному місці, хоча
    // `docs/release-process.md` прямо це забороняє. Інваріант, який справді
    // вартий перевірки, інший: C API повідомляє САМЕ ту версію, яку задала
    // система збірки. `TAMGA_VERSION_STRING` надходить тестовій цілі з того
    // самого `project()`, що й бібліотеці.
    ExpectTrue(ver != nullptr && std::string(ver) == std::string(TAMGA_VERSION_STRING),
               "tamga_version() must report the version the build system set, "
               "not a literal frozen in the source");

    tamga_session_t s = tamga_session_create();
    ExpectTrue(s != nullptr, "tamga_session_create should return non-null handle");

    int cfg_res = tamga_session_configure(s, nullptr, 1, "strict");
    ExpectTrue(cfg_res == TAMGA_C_OK, "tamga_session_configure should return TAMGA_C_OK");

    ExpectTrue(tamga_session_is_key_loaded(s) == 0,
               "tamga_session_is_key_loaded should return 0 before loading key");

    const std::uint8_t payload[] = {'c', 'a', 'p', 'i'};
    std::uint8_t* signed_data = nullptr;
    size_t signed_len = 0;
    int invalid_format = tamga_session_sign_data(
        s, payload, sizeof(payload), "not-a-format", &signed_data, &signed_len);
    ExpectTrue(invalid_format == TAMGA_C_ERR_INVALID_ARGUMENT,
               "tamga_session_sign_data must reject unknown formats before key lookup");
    ExpectTrue(signed_data == nullptr && signed_len == 0,
               "tamga_session_sign_data must clear output pointers on format rejection");

    int invalid_file_format = tamga_session_sign_file(
        s, "nonexistent.dat", "nonexistent.sig", "not-a-format");
    ExpectTrue(invalid_file_format == TAMGA_C_ERR_INVALID_ARGUMENT,
               "tamga_session_sign_file must reject unknown formats before key lookup");

    int invalid_verify_format = 0;
    int verify_format_res = tamga_session_verify_data(
        s, payload, sizeof(payload), nullptr, 0, "not-a-format", &invalid_verify_format);
    ExpectTrue(verify_format_res == TAMGA_C_ERR_INVALID_ARGUMENT,
               "tamga_session_verify_data must reject unknown formats");

    int missing_detached_signature = 0;
    int detached_shape_res = tamga_session_verify_data(
        s, payload, sizeof(payload), nullptr, 0, "cms-detached", &missing_detached_signature);
    ExpectTrue(detached_shape_res == TAMGA_C_ERR_INVALID_ARGUMENT,
               "CMS detached verification must require a non-empty signature");

    int sign_res = tamga_session_sign_file(s, "nonexistent.dat", "nonexistent.sig", "cms");
    ExpectTrue(sign_res == TAMGA_C_ERR_KEY_NOT_LOADED,
               "tamga_session_sign_file without key should return TAMGA_C_ERR_KEY_NOT_LOADED");

    const char* err = tamga_session_get_last_error(s);
    ExpectTrue(err != nullptr && *err != '\0',
               "tamga_session_get_last_error should return error description");

    int err_code = tamga_session_get_last_error_code(s);
    ExpectTrue(err_code == TAMGA_C_ERR_KEY_NOT_LOADED,
               "tamga_session_get_last_error_code should match TAMGA_C_ERR_KEY_NOT_LOADED");

    // Q-06: вихідний прапорець обнуляється ДО перевірки решти аргументів.
    // Раніше `*out_valid = 0` стояло після неї, тож виклик із `data == nullptr`
    // при справному `out_valid` лишав у ньому попереднє значення. Стартове
    // значення 1 тут не штучне: рівно так виглядає змінна, яку перевикористали
    // після успішного виклику.
    int lingering_data_flag = 1;
    const int null_data_res = tamga_session_verify_data(
        s, nullptr, 0, nullptr, 0, "cms", &lingering_data_flag);
    ExpectTrue(null_data_res == TAMGA_C_ERR_INVALID_ARGUMENT,
               "tamga_session_verify_data must reject a null data pointer");
    ExpectTrue(lingering_data_flag == 0,
               "tamga_session_verify_data must clear out_valid before any other argument check");

    int lingering_file_flag = 1;
    const int null_path_res = tamga_session_verify_file(s, nullptr, nullptr, "cms", &lingering_file_flag);
    ExpectTrue(null_path_res == TAMGA_C_ERR_INVALID_ARGUMENT,
               "tamga_session_verify_file must reject a null input path");
    ExpectTrue(lingering_file_flag == 0,
               "tamga_session_verify_file must clear out_valid before any other argument check");

    // Q-06: рання відмова мусить лишити слід у звіті, а не тільки в last_error.
    const char* rejected_report = tamga_session_get_last_report(s);
    ExpectTrue(rejected_report != nullptr,
               "tamga_session_get_last_report must return a report after an early verify rejection");
    if (rejected_report != nullptr) {
        const std::string report_text(rejected_report);
        ExpectContains(report_text, "tamga_session_verify_file",
                       "Early C ABI verify rejection must name the operation that actually failed");
        ExpectTrue(report_text.find("\"signatureValid\":true") == std::string::npos &&
                       report_text.find("\"signature_valid\":true") == std::string::npos,
                   "Early C ABI verify rejection must never report a valid signature");
    }

    tamga_session_destroy(s);
}

#if TAMGA_CRYPTONITE_ENABLED
// Q-06: послідовність «успішна перевірка -> рання відмова». Саме вона
// показувала дефект: `tamga_session_get_last_report` після відмови віддавав
// звіт ПОПЕРЕДНЬОЇ, успішної перевірки, бо ранні виходи C ABI оновлювали лише
// обгортковий last_error і не чіпали звіт у Session.
void TestCApiEarlyVerifyFailureReplacesPreviousReport() {
    const auto fixture = GenerateDstuFixture();
    ExpectTrue(fixture.valid, "DSTU4145 fixture generation should succeed (C ABI report sequence)");
    if (!fixture.valid) {
        return;
    }

    const auto key_path = MakeTemporaryFixturePath(".p12");
    ExpectTrue(WriteBinaryFile(key_path, fixture.pkcs12_blob),
               "PKCS#12 fixture should be written for the C ABI report sequence test");

    tamga_session_t s = tamga_session_create();
    ExpectTrue(s != nullptr, "tamga_session_create should return a handle for the report sequence test");
    if (s == nullptr) {
        std::error_code cleanup_ec;
        std::filesystem::remove(key_path, cleanup_ec);
        return;
    }

    const std::string work_dir = FixturePath(".").string();
    ExpectTrue(tamga_session_configure(s, work_dir.c_str(), 1, nullptr) == TAMGA_C_OK,
               "tamga_session_configure should succeed for the report sequence test");
    ExpectTrue(tamga_session_read_key_file(s, key_path.string().c_str(), "test", "test", "signer") == TAMGA_C_OK,
               "tamga_session_read_key_file should load the DSTU fixture container");

    const std::uint8_t payload[] = {'q', '0', '6'};
    std::uint8_t* signed_data = nullptr;
    size_t signed_len = 0;
    ExpectTrue(tamga_session_sign_data(s, payload, sizeof(payload), "cms-attached",
                                       &signed_data, &signed_len) == TAMGA_C_OK,
               "tamga_session_sign_data should produce an attached CMS for the report sequence test");

    if (signed_data != nullptr && signed_len != 0) {
        int first_valid = 0;
        ExpectTrue(tamga_session_verify_data(s, signed_data, signed_len, nullptr, 0,
                                             "cms-attached", &first_valid) == TAMGA_C_OK,
                   "The first verification of the sequence should succeed");
        ExpectTrue(first_valid == 1, "The first verification of the sequence should report a valid signature");

        const char* success_report = tamga_session_get_last_report(s);
        ExpectTrue(success_report != nullptr && std::string(success_report).find("VerifyDataInternal") != std::string::npos,
                   "The successful verification must be visible in the report before the failing call");

        // Рання відмова читання: файл свідомо не існує.
        const auto missing_path = MakeTemporaryFixturePath(".xml");
        std::error_code missing_ec;
        std::filesystem::remove(missing_path, missing_ec);

        int second_valid = 1;
        const int failing_res = tamga_session_verify_file(
            s, missing_path.string().c_str(), nullptr, "xades", &second_valid);
        ExpectTrue(failing_res == TAMGA_C_ERR_INVALID_ARGUMENT,
                   "Verification of a missing XML file must fail with an argument error");
        ExpectTrue(second_valid == 0, "A failed verification must leave out_valid at 0");

        const char* failure_report = tamga_session_get_last_report(s);
        ExpectTrue(failure_report != nullptr, "A technical report must exist after the failing call");
        if (failure_report != nullptr) {
            const std::string report_text(failure_report);
            ExpectContains(report_text, "tamga_session_verify_file",
                           "The technical report must describe the failed call, not the previous one");
            ExpectTrue(report_text.find("VerifyDataInternal") == std::string::npos,
                       "The technical report must not keep the previous successful operation");
            ExpectTrue(report_text.find("\"signatureValid\":true") == std::string::npos &&
                           report_text.find("\"signature_valid\":true") == std::string::npos,
                       "The technical report of a failed call must not claim a valid signature");
        }

        const char* failure_user_report = tamga_session_get_user_report(s);
        ExpectTrue(failure_user_report != nullptr, "A user report must exist after the failing call");
        if (failure_user_report != nullptr) {
            const std::string user_text(failure_user_report);
            ExpectTrue(user_text.find("VerifyDataInternal") == std::string::npos,
                       "The user report must not keep the previous successful operation either");
        }
    }

    tamga_free_bytes(signed_data);
    tamga_session_destroy(s);
    std::error_code cleanup_ec;
    std::filesystem::remove(key_path, cleanup_ec);
}
#endif  // TAMGA_CRYPTONITE_ENABLED
