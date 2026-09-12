// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// NativeAPI v2: метадані методів (включно з alias-іменами 1С),
// конфігурування та звіти, диспетчеризація опційних методів.

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

void TestNativeApiV2MethodMetadata() {
    TestMemoryManager memory;
    tamga::nativeapi::TamgaAddIn addin;
    ExpectTrue(addin.setMemManager(&memory), "NativeAPI addin should accept memory manager");

    const std::vector<std::wstring> removed_methods = {
        L"GetErrorDescription", L"SetSettings", L"ReadPrivateKey", L"ReadPrivateKeyBinary",
        L"ReadPrivateKeyFile", L"ResetPrivateKey", L"SetFileStoreSettings", L"SetOCSPSettings",
        L"SetTSPSettings", L"SetLDAPSettings", L"SetCMPSettings", L"SignDataBase64",
        L"VerifyDataBase64", L"SignDataInternal", L"VerifyDataInternal", L"VerifyDataInternalStr",
        L"SignDataInternalBase64", L"VerifyDataInternalBase64", L"VerifyDataInternalBase64Str",
        L"RawSignFile", L"RawVerifyFile", L"GetLastVerifyReport", L"SignFileAsicS",
        L"VerifyFileAsicS", L"SignFileAsicE", L"VerifyFileAsicE", L"AddSignatureToAsicE",
        L"ПолучитьОписаниеОшибки", L"УстановитьПараметры", L"СчитатьЛичныйКлюч",
        L"СчитатьЛичныйКлючДвоичныеДанные", L"СчитатьЛичныйКлючИзФайла",
        L"СброситьЛичныйКлюч", L"УстановитьПараметрыФайловогоХранилища",
        L"УстановитьПараметрыOCSPСервера", L"УстановитьПараметрыTSPСервера",
        L"УстановитьПараметрыLDAPСервера", L"УстановитьПараметрыCMPСервера",
        L"ПодписатьДанныеBASE64", L"ПроверитьПодписьBASE64", L"ПодписатьДанныеВнутренние",
        L"ПроверитьВнутреннююПодпись", L"ПроверитьВнутреннююПодписьСтрока",
        L"ПодписатьДанныеВнутренниеBASE64", L"ПроверитьВнутреннююПодписьBASE64",
        L"ПроверитьВнутреннююПодписьBASE64Строка", L"ПодписатьФайлУпрощенно",
        L"ПроверитьУпрощеннуюПодписьФайла", L"ПолучитьОтчетПоследнейПроверки",
        L"ПодписатьФайлASicS", L"ПроверитьФайлASicS", L"ПодписатьФайлASicE",
        L"ПроверитьФайлASicE", L"ДобавитьПодписьASicE"
    };
    for (const auto& method : removed_methods) {
        ExpectTrue(FindMethod(addin, method) < 0, "Deprecated NativeAPI method should not be exposed");
    }

    const std::vector<std::wstring> exposed_methods = {
        L"Initialize", L"Finalize", L"ShowCertificates", L"ShowCRLs", L"GetPrivateKeyMedia", L"GetCertificateInfo",
        L"BASE64Encode", L"BASE64Decode", L"SignData", L"VerifyData", L"SignFile", L"VerifyFile",
        L"SignXml", L"VerifyXml", L"SignPdf", L"VerifyPdf",
        L"Configure", L"ConfigureTsp", L"ConfigureOcsp", L"ConfigureLdap", L"ConfigureCmp", L"ConfigureTrustList",
        L"SyncTrustList", L"LoadKey", L"ResetKey", L"GetReport", L"GetUserReport", L"GetError",
        L"Инициализировать", L"ЗавершитьРаботу", L"ПоказатьСертификаты", L"ПоказатьСпискиОтзыва",
        L"ОпределитьПараметрыНосителяЛичногоКлюча", L"ПолучитьИнформациюОСертификате", L"BASE64Кодировать",
        L"BASE64Декодировать", L"ПодписатьДанные", L"ПроверитьПодпись", L"ПодписатьФайл",
        L"ПроверитьПодписьФайла", L"ПодписатьXML", L"ПроверитьXML", L"ПодписатьPDF",
        L"ПроверитьPDF", L"Настроить", L"НастроитьTSP", L"НастроитьOCSP", L"НастроитьLDAP",
        L"НастроитьCMP", L"НастроитьДоверенныйСписок", L"ОбновитьДоверенныйСписок", L"ЗагрузитьКлюч",
        L"СброситьКлюч", L"ПолучитьОтчет", L"ПолучитьОтчетПользователя", L"ПолучитьОшибку"
    };
    for (const auto& method : exposed_methods) {
        ExpectTrue(FindMethod(addin, method) >= 0, "Expected NativeAPI V2 method should be exposed");
    }

    const long configure = FindMethod(addin, L"Configure");
    const long configure_ru = FindMethod(addin, L"Настроить");
    ExpectTrue(configure >= 0, "FindMethod should locate Configure");
    ExpectTrue(configure == configure_ru, "FindMethod should locate Russian Configure alias");

    // N-004: 1С регістронезалежна до ідентифікаторів — FindMethod/FindProp
    // мусять знаходити метод у довільному регістрі (ASCII і кирилиця).
    ExpectTrue(FindMethod(addin, L"configure") == configure,
               "FindMethod should be case-insensitive for ASCII names (lower)");
    ExpectTrue(FindMethod(addin, L"CONFIGURE") == configure,
               "FindMethod should be case-insensitive for ASCII names (upper)");
    ExpectTrue(FindMethod(addin, L"cOnFiGuRe") == configure,
               "FindMethod should be case-insensitive for ASCII names (mixed)");
    ExpectTrue(FindMethod(addin, L"настроить") == configure_ru,
               "FindMethod should be case-insensitive for Cyrillic aliases (lower)");
    ExpectTrue(FindMethod(addin, L"НАСТРОИТЬ") == configure_ru,
               "FindMethod should be case-insensitive for Cyrillic aliases (upper)");
    ExpectTrue(FindMethod(addin, L"ЗагрузитьКлюч") == FindMethod(addin, L"загрузитьключ"),
               "FindMethod should case-fold a longer Cyrillic method name");
    ExpectTrue(FindMethod(addin, L"NoSuchMethodXyz") < 0,
               "FindMethod must still reject genuinely unknown names");
    ExpectTrue(addin.GetNParams(configure) == 5,
               "Configure should expose offline/workDir/trustMode/validationLevel/allowAiaIssuerFetch params");
    ExpectDefaultBool(addin, configure, 0, true, "Configure.offline default should be true");
    ExpectDefaultString(addin, configure, 1, L"", "Configure.workDir default should be empty");
    ExpectDefaultString(addin, configure, 2, L"strict", "Configure.trustMode default should be strict");
    // F-11: дефолт саме "standard" — те, що діяло неявно, доки параметра не було,
    // тож наявні 3-параметрові виклики з 1С не змінюють поведінку.
    ExpectDefaultString(addin, configure, 3, L"standard",
                        "Configure.validationLevel default should be standard");
    ExpectDefaultBool(addin, configure, 4, false,
                      "Configure.allowAiaIssuerFetch default should be false");

    const long configure_tsp = FindMethod(addin, L"ConfigureTsp");
    ExpectTrue(configure_tsp >= 0, "FindMethod should locate ConfigureTsp");
    ExpectTrue(configure_tsp == FindMethod(addin, L"НастроитьTSP"),
               "FindMethod should locate Russian ConfigureTsp alias");
    ExpectTrue(addin.GetNParams(configure_tsp) == 4, "ConfigureTsp should expose four positional params");
    ExpectDefaultString(addin, configure_tsp, 0, L"", "ConfigureTsp.url default should be empty");
    ExpectDefaultString(addin, configure_tsp, 1, L"", "ConfigureTsp.policyOid default should be empty");
    ExpectDefaultInt32(addin, configure_tsp, 2, 10000, "ConfigureTsp.timeoutMs default should be 10000");
    ExpectDefaultString(addin, configure_tsp, 3, L"", "ConfigureTsp.imprintDigestOid default should be empty");

    const long configure_ocsp = FindMethod(addin, L"ConfigureOcsp");
    ExpectTrue(configure_ocsp >= 0, "FindMethod should locate ConfigureOcsp");
    ExpectTrue(configure_ocsp == FindMethod(addin, L"НастроитьOCSP"),
               "FindMethod should locate Russian ConfigureOcsp alias");
    ExpectTrue(addin.GetNParams(configure_ocsp) == 3, "ConfigureOcsp should expose three positional params");
    ExpectDefaultString(addin, configure_ocsp, 0, L"", "ConfigureOcsp.url default should be empty");
    ExpectDefaultBool(addin, configure_ocsp, 1, true, "ConfigureOcsp.useNonce default should be true");
    ExpectDefaultInt32(addin, configure_ocsp, 2, 10000, "ConfigureOcsp.timeoutMs default should be 10000");

    const long configure_ldap = FindMethod(addin, L"ConfigureLdap");
    ExpectTrue(configure_ldap >= 0, "FindMethod should locate ConfigureLdap");
    ExpectTrue(configure_ldap == FindMethod(addin, L"НастроитьLDAP"),
               "FindMethod should locate Russian ConfigureLdap alias");
    ExpectTrue(addin.GetNParams(configure_ldap) == 3, "ConfigureLdap should expose three positional params");
    ExpectDefaultString(addin, configure_ldap, 0, L"", "ConfigureLdap.url default should be empty");
    ExpectDefaultString(addin, configure_ldap, 1, L"", "ConfigureLdap.baseDn default should be empty");
    ExpectDefaultInt32(addin, configure_ldap, 2, 10000, "ConfigureLdap.timeoutMs default should be 10000");

    const long configure_cmp = FindMethod(addin, L"ConfigureCmp");
    ExpectTrue(configure_cmp >= 0, "FindMethod should locate ConfigureCmp");
    ExpectTrue(configure_cmp == FindMethod(addin, L"НастроитьCMP"),
               "FindMethod should locate Russian ConfigureCmp alias");
    ExpectTrue(addin.GetNParams(configure_cmp) == 3, "ConfigureCmp should expose three positional params");
    ExpectDefaultString(addin, configure_cmp, 0, L"", "ConfigureCmp.url default should be empty");
    ExpectDefaultString(addin, configure_cmp, 1, L"", "ConfigureCmp.profile default should be empty");
    ExpectDefaultInt32(addin, configure_cmp, 2, 10000, "ConfigureCmp.timeoutMs default should be 10000");

    const long configure_trust_list = FindMethod(addin, L"ConfigureTrustList");
    ExpectTrue(configure_trust_list >= 0, "FindMethod should locate ConfigureTrustList");
    ExpectTrue(configure_trust_list == FindMethod(addin, L"НастроитьДоверенныйСписок"),
               "FindMethod should locate Russian ConfigureTrustList alias");
    // B-3: 4-й параметр pinnedCertBase64 — без нього перевірка підпису TL доводить
    // лише самоузгодженість документа, тож pinned-anchor мусить бути досяжним з 1С.
    ExpectTrue(addin.GetNParams(configure_trust_list) == 5,
               "ConfigureTrustList should expose URL, timeoutMs, ttlHours, pinnedCertBase64, signaturePolicy");
    ExpectDefaultString(addin, configure_trust_list, 0, L"", "ConfigureTrustList.url default should be empty");
    ExpectDefaultInt32(addin, configure_trust_list, 1, 30000, "ConfigureTrustList.timeoutMs default should be 30000");
    ExpectDefaultInt32(addin, configure_trust_list, 2, 24, "ConfigureTrustList.ttlHours default should be 24");
    ExpectDefaultString(addin, configure_trust_list, 3, L"",
                        "ConfigureTrustList.pinnedCertBase64 default should be empty");
    ExpectDefaultString(addin, configure_trust_list, 4, L"",
                        "ConfigureTrustList.signaturePolicy default should be empty (keep library default)");

    const long sync_trust_list = FindMethod(addin, L"SyncTrustList");
    ExpectTrue(sync_trust_list >= 0, "FindMethod should locate SyncTrustList");
    ExpectTrue(sync_trust_list == FindMethod(addin, L"ОбновитьДоверенныйСписок"),
               "FindMethod should locate Russian SyncTrustList alias");
    ExpectTrue(addin.GetNParams(sync_trust_list) == 0, "SyncTrustList should not require params");

    const long get_user_report = FindMethod(addin, L"GetUserReport");
    ExpectTrue(get_user_report >= 0, "FindMethod should locate GetUserReport");
    ExpectTrue(get_user_report == FindMethod(addin, L"ПолучитьОтчетПользователя"),
               "FindMethod should locate Russian GetUserReport alias");
    ExpectTrue(addin.GetNParams(get_user_report) == 0, "GetUserReport should not require params");

    const long load_key = FindMethod(addin, L"LoadKey");
    ExpectTrue(load_key >= 0, "FindMethod should locate LoadKey");
    ExpectTrue(load_key == FindMethod(addin, L"ЗагрузитьКлюч"),
               "FindMethod should locate Russian LoadKey alias");
    ExpectTrue(addin.GetNParams(load_key) == 5, "LoadKey should expose five positional params");
    ExpectDefaultString(addin, load_key, 2, L"", "LoadKey.keyPassword default should be empty");
    ExpectDefaultString(addin, load_key, 3, L"", "LoadKey.alias default should be empty");
    ExpectDefaultString(addin, load_key, 4, L"auto", "LoadKey.sourceType default should be auto");

    const long reset_key = FindMethod(addin, L"ResetKey");
    ExpectTrue(reset_key >= 0, "FindMethod should locate ResetKey");
    ExpectTrue(reset_key == FindMethod(addin, L"СброситьКлюч"),
               "FindMethod should locate Russian ResetKey alias");
    ExpectTrue(addin.GetNParams(reset_key) == 0, "ResetKey should not expose params");

    const long get_report = FindMethod(addin, L"GetReport");
    ExpectTrue(get_report >= 0, "FindMethod should locate GetReport");
    ExpectTrue(get_report == FindMethod(addin, L"ПолучитьОтчет"),
               "FindMethod should locate Russian GetReport alias");
    ExpectTrue(addin.GetNParams(get_report) == 0, "GetReport should not expose params");

    const long get_error = FindMethod(addin, L"GetError");
    ExpectTrue(get_error >= 0, "FindMethod should locate GetError");
    ExpectTrue(get_error == FindMethod(addin, L"ПолучитьОшибку"),
               "FindMethod should locate Russian GetError alias");
    ExpectTrue(addin.GetNParams(get_error) == 0, "GetError should not expose params");



    const long sign_xml = FindMethod(addin, L"SignXml");
    ExpectTrue(sign_xml >= 0, "FindMethod should locate SignXml");
    ExpectTrue(sign_xml == FindMethod(addin, L"ПодписатьXML"),
               "FindMethod should locate Russian SignXml alias");
    ExpectTrue(addin.GetNParams(sign_xml) == 2, "SignXml should expose xml + profile params");

    const long verify_xml = FindMethod(addin, L"VerifyXml");
    ExpectTrue(verify_xml >= 0, "FindMethod should locate VerifyXml");
    ExpectTrue(verify_xml == FindMethod(addin, L"ПроверитьXML"),
               "FindMethod should locate Russian VerifyXml alias");
    ExpectTrue(addin.GetNParams(verify_xml) == 1, "VerifyXml should expose signed XML string param");

    const long sign_pdf = FindMethod(addin, L"SignPdf");
    ExpectTrue(sign_pdf >= 0, "FindMethod should locate SignPdf");
    ExpectTrue(sign_pdf == FindMethod(addin, L"ПодписатьPDF"),
               "FindMethod should locate Russian SignPdf alias");
    // А-07: другий параметр — профіль PAdES ("", b/t/lt/lta), необовʼязковий.
    ExpectTrue(addin.GetNParams(sign_pdf) == 2,
               "SignPdf should expose the PDF blob and the optional PAdES profile");

    const long verify_pdf = FindMethod(addin, L"VerifyPdf");
    ExpectTrue(verify_pdf >= 0, "FindMethod should locate VerifyPdf");
    ExpectTrue(verify_pdf == FindMethod(addin, L"ПроверитьPDF"),
               "FindMethod should locate Russian VerifyPdf alias");
    ExpectTrue(addin.GetNParams(verify_pdf) == 1, "VerifyPdf should expose PDF blob param");

    const long sign_data = FindMethod(addin, L"SignData");
    ExpectTrue(addin.GetNParams(sign_data) == 3, "SignData should expose V2 optional mode params");
    ExpectDefaultString(addin, sign_data, 1, L"cms-detached",
                        "SignData.signatureFormat default should be cms-detached");
    ExpectDefaultString(addin, sign_data, 2, L"binary", "SignData.outputEncoding default should be binary");

    const long verify_data = FindMethod(addin, L"VerifyData");
    ExpectTrue(addin.GetNParams(verify_data) == 5, "VerifyData should expose V2 optional mode params");
    ExpectDefaultString(addin, verify_data, 2, L"cms-detached",
                        "VerifyData.signatureFormat default should be cms-detached");
    ExpectDefaultString(addin, verify_data, 3, L"binary", "VerifyData.inputEncoding default should be binary");
    ExpectDefaultString(addin, verify_data, 4, L"none", "VerifyData.contentEncoding default should be none");

    const long sign_file = FindMethod(addin, L"SignFile");
    ExpectTrue(addin.GetNParams(sign_file) == 4, "SignFile should expose V2 optional mode params");
    ExpectDefaultString(addin, sign_file, 1, L"", "SignFile.outputPath default should be empty");
    ExpectDefaultString(addin, sign_file, 2, L"cms-detached",
                        "SignFile.signatureFormat default should be cms-detached");
    ExpectDefaultString(addin, sign_file, 3, L"binary", "SignFile.outputEncoding default should be binary");

    const long verify_file = FindMethod(addin, L"VerifyFile");
    ExpectTrue(addin.GetNParams(verify_file) == 4, "VerifyFile should expose V2 optional mode params");
    ExpectDefaultString(addin, verify_file, 1, L"", "VerifyFile.signatureOrPath default should be empty");
    ExpectDefaultString(addin, verify_file, 2, L"cms-detached",
                        "VerifyFile.signatureFormat default should be cms-detached");
    ExpectDefaultString(addin, verify_file, 3, L"binary", "VerifyFile.inputEncoding default should be binary");
}

void TestNativeApiV2ConfigureAndReports() {
    TestMemoryManager memory;
    tamga::nativeapi::TamgaAddIn addin;
    ExpectTrue(addin.setMemManager(&memory), "NativeAPI addin should accept memory manager for V2 behavior test");

    const long initialize = FindMethod(addin, L"Initialize");
    tVariant init_ret{};
    ExpectTrue(CallNoArgs(addin, initialize, init_ret), "Initialize should be callable");
    bool initialized = false;
    ExpectTrue(tamga::util::GetBool(&init_ret, initialized) && initialized, "Initialize should return true");

    const long configure = FindMethod(addin, L"Configure");
    tVariant config_params[2]{};
    tamga::util::SetBool(&config_params[0], false);
    ExpectTrue(tamga::util::SetWString(&memory, &config_params[1], L""), "Configure.workDir param should be set");
    tVariant config_ret{};
    ExpectTrue(addin.CallAsFunc(configure, &config_ret, config_params, 2), "Configure should be callable");
    bool configured = false;
    ExpectTrue(tamga::util::GetBool(&config_ret, configured) && configured, "Configure should return true");

    const long configure_tsp = FindMethod(addin, L"ConfigureTsp");
    tVariant tsp_ret{};
    ExpectTrue(CallNoArgs(addin, configure_tsp, tsp_ret), "ConfigureTsp should accept omitted optional params");
    bool tsp_configured = false;
    ExpectTrue(tamga::util::GetBool(&tsp_ret, tsp_configured) && tsp_configured,
               "ConfigureTsp defaults should return true");

    const long configure_ocsp = FindMethod(addin, L"ConfigureOcsp");
    tVariant ocsp_ret{};
    ExpectTrue(CallNoArgs(addin, configure_ocsp, ocsp_ret), "ConfigureOcsp should accept omitted optional params");
    bool ocsp_configured = false;
    ExpectTrue(tamga::util::GetBool(&ocsp_ret, ocsp_configured) && ocsp_configured,
               "ConfigureOcsp defaults should return true");

    const long configure_ldap = FindMethod(addin, L"ConfigureLdap");
    tVariant ldap_ret{};
    ExpectTrue(CallNoArgs(addin, configure_ldap, ldap_ret), "ConfigureLdap should accept omitted optional params");
    bool ldap_configured = false;
    ExpectTrue(tamga::util::GetBool(&ldap_ret, ldap_configured) && ldap_configured,
               "ConfigureLdap defaults should return true");

    const long configure_cmp = FindMethod(addin, L"ConfigureCmp");
    tVariant cmp_ret{};
    ExpectTrue(CallNoArgs(addin, configure_cmp, cmp_ret), "ConfigureCmp should accept omitted optional params");
    bool cmp_configured = false;
    ExpectTrue(tamga::util::GetBool(&cmp_ret, cmp_configured) && cmp_configured,
               "ConfigureCmp defaults should return true");

    const long configure_trust_list = FindMethod(addin, L"ConfigureTrustList");
    tVariant trust_list_config_ret{};
    ExpectTrue(CallNoArgs(addin, configure_trust_list, trust_list_config_ret),
               "ConfigureTrustList should accept omitted optional params");
    bool trust_list_configured = false;
    ExpectTrue(tamga::util::GetBool(&trust_list_config_ret, trust_list_configured) && trust_list_configured,
               "ConfigureTrustList defaults should return true");

    const long get_user_report = FindMethod(addin, L"GetUserReport");
    tVariant user_report_ret{};
    ExpectTrue(CallNoArgs(addin, get_user_report, user_report_ret), "GetUserReport should be callable");
    std::wstring user_report;
    ExpectTrue(tamga::util::GetWString(&user_report_ret, user_report), "GetUserReport should return string");
    ExpectTrue(user_report.find(L"\"schemaVersion\"") != std::wstring::npos, "GetUserReport should return JSON with schemaVersion");

    const long sync_trust_list = FindMethod(addin, L"SyncTrustList");
    tamga::core::HttpClient::ScopedMockTransport sync_failure_mock(
        [](const tamga::core::HttpRequest&) {
            tamga::core::HttpResponse response;
            response.succeeded = false;
            response.status_code = 503;
            response.message = "offline test transport";
            return response;
        });
    tVariant sync_ret{};
    ExpectTrue(CallNoArgs(addin, sync_trust_list, sync_ret), "SyncTrustList should be callable with mocked network failure");
    bool synced = true;
    ExpectTrue(tamga::util::GetBool(&sync_ret, synced) && !synced,
               "SyncTrustList should return false when mocked trust list download fails");

    const long get_report = FindMethod(addin, L"GetReport");
    tVariant report_ret{};
    ExpectTrue(CallNoArgs(addin, get_report, report_ret), "GetReport should be callable");
    std::wstring report;
    ExpectTrue(tamga::util::GetWString(&report_ret, report), "GetReport should return string");
    ExpectTrue(report.find(L"\"schemaVersion\":\"2.2\"") != std::wstring::npos, "GetReport should return verify report JSON");

    const long get_error = FindMethod(addin, L"GetError");
    tVariant error_ret{};
    ExpectTrue(CallNoArgs(addin, get_error, error_ret), "GetError should be callable");
    std::wstring error_text;
    ExpectTrue(tamga::util::GetWString(&error_ret, error_text), "GetError should return string");

    const long reset_key = FindMethod(addin, L"ResetKey");
    tVariant reset_ret{};
    ExpectTrue(CallNoArgs(addin, reset_key, reset_ret), "ResetKey should be callable");
    bool reset = false;
    ExpectTrue(tamga::util::GetBool(&reset_ret, reset) && reset, "ResetKey should return true");

    const long load_key = FindMethod(addin, L"LoadKey");
    tVariant load_params[5]{};
    ExpectTrue(tamga::util::SetWString(&memory, &load_params[0], L"missing.key"), "LoadKey.source should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &load_params[1], L"password"), "LoadKey.password should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &load_params[4], L"unsupported"), "LoadKey.sourceType should be set");
    tVariant load_ret{};
    ExpectFalse(addin.CallAsFunc(load_key, &load_ret, load_params, 5),
                "LoadKey should reject unsupported sourceType before touching filesystem");
}

void TestNativeApiV2SignVerifyOptionalDispatch() {
    TestMemoryManager memory;
    tamga::nativeapi::TamgaAddIn addin;
    ExpectTrue(addin.setMemManager(&memory), "NativeAPI addin should accept memory manager for V2 sign dispatch test");

    const long initialize = FindMethod(addin, L"Initialize");
    tVariant init_ret{};
    ExpectTrue(CallNoArgs(addin, initialize, init_ret), "Initialize should be callable for V2 sign dispatch test");



    const long sign_xml = FindMethod(addin, L"SignXml");
    ExpectTrue(sign_xml >= 0, "FindMethod should locate SignXml");
    ExpectTrue(sign_xml == FindMethod(addin, L"ПодписатьXML"),
               "FindMethod should locate Russian SignXml alias");
    ExpectTrue(addin.GetNParams(sign_xml) == 2, "SignXml should expose xml + profile params");

    const long verify_xml = FindMethod(addin, L"VerifyXml");
    ExpectTrue(verify_xml >= 0, "FindMethod should locate VerifyXml");
    ExpectTrue(verify_xml == FindMethod(addin, L"ПроверитьXML"),
               "FindMethod should locate Russian VerifyXml alias");
    ExpectTrue(addin.GetNParams(verify_xml) == 1, "VerifyXml should expose signed XML string param");

    const long sign_pdf = FindMethod(addin, L"SignPdf");
    ExpectTrue(sign_pdf >= 0, "FindMethod should locate SignPdf");
    ExpectTrue(sign_pdf == FindMethod(addin, L"ПодписатьPDF"),
               "FindMethod should locate Russian SignPdf alias");
    // А-07: другий параметр — профіль PAdES ("", b/t/lt/lta), необовʼязковий.
    ExpectTrue(addin.GetNParams(sign_pdf) == 2,
               "SignPdf should expose the PDF blob and the optional PAdES profile");

    const long verify_pdf = FindMethod(addin, L"VerifyPdf");
    ExpectTrue(verify_pdf >= 0, "FindMethod should locate VerifyPdf");
    ExpectTrue(verify_pdf == FindMethod(addin, L"ПроверитьPDF"),
               "FindMethod should locate Russian VerifyPdf alias");
    ExpectTrue(addin.GetNParams(verify_pdf) == 1, "VerifyPdf should expose PDF blob param");

    const long sign_data = FindMethod(addin, L"SignData");
    tVariant sign_params[3]{};
    const std::vector<std::uint8_t> payload = {'v', '2'};
    ExpectTrue(tamga::util::SetBlob(&memory, &sign_params[0], payload), "SignData payload should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &sign_params[1], L"cades-bes"),
               "SignData signatureFormat should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &sign_params[2], L"base64"),
               "SignData outputEncoding should be set");
    tVariant sign_ret{};
    ExpectFalse(addin.CallAsFunc(sign_data, &sign_ret, sign_params, 3),
                "SignData with optional V2 params should reach core and fail without loaded key");

    const long get_error = FindMethod(addin, L"GetError");
    tVariant error_ret{};
    ExpectTrue(CallNoArgs(addin, get_error, error_ret), "GetError should be callable after failed SignData");
    std::wstring error_text;
    ExpectTrue(tamga::util::GetWString(&error_ret, error_text), "GetError should return string after SignData");
    ExpectFalse(error_text.empty(), "SignData optional dispatch should set core error instead of failing arity validation");

    const long verify_data = FindMethod(addin, L"VerifyData");
    tVariant verify_params[5]{};
    ExpectTrue(tamga::util::SetBlob(&memory, &verify_params[0], payload), "VerifyData payload should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_params[1], L"not-base64"),
               "VerifyData signature base64 should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_params[2], L"cms-detached"),
               "VerifyData signatureFormat should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_params[3], L"base64"),
               "VerifyData inputEncoding should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_params[4], L"none"),
               "VerifyData contentEncoding should be set");
    tVariant verify_ret{};
    ExpectFalse(addin.CallAsFunc(verify_data, &verify_ret, verify_params, 5),
                "VerifyData should reject invalid base64 after accepting optional V2 params");

    const long sign_file = FindMethod(addin, L"SignFile");
    tVariant sign_file_params[4]{};
    ExpectTrue(tamga::util::SetWString(&memory, &sign_file_params[0], L"__missing_v2_input__.bin"),
               "SignFile input path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &sign_file_params[1], L""),
               "SignFile output path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &sign_file_params[2], L"cades-bes"),
               "SignFile signatureFormat should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &sign_file_params[3], L"base64"),
               "SignFile outputEncoding should be set");
    tVariant sign_file_ret{};
    ExpectFalse(addin.CallAsFunc(sign_file, &sign_file_ret, sign_file_params, 4),
                "SignFile with optional V2 params should reach missing input path");

    const long verify_file = FindMethod(addin, L"VerifyFile");
    tVariant verify_file_params[4]{};
    ExpectTrue(tamga::util::SetWString(&memory, &verify_file_params[0], L"__missing_v2_input__.bin"),
               "VerifyFile input path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_file_params[1], L"not-base64"),
               "VerifyFile signature base64 should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_file_params[2], L"cms-detached"),
               "VerifyFile signatureFormat should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_file_params[3], L"base64"),
               "VerifyFile inputEncoding should be set");
    tVariant verify_file_ret{};
    ExpectFalse(addin.CallAsFunc(verify_file, &verify_file_ret, verify_file_params, 4),
                "VerifyFile should reject invalid base64 after accepting optional V2 params");

#if TAMGA_CRYPTONITE_ENABLED
    auto fixture = GenerateDstuFixture();
    if (!fixture.valid) {
        RecordSkip("DSTU fixture not available");
        return;
    }

    const long configure = FindMethod(addin, L"Configure");
    tVariant config_params[2]{};
    tamga::util::SetBool(&config_params[0], true);
    ExpectTrue(tamga::util::SetWString(&memory, &config_params[1], L""), "Configure offline workDir should be set");
    tVariant config_ret{};
    ExpectTrue(addin.CallAsFunc(configure, &config_ret, config_params, 2), "Configure offline should be callable");

    const long load_key = FindMethod(addin, L"LoadKey");
    tVariant load_params[5]{};
    ExpectTrue(tamga::util::SetBlob(&memory, &load_params[0], fixture.pkcs12_blob),
               "LoadKey auto blob source should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &load_params[1], L"test"), "LoadKey password should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &load_params[2], L"test"), "LoadKey keyPassword should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &load_params[3], L"signer"), "LoadKey alias should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &load_params[4], L"auto"), "LoadKey sourceType should be set");
    tVariant loaded_ret{};
    ExpectTrue(addin.CallAsFunc(load_key, &loaded_ret, load_params, 5), "LoadKey should accept auto + Blob");
    bool loaded = false;
    ExpectTrue(tamga::util::GetBool(&loaded_ret, loaded) && loaded, "LoadKey auto blob should return true");

    const std::vector<std::uint8_t> roundtrip_payload = {'h', 'e', 'l', 'l', 'o'};
    tVariant old_sign_params[1]{};
    ExpectTrue(tamga::util::SetBlob(&memory, &old_sign_params[0], roundtrip_payload),
               "Old SignData payload should be set");
    tVariant old_signature_ret{};
    ExpectTrue(addin.CallAsFunc(sign_data, &old_signature_ret, old_sign_params, 1),
               "Old SignData arity should remain callable");
    std::vector<std::uint8_t> old_signature;
    ExpectTrue(tamga::util::GetBlob(&old_signature_ret, old_signature) && !old_signature.empty(),
               "Old SignData arity should return signature blob");

    // Контейнерні alias-и є файловими форматами, а не синонімами detached CMS.
    // До цієї регресії вони проходили ParseSignatureFormat, але SignData і
    // VerifyData не відхиляли їх та мовчки виконували звичайний CMS-шлях.
    for (const wchar_t* const container_format : {L"asic-s-cades", L"asic-e-cades"}) {
        tVariant container_sign_data_params[3]{};
        ExpectTrue(tamga::util::SetBlob(&memory, &container_sign_data_params[0], roundtrip_payload),
                   "Container SignData payload should be set");
        ExpectTrue(tamga::util::SetWString(&memory, &container_sign_data_params[1], container_format),
                   "Container SignData format should be set");
        ExpectTrue(tamga::util::SetWString(&memory, &container_sign_data_params[2], L"binary"),
                   "Container SignData encoding should be set");
        tVariant container_sign_data_ret{};
        ExpectFalse(addin.CallAsFunc(sign_data, &container_sign_data_ret, container_sign_data_params, 3),
                    "SignData must reject ASiC CAdES container formats instead of returning detached CMS");

        tVariant container_verify_data_params[5]{};
        ExpectTrue(tamga::util::SetBlob(&memory, &container_verify_data_params[0], roundtrip_payload),
                   "Container VerifyData payload should be set");
        ExpectTrue(tamga::util::SetBlob(&memory, &container_verify_data_params[1], old_signature),
                   "Container VerifyData signature should be set");
        ExpectTrue(tamga::util::SetWString(&memory, &container_verify_data_params[2], container_format),
                   "Container VerifyData format should be set");
        ExpectTrue(tamga::util::SetWString(&memory, &container_verify_data_params[3], L"binary"),
                   "Container VerifyData input encoding should be set");
        ExpectTrue(tamga::util::SetWString(&memory, &container_verify_data_params[4], L"none"),
                   "Container VerifyData content encoding should be set");
        tVariant container_verify_data_ret{};
        ExpectFalse(addin.CallAsFunc(verify_data, &container_verify_data_ret, container_verify_data_params, 5),
                    "VerifyData must reject ASiC CAdES container formats instead of verifying detached CMS");
    }

    tVariant valid_verify_params[5]{};
    ExpectTrue(tamga::util::SetBlob(&memory, &valid_verify_params[0], roundtrip_payload),
               "NativeAPI stale report payload should be set");
    ExpectTrue(tamga::util::SetBlob(&memory, &valid_verify_params[1], old_signature),
               "NativeAPI stale report signature should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &valid_verify_params[2], L"cms-detached"),
               "NativeAPI stale report format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &valid_verify_params[3], L"binary"),
               "NativeAPI stale report input encoding should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &valid_verify_params[4], L"none"),
               "NativeAPI stale report content encoding should be set");
    tVariant valid_verify_ret{};
    ExpectTrue(addin.CallAsFunc(verify_data, &valid_verify_ret, valid_verify_params, 5),
               "VerifyData should accept valid detached signature before stale report regression");
    bool valid_verify_ok = false;
    ExpectTrue(tamga::util::GetBool(&valid_verify_ret, valid_verify_ok) && valid_verify_ok,
               "VerifyData should validate detached signature before stale report regression");

    const long get_user_report = FindMethod(addin, L"GetUserReport");
    tVariant success_user_report_ret{};
    ExpectTrue(CallNoArgs(addin, get_user_report, success_user_report_ret),
               "GetUserReport should be callable after successful NativeAPI verify");
    std::wstring success_user_report;
    ExpectTrue(tamga::util::GetWString(&success_user_report_ret, success_user_report),
               "Successful NativeAPI user report should be a string");
    ExpectTrue(success_user_report.find(L"\"present\":true") != std::wstring::npos,
               "Successful NativeAPI user report should contain signer fields before invalid Base64");

    auto expect_invalid_verify_data_user_report = [&](const char* context) {
        auto expect_true_with_context = [](const bool condition, const std::string& message) {
            ExpectTrue(condition, message.c_str());
        };
        tVariant report_ret{};
        expect_true_with_context(CallNoArgs(addin, get_user_report, report_ret),
                                 std::string("GetUserReport should be callable after ") + context);
        std::wstring report;
        expect_true_with_context(tamga::util::GetWString(&report_ret, report),
                                 std::string("User report should be a string after ") + context);
        expect_true_with_context(report.find(L"\"operation\":\"VerifyData\"") != std::wstring::npos,
                                 std::string("User report should identify VerifyData after ") + context);
        expect_true_with_context(report.find(L"\"errorCode\":\"InvalidArgument\"") != std::wstring::npos,
                                 std::string("User report should expose InvalidArgument after ") + context);
        expect_true_with_context(report.find(L"\"present\":false") != std::wstring::npos,
                                 std::string("User report should clear stale signer list after ") + context);
        expect_true_with_context(report.find(L"\"subject\":null") != std::wstring::npos,
                                 std::string("User report must not keep stale signer fields after ") + context);
    };

    auto restore_successful_verify_data_user_report = [&]() {
        tVariant restore_ret{};
        ExpectTrue(addin.CallAsFunc(verify_data, &restore_ret, valid_verify_params, 5),
                   "VerifyData should restore successful user report before validation regression");
        bool restore_ok = false;
        ExpectTrue(tamga::util::GetBool(&restore_ret, restore_ok) && restore_ok,
                   "VerifyData should validate fixture signature before validation regression");
        tVariant restore_report_ret{};
        ExpectTrue(CallNoArgs(addin, get_user_report, restore_report_ret),
                   "GetUserReport should be callable after restored successful VerifyData");
        std::wstring restore_report;
        ExpectTrue(tamga::util::GetWString(&restore_report_ret, restore_report),
                   "Restored VerifyData user report should be a string");
        ExpectTrue(restore_report.find(L"\"present\":true") != std::wstring::npos,
                   "Restored VerifyData user report should contain signer fields");
    };

    tVariant invalid_verify_params[5]{};
    ExpectTrue(tamga::util::SetBlob(&memory, &invalid_verify_params[0], roundtrip_payload),
               "Invalid NativeAPI VerifyData payload should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_params[1], L"not-base64***"),
               "Invalid NativeAPI VerifyData base64 signature should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_params[2], L"cms-detached"),
               "Invalid NativeAPI VerifyData format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_params[3], L"base64"),
               "Invalid NativeAPI VerifyData input encoding should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_params[4], L"none"),
               "Invalid NativeAPI VerifyData content encoding should be set");
    tVariant invalid_verify_ret{};
    ExpectFalse(addin.CallAsFunc(verify_data, &invalid_verify_ret, invalid_verify_params, 5),
                "VerifyData should still reject invalid Base64 at NativeAPI wrapper level");
    expect_invalid_verify_data_user_report("invalid NativeAPI VerifyData Base64");

    restore_successful_verify_data_user_report();
    tVariant invalid_verify_format_params[5]{};
    ExpectTrue(tamga::util::SetBlob(&memory, &invalid_verify_format_params[0], roundtrip_payload),
               "Invalid NativeAPI VerifyData format payload should be set");
    ExpectTrue(tamga::util::SetBlob(&memory, &invalid_verify_format_params[1], old_signature),
               "Invalid NativeAPI VerifyData format signature should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_format_params[2], L"bad-format"),
               "Invalid NativeAPI VerifyData format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_format_params[3], L"binary"),
               "Invalid NativeAPI VerifyData format input encoding should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_format_params[4], L"none"),
               "Invalid NativeAPI VerifyData format content encoding should be set");
    tVariant invalid_verify_format_ret{};
    ExpectFalse(addin.CallAsFunc(verify_data, &invalid_verify_format_ret, invalid_verify_format_params, 5),
                "VerifyData should still reject invalid signatureFormat at NativeAPI wrapper level");
    expect_invalid_verify_data_user_report("invalid NativeAPI VerifyData signatureFormat");

    restore_successful_verify_data_user_report();
    tVariant invalid_verify_encoding_params[5]{};
    ExpectTrue(tamga::util::SetBlob(&memory, &invalid_verify_encoding_params[0], roundtrip_payload),
               "Invalid NativeAPI VerifyData encoding payload should be set");
    ExpectTrue(tamga::util::SetBlob(&memory, &invalid_verify_encoding_params[1], old_signature),
               "Invalid NativeAPI VerifyData encoding signature should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_encoding_params[2], L"cms-detached"),
               "Invalid NativeAPI VerifyData encoding format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_encoding_params[3], L"bad-encoding"),
               "Invalid NativeAPI VerifyData input encoding should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_encoding_params[4], L"none"),
               "Invalid NativeAPI VerifyData encoding content encoding should be set");
    tVariant invalid_verify_encoding_ret{};
    ExpectFalse(addin.CallAsFunc(verify_data, &invalid_verify_encoding_ret, invalid_verify_encoding_params, 5),
                "VerifyData should still reject invalid inputEncoding at NativeAPI wrapper level");
    expect_invalid_verify_data_user_report("invalid NativeAPI VerifyData inputEncoding");

    tVariant attached_params[3]{};
    ExpectTrue(tamga::util::SetBlob(&memory, &attached_params[0], roundtrip_payload),
               "Attached SignData payload should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &attached_params[1], L"cms-attached"),
               "Attached SignData format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &attached_params[2], L"binary"),
               "Attached SignData encoding should be set");
    tVariant attached_ret{};
    ExpectTrue(addin.CallAsFunc(sign_data, &attached_ret, attached_params, 3),
               "SignData cms-attached should be callable");
    std::vector<std::uint8_t> attached_signature;
    ExpectTrue(tamga::util::GetBlob(&attached_ret, attached_signature) && !attached_signature.empty(),
               "SignData cms-attached should return CMS blob");

    tVariant verify_attached_params[5]{};
    tVarInit(&verify_attached_params[0]);
    ExpectTrue(tamga::util::SetBlob(&memory, &verify_attached_params[1], attached_signature),
               "Attached VerifyData signature should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_attached_params[2], L"cms-attached"),
               "Attached VerifyData format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_attached_params[3], L"binary"),
               "Attached VerifyData input encoding should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_attached_params[4], L"binary"),
               "Attached VerifyData content encoding should be set");
    tVariant attached_content_ret{};
    ExpectTrue(addin.CallAsFunc(verify_data, &attached_content_ret, verify_attached_params, 5),
               "VerifyData cms-attached should accept empty data argument");
    std::vector<std::uint8_t> attached_content;
    ExpectTrue(tamga::util::GetBlob(&attached_content_ret, attached_content) &&
                   attached_content == roundtrip_payload,
               "VerifyData cms-attached binary content should return original payload");

    ExpectTrue(tamga::util::SetWString(&memory, &verify_attached_params[4], L"text"),
               "Attached VerifyData text content encoding should be set");
    tVariant attached_text_ret{};
    ExpectTrue(addin.CallAsFunc(verify_data, &attached_text_ret, verify_attached_params, 5),
               "VerifyData cms-attached should support text contentEncoding");
    std::wstring attached_text;
    ExpectTrue(tamga::util::GetWString(&attached_text_ret, attached_text) && attached_text == L"hello",
               "VerifyData cms-attached text content should return original text");

    const auto input_path = MakeTemporaryFixturePath(".txt");
    const auto signature_path = MakeTemporaryFixturePath(".p7s");
    const auto asics_path = MakeTemporaryFixturePath(".asics");
    const auto asics_cades_path = MakeTemporaryFixturePath(".asics");
    const auto asice_cades_path = MakeTemporaryFixturePath(".asice");
    ExpectTrue(WriteBinaryFile(input_path, roundtrip_payload), "V2 SignFile input should be writable");

    tVariant sign_file_real_params[4]{};
    ExpectTrue(tamga::util::SetWString(&memory, &sign_file_real_params[0], input_path.wstring()),
               "SignFile real input path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &sign_file_real_params[1], signature_path.wstring()),
               "SignFile real output path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &sign_file_real_params[2], L"cades-bes"),
               "SignFile real format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &sign_file_real_params[3], L"file"),
               "SignFile real output encoding should be set");
    tVariant sign_file_real_ret{};
    ExpectTrue(addin.CallAsFunc(sign_file, &sign_file_real_ret, sign_file_real_params, 4),
               "SignFile cades-bes file output should be callable");
    bool sign_file_ok = false;
    ExpectTrue(tamga::util::GetBool(&sign_file_real_ret, sign_file_ok) && sign_file_ok,
               "SignFile cades-bes file output should return true");

    tVariant verify_file_real_params[4]{};
    ExpectTrue(tamga::util::SetWString(&memory, &verify_file_real_params[0], input_path.wstring()),
               "VerifyFile real input path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_file_real_params[1], signature_path.wstring()),
               "VerifyFile real signature path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_file_real_params[2], L"cms-detached"),
               "VerifyFile real format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &verify_file_real_params[3], L"file"),
               "VerifyFile real input encoding should be set");
    tVariant verify_file_real_ret{};
    ExpectTrue(addin.CallAsFunc(verify_file, &verify_file_real_ret, verify_file_real_params, 4),
               "VerifyFile file input should be callable");
    bool verify_file_ok = false;
    ExpectTrue(tamga::util::GetBool(&verify_file_real_ret, verify_file_ok) && verify_file_ok,
               "VerifyFile file input should validate generated signature");

    tVariant file_success_user_report_ret{};
    ExpectTrue(CallNoArgs(addin, get_user_report, file_success_user_report_ret),
               "GetUserReport should be callable after successful NativeAPI VerifyFile");
    std::wstring file_success_user_report;
    ExpectTrue(tamga::util::GetWString(&file_success_user_report_ret, file_success_user_report),
               "Successful NativeAPI VerifyFile user report should be a string");
    ExpectTrue(file_success_user_report.find(L"\"present\":true") != std::wstring::npos,
               "Successful NativeAPI VerifyFile user report should contain signer fields before invalid Base64");

    auto expect_invalid_verify_file_user_report = [&](const char* context) {
        auto expect_true_with_context = [](const bool condition, const std::string& message) {
            ExpectTrue(condition, message.c_str());
        };
        tVariant report_ret{};
        expect_true_with_context(CallNoArgs(addin, get_user_report, report_ret),
                                 std::string("GetUserReport should be callable after ") + context);
        std::wstring report;
        expect_true_with_context(tamga::util::GetWString(&report_ret, report),
                                 std::string("User report should be a string after ") + context);
        expect_true_with_context(report.find(L"\"operation\":\"VerifyFile\"") != std::wstring::npos,
                                 std::string("User report should identify VerifyFile after ") + context);
        expect_true_with_context(report.find(L"\"errorCode\":\"InvalidArgument\"") != std::wstring::npos,
                                 std::string("User report should expose InvalidArgument after ") + context);
        expect_true_with_context(report.find(L"\"present\":false") != std::wstring::npos,
                                 std::string("User report should clear stale signer list after ") + context);
        expect_true_with_context(report.find(L"\"subject\":null") != std::wstring::npos,
                                 std::string("User report must not keep stale signer fields after ") + context);
    };

    auto restore_successful_verify_file_user_report = [&]() {
        tVariant restore_ret{};
        ExpectTrue(addin.CallAsFunc(verify_file, &restore_ret, verify_file_real_params, 4),
                   "VerifyFile should restore successful user report before validation regression");
        bool restore_ok = false;
        ExpectTrue(tamga::util::GetBool(&restore_ret, restore_ok) && restore_ok,
                   "VerifyFile should validate generated signature before validation regression");
        tVariant restore_report_ret{};
        ExpectTrue(CallNoArgs(addin, get_user_report, restore_report_ret),
                   "GetUserReport should be callable after restored successful VerifyFile");
        std::wstring restore_report;
        ExpectTrue(tamga::util::GetWString(&restore_report_ret, restore_report),
                   "Restored VerifyFile user report should be a string");
        ExpectTrue(restore_report.find(L"\"present\":true") != std::wstring::npos,
                   "Restored VerifyFile user report should contain signer fields");
    };

    tVariant invalid_verify_file_params[4]{};
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_file_params[0], input_path.wstring()),
               "Invalid NativeAPI VerifyFile input path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_file_params[1], L"not-base64***"),
               "Invalid NativeAPI VerifyFile base64 signature should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_file_params[2], L"cms-detached"),
               "Invalid NativeAPI VerifyFile format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_file_params[3], L"base64"),
               "Invalid NativeAPI VerifyFile input encoding should be set");
    tVariant invalid_verify_file_ret{};
    ExpectFalse(addin.CallAsFunc(verify_file, &invalid_verify_file_ret, invalid_verify_file_params, 4),
                "VerifyFile should still reject invalid Base64 at NativeAPI wrapper level");
    expect_invalid_verify_file_user_report("invalid NativeAPI VerifyFile Base64");

    restore_successful_verify_file_user_report();
    tVariant invalid_verify_file_format_params[4]{};
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_file_format_params[0], input_path.wstring()),
               "Invalid NativeAPI VerifyFile format input path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_file_format_params[1], signature_path.wstring()),
               "Invalid NativeAPI VerifyFile format signature path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_file_format_params[2], L"bad-format"),
               "Invalid NativeAPI VerifyFile format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &invalid_verify_file_format_params[3], L"file"),
               "Invalid NativeAPI VerifyFile format input encoding should be set");
    tVariant invalid_verify_file_format_ret{};
    ExpectFalse(addin.CallAsFunc(verify_file, &invalid_verify_file_format_ret, invalid_verify_file_format_params, 4),
                "VerifyFile should still reject invalid signatureFormat at NativeAPI wrapper level");
    expect_invalid_verify_file_user_report("invalid NativeAPI VerifyFile signatureFormat");

    restore_successful_verify_file_user_report();
    tVariant unsupported_verify_file_mode_params[4]{};
    ExpectTrue(tamga::util::SetWString(&memory, &unsupported_verify_file_mode_params[0], input_path.wstring()),
               "Unsupported NativeAPI VerifyFile mode input path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &unsupported_verify_file_mode_params[1], signature_path.wstring()),
               "Unsupported NativeAPI VerifyFile mode signature path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &unsupported_verify_file_mode_params[2], L"cms-attached"),
               "Unsupported NativeAPI VerifyFile mode format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &unsupported_verify_file_mode_params[3], L"file"),
               "Unsupported NativeAPI VerifyFile mode input encoding should be set");
    tVariant unsupported_verify_file_mode_ret{};
    ExpectFalse(addin.CallAsFunc(verify_file, &unsupported_verify_file_mode_ret, unsupported_verify_file_mode_params, 4),
                "VerifyFile should still reject unsupported cms-attached mode at NativeAPI wrapper level");
    expect_invalid_verify_file_user_report("unsupported NativeAPI VerifyFile mode");

    ExpectTrue(FindMethod(addin, L"SetFileStoreSettings") < 0,
               "Deprecated NativeAPI SetFileStoreSettings should be removed from public dispatch");

    // B-02: `asic-s` через NativeAPI з 0.8.0 підписується XAdES
    // (`SignFileAsicS` -> `SignFileAsicXades`), тож без підсистеми XML цей
    // шлях коректно повертає `NotSupported`. Тест не гейтився за зміною
    // можливостей і робив базову конфігурацію червоною.
#if defined(TAMGA_XML_SIGNATURES_ENABLED)
    tVariant asics_sign_params[4]{};
    ExpectTrue(tamga::util::SetWString(&memory, &asics_sign_params[0], input_path.wstring()),
               "ASiC SignFile input path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &asics_sign_params[1], asics_path.wstring()),
               "ASiC SignFile output path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &asics_sign_params[2], L"asic-s"),
               "ASiC SignFile format should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &asics_sign_params[3], L"file"),
               "ASiC SignFile output encoding should be set");
    tVariant asics_sign_ret{};
    ExpectTrue(addin.CallAsFunc(sign_file, &asics_sign_ret, asics_sign_params, 4),
               "SignFile asic-s file output should be callable");
    bool asics_sign_ok = false;
    ExpectTrue(tamga::util::GetBool(&asics_sign_ret, asics_sign_ok) && asics_sign_ok,
               "SignFile asic-s should return true");

    tVariant asics_verify_params[3]{};
    ExpectTrue(tamga::util::SetWString(&memory, &asics_verify_params[0], asics_path.wstring()),
               "ASiC VerifyFile input path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &asics_verify_params[1], L""),
               "ASiC VerifyFile ignored signature path should be set");
    ExpectTrue(tamga::util::SetWString(&memory, &asics_verify_params[2], L"asic-s"),
               "ASiC VerifyFile format should be set");
    tVariant asics_verify_ret{};
    ExpectTrue(addin.CallAsFunc(verify_file, &asics_verify_ret, asics_verify_params, 3),
               "VerifyFile asic-s should be callable");
    bool asics_verify_ok = false;
    ExpectTrue(tamga::util::GetBool(&asics_verify_ret, asics_verify_ok) && asics_verify_ok,
               "VerifyFile asic-s should return true");
#else
    std::cerr << "  (asic-s через NativeAPI пропущено: збірка без "
                 "TAMGA_ENABLE_XML_SIGNATURES)\n";
#endif

    auto sign_and_verify_cades_container = [&](const wchar_t* const format,
                                                const std::filesystem::path& container_path,
                                                const char* const expected_mimetype,
                                                const char* const expected_signature_entry) {
        tVariant sign_params_local[4]{};
        ExpectTrue(tamga::util::SetWString(&memory, &sign_params_local[0], input_path.wstring()),
                   "ASiC CAdES SignFile input path should be set");
        ExpectTrue(tamga::util::SetWString(&memory, &sign_params_local[1], container_path.wstring()),
                   "ASiC CAdES SignFile output path should be set");
        ExpectTrue(tamga::util::SetWString(&memory, &sign_params_local[2], format),
                   "ASiC CAdES SignFile format should be set");
        ExpectTrue(tamga::util::SetWString(&memory, &sign_params_local[3], L"file"),
                   "ASiC CAdES SignFile output encoding should be set");
        tVariant sign_ret_local{};
        ExpectTrue(addin.CallAsFunc(sign_file, &sign_ret_local, sign_params_local, 4),
                   "SignFile ASiC CAdES alias should be callable");
        bool signed_ok = false;
        ExpectTrue(tamga::util::GetBool(&sign_ret_local, signed_ok) && signed_ok,
                   "SignFile ASiC CAdES alias should return true");

        tamga::asic::AsicReader reader;
        std::string reader_error;
        ExpectTrue(reader.LoadFromFile(container_path.u8string(), reader_error),
                   "ASiC CAdES output should be readable");
        std::string mimetype;
        ExpectTrue(reader.GetMimetype(mimetype) && mimetype == expected_mimetype,
                   "ASiC CAdES output should carry the expected container mimetype");
        std::vector<std::uint8_t> cades_signature;
        ExpectTrue(reader.ExtractFile(expected_signature_entry, cades_signature, reader_error) &&
                       !cades_signature.empty(),
                   "ASiC CAdES alias must create the profile-specific signature entry");

        tVariant verify_params_local[3]{};
        ExpectTrue(tamga::util::SetWString(&memory, &verify_params_local[0], container_path.wstring()),
                   "ASiC CAdES VerifyFile input path should be set");
        ExpectTrue(tamga::util::SetWString(&memory, &verify_params_local[1], L""),
                   "ASiC CAdES VerifyFile ignored signature path should be set");
        ExpectTrue(tamga::util::SetWString(&memory, &verify_params_local[2], format),
                   "ASiC CAdES VerifyFile format should be set");
        tVariant verify_ret_local{};
        ExpectTrue(addin.CallAsFunc(verify_file, &verify_ret_local, verify_params_local, 3),
                   "VerifyFile ASiC CAdES alias should be callable");
        bool verified_ok = false;
        ExpectTrue(tamga::util::GetBool(&verify_ret_local, verified_ok) && verified_ok,
                   "VerifyFile ASiC CAdES alias should validate its container");
    };

    sign_and_verify_cades_container(L"asic-s-cades", asics_cades_path,
                                    "application/vnd.etsi.asic-s+zip",
                                    "META-INF/signature.p7s");
    sign_and_verify_cades_container(L"asic-e-cades", asice_cades_path,
                                    "application/vnd.etsi.asic-e+zip",
                                    "META-INF/signature001.p7s");

    std::error_code ignored;
    std::filesystem::remove(input_path, ignored);
    std::filesystem::remove(signature_path, ignored);
    std::filesystem::remove(asics_path, ignored);
    std::filesystem::remove(asics_cades_path, ignored);
    std::filesystem::remove(asice_cades_path, ignored);
#endif
}
