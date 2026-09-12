// Група тестів, винесена з моноліту `tamga_tests.cpp` (Хвиля 8, п.5).
//
// Інваріант переносу: список `Running <name>`, який друкує бінарник, мусить
// лишитися тим самим і в тому самому порядку — і в КОЖНІЙ з трьох
// конфігурацій окремо, бо в кожній він свій. Саме він, а не зелений ctest,
// доводить, що жодного тесту не загублено.
// Контейнери ключів: JKS (файл, байти, дескриптор), PKCS#12/PKCS#8 PEM.
// Наскрізна тема — зіпсований контейнер має відхилятися, а не парситися
// «наполовину».

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

void TestJksParserRejectsOverflowingDerLength() {
    const auto fixture = FixturePath("jks/unicode-alias-password.jks");
    const auto original = ReadBinaryFixture(fixture);
    ExpectFalse(original.empty(), "JKS fixture must be readable for the DER overflow probe");
    if (original.size() < 32) {
        return;
    }

    static const std::uint8_t kOverflowLength[] = {
        0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    int probes = 0;
    for (std::size_t offset = 4; offset + sizeof(kOverflowLength) < original.size(); offset += 7) {
        std::vector<std::uint8_t> mutated = original;
        std::copy(std::begin(kOverflowLength), std::end(kOverflowLength),
                  mutated.begin() + static_cast<std::ptrdiff_t>(offset));

        tamga::core::JksKeyStoreParser::PrivateKeyEntry entry;
        std::string error;
        // Значення результату не фіксуємо: мутація може як зламати структуру,
        // так і лишити її формально коректною. Важливо інше — виклик мусить
        // повернутися, а не читати за межами буфера.
        (void)tamga::core::JksKeyStoreParser::LoadPrivateKeyEntry(
            mutated, u8"ПарольСховища1", u8"ПарольКлюча2", u8"КлючТест", entry, error);
        ++probes;
    }

    ExpectTrue(probes > 0, "DER overflow probe must actually run at least once");
}

void TestReadJksFileWithUnicodeAliasAndPasswords() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for JKS file fixture");

    const auto fixture = FixturePath("jks/unicode-alias-password.jks");
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyFile(fixture.string(), u8"ПарольСховища1", u8"ПарольКлюча2", u8"КлючТест"),
                      "ReadPrivateKeyFile should accept JKS with Unicode alias and passwords");
    ExpectTrue(session.IsPrivateKeyLoaded(), "ReadPrivateKeyFile should load private key from Unicode JKS fixture");
}

void TestReadJksBinaryWithUnicodeAliasAndPasswords() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for JKS binary fixture");

    const auto fixture = FixturePath("jks/unicode-alias-password.jks");
    const auto key_blob = ReadBinaryFixture(fixture);
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(key_blob, u8"ПарольСховища1", u8"ПарольКлюча2", u8"КлючТест"),
                      "ReadPrivateKeyBinary should accept JKS with Unicode alias and passwords");
}

void TestReadJksDescriptorWithUnicodeAliasAndPasswords() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for JKS descriptor fixture");

    const auto fixture = FixturePath("jks/unicode-alias-password.jks");
    const std::string descriptor =
        std::string("{\"path\":\"") + EscapeJson(fixture.string()) +
        "\",\"password\":\"" + u8"ПарольСховища1" +
        "\",\"keyPassword\":\"" + u8"ПарольКлюча2" +
        "\",\"alias\":\"" + u8"КлючТест" +
        "\"}";

    ExpectSessionTrue(session,
                      session.ReadPrivateKey(descriptor, std::string{}),
                      "ReadPrivateKey descriptor should accept JKS with Unicode alias and passwords");
}

void TestReadJksRejectsWrongAlias() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for wrong alias scenario");

    const auto fixture = FixturePath("jks/unicode-alias-password.jks");
    ExpectFalse(session.ReadPrivateKeyFile(fixture.string(), u8"ПарольСховища1", u8"ПарольКлюча2", u8"НеіснуючийAlias"),
                "ReadPrivateKeyFile should fail for unknown JKS alias");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
               "Wrong JKS alias should set InvalidArgument");
}

#if TAMGA_CRYPTONITE_ENABLED
namespace {

// Синтетичний контейнер ІІТ (`Key-6.dat`) — золотий вектор.
//
// Справжній `Key-6.dat` у репозиторій не кладемо: його відкритий текст і Є
// приватний ключ. Замість цього вектор побудовано зовнішнім стендом за
// ТИМИ САМИМИ параметрами, що були виміряні на реальному контейнері АТ «ІІТ»:
// ключ = 10000 ітерацій ГОСТ 34.311 від пароля "12345678", шифр ГОСТ 28147-89
// у режимі простої заміни з таблицею замін №1, поле mac = 4-байтний imit від
// відкритого тексту. Тому будь-яке відхилення в KDF, кількості ітерацій,
// таблиці замін, режимі шифру чи обчисленні imit ламає саме цей тест.
const std::vector<std::uint8_t> kIitSyntheticContainer = {
    0x30, 0x3C, 0x30, 0x1C, 0x06, 0x0C, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81,
    0x97, 0x46, 0x01, 0x01, 0x01, 0x02, 0x30, 0x0C, 0x04, 0x04, 0xA8, 0x91,
    0x6F, 0xDF, 0x04, 0x04, 0xFB, 0xEB, 0xB0, 0x30, 0x04, 0x1C, 0x24, 0x3E,
    0xB6, 0xED, 0x3B, 0xDC, 0x10, 0x00, 0xB7, 0x0E, 0x42, 0x49, 0x0F, 0x6A,
    0x57, 0xC3, 0xF2, 0x0C, 0x73, 0x7D, 0xD9, 0xA8, 0x3C, 0xF9, 0x98, 0x2D,
    0x91, 0x9F,
};

const std::vector<std::uint8_t> kIitSyntheticPlaintext = {
    0x30, 0x1A, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x0B, 0x2A, 0x86, 0x24,
    0x02, 0x01, 0x01, 0x01, 0x01, 0x03, 0x01, 0x01, 0x04, 0x06, 0x54, 0x41,
    0x4D, 0x47, 0x41, 0x21,
};

} // namespace

void TestIitKeyContainerDecryptsGoldenVector() {
    ExpectTrue(tamga::core::IitKeyContainerParser::Matches(kIitSyntheticContainer),
               "IIT container must be recognised by its 1.3.6.1.4.1.19398.1.1.1.2 OID");

    std::vector<std::uint8_t> pkcs8;
    std::string error;
    ExpectTrue(tamga::core::IitKeyContainerParser::Decrypt(
                   kIitSyntheticContainer, "12345678", pkcs8, error),
               "IIT container must decrypt with the correct password");
    ExpectTrue(pkcs8 == kIitSyntheticPlaintext,
               "IIT container plaintext must match the golden vector byte for byte");

    // Невірний пароль відсікає саме imit, а не «схожість на DER»: помилковий
    // ключ дає випадковий блок, який іноді випадково починається з 0x30.
    std::vector<std::uint8_t> wrong;
    std::string wrong_error;
    ExpectFalse(tamga::core::IitKeyContainerParser::Decrypt(
                    kIitSyntheticContainer, "87654321", wrong, wrong_error),
                "IIT container must reject a wrong password");
    ExpectTrue(wrong.empty(), "Rejected IIT container must not yield key material");
    ExpectTrue(wrong_error.find("MAC mismatch") != std::string::npos,
               "Wrong IIT password must be reported as a MAC mismatch");

    // Обрізаний контейнер має відхилятися структурно, а не парситися «наполовину».
    std::vector<std::uint8_t> truncated(kIitSyntheticContainer.begin(),
                                        kIitSyntheticContainer.begin() + 24);
    std::vector<std::uint8_t> truncated_out;
    std::string truncated_error;
    ExpectFalse(tamga::core::IitKeyContainerParser::Matches(truncated),
                "Truncated IIT container must not be recognised");
    ExpectFalse(tamga::core::IitKeyContainerParser::Decrypt(
                    truncated, "12345678", truncated_out, truncated_error),
                "Truncated IIT container must be rejected");

    // JKS не повинен помилково потрапляти в гілку ІІТ.
    const std::vector<std::uint8_t> jks_head = {0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02};
    ExpectFalse(tamga::core::IitKeyContainerParser::Matches(jks_head),
                "Non-IIT container must not match the IIT branch");
}

void TestReadIitKeyContainerThroughSession() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for IIT container fixture");

    // Наскрізний шлях: розпізнавання формату -> розшифрування -> PKCS#8.
    // Сертифіката контейнер ІІТ не містить, тож завантаження ключа має пройти
    // навіть без нього (підпис CMS відмовить пізніше й чесно).
    ExpectSessionTrue(session,
                      session.ReadPrivateKeyBinary(kIitSyntheticContainer, "12345678"),
                      "ReadPrivateKeyBinary should accept an IIT key container");
    ExpectTrue(session.IsPrivateKeyLoaded(), "IIT container should leave a private key loaded");

    tamga::core::Session bad;
    ExpectTrue(PrepareInitializedSession(bad), "Session should initialize for wrong IIT password");
    ExpectFalse(bad.ReadPrivateKeyBinary(kIitSyntheticContainer, "87654321"),
                "ReadPrivateKeyBinary should reject a wrong IIT password");
    ExpectTrue(bad.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
               "Wrong IIT password should set InvalidArgument");
}
#endif // TAMGA_CRYPTONITE_ENABLED

void TestReadCorruptedContainerBinaryRejectsInvalidArgument() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for corrupted binary fixture");
    const std::vector<std::uint8_t> blob = {0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00};
    ExpectFalse(session.ReadPrivateKeyBinary(blob, "irrelevant"), "ReadPrivateKeyBinary should reject corrupted JKS fixture");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
               "Corrupted binary container should set InvalidArgument");
}

void TestReadCorruptedContainerFileRejectsInvalidArgument() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for corrupted file fixture");
    const std::vector<std::uint8_t> blob = {0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00};
    const auto fixture = MakeTemporaryFixturePath(".jks");
    ExpectTrue(WriteBinaryFile(fixture, blob), "Corrupted fixture file should be writable");
    ExpectFalse(session.ReadPrivateKeyFile(fixture.string(), "irrelevant"), "ReadPrivateKeyFile should reject corrupted JKS fixture");
    ExpectTrue(session.GetLastError().code == tamga::core::ErrorCode::InvalidArgument,
               "Corrupted file container should set InvalidArgument");
    std::error_code ignored;
    std::filesystem::remove(fixture, ignored);
}

void TestReadPkcs12Pkcs8PemEndToEnd() {
    tamga::core::Session session;
    ExpectTrue(PrepareInitializedSession(session), "Session should initialize for PKI fixture scenarios");

    const auto pem = FixturePath("pki/keycert.pem");
    ExpectSessionTrue(session, session.ReadPrivateKeyFile(pem.string(), ""), "ReadPrivateKeyFile should load PEM key+cert fixture");
    ExpectTrue(session.IsPrivateKeyLoaded(), "PEM fixture should mark key as loaded");
}
