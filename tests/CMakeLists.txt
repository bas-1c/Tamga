# Додаткові інтеграційні сценарії підключаються явно; автономні тести їх не потребують.
set(TAMGA_PRIVATE_TEST_DIR "" CACHE PATH "Optional directory with additional integration test sources")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
if(TAMGA_PRIVATE_TEST_DIR AND NOT IS_DIRECTORY "${TAMGA_PRIVATE_TEST_DIR}")
    message(FATAL_ERROR "TAMGA_PRIVATE_TEST_DIR does not exist")
endif()

add_executable(tamga-tests
    tamga_tests.cpp
    support/TestSupport.cpp
    suites/PathBuildingTests.cpp
    suites/PolicyAndSigningTimeTests.cpp
    suites/VerifyReportTests.cpp
    suites/TrustListTests.cpp
    suites/CertificateResolutionTests.cpp
    suites/NativeApiAndPrimitivesTests.cpp
    suites/XmlDsigXadesTests.cpp
    suites/XadesProfileTests.cpp
    suites/XadesNamespaceProfileTests.cpp
    suites/PadesTests.cpp
    suites/UserReportTests.cpp
    suites/ChainValidationTests.cpp
    suites/TrustListSyncTests.cpp
    suites/SessionSettingsTests.cpp
    suites/KeyStoreContainerTests.cpp
    suites/RevocationTests.cpp
    suites/CmsSignVerifyTests.cpp
    suites/AsicContainerTests.cpp
    suites/TransportAndTspUrlTests.cpp
    suites/NativeApiV2Tests.cpp
    suites/CadesTimestampTests.cpp
    suites/UtilityPrimitivesTests.cpp
    suites/PolicyCacheTests.cpp
    suites/CryptoniteInternalsTests.cpp
    suites/TimestampModeTests.cpp
    suites/XmlEngineInternalsTests.cpp
    $<TARGET_OBJECTS:tamga-nativeapi-objects>
    $<TARGET_OBJECTS:tamga-c-api-objects>
)

target_link_libraries(tamga-tests
    PRIVATE
        tamga-core-static
        tamga_miniz
)

target_include_directories(tamga-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)
target_include_directories(tamga-tests SYSTEM PRIVATE ${TAMGA_1C_SDK_DIR})

target_compile_definitions(tamga-tests
    PRIVATE
        TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        TAMGA_STATIC_DEFINE=1
        # З того самого `project()`, що й бібліотека: тест звіряє, що C API
        # повідомляє версію збірки, а не літерал, зафіксований у коді.
        TAMGA_VERSION_STRING="${PROJECT_VERSION}"
)

add_executable(tamga-filesystem-unicode-tests
    filesystem_unicode_tests.cpp
)

target_link_libraries(tamga-filesystem-unicode-tests
    PRIVATE
        tamga-core-static
)

target_include_directories(tamga-filesystem-unicode-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)

# В-04: спільний ліміт розміру недовіреного входу. Не залежить від cryptonite —
# політика живе в util і має перевірятися в БУДЬ-ЯКІЙ конфігурації, зокрема
# діагностичній vendor=OFF, де решта security-сюїт пропускається.
add_executable(tamga-input-limit-tests
    input_limit_tests.cpp
)

target_link_libraries(tamga-input-limit-tests
    PRIVATE
        tamga-core-static
)

target_include_directories(tamga-input-limit-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)

# Хвиля 8, п.2: тесту потрібен корінь дерева — він перевіряє не лише
# поведінку ліміту, а й те, що жодне місце в src/lib не читає файл повз нього.
target_compile_definitions(tamga-input-limit-tests
    PRIVATE
        TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(
    NAME tamga-input-limit-tests
    COMMAND tamga-input-limit-tests
)

add_executable(tamga-user-report-unicode-tests
    user_report_unicode_tests.cpp
)

target_link_libraries(tamga-user-report-unicode-tests
    PRIVATE
        tamga-core-static
)

target_include_directories(tamga-user-report-unicode-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)

# Сторожа МЕХАНІЗМУ дублювання: будь-яка функція, визначена більш ніж в одному
# файлі `src/lib`, мусить бути в записаній базовій лінії. Нова копія — падіння;
# застарілий запис базової лінії — теж падіння, щоб вона лише скорочувалась.
add_executable(tamga-symbol-duplication-tests
    symbol_duplication_tests.cpp
)

target_compile_definitions(tamga-symbol-duplication-tests
    PRIVATE
        TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(
    NAME tamga-symbol-duplication-tests
    COMMAND tamga-symbol-duplication-tests
)

# Хвиля 8, п.5: JSON-шар винесено з моноліту Session у `util/Json`. Тест
# доводить, що консолідація не косметична: стара копія в PolicyCache не
# декодувала \uXXXX, тож round-trip через власний EscapeJson псував значення.
add_executable(tamga-json-util-tests
    json_util_tests.cpp
)

target_link_libraries(tamga-json-util-tests
    PRIVATE
        tamga-core-static
)

target_include_directories(tamga-json-util-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)

add_test(
    NAME tamga-json-util-tests
    COMMAND tamga-json-util-tests
)

# Хвиля 8, п.1: вердикти звіту мають рівно одне джерело (ADR-026). Тест
# закріплює таблицю вердиктів (К-01, В-03, HI-02) і стереже, щоб вердикти
# будувалися лише у `core/policy/VerifyChecks.cpp`.
add_executable(tamga-verify-checks-tests
    verify_checks_tests.cpp
)

target_link_libraries(tamga-verify-checks-tests
    PRIVATE
        tamga-core-static
)

target_include_directories(tamga-verify-checks-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)

target_compile_definitions(tamga-verify-checks-tests
    PRIVATE
        TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(
    NAME tamga-verify-checks-tests
    COMMAND tamga-verify-checks-tests
)

# Хвиля 8, п.2: єдиний DER-декодер у `util/Der`. Тест доводить, що консолідація
# не косметична — стара форма перевірки меж пропускала переповнення, нова ні.
# Залежностей від cryptonite/xml немає — будується в усіх конфігураціях.
add_executable(tamga-der-parsing-tests
    der_parsing_tests.cpp
)

target_link_libraries(tamga-der-parsing-tests
    PRIVATE
        tamga-core-static
)

target_include_directories(tamga-der-parsing-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)

target_compile_definitions(tamga-der-parsing-tests
    PRIVATE
        TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(
    NAME tamga-der-parsing-tests
    COMMAND tamga-der-parsing-tests
)

# Н-12: сторож кодування вихідних текстів. Українські повідомлення звіту
# лежать у рядкових літералах без BOM, тож їх коректність тримається лише на
# `/utf-8` із `tamga_enable_project_compile_policy`. Тест ловить і збереження
# файлу в CP1251, і подвійне кодування, яке лишається валідним UTF-8.
# Залежностей від cryptonite/xml немає — будується в усіх конфігураціях.
add_executable(tamga-source-encoding-tests
    source_encoding_tests.cpp
)

target_compile_definitions(tamga-source-encoding-tests
    PRIVATE
        TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(
    NAME tamga-source-encoding-tests
    COMMAND tamga-source-encoding-tests
)

# Н-08 (завершення): `vcpkg.json` — єдине джерело версій залежностей.
# Сторожа перевіряє, що baseline у маніфесті є і має ту саму форму, яку
# витягує `release.yml`, і що в жодному workflow не лишилося літерала SHA
# поруч зі згадкою vcpkg. Залежностей немає — будується всюди.
add_executable(tamga-vcpkg-baseline-tests
    vcpkg_baseline_tests.cpp
)

target_compile_definitions(tamga-vcpkg-baseline-tests
    PRIVATE
        TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(
    NAME tamga-vcpkg-baseline-tests
    COMMAND tamga-vcpkg-baseline-tests
)

# WP-0 заморожені контракти-headers: compile-guard, що доводить DoD WP-0
# (контракти самодостатні й компілюються незалежно від xml/cryptonite).
add_executable(tamga-wp0-contracts-compile-test
    wp0_contracts_compile_test.cpp
)

target_link_libraries(tamga-wp0-contracts-compile-test
    PRIVATE
        tamga-core-static
)

target_include_directories(tamga-wp0-contracts-compile-test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)

add_test(
    NAME tamga-wp0-contracts-compile-test
    COMMAND tamga-wp0-contracts-compile-test
)

# WP-9: canonical UA algorithm registry mapping tests (pure logic, always built).
add_executable(tamga-xml-algorithm-registry-tests
    xml_algorithm_registry_tests.cpp
)

target_link_libraries(tamga-xml-algorithm-registry-tests
    PRIVATE
        tamga-core-static
)

target_include_directories(tamga-xml-algorithm-registry-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)

add_test(
    NAME tamga-xml-algorithm-registry-tests
    COMMAND tamga-xml-algorithm-registry-tests
)

# WP-7 (HI-01): ASiC manifest parsing hardening. Pure string logic, always
# built — не залежить від xml/cryptonite.
add_executable(tamga-asic-manifest-parser-tests
    asic_manifest_parser_tests.cpp
)

target_link_libraries(tamga-asic-manifest-parser-tests
    PRIVATE
        tamga-core-static
)

target_include_directories(tamga-asic-manifest-parser-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)

add_test(
    NAME tamga-asic-manifest-parser-tests
    COMMAND tamga-asic-manifest-parser-tests
)

# WP-21 security-regression suite (ASiC ZIP hardening). Завжди збирається — не
# залежить від xml/cryptonite. WP-8 закрив діри (zip-bomb/traversal/duplicate),
# тож тест тепер має проходити як звичайний (xfail-маркер знято).
add_executable(tamga-asic-security-tests
    asic_security_tests.cpp
)

target_link_libraries(tamga-asic-security-tests
    PRIVATE
        tamga-core-static
)

target_include_directories(tamga-asic-security-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
)

target_compile_definitions(tamga-asic-security-tests
    PRIVATE
        TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(
    NAME tamga-asic-security-tests
    COMMAND tamga-asic-security-tests
)
set_tests_properties(tamga-asic-security-tests PROPERTIES
    SKIP_RETURN_CODE 77
)

if(TAMGA_CRYPTONITE_TARGETS)
    # tamga-tests безпосередньо включає внутрішні заголовки cryptonite, тому
    # залежність є власною test-only usage requirement, а не частиною
    # публічного інтерфейсу tamga-core-static.
    target_link_libraries(tamga-tests PRIVATE ${TAMGA_CRYPTONITE_TARGETS})
    target_compile_definitions(tamga-tests
        PRIVATE
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
    )
endif()

# Gated XMLDSIG-тести (Phase 2) бачать макрос лише коли увімкнено рушій. Сам
# код XMLDSIG лінкується транзитивно з tamga-core-static.
if(TAMGA_ENABLE_XML_SIGNATURES)
    target_compile_definitions(tamga-tests PRIVATE TAMGA_XML_SIGNATURES_ENABLED=1)
endif()

# Q-013: XmlSecContext crosscheck — компілюється лише до tamga-tests, не до lib.
# Вимагає TAMGA_ENABLE_XMLSEC_CROSSCHECK=ON (і TAMGA_ENABLE_XML_SIGNATURES=ON).
if(TAMGA_ENABLE_XMLSEC_CROSSCHECK)
    target_sources(tamga-tests PRIVATE ${CMAKE_SOURCE_DIR}/src/lib/xmldsig/XmlSecContext.cpp)
    target_compile_definitions(tamga-tests PRIVATE TAMGA_XMLSEC_CROSSCHECK_ENABLED=1)
    target_link_libraries(tamga-tests PRIVATE ${TAMGA_XMLSEC_TARGET})
endif()

if(TAMGA_ENABLE_XML_SIGNATURES AND TAMGA_CRYPTONITE_TARGETS)
    # Частина A/A1: прямий доказ на реальному TL ЦЗО, що RSA-примітив
    # cryptonite працює до підключення RSA до PKIX VerifyAdapter.
    add_executable(tamga-rsa-cryptonite-primitive-tests
        rsa_cryptonite_primitive_tests.cpp
    )
    target_link_libraries(tamga-rsa-cryptonite-primitive-tests
        PRIVATE tamga-core-static ${TAMGA_CRYPTONITE_TARGETS}
    )
    target_include_directories(tamga-rsa-cryptonite-primitive-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )
    target_compile_definitions(tamga-rsa-cryptonite-primitive-tests PRIVATE
        TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        CRYPTONITE_EXPORT=extern
        TAMGA_CRYPTONITE_ENABLED=1
        TAMGA_XML_SIGNATURES_ENABLED=1
    )
    add_test(
        NAME tamga-rsa-cryptonite-primitive-tests
        COMMAND tamga-rsa-cryptonite-primitive-tests
    )

    if(TAMGA_PRIVATE_TEST_DIR)
    add_executable(tamga-diia-xades-regression
        "${TAMGA_PRIVATE_TEST_DIR}/diia_xades_regression.cpp"
    )

    target_link_libraries(tamga-diia-xades-regression
        PRIVATE
            tamga-core-static
    )

    target_include_directories(tamga-diia-xades-regression PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-diia-xades-regression
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
            TAMGA_XML_SIGNATURES_ENABLED=1
    )

    add_test(
        NAME tamga-diia-xades-regression
        COMMAND tamga-diia-xades-regression
    )
    set_tests_properties(tamga-diia-xades-regression PROPERTIES
        SKIP_RETURN_CODE 77
    )
    endif()

    # WP-3: canonical certificate.timeValid (CR-02) — must come from real
    # X.509 chain validation, not an optimistic XAdES-B-LT heuristic.
    # Interop replay: Tamga проти РЕАЛЬНИХ підписів Дія/Вчасно. Саме ця сюїта
    # закриває клас регресій, який внутрішні round-trip тести пропускали
    # (підміна DigestMethod для Купини; мультипідпис CMS).
    if(TAMGA_PRIVATE_TEST_DIR)
    add_executable(tamga-interop-replay-tests
        "${TAMGA_PRIVATE_TEST_DIR}/interop_replay_tests.cpp"
    )

    target_link_libraries(tamga-interop-replay-tests
        PRIVATE
            tamga-core-static
    )

    target_include_directories(tamga-interop-replay-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-interop-replay-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
            TAMGA_XML_SIGNATURES_ENABLED=1
    )

    add_test(
        NAME tamga-interop-replay-tests
        COMMAND tamga-interop-replay-tests
    )
    set_tests_properties(tamga-interop-replay-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )
    endif()

    if(TAMGA_PRIVATE_TEST_DIR)
    add_executable(tamga-certificate-time-valid-tests
        "${TAMGA_PRIVATE_TEST_DIR}/certificate_time_valid_tests.cpp"
    )

    target_link_libraries(tamga-certificate-time-valid-tests
        PRIVATE
            tamga-core-static
    )

    target_include_directories(tamga-certificate-time-valid-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-certificate-time-valid-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
            TAMGA_XML_SIGNATURES_ENABLED=1
    )

    add_test(
        NAME tamga-certificate-time-valid-tests
        COMMAND tamga-certificate-time-valid-tests
    )
    set_tests_properties(tamga-certificate-time-valid-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )
    endif()

    # WP-5: XAdES LT/LTA evidence binding — CertificateValues/RevocationValues
    # must actually be USED (chain building + revocation), not just detected.
    if(TAMGA_PRIVATE_TEST_DIR)
    add_executable(tamga-xades-evidence-binding-tests
        "${TAMGA_PRIVATE_TEST_DIR}/xades_evidence_binding_tests.cpp"
    )

    target_link_libraries(tamga-xades-evidence-binding-tests
        PRIVATE
            tamga-core-static
    )

    target_include_directories(tamga-xades-evidence-binding-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-xades-evidence-binding-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
            TAMGA_XML_SIGNATURES_ENABLED=1
    )

    add_test(
        NAME tamga-xades-evidence-binding-tests
        COMMAND tamga-xades-evidence-binding-tests
    )
    set_tests_properties(tamga-xades-evidence-binding-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )
    endif()

    # Підпис контейнером PKCS#12 БЕЗ certBag із зовнішнім сертифікатом
    # (`.dat`/`.pfx` українських КНЕДП). Регресія на rc=525 і rc=272.
    add_executable(tamga-pkcs12-external-cert-tests
        pkcs12_external_cert_tests.cpp
    )

    target_link_libraries(tamga-pkcs12-external-cert-tests
        PRIVATE
            tamga-core-static
            ${TAMGA_CRYPTONITE_TARGETS}
    )

    target_include_directories(tamga-pkcs12-external-cert-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-pkcs12-external-cert-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
    )

    add_test(
        NAME tamga-pkcs12-external-cert-tests
        COMMAND tamga-pkcs12-external-cert-tests
    )
    set_tests_properties(tamga-pkcs12-external-cert-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )

    # WP-6 (HI-05): extendedKeyUsage через ASN.1 (EkuUtils.h), не byte-pattern.
    add_executable(tamga-eku-utils-tests
        eku_utils_tests.cpp
    )

    target_link_libraries(tamga-eku-utils-tests
        PRIVATE
            tamga-core-static
            ${TAMGA_CRYPTONITE_TARGETS}
    )

    target_include_directories(tamga-eku-utils-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-eku-utils-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
            TAMGA_XML_SIGNATURES_ENABLED=1
    )

    add_test(
        NAME tamga-eku-utils-tests
        COMMAND tamga-eku-utils-tests
    )
    set_tests_properties(tamga-eku-utils-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )

    # WP-21 security-regression: multi-signature ASiC-E false positive (C2/HI-03).
    # WP-2 тепер перевіряє всі підписи контейнера, тож тест став реальним зеленим
    # (xfail знято).
    if(TAMGA_PRIVATE_TEST_DIR)
    add_executable(tamga-xmldsig-security-tests
        "${TAMGA_PRIVATE_TEST_DIR}/xmldsig_security_tests.cpp"
    )

    target_link_libraries(tamga-xmldsig-security-tests
        PRIVATE
            tamga-core-static
    )

    target_include_directories(tamga-xmldsig-security-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-xmldsig-security-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
            TAMGA_XML_SIGNATURES_ENABLED=1
    )

    add_test(
        NAME tamga-xmldsig-security-tests
        COMMAND tamga-xmldsig-security-tests
    )
    set_tests_properties(tamga-xmldsig-security-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )
    endif()

    # WP-1 anti-wrapping regression: real green test (scoped SignatureContext
    # rejects XSW variants). Not xfail.
    if(TAMGA_PRIVATE_TEST_DIR)
    add_executable(tamga-xmldsig-wrapping-tests
        "${TAMGA_PRIVATE_TEST_DIR}/xmldsig_wrapping_tests.cpp"
    )

    target_link_libraries(tamga-xmldsig-wrapping-tests
        PRIVATE
            tamga-core-static
    )

    target_include_directories(tamga-xmldsig-wrapping-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-xmldsig-wrapping-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
            TAMGA_XML_SIGNATURES_ENABLED=1
    )

    add_test(
        NAME tamga-xmldsig-wrapping-tests
        COMMAND tamga-xmldsig-wrapping-tests
    )
    set_tests_properties(tamga-xmldsig-wrapping-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )
    endif()

    # WP-12: XmlSignatureVerifier::VerifyAll -- кілька ds:Signature в одному
    # документі, з незалежним per-signature вердиктом, без регресії наявного
    # anti-wrapping захисту.
    add_executable(tamga-xmldsig-multisig-tests
        xmldsig_multisig_tests.cpp
    )

    target_link_libraries(tamga-xmldsig-multisig-tests
        PRIVATE
            tamga-core-static
            ${TAMGA_CRYPTONITE_TARGETS}
    )

    target_include_directories(tamga-xmldsig-multisig-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-xmldsig-multisig-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
            TAMGA_XML_SIGNATURES_ENABLED=1
    )

    add_test(
        NAME tamga-xmldsig-multisig-tests
        COMMAND tamga-xmldsig-multisig-tests
    )
    set_tests_properties(tamga-xmldsig-multisig-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )

    # WP-2 (продовження): XadesVerifier::VerifyAll -- per-signature scoping на
    # XAdES-рівні (SignedProperties/CertDigest/CertificateValues), не лише на
    # XMLDSIG-рівні (tamga-xmldsig-multisig-tests).
    add_executable(tamga-xades-multisig-tests
        xades_multisig_tests.cpp
    )

    target_link_libraries(tamga-xades-multisig-tests
        PRIVATE
            tamga-core-static
            ${TAMGA_CRYPTONITE_TARGETS}
    )

    target_include_directories(tamga-xades-multisig-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-xades-multisig-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
            TAMGA_XML_SIGNATURES_ENABLED=1
    )

    add_test(
        NAME tamga-xades-multisig-tests
        COMMAND tamga-xades-multisig-tests
    )
    set_tests_properties(tamga-xades-multisig-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )

    # В-02/С-01: перевірка відкликання через CRL має бути fail-closed —
    # без issuer-сертифіката підпис CRL ніде не перевіряється, а прострочений
    # CRL не є доказом «не відкликаний».
    add_executable(tamga-revocation-security-tests
        revocation_security_tests.cpp
    )

    target_link_libraries(tamga-revocation-security-tests
        PRIVATE
            tamga-core-static
    )

    target_include_directories(tamga-revocation-security-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-revocation-security-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
    )

    add_test(
        NAME tamga-revocation-security-tests
        COMMAND tamga-revocation-security-tests
    )
    set_tests_properties(tamga-revocation-security-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )

    # WP-7 ASiC-E container coverage regression (M3): added unsigned file detected.
    if(TAMGA_PRIVATE_TEST_DIR)
    add_executable(tamga-asic-coverage-tests
        "${TAMGA_PRIVATE_TEST_DIR}/asic_coverage_tests.cpp"
    )

    target_link_libraries(tamga-asic-coverage-tests
        PRIVATE
            tamga-core-static
    )

    target_include_directories(tamga-asic-coverage-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-asic-coverage-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            CRYPTONITE_EXPORT=extern
            TAMGA_CRYPTONITE_ENABLED=1
            TAMGA_XML_SIGNATURES_ENABLED=1
    )

    add_test(
        NAME tamga-asic-coverage-tests
        COMMAND tamga-asic-coverage-tests
    )
    set_tests_properties(tamga-asic-coverage-tests PROPERTIES
        SKIP_RETURN_CODE 77
    )
    endif()
endif()

if(TAMGA_ENABLE_PDF_SIGNATURES)
    target_compile_definitions(tamga-tests PRIVATE TAMGA_PDF_SIGNATURES_ENABLED=1)
    target_link_libraries(tamga-tests PRIVATE ${TAMGA_QPDF_TARGET})
    # Interop-сюїта гейтиться на XMLDSIG, тож існує і в конфігурації "XML без
    # PDF" (linux-xmldsig у CI). Без цього визначення її PAdES-фікстури не
    # відрізнили б "рушій не зібрано" від справжньої регресії підпису.
    if(TARGET tamga-interop-replay-tests)
        target_compile_definitions(tamga-interop-replay-tests PRIVATE TAMGA_PDF_SIGNATURES_ENABLED=1)
    endif()

    # К-01: PAdES coverage regression. Документ, змінений після підписання
    # (дописані байти або інкрементальне оновлення, що підміняє вміст
    # сторінки), не повинен звітуватися як валідно підписаний. Сюїта тримає
    # і зворотний бік: незмінені PAdES-LT (/DSS поза ByteRange) та LTA мають
    # лишатися прийнятними.
    if(TAMGA_CRYPTONITE_TARGETS)
        if(TAMGA_PRIVATE_TEST_DIR)
        add_executable(tamga-pades-security-tests
            "${TAMGA_PRIVATE_TEST_DIR}/pades_security_tests.cpp"
        )

        target_link_libraries(tamga-pades-security-tests
            PRIVATE
                tamga-core-static
                ${TAMGA_QPDF_TARGET}
        )

        target_include_directories(tamga-pades-security-tests PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/lib
        )

        target_compile_definitions(tamga-pades-security-tests
            PRIVATE
                TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
                CRYPTONITE_EXPORT=extern
                TAMGA_CRYPTONITE_ENABLED=1
                TAMGA_PDF_SIGNATURES_ENABLED=1
        )

        add_test(
            NAME tamga-pades-security-tests
            COMMAND tamga-pades-security-tests
        )
        set_tests_properties(tamga-pades-security-tests PROPERTIES
            SKIP_RETURN_CODE 77
        )
        endif()
    endif()
endif()

# TAMGA_ENABLE_LIVE_POLICY_TESTS — повернено 2026-08-28 РАЗОМ із тестами.
#
# Історія варта одного абзацу. Опція існувала від першого коміту і додавала
# компіляційне визначення, якого не читав жоден файл: вона обіцяла «тести
# проти реальних сервісів ЦЗО/КНЕДП», а вмикання не змінювало нічого.
# Попередній аудит фіксував це як V-11 (no-op). Опцію прибрали з умовою, що
# вона повернеться разом із тестами, які вмикатиме, — і не раніше.
#
# Тепер вона вмикає `tests/live_policy_tests.cpp`: реальну синхронізацію з
# ЦЗО з перевіркою ІНВАРІАНТІВ (не поточних чисел — вони змінюються щоразу,
# коли ЦЗО оновлює список). Правила, за якими сюїта написана, — у
# `docs/live-replay-suite-dod.md`.
#
# Вимкнена типово навмисно: жоден звичайний прогін не має ходити в мережу, а
# тим паче бити по державному сервісу на кожен push.
option(TAMGA_ENABLE_LIVE_POLICY_TESTS "Enable live TL/OCSP/TSP validation tests" OFF)
if(TAMGA_ENABLE_LIVE_POLICY_TESTS)
    add_executable(tamga-live-policy-tests
        live_policy_tests.cpp
    )

    target_link_libraries(tamga-live-policy-tests
        PRIVATE
            tamga-core-static
    )

    target_include_directories(tamga-live-policy-tests
        PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/lib
    )

    target_compile_definitions(tamga-live-policy-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
    )

    add_test(
        NAME tamga-live-policy-tests
        COMMAND tamga-live-policy-tests
    )

    # Недоступність ЦЗО -> "Skipped", а не "Failed". Тест перевіряє НАШУ
    # поведінку, а не аптайм сервісу; провал резервується для випадку, коли
    # сервіс відповів, а ми обробили відповідь неправильно.
    set_tests_properties(tamga-live-policy-tests PROPERTIES
        SKIP_RETURN_CODE 77
        LABELS "live"
    )

    # П-19: живі перевірки OCSP і TSP — ОКРЕМІ тести від TL-перевірки вище.
    #
    # Навіщо окремо. `tamga-live-policy-tests` доводить, що ми коректно БЕРЕМО
    # довіру з ЦЗО, і нічого не каже про найдовший шлях відмови: «список
    # синхронізувався, а сервіс за адресою З НЬОГО не відповідає або відповідає
    # інакше». Кожен із тестів нижче осмислений і тоді, коли TL-перевірку
    # пропущено.
    #
    # Один бінарник, чотири зареєстровані тести: сценарій обирається аргументом.
    # Так спільні хелпери (звідки беруться адреси, як класифікується результат)
    # лишаються в одному місці, а CTest усе одно бачить окремі тести з
    # окремими вердиктами.
    add_executable(tamga-live-service-tests
        live_service_tests.cpp
        support/TestSupport.cpp
        $<TARGET_OBJECTS:tamga-nativeapi-objects>
        $<TARGET_OBJECTS:tamga-c-api-objects>
    )

    target_link_libraries(tamga-live-service-tests
        PRIVATE
            tamga-core-static
            tamga_miniz
    )

    target_include_directories(tamga-live-service-tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/lib
    )
    target_include_directories(tamga-live-service-tests SYSTEM PRIVATE ${TAMGA_1C_SDK_DIR})

    target_compile_definitions(tamga-live-service-tests
        PRIVATE
            TAMGA_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            TAMGA_STATIC_DEFINE=1
    )

    if(TAMGA_CRYPTONITE_TARGETS)
        target_link_libraries(tamga-live-service-tests PRIVATE ${TAMGA_CRYPTONITE_TARGETS})
        target_compile_definitions(tamga-live-service-tests
            PRIVATE
                CRYPTONITE_EXPORT=extern
                TAMGA_CRYPTONITE_ENABLED=1
        )
    endif()
    if(TAMGA_ENABLE_XML_SIGNATURES)
        target_compile_definitions(tamga-live-service-tests PRIVATE TAMGA_XML_SIGNATURES_ENABLED=1)
    endif()
    if(TAMGA_ENABLE_PDF_SIGNATURES)
        target_compile_definitions(tamga-live-service-tests PRIVATE TAMGA_PDF_SIGNATURES_ENABLED=1)
    endif()

    # tamga-live-ocsp-tests / tamga-live-tsp-tests — ходять у мережу за
    # адресами З ДОВІРЧОГО СПИСКУ (жодної зашитої адреси).
    # tamga-live-replay-* — двійники на детермінованому вході (правило 3 DoD):
    # без мережі, мусять бути зеленими завжди, зокрема тоді, коли КНЕДП лежить
    # і живе покриття зникає разом із ним.
    foreach(_tamga_live_case IN ITEMS ocsp tsp replay-ocsp replay-tsp)
        add_test(
            NAME tamga-live-${_tamga_live_case}-tests
            COMMAND tamga-live-service-tests ${_tamga_live_case}
        )
        set_tests_properties(tamga-live-${_tamga_live_case}-tests PROPERTIES
            SKIP_RETURN_CODE 77
            LABELS "live"
        )
    endforeach()
endif()


add_test(
    NAME tamga-tests
    COMMAND tamga-tests
)

add_test(
    NAME tamga-filesystem-unicode-tests
    COMMAND tamga-filesystem-unicode-tests
)

add_test(
    NAME tamga-user-report-unicode-tests
    COMMAND tamga-user-report-unicode-tests
)

add_test(
    NAME export_contract_files
    COMMAND ${CMAKE_COMMAND}
        -DTAMGA_SOURCE_DIR=${CMAKE_SOURCE_DIR}
        -P ${CMAKE_SOURCE_DIR}/tests/export-contract-files.cmake
)

# C ABI export gate: tamga-lib is a public FFI boundary, so accidental C++ or
# vendor exports must fail the test instead of becoming part of the ABI.
add_test(
    NAME tamga-c-api-export-contract
    COMMAND ${CMAKE_COMMAND}
        -DTAMGA_C_API_LIBRARY=$<TARGET_FILE:tamga-lib>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/c-api-export-contract.cmake
)

# Install and consume the package from an independent CMake project. This
# catches absolute build/dependency paths and proves that the public header is
# usable from a C translation unit.
add_test(
    NAME tamga-installed-package-consumer
    COMMAND ${CMAKE_COMMAND}
        -DTAMGA_BUILD_DIR=${CMAKE_BINARY_DIR}
        -DTAMGA_SOURCE_DIR=${CMAKE_SOURCE_DIR}
        -DTAMGA_GENERATOR=${CMAKE_GENERATOR}
        # Платформа генератора — ОКРЕМИЙ прапорець `-A`, вона не входить у
        # назву генератора. Без неї споживач під Visual Studio збирався б x64
        # незалежно від того, що встановлений пакет 32-бітний, і
        # `find_package(Tamga)` відхиляв би конфіг як несумісний
        # («version: 0.9.1 (32bit)»). Під Ninja змінна порожня — там
        # розрядність задає оточення компілятора.
        -DTAMGA_GENERATOR_PLATFORM=${CMAKE_GENERATOR_PLATFORM}
        -DTAMGA_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}
        -DTAMGA_C_COMPILER=${CMAKE_C_COMPILER}
        -DTAMGA_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        "-DTAMGA_C_FLAGS=${CMAKE_C_FLAGS}"
        "-DTAMGA_CXX_FLAGS=${CMAKE_CXX_FLAGS}"
        "-DTAMGA_EXE_LINKER_FLAGS=${CMAKE_EXE_LINKER_FLAGS}"
        -DTAMGA_RC_COMPILER=${TAMGA_RC_COMPILER}
        -DTAMGA_MT_COMPILER=${TAMGA_MT_COMPILER}
        -DTAMGA_CONFIG=$<CONFIG>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/package-consumer/run.cmake
)

if(TAMGA_BUILD_CLI)
    add_test(
        NAME tamga-cli-help
        COMMAND tamga-cli help
    )
    set_tests_properties(tamga-cli-help PROPERTIES
        PASS_REGULAR_EXPRESSION "asic-s / asic-e.*XAdES"
    )
    add_test(
        NAME tamga-cli-global-help-flag-ignores-config
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=--help|--config|missing.conf"
            -DEXPECT_CODE=0 "-DMATCH=Tamga CLI" "-DNOMATCH=Cannot read config"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-global-help-command-ignores-config
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=help|--config|missing.conf"
            -DEXPECT_CODE=0 "-DMATCH=Tamga CLI" "-DNOMATCH=Cannot read config"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-media
        COMMAND tamga-cli media
    )
    add_test(
        NAME tamga-cli-trust-help
        COMMAND tamga-cli trust --help
    )
    set_tests_properties(tamga-cli-trust-help PROPERTIES
        PASS_REGULAR_EXPRESSION "trust sync"
    )
    add_test(
        NAME tamga-cli-trust-help-ignores-config
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=trust|--help|--config|missing.conf"
            -DEXPECT_CODE=0 "-DMATCH=trust sync"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-verify-report-mode-help
        COMMAND tamga-cli verify --help
    )
    set_tests_properties(tamga-cli-verify-report-mode-help PROPERTIES
        PASS_REGULAR_EXPRESSION "technical-json"
    )
    add_test(
        NAME tamga-cli-verify-help-ignores-incomplete-option
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=verify|--help|--offline"
            -DEXPECT_CODE=0 "-DMATCH=technical-json"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-verify-report-mode-invalid-early
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=verify|--report|xml"
            -DEXPECT_CODE=1 "-DMATCH=Unknown report mode"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-verify-file-report-mode-invalid-early
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=verify-file|--report|xml"
            -DEXPECT_CODE=1 "-DMATCH=Unknown report mode"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-trust-sync-timeout-range
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=trust|sync|--work-dir|${CMAKE_BINARY_DIR}/cli-trust-range|--timeout-ms|0"
            -DEXPECT_CODE=1 "-DMATCH=Invalid numeric trust sync option"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-trust-sync-ttl-range
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=trust|sync|--work-dir|${CMAKE_BINARY_DIR}/cli-trust-range|--ttl-hours|0"
            -DEXPECT_CODE=1 "-DMATCH=Invalid numeric trust sync option"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-trust-sync-rejects-offline
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=trust|sync|--work-dir|${CMAKE_BINARY_DIR}/cli-trust-offline|--offline|true"
            -DEXPECT_CODE=1 "-DMATCH=online-only"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-verify-profile-invalid-early
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=verify|--validation-profile|badprofile"
            -DEXPECT_CODE=1 "-DMATCH=Unknown validation profile"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-verify-level-invalid-early
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=verify|--validation-level|badlevel"
            -DEXPECT_CODE=1 "-DMATCH=Unknown validation level"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-verify-profile-help-shown
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=verify|--help"
            -DEXPECT_CODE=0 "-DMATCH=validation-profile"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-sign-format-invalid-early
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=sign-file|--format|badformat|--input|dummy.bin|--output|dummy.sig"
            -DEXPECT_CODE=1 "-DMATCH=Unknown signature format"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-verify-format-invalid-early
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=verify-file|--format|badformat|--input|dummy.bin"
            -DEXPECT_CODE=1 "-DMATCH=Unknown signature format"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
    add_test(
        NAME tamga-cli-sign-missing-key-exit-code
        COMMAND ${CMAKE_COMMAND}
            -DCLI=$<TARGET_FILE:tamga-cli> "-DARGS=sign-file|--input|dummy.bin|--output|dummy.sig"
            -DEXPECT_CODE=2
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run-cli-check.cmake
    )
endif()

# Windows CI запускає тести з окремого CTest-процесу. Для XMLDSIG/PAdES release
# build виконувані файли залежать від runtime DLL з vcpkg, а також від DLL у
# multi-config output каталогах. Явно додаємо ці директорії в PATH для всіх
# CTest-тестів, щоб падіння запуску не маскувалися як помилки тестів.
if(WIN32)
    set(_tamga_test_runtime_paths
        "$<TARGET_FILE_DIR:tamga-tests>"
        "$<TARGET_FILE_DIR:tamga-filesystem-unicode-tests>"
        "$<TARGET_FILE_DIR:tamga-user-report-unicode-tests>"
    )
    if(TAMGA_ENABLE_XML_SIGNATURES AND TAMGA_CRYPTONITE_TARGETS)
        list(APPEND _tamga_test_runtime_paths "$<TARGET_FILE_DIR:tamga-rsa-cryptonite-primitive-tests>")
        if(TARGET tamga-diia-xades-regression)
            list(APPEND _tamga_test_runtime_paths "$<TARGET_FILE_DIR:tamga-diia-xades-regression>")
        endif()
    endif()
    if(TAMGA_BUILD_CLI)
        list(APPEND _tamga_test_runtime_paths "$<TARGET_FILE_DIR:tamga-cli>")
    endif()
    foreach(_tamga_prefix IN LISTS CMAKE_PREFIX_PATH)
        list(APPEND _tamga_test_runtime_paths "${_tamga_prefix}/bin")
    endforeach()
    # Рантайм ASan (див. cmake/Sanitizers.cmake): без нього збірка з
    # TAMGA_ENABLE_SANITIZERS=ON запускається лише з Developer Command Prompt.
    if(TAMGA_ASAN_RUNTIME_DIR)
        list(APPEND _tamga_test_runtime_paths "${TAMGA_ASAN_RUNTIME_DIR}")
    endif()

    set(_tamga_test_env_mods "")
    foreach(_tamga_path IN LISTS _tamga_test_runtime_paths)
        list(APPEND _tamga_test_env_mods "PATH=path_list_prepend:${_tamga_path}")
    endforeach()

    # Той самий набір потрібен і тестам із підкаталогів (tests/fuzz), а вони не
    # потрапляють у DIRECTORY PROPERTY TESTS цього каталогу.
    set(TAMGA_TEST_ENV_MODIFICATION "${_tamga_test_env_mods}")

    get_property(_tamga_defined_tests DIRECTORY PROPERTY TESTS)
    if(_tamga_defined_tests)
        set_tests_properties(${_tamga_defined_tests} PROPERTIES
            ENVIRONMENT_MODIFICATION "${_tamga_test_env_mods}"
        )
    endif()
endif()

# Усі цілі, створені безпосередньо в цьому каталозі, компілюються з тією
# самою first-party warning/safety policy, що й виробничий код. Цілі з
# tests/fuzz до цієї directory property не входять і вмикають policy у своєму CMakeLists.
get_property(_tamga_local_test_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
foreach(_tamga_test_target IN LISTS _tamga_local_test_targets)
    get_target_property(_tamga_test_target_type ${_tamga_test_target} TYPE)
    if(_tamga_test_target_type STREQUAL "EXECUTABLE")
        tamga_enable_project_compile_policy(${_tamga_test_target})
    endif()
endforeach()

# Fuzz-цілі та повтор корпусу (див. tests/fuzz/CMakeLists.txt і ADR 021).
add_subdirectory(fuzz)

# П-04: кількість зареєстрованих тестів — перевірюване число, а не запис у
# документі.
#
# `docs/testing-strategy.md` називає себе єдиним джерелом цих чисел і водночас
# суперечив сам собі: таблиця казала 47/32/31, розділ CI — 52/37/36, а
# фактично було 53/38/37. План при цьому спирається на правило «будь-яке
# зменшення цих чисел — регресія», тож інваріант був непрацездатний: невідомо,
# з чим порівнювати, і всі три записані числа менші за фактичні.
#
# Тепер число звіряється на етапі configure для ТРЬОХ задокументованих
# конфігурацій. Інші комбінації опцій (напр. XML без PDF) не гейтяться — для
# них немає задокументованого baseline, і вигадувати його тут було б гірше за
# відсутність перевірки.
get_property(_tamga_tests_here DIRECTORY PROPERTY TESTS)
get_property(_tamga_tests_fuzz DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/fuzz" PROPERTY TESTS)
set(_tamga_all_tests ${_tamga_tests_here} ${_tamga_tests_fuzz})
list(LENGTH _tamga_all_tests _tamga_test_count)

# Жива сюїта — окрема опція поза трьома штатними конфігураціями.
#
# П-19: раніше тут стояло `math(EXPR ... - 1)`. Одиниця була вірна рівно доти,
# доки живий тест був один; щойно їх стало пʼять, гейт почав би віднімати одну
# — і порівнювати з baseline число, більше за фактичне для трьох штатних
# конфігурацій. Помилка була б МОВЧАЗНОЮ в найгіршому напрямку: гейт, який
# «спрацював», але звірив не те.
#
# Тепер віднімається фактична кількість зареєстрованих живих тестів. Число
# нізвідки не переписується: воно рахується з тих самих імен, які щойно
# зареєстровано, тож додавання чи прибирання живого тесту не потребує правки
# арифметики і не може її розсинхронізувати.
set(_tamga_live_test_names "")
foreach(_tamga_registered_test IN LISTS _tamga_all_tests)
    if(_tamga_registered_test MATCHES "^tamga-live-")
        list(APPEND _tamga_live_test_names "${_tamga_registered_test}")
    endif()
endforeach()
list(LENGTH _tamga_live_test_names _tamga_live_test_count)
if(_tamga_live_test_count GREATER 0)
    message(STATUS "Tamga: живих тестів (мітка live) = ${_tamga_live_test_count}: ${_tamga_live_test_names}")
    math(EXPR _tamga_test_count "${_tamga_test_count} - ${_tamga_live_test_count}")
endif()

set(_tamga_expected_test_count "")
if(TAMGA_CRYPTONITE_TARGETS AND TAMGA_ENABLE_XML_SIGNATURES AND TAMGA_ENABLE_PDF_SIGNATURES)
    set(_tamga_expected_test_count 46)
    if(TAMGA_PRIVATE_TEST_DIR)
        set(_tamga_expected_test_count 54)
    endif()
    set(_tamga_expected_config "постачання (vendor=ON, XML=ON, PDF=ON)")
elseif(TAMGA_CRYPTONITE_TARGETS AND NOT TAMGA_ENABLE_XML_SIGNATURES AND NOT TAMGA_ENABLE_PDF_SIGNATURES)
    set(_tamga_expected_test_count 38)
    set(_tamga_expected_config "базова (vendor=ON, без XML/PDF)")
elseif(NOT TAMGA_CRYPTONITE_TARGETS AND NOT TAMGA_ENABLE_XML_SIGNATURES AND NOT TAMGA_ENABLE_PDF_SIGNATURES)
    set(_tamga_expected_test_count 37)
    set(_tamga_expected_config "діагностична (vendor=OFF)")
endif()

message(STATUS "Tamga: зареєстровано тестів CTest = ${_tamga_test_count}")
if(_tamga_expected_test_count)
    if(NOT _tamga_test_count EQUAL _tamga_expected_test_count)
        message(FATAL_ERROR
            "Конфігурація ${_tamga_expected_config} зареєструвала "
            "${_tamga_test_count} тестів, а задокументовано "
            "${_tamga_expected_test_count}.\n"
            "Якщо тест додано або прибрано свідомо — оновіть це число ТУТ і в "
            "docs/testing-strategy.md однією зміною. Якщо ні — тест зник "
            "мовчки, і саме це мала спіймати ця перевірка.")
    endif()
endif()
