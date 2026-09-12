cmake_minimum_required(VERSION 3.23)
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()
if(CMAKE_HOST_UNIX AND CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
endif()

# 0.10.0 — minor, бо змінюються і формат звіту, і розкладка створюваного PDF.
#
# Звіт: `schemaVersion` 2.1 -> 2.2 (ADR-035). Додано `timestamp.details[]` і
# `signatures[].timestamps[]` — окремий результат КОЖНОЇ мітки часу замість
# одного зведеного прапорця. Споживач, який читає лише старі поля, змін не
# помітить; `LTV_VALID` став суворішим — тепер вимагає підтверджених доказів
# усіх підписантів І повної перевірки врахованих TSA.
#
# PAdES: ADR-034 — Catalog оновлюється зі збереженням номера й покоління,
# трейлер успадковує `/Info` і перший `/ID`, `ByteRange` виключає весь рядок
# `/Contents` разом із `<` і `>`, а DSS і DocTimeStamp додаються ОКРЕМИМИ
# ревізіями. Раніше підписані документи лишаються перевірними: верифікатор
# бере `/ByteRange` із самого файлу.
#
# Решта циклу — виправлення за аудитом 2026-09-08: ліміт вкладеності JSON
# (40 КБ вводу валили процес-хост), IPv6 transition-діапазони (6to4 для
# 127.0.0.1 вважався публічним), обірване тіло WinHTTP видавалося за успіх,
# ранні відмови API лишали чужий звіт, CLI ковтав невдачу `--evidence-out`,
# кеш реєстру КНЕДП був вічним, ключ за відносним шляхом не бачив сертифікат
# поруч. Плюс шість дефектів складання, видимих лише в CI.
#
# 0.9.1 — patch: PAdES оголошує основний підпис як `ETSI.CAdES.detached`,
# ASiC-E/CAdES формує нумеровану пару `ASiCManifest001.xml` / `signature001.p7s`
# з Купиною-256 у маніфесті, а NativeAPI коректно маршрутизує явні alias-и
# `asic-s-cades` / `asic-e-cades`. `SignPdf` backward-compatible розширено
# необов'язковим параметром профілю B/T/LT/LTA.
#
# 0.9.0 — minor: типові `asic-s`/`asic-e` перейшли на XAdES-розкладку, яку
# створює і читає українська екосистема (Дія, ІІТ): META-INF/signatures*.xml
# плюс ODF-маніфест для ASiC-E. Попередня CAdES-розкладка лишилася доступною
# під іменами `asic-s-cades` / `asic-e-cades`. Разом із цим прибрано подвійне
# штампування (окремий META-INF/timestamp.tst поруч із CAdES-T), відновлено
# видимість невдалого TSP-запиту і зроблено дайджести XAdES-будівника
# симетричними до верифікатора за явно оголошеним алгоритмом підпису.
#
# 0.8.0 — minor: розкладка контейнерів ASiC приведена до ETSI EN 319 162-1.
# Змінюється БАЙТОВИЙ вигляд того, що ми створюємо: ASiC-S тепер пише
# `META-INF/signature.p7s` (було `signatures.p7s`), а в ASiC-E маніфест несе
# обов'язкові `ds:DigestMethod`/`ds:DigestValue` і підпис обчислюється НАД
# МАНІФЕСТОМ, а не над документом. Раніше створені контейнери лишаються
# читабельними, але сторонні валідатори їх не приймали — саме це й виправлено.
#
# 0.7.0 — minor: набір ПРИЙНЯТНИХ ключових контейнерів розширився, і разом із
# ним змінилася поведінка підпису. Тепер читаються власний контейнер АТ «ІІТ»
# (`Key-6.dat`, OID 1.3.6.1.4.1.19398.1.1.1.2) і `.ZS2` ЦСК «Україна» (PKCS#12
# з Купиною-KMAC та Калиною-256 CBC) — обидва раніше відмовляли (rc=102 і
# rc=536). У контейнері з двома ключами тепер вибирається той, що відповідає
# сертифікату підписанта, а не перший; сертифікат ключа протоколів розподілу
# ключів більше не підписує (гейт `keyUsage`). Патч vendor `0018` виправив
# підпис ключем із сертифікатом «епохи Купини»: раніше він створювався, але не
# проходив перевірку.
#
# Гейт `keyUsage` — саме та зміна, через яку це minor, а не patch: конфігурації,
# які помилково підписували сертифікатом шифрування, тепер отримають відмову.
#
# 0.6.0 — minor, бо змінилася поведінка підпису, а не лише її реалізація:
# контейнер PKCS#12 БЕЗ `certBag` (`.dat` українських КНЕДП) тепер підписує,
# якщо сертифікат знайдено поза контейнером (явний шлях, sidecar `.cer`, кеш,
# LDAP/CMP). Раніше такий ключ відмовляв із rc=525/272 незалежно від того, що
# знайшов авто-резолвер. Інтеграції, які покладалися на «`.dat` не підписує»,
# побачать іншу поведінку — patch-версія приховала б це.
# Разом із цим: чинна адреса реєстру КНЕДП ЦЗО (`/download/certificates/CAs.json`).
#
# 0.5.0 — minor, а не patch, і причина конкретна: ADR-030 зробив libxml2
# БЕЗУМОВНОЮ залежністю ядра. Конфігурація без toolchain vcpkg тепер падає на
# `find_package(LibXml2 REQUIRED)` у ВСІХ конфігураціях, включно з
# діагностичною. Для того, хто збирає з джерел, це ламна зміна, і patch-версія
# приховала б її.
#
# Решта циклу: власний вердикт для поламаного контейнера (ADR-029), PAdES подає
# timestamp evidence у канонічний рушій (ADR-031), механічна відтворюваність
# черги патчів vendor і SBOM з графа лінкування (ADR-032), шов коміту звіту
# (ADR-033), namespace-aware класифікація XAdES, політика мережевого доступу
# окремо від транспорту, живі перевірки OCSP/TSP.
project(Tamga VERSION 0.10.0 LANGUAGES C CXX)

include(GNUInstallDirs)

option(TAMGA_BUILD_TESTS "Build tests" OFF)
option(TAMGA_ENABLE_VENDOR_CRYPTONITE "Try to build and link vendored cryptonite" ON)
option(TAMGA_BUILD_CLI "Build Tamga command line utility" ON)
option(TAMGA_BUILD_TOOLS "Build diagnostic CLI tools" OFF)
option(TAMGA_MSVC_STATIC_RUNTIME "Link the MSVC runtime statically for single-binary release artifacts" ON)
option(TAMGA_ENABLE_SANITIZERS "Build with AddressSanitizer (+UBSan on Clang/GCC); diagnostic mode, not for shipping" OFF)

# С-09: ЄДИНЕ місце, де обирається MSVC runtime. Раніше поруч існувало друге,
# безумовне присвоєння в cmake/CompilerOptions.cmake, яке перезаписувало це —
# і опція OFF не діяла: збірка все одно виходила з /MT.
#
# OFF задає динамічний runtime ЯВНО, а не «як вийде»: покладатися на
# toolchain-дефолт означало б, що поведінка опції залежить від середовища.
if(MSVC)
    if(TAMGA_MSVC_STATIC_RUNTIME)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>")
    endif()
endif()

set(
    TAMGA_1C_SDK_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/1c-nativeapi-sdk/include"
    CACHE PATH
    "Path to 1C NativeAPI SDK headers"
)
set(
    TAMGA_VENDOR_CRYPTONITE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/cryptonite"
    CACHE PATH
    "Path to vendored cryptonite sources"
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(cmake/CompilerOptions.cmake)
include(cmake/Sanitizers.cmake)
include(cmake/ExportRules.cmake)

# С-09: сторожа проти повторення дефекту. Опція TAMGA_MSVC_STATIC_RUNTIME не
# діяла тому, що підключений нижче модуль мовчки перезаписував вибір runtime.
# Перевіряємо ФАКТИЧНЕ значення після всіх include: якщо колись зʼявиться друге
# присвоєння, configure впаде тут із поясненням, а не дасть збірку, що
# суперечить заявленій опції.
if(MSVC)
    if(TAMGA_MSVC_STATIC_RUNTIME)
        set(_tamga_expected_runtime "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set(_tamga_expected_runtime "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>")
    endif()
    if(NOT CMAKE_MSVC_RUNTIME_LIBRARY STREQUAL _tamga_expected_runtime)
        message(FATAL_ERROR
            "TAMGA_MSVC_STATIC_RUNTIME=${TAMGA_MSVC_STATIC_RUNTIME} expects "
            "CMAKE_MSVC_RUNTIME_LIBRARY='${_tamga_expected_runtime}', "
            "but it is '${CMAKE_MSVC_RUNTIME_LIBRARY}'. "
            "Runtime selection must happen in exactly one place.")
    endif()
    unset(_tamga_expected_runtime)
endif()

if(WIN32)
    find_program(TAMGA_RC_COMPILER NAMES rc rc.exe)
    find_program(TAMGA_MT_COMPILER NAMES mt mt.exe)
endif()

# --- Platform / architecture detection -------------------------------------
# 1C loads the component as a native shared object, so the bitness of the build
# must match the 1C platform (32-bit thin client vs 64-bit server/client).
# CMAKE_SIZEOF_VOID_P is the reliable signal: it already reflects -m32/-m64 and
# cross toolchains, whereas CMAKE_SYSTEM_PROCESSOR only names the host CPU.
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(TAMGA_TARGET_BITNESS 64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(TAMGA_TARGET_BITNESS 32)
else()
    set(TAMGA_TARGET_BITNESS "unknown")
endif()
message(STATUS
    "Tamga: system='${CMAKE_SYSTEM_NAME}' processor='${CMAKE_SYSTEM_PROCESSOR}' "
    "pointer=${CMAKE_SIZEOF_VOID_P}B (${TAMGA_TARGET_BITNESS}-bit)")

set(TAMGA_LIB_SOURCES
    src/lib/core/cryptonite/Names.cpp
    src/lib/core/cryptonite/CertUtil.cpp
    src/lib/core/cryptonite/Signer.cpp
    src/lib/core/cryptonite/SignOps.cpp
    src/lib/core/cryptonite/VerifyOps.cpp
    src/lib/core/cryptonite/CertificateInfo.cpp
    src/lib/core/cryptonite/KeyPairing.cpp
    src/lib/core/cryptonite/RevocationOps.cpp
    src/lib/core/cryptonite/CmsAttributeOps.cpp
    src/lib/core/RsaVerifier.cpp
    src/lib/core/HttpClient.cpp
    src/lib/core/net/HttpAccessPolicy.cpp
    src/lib/core/net/HttpMessageSyntax.cpp
    src/lib/core/TspClient.cpp
    src/lib/asic/AsicWriter.cpp
    src/lib/asic/AsicReader.cpp
    src/lib/asic/AsicContainers.cpp
    src/lib/core/Session.cpp
    src/lib/core/policy/AiaIssuerFetcher.cpp
    src/lib/core/policy/CertificateChainValidator.cpp
    src/lib/core/policy/CrlValidator.cpp
    src/lib/core/policy/CrlCache.cpp
    src/lib/core/policy/ImprintDigest.cpp
    src/lib/core/policy/OcspValidator.cpp
    src/lib/core/policy/PolicyCache.cpp
    src/lib/core/policy/PolicyDecision.cpp
    src/lib/core/policy/TimestampValidator.cpp
    src/lib/core/policy/TlXmlSigCheck.cpp
    src/lib/core/net/CertificateResolver.cpp
    src/lib/core/net/CertificateFetcher.cpp
    src/lib/core/net/CaSettingsRegistry.cpp
    src/lib/core/policy/TrustListParser.cpp
    src/lib/core/policy/TrustListSync.cpp
    src/lib/core/policy/UserReportBuilder.cpp
    src/lib/core/session/VerifyReportCommit.cpp
    src/lib/core/session/VerifySummary.cpp
    src/lib/core/validation/EvidenceStore.cpp
    src/lib/core/validation/PathEngine.cpp
    src/lib/core/validation/PolicyResolver.cpp
    src/lib/core/validation/RevocationEngine.cpp
    src/lib/core/validation/TimestampEngine.cpp
    src/lib/core/validation/ValidationEngine.cpp
    src/lib/core/validation/SigningTimeResolver.cpp
    src/lib/core/validation/TrustServiceEvaluator.cpp
    src/lib/core/validation/ValidationReportJson.cpp
    src/lib/core/validation/ValidationReportProjection.cpp
    src/lib/core/Errors.cpp
    src/lib/core/KeyParsers.cpp
    src/lib/util/AsicUri.cpp
    src/lib/util/Base64.cpp
    src/lib/util/Utf.cpp
    src/lib/util/FileSystem.cpp
    src/lib/util/SecureZero.cpp
    src/lib/util/Der.cpp
    src/lib/util/Json.cpp
    src/lib/util/Hex.cpp
    src/lib/util/Iso8601.cpp
    src/lib/util/X509Name.cpp
    src/lib/core/policy/VerifyChecks.cpp
    src/lib/core/policy/VerifyReportJson.cpp
    src/lib/xmldsig/XmlDigestEngine.cpp
    src/lib/xmldsig/XmlAlgorithmRegistry.cpp
)

# --- libxml2: БЕЗУМОВНА залежність ядра (ADR-030) --------------------------
# До ADR-030 libxml2 підключався лише разом із TAMGA_ENABLE_XML_SIGNATURES, а
# базова конфігурація читала XML двома саморобними сканерами підрядків — у
# `core/policy/TrustListParser.cpp` (корінь довіри!) і `asic/AsicContainers.cpp`.
# Один і той самий клас помилки (межа тега без урахування лапок) знайшли й
# виправили лише в ОДНОМУ зі сканерів. Тепер обидва парсери стоять на libxml2,
# тож залежність безумовна, а прапорець нижче керує ЛИШЕ підсистемою підпису.
#
# CONFIG спершу — з тієї самої причини, що й для ZLIB/JPEG нижче, але тут
# ставки вищі: у статичній збірці libxml2 МОЖЕ тягнути libiconv (і charset), а
# Find-модуль про це не знає. Конфігурація тоді проходить, а падає ЛІНКУВАННЯ
# з `unresolved external symbol libiconv_open` — тобто помилка спливає аж на
# кілька кроків пізніше за свою причину. `libxml2-config.cmake` від vcpkg
# несе транзитивні залежності у самому таргеті LibXml2::LibXml2.
#
# Ліцензійний бік: `vcpkg.json` оголошує libxml2 з `"default-features": false`,
# тобто БЕЗ фіч `iconv` і `zlib`. Це не косметика — саме `iconv` тягнув
# libiconv/libcharset під LGPL у статичне посилання. Перенесення залежності в
# кореневі `dependencies` цього не змінює: набір фіч той самий.
find_package(LibXml2 CONFIG QUIET)
if(NOT TARGET LibXml2::LibXml2)
    find_package(LibXml2 REQUIRED)
endif()
if(LibXml2_VERSION)
    set(LIBXML2_VERSION_STRING "${LibXml2_VERSION}")
endif()
message(STATUS "Tamga: libxml2 ${LIBXML2_VERSION_STRING} (безумовна залежність ядра, ADR-030)")

# --- Власний XMLDSIG/XAdES рушій (ADR 014, Q-013, ADR-030) -----------------
# C14N/transforms/resolution/побудова й перевірка підпису — ВЛАСНА реалізація
# (`src/lib/xmldsig/`, `src/lib/xades/`) поверх CryptoniteAdapter.
# `xmlsec1` тут НЕ бере участі: він потрібен лише діагностичному crosscheck за
# окремою опцією TAMGA_ENABLE_XMLSEC_CROSSCHECK (нижче, типово OFF).
#
# ADR-030: ця опція БІЛЬШЕ НЕ означає «збірка з libxml2». Вона означає рівно
# одне — чи компілюється підсистема ПІДПИСУ XMLDSIG/XAdES. Розбір XML доступний
# у будь-якій конфігурації. Типово вимкнено: без опції з xmldsig лишаються
# тільки безумовні pure-logic модулі — XmlDigestEngine (digest через
# ComputeImprint) і XmlAlgorithmRegistry.
option(TAMGA_ENABLE_XML_SIGNATURES "Build own XMLDSIG/XAdES signature subsystem (libxml2 is always required; xmlsec1 not used)" OFF)
if(TAMGA_ENABLE_XML_SIGNATURES)
    list(APPEND TAMGA_LIB_SOURCES
        src/lib/xmldsig/XmlCanonicalizer.cpp
        src/lib/xmldsig/XmlReferenceResolver.cpp
        src/lib/xmldsig/XmlTransformEngine.cpp
        src/lib/xmldsig/XmlSignatureBuilder.cpp
        src/lib/xmldsig/XmlHelpers.cpp
        src/lib/xmldsig/XmlSignatureVerifier.cpp
        src/lib/xades/XadesBuilder.cpp
        src/lib/xades/XadesVerifier.cpp
    )
    message(STATUS "Tamga: XMLDSIG signature subsystem enabled (libxml2 ${LIBXML2_VERSION_STRING})")
endif()

# --- xmlsec1 crosscheck (ADR 014, Q-013) ----------------------------------------
# XmlSecContext компілюється ЛИШЕ у tamga-tests для crosscheck власного XMLDSIG-рушія
# проти xmlsec1. Виробнича бібліотека залежить лише від libxml2; xmlsec1 — опційна
# test-only залежність. TAMGA_ENABLE_XMLSEC_CROSSCHECK потребує TAMGA_ENABLE_XML_SIGNATURES.
option(TAMGA_ENABLE_XMLSEC_CROSSCHECK "Compile XmlSecContext crosscheck against xmlsec1 (test-only)" OFF)
if(TAMGA_ENABLE_XMLSEC_CROSSCHECK)
    if(NOT TAMGA_ENABLE_XML_SIGNATURES)
        message(FATAL_ERROR "TAMGA_ENABLE_XMLSEC_CROSSCHECK requires TAMGA_ENABLE_XML_SIGNATURES=ON")
    endif()
    # На Windows/MSVC vcpkg надає коректний CMake config target для xmlsec.
    # Pkg-config лишається fallback для Unix-подібних системних пакетів.
    find_package(unofficial-xmlsec CONFIG QUIET)
    if(TARGET unofficial::xmlsec::xmlsec1-openssl)
        set(TAMGA_XMLSEC_TARGET unofficial::xmlsec::xmlsec1-openssl)
        set(TAMGA_XMLSEC_VERSION "vcpkg-config")
    else()
        find_package(PkgConfig REQUIRED)
        # Беремо саме crypto-enabled модуль (xmlsec1-openssl): bare xmlsec1 не
        # містить backend-символів xmlSecCrypto*. Він транзитивно тягне xmlsec1,
        # openssl та libxml2.
        pkg_check_modules(XMLSEC1 REQUIRED IMPORTED_TARGET xmlsec1-openssl)
        set(TAMGA_XMLSEC_TARGET PkgConfig::XMLSEC1)
        set(TAMGA_XMLSEC_VERSION "${XMLSEC1_VERSION}")
    endif()
    message(STATUS "Tamga: xmlsec1 crosscheck enabled (${TAMGA_XMLSEC_VERSION})")
endif()

# --- PAdES рушій qpdf (ADR 012, Phase 5) -----------------------------------
# PAdES (підпис PDF) спирається на qpdf для валідації структури; ByteRange та
# детачд CMS — на байтовому рівні + CryptoniteAdapter. За замовчуванням вимкнено.
option(TAMGA_ENABLE_PDF_SIGNATURES "Build PAdES engine on qpdf" OFF)
if(TAMGA_ENABLE_PDF_SIGNATURES)
    # На Windows/MSVC vcpkg надає CMake config target для qpdf. Pkg-config
    # лишається fallback для Unix-подібних системних пакетів.
    find_package(qpdf CONFIG QUIET)
    if(TARGET qpdf::libqpdf)
        set(TAMGA_QPDF_TARGET qpdf::libqpdf)
        set(TAMGA_QPDF_VERSION "vcpkg-config")
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(QPDF REQUIRED IMPORTED_TARGET libqpdf)
        set(TAMGA_QPDF_TARGET PkgConfig::QPDF)
        set(TAMGA_QPDF_VERSION "${QPDF_VERSION}")
    endif()
    # qpdf's static package may expose libjpeg as a plain "-ljpeg" linker item.
    # Link the CMake JPEG target explicitly and add its directory so raw -ljpeg
    # entries from qpdf's static interface resolve in vcpkg-only Linux builds.
    # Той самий підхід, що для ZLIB нижче: CONFIG знає фактичне ім'я бібліотеки
    # в конкретному triplet і не залежить від того, чи спрацювала vcpkg-обгортка.
    find_package(JPEG CONFIG QUIET)
    if(NOT TARGET JPEG::JPEG)
        find_package(JPEG REQUIRED)
    endif()
    set(TAMGA_PDF_LINK_DIRS "")
    foreach(_tamga_jpeg_var JPEG_LIBRARY JPEG_LIBRARIES)
        if(DEFINED ${_tamga_jpeg_var})
            foreach(_tamga_jpeg_item IN LISTS ${_tamga_jpeg_var})
                if(_tamga_jpeg_item AND EXISTS "${_tamga_jpeg_item}")
                    get_filename_component(_tamga_jpeg_dir "${_tamga_jpeg_item}" DIRECTORY)
                    list(APPEND TAMGA_PDF_LINK_DIRS "${_tamga_jpeg_dir}")
                endif()
            endforeach()
        endif()
    endforeach()
    if(TAMGA_PDF_LINK_DIRS)
        list(REMOVE_DUPLICATES TAMGA_PDF_LINK_DIRS)
        # Directory-scope — СВІДОМО, і його не можна замінити самим лише
        # `target_link_directories(... PRIVATE ...)` для core-таргетів нижче.
        #
        # Статичний інтерфейс qpdf несе «голі» лінкерні елементи (`zs.lib`,
        # `jpeg.lib`) без каталогу. Вони пропагуються через
        # INTERFACE_LINK_LIBRARIES у КОЖЕН таргет, що лінкує ядро, — зокрема в
        # `tamga-nativeapi` (Tamga.dll), `tamga-cli` і тестові бінарники. А
        # PRIVATE link-directories НЕ пропагуються, тож ці таргети лишилися б
        # без каталогу пошуку. Перевірено емпірично: без цього рядка збірка
        # постачання падає з `LINK : fatal error LNK1181: cannot open input
        # file 'zs.lib'` на Tamga.dll і tamga-cli.
        #
        # Це НЕ суперечить примітці O-05 нижче: там ідеться про прибрану
        # інфраструктуру `file(GLOB)`-аліасів і PUBLIC link-directories для
        # zlib, а не про цей вузький PDF-специфічний каталог.
        link_directories(${TAMGA_PDF_LINK_DIRS})
    endif()
    list(APPEND TAMGA_LIB_SOURCES
        src/lib/pades/PdfByteRange.cpp
        src/lib/pades/PdfParser.cpp
        src/lib/pades/PadesBuilder.cpp
        src/lib/pades/PadesVerifier.cpp
    )
    message(STATUS "Tamga: PAdES engine enabled (qpdf ${TAMGA_QPDF_VERSION}, JPEG ${JPEG_VERSION})")
endif()

# --- Static third-party dependency normalization ----------------------------
# Windows/MSVC static metadata from xmlsec/qpdf/libxml2 can expose dependency
# libraries through short linker items (for example zs.lib or jpeg.lib) even when
# vcpkg installs a differently named concrete static library. Make those
# dependencies explicit and provide local aliases so every target that consumes
# the third-party link interface can resolve the legacy names.
set(TAMGA_STATIC_THIRD_PARTY_NEEDS_ZLIB OFF)
if(TAMGA_ENABLE_XML_SIGNATURES OR TAMGA_ENABLE_PDF_SIGNATURES)
    set(TAMGA_STATIC_THIRD_PARTY_NEEDS_ZLIB ON)
    # CONFIG-режим спершу, MODULE — запасний.
    #
    # У статичному triplet vcpkg бібліотека zlib зветься `zs.lib`, і Find-модуль
    # такого імені не вгадує: його підставляє `share/zlib/vcpkg-cmake-wrapper.cmake`.
    # Обгортка ж застосовується лише тоді, коли toolchain коректно вирахував
    # внутрішній `_VCPKG_INSTALLED_DIR` — на GitHub-раннері цього не сталося, і
    # конфігурація падала з «Could NOT find ZLIB (missing: ZLIB_LIBRARY)», хоча
    # бібліотека лежала на місці.
    #
    # `ZLIBConfig.cmake`, який vcpkg постачає поруч, знає фактичне ім'я
    # авторитетно і не залежить від обгортки. MODULE лишається для системного
    # zlib (Linux), де config-файлу може не бути.
    find_package(ZLIB CONFIG QUIET)
    if(NOT TARGET ZLIB::ZLIB)
        find_package(ZLIB QUIET)
    endif()
    if(NOT TARGET ZLIB::ZLIB)
        # Останній шлях: шукаємо бібліотеку самі, за всіма іменами, які vcpkg
        # уживає в різних triplet. Проєкт уже знає цей перелік — він же стоїть у
        # перелік імен, який раніше був у tamga_make_msvc_static_alias (прибрано, O-05),
        # саме знання, застосоване раніше.
        #
        # Потрібно це тому, що обидва штатні шляхи можуть не спрацювати: обгортка
        # залежить від внутрішнього стану toolchain, а ZLIBConfig.cmake постачають
        # не всі порти й версії. Замість падіння з «не знайдено» при бібліотеці,
        # що лежить поруч, збираємо імпортований таргет самотужки.
        find_path(TAMGA_ZLIB_INCLUDE_DIR NAMES zlib.h)
        find_library(TAMGA_ZLIB_LIBRARY NAMES zs z zlib zlibstatic zlib1)
        if(TAMGA_ZLIB_INCLUDE_DIR AND TAMGA_ZLIB_LIBRARY)
            add_library(ZLIB::ZLIB UNKNOWN IMPORTED)
            set_target_properties(ZLIB::ZLIB PROPERTIES
                IMPORTED_LOCATION "${TAMGA_ZLIB_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${TAMGA_ZLIB_INCLUDE_DIR}")
            set(ZLIB_LIBRARY "${TAMGA_ZLIB_LIBRARY}" CACHE FILEPATH "zlib library resolved by Tamga" FORCE)
            set(ZLIB_INCLUDE_DIR "${TAMGA_ZLIB_INCLUDE_DIR}" CACHE PATH "zlib headers resolved by Tamga" FORCE)
            message(STATUS "Tamga: zlib resolved directly: ${TAMGA_ZLIB_LIBRARY}")
        else()
            message(FATAL_ERROR
                "zlib is required for XMLDSIG/PAdES but was not found. "
                "Searched CONFIG, MODULE and the vcpkg static names (zs/z/zlib/zlibstatic/zlib1).")
        endif()
    endif()
endif()

# O-05: інфраструктуру аліасів .lib і глобальні link-directories прибрано.
#
# Вона компенсувала те, що у статичному triplet vcpkg імена бібліотек не
# збігаються з очікуваними Find-модулями (zlib -> `zs.lib`), і підставляла копії
# під «правильними» іменами, а також додавала каталоги vcpkg у
# `target_link_directories(... PUBLIC ...)` через два `file(GLOB)`.
#
# Після переходу на `find_package(... CONFIG)` (ADR-016) імпортовані таргети
# несуть АБСОЛЮТНІ шляхи до бібліотек і транзитивні залежності, тож ні аліаси,
# ні пошук по каталогах більше не потрібні. Перевірено емпірично: збірка й
# 34/34 CTest проходять без них, а `Tamga.dll` залежить лише від системних DLL.
#
# Прибирати це важливо не заради рядків: `file(GLOB)` по каталогах vcpkg і
# PUBLIC link-directories робили резолвінг залежним від стану оточення, і саме
# ця крихкість коштувала кількох ітерацій CI.

# O-04: ядро компілюється ОДИН раз.
#
# Раніше той самий TAMGA_LIB_SOURCES передавався і в SHARED, і в STATIC, тож
# кожен core-`.cpp` збирався двічі з ІДЕНТИЧНИМИ прапорцями — це було прямо
# видно в логу Ninja. Тепер джерела належать OBJECT-бібліотеці, а обидві
# справжні бібліотеки лише лінкують її об'єктні файли.
#
# Патерн у цьому файлі вже усталений: так само зроблено `tamga-nativeapi-objects`.
add_library(tamga-core-objects OBJECT ${TAMGA_LIB_SOURCES})
tamga_enable_project_compile_policy(tamga-core-objects)

# C ABI is a separately compiled boundary.  It must not be pulled into the
# internal static core (and consequently into Tamga.dll), where it would also
# inherit the core's hidden visibility and export policy.
add_library(tamga-c-api-objects OBJECT src/lib/core/TamgaCApi.cpp)
tamga_enable_project_compile_policy(tamga-c-api-objects)

add_library(tamga-lib SHARED)
add_library(tamga::lib ALIAS tamga-lib)
add_library(tamga-core-static STATIC)
add_library(tamga::core-static ALIAS tamga-core-static)

# CMake >= 3.12: лінкування OBJECT-бібліотеки додає і її об'єктні файли, і її
# usage requirements. Власних джерел у цих таргетів немає, тому мову лінкера
# треба вказати явно.
target_link_libraries(tamga-lib PRIVATE tamga-core-objects tamga-c-api-objects)
target_link_libraries(tamga-core-static PRIVATE tamga-core-objects)
target_include_directories(tamga-lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
set_target_properties(tamga-lib tamga-core-static PROPERTIES LINKER_LANGUAGE CXX)

# Три категорії налаштувань нижче РІЗНІ, і плутати їх не можна:
#   * компіляція ядра             -> лише tamga-core-objects;
#   * PUBLIC-залежності           -> лише tamga-core-objects (пропагуються далі);
#   * PRIVATE-сторонні бібліотеки -> усі три: об'єктам потрібні include-шляхи,
#     двом бібліотекам — рядок лінкування, і при цьому нічого не протікає
#     у їхніх споживачів.
set(TAMGA_CORE_TARGETS tamga-core-objects tamga-lib tamga-core-static)

target_include_directories(tamga-core-objects
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/core
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/util
)

target_include_directories(tamga-c-api-objects PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/util
)
target_compile_definitions(tamga-c-api-objects PRIVATE TAMGA_LIB_EXPORTS=1)
set_target_properties(tamga-c-api-objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN NO
)

# --- Формати XMLDSIG / XAdES / PAdES (ADR 012) -----------------------------
# Phase 0 додає лише header-only стаб-контракти під src/lib/{xmldsig,xades,pades};
# вони вже видимі через PUBLIC include src/lib (наприклад "xmldsig/...").
# Реалізаційні .cpp та vendor-рушії (xmlsec/libxml2, qpdf) додаються до
# TAMGA_LIB_SOURCES у відповідних фазах плану
# docs/design/xmldsig-xades-pades-engineering-design.md. Compile-smoke для
# заголовків живе у tests/tamga_tests.cpp до появи реалізації.

# ADR-030: libxml2 лінкується БЕЗУМОВНО — на ньому стоять `TrustListParser` і
# `AsicContainers`, які компілюються в кожній конфігурації. Лінкування лишається
# PRIVATE: libxml2 не протікає у публічний include-контракт інших таргетів.
foreach(_tamga_core_target ${TAMGA_CORE_TARGETS})
    target_link_libraries(${_tamga_core_target} PRIVATE LibXml2::LibXml2)
endforeach()

# Лінкування XMLDSIG-рушія тримаємо локальним для tamga-lib/tamga-core-static:
# xmlsec/libxml2 не протікають у публічний include-контракт інших таргетів.
if(TAMGA_ENABLE_XML_SIGNATURES)
    target_compile_definitions(tamga-core-objects PRIVATE TAMGA_XML_SIGNATURES_ENABLED=1)
    # Q-013: xmlsec1 вилучено з lib/виробничих залежностей — лише libxml2.
    # ZLIB лишається саме тут: його тягне не парсер, а решта static-метаданих
    # третіх сторін (див. TAMGA_STATIC_THIRD_PARTY_NEEDS_ZLIB нижче/вище).
    foreach(_tamga_core_target ${TAMGA_CORE_TARGETS})
        target_link_libraries(${_tamga_core_target} PRIVATE ZLIB::ZLIB)
    endforeach()
endif()

if(TAMGA_ENABLE_PDF_SIGNATURES)
    target_compile_definitions(tamga-core-objects PRIVATE TAMGA_PDF_SIGNATURES_ENABLED=1)
    foreach(_tamga_core_target ${TAMGA_CORE_TARGETS})
        if(TAMGA_PDF_LINK_DIRS)
            target_link_directories(${_tamga_core_target} PRIVATE ${TAMGA_PDF_LINK_DIRS})
        endif()
        target_link_libraries(${_tamga_core_target} PRIVATE ${TAMGA_QPDF_TARGET} JPEG::JPEG ZLIB::ZLIB)
    endforeach()
endif()

set_target_properties(tamga-lib PROPERTIES
    OUTPUT_NAME "tamga-lib"
    EXPORT_NAME lib
)
set_target_properties(tamga-core-static PROPERTIES
    OUTPUT_NAME "tamga-core-static"
    POSITION_INDEPENDENT_CODE ON
)
# Видимість символів — властивість КОМПІЛЯЦІЇ, тож після O-04 вона мусить стояти
# там, де джерела фактично компілюються; на tamga-lib вона б уже нічого не
# робила. Наслідок: об'єкти ядра тепер приховані й для tamga-core-static — це
# правильна позиція, бо статична бібліотека йде в Tamga.dll, який експортує
# рівно 5 C-функцій із окремого таргета tamga-nativeapi-objects.
set_target_properties(tamga-core-objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

add_library(tamga_miniz STATIC
    vendor/miniz/miniz.c
    vendor/miniz/miniz_tdef.c
    vendor/miniz/miniz_tinfl.c
    vendor/miniz/miniz_zip.c
)
# miniz — vendored C-бібліотека. Її заголовок містить static inline zlib-compat
# wrappers, частина яких не використовується кожним translation unit-ом Tamga.
# Позначаємо include як SYSTEM, щоб first-party -Werror не перетворював цей
# vendor warning-noise на помилку компіляції Linux-збірки.
target_include_directories(tamga_miniz SYSTEM PUBLIC vendor/miniz)
set_target_properties(tamga_miniz PROPERTIES
    C_STANDARD 99
    POSITION_INDEPENDENT_CODE ON
)
if(MSVC)
    target_compile_options(tamga_miniz PRIVATE /W0)
else()
    target_compile_options(tamga_miniz PRIVATE -w)
endif()

target_link_libraries(tamga-core-objects PUBLIC tamga_miniz)

add_library(tamga-nativeapi-objects OBJECT
    src/nativeapi/TamgaAddIn.cpp
    src/nativeapi/Export.cpp
    src/nativeapi/VariantUtils.cpp
)
tamga_enable_project_compile_policy(tamga-nativeapi-objects)

target_include_directories(tamga-nativeapi-objects
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/core
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/util
)
target_include_directories(tamga-nativeapi-objects SYSTEM PRIVATE
    ${TAMGA_1C_SDK_DIR}
)

add_library(tamga-nativeapi SHARED
    $<TARGET_OBJECTS:tamga-nativeapi-objects>
)

target_link_libraries(tamga-nativeapi PRIVATE tamga-core-static)

# --- Linux / Unix system libraries -----------------------------------------
# The vendored cryptonite already pulls in pthread (via pthread_impl) and libm
# (via asn1) transitively, but Tamga links them explicitly so the core targets
# stay self-describing and keep building if cryptonite is disabled. libdl is
# required because 1C dlopen()'s the component and the HTTP backends may resolve
# symbols at runtime. NOTE: the DSTU crypto stack is fully self-contained inside
# vendor/cryptonite, so OpenSSL/libcrypto is intentionally NOT a dependency.
if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    target_link_libraries(tamga-core-objects PUBLIC Threads::Threads ${CMAKE_DL_LIBS} m)
endif()

if(NOT MSVC)
    target_compile_options(tamga-core-objects PRIVATE -Wconversion)
    target_compile_options(tamga-nativeapi-objects PRIVATE -Wconversion)
endif()

if(TAMGA_ENABLE_VENDOR_CRYPTONITE)
    if(EXISTS "${TAMGA_VENDOR_CRYPTONITE_DIR}/CMakeLists.txt")
        set(CRYPTONITE_BUILD_TESTS OFF CACHE BOOL "Disable cryptonite tests for embedded builds" FORCE)
        set(CRYPTONITE_BUILD_EXAMPLES OFF CACHE BOOL "Disable cryptonite examples for embedded builds" FORCE)
        set(CRYPTONITE_STRICT_WARNINGS OFF CACHE BOOL "Disable Werror in embedded cryptonite build" FORCE)

        add_subdirectory("${TAMGA_VENDOR_CRYPTONITE_DIR}" "${CMAKE_BINARY_DIR}/vendor_cryptonite" EXCLUDE_FROM_ALL)

        set(TAMGA_CRYPTONITE_TARGETS "")
        foreach(_candidate cryptonite asn1 pkix storage pthread_impl)
            if(TARGET ${_candidate})
                list(APPEND TAMGA_CRYPTONITE_TARGETS ${_candidate})
            endif()
        endforeach()

        if(TAMGA_CRYPTONITE_TARGETS)
            target_link_libraries(tamga-core-objects PUBLIC ${TAMGA_CRYPTONITE_TARGETS})
            if(MSVC)
                foreach(_target IN LISTS TAMGA_CRYPTONITE_TARGETS)
                    target_compile_options(${_target} PRIVATE /utf-8)
                endforeach()
            endif()
            target_compile_definitions(tamga-core-objects PRIVATE CRYPTONITE_EXPORT=extern TAMGA_CRYPTONITE_ENABLED=1)
            target_compile_definitions(tamga-nativeapi PRIVATE TAMGA_CRYPTONITE_ENABLED=1)
            target_compile_definitions(tamga-nativeapi-objects PRIVATE TAMGA_CRYPTONITE_ENABLED=1)
        else()
            message(FATAL_ERROR
                "Vendored cryptonite is enabled, but expected targets were not created. "
                "Apply the patch queue from patches/cryptonite before configuring with TAMGA_ENABLE_VENDOR_CRYPTONITE=ON."
            )
        endif()
    else()
        message(FATAL_ERROR "Vendored cryptonite directory is missing: ${TAMGA_VENDOR_CRYPTONITE_DIR}")
    endif()
else()
    target_compile_definitions(tamga-core-objects PRIVATE TAMGA_CRYPTONITE_ENABLED=0)
    target_compile_definitions(tamga-nativeapi PRIVATE TAMGA_CRYPTONITE_ENABLED=0)
    target_compile_definitions(tamga-nativeapi-objects PRIVATE TAMGA_CRYPTONITE_ENABLED=0)
endif()

target_compile_definitions(tamga-nativeapi PRIVATE
    ADDINCPP_EXPORTS
    TAMGA_SINGLE_BINARY=1
    TAMGA_WITH_GUI=0
    TAMGA_WITH_NETWORK_PROVIDER=0
    TAMGA_DESKTOP_ONLY=1
)
target_compile_definitions(tamga-nativeapi-objects PRIVATE
    ADDINCPP_EXPORTS
    TAMGA_SINGLE_BINARY=1
    TAMGA_WITH_GUI=0
    TAMGA_WITH_NETWORK_PROVIDER=0
    TAMGA_DESKTOP_ONLY=1
)

set_target_properties(tamga-nativeapi PROPERTIES
    OUTPUT_NAME "Tamga"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

tamga_apply_export_rules(tamga-nativeapi)

find_package(CURL QUIET)
if(CURL_FOUND)
    foreach(_tamga_core_target ${TAMGA_CORE_TARGETS})
        target_link_libraries(${_tamga_core_target} PRIVATE CURL::libcurl)
    endforeach()
    target_compile_definitions(tamga-core-objects PRIVATE TAMGA_LIBCURL_ENABLED=1)
else()
    target_compile_definitions(tamga-core-objects PRIVATE TAMGA_LIBCURL_ENABLED=0)
    if(WIN32)
        target_link_libraries(tamga-core-objects PUBLIC winhttp)
        message(STATUS "libcurl not found - using WinHTTP as HTTP backend")
    else()
        message(WARNING "libcurl not found and WinHTTP is not available on this platform. TSP will be disabled.")
    endif()
endif()

# B-3: на Windows зберігаємо чинний CNG backend для RSASSA-PKCS1-v1_5.
# Поза Windows RSA виконує PKIX VerifyAdapter vendored cryptonite; bcrypt/crypt32
# тут лишаються лише для незмінної Windows-поведінки.
# bcrypt/crypt32 — СИСТЕМНІ DLL Windows: single-DLL збірка не отримує жодної
# нової сторонньої залежності (перевіряється `dumpbin /DEPENDENTS`).
if(WIN32)
    # wldap32 — ТЗ Рівень 3: LDAP-каталог КНЕДП як джерело сертифіката підписувача.
    # ws2_32 — системне DNS-resolve для fail-closed SSRF destination policy.
    target_link_libraries(tamga-core-objects PUBLIC bcrypt crypt32 wldap32 ws2_32)
endif()

# Версія доступна коду єдиним джерелом — project(), а не продубльована в .cpp.
foreach(_tamga_versioned_target tamga-core-objects tamga-c-api-objects tamga-nativeapi-objects)
    if(TARGET ${_tamga_versioned_target})
        target_compile_definitions(${_tamga_versioned_target}
            PRIVATE TAMGA_VERSION_STRING="${PROJECT_VERSION}")
    endif()
endforeach()

if(TAMGA_BUILD_CLI)
    add_subdirectory(src/cli)
endif()

if(TAMGA_BUILD_TESTS)
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
endif()

if(TAMGA_BUILD_TOOLS)
    add_subdirectory(tools/tsp-diag)
    add_subdirectory(tools/interop-diag)
    # Проби вимірювання (O-01, O-02). Не тести: нічого не стверджують і не
    # гейтять — див. tools/bench/README.md.
    add_subdirectory(tools/bench)
endif()

# --- Правила встановлення (install) та експорту CMake пакета ----------------
include(CMakePackageConfigHelpers)

tamga_apply_c_api_export_rules(tamga-lib)

install(TARGETS tamga-lib
    EXPORT TamgaTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(TARGETS tamga-nativeapi
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

if(TAMGA_BUILD_CLI)
    install(TARGETS tamga-cli
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

# В-06: встановлюється ЛИШЕ публічний C ABI.
#
# `install(DIRECTORY include/tamga ...)` копіював також `Tamga.h` і `Session.h`,
# які включають внутрішні `core/Errors.h`, `core/Session.h`, `util/Base64.h` —
# а ті в install-дерево не потрапляють. Наслідок: документований C++ entrypoint
# не компілювався у споживача (`C1083`), і CTest цього не бачив, бо
# package-consumer включав лише C-заголовок.
#
# Рішення узгоджене з ADR-025: стабільною публічною межею пакета є C ABI.
# Обидва внутрішні фасади лишаються в дереві для власних цілей (CLI, tamga-lib),
# але не є частиною install-контракту.
install(FILES include/tamga/tamga_c_api.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tamga
)

install(EXPORT TamgaTargets
    FILE TamgaTargets.cmake
    NAMESPACE tamga::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Tamga
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/TamgaConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/TamgaConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/TamgaConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Tamga
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/TamgaConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/TamgaConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Tamga
)
