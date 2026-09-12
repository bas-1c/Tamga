# Fuzz-цілі для чотирьох поверхонь недовіреного вводу.
#
# Кожна ціль існує в ДВОХ режимах з одного й того самого файла:
#
#   * повтор корпусу (типово) — до цілі долінковується fuzz_replay_main.cpp,
#     і вона стає звичайним CTest-тестом, що проганяє наявні файли. Нових
#     дефектів не шукає; її робота — не дати повернутися вже знайденому.
#     Реальну користь дає в парі з TAMGA_ENABLE_SANITIZERS=ON.
#
#   * libFuzzer (TAMGA_ENABLE_LIBFUZZER=ON, потрібен Clang) — ціль ГЕНЕРУЄ
#     входи. MSVC libFuzzer не має, тому цей режим недоступний на основному
#     шляху збірки проєкту; див. ADR 021.

option(TAMGA_ENABLE_LIBFUZZER
    "Build fuzz targets as libFuzzer binaries instead of corpus-replay tests (requires Clang)" OFF)

set(TAMGA_FUZZ_TARGETS asic)
if(TAMGA_ENABLE_VENDOR_CRYPTONITE)
    list(APPEND TAMGA_FUZZ_TARGETS asn1)
endif()
if(TAMGA_ENABLE_XML_SIGNATURES)
    list(APPEND TAMGA_FUZZ_TARGETS xml)
endif()
if(TAMGA_ENABLE_PDF_SIGNATURES)
    list(APPEND TAMGA_FUZZ_TARGETS pdf)
endif()

if(TAMGA_ENABLE_LIBFUZZER AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
        "TAMGA_ENABLE_LIBFUZZER requires Clang or clang-cl: MSVC does not ship libFuzzer. "
        "Use TAMGA_ENABLE_SANITIZERS=ON for the corpus-replay mode instead.")
endif()

foreach(_fuzz_target IN LISTS TAMGA_FUZZ_TARGETS)
    set(_fuzz_name tamga-fuzz-${_fuzz_target})

    if(TAMGA_ENABLE_LIBFUZZER)
        add_executable(${_fuzz_name} fuzz_${_fuzz_target}.cpp)
        target_compile_options(${_fuzz_name} PRIVATE -fsanitize=fuzzer)
        target_link_options(${_fuzz_name} PRIVATE -fsanitize=fuzzer)
    else()
        add_executable(${_fuzz_name} fuzz_${_fuzz_target}.cpp fuzz_replay_main.cpp)
    endif()
    tamga_enable_project_compile_policy(${_fuzz_name})

    target_link_libraries(${_fuzz_name} PRIVATE tamga-core-static)
    target_include_directories(${_fuzz_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
    )

    # Ознаки збірки PRIVATE на tamga-core-objects і не пропагуються, тож
    # цілям їх треба виставити самостійно — так само, як це вже роблять
    # звичайні тести.
    if(TAMGA_ENABLE_VENDOR_CRYPTONITE)
        target_compile_definitions(${_fuzz_name} PRIVATE TAMGA_CRYPTONITE_ENABLED=1)
    endif()
    if(TAMGA_ENABLE_XML_SIGNATURES)
        target_compile_definitions(${_fuzz_name} PRIVATE TAMGA_XML_SIGNATURES_ENABLED=1)
    endif()
    if(TAMGA_ENABLE_PDF_SIGNATURES)
        target_compile_definitions(${_fuzz_name} PRIVATE TAMGA_PDF_SIGNATURES_ENABLED=1)
    endif()

    if(NOT TAMGA_ENABLE_LIBFUZZER)
        # Корпус = власні насіннєві файли та перевірені public fixtures,
        # включно із синтетичними некоректними ZIP-контейнерами.
        #
        # Кожна ціль отримує ВСІ фікстури, а не «свої»: PDF, поданий у розбір
        # ASN.1, — коректний випадок, бо саме так виглядає зіпсований контейнер
        # із реального обігу.
        add_test(NAME ${_fuzz_name}-corpus
                 COMMAND ${_fuzz_name}
                         ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${_fuzz_target}
                         ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures)

        # PATH для runtime-DLL (vcpkg, рантайм ASan) — той самий набір, який
        # tests/CMakeLists.txt виставляє решті тестів.
        if(TAMGA_TEST_ENV_MODIFICATION)
            set_tests_properties(${_fuzz_name}-corpus PROPERTIES
                ENVIRONMENT_MODIFICATION "${TAMGA_TEST_ENV_MODIFICATION}")
        endif()
    endif()
endforeach()

message(STATUS "Tamga: fuzz targets = ${TAMGA_FUZZ_TARGETS}")
