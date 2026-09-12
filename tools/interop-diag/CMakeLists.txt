cmake_minimum_required(VERSION 3.23)

# Підключається з кореневого CMakeLists.txt через add_subdirectory(tools/interop-diag)
add_executable(tamga_interop_diag main.cpp)
tamga_enable_project_compile_policy(tamga_interop_diag)

target_link_libraries(tamga_interop_diag PRIVATE tamga-core-static)

target_include_directories(tamga_interop_diag PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
    ${CMAKE_SOURCE_DIR}/src/lib/core
    ${CMAKE_SOURCE_DIR}/src/lib/util
)

# Той самий флаг криптоніту що і в основному проекті. Самі cryptonite/miniz/Curl
# залежності приходять транзитивно через tamga-core-static, щоб діагностична
# утиліта не мала окремого, розсинхронізованого списку third-party libraries.
if(TAMGA_ENABLE_VENDOR_CRYPTONITE AND TARGET cryptonite)
    target_compile_definitions(tamga_interop_diag PRIVATE
        CRYPTONITE_EXPORT=extern
        TAMGA_CRYPTONITE_ENABLED=1
    )
else()
    target_compile_definitions(tamga_interop_diag PRIVATE TAMGA_CRYPTONITE_ENABLED=0)
endif()

# tl-sig / xml / asice потребують власного XMLDSIG-рушія Tamga (ADR-014).
if(TAMGA_ENABLE_XML_SIGNATURES)
    target_compile_definitions(tamga_interop_diag PRIVATE TAMGA_XML_SIGNATURES_ENABLED=1)
endif()

set_target_properties(tamga_interop_diag PROPERTIES
    OUTPUT_NAME "tamga-interop-diag"
)
