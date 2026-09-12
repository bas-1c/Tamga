cmake_minimum_required(VERSION 3.23)
project(TamgaPackageConsumer LANGUAGES C CXX)

find_package(Tamga CONFIG REQUIRED)

add_executable(tamga-c-api-consumer c_api_consumer.c)
target_link_libraries(tamga-c-api-consumer PRIVATE tamga::lib)

add_executable(tamga-cpp-api-consumer cpp_api_consumer.cpp)
target_link_libraries(tamga-cpp-api-consumer PRIVATE tamga::lib)

# В-06: КОЖЕН встановлений публічний заголовок мусить компілюватися сам по собі
# з чистого install-префікса — і як C, і як C++.
#
# Раніше цей проєкт називався «C та C++ споживачі», але обидва включали лише
# `tamga/tamga_c_api.h`. Через це встановлений `tamga/Tamga.h`, який тягне
# внутрішні `core/Errors.h` та `core/Session.h`, роками ламався непомітно для
# CTest: помилку `C1083` знаходили тільки ручним `cl /c` під час аудиту.
#
# Тепер перелік перевірених заголовків не задається вручну, а виводиться з
# фактичного вмісту install-дерева. Якщо колись знову встановлять заголовок,
# що не є самодостатнім, тест впаде на самому цьому заголовку, а не на тому,
# що хтось згадав його додати.
set(_tamga_include_root "")
foreach(_prefix IN LISTS CMAKE_PREFIX_PATH)
    if(EXISTS "${_prefix}/include/tamga")
        set(_tamga_include_root "${_prefix}/include")
        break()
    endif()
endforeach()

if(_tamga_include_root STREQUAL "")
    message(FATAL_ERROR "Installed tamga include directory was not found under CMAKE_PREFIX_PATH")
endif()

file(GLOB _tamga_public_headers RELATIVE "${_tamga_include_root}" "${_tamga_include_root}/tamga/*.h")
if(_tamga_public_headers STREQUAL "")
    message(FATAL_ERROR "No public headers were installed under ${_tamga_include_root}/tamga")
endif()

set(_header_check_sources "")
foreach(_header IN LISTS _tamga_public_headers)
    string(MAKE_C_IDENTIFIER "${_header}" _slug)

    set(_c_src "${CMAKE_CURRENT_BINARY_DIR}/header_check_${_slug}.c")
    file(WRITE "${_c_src}" "#include <${_header}>\n#include <${_header}>\n")

    set(_cxx_src "${CMAKE_CURRENT_BINARY_DIR}/header_check_${_slug}.cpp")
    file(WRITE "${_cxx_src}" "#include <${_header}>\n#include <${_header}>\n")

    list(APPEND _header_check_sources "${_c_src}" "${_cxx_src}")
endforeach()

# Головна TU тримає main(); решта — по два включення кожного заголовка, що
# заодно доводить наявність include guard.
set(_header_check_main "${CMAKE_CURRENT_BINARY_DIR}/header_check_main.cpp")
file(WRITE "${_header_check_main}" "int main() { return 0; }\n")

add_executable(tamga-installed-headers-compile
    "${_header_check_main}"
    ${_header_check_sources}
)
target_link_libraries(tamga-installed-headers-compile PRIVATE tamga::lib)

message(STATUS "Tamga package consumer: checking installed public headers: ${_tamga_public_headers}")
