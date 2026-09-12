cmake_minimum_required(VERSION 3.10)
project(asn1)

file(GLOB SOURCE c/*.c)

if(CMAKE_BUILD_TYPE STREQUAL Release AND NOT MSVC)
    add_compile_options(-Wno-maybe-uninitialized)
endif()

add_library(asn1 STATIC ${SOURCE})
if(WIN32)
    target_link_libraries(asn1 cryptonite)
else()
    target_link_libraries(asn1 cryptonite m)
endif()
target_include_directories(asn1 PUBLIC c)
