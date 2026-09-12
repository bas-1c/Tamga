cmake_minimum_required(VERSION 3.10)
project(cryptonite-main LANGUAGES C CXX)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(CRYPTONITE_STANDALONE_DEFAULT ON)
else()
    set(CRYPTONITE_STANDALONE_DEFAULT OFF)
endif()

option(CRYPTONITE_BUILD_TESTS "Build cryptonite test targets" ${CRYPTONITE_STANDALONE_DEFAULT})
option(CRYPTONITE_BUILD_EXAMPLES "Build cryptonite example targets" ${CRYPTONITE_STANDALONE_DEFAULT})

#################################################################################
# Define
#################################################################################
add_definitions(-DCRYPTONITE_EXPORT=extern)

#################################################################################
# Flags
#################################################################################
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CRYPTONITE_STRICT_WARNINGS
    "Enable strict compiler warnings (warnings as errors on GCC/Clang)"
    ${CRYPTONITE_STANDALONE_DEFAULT})

if(MSVC)
    if(CRYPTONITE_STRICT_WARNINGS)
        add_compile_options(/W4)
    else()
        # Embedded builds keep upstream noise isolated while preserving the
        # uninitialized-local diagnostics tracked separately by Tamga.
        add_compile_options(/W1 /w14701 /w14703)
    endif()
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    if(CRYPTONITE_STRICT_WARNINGS)
        add_compile_options(-Wall -Werror)
    endif()
endif()

#set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -m32")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g2 ")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -lpthread -fPIC -I/libs/libee")

#################################################################################
# Modules
#################################################################################

add_subdirectory(src/pthread)
add_subdirectory(src/cryptonite)
add_subdirectory(src/asn1)
add_subdirectory(src/pkix)
add_subdirectory(src/storage)

#################################################################################
# Test
#################################################################################
if(CRYPTONITE_BUILD_TESTS)
    add_subdirectory(src/cryptoniteTestUtils)
    add_subdirectory(src/cryptoniteUtest)
    add_subdirectory(src/cryptoniteAtest)
    add_subdirectory(src/cryptonitePtest)
    add_subdirectory(src/cryptoniteXtest)
    add_subdirectory(src/asn1Utest)
    add_subdirectory(src/pkixTestUtils)
    add_subdirectory(src/pkixUtest)
    add_subdirectory(src/storageUtest)
endif()

if(CRYPTONITE_BUILD_EXAMPLES)
    add_subdirectory(src/cryptoniteExample)
    add_subdirectory(src/pkiExample)
endif()
