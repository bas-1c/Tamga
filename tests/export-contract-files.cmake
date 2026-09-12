set(def_file "${TAMGA_SOURCE_DIR}/src/nativeapi/Tamga.def")
set(export_list_file "${TAMGA_SOURCE_DIR}/src/nativeapi/exported_symbols.list")
set(version_script_file "${TAMGA_SOURCE_DIR}/src/nativeapi/version.script")
set(export_cpp_file "${TAMGA_SOURCE_DIR}/src/nativeapi/Export.cpp")

set(required_symbols
    GetClassObject
    DestroyObject
    GetClassNames
    SetPlatformCapabilities
    GetAttachType
)

if(NOT EXISTS "${def_file}" OR NOT EXISTS "${export_list_file}" OR NOT EXISTS "${version_script_file}" OR NOT EXISTS "${export_cpp_file}")
    message(FATAL_ERROR "Export contract files are missing")
endif()

file(READ "${def_file}" def_content)
string(REPLACE "\r" "" def_content "${def_content}")
file(READ "${export_list_file}" export_list_content)
string(REPLACE "\r" "" export_list_content "${export_list_content}")
file(READ "${version_script_file}" version_script_content)
string(REPLACE "\r" "" version_script_content "${version_script_content}")
file(READ "${export_cpp_file}" export_cpp_content)
string(REPLACE "\r" "" export_cpp_content "${export_cpp_content}")

set(def_symbols)
string(REGEX MATCHALL "[ \t]+([A-Za-z_][A-Za-z0-9_]*)" def_matches "${def_content}")
foreach(match IN LISTS def_matches)
    string(STRIP "${match}" name)
    if(NOT name STREQUAL "LIBRARY" AND NOT name STREQUAL "EXPORTS" AND NOT name STREQUAL "Tamga")
        list(APPEND def_symbols "${name}")
    endif()
endforeach()

set(list_symbols)
string(REGEX MATCHALL "_[A-Za-z_][A-Za-z0-9_]*" list_matches "${export_list_content}")
foreach(match IN LISTS list_matches)
    string(SUBSTRING "${match}" 1 -1 name)
    list(APPEND list_symbols "${name}")
endforeach()

set(cpp_symbols)
string(REGEX MATCHALL "extern[ \t\r\n]+\"C\"[ \t\r\n]+[^;\r\n{()]+[ \t\r\n]+([A-Za-z_][A-Za-z0-9_]*)[ \t\r\n]*\\(" cpp_matches "${export_cpp_content}")
foreach(match IN LISTS cpp_matches)
    string(REGEX REPLACE ".*extern[ \t\r\n]+\"C\"[ \t\r\n]+[^;\r\n{()]+[ \t\r\n]+([A-Za-z_][A-Za-z0-9_]*)[ \t\r\n]*\\(.*" "\\1" name "${match}")
    list(APPEND cpp_symbols "${name}")
endforeach()

set(version_symbols)
string(REGEX MATCHALL "[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*;" version_matches "${version_script_content}")
foreach(match IN LISTS version_matches)
    string(STRIP "${match}" name)
    string(REPLACE ";" "" name "${name}")
    if(NOT name STREQUAL "" AND NOT name STREQUAL "global" AND NOT name STREQUAL "local")
        list(APPEND version_symbols "${name}")
    endif()
endforeach()

foreach(symbol_set IN ITEMS cpp_symbols def_symbols list_symbols version_symbols)
    list(LENGTH ${symbol_set} symbol_count)
    if(NOT symbol_count EQUAL 5)
        message(FATAL_ERROR "${symbol_set} must contain exactly 5 symbols, found ${symbol_count}")
    endif()
    foreach(required_symbol IN LISTS required_symbols)
        list(FIND ${symbol_set} "${required_symbol}" index)
        if(index EQUAL -1)
            message(FATAL_ERROR "${symbol_set} does not contain required symbol ${required_symbol}")
        endif()
    endforeach()
endforeach()

message(STATUS "Export contract files contain exactly the required 5 symbols")
