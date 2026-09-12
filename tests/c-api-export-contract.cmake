if(NOT DEFINED TAMGA_C_API_LIBRARY OR NOT EXISTS "${TAMGA_C_API_LIBRARY}")
    message(FATAL_ERROR "TAMGA_C_API_LIBRARY must point to the built tamga-lib")
endif()

if(WIN32)
    find_program(TAMGA_DUMPBIN dumpbin)
    if(NOT TAMGA_DUMPBIN)
        file(GLOB _dumpbin_candidates
            "$ENV{SystemDrive}/Program Files/Microsoft Visual Studio/*/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"
            "$ENV{SystemDrive}/Program Files (x86)/Microsoft Visual Studio/*/BuildTools/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"
        )
        list(LENGTH _dumpbin_candidates _dumpbin_count)
        if(_dumpbin_count GREATER 0)
            list(GET _dumpbin_candidates 0 TAMGA_DUMPBIN)
        else()
            message(FATAL_ERROR "dumpbin is required for the Windows C ABI export contract")
        endif()
    endif()
    execute_process(
        COMMAND "${TAMGA_DUMPBIN}" /nologo /exports "${TAMGA_C_API_LIBRARY}"
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _output
        ERROR_VARIABLE _error
    )
elseif(APPLE)
    find_program(TAMGA_NM nm REQUIRED)
    execute_process(
        COMMAND "${TAMGA_NM}" -gU "${TAMGA_C_API_LIBRARY}"
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _output
        ERROR_VARIABLE _error
    )
else()
    find_program(TAMGA_NM nm REQUIRED)
    execute_process(
        COMMAND "${TAMGA_NM}" -D --defined-only "${TAMGA_C_API_LIBRARY}"
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _output
        ERROR_VARIABLE _error
    )
endif()

if(NOT _result EQUAL 0)
    message(FATAL_ERROR "Could not inspect tamga-lib exports: ${_error}")
endif()

string(REGEX MATCHALL "tamga_[A-Za-z0-9_]+" _symbols "${_output}")
list(REMOVE_DUPLICATES _symbols)
set(_expected
    tamga_version
    tamga_session_create
    tamga_session_destroy
    tamga_session_configure
    tamga_session_read_key_file
    tamga_session_read_key_descriptor
    tamga_session_is_key_loaded
    tamga_session_sign_file
    tamga_session_sign_data
    tamga_session_verify_file
    tamga_session_verify_data
    tamga_session_sync_trust_list
    tamga_session_get_last_error
    tamga_session_get_last_error_code
    tamga_session_get_last_report
    tamga_session_get_user_report
    tamga_free_bytes
    tamga_free_string
)
list(SORT _symbols)
list(SORT _expected)
if(NOT _symbols STREQUAL _expected)
    message(FATAL_ERROR "Unexpected tamga-lib C ABI exports. Expected: ${_expected}; actual: ${_symbols}")
endif()
