# Portable CLI assertion runner for ctest (replaces PowerShell-only checks).
#
# Runs ${CLI} with pipe-delimited ${ARGS}, then asserts:
#   * exit code equals ${EXPECT_CODE} (default 0);
#   * combined stdout+stderr matches ${MATCH} (if provided);
#   * combined stdout+stderr does NOT match ${NOMATCH} (if provided).
#
# Works identically on Windows, Linux and macOS because it only relies on
# CMake script mode. Invoke via:
#   ${CMAKE_COMMAND} -DCLI=<exe> -DARGS=a|b|c -DEXPECT_CODE=1 -DMATCH=... -P run-cli-check.cmake

if(NOT DEFINED CLI)
    message(FATAL_ERROR "run-cli-check: CLI is not set")
endif()
if(NOT DEFINED EXPECT_CODE)
    set(EXPECT_CODE 0)
endif()

set(_args "")
if(DEFINED ARGS AND NOT ARGS STREQUAL "")
    string(REPLACE "|" ";" _args "${ARGS}")
endif()

execute_process(
    COMMAND "${CLI}" ${_args}
    OUTPUT_VARIABLE _out
    ERROR_VARIABLE _err
    RESULT_VARIABLE _code
)
set(_text "${_out}${_err}")

message(STATUS "command : ${CLI} ${_args}")
message(STATUS "exit    : ${_code} (expected ${EXPECT_CODE})")
message(STATUS "output  :\n${_text}")

# STREQUAL (not EQUAL): execute_process sets RESULT_VARIABLE to an error string
# (e.g. "No such file or directory") when the process fails to start, and EQUAL
# would abort CMake on a non-numeric operand. STREQUAL compares safely.
if(NOT "${_code}" STREQUAL "${EXPECT_CODE}")
    message(FATAL_ERROR "run-cli-check: expected exit code ${EXPECT_CODE}, got ${_code}")
endif()

if(DEFINED MATCH AND NOT MATCH STREQUAL "")
    if(NOT _text MATCHES "${MATCH}")
        message(FATAL_ERROR "run-cli-check: output does not match required pattern '${MATCH}'")
    endif()
endif()

if(DEFINED NOMATCH AND NOT NOMATCH STREQUAL "")
    if(_text MATCHES "${NOMATCH}")
        message(FATAL_ERROR "run-cli-check: output unexpectedly matches forbidden pattern '${NOMATCH}'")
    endif()
endif()
