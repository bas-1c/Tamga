if(NOT DEFINED TAMGA_BUILD_DIR OR NOT DEFINED TAMGA_SOURCE_DIR)
    message(FATAL_ERROR "TAMGA_BUILD_DIR and TAMGA_SOURCE_DIR are required")
endif()

set(_work "${TAMGA_BUILD_DIR}/tamga-package-consumer")
set(_prefix "${_work}/install")
set(_consumer_build "${_work}/consumer-build")
file(REMOVE_RECURSE "${_work}")

set(_install_args --install "${TAMGA_BUILD_DIR}" --prefix "${_prefix}")
if(DEFINED TAMGA_CONFIG AND NOT TAMGA_CONFIG STREQUAL "")
    list(APPEND _install_args --config "${TAMGA_CONFIG}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" ${_install_args}
    RESULT_VARIABLE _install_result
    OUTPUT_VARIABLE _install_output
    ERROR_VARIABLE _install_error
)
if(NOT _install_result EQUAL 0)
    message(FATAL_ERROR "Package installation failed:\n${_install_output}\n${_install_error}")
endif()

set(_configure_args
    -S "${TAMGA_SOURCE_DIR}/tests/package-consumer"
    -B "${_consumer_build}"
    "-DCMAKE_PREFIX_PATH=${_prefix}"
)
if(DEFINED TAMGA_GENERATOR AND NOT TAMGA_GENERATOR STREQUAL "")
    list(APPEND _configure_args -G "${TAMGA_GENERATOR}")
    # Розрядність мусить збігтися зі встановленим пакетом, інакше
    # `find_package(Tamga CONFIG)` відхилить конфіг як несумісний, і помилка
    # виглядатиме як «пакет не знайдено», хоча він поруч і цілий.
    if(DEFINED TAMGA_GENERATOR_PLATFORM AND NOT TAMGA_GENERATOR_PLATFORM STREQUAL "")
        list(APPEND _configure_args -A "${TAMGA_GENERATOR_PLATFORM}")
    endif()
endif()
if(DEFINED TAMGA_MAKE_PROGRAM AND NOT TAMGA_MAKE_PROGRAM STREQUAL "")
    list(APPEND _configure_args "-DCMAKE_MAKE_PROGRAM=${TAMGA_MAKE_PROGRAM}")
endif()
if(DEFINED TAMGA_C_COMPILER AND NOT TAMGA_C_COMPILER STREQUAL "")
    list(APPEND _configure_args "-DCMAKE_C_COMPILER=${TAMGA_C_COMPILER}")
endif()
if(DEFINED TAMGA_CXX_COMPILER AND NOT TAMGA_CXX_COMPILER STREQUAL "")
    list(APPEND _configure_args "-DCMAKE_CXX_COMPILER=${TAMGA_CXX_COMPILER}")
endif()
if(DEFINED TAMGA_RC_COMPILER AND NOT TAMGA_RC_COMPILER STREQUAL "")
    list(APPEND _configure_args "-DCMAKE_RC_COMPILER=${TAMGA_RC_COMPILER}")
endif()
if(DEFINED TAMGA_MT_COMPILER AND NOT TAMGA_MT_COMPILER STREQUAL "")
    list(APPEND _configure_args "-DCMAKE_MT=${TAMGA_MT_COMPILER}")
endif()
# GCC/Ninja задає x86 через -m32, без generator platform. Передаємо
# compile/link flags, щоб незалежний consumer мав ABI встановленого пакета.
foreach(_flags C_FLAGS CXX_FLAGS EXE_LINKER_FLAGS)
    if(DEFINED TAMGA_${_flags})
        list(APPEND _configure_args "-DCMAKE_${_flags}=${TAMGA_${_flags}}")
    endif()
endforeach()
execute_process(
    COMMAND "${CMAKE_COMMAND}" ${_configure_args}
    RESULT_VARIABLE _configure_result
    OUTPUT_VARIABLE _configure_output
    ERROR_VARIABLE _configure_error
)
if(NOT _configure_result EQUAL 0)
    message(FATAL_ERROR "Package consumer configure failed:\n${_configure_output}\n${_configure_error}")
endif()

set(_targets_file "${_prefix}/lib/cmake/Tamga/TamgaTargets.cmake")
if(NOT EXISTS "${_targets_file}")
    message(FATAL_ERROR "Installed TamgaTargets.cmake is missing: ${_targets_file}")
endif()
file(READ "${_targets_file}" _targets)
if(_targets MATCHES "INTERFACE_LINK_DIRECTORIES")
    message(FATAL_ERROR "Installed package must not export INTERFACE_LINK_DIRECTORIES")
endif()
if(_targets MATCHES "[A-Za-z]:/vcpkg/" OR _targets MATCHES "[A-Za-z]:\\\\vcpkg\\\\")
    message(FATAL_ERROR "Installed package contains an absolute vcpkg path")
endif()
file(TO_CMAKE_PATH "${TAMGA_SOURCE_DIR}" _source_norm)
if(_targets MATCHES "${_source_norm}")
    message(FATAL_ERROR "Installed package contains a source-tree path")
endif()

set(_build_args --build "${_consumer_build}")
if(DEFINED TAMGA_CONFIG AND NOT TAMGA_CONFIG STREQUAL "")
    list(APPEND _build_args --config "${TAMGA_CONFIG}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" ${_build_args}
    RESULT_VARIABLE _build_result
    OUTPUT_VARIABLE _build_output
    ERROR_VARIABLE _build_error
)
if(NOT _build_result EQUAL 0)
    message(FATAL_ERROR "Package consumer build failed:\n${_build_output}\n${_build_error}")
endif()

if(WIN32)
    set(_exe_suffix ".exe")
    set(_path_separator ";")
else()
    set(_exe_suffix "")
    set(_path_separator ":")
endif()
set(_old_path "$ENV{PATH}")
set(ENV{PATH} "${_prefix}/bin${_path_separator}${_prefix}/lib${_path_separator}${_old_path}")
foreach(_consumer tamga-c-api-consumer tamga-cpp-api-consumer)
    # Розкладка виконуваного файлу залежить від генератора, і це не деталь:
    # single-config (Ninja, Makefiles) кладе його прямо в каталог збірки, а
    # multi-config (Visual Studio) — у підкаталог конфігурації. Збірка вище це
    # враховує через `--config`, а запуск раніше — ні, тож у
    # `windows-msvc-matrix` тест падав із «no such file or directory», хоча
    # споживач успішно зібрався. У `windows-static-shipping` (Ninja) той самий
    # тест проходив, тому розбіжність довго лишалася невидимою.
    set(_candidates "${_consumer_build}/${_consumer}${_exe_suffix}")
    if(DEFINED TAMGA_CONFIG AND NOT TAMGA_CONFIG STREQUAL "")
        list(INSERT _candidates 0 "${_consumer_build}/${TAMGA_CONFIG}/${_consumer}${_exe_suffix}")
    endif()
    set(_consumer_exe "")
    foreach(_candidate IN LISTS _candidates)
        if(EXISTS "${_candidate}")
            set(_consumer_exe "${_candidate}")
            break()
        endif()
    endforeach()
    if(_consumer_exe STREQUAL "")
        message(FATAL_ERROR
            "${_consumer}: виконуваний файл не знайдено. Перевірені шляхи:\n"
            "  ${_candidates}\n"
            "Це означає, що споживач або не зібрався, або генератор кладе "
            "результат у ще одну розкладку, якої тут немає.")
    endif()
    execute_process(
        COMMAND "${_consumer_exe}"
        RESULT_VARIABLE _run_result
        OUTPUT_VARIABLE _run_output
        ERROR_VARIABLE _run_error
    )
    if(NOT _run_result EQUAL 0)
        message(FATAL_ERROR "${_consumer} failed (${_run_result}):\n${_run_output}\n${_run_error}")
    endif()
endforeach()
