# Динамічні детектори помилок пам'яті та невизначеної поведінки.
#
# Вмикається опцією TAMGA_ENABLE_SANITIZERS (за замовчуванням OFF): збірка з
# санітайзерами повільніша й не є артефактом постачання — це діагностичний
# режим для CI та локальної перевірки.
#
# Область дії свідомо ГЛОБАЛЬНА (add_compile_options на рівні каталогу), тому
# інструментується і vendored cryptonite. Це не побічний ефект, а мета:
# cryptonite — код на C з ручними malloc/free, і саме там уже знаходили витоки
# (V-07, `sinfo` у VerifyCmsSignerAt). Сторонні бібліотеки з vcpkg лишаються
# неінструментованими — ASan цього не потребує, він працює і без наскрізної
# інструментації всієї програми.

if(NOT TAMGA_ENABLE_SANITIZERS)
    return()
endif()

if(MSVC AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # MSVC надає лише AddressSanitizer; UBSan у нього немає — це прямий наслідок
    # вибору Windows/MSVC як основного шляху (ADR 001/README). Повний набір
    # ASan+UBSan доступний у Clang-збірці.
    message(STATUS "Tamga: sanitizers = AddressSanitizer (MSVC; UBSan недоступний)")
    # ASan діагностика потребує символів також у Release (/WX і C5072).
    add_compile_options(/fsanitize=address /Zi)
    add_link_options(/DEBUG)

    # `/fsanitize=address` вмикає анотації контейнерів MSVC STL
    # (`std::string`, `std::vector`, `std::optional`) у нашому коді. Прибудовані
    # бібліотеки з vcpkg зібрані БЕЗ ASan, тож їхні об'єктні файли несуть
    # протилежне значення тих самих маркерів, і лінкер валить збірку з LNK2038.
    # Практично це стосується qpdf: він на C++, тоді як libxml2 і zlib — на C.
    #
    # Тому анотації типово вимкнено одним макросом `_DISABLE_STL_ANNOTATION`.
    # Втрата реальна, і називаю її прямо: зникає детекція container-overflow —
    # запис за межі частини, зарезервованої, але ще не використаної контейнером.
    # Решта ASan — heap/stack/global overflow, use-after-free, подвійне
    # звільнення, витоки — працює в повному обсязі.
    #
    # Вмикати назад має сенс лише там, де ВСІ C++-залежності зібрано з ASan
    # (наприклад, конфігурація з TAMGA_ENABLE_PDF_SIGNATURES=OFF).
    option(TAMGA_ASAN_STL_ANNOTATIONS
        "Keep MSVC ASan STL container annotations (requires every C++ dependency to be ASan-built)" OFF)
    if(NOT TAMGA_ASAN_STL_ANNOTATIONS)
        add_compile_definitions(_DISABLE_STL_ANNOTATION=1)
        message(STATUS "Tamga: ASan STL-анотації вимкнено (сумісність із прибудованими vcpkg-залежностями)")
    endif()
    # ASan несумісний з інкрементальним лінкуванням і з edit-and-continue.
    add_link_options(/INCREMENTAL:NO)
    string(REPLACE "/INCREMENTAL" "" CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
    string(REPLACE "/INCREMENTAL" "" CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
    string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    set(TAMGA_SANITIZERS_SUMMARY "address" CACHE INTERNAL "")

    # MSVC лінкує ASan ДИНАМІЧНО навіть при /MT, тож поруч із тестами має бути
    # clang_rt.asan_dynamic. Без нього запуск падає з 0xc0000135
    # (STATUS_DLL_NOT_FOUND) ЩЕ ДО входу в main — і CTest покаже це як «тест
    # впав», хоча жоден тест не виконався. Каталог знаходимо поруч із
    # компілятором і додаємо в PATH тестів (див. tests/CMakeLists.txt).
    get_filename_component(_tamga_msvc_bin_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    find_file(TAMGA_ASAN_RUNTIME_DLL
        NAMES clang_rt.asan_dynamic-x86_64.dll clang_rt.asan_dynamic-i386.dll
        HINTS "${_tamga_msvc_bin_dir}"
        NO_DEFAULT_PATH)
    if(TAMGA_ASAN_RUNTIME_DLL)
        get_filename_component(TAMGA_ASAN_RUNTIME_DIR "${TAMGA_ASAN_RUNTIME_DLL}" DIRECTORY)
        message(STATUS "Tamga: ASan runtime = ${TAMGA_ASAN_RUNTIME_DLL}")
    else()
        message(WARNING
            "Tamga: clang_rt.asan_dynamic не знайдено поруч із компілятором. "
            "Тести доведеться запускати з Developer Command Prompt, інакше вони "
            "впадуть із 0xc0000135 ще до старту.")
    endif()
else()
    # -fno-sanitize-recover: UBSan за замовчуванням лише ДРУКУЄ діагностику і
    # продовжує роботу, тож у CI такий запуск лишався б зеленим. Нам потрібен
    # ненульовий код виходу, інакше детектор нічого не сторожить.
    set(_tamga_san address,undefined)
    message(STATUS "Tamga: sanitizers = ${_tamga_san}")
    add_compile_options(
        -fsanitize=${_tamga_san}
        -fno-sanitize-recover=undefined
        -fno-omit-frame-pointer
        -g
    )
    add_link_options(-fsanitize=${_tamga_san})
    set(TAMGA_SANITIZERS_SUMMARY "${_tamga_san}" CACHE INTERNAL "")
endif()
