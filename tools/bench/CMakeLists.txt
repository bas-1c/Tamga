cmake_minimum_required(VERSION 3.23)

# Підключається з кореневого CMakeLists.txt через add_subdirectory(tools/bench)
# за прапорцем TAMGA_BUILD_TOOLS (типово OFF).
#
# Чому ці програми живуть тут, а не в tests/: вони нічого не стверджують і
# нічого не гейтять — вони МІРЯЮТЬ. Помістити їх у CTest означало б або
# зафіксувати очікуване число (і зробити сюїту червоною на іншій машині), або
# перевіряти нічого. Число тут отримує людина й порівнює його сама.

if(TAMGA_CRYPTONITE_TARGETS)
add_executable(tamga_resolve_bench resolve-bench.cpp)
tamga_enable_project_compile_policy(tamga_resolve_bench)
target_link_libraries(tamga_resolve_bench PRIVATE tamga-core-static)
target_include_directories(tamga_resolve_bench PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
    ${CMAKE_SOURCE_DIR}/src/lib/core
    ${CMAKE_SOURCE_DIR}/src/lib/util
)
if(TAMGA_CRYPTONITE_TARGETS)
    # Лінкуємося саме з цілями cryptonite, а не лише з tamga-core-static:
    # заголовки (`aid.h`, `cert.h`, …) приходять транзитивно від них, як і в
    # `tests/CMakeLists.txt`. Через tamga-core-static вони не видні — він
    # свідомо не протікає vendor-заголовками у споживачів.
    target_link_libraries(tamga_resolve_bench PRIVATE ${TAMGA_CRYPTONITE_TARGETS})
    target_compile_definitions(tamga_resolve_bench PRIVATE
        CRYPTONITE_EXPORT=extern
        TAMGA_CRYPTONITE_ENABLED=1
    )
else()
    target_compile_definitions(tamga_resolve_bench PRIVATE TAMGA_CRYPTONITE_ENABLED=0)
endif()
set_target_properties(tamga_resolve_bench PROPERTIES OUTPUT_NAME "tamga-resolve-bench")
endif()

add_executable(tamga_read_alloc_probe read-alloc-probe.cpp)
tamga_enable_project_compile_policy(tamga_read_alloc_probe)
target_link_libraries(tamga_read_alloc_probe PRIVATE tamga-core-static)
target_include_directories(tamga_read_alloc_probe PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
    ${CMAKE_SOURCE_DIR}/src/lib/util
)
set_target_properties(tamga_read_alloc_probe PROPERTIES OUTPUT_NAME "tamga-read-alloc-probe")
