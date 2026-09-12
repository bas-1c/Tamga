add_executable(tamga-cli
    main.cpp
)
tamga_enable_project_compile_policy(tamga-cli)

target_link_libraries(tamga-cli PRIVATE tamga-core-static)

target_include_directories(tamga-cli PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/lib
)
