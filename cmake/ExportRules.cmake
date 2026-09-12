function(tamga_apply_export_rules target)
    if(WIN32)
        target_sources(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/nativeapi/Tamga.def)
    elseif(APPLE)
        target_link_options(${target} PRIVATE
            "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/src/nativeapi/exported_symbols.list"
            -Wl,-dead_strip
        )
    else()
        target_link_options(${target} PRIVATE
            "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/nativeapi/version.script"
            -Wl,--exclude-libs,ALL
            -Wl,--gc-sections
        )
    endif()
endfunction()

function(tamga_apply_c_api_export_rules target)
    if(WIN32)
        target_sources(${target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/core/TamgaLib.def
        )
    elseif(APPLE)
        target_link_options(${target} PRIVATE
            "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/src/lib/core/tamga_lib.exported_symbols.list"
            -Wl,-dead_strip
        )
    else()
        target_link_options(${target} PRIVATE
            "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/lib/core/tamga_lib.version.script"
            -Wl,--exclude-libs,ALL
            -Wl,--gc-sections
        )
    endif()
endfunction()
