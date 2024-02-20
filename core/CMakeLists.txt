configure_file(Kbuild.in ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild @ONLY)

set(KFLAT_CORE kflat_core.ko)

set(KBUILD_CMD $(MAKE) M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} ${KBUILD_FLAGS} modules)

add_custom_command(
    OUTPUT ${KFLAT_CORE}
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)

add_custom_target(kflat_core ALL DEPENDS ${KFLAT_CORE} tests_list)