set(KBUILD_CMD $(MAKE) M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} ${KBUILD_FLAGS} modules)
# Edit these two lines
set(RECIPE_SOURCE_NAME ioctl_module)
set(TARGET_NAME ioctl_test_module)

list(TRANSFORM RECIPE_SOURCE_NAME APPEND ".o")
configure_file(${PROJECT_SOURCE_DIR}/cmake/Kbuild.recipe_template.in ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild @ONLY)

add_custom_command(
    OUTPUT ${RECIPE_SOURCE_NAME}
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)

add_custom_target(${TARGET_NAME} ALL DEPENDS kflat_core ${RECIPE_SOURCE_NAME})
