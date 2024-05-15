set(KBUILD_CMD $(MAKE) M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} ${KBUILD_FLAGS} modules)

set(RECIPE_SOURCE_NAME do_init_module_recipe)
set(TARGET_NAME do_init_module)

list(TRANSFORM RECIPE_SOURCE_NAME APPEND ".o")
string(REPLACE ";" " " RECIPE_SOURCE_NAME "${RECIPE_SOURCE_NAME}")

configure_file(${CMAKE_SOURCE_DIR}/cmake/Kbuild.recipe_template.in ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild @ONLY)

add_custom_command(
    OUTPUT ${RECIPE_SOURCE_NAME}
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)

add_executable(do_init_module_client client_app.cpp)
target_link_libraries(do_init_module_client PRIVATE ExecFlat_static unflatten_static)
target_include_directories(do_init_module_client PRIVATE ${KFLAT_INCLUDES})

add_custom_target(${TARGET_NAME} ALL DEPENDS kflat_core ${RECIPE_SOURCE_NAME} random_read do_init_module_client)
