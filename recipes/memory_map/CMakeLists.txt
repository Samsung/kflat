set(KBUILD_CMD $(MAKE) M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} ${KBUILD_FLAGS} modules)
# Edit these two lines
set(RECIPE_SOURCE_NAME memory_map_recipe)
set(TARGET_NAME memory_map)

set(DEPENDENT_SOURCES ${RECIPE_SOURCE_NAME})
list(TRANSFORM DEPENDENT_SOURCES APPEND ".c")
string(REPLACE ";" " " DEPENDENT_SOURCES "${DEPENDENT_SOURCES}")

list(TRANSFORM RECIPE_SOURCE_NAME APPEND ".o")
string(REPLACE ";" " " RECIPE_SOURCE_NAME "${RECIPE_SOURCE_NAME}")

configure_file(${PROJECT_SOURCE_DIR}/cmake/Kbuild.recipe_template.in ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild @ONLY)

add_custom_command(
    OUTPUT ${RECIPE_SOURCE_NAME}
    COMMAND ${KBUILD_CMD}
    DEPENDS ${DEPENDENT_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)



add_custom_target(${TARGET_NAME} ALL DEPENDS kflat_core ${RECIPE_SOURCE_NAME})

add_executable(memory_map_client client_app.cpp)
target_include_directories(memory_map_client PRIVATE ${KFLAT_INCLUDES} ${PROJECT_SOURCE_DIR}/lib/include_priv)
target_link_libraries(memory_map_client PRIVATE unflatten_static)
target_link_options(memory_map_client PRIVATE -static)

add_dependencies(${TARGET_NAME} memory_map_client)