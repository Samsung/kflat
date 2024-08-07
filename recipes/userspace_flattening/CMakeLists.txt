set(KBUILD_CMD $(MAKE) M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} ${KBUILD_FLAGS} modules)
# Edit these two lines
set(RECIPE_SOURCE_NAME userspace_flattening_recipe)
set(TARGET_NAME userspace_flattening)

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

add_executable(ioctl_client ioctl_client.cpp)
target_link_libraries(ioctl_client PRIVATE ExecFlat_static)
target_include_directories(ioctl_client PRIVATE ${KFLAT_INCLUDES})

add_subdirectory(ioctl_module)
add_custom_target(${TARGET_NAME} ALL DEPENDS kflat_core ioctl_test_module ${RECIPE_SOURCE_NAME})
