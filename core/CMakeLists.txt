configure_file(Kbuild.in ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild @ONLY)

set(KFLAT_CORE kflat_core.ko)

# Specify source files dependencies to track their modifications
set(KFLAT_CORE_SOURCES kflat.c kdump.c flatten_impl.c probing_arm64.S probing_x86_64.S probing.c)
set(KFLAT_CORE_INCLUDES flatten_impl.h probing.h)
file(GLOB KFLAT_INCLUDES ${CMAKE_SOURCE_DIR}/include/*.h)
file(GLOB TEST_SOURCES ${CMAKE_SOURCE_DIR}/tests/*.c)
file(GLOB KFLAT_TEST_SOURCES ${CMAKE_SOURCE_DIR}/tests/kflat/*.c)

set(KBUILD_CMD $(MAKE) M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} ${KBUILD_FLAGS} modules)

add_custom_command(
    OUTPUT ${KFLAT_CORE}
    COMMAND ${KBUILD_CMD}
    DEPENDS ${KFLAT_CORE_SOURCES} ${KFLAT_CORE_INCLUDES} ${KFLAT_INCLUDES} ${TEST_SOURCES} ${KFLAT_TEST_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)

add_custom_target(kflat_core ALL DEPENDS ${KFLAT_CORE} tests_list)