# ======================
# ====== executor ======
# ======================
add_executable(executor executor_v2.cpp)
set_target_properties(executor PROPERTIES CXX_STANDARD 17)
target_link_libraries(executor ExecFlat_static)
target_link_options(executor PRIVATE "-static")
target_include_directories(executor PUBLIC ${KFLAT_INCLUDES})

# =======================
# ======== tests ========
# =======================

# Library for nice and colored logging
add_library(common OBJECT common_tools.c)
target_compile_definitions(common PRIVATE __VALIDATOR__)
target_include_directories(common PRIVATE 
    ${KFLAT_INCLUDES} 
    ${CMAKE_SOURCE_DIR}/tools
)

# Collect all test files
file(GLOB TEST_SOURCES ${CMAKE_SOURCE_DIR}/tests/*.c)
file(GLOB KFLAT_TEST_SOURCES ${CMAKE_SOURCE_DIR}/tests/kflat/*.c)
file(GLOB UFLAT_TEST_SOURCES ${CMAKE_SOURCE_DIR}/tests/uflat/*.c)

# kflat testing
add_executable(kflattest kflattest.c ${TEST_SOURCES} ${KFLAT_TEST_SOURCES})
add_dependencies(kflattest kflat_core tests_list)

target_include_directories(kflattest PRIVATE ${KFLAT_INCLUDES} ${CMAKE_SOURCE_DIR}/tests)
target_link_libraries(kflattest common unflatten_static)

target_compile_definitions(kflattest PRIVATE __VALIDATOR__)
target_link_options(kflattest PRIVATE "-static")

# uflat testing
set(UFLATTEST_RUNNER_SOURCES uflattest.c ${TEST_SOURCES} ${UFLAT_TEST_SOURCES})
add_executable(uflattest ${UFLATTEST_RUNNER_SOURCES})

add_dependencies(uflattest tests_list)
target_include_directories(uflattest PRIVATE ${KFLAT_INCLUDES} ${CMAKE_SOURCE_DIR}/tests ${CMAKE_SOURCE_DIR}/lib/include_priv)

target_link_libraries(uflattest common unflatten_static uflat_static dl)
target_compile_definitions(uflattest PRIVATE __VALIDATOR__ __TESTER__ FLATTEN_USERSPACE_BSP)
target_link_options(uflattest PRIVATE "-static")

add_custom_target(tools DEPENDS executor uflattest kflattest)
