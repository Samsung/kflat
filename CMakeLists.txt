cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(kflat LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE RelWithDebInfo)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(KFLAT_INCLUDES ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

if (NOT KDIR)
    execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(KDIR /lib/modules/${KERNEL_RELEASE}/build)
endif()

message(STATUS "KFLAT compilation target set to ${CMAKE_SYSTEM_PROCESSOR}.")

# This variable is set when the CMAKE_TOOLCHAIN_FILE is specified
if(NOT CMAKE_CROSSCOMPILING)
    message(STATUS "CMake toolchain not set. Defaulting to CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER} LD=${CMAKE_LINKER}.")
endif()

# Flags passed to the make command when building kernel modules
set(KBUILD_FLAGS -C ${KDIR} CC=${CMAKE_C_COMPILER} LD=${CMAKE_LINKER})
if(CMAKE_SYSTEM_PROCESSOR MATCHES arm64)
    list(
        APPEND KBUILD_FLAGS 
        ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CFLAGS="--target=aarch64-linux-gnu --prefix=aarch64-linux-gnu-"
    )
    set(CMAKE_C_FLAGS "--target=aarch64-linux-gnu --prefix=aarch64-linux-gnu-")
    set(CMAKE_CXX_FLAGS "--target=aarch64-linux-gnu --prefix=aarch64-linux-gnu-")
endif()

if(KFLAT_OPTS)
    list(
        APPEND KBUILD_FLAGS 
        OPTS=${KFLAT_OPTS}
    )
endif()

# Generating a header file containing all tests
configure_file(${PROJECT_SOURCE_DIR}/cmake/tests_list_gen.sh.in ${PROJECT_SOURCE_DIR}/tests/tests_list_gen.sh @ONLY)
add_custom_command(
    OUTPUT uflat_tests_list.h kflat_tests_list.h
    COMMAND bash ${PROJECT_SOURCE_DIR}/tests/tests_list_gen.sh
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/
    VERBATIM
)
add_custom_target(tests_list DEPENDS uflat_tests_list.h kflat_tests_list.h)

add_subdirectory(core)
add_subdirectory(lib)
add_subdirectory(tools)
add_subdirectory(recipes)

if(RECIPE_DIRS)
    add_subdirectory(${RECIPE_DIRS} ${PROJECT_BINARY_DIR}/external_recipes)
endif()

enable_testing()

add_test(
    NAME kflat
    COMMAND $<TARGET_FILE:kflattest> ALL
)

add_test(
    NAME uflat
    COMMAND $<TARGET_FILE:uflattest> ALL
)
