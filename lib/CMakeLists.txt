# Every library can be build in two versions: static and shared.
# You can build only static or only shared by using a target e.g. "ExecFlat_static".
# You can also build both with one command by using a dummy target e.g. "ExecFlat". 

set(RBTREE_SOURCES rbtree.c)
add_library(rbtree_obj OBJECT ${RBTREE_SOURCES})
set_source_files_properties(${RBTREE_SOURCES} PROPERTIES LANGUAGE CXX)
target_include_directories(rbtree_obj PRIVATE ${PROJECT_SOURCE_DIR}/lib/include_priv)

# ==========================================
# ================ ExecFlat ================
# ==========================================
set(EXECFLAT_SOURCES ExecFlat.cpp)
set(EXECFLAT_INCLUDES ${KFLAT_INCLUDES})

# Create a common OBJECT library so that the sources are compiled only once and then linked both statically and dynamically
add_library(ExecFlat_obj OBJECT ${EXECFLAT_SOURCES})
target_include_directories(ExecFlat_obj PUBLIC ${KFLAT_INCLUDES})
set_target_properties(ExecFlat_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)

# STATIC
add_library(ExecFlat_static STATIC $<TARGET_OBJECTS:ExecFlat_obj>)
set_target_properties(ExecFlat_static PROPERTIES OUTPUT_NAME ExecFlat)
target_include_directories(ExecFlat_static PUBLIC ${KFLAT_INCLUDES})

# SHARED
add_library(ExecFlat_shared SHARED $<TARGET_OBJECTS:ExecFlat_obj>)
set_target_properties(ExecFlat_shared PROPERTIES OUTPUT_NAME ExecFlat)
target_include_directories(ExecFlat_shared PUBLIC ${KFLAT_INCLUDES})

# Custom ExecFlat target that compiles both dynamic and static version of ExecFlat
add_custom_target(ExecFlat DEPENDS ExecFlat_static ExecFlat_shared)


# =======================================
# ================ uflat ================
# =======================================
set(UFLAT_SOURCES uflat.c funcsymsutils.c ${PROJECT_SOURCE_DIR}/core/flatten_impl.c)
set(UFLAT_INCLUDES ${KFLAT_INCLUDES} ${PROJECT_SOURCE_DIR}/lib/include_priv ${PROJECT_SOURCE_DIR}/core)

# Force cmake to compile .c files with the C++ compiler
foreach(source ${UFLAT_SOURCES})
    set_source_files_properties(SOURCE ${source} PROPERTIES LANGUAGE CXX)
endforeach()

# Create a common OBJECT library so that the sources are compiled only once and then linked both statically and dynamically
add_library(uflat_obj OBJECT ${UFLAT_SOURCES} rbtree.c)
target_compile_definitions(uflat_obj PUBLIC FLATTEN_USERSPACE_BSP)
target_include_directories(uflat_obj PUBLIC ${UFLAT_INCLUDES})

# STATIC
add_library(uflat_static STATIC $<TARGET_OBJECTS:uflat_obj>)
set_target_properties(uflat_static PROPERTIES OUTPUT_NAME uflat)
target_include_directories(uflat_static PUBLIC ${UFLAT_INCLUDES})

# SHARED
add_library(uflat_shared SHARED $<TARGET_OBJECTS:uflat_obj>)
set_target_properties(uflat_shared PROPERTIES OUTPUT_NAME uflat)
target_include_directories(uflat_shared PUBLIC ${UFLAT_INCLUDES})

# Custom uflat target that compiles both dynamic and static version of uflat
add_custom_target(uflat DEPENDS uflat_static uflat_shared)


# ===========================================
# ================ unflatten ================
# ===========================================
set(UNFLATTEN_SOURCE unflatten.cpp unflatten.hpp)
set(UNFLATTEN_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include_priv ${KFLAT_INCLUDES})

# Create a common OBJECT library so that the sources are compiled only once and then linked both statically and dynamically
add_library(unflatten_obj OBJECT ${UNFLATTEN_SOURCE} rbtree.c)
target_include_directories(unflatten_obj PUBLIC ${UNFLATTEN_INCLUDES})
set_target_properties(unflatten_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)

# STATIC
add_library(unflatten_static STATIC $<TARGET_OBJECTS:unflatten_obj>)
add_custom_command(
    TARGET unflatten_static
    POST_BUILD
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/lib/
    COMMAND bash ${PROJECT_SOURCE_DIR}/cmake/chop_unflatten.sh ${PROJECT_BINARY_DIR}
)
set_target_properties(unflatten_static PROPERTIES OUTPUT_NAME unflatten)

# SHARED
add_library(unflatten_shared SHARED $<TARGET_OBJECTS:unflatten_obj>)
set_target_properties(unflatten_shared PROPERTIES OUTPUT_NAME unflatten)

# Custom unflatten target that compiles both dynamic and static version of unflatten
add_custom_target(unflatten DEPENDS unflatten_static unflatten_shared)


# These targets require a specific compiler, so they have to be built manually by custom commands.
find_program(clang++-13_FOUND clang++-13 NOCACHE PATH ${KLEE_CLANGXX_PATH})
if (KLEE_LIBCXX_INSTALL AND clang++-13_FOUND)
    set(KLEE_COMPILER ${clang++-13_FOUND})
    set(KLEE_FLAGS -emit-llvm -D KLEE_SUPPORT -c -std=c++11  -nostdinc++)
    set(KLEE_INCLUDES -I${PROJECT_SOURCE_DIR}/include -I${PROJECT_SOURCE_DIR}/lib/include_priv -I${KLEE_LIBCXX_INSTALL}/include/c++/v1/)
    
    set(KLEE_UNFLATTEN_OUTPUT unflatten.bc)
    set(KLEE_UNFLATTEN_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/unflatten.cpp)
    add_custom_command(
        OUTPUT ${KLEE_UNFLATTEN_OUTPUT}
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/lib/
        COMMAND ${KLEE_COMPILER} -o ${KLEE_UNFLATTEN_OUTPUT} ${KLEE_FLAGS} ${KLEE_INCLUDES} ${KLEE_UNFLATTEN_SOURCES}
    )

    set(KLEE_RBTREE_OUTPUT rbtree.bc)
    set(KLEE_RBTREE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rbtree.c)
    add_custom_command(
        OUTPUT ${KLEE_RBTREE_OUTPUT}
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/lib/
        COMMAND ${KLEE_COMPILER} -o ${KLEE_RBTREE_OUTPUT} ${KLEE_FLAGS} ${KLEE_INCLUDES} ${KLEE_RBTREE_SOURCES}
    )

    add_custom_target(klee_libs ALL DEPENDS ${KLEE_UNFLATTEN_OUTPUT} ${KLEE_RBTREE_OUTPUT})
endif()

find_program(clang15_FOUND clang-15 NOCACHE PATH ${DFSAN_CLANG_PATH})
if (clang15_FOUND)
    set(DFSAN_COMPILER ${clang15_FOUND})
    set(DFSAN_FLAGS -I${PROJECT_SOURCE_DIR}/include -I${PROJECT_SOURCE_DIR}/lib/include_priv -O3 -Wall -fPIC -fsanitize=dataflow -mllvm -dfsan-event-callbacks -c)

    set(DFSAN_UNFLATTEN_OUTPUT unflatten_dfsan.o)
    set(DFSAN_UNFLATTEN_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/unflatten.cpp)
    add_custom_command(
        OUTPUT ${DFSAN_UNFLATTEN_OUTPUT}
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/lib/
        COMMAND ${DFSAN_COMPILER} -o ${DFSAN_UNFLATTEN_OUTPUT} ${DFSAN_FLAGS} ${DFSAN_UNFLATTEN_SOURCES}
    )

    set(DFSAN_RBTREE_OUTPUT rbtree_dfsan.o)
    set(DFSAN_RBTREE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/unflatten.cpp)
    add_custom_command(
        OUTPUT ${DFSAN_RBTREE_OUTPUT}
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/lib/
        COMMAND ${DFSAN_COMPILER} -o ${DFSAN_RBTREE_OUTPUT} ${DFSAN_FLAGS} ${DFSAN_RBTREE_SOURCES}
    )

    set(DFSAN_OUTPUT libunflatten_dfsan.a)
    add_custom_command(
        OUTPUT ${DFSAN_OUTPUT}
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/lib/
        COMMAND ar rcs ${DFSAN_OUTPUT} ${DFSAN_UNFLATTEN_OUTPUT} ${DFSAN_RBTREE_OUTPUT}
        DEPENDS ${DFSAN_UNFLATTEN_OUTPUT} ${DFSAN_RBTREE_OUTPUT}
    )
    add_custom_target(dfsan_libs ALL DEPENDS ${DFSAN_OUTPUT})
endif()
