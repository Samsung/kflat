# Directory names and target names (defined in each recipe's individual CMakeLists.txt) must match
set(RECIPES random_read memory_map drm_framebuffer task_current userspace_flattening do_init_module)

foreach(dir ${RECIPES})
    add_subdirectory(${dir})
endforeach()

add_custom_target(recipes)
add_dependencies(recipes ${RECIPES})
