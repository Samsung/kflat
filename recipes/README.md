# Kflat recipes repository

In order to properly dump kernel structures, kflat requires description of data type called *kflat recipe*. Each recipe is built as a separate kernel module that could be loaded when needed.

## Module structure

A basic scheme for kflat recipe module is presented below. Ready to use example can be found in directory `random_read`.

```c
#include <linux/module.h>
#include <linux/interval_tree_generic.h>

#include "kflat.h"
#include "kflat_recipe.h"


// Declare recipes for required data_types
FUNCTION_DEFINE_FLATTEN_STRUCT(priv_data,
	// ...
);

// Declare pointers for global variables
static void* some_global_var;

// Create optional pre_handler responsible for extracting pointers to
//  global variables from kallsyms
static void pre_handler(struct kflat* kflat) {
    some_global_var = flatten_global_address_by_name("global_variable_name");
}

// Create base handler that will be invoked in instrumented function
//  flatten_init, flatten_write and flatten_fini were/will be invoked by
//  kflat core module, so they shouldn't be added here.
// Access instrumented func args by using fields arg0, arg1, ... in regs
static void handler(struct kflat* kflat, struct probe_regs* regs) {
    struct priv_data* priv = (void*) regs->arg1;

    // Dump structure
    FOR_ROOT_POINTER(priv,
        FLATTEN_STRUCT(priv_data, priv);
    );

    // Dump global variable
    if(some_global_var != NULL) {
        FOR_EXTENDED_ROOT_POINTER(some_global_var, "global_variable_name", 32,
			FLATTEN_STRUCT(global_type, some_global_var);
		);
    }
}

// Declaration of instrumented functions
//  For each func assign handler. Function name is also the ID of recipe
KFLAT_RECIPE_LIST(
    KFLAT_RECIPE_EX("<function_name, ex. random_read>", handler, pre_handler),
    // ... More if needed
);
KFLAT_RECIPE_MODULE("<Description of your module>");
```

## Creating module

To add new kflat recipe, upload `.c`/`.h` files to the new directory and copy the CMakeLists.txt.template file (rename it to CMakeLists.txt).
The CMakeLists.txt should look as follows:
```cmake
set(KBUILD_CMD $(MAKE) M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} ${KBUILD_FLAGS} modules)
# Edit these two lines
set(RECIPE_SOURCE_NAME edit_me)
set(TARGET_NAME edit_me)

configure_file(${CMAKE_SOURCE_DIR}/cmake/Kbuild.recipe_template.in ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild @ONLY)

add_custom_command(
    OUTPUT ${RECIPE_SOURCE_NAME}
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)set(RECIPES random_read memory_map drm_framebuffer task_current userspace_flattening)

add_custom_target(${TARGET_NAME} ALL DEPENDS kflat_core ${RECIPE_SOURCE_NAME})
```
Let's say we want to create a new recipe called `my_kflat_example`. The source file is `recipes/my_kflat_example/my_kflat_example_recipe.c`.
Then we should set `RECIPE_SOURCE_NAME` to `my_kflat_example_recipe` and `TARGET_NAME` to `my_kflat_example`. The directory name conaining sources and the TARGET_NAME should be the same.

Next, we need to update the `recipes/CMakeLists.txt` by adding the target to `RECIPES`:
```diff
- set(RECIPES random_read memory_map drm_framebuffer task_current userspace_flattening)
+ set(RECIPES random_read memory_map drm_framebuffer task_current userspace_flattening my_kflat_example)
```

Finally, build the module by invoking `cmake .. && cmake --build . --target my_kflat_example` command in the cmake build directory of this project.

Note: CMake seems to get confused when you set `RECIPE_SOURCE_NAME` and `TARGET_NAME` to the same value, so don't do it.

If you need to build e.g. additional userspace client applications to trigger the recipe, you can also do it in the CMakeLists.txt. Make sure to add the app as the recipe's dependency, so it will be build automatically whenever the recipe is build. See the `userspace_flattening` example for reference.

## Appendix

### Accessing function arguments
Structure `probe_regs` holds the content of the processor registers from the moment when the target function was supposed to be invoked. Use fields `arg1` to `arg6` to access function arguments (like shown in the Module structure section). Currently, accessing arguments passed by stack is not supported.
