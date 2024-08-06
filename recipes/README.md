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
set(RECIPE_SOURCE_NAME edit_me0)
set(TARGET_NAME edit_me1)

list(TRANSFORM RECIPE_SOURCE_NAME APPEND ".o")
string(REPLACE ";" " " RECIPE_SOURCE_NAME "${RECIPE_SOURCE_NAME}")

configure_file(${PROJECT_SOURCE_DIR}/cmake/Kbuild.recipe_template.in ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild @ONLY)

add_custom_command(
    OUTPUT ${RECIPE_SOURCE_NAME}
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)

add_custom_target(${TARGET_NAME} ALL DEPENDS kflat_core ${RECIPE_SOURCE_NAME})

```
Let's say we want to create a new recipe called `my_kflat_example`. The source file is `recipes/my_kflat_example/my_kflat_example_recipe.c`.
Then we should set `RECIPE_SOURCE_NAME` to `my_kflat_example_recipe` and `TARGET_NAME` to `my_kflat_example`. If our module is built from multiple source .c files, then we can pass them like this: `set(RECIPE_SOURCE_NAME src0 src1 src2)` The directory name conaining sources and the TARGET_NAME should be the same.

Next, we need to update the `recipes/CMakeLists.txt` by adding the target to `RECIPES`:
```diff
- set(RECIPES random_read memory_map drm_framebuffer task_current userspace_flattening)
+ set(RECIPES random_read memory_map drm_framebuffer task_current userspace_flattening my_kflat_example)
```

Finally, build the module by invoking `cmake .. && cmake --build . --target my_kflat_example` command in the cmake build directory of this project.

Note: CMake seems to get confused when you set `RECIPE_SOURCE_NAME` and `TARGET_NAME` to the same value, so don't do it.

If you need to build e.g. additional userspace client applications to trigger the recipe, you can also do it in the CMakeLists.txt. Make sure to add the app as the recipe's dependency, so it will be build automatically whenever the recipe is build. See the `userspace_flattening` example for reference.

## Building modules outside of the kflat project
If you want to build kflat recipes outside of the kflat project diretory, you can use the `RECIPE_DIRS` variable.

First, you need to create a root directory with `CMakeLists.txt` based on the template `kflat/cmake/CMakeLists.txt.external_recipes_root`. 

Next, put directories with recipes inside the root directory. In each recipe's directory there must a `CMakeLists.txt` file based on the template `kflat/cmake/CMakeLists.txt.recipe_template`.

Let's consider the following directory structure:

```
external/
├─ example1/
│  ├─ example1_recipe.c
│  ├─ CMakeLists.txt
├─ example2/
│  ├─ example2_recipe.c
│  ├─ CMakeLists.txt
├─ CMakeLists.txt
```

The `CmakeLists.txt` files should be as follows:

#### external/CMakeLists.txt:
```cmake
# Directory names and target names (defined in each recipe's individual CMakeLists.txt) must match
set(EXTERNAL_RECIPES example1 example2)

foreach(dir ${EXTERNAL_RECIPES})
    add_subdirectory(${dir})
endforeach()

add_custom_target(external_recipes)
add_dependencies(external_recipes ${EXTERNAL_RECIPES})
```

#### external/example1/CMakeLists.txt
```cmake
set(KBUILD_CMD $(MAKE) M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} ${KBUILD_FLAGS} modules)
set(RECIPE_SOURCE_NAME example1_recipe)
set(TARGET_NAME example1)

list(TRANSFORM RECIPE_SOURCE_NAME APPEND ".o")
string(REPLACE ";" " " RECIPE_SOURCE_NAME "${RECIPE_SOURCE_NAME}")

configure_file(${PROJECT_SOURCE_DIR}/cmake/Kbuild.recipe_template.in ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild @ONLY)

add_custom_command(
    OUTPUT ${RECIPE_SOURCE_NAME}
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)

add_custom_target(${TARGET_NAME} ALL DEPENDS kflat_core ${RECIPE_SOURCE_NAME})
```

#### external/example2/CMakeLists.txt
```cmake
set(KBUILD_CMD $(MAKE) M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR} ${KBUILD_FLAGS} modules)
set(RECIPE_SOURCE_NAME example2_recipe)
set(TARGET_NAME example2)

list(TRANSFORM RECIPE_SOURCE_NAME APPEND ".o")
string(REPLACE ";" " " RECIPE_SOURCE_NAME "${RECIPE_SOURCE_NAME}")

configure_file(${PROJECT_SOURCE_DIR}/cmake/Kbuild.recipe_template.in ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild @ONLY)

add_custom_command(
    OUTPUT ${RECIPE_SOURCE_NAME}
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM
)

add_custom_target(${TARGET_NAME} ALL DEPENDS kflat_core ${RECIPE_SOURCE_NAME})
```

Now, you can build all the recipes in `RECIPE_DIRS` by running
```bash
# in kflat/build
cmake -DRECIPE_DIRS=/path/to/external ..
cmake --build . -j32 --target external_recipes 
```

or you can build specific recipes by setting the target to their `TARGET_NAME`. The following:
```bash
# in kflat/build
cmake -DRECIPE_DIRS=/path/to/external ..
cmake --build . -j32 --target example1
```
will only build the recipe located in `external/example1`.
## Appendix

### Accessing function arguments
Structure `probe_regs` holds the content of the processor registers from the moment when the target function was supposed to be invoked. Use fields `arg1` to `arg6` to access function arguments (like shown in the Module structure section). Currently, accessing arguments passed by stack is not supported.
