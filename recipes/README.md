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

To add new kflat recipe, upload `.c`/`.h` files to the new directory and add Kbuild file with the following content:

```make
obj-m += your-c-file-1.o your-c-file-2.o
EXTRA_CFLAGS := -I${PWD}/include/
```

Next, update Kbuild file present in this directory by appending the name of newly created directory to `obj-m` statement. 

```diff
  obj-m += random_read/
+ obj-m += your-directory/
```
Finally, build the module by invoking `make` command in the root directory of this project.

## Appendix

### Accessing function arguments
Structure `probe_regs` holds the content of the processor registers from the moment when the target function was supposed to be invoked. Use fields `arg1` to `arg6` to access function arguments (like shown in the Module structure section). Currently, accessing arguments passed by stack is not supported.
